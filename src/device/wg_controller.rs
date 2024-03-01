use super::{Entities, RequestedState, Result};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::collections::{BTreeMap, HashSet};
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use telio_crypto::PublicKey;
use telio_dns::DnsResolver;
use telio_firewall::firewall::{Firewall, FILE_SEND_PORT};
use telio_model::api_config::Features;
use telio_model::constants::{VPN_EXTERNAL_IPV4, VPN_INTERNAL_IPV4, VPN_INTERNAL_IPV6};
use telio_model::mesh::NodeState::Connected;
use telio_model::EndpointMap;
use telio_model::SocketAddr;
use telio_proto::{PeersStatesMap, Session};
use telio_proxy::Proxy;
use telio_traversal::{
    cross_ping_check::CrossPingCheckTrait,
    endpoint_providers::{
        stun::StunEndpointProvider, upnp::UpnpEndpointProvider, EndpointProvider,
    },
    SessionKeeperTrait, UpgradeSyncTrait, WireGuardEndpointCandidateChangeEvent,
};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};
use telio_wg::{uapi::Peer, WireGuard};
use thiserror::Error as TError;
use tokio::sync::Mutex;

pub const DEFAULT_PEER_UPGRADE_WINDOW: u64 = 15;

#[derive(Debug, TError)]
pub enum Error {
    #[error("Duplicate allowed ips.")]
    BadAllowedIps,
    #[error("Peer not found error")]
    PeerNotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerState {
    Disconnected,
    Proxying,
    Upgrading,
    Direct,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestedPeer {
    peer: Peer,
    local_direct_endpoint: Option<(SocketAddr, Session)>,
}

pub async fn consolidate_wg_state(
    requested_state: &RequestedState,
    entities: &Entities,
    features: &Features,
) -> Result {
    let remote_peer_states = if let Some(meshnet_entities) = entities.meshnet.as_ref() {
        meshnet_entities.derp.get_remote_peer_states().await
    } else {
        Default::default()
    };

    consolidate_wg_private_key(
        requested_state,
        &*entities.wireguard_interface,
        &entities.postquantum_wg,
    )
    .await?;
    consolidate_wg_fwmark(requested_state, &*entities.wireguard_interface).await?;
    consolidate_wg_peers(
        requested_state,
        &*entities.wireguard_interface,
        entities.meshnet.as_ref().map(|m| &*m.proxy),
        entities.cross_ping_check(),
        entities.upgrade_sync(),
        entities.session_keeper(),
        &*entities.dns,
        remote_peer_states,
        entities.meshnet.as_ref().and_then(|m| {
            m.direct
                .as_ref()
                .and_then(|direct| direct.stun_endpoint_provider.as_ref())
        }),
        entities.meshnet.as_ref().and_then(|m| {
            m.direct
                .as_ref()
                .and_then(|direct| direct.upnp_endpoint_provider.as_ref())
        }),
        &entities.postquantum_wg,
        features,
    )
    .await?;
    consolidate_firewall(requested_state, &*entities.firewall).await?;
    Ok(())
}

async fn consolidate_wg_private_key<W: WireGuard>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
    post_quantum_vpn: &impl telio_pq::PostQuantum,
) -> Result {
    let private_key = if let Some(pq) = post_quantum_vpn.keys() {
        pq.wg_secret
    } else {
        requested_state.device_config.private_key
    };

    let actual_private_key = wireguard_interface.get_interface().await?.private_key;

    if actual_private_key != Some(private_key) {
        wireguard_interface.set_secret_key(private_key).await?;
    }

    Ok(())
}

async fn consolidate_wg_fwmark<W: WireGuard>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
) -> Result {
    let actual_fwmark = wireguard_interface.get_interface().await?.fwmark;
    let requested_fwmark = requested_state.device_config.fwmark.unwrap_or(0);
    if actual_fwmark != requested_fwmark {
        wireguard_interface.set_fwmark(requested_fwmark).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn consolidate_wg_peers<
    W: WireGuard,
    P: Proxy,
    C: CrossPingCheckTrait,
    U: UpgradeSyncTrait,
    S: SessionKeeperTrait,
    D: DnsResolver,
>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
    proxy: Option<&P>,
    cross_ping_check: Option<&Arc<C>>,
    upgrade_sync: Option<&Arc<U>>,
    session_keeper: Option<&Arc<S>>,
    dns: &Mutex<crate::device::DNS<D>>,
    remote_peer_states: PeersStatesMap,
    stun_ep_provider: Option<&Arc<StunEndpointProvider>>,
    upnp_ep_provider: Option<&Arc<UpnpEndpointProvider>>,
    post_quantum_vpn: &impl telio_pq::PostQuantum,
    features: &Features,
) -> Result {
    let proxy_endpoints = if let Some(p) = proxy {
        p.get_endpoint_map().await?
    } else {
        Default::default()
    };
    let requested_peers = build_requested_peers_list(
        requested_state,
        wireguard_interface,
        cross_ping_check,
        upgrade_sync,
        dns,
        &proxy_endpoints,
        &remote_peer_states,
        post_quantum_vpn,
        features,
    )
    .await?;

    check_allowed_ips_correctness(&requested_peers)?;

    let actual_peers = wireguard_interface.get_interface().await?.peers;

    // Calculate diff between requested and actual list of peers
    let requested_keys: HashSet<&PublicKey> = requested_peers.keys().collect();
    let actual_keys: HashSet<&PublicKey> = actual_peers.keys().collect();
    let delete_keys = &actual_keys - &requested_keys;
    let insert_keys = &requested_keys - &actual_keys;
    let update_keys = &requested_keys & &actual_keys;

    for key in delete_keys {
        telio_log_info!("Removing peer: {:?}", actual_peers.get(key));
        wireguard_interface.del_peer(*key).await?;
    }

    for key in insert_keys {
        telio_log_info!("Inserting peer: {:?}", requested_peers.get(key));
        let peer = requested_peers.get(key).ok_or(Error::PeerNotFound)?;
        wireguard_interface.add_peer(peer.peer.clone()).await?;

        if let Some(stun) = stun_ep_provider {
            if let Some(wg_stun_server) = requested_state.wg_stun_server.as_ref() {
                if wg_stun_server.public_key == *key {
                    stun.trigger_endpoint_candidates_discovery(false).await?;
                }
            }
        }
    }

    let mut is_any_peer_eligible_for_upgrade = false;

    for key in update_keys {
        let requested_peer = requested_peers.get(key).ok_or(Error::PeerNotFound)?;
        let actual_peer = actual_peers.get(key).ok_or(Error::PeerNotFound)?;

        // Check if anything of importance has changed and update if needed
        if !compare_peers(&requested_peer.peer, actual_peer) {
            // Update peer
            telio_log_info!(
                "Peer updated: {:?} -> {:?}",
                actual_peers.get(key),
                requested_peers.get(key)
            );
            wireguard_interface
                .add_peer(requested_peer.peer.clone())
                .await?;
        }

        let is_actual_peer_proxying = is_peer_proxying(actual_peer, &proxy_endpoints);
        match (
            is_actual_peer_proxying,
            is_peer_proxying(&requested_peer.peer, &proxy_endpoints),
        ) {
            (false, true) => {
                // We have downgraded the connection. Notify cross ping check about that.
                if let Some(cpc) = cross_ping_check {
                    cpc.notify_failed_wg_connection(requested_peer.peer.public_key)
                        .await?;
                }

                if let Some(sk) = session_keeper {
                    sk.remove_node(&requested_peer.peer.public_key).await?;
                }

                // Unmute pair to allow communication through proxy
                if let Some(p) = proxy {
                    p.mute_peer(requested_peer.peer.public_key, None).await?;
                }
            }

            (true, false) => {
                // We have upgraded the connection. If the upgrade happened because we have
                // selected a new direct endpoint candidate -> notify the other node about our own
                // local side endpoint, such that the other node can do this upgrade too.
                let public_key = requested_peer.peer.public_key;

                if let (Some(remote_endpoint), Some(local_direct_endpoint)) = (
                    requested_peer.peer.endpoint,
                    requested_peer.local_direct_endpoint,
                ) {
                    if let Some(us) = upgrade_sync {
                        us.request_upgrade(&public_key, remote_endpoint, local_direct_endpoint)
                            .await?
                    }
                }

                // TODO we're not completely sure that the other side has upgraded too and that we're in 'Upgrading' state.
                // Mute pair to avoid oscillations
                if let Some(p) = proxy {
                    p.mute_peer(
                        requested_peer.peer.public_key,
                        Some(Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW)),
                    )
                    .await?;
                }

                // Initiate session keeper to start sending data between peers connected directly
                if let (Some(sk), Some(mesh_ip1), maybe_mesh_ip2) = (
                    session_keeper,
                    requested_peer.peer.allowed_ips.get(0),
                    requested_peer.peer.allowed_ips.get(1),
                ) {
                    let target = if features.ipv6 {
                        match (mesh_ip1.ip(), maybe_mesh_ip2.map(|ip| ip.ip())) {
                            (IpAddr::V4(ip4), Some(IpAddr::V6(ip6))) => (Some(ip4), Some(ip6)),
                            (IpAddr::V6(ip6), Some(IpAddr::V4(ip4))) => (Some(ip4), Some(ip6)),
                            (IpAddr::V4(ip4), _) => (Some(ip4), None),
                            (IpAddr::V6(ip6), _) => (None, Some(ip6)),
                        }
                    } else {
                        match mesh_ip1.ip() {
                            IpAddr::V4(ip4) => (Some(ip4), None),
                            _ => (None, None),
                        }
                    };

                    // Start persistent keepalives
                    sk.add_node(
                        &requested_peer.peer.public_key,
                        target,
                        Duration::from_secs(
                            requested_peer
                                .peer
                                .persistent_keepalive_interval
                                .unwrap_or(requested_state.keepalive_periods.direct)
                                .into(),
                        ),
                    )
                    .await?;
                }
            }

            _ => {}
        }
        telio_log_debug!(
            "peer {:?} proxying: {:?}, state: {:?}, lh: {:?}",
            actual_peer.public_key,
            is_actual_peer_proxying,
            actual_peer.state(),
            actual_peer.time_since_last_handshake
        );
        if is_actual_peer_proxying && actual_peer.state() == Connected {
            is_any_peer_eligible_for_upgrade = true;
        }
    }

    let ep_control = |ep: Arc<dyn EndpointProvider>| async move {
        if is_any_peer_eligible_for_upgrade {
            telio_log_debug!("Unpausing {} provider", ep.name());
            ep.unpause().await;
        } else {
            telio_log_debug!("Pausing {} provider", ep.name());
            ep.pause().await;
        }
    };

    if let Some(stun) = stun_ep_provider {
        ep_control(stun.clone()).await;
    }

    if let Some(upnp) = upnp_ep_provider {
        ep_control(upnp.clone()).await;
    }

    Ok(())
}

fn check_allowed_ips_correctness(peers: &BTreeMap<PublicKey, RequestedPeer>) -> Result {
    peers
        .iter()
        .map(|(_, p)| HashSet::from_iter(&p.peer.allowed_ips))
        .try_fold(HashSet::new(), |all_allowed_ips, peer_allowed_ips| {
            if all_allowed_ips.is_disjoint(&peer_allowed_ips) {
                Some(HashSet::from_iter(
                    all_allowed_ips.union(&peer_allowed_ips).cloned(),
                ))
            } else {
                None
            }
        })
        .map(|_| ())
        .ok_or_else(|| Error::BadAllowedIps.into())
}

fn iter_peers(
    requested_state: &RequestedState,
) -> impl Iterator<Item = &telio_model::config::Peer> {
    requested_state
        .meshnet_config
        .iter()
        .flat_map(|c| c.peers.iter())
        .flatten()
}

async fn consolidate_firewall<F: Firewall>(
    requested_state: &RequestedState,
    firewall: &F,
) -> Result {
    let from_keys_peer_whitelist: HashSet<PublicKey> =
        firewall.get_peer_whitelist().iter().copied().collect();
    let from_keys_ports_whitelist: HashSet<PublicKey> =
        firewall.get_port_whitelist().keys().copied().collect();

    // Build a list of peers expected to be peer-whitelisted according
    // to allow_incoming_connections permission
    let mut to_keys_peer_whitelist: HashSet<PublicKey> = iter_peers(requested_state)
        .filter(|p| p.allow_incoming_connections)
        .map(|p| p.public_key)
        .collect();

    // VPN peer must always be peer-whitelisted
    if let Some(exit_node) = &requested_state.exit_node {
        let is_vpn_exit_node =
            !iter_peers(requested_state).any(|p| p.public_key == exit_node.public_key);

        if is_vpn_exit_node {
            to_keys_peer_whitelist.insert(exit_node.public_key);
        }
    }

    // Build a list of peers expected to be port-whitelisted according
    // to allow_peer_send_files permission
    let to_keys_ports_whitelist: HashSet<PublicKey> = iter_peers(requested_state)
        .filter(|p| p.allow_peer_send_files)
        .map(|p| p.public_key)
        .collect();

    // Consolidate peer-whitelist
    let delete_keys = &from_keys_peer_whitelist - &to_keys_peer_whitelist;
    let add_keys = &to_keys_peer_whitelist - &from_keys_peer_whitelist;
    for key in delete_keys {
        firewall.remove_from_peer_whitelist(key);
    }
    for key in add_keys {
        firewall.add_to_peer_whitelist(key);
    }

    // Consolidate port-whitelist
    let delete_keys = &from_keys_ports_whitelist - &to_keys_ports_whitelist;
    let add_keys = &to_keys_ports_whitelist - &from_keys_ports_whitelist;
    for key in delete_keys {
        firewall.remove_from_port_whitelist(key);
    }
    for key in add_keys {
        firewall.add_to_port_whitelist(key, FILE_SEND_PORT);
    }

    Ok(())
}

// Builds a full list of WG peers according to current requested state (config) and entities state
#[allow(clippy::too_many_arguments)]
async fn build_requested_peers_list<
    W: WireGuard,
    C: CrossPingCheckTrait,
    U: UpgradeSyncTrait,
    D: DnsResolver,
>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
    cross_ping_check: Option<&Arc<C>>,
    upgrade_sync: Option<&Arc<U>>,
    dns: &Mutex<crate::device::DNS<D>>,
    proxy_endpoints: &EndpointMap,
    remote_peer_states: &PeersStatesMap,
    post_quantum_vpn: &impl telio_pq::PostQuantum,
    features: &Features,
) -> Result<BTreeMap<PublicKey, RequestedPeer>> {
    // Build a list of meshnet peers
    let mut requested_peers = build_requested_meshnet_peers_list(
        requested_state,
        wireguard_interface,
        cross_ping_check,
        upgrade_sync,
        proxy_endpoints,
        remote_peer_states,
        features,
    )
    .await?;
    let mut exit_node_exists = false;

    // Add or promote exit node peer
    if let Some(exit_node) = &requested_state.exit_node {
        let allowed_ips: Vec<IpNetwork> = exit_node
            .allowed_ips
            .clone()
            .unwrap_or(vec![
                IpNetwork::V4("0.0.0.0/0".parse()?),
                IpNetwork::V6("::/0".parse()?),
            ])
            .into_iter()
            .filter(|network| features.ipv6 || network.is_ipv4())
            .collect();

        if let Some(meshnet_peer) = requested_peers.get_mut(&exit_node.public_key) {
            // Exit node is meshnet peer, so just promote already existing node to be exit node
            // with allowed ips change
            meshnet_peer.peer.allowed_ips = allowed_ips;
            exit_node_exists = true;
        } else {
            // Exit node is a fresh node, therefore - insert create new peer
            let public_key = exit_node.public_key;
            let endpoint = exit_node.endpoint;

            let mut ip_addresses = vec![IpAddr::V4(Ipv4Addr::from(VPN_INTERNAL_IPV4))];
            if features.ipv6 {
                ip_addresses.push(IpAddr::V6(Ipv6Addr::from(VPN_INTERNAL_IPV6)));
            }
            ip_addresses.push(IpAddr::V4(Ipv4Addr::from(VPN_EXTERNAL_IPV4)));
            let persistent_keepalive_interval = requested_state.keepalive_periods.vpn;

            // If the PQ VPN is set up we need to configure the preshared key
            match (post_quantum_vpn.is_rotating_keys(), post_quantum_vpn.keys()) {
                (true, None) => {
                    // The post quantum state is not ready, we don't want to set up quantum
                    // unsafe tunnel with this peer
                }
                (_, pq_keys) => {
                    let preshared_key = pq_keys.map(|pq| pq.pq_shared);

                    requested_peers.insert(
                        exit_node.public_key,
                        RequestedPeer {
                            peer: telio_wg::uapi::Peer {
                                public_key,
                                endpoint,
                                ip_addresses,
                                persistent_keepalive_interval,
                                allowed_ips,
                                preshared_key,
                                ..Default::default()
                            },
                            local_direct_endpoint: None,
                        },
                    );
                }
            }
        }
    }

    // Add DNS peer if enabled
    let dns = dns.lock().await;
    if let (Some(_), Some(resolver)) = (&requested_state.upstream_servers, &dns.resolver) {
        let dns_allowed_ips = if exit_node_exists {
            resolver.get_exit_connected_dns_allowed_ips()
        } else {
            resolver.get_default_dns_allowed_ips()
        };
        let dns_peer = resolver.get_peer(dns_allowed_ips);
        let dns_peer_public_key = dns_peer.public_key;
        let requested_peer = RequestedPeer {
            peer: dns_peer,
            local_direct_endpoint: None,
        };
        requested_peers.insert(dns_peer_public_key, requested_peer);
    }

    if let Some(wg_stun_server) = &requested_state.wg_stun_server {
        let public_key = wg_stun_server.public_key;
        let endpoint = SocketAddr::new(IpAddr::V4(wg_stun_server.ipv4), wg_stun_server.stun_port);
        telio_log_debug!("Configuring wg-stun peer: {}, at {}", public_key, endpoint);
        let persistent_keepalive_interval = requested_state.keepalive_periods.stun;
        let allowed_ips = if features.ipv6 {
            vec![
                IpNetwork::V4("100.64.0.4/32".parse()?),
                IpNetwork::V6("fd74:656c:696f::4/128".parse()?),
            ]
        } else {
            vec![IpNetwork::V4("100.64.0.4/32".parse()?)]
        };
        let ip_addresses = allowed_ips.iter().copied().map(|ip| ip.ip()).collect();

        requested_peers.insert(
            public_key,
            RequestedPeer {
                peer: telio_wg::uapi::Peer {
                    public_key,
                    endpoint: Some(endpoint),
                    ip_addresses,
                    persistent_keepalive_interval,
                    allowed_ips,
                    ..Default::default()
                },
                local_direct_endpoint: None,
            },
        );
    } else {
        telio_log_debug!("wg-stun peer not configured");
    }

    Ok(requested_peers)
}

// Builds a list of peers for meshnet, not taking into account any exit node, DNS, etc. peers
#[allow(clippy::too_many_arguments)]
async fn build_requested_meshnet_peers_list<
    W: WireGuard,
    C: CrossPingCheckTrait,
    U: UpgradeSyncTrait,
>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
    cross_ping_check: Option<&Arc<C>>,
    upgrade_sync: Option<&Arc<U>>,
    proxy_endpoints: &EndpointMap,
    remote_peer_states: &PeersStatesMap,
    features: &Features,
) -> Result<BTreeMap<PublicKey, RequestedPeer>> {
    // Retrieve meshnet config. If it is not set, no peers are requested
    let meshnet_config = match &requested_state.meshnet_config {
        None => return Ok(BTreeMap::new()),
        Some(cfg) => cfg,
    };

    // Retrieve peer list from meshnet config. If it is not set, no peers are requested
    let requested_peers = match &meshnet_config.peers {
        None => return Ok(BTreeMap::new()),
        Some(peers) => peers,
    };

    let mut deduplicated_peer_ips = deduplicate_peer_ips(requested_peers);

    // map config peers into wg interface peers. Taking endpoint addresses from proxy state
    let mut requested_peers: BTreeMap<PublicKey, RequestedPeer> = requested_peers
        .iter()
        .map(|p| {
            // Retrieve public key
            let public_key = p.base.public_key;
            let persistent_keepalive_interval = requested_state.keepalive_periods.proxying;
            let endpoint = proxy_endpoints.get(&public_key).cloned();

            // Keep track of meshnet IP needed for instance for QoS analytics
            let ip_addresses = match deduplicated_peer_ips.get(&public_key) {
                Some(ips) => ips.clone(),
                None => vec![],
            };

            // Retrieve node's meshnet IP from config, and convert it into `/32` network type for v4, and `/128` for v6
            let allowed_ips = deduplicated_peer_ips
                .remove(&public_key)
                .map_or(vec![], |ips| {
                    ips.iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(_) => IpNetwork::new(*ip, 32).ok(),
                            IpAddr::V6(_) if features.ipv6 => IpNetwork::new(*ip, 128).ok(),
                            IpAddr::V6(_) => None,
                        })
                        .collect()
                });
            telio_log_debug!(
                "Allowed IPs for peer with public key {:?}: {:?}",
                &public_key,
                &allowed_ips
            );

            // Build telio_wg::uapi::Peer struct
            (
                public_key,
                RequestedPeer {
                    peer: telio_wg::uapi::Peer {
                        public_key,
                        endpoint,
                        ip_addresses,
                        persistent_keepalive_interval,
                        allowed_ips,
                        ..Default::default()
                    },
                    local_direct_endpoint: None,
                },
            )
        })
        .collect();

    // Retrieve actual list of peers
    let actual_peers = wireguard_interface.get_interface().await?.peers;
    let checked_endpoints = if let Some(cpc) = cross_ping_check {
        cpc.get_validated_endpoints().await?
    } else {
        Default::default()
    };
    let upgrade_request_endpoints = if let Some(us) = upgrade_sync {
        us.get_upgrade_requests().await?
    } else {
        Default::default()
    };

    // See which peers can be upgraded to direct connection
    for (public_key, requested_peer) in requested_peers.iter_mut() {
        // Gather required information
        let actual_peer = actual_peers.get(public_key);
        let time_since_last_endpoint_change = wireguard_interface
            .time_since_last_endpoint_change(*public_key)
            .await?;
        let checked_endpoint = checked_endpoints.get(public_key);
        let proxy_endpoint = proxy_endpoints.get(public_key);
        let upgrade_request_endpoint = upgrade_request_endpoints
            .get(public_key)
            .map(|ur| ur.endpoint);

        // Handshake packets are not counted by the interface
        let time_since_last_rx = wireguard_interface.time_since_last_rx(*public_key).await?;
        let time_since_last_hs = actual_peer.and_then(|peer| peer.time_since_last_handshake);

        let time_since_last_rx_or_handshake = match (time_since_last_rx, time_since_last_hs) {
            (Some(last_rx), Some(last_hs)) => Some(last_rx.min(last_hs)),
            (Some(last_rx), None) => Some(last_rx),
            (None, Some(last_hs)) => Some(last_hs),
            _ => None,
        };

        // Compute the current endpoint state
        let peer_state = peer_state(
            actual_peer,
            time_since_last_rx_or_handshake.as_ref(),
            time_since_last_endpoint_change.as_ref(),
            proxy_endpoint,
            requested_state,
        );

        // If we are in direct state, tell cross ping check about it
        if peer_state == PeerState::Direct {
            if let Some(cpc) = cross_ping_check {
                cpc.notify_successfull_wg_connection_upgrade(*public_key)
                    .await?;
            }
        }

        // Select actual endpoint
        let (selected_remote_endpoint, selected_local_endpoint) = select_endpoint_for_peer(
            public_key,
            &actual_peer.cloned(),
            &time_since_last_rx_or_handshake,
            peer_state,
            &checked_endpoint.cloned(),
            &proxy_endpoint.cloned(),
            &upgrade_request_endpoint,
        )
        .await?;

        // Apply the selected endpoints, and save local endpoint because we may need to share it
        // with the other end
        requested_peer.peer.endpoint = selected_remote_endpoint;
        requested_peer.local_direct_endpoint = selected_local_endpoint;

        // Adjust keepalive for direct and offline peers
        requested_peer.peer.persistent_keepalive_interval =
            if is_peer_proxying(&requested_peer.peer, proxy_endpoints) {
                if matches!(
                    remote_peer_states.get(&requested_peer.peer.public_key),
                    Some(false)
                ) {
                    // If peer is offline according to derp, we turn off keepalives.
                    None
                } else {
                    requested_state.keepalive_periods.proxying
                }
            } else {
                Some(requested_state.keepalive_periods.direct)
            };
    }

    Ok(requested_peers)
}

/// Internal peers will never have IP collisions, but external peers can collide with both internal and external peers
/// In case of collision, exclude the colliding IPs from external peers
/// If a peer ends up not having any IPs after deduplicating, the peer will be unreachable
fn deduplicate_peer_ips(peers: &[telio_model::config::Peer]) -> HashMap<PublicKey, Vec<IpAddr>> {
    let mut peer_ips = HashMap::new();
    let mut occupied_ips = vec![];
    let mut external_peers = vec![];
    let mut process_ips_for_peer = |peer: &telio_model::config::Peer| {
        if let Some(ips) = &peer.ip_addresses {
            let ips = ips
                .iter()
                .filter_map(|ip| {
                    if occupied_ips.contains(ip) {
                        telio_log_warn!(
                            "IP collision for peer with public key {:?} and IP {:?}",
                            peer.public_key,
                            ip
                        );
                        None
                    } else {
                        occupied_ips.push(*ip);
                        Some(*ip)
                    }
                })
                .collect();
            peer_ips.insert(peer.public_key, ips);
        }
    };
    for peer in peers {
        if !peer.is_local {
            external_peers.push(peer);
        } else {
            process_ips_for_peer(peer);
        }
    }
    for peer in external_peers {
        process_ips_for_peer(peer);
    }
    peer_ips
}

// Select endpoint for peer
async fn select_endpoint_for_peer<'a>(
    public_key: &PublicKey,
    actual_peer: &Option<Peer>,
    time_since_last_rx: &Option<Duration>,
    peer_state: PeerState,
    checked_endpoint: &Option<WireGuardEndpointCandidateChangeEvent>,
    proxy_endpoint: &Option<SocketAddr>,
    upgrade_request_endpoint: &Option<SocketAddr>,
) -> Result<(Option<SocketAddr>, Option<(SocketAddr, Session)>)> {
    // Retrieve some helper information
    let actual_endpoint = actual_peer.clone().and_then(|p| p.endpoint);

    // Use match statement to cover all possible variants
    match (upgrade_request_endpoint, peer_state, checked_endpoint) {
        // If the other side has requested us to upgrade endpoint -> do that
        (Some(upgrade_request_endpoint), _, _) => {
            telio_log_debug!(
                "Upgrading peer's {:?} endpoint to {:?} due to request from the other side",
                public_key,
                upgrade_request_endpoint
            );
            if let Some(peer) = actual_peer {
                telio_log_debug!("Our actual endpoint is: {:?}", peer.endpoint);
            }

            if (peer_state == PeerState::Upgrading || peer_state == PeerState::Direct)
                && actual_endpoint.is_some()
                && actual_endpoint != *proxy_endpoint
            {
                telio_log_debug!("Keeping the current direct endpoint: {:?}", actual_endpoint);
                Ok((actual_endpoint, None))
            } else {
                telio_log_debug!(
                    "Changing endpoint to the one from update request: {:?}",
                    *upgrade_request_endpoint
                );
                Ok((Some(*upgrade_request_endpoint), None))
            }
        }

        // Connection is dead-> always force proxy. Note that we may enter this state in direct
        // mode and after changing to proxied connections -> recover the connection in proxying
        // mode.
        (None, PeerState::Disconnected, _) => {
            telio_log_debug!(
                "Connections seems to be dead, forcing proxied EP: {:?} {:?}",
                public_key,
                time_since_last_rx,
            );
            Ok((*proxy_endpoint, None))
        }

        // Just proxying, nothing to upgrade to...
        (None, PeerState::Proxying, None) => {
            telio_log_debug!(
                "Keeping proxied EP: {:?} {:?}",
                public_key,
                time_since_last_rx,
            );
            Ok((*proxy_endpoint, None))
        }

        // Proxying, but we have something to upgrade to. Lets try to upgrade.
        (None, PeerState::Proxying, Some(checked_endpoint)) => {
            telio_log_debug!(
                "Selecting checked EP: {:?} {:?}",
                public_key,
                time_since_last_rx,
            );
            Ok((
                Some(checked_endpoint.remote_endpoint),
                Some((checked_endpoint.local_endpoint, checked_endpoint.session)), // << This endpoint will be advertised to the other side
            ))
        }

        // Upgrading, means that we have some direct endpoint within WG. Keep it.
        (None, PeerState::Upgrading, _) => {
            telio_log_debug!(
                "Selecting current Direct EP: {:?} {:?}",
                public_key,
                time_since_last_rx,
            );
            Ok((actual_endpoint, None))
        }

        // Direct connection is alive -> just keep it.
        (None, PeerState::Direct, _) => {
            telio_log_debug!(
                "Selecting current Direct EP: {:?} {:?}",
                public_key,
                time_since_last_rx,
            );
            Ok((actual_endpoint, None))
        }
    }
}

// Convenience function to check whether peers are equal or not. Note that this function compares
// peers only in a sense what a controller would consider peers to be equal, therefore various
// status fields, like handshake timestamps, tx'ed or rx'ed data or similar is *not* compared. What
// is more, "None" peer will always compare _false_ to anything
fn compare_peers(a: &telio_wg::uapi::Peer, b: &telio_wg::uapi::Peer) -> bool {
    a.public_key == b.public_key
        && a.endpoint == b.endpoint
        && a.persistent_keepalive_interval == b.persistent_keepalive_interval
        && a.allowed_ips == b.allowed_ips
        && a.preshared_key == b.preshared_key
}

fn is_peer_proxying(
    peer: &telio_wg::uapi::Peer,
    proxy_endpoints: &HashMap<PublicKey, SocketAddr>,
) -> bool {
    // If proxy has no knowledge of the public key -> the node definitely does not proxy
    let proxy_endpoint = if let Some(proxy_endpoint) = proxy_endpoints.get(&peer.public_key) {
        proxy_endpoint
    } else {
        return false;
    };

    // Otherwise, we are only proxying if peer endpoint matches proxy endpoint
    peer.endpoint == Some(*proxy_endpoint)
}

fn peer_state(
    peer: Option<&telio_wg::uapi::Peer>,
    time_since_last_rx: Option<&Duration>,
    time_since_last_endpoint_change: Option<&Duration>,
    proxy_endpoint: Option<&SocketAddr>,
    requested_state: &RequestedState,
) -> PeerState {
    // Define some useful constants
    let keepalive_period = peer
        .and_then(|p| p.persistent_keepalive_interval)
        .unwrap_or(requested_state.keepalive_periods.direct);
    let peer_connectivity_timeout = Duration::from_secs((keepalive_period * 3) as u64);
    let peer_upgrade_window = Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW);

    // If peer is none -> disconnected
    let peer = match peer {
        Some(peer) => peer,
        None => return PeerState::Disconnected,
    };

    // At least one endpoint change is required for peer to be able to be connected
    let time_since_last_endpoint_change = match time_since_last_endpoint_change {
        Some(time_since_last_endpoint_change) => time_since_last_endpoint_change,
        None => return PeerState::Disconnected,
    };

    // At least one packet rx is required for peer to be able to be connected
    let time_since_last_rx = match time_since_last_rx {
        Some(time_since_last_rx) => time_since_last_rx,
        None => return PeerState::Disconnected,
    };

    let has_contact = time_since_last_rx < &peer_connectivity_timeout;
    let is_proxying = peer.endpoint.as_ref() == proxy_endpoint;
    let is_in_upgrade_window = time_since_last_endpoint_change < &peer_upgrade_window;

    match (has_contact, is_proxying, is_in_upgrade_window) {
        (false, _, _) => PeerState::Disconnected,
        (true, true, _) => PeerState::Proxying,
        (true, false, true) => PeerState::Upgrading,
        (true, false, false) => PeerState::Direct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceConfig, DNS};
    use mockall::predicate::{self, eq};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
    use telio_crypto::SecretKey;
    use telio_dns::MockDnsResolver;
    use telio_firewall::firewall::{MockFirewall, FILE_SEND_PORT};
    use telio_model::api_config::{
        FeatureDns, TtlValue, DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
        DEFAULT_PERSISTENT_KEEPALIVE_PERIOD,
    };
    use telio_model::config::{Config, PeerBase, Server};
    use telio_model::mesh::ExitNode;
    use telio_pq::MockPostQuantum;
    use telio_proto::Session;
    use telio_proxy::MockProxy;
    use telio_traversal::cross_ping_check::MockCrossPingCheckTrait;
    use telio_traversal::{MockSessionKeeperTrait, MockUpgradeSyncTrait, UpgradeRequest};
    use telio_wg::uapi::Interface;
    use telio_wg::MockWireGuard;
    use tokio::time::Instant;

    type AllowIncomingConnections = bool;
    type AllowPeerSendFiles = bool;
    type AllowedIps = Vec<IpAddr>;

    #[tokio::test]
    async fn update_wg_private_key_when_changed() {
        let mut wg_mock = MockWireGuard::new();
        let mut pq_mock = MockPostQuantum::new();
        let secret_key_a = SecretKey::gen();
        let secret_key_b = SecretKey::gen();

        wg_mock.expect_get_interface().returning(move || {
            Ok(Interface {
                private_key: Some(secret_key_a),
                ..Default::default()
            })
        });

        wg_mock
            .expect_set_secret_key()
            .with(predicate::eq(secret_key_b))
            .returning(|_| Ok(()));

        pq_mock.expect_keys().returning(|| None);

        let requested_state = RequestedState {
            device_config: DeviceConfig {
                private_key: secret_key_b,
                ..Default::default()
            },
            ..Default::default()
        };

        consolidate_wg_private_key(&requested_state, &wg_mock, &pq_mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn do_not_update_wg_private_key_when_not_changed() {
        let mut wg_mock = MockWireGuard::new();
        let mut pq_mock = MockPostQuantum::new();
        let secret_key_a = SecretKey::gen();
        let secret_key_a_cpy = secret_key_a.clone();

        wg_mock.expect_get_interface().returning(move || {
            Ok(Interface {
                private_key: Some(secret_key_a_cpy),
                ..Default::default()
            })
        });

        pq_mock.expect_keys().returning(|| None);
        pq_mock.expect_is_rotating_keys().returning(|| false);

        let requested_state = RequestedState {
            device_config: DeviceConfig {
                private_key: secret_key_a,
                ..Default::default()
            },
            ..Default::default()
        };

        consolidate_wg_private_key(&requested_state, &wg_mock, &pq_mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_fwmark_when_changed() {
        let mut wg_mock = MockWireGuard::new();

        let old = 15;
        let new = 16;

        wg_mock.expect_get_interface().returning(move || {
            Ok(Interface {
                fwmark: old,
                ..Default::default()
            })
        });

        wg_mock
            .expect_set_fwmark()
            .with(predicate::eq(new))
            .returning(|_| Ok(()));

        let requested_state = RequestedState {
            device_config: DeviceConfig {
                fwmark: Some(new),
                ..Default::default()
            },
            ..Default::default()
        };

        consolidate_wg_fwmark(&requested_state, &wg_mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn do_not_update_fwmark_when_not_changed() {
        let mut wg_mock = MockWireGuard::new();

        let old = 15;

        wg_mock.expect_get_interface().returning(move || {
            Ok(Interface {
                fwmark: old,
                ..Default::default()
            })
        });

        let requested_state = RequestedState {
            device_config: DeviceConfig {
                fwmark: Some(old),
                ..Default::default()
            },
            ..Default::default()
        };

        consolidate_wg_fwmark(&requested_state, &wg_mock)
            .await
            .unwrap();
    }

    fn create_requested_state(
        input: Vec<(
            PublicKey,
            AllowedIps,
            AllowIncomingConnections,
            AllowPeerSendFiles,
        )>,
    ) -> RequestedState {
        let mut requested_state = RequestedState::default();

        let mut meshnet_config = Config {
            peers: Some(vec![]),
            ..Default::default()
        };

        if let Some(peers) = meshnet_config.peers.as_mut() {
            for i in input {
                let peer = telio_model::config::Peer {
                    base: PeerBase {
                        public_key: i.0,
                        ip_addresses: Some(i.1),
                        ..Default::default()
                    },
                    allow_incoming_connections: i.2,
                    allow_peer_send_files: i.3,
                    ..Default::default()
                };
                peers.push(peer);
            }
        }

        requested_state.meshnet_config = Some(meshnet_config);

        requested_state
    }

    fn expect_add_to_peer_whitelist(firewall: &mut MockFirewall, pub_key: PublicKey) {
        firewall
            .expect_add_to_peer_whitelist()
            .with(eq(pub_key))
            .once()
            .return_const(());
    }

    fn expect_remove_from_peer_whitelist(firewall: &mut MockFirewall, pub_key: PublicKey) {
        firewall
            .expect_remove_from_peer_whitelist()
            .with(eq(pub_key))
            .once()
            .return_const(());
    }

    fn expect_add_to_port_whitelist(firewall: &mut MockFirewall, pub_key: PublicKey) {
        firewall
            .expect_add_to_port_whitelist()
            .with(eq(pub_key), eq(FILE_SEND_PORT))
            .once()
            .return_const(());
    }

    fn expect_remove_from_port_whitelist(firewall: &mut MockFirewall, pub_key: PublicKey) {
        firewall
            .expect_remove_from_port_whitelist()
            .with(eq(pub_key))
            .once()
            .return_const(());
    }

    fn expect_get_peer_whitelist(firewall: &mut MockFirewall, pub_keys: Vec<PublicKey>) {
        firewall
            .expect_get_peer_whitelist()
            .return_once(move || pub_keys.into_iter().collect());
    }

    fn expect_get_port_whitelist(firewall: &mut MockFirewall, pub_keys: Vec<PublicKey>) {
        firewall
            .expect_get_port_whitelist()
            .return_once(move || pub_keys.into_iter().map(|k| (k, FILE_SEND_PORT)).collect());
    }

    #[tokio::test]
    async fn add_newly_requested_peers_to_firewall() {
        let mut firewall = MockFirewall::new();

        let pub_key_1 = SecretKey::gen().public();
        let pub_key_2 = SecretKey::gen().public();
        let pub_key_3 = SecretKey::gen().public();
        let pub_key_4 = SecretKey::gen().public();

        let requested_state = create_requested_state(vec![
            (pub_key_1, vec![], true, true),
            (pub_key_2, vec![], true, false),
            (pub_key_3, vec![], false, true),
            (pub_key_4, vec![], false, false),
        ]);

        firewall
            .expect_get_peer_whitelist()
            .return_once(|| Default::default());

        firewall
            .expect_get_port_whitelist()
            .return_once(|| Default::default());

        expect_add_to_peer_whitelist(&mut firewall, pub_key_1);
        expect_add_to_port_whitelist(&mut firewall, pub_key_1);

        expect_add_to_peer_whitelist(&mut firewall, pub_key_2);

        expect_add_to_port_whitelist(&mut firewall, pub_key_3);

        consolidate_firewall(&requested_state, &firewall)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_permissions_for_requested_peers_in_firewall() {
        let mut firewall = MockFirewall::new();

        let pub_key_1 = SecretKey::gen().public();
        let pub_key_2 = SecretKey::gen().public();
        let pub_key_3 = SecretKey::gen().public();
        let pub_key_4 = SecretKey::gen().public();

        let requested_state = create_requested_state(vec![
            (pub_key_1, vec![], true, true),
            (pub_key_2, vec![], true, false),
            (pub_key_3, vec![], false, true),
            (pub_key_4, vec![], false, false),
        ]);

        expect_get_peer_whitelist(
            &mut firewall,
            vec![pub_key_1, pub_key_2, pub_key_3, pub_key_4],
        );

        expect_get_port_whitelist(
            &mut firewall,
            vec![pub_key_1, pub_key_2, pub_key_3, pub_key_4],
        );

        firewall
            .expect_get_port_whitelist()
            .return_once(|| Default::default());

        expect_remove_from_port_whitelist(&mut firewall, pub_key_2);

        expect_remove_from_peer_whitelist(&mut firewall, pub_key_3);

        expect_remove_from_peer_whitelist(&mut firewall, pub_key_4);
        expect_remove_from_port_whitelist(&mut firewall, pub_key_4);

        consolidate_firewall(&requested_state, &firewall)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn add_vpn_exit_node_to_firewall() {
        let mut firewall = MockFirewall::new();

        let pub_key_1 = SecretKey::gen().public();
        let pub_key_2 = SecretKey::gen().public();

        let mut requested_state = create_requested_state(vec![(pub_key_1, vec![], false, false)]);

        requested_state.exit_node = Some(ExitNode {
            public_key: pub_key_2,
            ..Default::default()
        });

        expect_get_peer_whitelist(&mut firewall, vec![pub_key_1]);
        expect_get_port_whitelist(&mut firewall, vec![]);

        expect_remove_from_peer_whitelist(&mut firewall, pub_key_1);

        expect_add_to_peer_whitelist(&mut firewall, pub_key_2);

        consolidate_firewall(&requested_state, &firewall)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn do_not_add_meshnet_exit_node_to_firewall_if_it_does_not_allow_incoming_connections() {
        let mut firewall = MockFirewall::new();

        let pub_key_1 = SecretKey::gen().public();

        let mut requested_state = create_requested_state(vec![(pub_key_1, vec![], false, false)]);

        requested_state.exit_node = Some(ExitNode {
            public_key: pub_key_1,
            ..Default::default()
        });

        expect_get_peer_whitelist(&mut firewall, vec![]);
        expect_get_port_whitelist(&mut firewall, vec![]);

        consolidate_firewall(&requested_state, &firewall)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn remove_meshnet_exit_node_from_firewall_if_it_does_not_allow_incoming_connections_anymore(
    ) {
        let mut firewall = MockFirewall::new();

        let pub_key_1 = SecretKey::gen().public();

        let mut requested_state = create_requested_state(vec![(pub_key_1, vec![], false, false)]);

        requested_state.exit_node = Some(ExitNode {
            public_key: pub_key_1,
            ..Default::default()
        });

        expect_get_peer_whitelist(&mut firewall, vec![pub_key_1]);
        expect_get_port_whitelist(&mut firewall, vec![]);

        expect_remove_from_peer_whitelist(&mut firewall, pub_key_1);

        consolidate_firewall(&requested_state, &firewall)
            .await
            .unwrap();
    }

    struct Fixture {
        requested_state: RequestedState,
        wireguard_interface: MockWireGuard,
        proxy: MockProxy,
        cross_ping_check: MockCrossPingCheckTrait,
        upgrade_sync: MockUpgradeSyncTrait,
        session_keeper: MockSessionKeeperTrait,
        dns: Mutex<DNS<MockDnsResolver>>,
        features: Features,
        post_quantum: MockPostQuantum,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                requested_state: RequestedState::default(),
                wireguard_interface: MockWireGuard::new(),
                proxy: MockProxy::new(),
                cross_ping_check: MockCrossPingCheckTrait::new(),
                upgrade_sync: MockUpgradeSyncTrait::new(),
                session_keeper: MockSessionKeeperTrait::new(),
                dns: Mutex::new(DNS {
                    resolver: Some(MockDnsResolver::new()),
                    virtual_host_tun_fd: None,
                }),
                // currently we care only about ipv6, so they might be empty
                features: Features {
                    wireguard: Default::default(),
                    nurse: None,
                    lana: None,
                    paths: None,
                    direct: None,
                    is_test_env: if cfg!(any(target_os = "macos", feature = "pretend_to_be_macos"))
                    {
                        Some(true)
                    } else {
                        None
                    },
                    derp: None,
                    validate_keys: Default::default(),
                    ipv6: true,
                    nicknames: false,
                    boringtun_reset_connections: Default::default(),
                    flush_events_on_stop_timeout_seconds: None,
                    post_quantum_vpn: Default::default(),
                    link_detection: None,
                    dns: FeatureDns {
                        exit_dns: None,
                        ttl_value: TtlValue(60),
                    },
                    pmtu_discovery: Default::default(),
                },
                post_quantum: MockPostQuantum::new(),
            }
        }

        fn when_requested_meshnet_config(&mut self, input: Vec<(PublicKey, AllowedIps)>) {
            let meshnet_config = Config {
                peers: Some(
                    input
                        .iter()
                        .map(|i| telio_model::config::Peer {
                            base: PeerBase {
                                public_key: i.0,
                                ip_addresses: Some(i.1.clone()),
                                ..Default::default()
                            },
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            };

            self.requested_state.meshnet_config = Some(meshnet_config);
        }

        fn when_proxy_mapping(&mut self, input: Vec<(PublicKey, u16)>) {
            let proxy_endpoint_map: EndpointMap = input
                .iter()
                .map(|i| {
                    (
                        i.0,
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, i.1)),
                    )
                })
                .collect();

            self.proxy
                .expect_get_endpoint_map()
                .returning(move || Ok(proxy_endpoint_map.clone()));
        }

        fn then_proxy_mute(&mut self, input: Vec<(PublicKey, Option<Duration>)>) {
            for i in input {
                self.proxy
                    .expect_mute_peer()
                    .once()
                    .with(eq(i.0), eq(i.1))
                    .return_once(|_, _| Ok(()));
            }
        }

        fn when_current_peers(&mut self, input: Vec<(PublicKey, SocketAddr, u32, AllowedIps)>) {
            let peers: BTreeMap<PublicKey, Peer> = input
                .into_iter()
                .map(|i| {
                    (
                        i.0,
                        Peer {
                            public_key: i.0,
                            endpoint: Some(i.1),
                            persistent_keepalive_interval: Some(i.2),
                            allowed_ips: i.3.into_iter().map(|ip| ip.into()).collect(),
                            ..Default::default()
                        },
                    )
                })
                .collect();

            self.wireguard_interface
                .expect_get_interface()
                .returning(move || {
                    Ok(Interface {
                        peers: peers.clone(),
                        ..Default::default()
                    })
                });
        }

        fn when_time_since_last_rx(&mut self, input: Vec<(PublicKey, u64)>) {
            self.wireguard_interface
                .expect_time_since_last_rx()
                .returning(move |pk| {
                    input
                        .iter()
                        .find(|i| i.0 == pk)
                        .map_or(Ok(None), |i| Ok(Some(Duration::from_secs(i.1))))
                });
        }

        fn when_time_since_last_endpoint_change(&mut self, input: Vec<(PublicKey, u64)>) {
            self.wireguard_interface
                .expect_time_since_last_endpoint_change()
                .returning(move |pk| {
                    input
                        .iter()
                        .find(|i| i.0 == pk)
                        .map_or(Ok(None), |i| Ok(Some(Duration::from_secs(i.1))))
                });
        }

        fn when_cross_check_validated_endpoints(
            &mut self,
            input: Vec<(PublicKey, SocketAddr, (SocketAddr, Session))>,
        ) {
            let map: HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent> = input
                .iter()
                .map(|i| {
                    (
                        i.0,
                        WireGuardEndpointCandidateChangeEvent {
                            public_key: i.0,
                            remote_endpoint: i.1,
                            local_endpoint: i.2 .0,
                            session: i.2 .1,
                        },
                    )
                })
                .collect();

            self.cross_ping_check
                .expect_get_validated_endpoints()
                .returning(move || Ok(map.clone()));
        }

        fn when_upgrade_requests(&mut self, input: Vec<(PublicKey, SocketAddr, Instant)>) {
            use rand::RngCore;
            let map: HashMap<PublicKey, UpgradeRequest> = input
                .iter()
                .map(|i| {
                    (
                        i.0,
                        UpgradeRequest {
                            endpoint: i.1,
                            requested_at: i.2,
                            session: rand::thread_rng().next_u64(),
                        },
                    )
                })
                .collect();

            self.upgrade_sync
                .expect_get_upgrade_requests()
                .returning(move || Ok(map.clone()));
        }

        fn then_add_peer(
            &mut self,
            input: Vec<(PublicKey, SocketAddr, u32, Vec<IpNetwork>, Vec<IpAddr>)>,
        ) {
            for i in input {
                self.wireguard_interface
                    .expect_add_peer()
                    .once()
                    .with(eq(Peer {
                        public_key: i.0,
                        endpoint: Some(i.1),
                        ip_addresses: i.4,
                        persistent_keepalive_interval: Some(i.2),
                        allowed_ips: i.3,
                        rx_bytes: None,
                        tx_bytes: None,
                        time_since_last_handshake: None,
                        preshared_key: None,
                    }))
                    .return_once(|_| Ok(()));
            }
        }

        fn then_del_peer(&mut self, input: Vec<PublicKey>) {
            for i in input {
                self.wireguard_interface
                    .expect_del_peer()
                    .once()
                    .with(eq(i))
                    .return_once(|_| Ok(()));
            }
        }

        fn then_notify_failed_wg_connection(&mut self, input: Vec<PublicKey>) {
            for i in input {
                self.cross_ping_check
                    .expect_notify_failed_wg_connection()
                    .once()
                    .with(eq(i))
                    .return_once(|_| Ok(()));
            }
        }

        fn then_request_upgrade(
            &mut self,
            input: Vec<(PublicKey, SocketAddr, (SocketAddr, Session))>,
        ) {
            for i in input {
                self.upgrade_sync
                    .expect_request_upgrade()
                    .once()
                    .with(eq(i.0), eq(i.1), eq(i.2))
                    .return_once(|_, _, _| Ok(()));
            }
        }

        fn then_keeper_add_node(&mut self, input: Vec<(PublicKey, IpAddr, Option<IpAddr>, u32)>) {
            for i in input {
                let ip4 = {
                    match i.1 {
                        IpAddr::V4(ip4) => ip4,
                        IpAddr::V6(_) => panic!("Only ip4 is allowed"),
                    }
                };

                let ip6 = {
                    match i.2 {
                        Some(ip) => match ip {
                            IpAddr::V4(_ip4) => panic!("Only ip6 is allowed"),
                            IpAddr::V6(ip6) => Some(ip6),
                        },
                        _ => None,
                    }
                };

                self.session_keeper
                    .expect_add_node()
                    .once()
                    .with(
                        eq(i.0),
                        eq((Some(ip4), ip6)),
                        eq(Duration::from_secs(i.3.into())),
                    )
                    .return_once(|_, _, _| Ok(()));
            }
        }

        fn then_keeper_remove_node(&mut self, input: Vec<PublicKey>) {
            for i in input {
                self.session_keeper
                    .expect_remove_node()
                    .once()
                    .with(eq(i))
                    .return_once(|_| Ok(()));
            }
        }

        fn then_notify_successfull_wg_connection_upgrade(&mut self, input: Vec<PublicKey>) {
            for i in input {
                self.cross_ping_check
                    .expect_notify_successfull_wg_connection_upgrade()
                    .once()
                    .with(eq(i))
                    .return_once(|_| Ok(()));
            }
        }

        fn then_post_quantum_is_checked(&mut self) {
            self.post_quantum.expect_keys().returning(|| None);
            self.post_quantum
                .expect_is_rotating_keys()
                .returning(|| false);
        }

        async fn consolidate_peers(self) {
            let cross_ping_check = Arc::new(self.cross_ping_check);
            let upgrade_sync = Arc::new(self.upgrade_sync);
            let session_keeper = Arc::new(self.session_keeper);

            consolidate_wg_peers(
                &self.requested_state,
                &self.wireguard_interface,
                Some(&self.proxy),
                Some(&cross_ping_check),
                Some(&upgrade_sync),
                Some(&session_keeper),
                &self.dns,
                HashMap::new(),
                None,
                None,
                &self.post_quantum,
                &self.features,
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn when_fresh_start_then_proxy_enpoint_is_added() {
        let mut f = Fixture::new();

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::from([1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        let ip2v6 = IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]);
        let allowed_ips = vec![ip1, ip1v6, ip2, ip2v6];
        let mapped_port = 18;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        let proxying_keepalive_time = 1234;
        f.requested_state.keepalive_periods.proxying = Some(proxying_keepalive_time);

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![]);
        f.when_time_since_last_rx(vec![]);
        f.when_time_since_last_endpoint_change(vec![]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            proxy_endpoint,
            proxying_keepalive_time,
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_upgrade_requested_by_peer_then_upgrade() {
        let mut f = Fixture::new();
        f.features.ipv6 = true;

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::V6(Ipv6Addr::from([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4,
        ]));
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        let ip2v6 = IpAddr::V6(Ipv6Addr::from([
            5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8,
        ]));
        let allowed_ips = vec![ip1, ip1v6, ip2, ip2v6];
        let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        let direct_keepalive_period = 1234;
        f.requested_state.keepalive_periods.direct = direct_keepalive_period;

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            DEFAULT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 5)]);
        f.when_time_since_last_endpoint_change(vec![(pub_key, 5)]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![(pub_key, remote_wg_endpoint, Instant::now())]);

        f.then_add_peer(vec![(
            pub_key,
            remote_wg_endpoint,
            direct_keepalive_period,
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);
        f.then_proxy_mute(vec![(
            pub_key,
            Some(Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW)),
        )]);
        f.then_keeper_add_node(vec![(pub_key, ip1, Some(ip1v6), direct_keepalive_period)]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_cross_check_vailidated_then_upgrade() {
        let mut f = Fixture::new();
        f.features.ipv6 = true;

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::V6(Ipv6Addr::from([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4,
        ]));
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        let ip2v6 = IpAddr::V6(Ipv6Addr::from([
            5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8,
        ]));
        let allowed_ips = vec![ip1, ip1v6, ip2, ip2v6];
        let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let local_wg_endpoint = (SocketAddr::from(([192, 168, 0, 2], 15)), rand::random());
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        let direct_keepalive_period = 1234;
        f.requested_state.keepalive_periods.direct = direct_keepalive_period;

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            DEFAULT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 5)]);
        f.when_time_since_last_endpoint_change(vec![(pub_key, 5)]);
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            local_wg_endpoint,
        )]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            remote_wg_endpoint,
            direct_keepalive_period,
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);
        f.then_request_upgrade(vec![(pub_key, remote_wg_endpoint, local_wg_endpoint)]);
        f.then_keeper_add_node(vec![(pub_key, ip1, Some(ip1v6), direct_keepalive_period)]);
        f.then_proxy_mute(vec![(
            pub_key,
            Some(Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW)),
        )]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_cross_check_vailidated_but_connection_dead_then_do_not_upgrade() {
        let mut f = Fixture::new();

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::from([1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        let ip2v6 = IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]);
        let allowed_ips = vec![ip1, ip1v6, ip2, ip2v6];
        let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let local_wg_endpoint = (SocketAddr::from(([192, 168, 0, 2], 15)), rand::random());
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        let proxying_keepalive_period = 1234;
        f.requested_state.keepalive_periods.proxying = Some(proxying_keepalive_period);

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![]);
        f.when_time_since_last_rx(vec![(pub_key, 100)]);
        f.when_time_since_last_endpoint_change(vec![(pub_key, 100)]);
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            local_wg_endpoint,
        )]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            proxy_endpoint,
            proxying_keepalive_period,
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_peers_removed_from_config_then_del_peer() {
        let mut f = Fixture::new();

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::from([1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        let ip2v6 = IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]);
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        f.when_requested_meshnet_config(vec![]);
        f.when_proxy_mapping(vec![]);
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            DEFAULT_PERSISTENT_KEEPALIVE_PERIOD,
            vec![ip1, ip1v6, ip2, ip2v6],
        )]);
        f.when_time_since_last_rx(vec![]);
        f.when_time_since_last_endpoint_change(vec![]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_del_peer(vec![pub_key]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_no_change_in_peers_then_no_update() {
        let mut f = Fixture::new();

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::from([1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        let ip2v6 = IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]);
        let allowed_ips = vec![ip1, ip1v6, ip2, ip2v6];
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            DEFAULT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips,
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 4)]);
        f.when_time_since_last_endpoint_change(vec![(pub_key, 4)]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        // then nothing happens

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_connection_timedout_then_downgrade() {
        let mut f = Fixture::new();

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]);
        let allowed_ips = vec![ip1, ip1v6];
        let mapped_port = 12;
        let wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        let proxying_keepalive_period = 1234;
        f.requested_state.keepalive_periods.proxying = Some(proxying_keepalive_period);

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            wg_endpoint,
            DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 100)]);
        f.when_time_since_last_endpoint_change(vec![(pub_key, 5)]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            proxy_endpoint,
            proxying_keepalive_period,
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);
        f.then_notify_failed_wg_connection(vec![pub_key]);
        f.then_keeper_remove_node(vec![pub_key]);
        f.then_proxy_mute(vec![(pub_key, None)]);
        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_direct_connection_becomes_stable() {
        let mut f = Fixture::new();

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]);
        let allowed_ips = vec![ip1, ip1v6];
        let mapped_port = 12;
        let wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            wg_endpoint,
            DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 5)]);
        f.when_time_since_last_endpoint_change(vec![(pub_key, DEFAULT_PEER_UPGRADE_WINDOW)]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_notify_successfull_wg_connection_upgrade(vec![pub_key]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_vpn_peer_is_added() {
        let mut f = Fixture::new();

        let public_key = SecretKey::gen().public();
        let allowed_ips = vec![
            IpNetwork::new(IpAddr::from([7, 6, 5, 4]), 23).unwrap(),
            IpNetwork::new(
                IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]),
                128,
            )
            .unwrap(),
        ];
        let ip_addresses = vec![
            IpAddr::V4(Ipv4Addr::from(VPN_INTERNAL_IPV4)),
            IpAddr::V6(Ipv6Addr::from(VPN_INTERNAL_IPV6)),
            IpAddr::V4(Ipv4Addr::from(VPN_EXTERNAL_IPV4)),
        ];

        let endpoint_raw = SocketAddr::from(([192, 168, 0, 1], 13));
        let endpoint = Some(endpoint_raw);

        let vpn_persistent_keepalive = 4321;
        f.requested_state.keepalive_periods.vpn = Some(vpn_persistent_keepalive);
        f.requested_state.exit_node = Some(ExitNode {
            identifier: "".to_owned(),
            public_key,
            allowed_ips: Some(allowed_ips.clone()),
            endpoint,
        });
        f.features.ipv6 = true;

        f.when_requested_meshnet_config(vec![]);
        f.when_proxy_mapping(vec![]);
        f.when_current_peers(vec![]);
        f.when_time_since_last_rx(vec![]);
        f.when_time_since_last_endpoint_change(vec![]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            public_key,
            endpoint_raw,
            vpn_persistent_keepalive,
            allowed_ips,
            ip_addresses,
        )]);
        f.then_post_quantum_is_checked();

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_stun_peer_is_added() {
        let mut f = Fixture::new();

        let public_key = SecretKey::gen().public();

        let allowed_ips = vec![
            IpNetwork::new(IpAddr::from([100, 64, 0, 4]), 32).unwrap(),
            IpNetwork::new(
                IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 4)),
                128,
            )
            .unwrap(),
        ];
        let ip_addresses = allowed_ips.iter().copied().map(|ip| ip.network()).collect();

        let stun_port = 1234;
        let endpoint_ip = Ipv4Addr::from([100, 10, 0, 17]);
        let endpoint_raw = SocketAddr::from((endpoint_ip, stun_port));

        let stun_persistent_keepalive = 4321;
        f.requested_state.keepalive_periods.stun = Some(stun_persistent_keepalive);
        f.requested_state.wg_stun_server = Some(Server {
            ipv4: endpoint_ip,
            stun_port,
            public_key,
            ..Default::default()
        });

        f.when_requested_meshnet_config(vec![]);
        f.when_proxy_mapping(vec![]);
        f.when_current_peers(vec![]);
        f.when_time_since_last_rx(vec![]);
        f.when_time_since_last_endpoint_change(vec![]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            public_key,
            endpoint_raw,
            stun_persistent_keepalive,
            allowed_ips,
            ip_addresses,
        )]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_connection_timeout_changed_during_upgrade() {
        let mut f = Fixture::new();
        f.features.ipv6 = true;

        let pub_key = SecretKey::gen().public();
        let ip1 = IpAddr::from([1, 2, 3, 4]);
        let ip1v6 = IpAddr::V6(Ipv6Addr::from([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4,
        ]));
        let ip2 = IpAddr::from([5, 6, 7, 8]);
        let ip2v6 = IpAddr::V6(Ipv6Addr::from([
            5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8,
        ]));
        let allowed_ips = vec![ip1, ip1v6, ip2, ip2v6];
        let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let local_wg_endpoint = (SocketAddr::from(([192, 168, 0, 2], 15)), rand::random());
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 20)]);
        f.when_time_since_last_endpoint_change(vec![(pub_key, 100)]);
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            local_wg_endpoint,
        )]);
        f.when_upgrade_requests(vec![(pub_key, remote_wg_endpoint, Instant::now())]);

        f.then_add_peer(vec![(
            pub_key,
            remote_wg_endpoint,
            DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);
        f.then_proxy_mute(vec![(
            pub_key,
            Some(Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW)),
        )]);
        f.then_keeper_add_node(vec![(
            pub_key,
            ip1,
            Some(ip1v6),
            DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
        )]);

        f.consolidate_peers().await;
    }

    #[test]
    fn test_ip_deduplication() {
        fn make_peer(
            public_key: PublicKey,
            ip_addresses: Vec<IpAddr>,
            is_local: bool,
        ) -> telio_model::config::Peer {
            let base = PeerBase {
                public_key,
                ip_addresses: Some(ip_addresses),
                ..Default::default()
            };
            telio_model::config::Peer {
                base,
                is_local,
                ..Default::default()
            }
        }

        let peer1_key = SecretKey::gen().public();
        let peer1_ips = vec!["1.2.3.4".parse().unwrap(), "fd00::4".parse().unwrap()];

        let peer2_key = SecretKey::gen().public();
        let peer2_ips = vec!["5.6.7.8".parse().unwrap(), "fc12::8".parse().unwrap()];

        let peer3_key = SecretKey::gen().public();
        let peer3_ips = vec![
            "1.2.3.4".parse().unwrap(),
            "9.10.11.12".parse().unwrap(),
            "fc12::8".parse().unwrap(),
            "fd12::dead".parse().unwrap(),
        ];
        let peer3_expected_ips: Vec<IpAddr> =
            vec!["9.10.11.12".parse().unwrap(), "fd12::dead".parse().unwrap()];

        let peer4_key = SecretKey::gen().public();
        let peer4_ips = vec![
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            "fd00::4".parse().unwrap(),
            "fc12::8".parse().unwrap(),
        ];

        let peers = vec![
            make_peer(peer1_key, peer1_ips.clone(), true),
            make_peer(peer2_key, peer2_ips.clone(), true),
            make_peer(peer3_key, peer3_ips.clone(), false),
            make_peer(peer4_key, peer4_ips.clone(), false),
        ];

        let deduplicated_ips = deduplicate_peer_ips(&peers);

        assert_eq!(deduplicated_ips[&peer1_key], peer1_ips);
        assert_eq!(deduplicated_ips[&peer2_key], peer2_ips);
        assert_eq!(deduplicated_ips[&peer3_key], peer3_expected_ips);
        assert!(deduplicated_ips[&peer4_key].is_empty());
    }
}
