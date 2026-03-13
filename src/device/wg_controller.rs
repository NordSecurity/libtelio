use super::{Entities, RequestedState, Result};
use futures::FutureExt;
use ipnet::IpNet;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use telio_crypto::PublicKey;
use telio_dns::DnsResolver;
#[cfg(feature = "enable_firewall")]
use telio_firewall::firewall::{Firewall, FirewallState, Permissions, FILE_SEND_PORT};
use telio_model::constants::{VPN_EXTERNAL_IPV4, VPN_INTERNAL_IPV4, VPN_INTERNAL_IPV6};
use telio_model::features::Features;
use telio_model::mesh::{LinkState, NodeState};
use telio_model::EndpointMap;
use telio_model::SocketAddr;
use telio_nurse::aggregator::ConnectivityDataAggregator;
use telio_proto::{PeersStatesMap, Session};
use telio_proxy::Proxy;
use telio_starcast::starcast_peer::StarcastPeer;
use telio_traversal::{
    cross_ping_check::CrossPingCheckTrait, endpoint_providers::EndpointProvider,
    SessionKeeperTrait, UpgradeSyncTrait, WireGuardEndpointCandidateChangeEvent,
};
use telio_utils::{build_ping_endpoint, telio_log_debug, telio_log_info, telio_log_warn, Instant};
use telio_wg::uapi::{AnalyticsEvent, UpdateReason};
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
    #[error("Meshnet IP address not set")]
    IpNotSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerState {
    Disconnected,
    Proxying,
    Upgrading,
    Direct,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct EndpointState {
    local_address: SocketAddr,
    session: Session,
    local_type: telio_model::features::EndpointProvider,
    remote_type: telio_model::features::EndpointProvider,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct RequestedPeer {
    peer: Peer,
    endpoint: Option<EndpointState>,
}

pub async fn consolidate_wg_state(
    requested_state: &RequestedState,
    entities: &Entities,
    features: &Features,
) -> Result {
    // This tells the PQ entity to restart itself if it deems it necessary.
    // That decision is based on an internal timestamp since last time it
    // performed a handshake (internal timestamp to account for different wg
    // implementations reporting time since last handshake differently) to
    // determine if the last handshake was done more than 180s ago (the time
    // after which wireguard abandons an inactive connection)
    entities.postquantum_wg.maybe_restart().await;

    let remote_peer_states = if let Some(meshnet_entities) = entities.meshnet.left() {
        meshnet_entities.derp.get_remote_peer_states().await
    } else {
        Default::default()
    };

    consolidate_wg_private_key(
        requested_state,
        &*entities.wireguard_interface,
        &entities.postquantum_wg,
        &entities.dns,
    )
    .await?;
    consolidate_wg_fwmark(requested_state, &*entities.wireguard_interface).await?;
    consolidate_endpoint_invalidation(
        &*entities.wireguard_interface,
        entities.meshnet.left().map(|m| &*m.proxy),
        entities.cross_ping_check(),
    )
    .await?;
    consolidate_wg_peers(
        requested_state,
        &*entities.wireguard_interface,
        entities.meshnet.left().map(|m| &*m.proxy),
        entities.cross_ping_check(),
        entities.upgrade_sync(),
        &entities.aggregator,
        entities.session_keeper(),
        &*entities.dns,
        remote_peer_states,
        entities.meshnet.left().and_then(|m| {
            m.direct
                .as_ref()
                .and_then(|direct| direct.stun_endpoint_provider.as_ref())
        }),
        entities.meshnet.left().and_then(|m| {
            m.direct
                .as_ref()
                .and_then(|direct| direct.upnp_endpoint_provider.as_ref())
        }),
        &entities.postquantum_wg,
        entities.starcast_vpeer(),
        features,
    )
    .boxed()
    .await?;
    consolidate_endpoint_invalidation(
        &*entities.wireguard_interface,
        entities.meshnet.left().map(|m| &*m.proxy),
        entities.cross_ping_check(),
    )
    .await?;
    consolidate_wg_listen_port(
        &*entities.wireguard_interface,
        entities.meshnet.left().map(|m| &*m.proxy),
        entities.starcast_vpeer(),
    )
    .await?;

    #[cfg(feature = "enable_firewall")]
    let starcast_pub_key = if let Some(starcast_vpeer) = entities.starcast_vpeer() {
        Some(starcast_vpeer.get_peer().await?.public_key)
    } else {
        None
    };

    #[cfg(feature = "enable_firewall")]
    let dns_pubkey = entities
        .dns
        .as_ref()
        .lock()
        .await
        .resolver
        .as_ref()
        .map(|resolver| resolver.public_key());

    #[cfg(feature = "enable_firewall")]
    if let Some(firewall) = entities.firewall.as_ref() {
        consolidate_firewall(
            requested_state,
            (*firewall).as_ref(),
            starcast_pub_key,
            dns_pubkey,
        )
        .await?;
    }

    Ok(())
}

async fn consolidate_wg_private_key<W: WireGuard>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
    post_quantum_vpn: &impl telio_pq::PostQuantum,
    dns: &Mutex<crate::device::DNS<impl DnsResolver>>,
) -> Result {
    let private_key = if let Some(pq) = post_quantum_vpn.keys() {
        pq.wg_secret
    } else {
        requested_state.device_config.private_key.clone()
    };

    let actual_private_key = wireguard_interface.get_interface().await?.private_key;

    if actual_private_key != Some(private_key.clone()) {
        wireguard_interface
            .set_secret_key(private_key.clone())
            .await?;
        let dns = dns.lock().await;

        if let Some(resolver) = dns.resolver.as_ref() {
            resolver.set_peer_public_key(private_key.public()).await;
        }
    }

    Ok(())
}

async fn consolidate_wg_listen_port<W: WireGuard, P: Proxy>(
    wireguard_interface: &W,
    proxy: Option<&P>,
    starcast_vpeer: Option<&Arc<StarcastPeer>>,
) -> Result {
    // WireGuard listen port may change during runtime, for example when using WireGuard-NT, it's
    // up/down state is controlled according to the needs. This means that every time we go into
    // down->up transition, listen-port may change. Therefore this consolidation has been added to
    // keep it in sync all the time.

    if let (None, None) = (proxy, starcast_vpeer) {
        return Ok(());
    }

    let wg_port = wireguard_interface.get_interface().await?.listen_port;

    // notify about the port to required modules
    if let Some(proxy) = proxy {
        let wg_addr = wg_port.map(|p| (Ipv4Addr::LOCALHOST, p).into());
        proxy.set_wg_address(wg_addr).await?;
    }
    if let Some(starcast_vpeer) = starcast_vpeer {
        let wg_addr = wg_port.map(|p| (Ipv4Addr::LOCALHOST, p).into());
        starcast_vpeer.set_wg_address(wg_addr).await?;
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

async fn consolidate_endpoint_invalidation<W: WireGuard, P: Proxy, C: CrossPingCheckTrait>(
    wireguard_interface: &W,
    proxy: Option<&P>,
    cross_ping_check: Option<&Arc<C>>,
) -> Result {
    // For each peer, we have to notify CPC and Endpoint Providers if
    // some endpoint failed.
    //    Endpoint failure is considered to be one of two things:
    //    * Endpoint has been downgraded for any reason
    //    * Remote node has roamed to different endpoint
    //
    //    Endpoint is *not* considered failed if endpoint has changed in
    //    WireGuard by writing to it.
    //
    // Note:  Invalidation must be done before WireGuard peer consolidation,
    //        as we must *not* consider endpoints-to-be-invalidated as eligible
    //        for upgrade
    // Note2: But, on the other hand, if WireGuard Peers consolidation makes
    //        a decision to downgrade its connection - running this endpoint
    //        invalidation just before WG peer consolidation would delay endpoint
    //        invalidation until the next consolidation cycle. This is undesirable,
    //        therefore endpoint invalidation checks should be run before *and*
    //        after WireGuard peer consolidation.

    // Retreive some helper values
    let (proxy_endpoints, cpc, checked_endpoints) = match (proxy, cross_ping_check) {
        (Some(proxy), Some(cpc)) => (
            proxy.get_endpoint_map().await?,
            cpc,
            cpc.get_validated_endpoints().await?,
        ),
        _ => {
            return Ok(()); // Meshnet is disabled
        }
    };
    let actual_peers = wireguard_interface.get_interface().await?.peers;

    // Each peer endpoint invalidation is processed individually
    for (public_key, actual_peer) in actual_peers {
        let is_proxying = is_peer_proxying(&actual_peer, &proxy_endpoints);
        let actual_endpoint = actual_peer.endpoint;
        let changed_at = actual_peer.endpoint_changed_at;
        let published_endpoint = checked_endpoints.get(&public_key);
        let published_at = published_endpoint.map(|endpoint| endpoint.changed_at);
        let mut should_invalidate_endpoints = false;

        // At debug level -> log every endpoint invalidation consideration. For info - only once a
        // decision to invalidate has been taken
        telio_log_debug!(
            "Considering endpoint invalidation.\
                         Decision info: {is_proxying:?} \
                         {actual_endpoint:?} {changed_at:?} \
                         {published_endpoint:?} {published_at:?}"
        );

        // If endpoint has never changed in wireguard or we have no published endpoints - there is
        // nothing to invalidate.
        let (changed_at, published_at) = match (changed_at, published_at) {
            (Some(changed_at), Some(published_at)) => (changed_at, published_at),
            _ => continue,
        };

        // Any endpoint published before an actual downgrade has occured is considered failed
        if is_proxying && (published_at < changed_at.0) {
            let change_reason = changed_at.1;
            telio_log_info!(
                "Invalidating published EPs for {public_key:?} after downgrade.\
                            Decision info: {actual_endpoint:?} {changed_at:?} {change_reason:?}\
                            {published_endpoint:?} {published_at:?}"
            );
            should_invalidate_endpoints = true;
        }

        // In direct connection if we have roamed from one direct EP to another - old checked EP is
        // considered not valid anymore.
        // Note, that endpoint change caused by libtelio writing new endpoint into WireGuard interface
        // is *not* considered roaming.
        if !is_proxying && changed_at.1 == UpdateReason::Pull && (published_at < changed_at.0) {
            telio_log_info!(
                "Invalidating published EPs for {public_key:?} after roaming.\
                            Decision info: {actual_endpoint:?} {changed_at:?} \
                            {published_endpoint:?} {published_at:?}"
            );
            should_invalidate_endpoints = true;
        }

        if should_invalidate_endpoints {
            if let Err(err) = cpc.notify_failed_wg_connection(public_key).await {
                telio_log_warn!(
                    "Failed to send connection failed report for {public_key}: {err:?}"
                );
            }
        }
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
    E1: EndpointProvider,
    E2: EndpointProvider,
>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
    proxy: Option<&P>,
    cross_ping_check: Option<&Arc<C>>,
    upgrade_sync: Option<&Arc<U>>,
    aggregator: &ConnectivityDataAggregator,
    session_keeper: Option<&Arc<S>>,
    dns: &Mutex<crate::device::DNS<D>>,
    remote_peer_states: PeersStatesMap,
    stun_ep_provider: Option<&Arc<E1>>,
    upnp_ep_provider: Option<&Arc<E2>>,
    post_quantum_vpn: &impl telio_pq::PostQuantum,
    starcast_vpeer: Option<&Arc<StarcastPeer>>,
    features: &Features,
) -> Result {
    let proxy_endpoints = if let Some(p) = proxy {
        p.get_endpoint_map().await?
    } else {
        Default::default()
    };

    let actual_peers = wireguard_interface.get_interface().await?.peers;
    let mut is_any_peer_eligible_for_upgrade = false;

    for (_, peer) in actual_peers.iter() {
        if is_peer_proxying(peer, &proxy_endpoints) && peer.state() == NodeState::Connected {
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

    let requested_peers = build_requested_peers_list(
        requested_state,
        wireguard_interface,
        cross_ping_check,
        upgrade_sync,
        dns,
        &proxy_endpoints,
        starcast_vpeer,
        &remote_peer_states,
        post_quantum_vpn,
        features,
        stun_ep_provider,
    )
    .await?;

    check_allowed_ips_correctness(&requested_peers)?;

    // Calculate diff between requested and actual list of peers
    let requested_keys: HashSet<&PublicKey> = requested_peers.keys().collect();
    let actual_keys: HashSet<&PublicKey> = actual_peers.keys().collect();
    let delete_keys = &actual_keys - &requested_keys;
    let insert_keys = &requested_keys - &actual_keys;
    let update_keys = &requested_keys & &actual_keys;

    for key in delete_keys {
        let actual_peer = actual_peers.get(key).ok_or(Error::PeerNotFound)?;
        telio_log_info!("Removing peer: {:?}", actual_peer);

        let event = AnalyticsEvent {
            public_key: *key,
            dual_ip_addresses: actual_peer.get_dual_ip_addresses(),
            tx_bytes: actual_peer.tx_bytes.unwrap_or_default(),
            rx_bytes: actual_peer.rx_bytes.unwrap_or_default(),
            peer_state: NodeState::Disconnected,
            timestamp: Instant::now(),
        };
        aggregator.report_peer_state_relayed(&event).await;

        wireguard_interface.del_peer(*key).await?;

        // Remove from session_keeper
        if let Some(sk) = session_keeper {
            sk.remove_node(key).await?;
        }
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
        let is_requested_peer_proxying = is_peer_proxying(&requested_peer.peer, &proxy_endpoints);

        if let Some(sk) = session_keeper {
            if !is_actual_peer_proxying && is_requested_peer_proxying {
                sk.remove_node(key).await?;
            }
        }

        let event = AnalyticsEvent {
            public_key: *key,
            dual_ip_addresses: actual_peer.get_dual_ip_addresses(),
            tx_bytes: actual_peer.tx_bytes.unwrap_or_default(),
            rx_bytes: actual_peer.rx_bytes.unwrap_or_default(),
            peer_state: actual_peer.state(),
            timestamp: Instant::now(),
        };

        if is_actual_peer_proxying {
            aggregator.report_peer_state_relayed(&event).await;
        } else if let Some(us) = upgrade_sync {
            if let Some(accepted_direct_session) = us.get_accepted_session(*key).await {
                aggregator
                    .report_peer_state_direct(
                        &event,
                        accepted_direct_session.local_ep,
                        accepted_direct_session.remote_ep,
                    )
                    .await;
            }
        }

        if is_actual_peer_proxying && !is_requested_peer_proxying {
            // We have upgraded the connection. If the upgrade happened because we have
            // selected a new direct endpoint candidate -> notify the other node about our own
            // local side endpoint, such that the other node can do this upgrade too.
            let public_key = requested_peer.peer.public_key;

            if let (Some(remote_endpoint), Some(endpoint)) =
                (requested_peer.peer.endpoint, requested_peer.endpoint)
            {
                if let Some(us) = upgrade_sync {
                    us.request_upgrade(
                        &public_key,
                        (remote_endpoint, endpoint.remote_type),
                        (endpoint.local_address, endpoint.local_type),
                        endpoint.session,
                    )
                    .await?;
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

            if let Some(sk) = session_keeper {
                let target = build_ping_endpoint(&requested_peer.peer.ip_addresses, features.ipv6);
                if target.0.is_some() || target.1.is_some() {
                    sk.add_node(
                        requested_peer.peer.public_key,
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
                } else {
                    telio_log_warn!("Peer {:?} has no ip address", key);
                }
            }
        }

        telio_log_debug!(
            "peer {:?} proxying: {:?}, state: {:?}, last handshake: {:?}",
            actual_peer.public_key,
            is_actual_peer_proxying,
            actual_peer.state(),
            actual_peer.time_since_last_handshake
        );
    }

    Ok(())
}

fn check_allowed_ips_correctness(peers: &BTreeMap<PublicKey, RequestedPeer>) -> Result {
    peers
        .values()
        .map(|p| HashSet::from_iter(&p.peer.allowed_ips))
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

#[cfg(feature = "enable_firewall")]
fn iter_peers(
    requested_state: &RequestedState,
) -> impl Iterator<Item = &telio_model::config::Peer> {
    requested_state
        .meshnet_config
        .iter()
        .flat_map(|c| c.peers.iter())
        .flatten()
}

#[cfg(feature = "enable_firewall")]
async fn consolidate_firewall<F: Firewall>(
    requested_state: &RequestedState,
    firewall: &F,
    starcast_vpeer_pubkey: Option<PublicKey>,
    dns_pubkey: Option<PublicKey>,
) -> Result {
    let mut state = FirewallState::default();

    state.whitelist.port_whitelist = iter_peers(requested_state)
        .filter(|p| p.allow_peer_send_files)
        .map(|p| (p.public_key, FILE_SEND_PORT))
        .collect();

    for permission in Permissions::VALUES {
        state.whitelist.peer_whitelists[permission] = iter_peers(requested_state)
            .filter(|p| match permission {
                Permissions::IncomingConnections => p.allow_incoming_connections,
                Permissions::LocalAreaConnections => p.allow_peer_local_network_access,
                Permissions::RoutingConnections => p.allow_peer_traffic_routing,
            })
            .map(|p| p.public_key)
            .collect();
    }

    if let Some(key) = starcast_vpeer_pubkey {
        state.whitelist.peer_whitelists[Permissions::RoutingConnections].insert(key);
        state.whitelist.peer_whitelists[Permissions::IncomingConnections].insert(key);
    }

    if let Some(key) = dns_pubkey {
        state.whitelist.peer_whitelists[Permissions::RoutingConnections].insert(key);
    }

    if let Some(exit_node) = &requested_state.exit_node {
        let is_vpn_exit_node =
            !iter_peers(requested_state).any(|p| p.public_key == exit_node.public_key);

        if is_vpn_exit_node {
            state.whitelist.vpn_peer = Some(exit_node.public_key);
        }
    }

    if let Some(meshnet_config) = &requested_state.meshnet_config {
        state.ip_addresses = meshnet_config
            .this
            .ip_addresses
            .clone()
            .ok_or(Error::IpNotSet)?;
    }

    firewall.apply_state(state);

    Ok(())
}

// Builds a full list of WG peers according to current requested state (config) and entities state
#[allow(clippy::too_many_arguments)]
async fn build_requested_peers_list<
    W: WireGuard,
    C: CrossPingCheckTrait,
    U: UpgradeSyncTrait,
    D: DnsResolver,
    E: EndpointProvider,
>(
    requested_state: &RequestedState,
    wireguard_interface: &W,
    cross_ping_check: Option<&Arc<C>>,
    upgrade_sync: Option<&Arc<U>>,
    dns: &Mutex<crate::device::DNS<D>>,
    proxy_endpoints: &EndpointMap,
    starcast_vpeer: Option<&Arc<StarcastPeer>>,
    remote_peer_states: &PeersStatesMap,
    post_quantum_vpn: &impl telio_pq::PostQuantum,
    features: &Features,
    stun_ep_provider: Option<&Arc<E>>,
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
        let allowed_ips: Vec<IpNet> = exit_node
            .allowed_ips
            .clone()
            .unwrap_or(vec![
                IpNet::V4("0.0.0.0/0".parse()?),
                IpNet::V6("::/0".parse()?),
            ])
            .into_iter()
            .filter(|network| features.ipv6 || network.addr().is_ipv4())
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

            let mut ip_addresses = vec![VPN_INTERNAL_IPV4.into()];
            if features.ipv6 {
                ip_addresses.push(VPN_INTERNAL_IPV6.into());
            }
            ip_addresses.push(VPN_EXTERNAL_IPV4.into());

            // If the PQ VPN is set up we need to configure the preshared key
            match (post_quantum_vpn.is_rotating_keys(), post_quantum_vpn.keys()) {
                (true, None) => {
                    // The post quantum state is not ready, we don't want to set up quantum
                    // unsafe tunnel with this peer
                    telio_log_debug!("PQ not ready to insert exit node peer");
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
                                persistent_keepalive_interval: requested_state
                                    .keepalive_periods
                                    .vpn,
                                allowed_ips,
                                preshared_key,
                                ..Default::default()
                            },
                            endpoint: None,
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
        let mut dns_peer = resolver.get_peer(dns_allowed_ips);
        dns_peer.ip_addresses = dns_peer
            .allowed_ips
            .iter()
            .copied()
            .map(|ip| ip.addr())
            .collect();
        let dns_peer_public_key = dns_peer.public_key;
        let requested_peer = RequestedPeer {
            peer: dns_peer,
            endpoint: None,
        };
        requested_peers.insert(dns_peer_public_key, requested_peer);
    }

    if let Some(starcast_vpeer) = starcast_vpeer {
        let starcast_peer = starcast_vpeer.get_peer().await?;
        let starcast_peer_public_key = starcast_peer.public_key;
        let requested_starcast_peer = RequestedPeer {
            peer: starcast_peer,
            endpoint: None,
        };
        requested_peers.insert(starcast_peer_public_key, requested_starcast_peer);
    }

    if let (Some(wg_stun_server), Some(stun)) = (&requested_state.wg_stun_server, stun_ep_provider)
    {
        if !stun.is_paused().await {
            let public_key = wg_stun_server.public_key;
            let endpoint =
                SocketAddr::new(IpAddr::V4(wg_stun_server.ipv4), wg_stun_server.stun_port);
            telio_log_debug!("Configuring wg-stun peer: {}, at {}", public_key, endpoint);

            let allowed_ips = if features.ipv6 {
                vec![
                    IpNet::V4("100.64.0.4/32".parse()?),
                    IpNet::V6("fd74:656c:696f::4/128".parse()?),
                ]
            } else {
                vec![IpNet::V4("100.64.0.4/32".parse()?)]
            };
            let ip_addresses = allowed_ips.iter().copied().map(|ip| ip.addr()).collect();
            requested_peers.insert(
                public_key,
                RequestedPeer {
                    peer: telio_wg::uapi::Peer {
                        public_key,
                        endpoint: Some(endpoint),
                        ip_addresses,
                        persistent_keepalive_interval: requested_state.keepalive_periods.stun,
                        allowed_ips,
                        ..Default::default()
                    },
                    endpoint: None,
                },
            );
        } else {
            telio_log_debug!("Stun ep is paused, not adding wg-stun peer");
        }
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
            let endpoint = proxy_endpoints
                .get(&public_key)
                .and_then(|eps| eps.first())
                .cloned();

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
                            IpAddr::V4(_) => IpNet::new(*ip, 32).ok(),
                            IpAddr::V6(_) if features.ipv6 => IpNet::new(*ip, 128).ok(),
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
                        persistent_keepalive_interval: requested_state.keepalive_periods.proxying,
                        allowed_ips,
                        ..Default::default()
                    },
                    endpoint: None,
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
        let time_since_last_endpoint_change = actual_peer
            .and_then(|p| p.endpoint_changed_at)
            .map(|(t, _)| t.elapsed());
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

        let link_state = wireguard_interface.get_link_state(*public_key).await?;

        // Compute the current endpoint state
        let peer_state = peer_state(
            actual_peer,
            time_since_last_rx_or_handshake.as_ref(),
            time_since_last_endpoint_change.as_ref(),
            link_state,
            match proxy_endpoint {
                Some(eps) => eps,
                None => &[],
            },
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
            match proxy_endpoint {
                Some(eps) => eps,
                None => &[],
            },
            &upgrade_request_endpoint,
        )
        .await?;

        // Apply the selected endpoints, and save local endpoint because we may need to share it
        // with the other end
        requested_peer.peer.endpoint = selected_remote_endpoint;
        requested_peer.endpoint = selected_local_endpoint;

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
#[allow(clippy::too_many_arguments)]
async fn select_endpoint_for_peer(
    public_key: &PublicKey,
    actual_peer: &Option<Peer>,
    time_since_last_rx: &Option<Duration>,
    peer_state: PeerState,
    checked_endpoint: &Option<WireGuardEndpointCandidateChangeEvent>,
    proxy_endpoint: &[SocketAddr],
    upgrade_request_endpoint: &Option<SocketAddr>,
) -> Result<(Option<SocketAddr>, Option<EndpointState>)> {
    // Retrieve some helper information
    let actual_endpoint = actual_peer.as_ref().and_then(|p| p.endpoint);

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

            #[allow(clippy::expect_used)]
            if (peer_state == PeerState::Upgrading || peer_state == PeerState::Direct)
                && actual_endpoint.is_some()
                && !proxy_endpoint.contains(
                    &actual_endpoint.expect("Previous check mandates there be an endpoint here"),
                )
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
            Ok((proxy_endpoint.first().copied(), None))
        }

        // Just proxying, nothing to upgrade to...
        (None, PeerState::Proxying, None) => {
            telio_log_debug!(
                "Keeping proxied EP: {:?} {:?}",
                public_key,
                time_since_last_rx,
            );
            Ok((proxy_endpoint.first().copied(), None))
        }

        // Proxying, but we have something to upgrade to. Lets try to upgrade.
        (None, PeerState::Proxying, Some(checked_endpoint)) => {
            telio_log_debug!(
                "Selecting checked EP: {:?} {:?}",
                public_key,
                time_since_last_rx,
            );
            Ok((
                Some(checked_endpoint.remote_endpoint.0),
                Some(EndpointState {
                    local_address: checked_endpoint.local_endpoint.0,
                    session: checked_endpoint.session,
                    local_type: checked_endpoint.local_endpoint.1,
                    remote_type: checked_endpoint.remote_endpoint.1,
                }), // << This endpoint will be advertised to the other side
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

fn is_peer_proxying(peer: &telio_wg::uapi::Peer, proxy_endpoints: &EndpointMap) -> bool {
    // If proxy has no knowledge of the public key -> the node definitely does not proxy
    let proxy_endpoints = if let Some(proxy_endpoints) = proxy_endpoints.get(&peer.public_key) {
        proxy_endpoints
    } else {
        return false;
    };

    // Otherwise, we are only proxying if peer endpoint matches proxy endpoint
    peer.endpoint
        .map(|ep| proxy_endpoints.contains(&ep))
        .unwrap_or_default()
}

fn peer_state(
    peer: Option<&telio_wg::uapi::Peer>,
    time_since_last_rx: Option<&Duration>,
    time_since_last_endpoint_change: Option<&Duration>,
    link_state: Option<LinkState>,
    proxy_endpoints: &[SocketAddr],
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

    let is_proxying = peer
        .endpoint
        .map(|ep| proxy_endpoints.contains(&ep))
        .unwrap_or_default();
    let is_in_upgrade_window = time_since_last_endpoint_change < &peer_upgrade_window;

    let has_contact = if let Some(link_state) = link_state {
        // Use link detection for downgrade is enabled
        if time_since_last_rx > &Duration::from_secs(180) {
            // Safety duration
            false
        } else {
            link_state != LinkState::Down
        }
    } else {
        // Use old keepalive method
        time_since_last_rx < &peer_connectivity_timeout
    };

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

    use crate::device::{RequestedDeviceConfig, DNS};
    use mockall::predicate::{self, eq};
    use telio_nurse::config::AggregatorConfig;

    use enum_map::enum_map;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

    use telio_crypto::SecretKey;
    use telio_dns::MockDnsResolver;
    use telio_firewall::firewall::{HashSet as FwHashSet, MockFirewall, Whitelist, FILE_SEND_PORT};
    use telio_model::config::{Config, PeerBase, Server};
    use telio_model::features::{EndpointProvider as ApiEndpointProvider, FeatureDns, TtlValue};
    use telio_model::mesh::ExitNode;
    use telio_pq::MockPostQuantum;
    use telio_proto::Session;
    use telio_proxy::MockProxy;
    use telio_traversal::cross_ping_check::MockCrossPingCheckTrait;
    use telio_traversal::endpoint_providers::MockEndpointProvider;
    use telio_traversal::{MockSessionKeeperTrait, MockUpgradeSyncTrait, UpgradeRequest};
    use telio_wg::uapi::Interface;
    use telio_wg::MockWireGuard;

    type AllowIncomingConnections = bool;
    type AllowLocalAreaAccess = bool;
    type AllowRouting = bool;
    type AllowPeerSendFiles = bool;
    type AllowedIps = Vec<IpAddr>;

    const TEST_PERSISTENT_KEEPALIVE_PERIOD: u32 = 25;
    const TEST_DIRECT_PERSISTENT_KEEPALIVE_PERIOD: u32 = 5;

    #[tokio::test]
    async fn update_wg_private_key_when_changed() {
        let mut wg_mock = MockWireGuard::new();
        let mut pq_mock = MockPostQuantum::new();
        let dns_mock: Mutex<DNS<MockDnsResolver>> = Mutex::default();

        let secret_key_a = SecretKey::gen();
        let secret_key_b = SecretKey::gen();

        wg_mock.expect_get_interface().returning(move || {
            Ok(Interface {
                private_key: Some(secret_key_a.clone()),
                ..Default::default()
            })
        });

        wg_mock
            .expect_set_secret_key()
            .with(predicate::eq(secret_key_b.clone()))
            .returning(|_| Ok(()));

        pq_mock.expect_keys().returning(|| None);

        let requested_state = RequestedState {
            device_config: RequestedDeviceConfig {
                private_key: secret_key_b,
                ..Default::default()
            },
            ..Default::default()
        };

        consolidate_wg_private_key(&requested_state, &wg_mock, &pq_mock, &dns_mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn do_not_update_wg_private_key_when_not_changed() {
        let mut wg_mock = MockWireGuard::new();
        let mut pq_mock = MockPostQuantum::new();
        let dns_mock: Mutex<DNS<MockDnsResolver>> = Mutex::default();

        let secret_key_a = SecretKey::gen();
        let secret_key_a_cpy = secret_key_a.clone();

        wg_mock.expect_get_interface().returning(move || {
            Ok(Interface {
                private_key: Some(secret_key_a_cpy.clone()),
                ..Default::default()
            })
        });

        pq_mock.expect_keys().returning(|| None);
        pq_mock.expect_is_rotating_keys().returning(|| false);

        let requested_state = RequestedState {
            device_config: RequestedDeviceConfig {
                private_key: secret_key_a,
                ..Default::default()
            },
            ..Default::default()
        };

        consolidate_wg_private_key(&requested_state, &wg_mock, &pq_mock, &dns_mock)
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
            device_config: RequestedDeviceConfig {
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
            device_config: RequestedDeviceConfig {
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
            AllowLocalAreaAccess,
            AllowRouting,
            AllowPeerSendFiles,
        )>,
    ) -> RequestedState {
        let mut requested_state = RequestedState::default();

        let mut meshnet_config = Config {
            peers: Some(vec![]),
            this: PeerBase {
                ip_addresses: Some(vec![
                    (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                ]),
                ..Default::default()
            },
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
                    allow_peer_local_network_access: i.3,
                    allow_peer_traffic_routing: i.4,
                    allow_peer_send_files: i.5,
                    ..Default::default()
                };
                peers.push(peer);
            }
        }

        requested_state.meshnet_config = Some(meshnet_config);

        requested_state
    }

    #[cfg(feature = "enable_firewall")]
    #[tokio::test]
    async fn add_newly_requested_peers_to_firewall() {
        let mut firewall = MockFirewall::new();

        let pub_key_starcast_vpeer = SecretKey::gen().public();
        let pub_key_1 = SecretKey::gen().public();
        let pub_key_2 = SecretKey::gen().public();
        let pub_key_3 = SecretKey::gen().public();
        let pub_key_4 = SecretKey::gen().public();

        let requested_state = create_requested_state(vec![
            (pub_key_1, vec![], true, false, false, true),
            (pub_key_2, vec![], true, false, false, false),
            (pub_key_3, vec![], false, false, false, true),
            (pub_key_4, vec![], false, false, false, false),
        ]);

        firewall
            .expect_apply_state()
            .once()
            .with(eq(FirewallState {
                whitelist: Whitelist {
                    peer_whitelists: enum_map! {
                        Permissions::IncomingConnections => FwHashSet::from_iter([pub_key_1, pub_key_2, pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::RoutingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::LocalAreaConnections => FwHashSet::default(),
                    },
                    port_whitelist: [(pub_key_1, FILE_SEND_PORT), (pub_key_3, FILE_SEND_PORT)].iter().cloned().collect(),
                    vpn_peer: None,
                },
                ip_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)],
                ..Default::default()
            }))
            .return_const(());

        consolidate_firewall(
            &requested_state,
            &firewall,
            Some(pub_key_starcast_vpeer),
            None,
        )
        .await
        .unwrap();
    }

    #[cfg(feature = "enable_firewall")]
    #[tokio::test]
    async fn update_permissions_for_requested_peers_in_firewall() {
        let mut firewall = MockFirewall::new();

        let pub_key_starcast_vpeer = SecretKey::gen().public();
        let pub_key_1 = SecretKey::gen().public();
        let pub_key_2 = SecretKey::gen().public();
        let pub_key_3 = SecretKey::gen().public();
        let pub_key_4 = SecretKey::gen().public();

        let requested_state = create_requested_state(vec![
            (pub_key_1, vec![], true, true, true, true),
            (pub_key_2, vec![], true, true, true, false),
            (pub_key_3, vec![], false, false, false, true),
            (pub_key_4, vec![], false, false, false, false),
        ]);

        firewall
            .expect_apply_state()
            .once()
            .with(eq(FirewallState {
                whitelist: Whitelist {
                    peer_whitelists: enum_map! {
                        Permissions::IncomingConnections => FwHashSet::from_iter([pub_key_1, pub_key_2, pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::RoutingConnections => FwHashSet::from_iter([pub_key_1, pub_key_2, pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::LocalAreaConnections => FwHashSet::from_iter([pub_key_1, pub_key_2].iter().cloned()),
                    },
                    port_whitelist: [(pub_key_1, FILE_SEND_PORT), (pub_key_3, FILE_SEND_PORT)].iter().cloned().collect(),
                    vpn_peer: None,
                },
                ip_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)],
                ..Default::default()
            }))
            .return_const(());

        consolidate_firewall(
            &requested_state,
            &firewall,
            Some(pub_key_starcast_vpeer),
            None,
        )
        .await
        .unwrap();
    }

    #[cfg(feature = "enable_firewall")]
    #[tokio::test]
    async fn add_vpn_exit_node_to_firewall() {
        let mut firewall = MockFirewall::new();

        let pub_key_starcast_vpeer = SecretKey::gen().public();
        let pub_key_1 = SecretKey::gen().public();
        let pub_key_2 = SecretKey::gen().public();

        let mut requested_state =
            create_requested_state(vec![(pub_key_1, vec![], false, false, false, false)]);

        requested_state.exit_node = Some(ExitNode {
            public_key: pub_key_2,
            ..Default::default()
        });

        firewall
            .expect_apply_state()
            .once()
            .with(eq(FirewallState {
                whitelist: Whitelist {
                    peer_whitelists: enum_map! {
                        Permissions::IncomingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::RoutingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::LocalAreaConnections => FwHashSet::default(),
                    },
                    port_whitelist: Default::default(),
                    vpn_peer: Some(pub_key_2),
                },
                ip_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)],
                ..Default::default()
            }))
            .return_const(());

        consolidate_firewall(
            &requested_state,
            &firewall,
            Some(pub_key_starcast_vpeer),
            None,
        )
        .await
        .unwrap();
    }

    #[cfg(feature = "enable_firewall")]
    #[tokio::test]
    async fn do_not_add_meshnet_exit_node_to_firewall_if_it_does_not_allow_incoming_connections() {
        let mut firewall = MockFirewall::new();

        let pub_key_starcast_vpeer = SecretKey::gen().public();
        let pub_key_1 = SecretKey::gen().public();

        let mut requested_state =
            create_requested_state(vec![(pub_key_1, vec![], false, false, false, false)]);

        requested_state.exit_node = Some(ExitNode {
            public_key: pub_key_1,
            ..Default::default()
        });

        firewall
            .expect_apply_state()
            .once()
            .with(eq(FirewallState {
                whitelist: Whitelist {
                    peer_whitelists: enum_map! {
                        Permissions::IncomingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::RoutingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::LocalAreaConnections => FwHashSet::default(),
                    },
                    port_whitelist: Default::default(),
                    vpn_peer: None,
                },
                ip_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)],
                ..Default::default()
            }))
            .return_const(());

        consolidate_firewall(
            &requested_state,
            &firewall,
            Some(pub_key_starcast_vpeer),
            None,
        )
        .await
        .unwrap();
    }

    #[cfg(feature = "enable_firewall")]
    #[tokio::test]
    async fn remove_meshnet_exit_node_from_firewall_if_it_does_not_allow_incoming_connections_anymore(
    ) {
        let mut firewall = MockFirewall::new();

        let pub_key_starcast_vpeer = SecretKey::gen().public();
        let pub_key_1 = SecretKey::gen().public();

        let mut requested_state =
            create_requested_state(vec![(pub_key_1, vec![], false, false, false, false)]);

        requested_state.exit_node = Some(ExitNode {
            public_key: pub_key_1,
            ..Default::default()
        });

        firewall
            .expect_apply_state()
            .once()
            .with(eq(FirewallState {
                whitelist: Whitelist {
                    peer_whitelists: enum_map! {
                        Permissions::IncomingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::RoutingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                        Permissions::LocalAreaConnections => FwHashSet::default(),
                    },
                    port_whitelist: Default::default(),
                    vpn_peer: None,
                },
                ip_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)],
                ..Default::default()
            }))
            .return_const(());

        consolidate_firewall(
            &requested_state,
            &firewall,
            Some(pub_key_starcast_vpeer),
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn consolidate_firewall_is_idempotent() {
        let mut firewall = MockFirewall::new();

        let pub_key_starcast_vpeer = SecretKey::gen().public();
        let pub_key_1 = SecretKey::gen().public();
        let pub_key_2 = SecretKey::gen().public();

        let requested_state = create_requested_state(vec![
            (pub_key_1, vec![], true, false, false, true),
            (pub_key_2, vec![], false, true, false, false),
        ]);

        let expected_state = FirewallState {
            whitelist: Whitelist {
                peer_whitelists: enum_map! {
                    Permissions::IncomingConnections => FwHashSet::from_iter([pub_key_1, pub_key_starcast_vpeer].iter().cloned()),
                    Permissions::RoutingConnections => FwHashSet::from_iter([pub_key_starcast_vpeer].iter().cloned()),
                    Permissions::LocalAreaConnections => FwHashSet::from_iter([pub_key_2].iter().cloned()),
                },
                port_whitelist: [(pub_key_1, FILE_SEND_PORT)].iter().cloned().collect(),
                vpn_peer: None,
            },
            ip_addresses: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            ..Default::default()
        };

        // Calling consolidate_firewall multiple times with same state should produce same config
        firewall
            .expect_apply_state()
            .times(3)
            .with(eq(expected_state))
            .returning(|_| ());

        for _ in 0..3 {
            consolidate_firewall(
                &requested_state,
                &firewall,
                Some(pub_key_starcast_vpeer),
                None,
            )
            .await
            .unwrap();
        }
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
        stun_ep_provider: Option<MockEndpointProvider>,
    }

    impl Fixture {
        fn new() -> Self {
            let stun_ep_provider = Some(Self::create_default_stun_ep(false));
            let mut wireguard_interface = MockWireGuard::new();
            wireguard_interface
                .expect_get_link_state()
                .returning(|_| Ok(None));
            Self {
                requested_state: RequestedState::default(),
                wireguard_interface,
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
                    hide_user_data: false,
                    hide_thread_id: false,
                    derp: None,
                    validate_keys: Default::default(),
                    ipv6: true,
                    nicknames: false,
                    firewall: Default::default(),
                    flush_events_on_stop_timeout_seconds: None,
                    post_quantum_vpn: Default::default(),
                    link_detection: None,
                    dns: FeatureDns {
                        exit_dns: None,
                        ttl_value: TtlValue(60),
                    },
                    multicast: false,
                    error_notification_service: None,
                },
                post_quantum: MockPostQuantum::new(),
                stun_ep_provider,
            }
        }

        fn create_default_stun_ep(paused: bool) -> MockEndpointProvider {
            let mut stun_ep_provider = MockEndpointProvider::new();
            stun_ep_provider
                .expect_is_paused()
                .returning(move || paused);
            stun_ep_provider
                .expect_trigger_endpoint_candidates_discovery()
                .returning(|_| Ok(()));
            stun_ep_provider.expect_pause().returning(|| ());
            stun_ep_provider.expect_name().returning(|| "stun");
            stun_ep_provider
        }

        fn create_any_allowed_ips() -> Vec<IpAddr> {
            let ip1 = IpAddr::from([1, 2, 3, 4]);
            let ip1v6 = IpAddr::V6(Ipv6Addr::from([
                1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4,
            ]));
            let ip2 = IpAddr::from([5, 6, 7, 8]);
            let ip2v6 = IpAddr::V6(Ipv6Addr::from([
                5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8,
            ]));

            vec![ip1, ip1v6, ip2, ip2v6]
        }

        fn create_any_session_id() -> u64 {
            rand::random()
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
                        vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, i.1))],
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

        fn when_current_peers(
            &mut self,
            input: Vec<(
                PublicKey,
                SocketAddr,
                u32,
                AllowedIps,
                (Instant, UpdateReason),
            )>,
        ) {
            let peers: BTreeMap<PublicKey, Peer> = input
                .into_iter()
                .map(|i| {
                    (
                        i.0,
                        Peer {
                            public_key: i.0,
                            endpoint: Some(i.1),
                            endpoint_changed_at: Some(i.4),
                            persistent_keepalive_interval: Some(i.2),
                            allowed_ips: i.3.clone().into_iter().map(|ip| ip.into()).collect(),
                            ip_addresses: i.3.clone().into_iter().collect(),
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

        fn when_cross_check_validated_endpoints(
            &mut self,
            input: Vec<(PublicKey, SocketAddr, (SocketAddr, Session), Instant)>,
        ) {
            let map: HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent> = input
                .iter()
                .map(|i| {
                    (
                        i.0,
                        WireGuardEndpointCandidateChangeEvent {
                            public_key: i.0,
                            remote_endpoint: (i.1, ApiEndpointProvider::Local),
                            local_endpoint: (i.2 .0, ApiEndpointProvider::Local),
                            session: i.2 .1,
                            changed_at: i.3,
                        },
                    )
                })
                .collect();

            self.cross_ping_check
                .expect_get_validated_endpoints()
                .returning(move || Ok(map.clone()));
        }

        fn then_cross_ping_check_notfied_about_failed_connections(
            &mut self,
            input: Vec<PublicKey>,
        ) {
            for pk in input {
                self.cross_ping_check
                    .expect_notify_failed_wg_connection()
                    .once()
                    .with(eq(pk))
                    .return_once(|_| Ok(()));
            }
        }

        fn then_cross_ping_check_not_notfied_about_failed_connections(
            &mut self,
            input: Vec<PublicKey>,
        ) {
            for pk in input {
                self.cross_ping_check
                    .expect_notify_failed_wg_connection()
                    .times(0)
                    .with(eq(pk))
                    .return_once(|_| Ok(()));
            }
        }

        fn when_upgrade_requests(&mut self, input: Vec<(PublicKey, SocketAddr, Instant)>) {
            use rand::Rng;
            let map: HashMap<PublicKey, UpgradeRequest> = input
                .iter()
                .map(|i| {
                    (
                        i.0,
                        UpgradeRequest {
                            endpoint: i.1,
                            requested_at: i.2,
                            session: rand::rng().next_u64(),
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
            input: Vec<(PublicKey, SocketAddr, Option<u32>, Vec<IpNet>, Vec<IpAddr>)>,
        ) {
            for i in input {
                self.wireguard_interface
                    .expect_add_peer()
                    .once()
                    .with(eq(Peer {
                        public_key: i.0,
                        endpoint: Some(i.1),
                        endpoint_changed_at: None,
                        ip_addresses: i.4,
                        persistent_keepalive_interval: i.2,
                        allowed_ips: i.3,
                        rx_bytes: None,
                        tx_bytes: None,
                        time_since_last_handshake: None,
                        time_since_last_rx: None,
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

        fn then_peer_not_added(
            &mut self,
            input: Vec<(PublicKey, SocketAddr, u32, Vec<IpNet>, Vec<IpAddr>)>,
        ) {
            for i in input {
                self.wireguard_interface
                    .expect_add_peer()
                    .never()
                    .with(eq(Peer {
                        public_key: i.0,
                        endpoint: Some(i.1),
                        endpoint_changed_at: None,
                        ip_addresses: i.4,
                        persistent_keepalive_interval: Some(i.2),
                        allowed_ips: i.3,
                        rx_bytes: None,
                        tx_bytes: None,
                        time_since_last_handshake: None,
                        time_since_last_rx: None,
                        preshared_key: None,
                    }));
            }
        }

        fn then_request_upgrade(
            &mut self,
            input: Vec<(PublicKey, SocketAddr, SocketAddr, Session)>,
        ) {
            for (pk, remote_wg_endpoint, local_wg_endpoint, session_id) in input {
                self.upgrade_sync
                    .expect_request_upgrade()
                    .once()
                    .with(
                        eq(pk),
                        eq((remote_wg_endpoint, ApiEndpointProvider::Local)),
                        eq((local_wg_endpoint, ApiEndpointProvider::Local)),
                        eq(session_id),
                    )
                    .return_once(|_, _, _, _| Ok(true));
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

        fn then_notify_successfull_wg_connection_upgrade(&mut self, input: Vec<PublicKey>) {
            for i in input {
                self.cross_ping_check
                    .expect_notify_successfull_wg_connection_upgrade()
                    .once()
                    .with(eq(i))
                    .return_once(|_| Ok(()));
                self.upgrade_sync
                    .expect_get_accepted_session()
                    .once()
                    .with(eq(i))
                    .return_once(|_| None);
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
            let stun_ep_provider = { self.stun_ep_provider.map(Arc::new) };
            let upnp_ep_provider: Option<Arc<MockEndpointProvider>> = None;
            let wireguard_interface = Arc::new(self.wireguard_interface);
            let aggregator = ConnectivityDataAggregator::new(
                AggregatorConfig::default(),
                wireguard_interface.clone(),
                Default::default(),
            );

            consolidate_wg_peers(
                &self.requested_state,
                wireguard_interface.as_ref(),
                Some(&self.proxy),
                Some(&cross_ping_check),
                Some(&upgrade_sync),
                &aggregator,
                Some(&session_keeper),
                &self.dns,
                HashMap::new(),
                stun_ep_provider.as_ref(),
                upnp_ep_provider.as_ref(),
                &self.post_quantum,
                None,
                &self.features,
            )
            .await
            .unwrap();
        }

        async fn consolidate_endpoint_invalidation(self) {
            let cross_ping_check = Arc::new(self.cross_ping_check);
            let wireguard_interface = Arc::new(self.wireguard_interface);

            consolidate_endpoint_invalidation(
                wireguard_interface.as_ref(),
                Some(&self.proxy),
                Some(&cross_ping_check),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn when_fresh_start_then_proxy_endpoint_is_added() {
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
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            proxy_endpoint,
            Some(proxying_keepalive_time),
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
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (Instant::now() - Duration::from_secs(5), UpdateReason::Pull),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 5)]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![(pub_key, remote_wg_endpoint, Instant::now())]);

        f.then_add_peer(vec![(
            pub_key,
            remote_wg_endpoint,
            Some(direct_keepalive_period),
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);

        f.then_keeper_add_node(vec![(pub_key, ip1, Some(ip1v6), direct_keepalive_period)]);

        f.then_proxy_mute(vec![(
            pub_key,
            Some(Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW)),
        )]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_ep_is_validated_after_wg_update_produce_no_failed_notification() {
        // No failed notification should be provided regardless
        // whether we are proxying or in direct connection.
        //
        // Test for that both of these cases
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));
        let local_wg_endpoint = SocketAddr::from(([192, 168, 0, 2], 15));
        let wg_endpoints = vec![proxy_endpoint, local_wg_endpoint];

        // Test all wg_endpoint cases
        for wg_endpoint in wg_endpoints {
            let mut f = Fixture::new();
            f.features.ipv6 = true;

            let pub_key = SecretKey::gen().public();
            let allowed_ips = Fixture::create_any_allowed_ips();
            let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
            let changed_endpoint_at = Instant::now();
            let cpc_endpoint_at = changed_endpoint_at + Duration::from_secs(1);

            // Arrange proxy mappings
            f.when_proxy_mapping(vec![(pub_key, mapped_port)]);

            // Arrange peers in wireguard_interface
            f.when_current_peers(vec![(
                pub_key,
                wg_endpoint,
                TEST_PERSISTENT_KEEPALIVE_PERIOD,
                allowed_ips.clone(),
                (changed_endpoint_at, UpdateReason::Pull),
            )]);

            // Arrange a list of validated CPC endpoints
            f.when_cross_check_validated_endpoints(vec![(
                pub_key,
                remote_wg_endpoint,
                (local_wg_endpoint, Fixture::create_any_session_id()),
                cpc_endpoint_at,
            )]);

            // Prepare assertions
            f.then_cross_ping_check_not_notfied_about_failed_connections(vec![pub_key]);

            // Act
            f.consolidate_endpoint_invalidation().await;
        }
    }

    #[tokio::test]
    async fn when_ep_is_validated_before_downgrade_produce_failed_notification() {
        // EndpointGone notification should be produced regardless whether we
        // have pushed the endpoint into to the WG ourselves, or read it from
        // wireguard_interface after roaming.
        //
        // Test for both cases
        let update_reasons = vec![UpdateReason::Push, UpdateReason::Pull];

        for update_reason in update_reasons {
            let mut f = Fixture::new();
            f.features.ipv6 = true;

            let pub_key = SecretKey::gen().public();
            let allowed_ips = Fixture::create_any_allowed_ips();
            let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
            let local_wg_endpoint = SocketAddr::from(([192, 168, 0, 2], 15));

            let mapped_port = 12;
            let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));
            let changed_endpoint_at = Instant::now();
            let cpc_endpoint_at = changed_endpoint_at - Duration::from_secs(1);

            // Arrange proxy mappings
            f.when_proxy_mapping(vec![(pub_key, mapped_port)]);

            // Arrange peers in wireguard interface
            f.when_current_peers(vec![(
                pub_key,
                proxy_endpoint,
                TEST_PERSISTENT_KEEPALIVE_PERIOD,
                allowed_ips.clone(),
                (changed_endpoint_at, update_reason),
            )]);

            // Arrange CPC validated list of endpoints
            f.when_cross_check_validated_endpoints(vec![(
                pub_key,
                remote_wg_endpoint,
                (local_wg_endpoint, Fixture::create_any_session_id()),
                cpc_endpoint_at,
            )]);

            // Prepare assertions
            f.then_cross_ping_check_notfied_about_failed_connections(vec![pub_key]);

            // Act
            f.consolidate_endpoint_invalidation().await;
        }
    }

    #[tokio::test]
    async fn when_validated_ep_is_pushed_into_wg_produce_no_failed_notification() {
        // We had cases where endpoint change triggerd by *writing* endpoint
        // into WG would invalidate all checked endpoints. This is incorrect.
        //
        // Test that this does not happen
        let mut f = Fixture::new();
        f.features.ipv6 = true;

        let pub_key = SecretKey::gen().public();
        let allowed_ips = Fixture::create_any_allowed_ips();
        let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let local_wg_endpoint = SocketAddr::from(([192, 168, 0, 2], 15));

        let mapped_port = 12;
        let changed_endpoint_at = Instant::now();
        let cpc_endpoint_at = changed_endpoint_at - Duration::from_secs(1);

        // Arrange proxy mappings
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);

        // Arrange peers in wireguard interface
        f.when_current_peers(vec![(
            pub_key,
            local_wg_endpoint,
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (changed_endpoint_at, UpdateReason::Push),
        )]);

        // Arrange CPC validated list of endpoints
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            (local_wg_endpoint, Fixture::create_any_session_id()),
            cpc_endpoint_at,
        )]);

        // Prepare assertions
        f.then_cross_ping_check_not_notfied_about_failed_connections(vec![pub_key]);

        // Act
        f.consolidate_endpoint_invalidation().await;
    }

    #[tokio::test]
    async fn when_roaming_from_direct_to_direct_produce_failed_notification() {
        // If validated endpoint has been roamed to something else. It means
        // that likely old endpoint will not be available for use anymore,
        // therefore we should invalidate it.
        //
        // Test that this does in fact happen
        let mut f = Fixture::new();
        f.features.ipv6 = true;

        let pub_key = SecretKey::gen().public();
        let allowed_ips = Fixture::create_any_allowed_ips();
        let remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let local_wg_endpoint = SocketAddr::from(([192, 168, 0, 2], 15));

        let mapped_port = 12;
        let changed_endpoint_at = Instant::now();
        let cpc_endpoint_at = changed_endpoint_at - Duration::from_secs(1);

        // Arrange proxy mappings
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);

        // Arrange peers in wireguard interface
        f.when_current_peers(vec![(
            pub_key,
            local_wg_endpoint,
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (changed_endpoint_at, UpdateReason::Pull),
        )]);

        // Arrange CPC validated list of endpoints
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            (local_wg_endpoint, Fixture::create_any_session_id()),
            cpc_endpoint_at,
        )]);

        // Prepare assertions
        f.then_cross_ping_check_notfied_about_failed_connections(vec![pub_key]);

        // Act
        f.consolidate_endpoint_invalidation().await;
    }

    #[tokio::test]
    async fn when_no_ep_was_validated_produce_no_failed_notification() {
        let mut f = Fixture::new();
        f.features.ipv6 = true;

        let pub_key = SecretKey::gen().public();
        let allowed_ips = Fixture::create_any_allowed_ips();

        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));
        let changed_endpoint_at = Instant::now();

        // Arrange proxy mappings
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);

        // Arrange peers in wireguard interface
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (changed_endpoint_at, UpdateReason::Pull),
        )]);

        // Arrange CPC validated list of endpoints
        f.when_cross_check_validated_endpoints(vec![]);

        // Prepare assertions
        f.then_cross_ping_check_not_notfied_about_failed_connections(vec![pub_key]);

        // Act
        f.consolidate_endpoint_invalidation().await;
    }

    #[tokio::test]
    async fn when_meshnet_disabled_produce_no_failed_notification() {
        let mut f = Fixture::new();
        f.features.ipv6 = true;

        let pub_key = SecretKey::gen().public();
        let allowed_ips = Fixture::create_any_allowed_ips();
        let local_wg_endpoint = SocketAddr::from(([192, 168, 0, 2], 15));
        let changed_endpoint_at = Instant::now();

        // Arrange peers in wireguard interface
        f.when_current_peers(vec![(
            pub_key,
            local_wg_endpoint,
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (changed_endpoint_at, UpdateReason::Pull),
        )]);

        // Act
        consolidate_endpoint_invalidation::<MockWireGuard, MockProxy, MockCrossPingCheckTrait>(
            &f.wireguard_interface,
            None,
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn when_cross_check_validated_is_old_but_set_by_telio_then_upgrade() {
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
        let local_wg_endpoint = SocketAddr::from(([192, 168, 0, 2], 15));
        let session_id = rand::random();
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));

        let direct_keepalive_period = 1234;
        f.requested_state.keepalive_periods.direct = direct_keepalive_period;

        let cpc_endpoint_at = Instant::now();
        // changed_endpoint >= cpc_changed_endpoint
        let changed_endpoint_at = cpc_endpoint_at;

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (changed_endpoint_at, UpdateReason::Push),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 0)]);
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            (local_wg_endpoint, session_id),
            cpc_endpoint_at,
        )]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            remote_wg_endpoint,
            Some(direct_keepalive_period),
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips,
        )]);
        f.then_request_upgrade(vec![(
            pub_key,
            remote_wg_endpoint,
            local_wg_endpoint,
            session_id,
        )]);
        f.then_proxy_mute(vec![(
            pub_key,
            Some(Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW)),
        )]);

        f.then_keeper_add_node(vec![(pub_key, ip1, Some(ip1v6), direct_keepalive_period)]);

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
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            local_wg_endpoint,
            Instant::now() - Duration::from_secs(100),
        )]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            proxy_endpoint,
            Some(proxying_keepalive_period),
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
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            vec![ip1, ip1v6, ip2, ip2v6],
            (Instant::now(), UpdateReason::Pull),
        )]);
        f.when_time_since_last_rx(vec![]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);
        f.session_keeper
            .expect_remove_node()
            .once()
            .with(eq(pub_key.clone()))
            .returning(|_| Ok(()));

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
            TEST_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips,
            (Instant::now() - Duration::from_secs(4), UpdateReason::Pull),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 4)]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);
        // then nothing happens

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
            TEST_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (
                Instant::now() - Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW),
                UpdateReason::Pull,
            ),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 5)]);
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);
        f.then_notify_successfull_wg_connection_upgrade(vec![pub_key]);

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_proxy_endpoint_present_direct_peer_downgraded() {
        let mut f = Fixture::new();

        let pub_key = SecretKey::gen().public();
        let allowed_ips = vec![IpAddr::from([1, 2, 3, 4])];

        let _remote_wg_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let mapped_port = 12;
        let proxy_endpoint = SocketAddr::from(([127, 0, 0, 1], mapped_port));
        let local_endpoint = SocketAddr::from(([192, 168, 0, 1], 13));
        let proxying_keepalive_period = 5;

        f.requested_state.keepalive_periods.proxying = Some(proxying_keepalive_period);
        f.requested_state.keepalive_periods.direct = 5;

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            local_endpoint,
            TEST_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (
                Instant::now() - Duration::from_secs(DEFAULT_PEER_UPGRADE_WINDOW),
                UpdateReason::Pull,
            ),
        )]);

        f.when_cross_check_validated_endpoints(vec![]);

        f.upgrade_sync
            .expect_get_accepted_session()
            .once()
            .with(eq(pub_key))
            .return_once(|_| None);

        f.when_time_since_last_rx(vec![(pub_key, 16)]);

        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            pub_key,
            proxy_endpoint,
            Some(proxying_keepalive_period),
            allowed_ips.iter().copied().map(|ip| ip.into()).collect(),
            allowed_ips.clone(),
        )]);

        f.session_keeper
            .expect_remove_node()
            .once()
            .with(eq(pub_key))
            .returning(|_| Ok(()));

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_vpn_peer_is_added() {
        let mut f = Fixture::new();

        let public_key = SecretKey::gen().public();
        let allowed_ips = vec![
            IpNet::new(IpAddr::from([7, 6, 5, 4]), 23).unwrap(),
            IpNet::new(
                IpAddr::from([5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8]),
                128,
            )
            .unwrap(),
        ];
        let ip_addresses = vec![
            VPN_INTERNAL_IPV4.into(),
            VPN_INTERNAL_IPV6.into(),
            VPN_EXTERNAL_IPV4.into(),
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
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            public_key,
            endpoint_raw,
            Some(vpn_persistent_keepalive),
            allowed_ips,
            ip_addresses,
        )]);

        f.then_post_quantum_is_checked();

        f.consolidate_peers().await;
    }

    #[tokio::test]
    async fn when_stun_peer_should_be_added() {
        #[derive(PartialEq)]
        enum Condition {
            StunNotPresent,
            StunPresent,
            StunPresentAndPaused,
        }

        for condition in [
            Condition::StunNotPresent,
            Condition::StunPresent,
            Condition::StunPresentAndPaused,
        ] {
            let mut f = {
                let mut init_f = Fixture::new();

                match condition {
                    Condition::StunNotPresent => {
                        init_f.stun_ep_provider = None;
                    }
                    Condition::StunPresentAndPaused => {
                        init_f.stun_ep_provider = Some(Fixture::create_default_stun_ep(true));
                    }
                    _ => {}
                }

                init_f
            };

            let public_key = SecretKey::gen().public();

            let allowed_ips = vec![
                IpNet::new(IpAddr::from([100, 64, 0, 4]), 32).unwrap(),
                IpNet::new(
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
            f.when_cross_check_validated_endpoints(vec![]);
            f.when_upgrade_requests(vec![]);

            if condition == Condition::StunPresent {
                f.then_add_peer(vec![(
                    public_key,
                    endpoint_raw,
                    Some(stun_persistent_keepalive),
                    allowed_ips,
                    ip_addresses,
                )]);
            } else {
                f.then_peer_not_added(vec![(
                    public_key,
                    endpoint_raw,
                    stun_persistent_keepalive,
                    allowed_ips,
                    ip_addresses,
                )]);
            }

            f.consolidate_peers().await;
        }
    }

    #[tokio::test]
    async fn when_stun_peer_is_added() {
        let mut f = Fixture::new();

        let public_key = SecretKey::gen().public();

        let allowed_ips = vec![
            IpNet::new(IpAddr::from([100, 64, 0, 4]), 32).unwrap(),
            IpNet::new(
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
        f.when_cross_check_validated_endpoints(vec![]);
        f.when_upgrade_requests(vec![]);

        f.then_add_peer(vec![(
            public_key,
            endpoint_raw,
            Some(stun_persistent_keepalive),
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

        let upgrade_sync_at = Instant::now();
        let cpc_at = upgrade_sync_at - Duration::from_secs(95);
        let endpoint_change_at = upgrade_sync_at - Duration::from_secs(100);

        f.when_requested_meshnet_config(vec![(pub_key, allowed_ips.clone())]);
        f.when_proxy_mapping(vec![(pub_key, mapped_port)]);
        f.when_current_peers(vec![(
            pub_key,
            proxy_endpoint,
            TEST_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            allowed_ips.clone(),
            (endpoint_change_at, UpdateReason::Pull),
        )]);
        f.when_time_since_last_rx(vec![(pub_key, 20)]);
        f.when_cross_check_validated_endpoints(vec![(
            pub_key,
            remote_wg_endpoint,
            local_wg_endpoint,
            cpc_at,
        )]);
        f.when_upgrade_requests(vec![(pub_key, remote_wg_endpoint, upgrade_sync_at)]);

        f.then_add_peer(vec![(
            pub_key,
            remote_wg_endpoint,
            Some(TEST_DIRECT_PERSISTENT_KEEPALIVE_PERIOD),
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
            TEST_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
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
