use super::{Entities, Error, RequestedState, Result};
use telio_proxy::Proxy;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use telio_model::config::{Peer, RelayState, Server as RelayEvent};
use telio_model::constants::{VPN_EXTERNAL_IPV4, VPN_INTERNAL_IPV4};
use telio_model::event::Set;
use telio_model::features::PathType;
use telio_model::mesh::{ExitNode, LinkState};
use telio_model::{event::Event, mesh::Node, EndpointMap, PublicKey};
use telio_pq::Entity as PqEntity;
use telio_relay::DerpRelay;
use telio_task::io::mc_chan::Tx;
use telio_wg::uapi::{Peer as WGPeer, PeerState};
use telio_wg::{DynamicWg, WireGuard};

pub struct EventReporter {
    event_publisher: Tx<Box<Event>>,
    last_reported_derp_state: Option<RelayEvent>,
    last_reported_node_state: HashMap<PublicKey, Node>,
}

impl EventReporter {
    pub fn new(event_publisher: Tx<Box<Event>>) -> Self {
        return Self {
            event_publisher,
            last_reported_derp_state: Default::default(),
            last_reported_node_state: Default::default(),
        };
    }

    /// Report any state changes to the libtelio library users
    ///
    /// This function will mainly take care of the following uses cases:
    /// * Report event for any state change of any VPN/Meshnet Node. VPN nodes may retrieve their
    ///   statuses from telio-pq as well as telio-wg as sources of truth for current state.
    /// * Report DERP connection status changes.
    /// * Notify apps about non-recoverable issues, for example in case WireGuard starts spewing
    ///   errors over UAPI.
    ///
    /// The list above may get extended in the future.
    ///
    /// This module depends on external monitoring of state changes, it will not monitor for it
    /// itself. Hence the handle_state_change function should get called whenever any state change
    /// occurs.
    ///
    /// Note here we are *not* handling panic's reporting.
    pub async fn report_events(
        &mut self,
        requested_state: &RequestedState,
        entities: &Entities,
    ) -> Result {
        // Report any changes to DERP state
        self.report_derp_events(entities.meshnet.left().map(|e| &e.derp))
            .await?;

        // Report any changes to Nodes state, but first - lets acquire some information required to
        // do the reporting
        let proxy_endpoints = match entities.meshnet.left() {
            None => Default::default(),
            Some(mesh) => mesh.proxy.get_endpoint_map().await?,
        };
        let requested_nodes: HashMap<PublicKey, Peer> = requested_state.meshnet_config.as_ref()
            .and_then(|mesh| mesh.peers.clone())
            .map_or(vec![], |peers| peers)
            .iter()
            .map(|p| (p.public_key.clone(), p.clone()))
            .collect();

        self.report_node_events(
            &entities.wireguard_interface,
            &entities.postquantum_wg,
            &requested_state.exit_node,
            &proxy_endpoints,
            &requested_nodes,
        )
        .await?;
        Ok(())
    }

    pub async fn report_derp_events(&mut self, relay: Option<&Arc<DerpRelay>>) -> Result {
        // Meshnet may be disabled, in which case relay will be None
        // Otherwise we may have no server selected
        // Or we may be attemting to connect to some server
        // Or we may be connected to some server
        let current_relay_state = match relay {
            Some(r) => r.get_connected_server().await,
            _ => None,
        };

        // Evaluate if anything has changed and build an even if necessary
        let event = match (
            self.last_reported_derp_state.clone(),
            current_relay_state.clone(),
        ) {
            // Nothing Changed
            (None, None) => return Ok(()),
            (Some(a), Some(b)) if a == b => return Ok(()),

            // Either freshly connected or connection info has changed
            (None, Some(current_state)) | (Some(_), Some(current_state)) => {
                Event::builder::<RelayEvent>()
                    .set(current_state)
                    .build()
                    .ok_or(Error::EventBuildingError)?
            }

            // Disconnected
            (Some(last_reported_derp_state), None) => {
                let relay_event = RelayEvent {
                    conn_state: RelayState::Disconnected,
                    ..last_reported_derp_state
                };
                Event::builder::<RelayEvent>()
                    .set(relay_event)
                    .build()
                    .ok_or(Error::EventBuildingError)?
            }
        };

        // Fire event
        self.event_publisher.send(Box::new(event))?;

        // Make sure, that we know what has been reported in the future iterations
        self.last_reported_derp_state = current_relay_state;
        Ok(())
    }

    pub async fn report_node_events(
        &mut self,
        wireguard: &Arc<DynamicWg>,
        pq: &PqEntity,
        exit_node: &Option<ExitNode>,
        proxy_endpoint_map: &EndpointMap,
        requested_nodes: &HashMap<PublicKey, Peer>
    ) -> Result {
        // Retreive relevant WireGuard peers
        let wg_peers = wireguard
            .get_interface()
            .await?
            .peers;

        let nodes = wg_peers
            .values()
            .into_iter()
            .map(|wg_peer| (wg_peer, requested_nodes.get(&wg_peer.public_key), exit_node.clone().filter(|e| e.public_key == wg_peer.public_key)));

        // TODO: convert wg_peers to Nodes

        // TODO: if pq.is_rotating_keys() is true, but Node is not present in Nodes map -> insert
        // one

        // TODO: Find all disconnected nodes (present in last_reported_node_state, but not in new
        // nodes map). And issue disconnect event for all of them. Delete them from hasmap

        // TODO: for the rest of the nodes issue events if node structs are unequal

        Ok(())
    }

    fn merge_wg_peer_and_requested_node_info(
        peer: &WGPeer,
        requested_peer: &Option<Peer>,
        state: PeerState,
        link_state: Option<LinkState>,
        exit_node: &Option<ExitNode>,
        proxy_endpoint_map: &EndpointMap,
    ) -> Result<Node> {
        // Make sure that, whenever provided - requested_peer and/or exit_node refers to the same
        // peer (identified by public key) as the WG information is coming from
        if requested_peer.as_ref().map_or(true, |rn| rn.public_key == peer.public_key)
            && exit_node.as_ref().map_or(true, |en| en.public_key == peer.public_key) {
            return Err(Error::EventReportingError(String::from("Event information merging attempted on mismatched peers/nodes/exit_nodes")));
        }

        // Make sure that we are merging information for peers which has been requested by
        // integrators. This means that either requested_peer or exit_node must be Some(_).
        let cfg_id = match (&requested_peer, &exit_node) {
            (Some(requested_peer), _) => requested_peer.base.identifier.clone(),
            (_, Some(exit_node)) => exit_node.identifier.clone(),
            (None, None) => {
                return Err(Error::EventReportingError(String::from("Event information merging attempted on internal peer")));
            }
        };

        // Determine path type according to proxy endpoint map
        let path = proxy_endpoint_map
            .get(&peer.public_key)
            .and_then(|proxy| peer.endpoint.filter(|endpoint| proxy.contains(endpoint)))
            .map_or(PathType::Direct, |_| PathType::Relay);

        // Determine IP addresses assigned to the peer
        let ip_addresses = match (requested_peer, exit_node) {
            (Some(requested_node), _) => requested_node.ip_addresses.clone().unwrap_or_default(),
            (_, Some(_)) => vec![IpAddr::V4(VPN_EXTERNAL_IPV4), IpAddr::V4(VPN_INTERNAL_IPV4)],
            (None, None) => vec!{}
        };

        // Build node struct out of all the information we have
        Ok(Node {
            identifier: cfg_id,
            public_key: peer.public_key,
            nickname: requested_peer.as_ref().map(|p| p.base.nickname.clone()).flatten().map(|n| n.0),
            state,
            link_state,
            is_exit: exit_node.is_some(),
            is_vpn: (exit_node.is_some() && requested_peer.is_none()),
            ip_addresses,
            allowed_ips: peer.allowed_ips.clone(),
            endpoint: peer.endpoint,
            hostname: requested_peer.as_ref().map(|p| p.base.hostname.0.clone()),
            allow_incoming_connections: requested_peer.as_ref().map(|n| n.allow_incoming_connections).unwrap_or_default(),
            allow_peer_send_files: requested_peer.as_ref().map(|n| n.allow_peer_send_files).unwrap_or_default(),
            path,
            allow_multicast: requested_peer.as_ref().map(|n| n.allow_multicast).unwrap_or_default(),
            peer_allows_multicast: requested_peer.as_ref().map(|n| n.peer_allows_multicast).unwrap_or_default(),
        })
    }
}
