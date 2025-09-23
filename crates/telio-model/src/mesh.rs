//! Definition of basic components in a mesh network

use super::EndpointMap as RelayEndpointMap;

use crate::features::PathType;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};
use telio_crypto::PublicKey;

use super::config::{Config, Peer, PeerBase};

pub use ipnet::IpNet;
pub use std::net::{Ipv4Addr, SocketAddr};

/// Description of a Node
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Node {
    /// An identifier for a node
    /// Makes it possible to distinguish different nodes in the presence of key reuse
    pub identifier: String,
    /// Public key of the Node
    pub public_key: PublicKey,
    /// Nickname for the peer
    pub nickname: Option<String>,
    /// State of the node (Connecting, connected, or disconnected)
    pub state: NodeState,
    /// Hint of the link state based on last rx timestamp (Up, down)
    pub link_state: Option<LinkState>,
    /// Is the node exit node
    pub is_exit: bool,
    /// Is the node is a vpn server.
    pub is_vpn: bool,
    /// IP addresses of the node
    pub ip_addresses: Vec<IpAddr>,
    /// List of IP's which can connect to the node
    pub allowed_ips: Vec<IpNet>,
    /// Endpoint used by node
    pub endpoint: Option<SocketAddr>,
    /// Hostname of the node
    pub hostname: Option<String>,
    /// Flag to control whether the Node allows incoming connections
    pub allow_incoming_connections: bool,
    /// Flag to control whether the Node allows routing through
    pub allow_peer_traffic_routing: bool,
    /// Flag to control whether the Node allows incoming local area access
    pub allow_peer_local_network_access: bool,
    /// Flag to control whether the Node allows incoming files
    pub allow_peer_send_files: bool,
    /// Connection type in the network mesh (through Relay or hole punched directly)
    pub path: PathType,
    /// Flag to control whether we allow multicast messages from the Node
    pub allow_multicast: bool,
    /// Flag to control whether the Node allows multicast messages from us
    pub peer_allows_multicast: bool,
    /// Latest NordLynx VPN error received from the VPN's Error Notification Service
    pub vpn_connection_error: Option<VpnConnectionError>,
}

/// Possible VPN errors received from the Error Notification Service
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnConnectionError {
    /// Unknown error
    Unknown,
    /// Connection limit reached
    ConnectionLimitReached,
    /// Server will undergo maintenance in the near future.
    ///
    /// Will be sent only when server is going down for a longer time (rollout is ‘maintain’ free),
    /// so that we do not expect to get such a messages often from the same server. More than 2 such
    /// messages from the same server in less than 10 minutes is suspicious. Once app gets this message,
    /// it should pull server list from the API and use that new list. This is because SRE is removing
    /// maintained servers from the server list in advance of maintenance.
    ServerMaintenance,
    /// Authentication failed
    Unauthenticated,
    /// There is a newer connection to this VPN server
    Superseded,
}

/// Description of the Exit Node
/// It is the gateway node to the internet
#[derive(Debug, Default, Clone, Serialize)]
pub struct ExitNode {
    /// An identifier for an exit node
    /// Makes it possible to distinguish different exit nodes in the presence of key reuse
    pub identifier: String,
    /// The public key of the exit node
    pub public_key: PublicKey,
    /// List of all allowed Ip's for the Exit Node
    pub allowed_ips: Option<Vec<IpNet>>,
    /// Socket address of the Exit Node
    pub endpoint: Option<SocketAddr>,
}

/// Connection state of the node
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeState {
    /// Node is disconnected
    #[default]
    Disconnected,
    /// Trying to connect to the Node
    Connecting,
    /// Node is connected
    Connected,
}

/// This is a hint state computed based on the last_rx_timestamp
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkState {
    /// Link is Down
    Down,
    /// Link is Up
    Up,
}

/// Network mesh map of all the nodes
#[derive(Debug, Default)]
pub struct Map {
    /// Public key of self
    pub public_key: PublicKey,
    /// The list of Ip's that can communicate with the device
    pub allowed_ips: Vec<IpNet>,
    /// Hash map of all the nodes in the network mesh
    pub nodes: HashMap<PublicKey, Node>,
}

impl From<&PeerBase> for Node {
    fn from(peer: &PeerBase) -> Self {
        Self {
            identifier: peer.identifier.clone(),
            public_key: peer.public_key,
            nickname: peer
                .nickname
                .as_ref()
                .map(|hidden_nick| hidden_nick.0.to_owned()),
            allowed_ips: peer
                .ip_addresses
                .as_ref()
                .map(|ips| ips.iter().map(|a| (*a).into()).collect())
                .unwrap_or_default(),
            hostname: Some(peer.hostname.0.to_owned().to_string()),
            ..Default::default()
        }
    }
}

impl From<&Peer> for Node {
    fn from(peer: &Peer) -> Self {
        Self {
            public_key: peer.public_key,
            nickname: peer
                .nickname
                .as_ref()
                .map(|hidden_nick| hidden_nick.0.to_owned()),
            allowed_ips: peer
                .ip_addresses
                .as_ref()
                .map(|ips| ips.iter().map(|a| (*a).into()).collect())
                .unwrap_or_default(),
            hostname: Some(peer.hostname.0.to_owned().to_string()),
            allow_incoming_connections: peer.allow_incoming_connections,
            allow_peer_traffic_routing: peer.allow_peer_traffic_routing,
            allow_peer_local_network_access: peer.allow_peer_local_network_access,
            allow_peer_send_files: peer.allow_peer_send_files,
            ..Default::default()
        }
    }
}

impl Map {
    /// Flags the relay nodes in the network mesh map
    pub fn set_relay_endpoints(&mut self, endpoints: RelayEndpointMap) {
        for (key, endpoint) in endpoints {
            // TODO: check if endpoint already contains primary, assume it should stay primary
            //      think, how to check for old derp endpoint.
            if let Some(node) = self.nodes.get_mut(&key) {
                node.endpoint = endpoint.first().copied();
            }
        }
    }
}

impl From<&Config> for Map {
    fn from(c: &Config) -> Self {
        let Node {
            public_key,
            allowed_ips,
            ..
        } = From::<&PeerBase>::from(c);
        Self {
            public_key,
            allowed_ips,
            nodes: c
                .peers
                .as_ref()
                .map(|peers| {
                    peers
                        .iter()
                        .map(|p| (p.public_key, From::<&Peer>::from(p)))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}
