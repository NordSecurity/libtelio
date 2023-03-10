//! Definition of basic components in a mesh network

use super::EndpointMap as RelayEndpointMap;

use crate::api_config::PathType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use telio_crypto::PublicKey;

use telio_wg::uapi::{Event as PeerEvent, Peer as UapiPeer, PeerState};

use super::config::{Config, Peer, PeerBase};

pub use ipnetwork::IpNetwork;
pub use std::net::{Ipv4Addr, SocketAddr};

/// Mesh network endpoint of a Node
#[derive(Debug, Clone, PartialEq, Deserialize, Eq, Serialize)]
#[serde(from = "SocketAddr")]
pub struct Endpoint {
    #[serde(rename = "address")]
    /// Ip address and port number of the endpoint
    pub sockaddr: SocketAddr,
    /// Is this endpoint a relay
    pub primary: bool,
}

/// Description of a Node
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    /// Public key of the Node
    pub public_key: PublicKey,
    /// State of the node (Connecting, connected, or disconnected)
    pub state: Option<NodeState>,
    /// Is the node exit node
    pub is_exit: bool,
    /// Is the node is a vpn server.
    pub is_vpn: bool,
    /// List of Ip's which can connect to the Node
    pub allowed_ips: Vec<IpNetwork>,
    /// List of endpoints connected to the Node
    pub endpoints: Vec<Endpoint>,
    /// Hostname of the node
    pub hostname: Option<String>,
    /// Flag to control whether the Node allows incoming connections
    pub allow_incoming_connections: bool,
    /// Connection type in the network mesh (through Relay or hole punched directly)
    pub path: PathType,
}

/// Description of the Exit Node
/// It is the gateway node to the internet
#[derive(Debug, Default, Clone, Serialize)]
pub struct ExitNode {
    /// The public key of the exit node
    pub public_key: PublicKey,
    /// List of all allowed Ip's for the Exit Node
    pub allowed_ips: Option<Vec<IpNetwork>>,
    /// Socket address of the Exit Node
    pub endpoint: Option<SocketAddr>,
}

/// The connection state of the Node
pub type NodeState = PeerState;

/// Network mesh map of all the nodes
#[derive(Debug, Default)]
pub struct Map {
    /// Public key of self
    pub public_key: PublicKey,
    /// The list of Ip's that can communicate with the device
    pub allowed_ips: Vec<IpNetwork>,
    /// Hash map of all the nodes in the network mesh
    pub nodes: HashMap<PublicKey, Node>,
}

impl std::ops::Deref for Endpoint {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.sockaddr
    }
}

impl std::ops::DerefMut for Endpoint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sockaddr
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            sockaddr: ([0, 0, 0, 0], 0).into(),
            primary: false,
        }
    }
}

impl<A: Into<SocketAddr>> From<(A, bool)> for Endpoint {
    fn from(data: (A, bool)) -> Self {
        Self {
            sockaddr: data.0.into(),
            primary: data.1,
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        (addr, false).into()
    }
}

impl From<&ExitNode> for Node {
    fn from(other: &ExitNode) -> Self {
        #[allow(unwrap_check)]
        let address = "0.0.0.0/0".parse().unwrap();
        Self {
            public_key: other.public_key,
            is_exit: true,
            is_vpn: other.endpoint.is_some(),
            allowed_ips: other
                .allowed_ips
                .as_ref()
                .cloned()
                .unwrap_or_else(|| vec![address]),
            endpoints: other
                .endpoint
                .map(|e| vec![(e, true).into()])
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<&PeerBase> for Node {
    fn from(peer: &PeerBase) -> Self {
        Self {
            public_key: peer.public_key,
            allowed_ips: peer
                .ip_addresses
                .as_ref()
                .map(|ips| ips.iter().map(|a| (*a).into()).collect())
                .unwrap_or_default(),
            endpoints: vec![],
            hostname: Some(peer.hostname.to_owned()),
            ..Default::default()
        }
    }
}

impl From<&Peer> for Node {
    fn from(peer: &Peer) -> Self {
        Self {
            public_key: peer.public_key,
            allowed_ips: peer
                .ip_addresses
                .as_ref()
                .map(|ips| ips.iter().map(|a| (*a).into()).collect())
                .unwrap_or_default(),
            endpoints: vec![],
            hostname: Some(peer.hostname.to_owned()),
            allow_incoming_connections: peer.allow_incoming_connections,
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
                node.endpoints = vec![(endpoint, true).into()];
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

impl From<&UapiPeer> for Node {
    fn from(other: &UapiPeer) -> Self {
        Self {
            public_key: other.public_key,
            allowed_ips: other.allowed_ips.clone(),
            endpoints: other
                .endpoint
                .map(|e| vec![(e, true).into()])
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<&PeerEvent> for Node {
    fn from(other: &PeerEvent) -> Node {
        Self {
            public_key: other.peer.public_key,
            state: Some(other.state),
            allowed_ips: other.peer.allowed_ips.clone(),
            endpoints: other
                .peer
                .endpoint
                .map(|e| vec![(e, true).into()])
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<&Node> for UapiPeer {
    fn from(other: &Node) -> UapiPeer {
        UapiPeer {
            public_key: other.public_key,
            allowed_ips: other.allowed_ips.clone(),
            endpoint: other
                .endpoints
                .iter()
                .find(|e| e.primary)
                .map(|e| e.sockaddr),
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        }
    }
}

impl From<&ExitNode> for UapiPeer {
    fn from(other: &ExitNode) -> UapiPeer {
        #[allow(unwrap_check)]
        let address = "0.0.0.0/0".parse().unwrap();
        UapiPeer {
            public_key: other.public_key,
            allowed_ips: other
                .allowed_ips
                .as_ref()
                .cloned()
                .unwrap_or_else(|| vec![address]),
            endpoint: other.endpoint,
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        }
    }
}
