//! Description of a network configuration map

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_json::{from_value, Error, Value};

use std::{
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
};

use telio_crypto::PublicKey;

/// Characterstics descriping a peer
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBase {
    /// 32-character identifier of the peer
    pub identifier: String,
    /// Public key of the peer
    pub public_key: PublicKey,
    /// Hostname of the peer
    pub hostname: String,
    /// Ip address of peer
    pub ip_addresses: Option<Vec<IpAddr>>,
}

/// Description of a peer
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    #[serde(flatten)]
    /// The base object describing a peer
    pub base: PeerBase,
    /// The peer is local, when the flag is set
    pub is_local: bool,
    /// Flag to control whether the peer allows incoming connections
    pub allow_incoming_connections: bool,
    #[serde(default)]
    /// Flag to control whether the peer allows incoming files
    pub allow_peer_send_files: bool,
}

/// Representation of DNS configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    /// List of DNS servers
    pub dns_servers: Option<Vec<IpAddr>>,
}

/// The currrent state of our connection to derp server
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayState {
    /// Disconnected from the Derp server
    Disconnected,
    /// Connecting to the Derp server
    Connecting,
    /// Connected to the Derp server
    Connected,
}

impl Default for RelayState {
    fn default() -> RelayState {
        RelayState::Disconnected
    }
}

/// Representation of a server, which might be used
/// both as a Relay server and Stun Server
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Server {
    /// Server region code
    pub region_code: String,
    /// Short name for the server
    pub name: String,
    /// Hostname of the server
    pub hostname: String,
    /// IP address of the server
    pub ipv4: Ipv4Addr,
    /// Port on which server listens to relay requests
    pub relay_port: u16,
    /// Port on which server listens to stun requests
    pub stun_port: u16,
    /// Port on which server listens for unencrypted stun requests
    #[serde(default)]
    pub stun_plaintext_port: u16,
    /// Server public key
    pub public_key: PublicKey,
    /// Determines in which order the client tries to connect to the derp servers
    pub weight: u32,

    /// When enabled the connection to servers is not encrypted
    #[serde(default)]
    pub use_plain_text: bool,

    /// Status of the connection with the server
    #[serde(default)]
    pub conn_state: RelayState,
}

impl Server {
    /// Returns the full address of the server
    pub fn get_address(&self) -> String {
        if self.use_plain_text {
            format!("http://{}:{}", self.hostname, self.relay_port)
        } else {
            format!("https://{}:{}", self.hostname, self.relay_port)
        }
    }
}

impl PartialEq for Server {
    // Ignore fields used by DerpRelay itself only
    fn eq(&self, other: &Self) -> bool {
        self.region_code == other.region_code
            && self.name == other.name
            && self.hostname == other.hostname
            && self.ipv4 == other.ipv4
            && self.relay_port == other.relay_port
            && self.stun_port == other.stun_port
            && self.stun_plaintext_port == other.stun_plaintext_port
            && self.public_key == other.public_key
            && self.use_plain_text == other.use_plain_text
        // Do not compare weights, priority for connection persistence
        // && self.weight == other.weight
        // also probably ignore conn_state
        // && self.conn_state == other.conn_state
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            region_code: "".to_string(),
            name: "".to_string(),
            hostname: "".to_string(),
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
            relay_port: 0,
            stun_port: 0,
            stun_plaintext_port: 0,
            public_key: PublicKey::default(),
            weight: 0,
            use_plain_text: false,
            conn_state: RelayState::Disconnected,
        }
    }
}

/// [PartialConfig] is similar to [Config] but allows for `peers` to contain invalid entries.
#[derive(Debug, Deserialize)]
pub struct PartialConfig {
    #[serde(flatten)]
    this: PeerBase,
    peers: Option<Vec<Value>>,
    derp_servers: Option<Vec<Server>>,
    dns: Option<DnsConfig>,
}

impl PartialConfig {
    /// Convert `self` to [Config]. When any given peer fails to convert, error for that will
    /// be collected in the resulting vector and it will be omitted from resulting [Config].
    pub fn to_config(self) -> (Config, Vec<Error>) {
        let (failures, peers) = self
            .peers
            .map(|peers| {
                let (failures, peers) = peers.into_iter().map(from_value).partition_map(Into::into);
                (failures, Some(peers))
            })
            .unwrap_or((vec![], None));
        (
            Config {
                this: self.this,
                peers,
                derp_servers: self.derp_servers,
                dns: self.dns,
            },
            failures,
        )
    }
}

/// Rust representation of [meshnet map]
/// A network map of all the Peers and the servers
/// [meshnet map]: https://docs.nordvpn.com/client-api/#get-map
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    /// Description of the local peer
    pub this: PeerBase,
    /// List of connected peers
    pub peers: Option<Vec<Peer>>,
    /// List of available derp servers
    pub derp_servers: Option<Vec<Server>>,
    /// Dns configuration
    pub dns: Option<DnsConfig>,
}

impl Deref for Peer {
    type Target = PeerBase;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl Deref for Config {
    type Target = PeerBase;

    fn deref(&self) -> &Self::Target {
        &self.this
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::from_str;

    #[test]
    fn json_to_config() {
        let json = r#"
             {
              "identifier": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "public_key": "qj1pru+cP0mU9K0FrU8e0JYtTaPo0YiQG8O2NbFHeH4=",
              "hostname": "everest-alice.nord",
              "os": "android",
              "os_version": "Arch Linux; kernel=5.11.13-arch1-1",
              "ip_addresses": [
                "198.51.100.42"
              ],
              "discovery_key": "63fe62d704226c770004d1ec31de1192fba88dffc2539ddda29543be878fb6ea",
              "relay_address": "disco.nordmesh:12345",
              "peers": [
                {
                  "identifier": "98e00fa1-2c83-4e85-bf01-45c1d4eefea6",
                  "public_key": "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I=",
                  "hostname": "everest-bob.nord",
                  "os": "android",
                  "os_version": "29",
                  "ip_addresses": [
                    "198.51.100.43"
                  ],
                  "is_local": true,
                  "user_email": "alice@example.com",
                  "allow_incoming_connections": true,
                  "allow_peer_send_files": true,
                  "peer_allows_traffic_routing": false,
                  "allow_peer_traffic_routing": true
                },
                {},
                {
                  "identifier": "64463e0f-64ee-455d-b468-e29302e3e747",
                  "public_key": "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I=",
                  "hostname": "everest-alice.nord",
                  "os": "android",
                  "os_version": "29",
                  "ip_addresses": [
                    "198.51.100.43"
                  ],
                  "is_local": false,
                  "user_email": "bob@example.com",
                  "allow_incoming_connections": false,
                  "allow_peer_send_files": false,
                  "peer_allows_traffic_routing": true,
                  "allow_peer_traffic_routing": false
                },
                {
                  "invalid_key": "98e00fa1-2c83-4e85-bf01-45c1d4eefea6",
                  "public_key": "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I=",
                  "hostname": "everest-bob.nord",
                  "os": "android",
                  "os_version": "29",
                  "ip_addresses": [
                    "198.51.100.43"
                  ],
                  "is_local": true,
                  "user_email": "alice@example.com",
                  "allow_incoming_connections": true,
                  "allow_peer_send_files": true,
                  "peer_allows_traffic_routing": false,
                  "allow_peer_traffic_routing": true
                },
                {
                  "identifier": "98e00fa1-2c83-4e85-bf01-45c1d4eefea6",
                  "public_key": "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I=",
                  "hostname": "everest-bob.nord",
                  "os": "android",
                  "os_version": "29",
                  "ip_addresses": [
                    "198.51.100.43"
                  ],
                  "is_local": 42,
                  "user_email": "alice@example.com",
                  "allow_incoming_connections": true,
                  "allow_peer_send_files": true,
                  "peer_allows_traffic_routing": false,
                  "allow_peer_traffic_routing": true
                }
              ],
              "dns": {
                "dns_servers": [
                  "1.1.1.1"
                ],
                "domains": [
                  "nordmesh.net."
                ],
                "hosts": {
                  "everest-alice.nord": "198.51.100.42",
                  "everest-bob.nord": "198.51.100.43"
                }
              },
              "future_field_testing_backwards_compatability": "labadienasuvistiena",
              "derp_servers": [
                {
                  "region_code": "lt",
                  "name": "lt123",
                  "hostname": "relayserver.example.com",
                  "ipv4": "190.2.149.19",
                  "relay_port": 8765,
                  "stun_port": 3479,
                  "stun_plaintext_port": 3480,
                  "public_key": "ilHv1Nl6nszdnELcn2uFYs1yVDsSkzhvY2/sSEh3Zlg=",
                  "weight": 1,
                  "conn_state": "connecting"
                }
              ]
            }
       "#;
        let expected_config = Config {
            this: PeerBase {
                identifier: "3fa85f64-5717-4562-b3fc-2c963f66afa6".to_owned(),
                public_key: "qj1pru+cP0mU9K0FrU8e0JYtTaPo0YiQG8O2NbFHeH4="
                    .parse()
                    .unwrap(),
                hostname: "everest-alice.nord".to_owned(),
                ip_addresses: Some(vec!["198.51.100.42".parse().unwrap()]),
            },
            peers: Some(vec![
                Peer {
                    base: PeerBase {
                        identifier: "98e00fa1-2c83-4e85-bf01-45c1d4eefea6".to_owned(),
                        public_key: "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I="
                            .parse()
                            .unwrap(),
                        hostname: "everest-bob.nord".to_owned(),
                        ip_addresses: Some(vec!["198.51.100.43".parse().unwrap()]),
                    },
                    is_local: true,
                    allow_incoming_connections: true,
                    allow_peer_send_files: true,
                },
                Peer {
                    base: PeerBase {
                        identifier: "64463e0f-64ee-455d-b468-e29302e3e747".to_owned(),
                        public_key: "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I="
                            .parse()
                            .unwrap(),
                        hostname: "everest-alice.nord".to_owned(),
                        ip_addresses: Some(vec!["198.51.100.43".parse().unwrap()]),
                    },
                    is_local: false,
                    allow_incoming_connections: false,
                    allow_peer_send_files: false,
                },
            ]),
            derp_servers: Some(vec![Server {
                region_code: "lt".to_owned(),
                name: "lt123".to_owned(),
                hostname: "relayserver.example.com".to_owned(),
                ipv4: "190.2.149.19".parse().unwrap(),
                relay_port: 8765,
                stun_port: 3479,
                stun_plaintext_port: 3480,
                public_key: "ilHv1Nl6nszdnELcn2uFYs1yVDsSkzhvY2/sSEh3Zlg="
                    .parse()
                    .unwrap(),
                use_plain_text: false,
                weight: 1,
                conn_state: RelayState::Disconnected,
            }]),
            dns: Some(DnsConfig {
                dns_servers: Some(vec!["1.1.1.1".parse().unwrap()]),
            }),
        };

        let partial_config: PartialConfig = from_str(json).unwrap();
        let (full_config, peer_deserialization_failures) = partial_config.to_config();

        assert_eq!(peer_deserialization_failures.len(), 3);
        assert_eq!(full_config, expected_config);
    }
}
