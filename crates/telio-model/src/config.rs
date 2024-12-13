//! Description of a network configuration map

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_json::{from_value, Error, Value};
use smart_default::SmartDefault;
use telio_utils::{telio_log_error, telio_log_warn, Hidden};
use tokio::time::Instant;

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Deref,
};

use telio_crypto::PublicKey;

const MAX_CONFIG_LENGTH: usize = 16 * 1024 * 1024;

/// Characterstics descriping a peer
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBase {
    /// 32-character identifier of the peer
    pub identifier: String,
    /// Public key of the peer
    pub public_key: PublicKey,
    /// Hostname of the peer
    pub hostname: Hidden<String>,
    /// Ip address of peer
    pub ip_addresses: Option<Vec<IpAddr>>,
    /// Nickname for the peer
    pub nickname: Option<Hidden<String>>,
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
    /// Flag to control whether the Node allows routing through
    pub allow_peer_traffic_routing: bool,
    /// Flag to control whether the Node allows incoming local area access
    pub allow_peer_local_network_access: bool,
    #[serde(default)]
    /// Flag to control whether the peer allows incoming files
    pub allow_peer_send_files: bool,
    #[serde(default)]
    /// Flag to control whether we allow multicast messages from the peer
    pub allow_multicast: bool,
    #[serde(default)]
    /// Flag to control whether the peer allows multicast messages from us
    pub peer_allows_multicast: bool,
}

/// Representation of DNS configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    /// List of DNS servers
    pub dns_servers: Option<Vec<IpAddr>>,
}

/// The currrent state of our connection to derp server
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayState {
    /// Disconnected from the Derp server
    #[default]
    Disconnected,
    /// Connecting to the Derp server
    Connecting,
    /// Connected to the Derp server
    Connected,
}

/// Representation of a server, which might be used
/// both as a Relay server and Stun Server
#[derive(Debug, Clone, Deserialize, Serialize, SmartDefault)]
pub struct Server {
    /// Server region code
    pub region_code: String,
    /// Short name for the server
    pub name: String,
    /// Hostname of the server
    pub hostname: String,
    /// IP address of the server
    #[default(Ipv4Addr::new(0, 0, 0, 0))]
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

/// Possible relay server connectivity change reasons
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum RelayConnectionChangeReason {
    // Numbers smaller than 200 for configuration changes
    /// Generic reason used when everything goes right
    ConfigurationChange,
    /// The connection was explicitely closed by user
    DisabledByUser,
    /// Some kind of unexpected internal error
    ClientError,

    // Numbers larger than 200 for network problems
    /// Derp server connection timed out
    IoError(ErrorKind),
}

impl From<RelayConnectionChangeReason> for u64 {
    fn from(reason: RelayConnectionChangeReason) -> u64 {
        match reason {
            RelayConnectionChangeReason::ConfigurationChange => 0,
            RelayConnectionChangeReason::DisabledByUser => 101,
            RelayConnectionChangeReason::ClientError => 102,
            RelayConnectionChangeReason::IoError(io_err) => 200 + (io_err as u64),
        }
    }
}

/// An event informing analytics about change in the Derp server state
#[derive(Clone, Debug)]
pub struct DerpAnalyticsEvent {
    /// Derp analytic event uses server address as its ID
    pub server_address: SocketAddr,

    /// Current Derp server state
    pub state: RelayState,

    /// Reason why the Derp server state has changed
    pub reason: RelayConnectionChangeReason,

    /// Timestamp when event was created
    pub timestamp: Instant,
}

impl DerpAnalyticsEvent {
    /// Creates a new Derp analytics event for a given current Derp server state and reason
    pub fn new(server: &Server, reason: RelayConnectionChangeReason) -> DerpAnalyticsEvent {
        DerpAnalyticsEvent {
            server_address: SocketAddr::new(server.ipv4.into(), server.relay_port),
            state: server.conn_state,
            reason,
            timestamp: Instant::now(),
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

impl Config {
    /// Deserialize string to `Config`, with `PartialConfig` as an intermediate step
    pub fn new_from_str(value: &str) -> Result<(Self, usize), ConfigParseError> {
        if value.is_empty() {
            telio_log_error!("config string was empty");
            return Err(ConfigParseError::EmptyString);
        } else if value.len() > MAX_CONFIG_LENGTH {
            telio_log_error!(
                "config string exceeds maximum allowed length ({}): {}",
                MAX_CONFIG_LENGTH,
                value.len()
            );
            return Err(ConfigParseError::TooLongString);
        }
        let cfg: PartialConfig =
            serde_json::from_str(value).map_err(|_| ConfigParseError::BadConfig)?;
        let (cfg, peer_deserialization_failures) = cfg.to_config();
        let res = (cfg, peer_deserialization_failures.len());
        for failure in peer_deserialization_failures {
            telio_log_warn!("Failed to deserialize one of the peers: {}", failure);
        }
        Ok(res)
    }
}

/// Represents the possible issues when deserializing a json-string to a config object
#[derive(Copy, Clone, Debug)]
pub enum ConfigParseError {
    /// The passed string was empty
    EmptyString,
    /// The passed string was longer than the allowed max length
    TooLongString,
    /// The string did not represent a valid Config
    BadConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_string_meshnet_config_empty_string() {
        let actual = Config::new_from_str("").unwrap_err();
        assert!(matches!(actual, ConfigParseError::EmptyString));
    }

    #[test]
    fn test_string_meshnet_config_too_long_string() {
        let actual = Config::new_from_str(&"a".repeat(MAX_CONFIG_LENGTH + 1)).unwrap_err();
        dbg!(actual);
        assert!(matches!(actual, ConfigParseError::TooLongString));
    }

    #[test]
    fn test_string_meshnet_config_invalid_string() {
        let actual = Config::new_from_str(r#"{"invalid": "field"}"#).unwrap_err();
        assert!(matches!(actual, ConfigParseError::BadConfig));
    }

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
              "nickname": "bunnyg",
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
                  "nickname": "",
                  "is_local": true,
                  "user_email": "alice@example.com",
                  "allow_incoming_connections": true,
                  "allow_peer_local_network_access": true,
                  "allow_peer_send_files": true,
                  "peer_allows_traffic_routing": false,
                  "allow_peer_traffic_routing": true,
                  "allow_multicast": true,
                  "peer_allows_multicast": true
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
                  "allow_peer_local_network_access": false,
                  "allow_peer_send_files": false,
                  "peer_allows_traffic_routing": true,
                  "allow_peer_traffic_routing": false,
                  "allow_multicast": true
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
                  "nickname": "",
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
                hostname: telio_utils::Hidden("everest-alice.nord".to_owned()),
                ip_addresses: Some(vec!["198.51.100.42".parse().unwrap()]),
                nickname: Some(telio_utils::Hidden("bunnyg".to_owned())),
            },
            peers: Some(vec![
                Peer {
                    base: PeerBase {
                        identifier: "98e00fa1-2c83-4e85-bf01-45c1d4eefea6".to_owned(),
                        public_key: "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I="
                            .parse()
                            .unwrap(),
                        hostname: telio_utils::Hidden("everest-bob.nord".to_owned()),
                        ip_addresses: Some(vec!["198.51.100.43".parse().unwrap()]),
                        nickname: Some(telio_utils::Hidden("".to_owned())),
                    },
                    is_local: true,
                    allow_incoming_connections: true,
                    allow_peer_traffic_routing: true,
                    allow_peer_local_network_access: true,
                    allow_peer_send_files: true,
                    allow_multicast: true,
                    peer_allows_multicast: true,
                },
                Peer {
                    base: PeerBase {
                        identifier: "64463e0f-64ee-455d-b468-e29302e3e747".to_owned(),
                        public_key: "LRrbraNJXOrVdnpXy6gA/XcpmxymE0oMZlzP5Pqi20I="
                            .parse()
                            .unwrap(),
                        hostname: telio_utils::Hidden("everest-alice.nord".to_owned()),
                        ip_addresses: Some(vec!["198.51.100.43".parse().unwrap()]),
                        nickname: None,
                    },
                    is_local: false,
                    allow_incoming_connections: false,
                    allow_peer_traffic_routing: false,
                    allow_peer_local_network_access: false,
                    allow_peer_send_files: false,
                    allow_multicast: true,
                    peer_allows_multicast: false,
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

        let (full_config, peer_deserialization_failure_count) = Config::new_from_str(json).unwrap();

        assert_eq!(peer_deserialization_failure_count, 3);
        assert_eq!(full_config, expected_config);
    }
}
