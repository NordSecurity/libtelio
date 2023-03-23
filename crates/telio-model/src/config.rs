//! Description of a network configuration map

use serde::Deserialize;

use std::{net::IpAddr, ops::Deref};

use telio_crypto::PublicKey;
use telio_relay::derp::Server as DerpServer;

/// Characterstics descriping a peer
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Peer {
    #[serde(flatten)]
    /// The base object describing a peer
    pub base: PeerBase,
    /// The peer is local, when the flag is set
    pub is_local: bool,
    /// Flag to control whether the peer allows incoming connections
    pub allow_incoming_connections: bool,
}

/// Representation of DNS configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct DnsConfig {
    /// List of DNS servers
    pub dns_servers: Option<Vec<IpAddr>>,
}

/// Rust representation of [meshnet map]
/// A network map of all the Peers and the servers
/// [meshnet map]: https://docs.nordvpn.com/client-api/#get-map
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    /// Description of the local peer
    pub this: PeerBase,
    /// List of connected peers
    pub peers: Option<Vec<Peer>>,
    /// List of available derp servers
    pub derp_servers: Option<Vec<DerpServer>>,
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
    use telio_relay::derp::RelayState;

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
                  "public_key": "ilHv1Nl6nszdnELcn2uFYs1yVDsSkzhvY2/sSEh3Zlg=",
                  "weight": 1
                }
              ]
            }
       "#;
        let config = Config {
            this: PeerBase {
                identifier: "3fa85f64-5717-4562-b3fc-2c963f66afa6".to_owned(),
                public_key: "qj1pru+cP0mU9K0FrU8e0JYtTaPo0YiQG8O2NbFHeH4="
                    .parse()
                    .unwrap(),
                hostname: "everest-alice.nord".to_owned(),
                ip_addresses: Some(vec!["198.51.100.42".parse().unwrap()]),
            },
            peers: Some(vec![Peer {
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
            }]),
            derp_servers: Some(vec![DerpServer {
                region_code: "lt".to_owned(),
                name: "lt123".to_owned(),
                hostname: "relayserver.example.com".to_owned(),
                ipv4: "190.2.149.19".parse().unwrap(),
                relay_port: 8765,
                stun_port: 3479,
                stun_plaintext_port: Default::default(),
                public_key: "ilHv1Nl6nszdnELcn2uFYs1yVDsSkzhvY2/sSEh3Zlg="
                    .parse()
                    .unwrap(),
                use_plain_text: false,
                weight: 1,
                conn_state: RelayState::Disconnected,
                used: false,
            }]),
            dns: Some(DnsConfig {
                dns_servers: Some(vec!["1.1.1.1".parse().unwrap()]),
            }),
        };

        assert_eq!(serde_json::from_str::<Config>(json).unwrap(), config);
    }
}
