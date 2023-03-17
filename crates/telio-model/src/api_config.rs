//! Object descriptions of various
//! telio configurable features via API

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use strum_macros::EnumCount;

/// Default keepalive period for most kind of peers
pub const DEFAULT_PERSISTENT_KEEPALIVE_PERIOD: u32 = 25;

/// Default keepalive period for direct peers
pub const DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD: u32 = 5;

/// Configurable persistent keepalive periods for different types of peers
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeaturePersistentKeepalive {
    /// Persistent keepalive period given for VPN peers (in seconds) [default 15s]
    #[serde(default = "FeaturePersistentKeepalive::get_default_keepalive_period")]
    pub vpn: Option<u32>,

    /// Persistent keepalive period for direct peers (in seconds) [default 5s]
    #[serde(default = "FeaturePersistentKeepalive::get_default_direct_keepalive_period")]
    pub direct: u32,

    /// Persistent keepalive period for proxying peers (in seconds) [default 25s]
    #[serde(default = "FeaturePersistentKeepalive::get_default_keepalive_period")]
    pub proxying: Option<u32>,

    /// Persistent keepalive period for stun peers (in seconds) [default 25s]
    #[serde(default = "FeaturePersistentKeepalive::get_default_keepalive_period")]
    pub stun: Option<u32>,
}

impl FeaturePersistentKeepalive {
    fn get_default_keepalive_period() -> Option<u32> {
        Some(DEFAULT_PERSISTENT_KEEPALIVE_PERIOD)
    }

    fn get_default_direct_keepalive_period() -> u32 {
        DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD
    }
}

impl Default for FeaturePersistentKeepalive {
    fn default() -> Self {
        Self {
            vpn: Some(DEFAULT_PERSISTENT_KEEPALIVE_PERIOD),
            direct: DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD,
            proxying: Some(DEFAULT_PERSISTENT_KEEPALIVE_PERIOD),
            stun: Some(DEFAULT_PERSISTENT_KEEPALIVE_PERIOD),
        }
    }
}

/// Configurable features for Meshnet nodes
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureMeshnet {
    /// Configurable persistent keepalive periods for meshnet peers
    #[serde(default)]
    pub persistent_keepalive: FeaturePersistentKeepalive,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
/// QoS configuration options
pub struct FeatureQoS {
    /// How often to collect rtt data in seconds. Default value is 300.
    pub rtt_interval: Option<u32>,
    /// Number of tries for each node. Default value is 3.
    pub rtt_tries: Option<u32>,
    /// Types of rtt analytics. Default is Ping.
    pub rtt_types: Option<Vec<String>>,
    /// Number of buckets used for rtt and throughput. Default value is 5.
    pub buckets: Option<u32>,
    /// Heartbeat interval in seconds. Default value is 3600.
    pub heartbeat_interval: Option<u32>,
}

/// Configurable features for Nurse module
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureNurse {
    /// The unique identifier of the device, used for meshnet ID
    pub fingerprint: String,
    /// QoS configuration for Nurse
    pub qos: Option<FeatureQoS>,
}

/// Configurable features for Lana module
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureLana {
    /// Path of the file where events will be stored. If such file does not exist, it will be created, otherwise reused
    pub event_path: String,
    /// Whether the events should be sent to produciton or not
    pub prod: bool,
}

/// Configurable features for exit Dns
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureExitDns {
    /// Controls if it is allowed to reconfigure DNS peer when exit node is
    /// (dis)connected.
    pub auto_switch_dns_ips: Option<bool>,
}

/// Mesh connection path type
#[derive(Clone, Copy, Debug, EnumCount, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathType {
    /// Nodes connected via a middle-man relay
    Relay,
    /// Nodes connected directly via hole punching
    UdpHolePunch,
    /// Nodes connected directly via WG
    Direct,
}

impl Default for PathType {
    fn default() -> Self {
        PathType::Relay
    }
}

/// Enable wanted paths for telio
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeaturePaths {
    /// Enable paths in increasing priority: 0 is worse then 1 is worse then 2 ...
    /// [PathType::Relay] always assumed as -1
    pub priority: Vec<PathType>,
    /// Force only one specific path to be used.
    pub force: Option<PathType>,
}

/// Available Endpoint Providers for meshnet direct connections
#[derive(Clone, Copy, Debug, EnumCount, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointProvider {
    /// Use local interface ips as possible endpoints
    Local,
    /// Use stun and wg-stun results as possible endpoints
    Stun,
}

/// Endpoint polling interval
pub const DEFAULT_ENDPOINT_POLL_INTERVAL_SECS: u64 = 10;

/// Enable meshent direct connection
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureDirect {
    /// Endpoint providers [default all]
    pub providers: Option<HashSet<EndpointProvider>>,
    /// Polling interval for endpoints [default 10s]
    pub endpoint_interval_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
/// Encompasses all of the possible features that can be enabled
pub struct Features {
    /// Additional meshnet configuration
    #[serde(default)]
    pub meshnet: FeatureMeshnet,
    /// Nurse features that can be configured for QoS
    pub nurse: Option<FeatureNurse>,
    /// Event logging configurable features
    pub lana: Option<FeatureLana>,
    /// Deprecated by direct since 4.0.0
    pub paths: Option<FeaturePaths>,
    /// Configure options for exit dns
    pub exit_dns: Option<FeatureExitDns>,
    /// Configure options for direct WG connections
    pub direct: Option<FeatureDirect>,
}

impl FeaturePaths {
    /// Returns a vector of 'PathType' sorted according to the priority
    pub fn paths(&self) -> Vec<PathType> {
        if let Some(path) = self.force {
            vec![path]
        } else {
            // Collect PathType array, without any duplicates, and keeping prio for priorities
            [PathType::Relay]
                .iter()
                .chain(self.priority.iter())
                .fold(Vec::new(), |mut v, p| {
                    if !v.contains(p) {
                        v.push(*p);
                    }
                    v
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_direct_feature_set() {
        let full_json = r#"
        {
            "providers": ["local", "stun"],
            "endpoint_interval_secs": 30
        }"#;

        let partial_json = r#"
        {
            "providers": ["local"]
        }"#;

        let full_features = FeatureDirect {
            providers: Some(
                vec![EndpointProvider::Local, EndpointProvider::Stun]
                    .into_iter()
                    .collect(),
            ),
            endpoint_interval_secs: Some(30),
        };

        let partial_features = FeatureDirect {
            providers: Some(vec![EndpointProvider::Local].into_iter().collect()),
            endpoint_interval_secs: None,
        };

        assert_eq!(
            serde_json::from_str::<FeatureDirect>(full_json).unwrap(),
            full_features
        );
        assert_eq!(
            serde_json::from_str::<FeatureDirect>(partial_json).unwrap(),
            partial_features
        );
    }

    #[test]
    fn test_json_to_qos_feature_set() {
        let full_json = r#"
        {
            "rtt_interval": 3600,
            "rtt_tries": 5,
            "rtt_types": ["Ping"],
            "buckets": 5,
            "heartbeat_interval": 3600
        }"#;

        let partial_json = r#"
        {
            "rtt_interval": 3600
        }"#;

        let full_features = FeatureQoS {
            rtt_interval: Some(3600),
            rtt_tries: Some(5),
            rtt_types: Some(vec![String::from("Ping")]),
            buckets: Some(5),
            heartbeat_interval: Some(3600),
        };

        let partial_features = FeatureQoS {
            rtt_interval: Some(3600),
            rtt_tries: None,
            rtt_types: None,
            buckets: None,
            heartbeat_interval: None,
        };

        assert_eq!(
            serde_json::from_str::<FeatureQoS>(full_json).unwrap(),
            full_features
        );
        assert_eq!(
            serde_json::from_str::<FeatureQoS>(partial_json).unwrap(),
            partial_features
        );
    }

    #[test]
    fn test_json_to_nurse_feature_set() {
        let full_json = r#"
        {
            "nurse": {
                "fingerprint": "fingerprint_test",
                "qos": {
                    "rtt_interval": 3600,
                    "rtt_tries": 5,
                    "rtt_types": ["Ping"],
                    "buckets": 5,
                    "heartbeat_interval": 3600
                }
            }
        }"#;

        let empty_qos_json = r#"
        {
            "nurse": {
                "fingerprint": "fingerprint_test",
                "qos": {}
            }
        }"#;

        let no_qos_json = r#"
        {
            "nurse": {
                "fingerprint": "fingerprint_test"
            }
        }"#;

        let full_features = Features {
            meshnet: Default::default(),
            nurse: Some(FeatureNurse {
                fingerprint: String::from("fingerprint_test"),
                qos: Some(FeatureQoS {
                    rtt_interval: Some(3600),
                    rtt_tries: Some(5),
                    rtt_types: Some(vec![String::from("Ping")]),
                    buckets: Some(5),
                    heartbeat_interval: Some(3600),
                }),
            }),
            lana: None,
            paths: None,
            direct: None,
            exit_dns: None,
        };

        let empty_qos_features = Features {
            meshnet: Default::default(),
            nurse: Some(FeatureNurse {
                fingerprint: String::from("fingerprint_test"),
                qos: Some(FeatureQoS {
                    rtt_interval: None,
                    rtt_tries: None,
                    rtt_types: None,
                    buckets: None,
                    heartbeat_interval: None,
                }),
            }),
            lana: None,
            paths: None,
            direct: None,
            exit_dns: None,
        };

        let no_qos_features = Features {
            meshnet: Default::default(),
            nurse: Some(FeatureNurse {
                fingerprint: String::from("fingerprint_test"),
                qos: None,
            }),
            lana: None,
            paths: None,
            direct: None,
            exit_dns: None,
        };

        assert_eq!(
            serde_json::from_str::<Features>(full_json).unwrap(),
            full_features
        );
        assert_eq!(
            serde_json::from_str::<Features>(empty_qos_json).unwrap(),
            empty_qos_features
        );
        assert_eq!(
            serde_json::from_str::<Features>(no_qos_json).unwrap(),
            no_qos_features
        );
    }

    #[test]
    fn test_json_to_exit_dns_feature_set() {
        let full_json = r#"
        {
            "exit_dns": {
                "auto_switch_dns_ips": true
            }
        }"#;

        let empty_json = r#"
        {
            "exit_dns": {}
        }"#;

        let full_features = Features {
            meshnet: Default::default(),
            nurse: None,
            lana: None,
            paths: None,
            direct: None,
            exit_dns: Some(FeatureExitDns {
                auto_switch_dns_ips: Some(true),
            }),
        };

        let empty_features = Features {
            meshnet: Default::default(),
            nurse: None,
            lana: None,
            paths: None,
            direct: None,
            exit_dns: Some(FeatureExitDns {
                auto_switch_dns_ips: None,
            }),
        };

        assert_eq!(
            serde_json::from_str::<Features>(full_json).unwrap(),
            full_features
        );
        assert_eq!(
            serde_json::from_str::<Features>(empty_json).unwrap(),
            empty_features
        );
    }

    #[test]
    fn test_json_to_feature_set() {
        let json = r#"
        {
            "meshnet":
            {
                "persistent_keepalive": {
                    "vpn": null,
                    "stun": 50
                }
            },
            "nurse":
            {
                "fingerprint": "fingerprint_test"
            },
            "lana":
            {
                "event_path": "path/to/some/event/data",
                "prod": true
            },
            "paths":
            {
                "priority": ["relay", "udp-hole-punch"],
                "force": "relay"
            },
            "direct": {},
            "exit_dns": {}
        }"#;

        let features = Features {
            meshnet: FeatureMeshnet {
                persistent_keepalive: FeaturePersistentKeepalive {
                    vpn: None,
                    direct: 5,
                    proxying: Some(25),
                    stun: Some(50),
                },
            },
            nurse: Some(FeatureNurse {
                fingerprint: "fingerprint_test".to_string(),
                qos: None,
            }),
            lana: Some(FeatureLana {
                event_path: "path/to/some/event/data".to_string(),
                prod: true,
            }),
            paths: Some(FeaturePaths {
                priority: vec![PathType::Relay, PathType::UdpHolePunch],
                force: Some(PathType::Relay),
            }),
            direct: Some(FeatureDirect {
                providers: None,
                endpoint_interval_secs: None,
            }),
            exit_dns: Some(FeatureExitDns {
                auto_switch_dns_ips: None,
            }),
        };

        assert_eq!(serde_json::from_str::<Features>(json).unwrap(), features);
    }

    #[test]
    fn test_default_features() {
        let expected_defaults = Features {
            meshnet: Default::default(),
            nurse: None,
            lana: None,
            paths: None,
            exit_dns: None,
            direct: None,
        };

        assert_eq!(Features::default(), expected_defaults);
    }

    #[test]
    fn get_paths_from_feature_paths() {
        assert_eq!(
            FeaturePaths {
                priority: vec![PathType::UdpHolePunch],
                force: None
            }
            .paths(),
            vec![PathType::Relay, PathType::UdpHolePunch]
        );
        assert_eq!(
            FeaturePaths {
                priority: vec![
                    PathType::UdpHolePunch,
                    PathType::Relay,
                    PathType::UdpHolePunch
                ],
                force: None
            }
            .paths(),
            vec![PathType::Relay, PathType::UdpHolePunch]
        );
        assert_eq!(
            FeaturePaths {
                priority: vec![
                    PathType::UdpHolePunch,
                    PathType::Relay,
                    PathType::UdpHolePunch
                ],
                force: Some(PathType::UdpHolePunch)
            }
            .paths(),
            vec![PathType::UdpHolePunch]
        );
    }
}
