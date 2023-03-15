//! Object descriptions of various
//! telio configurable features via API

use std::{collections::HashSet, fmt};

use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serialize};
use strum_macros::EnumCount;
use telio_utils::telio_log_warn;

/// Default keepalive period used for proxying peers,
/// STUN servers and VPN servers
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

/// Configurable features for Wireguard peers
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureWireguard {
    /// Configurable persistent keepalive periods for wireguard peers
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
}

/// Configurable features for Nurse module
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureNurse {
    /// The unique identifier of the device, used for meshnet ID
    pub fingerprint: String,
    /// Heartbeat interval in seconds. Default value is 3600.
    pub heartbeat_interval: Option<u32>,
    /// QoS configuration for Nurse
    pub qos: Option<FeatureQoS>,
}

/// Configurable features for Lana module
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureLana {
    /// Path of the file where events will be stored. If such file does not exist, it will be created, otherwise reused
    pub event_path: String,
    /// Whether the events should be sent to produciton or not
    pub prod: bool,
}

impl fmt::Debug for FeatureLana {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FeatureLana")
            .field("prod", &self.prod)
            .finish()
    }
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
    /// Use IGD and upnp to generate endpoints
    Upnp,
}

/// Endpoint polling interval
pub const DEFAULT_ENDPOINT_POLL_INTERVAL_SECS: u64 = 10;

/// Enable meshent direct connection
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureDirect {
    /// Endpoint providers [default all]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_providers")]
    pub providers: Option<HashSet<EndpointProvider>>,
    /// Polling interval for endpoints [default 10s]
    pub endpoint_interval_secs: Option<u64>,
}

/// Configure derp behaviour
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureDerp {
    /// Tcp keepalive set on derp server's side [default 15s]
    pub tcp_keepalive: Option<u32>,
    /// Derp will send empty messages after this many seconds of not sending/receiving any data [default 60s]
    pub derp_keepalive: Option<u32>,
}

fn deserialize_providers<'de, D>(de: D) -> Result<Option<HashSet<EndpointProvider>>, D::Error>
where
    D: Deserializer<'de>,
{
    let eps: Vec<&str> = match Deserialize::deserialize(de) {
        Ok(vec) => vec,
        Err(_) => return Ok(None),
    };

    let eps: HashSet<_> = eps
        .into_iter()
        .filter_map(|provider| {
            EndpointProvider::deserialize(<&str as IntoDeserializer>::into_deserializer(provider))
                .map_err(|e| {
                    telio_log_warn!("Failed to parse EndpointProvider: {}", e);
                })
                .ok()
        })
        .collect();

    Ok(Some(eps))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
/// Encompasses all of the possible features that can be enabled
pub struct Features {
    /// Additional wireguard configuration
    #[serde(default)]
    pub wireguard: FeatureWireguard,
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
    /// Should only be set for macos sideload
    #[cfg(any(target_os = "macos", feature = "pretend_to_be_macos"))]
    pub macos_sideload: bool,
    /// Derp server specific configuration
    pub derp: Option<FeatureDerp>,
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
    use once_cell::sync::Lazy;
    use serde_json::from_str;

    use super::*;

    const CORRECT_FEATURES_JSON_WITHOUT_MACOS_SIDELOAD: &str = r#"
        {
            "wireguard":
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
                "priority": ["relay", "direct"],
                "force": "relay"
            },
            "direct": {},
            "exit_dns": {}
        }"#;

    const CORRECT_FEATURES_JSON_WITH_MACOS_SIDELOAD: &str = r#"
        {
            "wireguard":
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
                "priority": ["relay", "direct"],
                "force": "relay"
            },
            "direct": {},
            "exit_dns": {},
            "macos_sideload": true
        }"#;

    static EXPECTED_FEATURES: Lazy<Features> = Lazy::new(|| Features {
        wireguard: FeatureWireguard {
            persistent_keepalive: FeaturePersistentKeepalive {
                vpn: None,
                direct: 5,
                proxying: Some(25),
                stun: Some(50),
            },
        },
        nurse: Some(FeatureNurse {
            fingerprint: "fingerprint_test".to_string(),
            heartbeat_interval: None,
            qos: None,
        }),
        lana: Some(FeatureLana {
            event_path: "path/to/some/event/data".to_string(),
            prod: true,
        }),
        paths: Some(FeaturePaths {
            priority: vec![PathType::Relay, PathType::Direct],
            force: Some(PathType::Relay),
        }),
        direct: Some(FeatureDirect {
            providers: None,
            endpoint_interval_secs: None,
        }),
        exit_dns: Some(FeatureExitDns {
            auto_switch_dns_ips: None,
        }),
        #[cfg(any(target_os = "macos", feature = "pretend_to_be_macos"))]
        macos_sideload: true,
        derp: None,
    });

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

        assert_eq!(from_str::<FeatureDirect>(full_json).unwrap(), full_features);
        assert_eq!(
            from_str::<FeatureDirect>(partial_json).unwrap(),
            partial_features
        );
    }

    #[test]
    fn test_json_direct_accepts_arbitrary_providers() {
        let arbitrery_providers_json = r#"
        {
            "providers": ["local", "stun", "other", "none"]
        }"#;

        let parsed_feature = FeatureDirect {
            providers: Some(
                vec![EndpointProvider::Local, EndpointProvider::Stun]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };

        assert_eq!(
            from_str::<FeatureDirect>(arbitrery_providers_json).unwrap(),
            parsed_feature
        );
    }

    #[test]
    fn test_json_direct_allow_empty() {
        // Custom deserialize needs default to make Option None

        let empty_json = r#"{}"#;

        let parsed_feature = FeatureDirect::default();

        assert_eq!(
            from_str::<FeatureDirect>(empty_json).unwrap(),
            parsed_feature
        );
    }

    #[test]
    fn test_json_to_qos_feature_set() {
        let full_json = r#"
        {
            "rtt_interval": 3600,
            "rtt_tries": 5,
            "rtt_types": ["Ping"],
            "buckets": 5
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
        };

        let partial_features = FeatureQoS {
            rtt_interval: Some(3600),
            rtt_tries: None,
            rtt_types: None,
            buckets: None,
        };

        assert_eq!(from_str::<FeatureQoS>(full_json).unwrap(), full_features);
        assert_eq!(
            from_str::<FeatureQoS>(partial_json).unwrap(),
            partial_features
        );
    }

    #[test]
    #[cfg(not(any(target_os = "macos", feature = "pretend_to_be_macos")))]
    fn test_json_to_nurse_feature_set() {
        let full_json = r#"
        {
            "nurse": {
                "fingerprint": "fingerprint_test",
                "heartbeat_interval": 3600,
                "qos": {
                    "rtt_interval": 3600,
                    "rtt_tries": 5,
                    "rtt_types": ["Ping"],
                    "buckets": 5
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
            wireguard: Default::default(),
            nurse: Some(FeatureNurse {
                fingerprint: String::from("fingerprint_test"),
                heartbeat_interval: Some(3600),
                qos: Some(FeatureQoS {
                    rtt_interval: Some(3600),
                    rtt_tries: Some(5),
                    rtt_types: Some(vec![String::from("Ping")]),
                    buckets: Some(5),
                }),
            }),
            lana: None,
            paths: None,
            direct: None,
            exit_dns: None,
            derp: None,
        };

        let empty_qos_features = Features {
            wireguard: Default::default(),
            nurse: Some(FeatureNurse {
                fingerprint: String::from("fingerprint_test"),
                heartbeat_interval: None,
                qos: Some(FeatureQoS {
                    rtt_interval: None,
                    rtt_tries: None,
                    rtt_types: None,
                    buckets: None,
                }),
            }),
            lana: None,
            paths: None,
            direct: None,
            exit_dns: None,
            derp: None,
        };

        let no_qos_features = Features {
            wireguard: Default::default(),
            nurse: Some(FeatureNurse {
                fingerprint: String::from("fingerprint_test"),
                heartbeat_interval: None,
                qos: None,
            }),
            lana: None,
            paths: None,
            direct: None,
            exit_dns: None,
            derp: None,
        };

        assert_eq!(from_str::<Features>(full_json).unwrap(), full_features);
        assert_eq!(
            from_str::<Features>(empty_qos_json).unwrap(),
            empty_qos_features
        );
        assert_eq!(from_str::<Features>(no_qos_json).unwrap(), no_qos_features);
    }

    #[test]
    #[cfg(not(any(target_os = "macos", feature = "pretend_to_be_macos")))]
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
            wireguard: Default::default(),
            nurse: None,
            lana: None,
            paths: None,
            direct: None,
            exit_dns: Some(FeatureExitDns {
                auto_switch_dns_ips: Some(true),
            }),
            derp: None,
        };

        let empty_features = Features {
            wireguard: Default::default(),
            nurse: None,
            lana: None,
            paths: None,
            direct: None,
            exit_dns: Some(FeatureExitDns {
                auto_switch_dns_ips: None,
            }),
            derp: None,
        };

        assert_eq!(from_str::<Features>(full_json).unwrap(), full_features);
        assert_eq!(from_str::<Features>(empty_json).unwrap(), empty_features);
    }

    #[test]
    fn test_json_without_macos_sideload_to_feature_set() {
        let deserialization: Result<Features, _> =
            from_str(CORRECT_FEATURES_JSON_WITHOUT_MACOS_SIDELOAD);
        #[cfg(any(target_os = "macos", feature = "pretend_to_be_macos"))]
        assert!(deserialization.is_err());

        #[cfg(not(any(target_os = "macos", feature = "pretend_to_be_macos")))]
        assert_eq!(deserialization.unwrap(), *EXPECTED_FEATURES);
    }

    #[test]
    fn test_json_with_macos_sideload_to_feature_set() {
        let deserialization: Result<Features, _> =
            from_str(CORRECT_FEATURES_JSON_WITH_MACOS_SIDELOAD);

        assert_eq!(deserialization.unwrap(), *EXPECTED_FEATURES);
    }

    #[test]
    #[cfg(not(any(target_os = "macos", feature = "pretend_to_be_macos")))]
    fn test_default_features() {
        let expected_defaults = Features {
            wireguard: Default::default(),
            nurse: None,
            lana: None,
            paths: None,
            exit_dns: None,
            direct: None,
            derp: None,
        };

        assert_eq!(Features::default(), expected_defaults);
    }

    #[test]
    fn get_paths_from_feature_paths() {
        assert_eq!(
            FeaturePaths {
                priority: vec![PathType::Direct],
                force: None
            }
            .paths(),
            vec![PathType::Relay, PathType::Direct]
        );
        assert_eq!(
            FeaturePaths {
                priority: vec![PathType::Direct, PathType::Relay, PathType::Direct],
                force: None
            }
            .paths(),
            vec![PathType::Relay, PathType::Direct]
        );
        assert_eq!(
            FeaturePaths {
                priority: vec![PathType::Direct, PathType::Relay, PathType::Direct],
                force: Some(PathType::Direct)
            }
            .paths(),
            vec![PathType::Direct]
        );
    }
}
