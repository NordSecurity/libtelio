//! Object descriptions of various
//! telio configurable features via API

use std::{collections::HashSet, fmt};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serialize};
use smart_default::SmartDefault;
use strum_macros::EnumCount;
use telio_utils::telio_log_warn;

/// Type alias for UniFFI
pub type EndpointProviders = HashSet<EndpointProvider>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
/// Encompasses all of the possible features that can be enabled
pub struct Features {
    /// Additional wireguard configuration
    #[serde(deserialize_with = "FeatureWireguard::default_on_null")]
    pub wireguard: FeatureWireguard,
    /// Nurse features that can be configured for QoS
    #[default(Some(Default::default()))]
    pub nurse: Option<FeatureNurse>,
    /// Event logging configurable features
    pub lana: Option<FeatureLana>,
    /// Deprecated by direct since 4.0.0
    pub paths: Option<FeaturePaths>,
    /// Configure options for direct WG connections
    pub direct: Option<FeatureDirect>,
    /// Test environment (natlab) requires binding feature disabled
    /// TODO: Remove it once mac integration tests support the binding mechanism
    pub is_test_env: Option<bool>,
    /// Controll if IP addresses should be hidden in logs
    #[default(true)]
    pub hide_ips: bool,
    /// Derp server specific configuration
    pub derp: Option<FeatureDerp>,
    /// Flag to specify if keys should be validated
    pub validate_keys: FeatureValidateKeys,
    /// IPv6 support
    pub ipv6: bool,
    /// Nicknames support
    pub nicknames: bool,
    /// Flag to turn on connection reset upon VPN server change for boringtun adapter
    pub firewall: FeatureFirewall,
    /// If and for how long to flush events when stopping telio. Setting to Some(0) means waiting until all events have been flushed, regardless of how long it takes
    pub flush_events_on_stop_timeout_seconds: Option<u64>,
    /// Post quantum VPN tunnel configuration
    pub post_quantum_vpn: FeaturePostQuantumVPN,
    /// No link detection mechanism
    pub link_detection: Option<FeatureLinkDetection>,
    /// Feature configuration for DNS.
    pub dns: FeatureDns,
    /// PMTU discovery configuration, enabled by default
    #[default(Some(Default::default()))]
    pub pmtu_discovery: Option<FeaturePmtuDiscovery>,
    /// Multicast support
    pub multicast: bool,
    /// Batching feature configuration, disabled by default, used for batching keep-alives
    pub batching: Option<FeatureBatching>,
}

/// Configure keepalive batching
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeatureBatching {
    /// Direct connection threshold when batching (in seconds) [default 0s]
    #[default(0)]
    pub direct_connection_threshold: u32,
}

/// Configurable features for Wireguard peers
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureWireguard {
    /// Configurable persistent keepalive periods for wireguard peers
    #[serde(default)]
    pub persistent_keepalive: FeaturePersistentKeepalive,
}

impl FeatureWireguard {
    fn default_on_null<'de, D>(deserializer: D) -> Result<FeatureWireguard, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::deserialize(deserializer)?;
        Ok(opt.unwrap_or_default())
    }
}

/// Configurable persistent keepalive periods for different types of peers
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeaturePersistentKeepalive {
    /// Persistent keepalive period given for VPN peers (in seconds) [default 15s]
    #[default(Some(25))]
    pub vpn: Option<u32>,

    /// Persistent keepalive period for direct peers (in seconds) [default 5s]
    #[default(5)]
    pub direct: u32,

    /// Persistent keepalive period for proxying peers (in seconds) [default 25s]
    #[default(Some(25))]
    pub proxying: Option<u32>,

    /// Persistent keepalive period for stun peers (in seconds) [default 25s]
    #[default(Some(25))]
    pub stun: Option<u32>,
}

/// Configurable features for Nurse module
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeatureNurse {
    /// Heartbeat interval in seconds. Default value is 3600.
    #[default(60 * 60)]
    pub heartbeat_interval: u64,
    /// Initial heartbeat interval in seconds. Default value is 300.
    #[default(5 * 60)]
    pub initial_heartbeat_interval: u64,
    /// QoS configuration for Nurse. Enabled by default.
    #[default(Some(Default::default()))]
    pub qos: Option<FeatureQoS>,
    /// Enable/disable collecting nat type. Disabled by default.
    pub enable_nat_type_collection: bool,
    /// Enable/disable Relay connection data. Enabled by default.
    #[default(true)]
    pub enable_relay_conn_data: bool,
    /// Enable/disable NAT-traversal connections data. Enabled by default.
    #[default(true)]
    pub enable_nat_traversal_conn_data: bool,
    /// How long a session can be before it is forcibly reported, in seconds. Default value is 24h.
    #[default(60 * 60 * 24)]
    pub state_duration_cap: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
/// QoS configuration options
pub struct FeatureQoS {
    /// How often to collect rtt data in seconds. Default value is 300.
    #[default(5 * 60)]
    pub rtt_interval: u64,
    /// Number of tries for each node. Default value is 3.
    #[default(3)]
    pub rtt_tries: u32,
    /// Types of rtt analytics. Default is Ping.
    #[default(vec![RttType::Ping])]
    pub rtt_types: Vec<RttType>,
    /// Number of buckets used for rtt and throughput. Default value is 5.
    #[default(5)]
    pub buckets: u32,
}

/// Enum denoting ways to calculate RTT.
#[derive(Eq, PartialEq, Debug, Clone, Deserialize)]
#[repr(u32)]
pub enum RttType {
    /// Simple ping request.
    Ping,
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

/// Enable wanted paths for telio
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeaturePaths {
    /// Enable paths in increasing priority: 0 is worse then 1 is worse then 2 ...
    /// [PathType::Relay] always assumed as -1
    pub priority: Vec<PathType>,
    /// Force only one specific path to be used.
    pub force: Option<PathType>,
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

/// Mesh connection path type
#[derive(Clone, Copy, Debug, Default, EnumCount, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathType {
    /// Nodes connected via a middle-man relay
    #[default]
    Relay,
    /// Nodes connected directly via WG
    Direct,
}

/// Enable meshent direct connection
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeatureDirect {
    /// Endpoint providers [default all]
    #[serde(deserialize_with = "deserialize_providers")]
    pub providers: Option<EndpointProviders>,
    /// Polling interval for endpoints [default 10s]
    #[default = 25]
    pub endpoint_interval_secs: u64,
    /// Configuration options for skipping unresponsive peers
    #[default(Some(Default::default()))]
    pub skip_unresponsive_peers: Option<FeatureSkipUnresponsivePeers>,
    /// Parameters to optimize battery lifetime
    #[default(Some(Default::default()))]
    pub endpoint_providers_optimization: Option<FeatureEndpointProvidersOptimization>,
}

fn deserialize_providers<'de, D>(de: D) -> Result<Option<EndpointProviders>, D::Error>
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

/// Available Endpoint Providers for meshnet direct connections
#[derive(
    Clone,
    Copy,
    Debug,
    EnumCount,
    IntoPrimitive,
    TryFromPrimitive,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
#[repr(u32)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointProvider {
    /// Use local interface ips as possible endpoints
    Local = 1,
    /// Use stun and wg-stun results as possible endpoints
    Stun = 2,
    /// Use IGD and upnp to generate endpoints
    Upnp = 3,
}

/// Avoid sending periodic messages to peers with no traffic reported by wireguard
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeatureSkipUnresponsivePeers {
    /// Time after which peers is considered unresponsive if it didn't receive any packets
    #[default = 180]
    pub no_rx_threshold_secs: u64,
}

/// Control which battery optimizations are turned on
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeatureEndpointProvidersOptimization {
    /// Controls whether Stun endpoint provider should be turned off when there are no proxying peers
    #[default = true]
    pub optimize_direct_upgrade_stun: bool,
    /// Controls whether Upnp endpoint provider should be turned off when there are no proxying peers
    #[default = true]
    pub optimize_direct_upgrade_upnp: bool,
}

/// Configure derp behaviour
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureDerp {
    /// Tcp keepalive set on derp server's side [default 15s]
    pub tcp_keepalive: Option<u32>,
    /// Derp will send empty messages after this many seconds of not sending/receiving any data [default 60s]
    pub derp_keepalive: Option<u32>,
    /// Enable polling of remote peer states to reduce derp traffic
    pub enable_polling: Option<bool>,
    /// Use Mozilla's root certificates instead of OS ones [default false]
    #[serde(default)]
    pub use_built_in_root_certificates: bool,
}

/// Whether to validate keys
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct FeatureValidateKeys(pub bool);

impl Default for FeatureValidateKeys {
    fn default() -> Self {
        Self(true)
    }
}

/// Feature config for firewall
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct FeatureFirewall {
    /// Turns on connection resets upon VPN server change
    #[serde(default)]
    pub boringtun_reset_conns: bool,
}

/// Turns on post quantum VPN tunnel
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeaturePostQuantumVPN {
    /// Initial handshake retry interval in seconds
    #[default = 8]
    pub handshake_retry_interval_s: u32,

    /// Rekey interval in seconds
    #[default = 90]
    pub rekey_interval_s: u32,
}

/// Turns on the no link detection mechanism
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeatureLinkDetection {
    /// Configurable rtt in seconds
    #[default = 15]
    pub rtt_seconds: u64,

    /// Check the link state before reporting it as down
    #[default = 0]
    pub no_of_pings: u32,

    /// Use link detection for downgrade logic
    #[default = false]
    pub use_for_downgrade: bool,
}

/// Feature configuration for DNS.
#[derive(Default, Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeatureDns {
    /// TTL for SOA record and for A and AAAA records.
    #[serde(default)]
    pub ttl_value: TtlValue,
    /// Configure options for exit dns
    #[serde(default)]
    pub exit_dns: Option<FeatureExitDns>,
}

/// Newtype for TTL value to ensure that the default function returns the actual default value and not 0.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct TtlValue(pub u32);

impl Default for TtlValue {
    fn default() -> Self {
        Self(60)
    }
}

/// Configurable features for exit Dns
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FeatureExitDns {
    /// Controls if it is allowed to reconfigure DNS peer when exit node is
    /// (dis)connected.
    pub auto_switch_dns_ips: Option<bool>,
}

/// PMTU discovery configuration for VPN connection
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
#[serde(default)]
pub struct FeaturePmtuDiscovery {
    /// A timeout for wait for the ICMP response packet
    #[default = 5]
    pub response_wait_timeout_s: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_json {
        ($json_str:expr, $expected:expr, $access_expr:ident . $($access_rest:tt)* ) => {
            {
                assert_json!(Features, $json_str, $expected, $access_expr.$($access_rest)*);
            }
        };
        ($json_str:expr, $expected:expr, $access_expr:ident ) => {
            {
                assert_json!(Features, $json_str, $expected, $access_expr);
            }
        };
        ($t:ty, $json_str:expr, $expected:expr, $access_expr:ident . $($access_rest:tt)* ) => {
            {
                let parsed: $t = serde_json::from_str($json_str).expect("Failed to parse JSON");
                assert_eq!(parsed.$access_expr.$($access_rest)*, $expected);
            }
        };
        ($t:ty, $json_str:expr, $expected:expr, $access_expr:ident ) => {
            {
                let parsed: $t = serde_json::from_str($json_str).expect("Failed to parse JSON");
                assert_eq!(parsed.$access_expr, $expected);
            }
        };
        ($t:ty, $json_str:expr, $expected:expr) => {
            {
                let parsed: $t = serde_json::from_str($json_str).expect("Failed to parse JSON");
                assert_eq!(parsed, $expected);
            }
        };
    }

    mod deserialization {
        use super::*;

        #[test]
        fn test_empty_json() {
            assert_json!(Features, "{}", Features::default());
        }

        #[test]
        fn test_all_fields_with_non_default_values() {
            assert_json!(
                Features,
                r#"
        {
            "wireguard": {
                "persistent_keepalive": {
                    "vpn": 1,
                    "direct": 2,
                    "proxying": 3,
                    "stun": 4
                }
            },
            "nurse": {
                "fingerprint": "test_fingerprint",
                "heartbeat_interval": 5,
                "initial_heartbeat_interval": 6,
                "qos": {
                    "rtt_interval": 7,
                    "rtt_tries": 8,
                    "rtt_types": ["Ping"],
                    "buckets": 9
                },
                "enable_nat_type_collection": true,
                "enable_relay_conn_data": false,
                "enable_nat_traversal_conn_data": false,
                "state_duration_cap": 10
            },
            "lana": {
                "event_path": "some/test/path.db",
                "prod": true
            },
            "paths": {
                "priority": ["direct"],
                "force": "relay"
            },
            "direct": {
                "providers": ["local"],
                "endpoint_interval_secs": 11,
                "skip_unresponsive_peers": {
                    "no_rx_threshold_secs": 12
                },
                "endpoint_providers_optimization": {
                    "optimize_direct_upgrade_stun": false,
                    "optimize_direct_upgrade_upnp": false
                }
            },
            "is_test_env": true,
            "hide_ips": false,
            "derp": {
                "tcp_keepalive": 13,
                "derp_keepalive": 14,
                "enable_polling": true,
                "use_built_in_root_certificates": true
            },
            "validate_keys": false,
            "ipv6": true,
            "nicknames": true,
            "firewall": {
                "boringtun_reset_conns": true
            },
            "flush_events_on_stop_timeout_seconds": 15,
            "post_quantum_vpn": {
                "handshake_retry_interval_s": 15,
                "rekey_interval_s": 16
            },
            "link_detection": {
                "rtt_seconds": 17,
                "no_of_pings": 18,
                "use_for_downgrade": true
            },
            "dns": {
                "ttl_value": 19,
                "exit_dns": {
                    "auto_switch_dns_ips": true
                }
            },
            "pmtu_discovery": {
                "response_wait_timeout_s": 20
            },
            "multicast": true,
            "batching": {
                "direct_connection_threshold": 60
            }
        }
        "#,
                Features {
                    wireguard: FeatureWireguard {
                        persistent_keepalive: FeaturePersistentKeepalive {
                            vpn: Some(1),
                            direct: 2,
                            proxying: Some(3),
                            stun: Some(4),
                        },
                    },
                    nurse: Some(FeatureNurse {
                        heartbeat_interval: 5,
                        initial_heartbeat_interval: 6,
                        qos: Some(FeatureQoS {
                            rtt_interval: 7,
                            rtt_tries: 8,
                            rtt_types: vec![RttType::Ping],
                            buckets: 9,
                        }),
                        enable_nat_type_collection: true,
                        enable_relay_conn_data: false,
                        enable_nat_traversal_conn_data: false,
                        state_duration_cap: 10,
                    }),
                    lana: Some(FeatureLana {
                        event_path: "some/test/path.db".to_owned(),
                        prod: true,
                    }),
                    paths: Some(FeaturePaths {
                        priority: vec![PathType::Direct],
                        force: Some(PathType::Relay),
                    }),
                    direct: Some(FeatureDirect {
                        providers: Some([EndpointProvider::Local].iter().copied().collect()),
                        endpoint_interval_secs: 11,
                        skip_unresponsive_peers: Some(FeatureSkipUnresponsivePeers {
                            no_rx_threshold_secs: 12,
                        }),
                        endpoint_providers_optimization: Some(
                            FeatureEndpointProvidersOptimization {
                                optimize_direct_upgrade_stun: false,
                                optimize_direct_upgrade_upnp: false,
                            }
                        ),
                    }),
                    is_test_env: Some(true),
                    hide_ips: false,
                    derp: Some(FeatureDerp {
                        tcp_keepalive: Some(13),
                        derp_keepalive: Some(14),
                        enable_polling: Some(true),
                        use_built_in_root_certificates: true,
                    }),
                    validate_keys: FeatureValidateKeys(false),
                    ipv6: true,
                    nicknames: true,
                    firewall: FeatureFirewall {
                        boringtun_reset_conns: true,
                    },
                    flush_events_on_stop_timeout_seconds: Some(15),
                    post_quantum_vpn: FeaturePostQuantumVPN {
                        handshake_retry_interval_s: 15,
                        rekey_interval_s: 16,
                    },
                    link_detection: Some(FeatureLinkDetection {
                        rtt_seconds: 17,
                        no_of_pings: 18,
                        use_for_downgrade: true,
                    }),
                    dns: FeatureDns {
                        ttl_value: TtlValue(19),
                        exit_dns: Some(FeatureExitDns {
                            auto_switch_dns_ips: Some(true),
                        }),
                    },
                    pmtu_discovery: Some(FeaturePmtuDiscovery {
                        response_wait_timeout_s: 20,
                    }),
                    multicast: true,
                    batching: Some(FeatureBatching {
                        direct_connection_threshold: 60,
                    }),
                }
            );
        }

        #[test]
        fn test_empty_wireguard() {
            assert_json!(
                r#"{"wireguard": {}}"#,
                FeatureWireguard::default(),
                wireguard
            );
        }

        #[test]
        fn test_empty_wireguard_persistent_keepalive() {
            assert_json!(
                r#"{"wireguard": {"persistent_keepalive": {}}}"#,
                FeaturePersistentKeepalive::default(),
                wireguard.persistent_keepalive
            );
        }

        #[test]
        fn test_empty_nurse() {
            assert_json!(
                r#"{"nurse": {"fingerprint": ""}}"#,
                FeatureNurse::default(),
                nurse.unwrap()
            );
        }

        #[test]
        fn test_empty_nurse_qos() {
            assert_json!(
                r#"{"nurse": {"fingerprint": "", "qos": {}}}"#,
                FeatureQoS::default(),
                nurse.unwrap().qos.unwrap()
            );
        }

        #[test]
        fn test_empty_paths() {
            assert_json!(
                r#"{"paths": {"priority": []}}"#,
                FeaturePaths::default(),
                paths.unwrap()
            );
        }

        #[test]
        fn test_empty_direct() {
            assert_json!(
                r#"{"direct": {}}"#,
                FeatureDirect::default(),
                direct.unwrap()
            );
        }

        #[test]
        fn test_empty_direct_skip_unresponsive_peers() {
            assert_json!(
                r#"{"direct": {"skip_unresponsive_peers": {}}}"#,
                FeatureSkipUnresponsivePeers::default(),
                direct.unwrap().skip_unresponsive_peers.unwrap()
            );
        }

        #[test]
        fn test_empty_direct_endpoint_providers_optimization() {
            assert_json!(
                r#"{"direct": {"endpoint_providers_optimization": {}}}"#,
                FeatureEndpointProvidersOptimization::default(),
                direct.unwrap().endpoint_providers_optimization.unwrap()
            );
        }

        #[test]
        fn test_empty_derp() {
            assert_json!(r#"{"derp": {}}"#, FeatureDerp::default(), derp.unwrap());
        }

        #[test]
        fn test_empty_firewall() {
            assert_json!(r#"{"firewall": {}}"#, FeatureFirewall::default(), firewall);
        }

        #[test]
        fn test_empty_post_quantum_vpn() {
            assert_json!(
                r#"{"post_quantum_vpn": {}}"#,
                FeaturePostQuantumVPN::default(),
                post_quantum_vpn
            );
        }

        #[test]
        fn test_empty_link_detection() {
            assert_json!(
                r#"{"link_detection": {}}"#,
                FeatureLinkDetection::default(),
                link_detection.unwrap()
            );
        }

        #[test]
        fn test_empty_dns() {
            assert_json!(r#"{"dns": {}}"#, FeatureDns::default(), dns);
        }

        #[test]
        fn test_empty_dns_exit_dns() {
            assert_json!(
                r#"{"dns": {"exit_dns": {}}}"#,
                FeatureExitDns::default(),
                dns.exit_dns.unwrap()
            );
        }

        #[test]
        fn test_empty_pmtu_discovery() {
            assert_json!(
                r#"{"pmtu_discovery": {}}"#,
                FeaturePmtuDiscovery::default(),
                pmtu_discovery.unwrap()
            );
        }

        #[test]
        fn test_json_direct_accepts_arbitrary_providers() {
            assert_json!(
                FeatureDirect,
                r#"{"providers": ["local", "stun", "stun", "stun", "other", "none"]}"#,
                FeatureDirect {
                    providers: Some(
                        vec![EndpointProvider::Local, EndpointProvider::Stun]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                }
            );
        }

        #[test]
        fn test_json_allow_null_for_wireguard() {
            assert_json!(
                r#"{"wireguard": null}"#,
                FeatureWireguard::default(),
                wireguard
            );
        }

        #[test]
        fn test_hide_ips() {
            assert_json!(r#"{}"#, true, hide_ips);
            assert_json!(r#"{"hide_ips": false}"#, false, hide_ips);
            assert_json!(r#"{"hide_ips": true}"#, true, hide_ips);
        }
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
