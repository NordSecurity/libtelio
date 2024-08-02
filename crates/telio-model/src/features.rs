//! Object descriptions of various
//! telio configurable features via API

use std::{collections::HashSet, fmt};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serialize};
use smart_default::SmartDefault;
use strum_macros::EnumCount;
use telio_utils::telio_log_warn;

/// Default keepalive period used for proxying peers,
/// STUN servers and VPN servers
pub const DEFAULT_PERSISTENT_KEEPALIVE_PERIOD: u32 = 25;

/// Default keepalive period for direct peers
pub const DEFAULT_DIRECT_PERSISTENT_KEEPALIVE_PERIOD: u32 = 5;

/// Endpoint polling interval
pub const DEFAULT_ENDPOINT_POLL_INTERVAL_SECS: u64 = 25;

/// Type alias for UniFFI
pub type EndpointProviders = HashSet<EndpointProvider>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, SmartDefault)]
/// Encompasses all of the possible features that can be enabled
pub struct Features {
    /// Additional wireguard configuration
    #[serde(default, deserialize_with = "FeatureWireguard::default_on_null")]
    pub wireguard: FeatureWireguard,
    /// Nurse features that can be configured for QoS
    #[serde(default = "Features::default_nurse")]
    #[default(Features::default_nurse())]
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
    /// Derp server specific configuration
    pub derp: Option<FeatureDerp>,
    /// Flag to specify if keys should be validated
    #[serde(default)]
    pub validate_keys: FeatureValidateKeys,
    /// IPv6 support
    #[serde(default)]
    pub ipv6: bool,
    /// Nicknames support
    #[serde(default)]
    pub nicknames: bool,
    /// Flag to turn on connection reset upon VPN server change for boringtun adapter
    #[serde(default)]
    pub firewall: FeatureFirewall,
    /// If and for how long to flush events when stopping telio. Setting to Some(0) means waiting until all events have been flushed, regardless of how long it takes
    pub flush_events_on_stop_timeout_seconds: Option<u64>,
    /// Post quantum VPN tunnel configuration
    #[serde(default)]
    pub post_quantum_vpn: FeaturePostQuantumVPN,
    /// No link detection mechanism
    #[serde(default)]
    pub link_detection: Option<FeatureLinkDetection>,
    /// Feature configuration for DNS.
    #[serde(default)]
    pub dns: FeatureDns,
    /// PMTU discovery configuration, enabled by default
    #[serde(default = "FeaturePmtuDiscovery::serde_default")]
    #[default(FeaturePmtuDiscovery::serde_default())]
    pub pmtu_discovery: Option<FeaturePmtuDiscovery>,
    /// Multicast support
    #[serde(default)]
    pub multicast: bool,
}

impl Features {
    fn default_nurse() -> Option<FeatureNurse> {
        Some(Default::default())
    }
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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeaturePersistentKeepalive {
    /// Persistent keepalive period given for VPN peers (in seconds) [default 15s]
    #[serde(default = "FeaturePersistentKeepalive::default_keepalive_period")]
    pub vpn: Option<u32>,

    /// Persistent keepalive period for direct peers (in seconds) [default 5s]
    #[serde(default = "FeaturePersistentKeepalive::default_direct_keepalive_period")]
    pub direct: u32,

    /// Persistent keepalive period for proxying peers (in seconds) [default 25s]
    #[serde(default = "FeaturePersistentKeepalive::default_keepalive_period")]
    pub proxying: Option<u32>,

    /// Persistent keepalive period for stun peers (in seconds) [default 25s]
    #[serde(default = "FeaturePersistentKeepalive::default_keepalive_period")]
    pub stun: Option<u32>,
}

impl FeaturePersistentKeepalive {
    fn default_keepalive_period() -> Option<u32> {
        Some(DEFAULT_PERSISTENT_KEEPALIVE_PERIOD)
    }

    fn default_direct_keepalive_period() -> u32 {
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

/// Configurable features for Nurse module
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeatureNurse {
    /// Heartbeat interval in seconds. Default value is 3600.
    #[serde(default = "FeatureNurse::default_heartbeat_interval")]
    pub heartbeat_interval: u64,
    /// Initial heartbeat interval in seconds. Default value is 300.
    #[serde(default = "FeatureNurse::default_initial_heartbeat_interval")]
    pub initial_heartbeat_interval: u64,
    /// QoS configuration for Nurse. Enabled by default.
    #[serde(default = "FeatureNurse::default_qos")]
    pub qos: Option<FeatureQoS>,
    /// Enable/disable collecting nat type. Disabled by default.
    #[serde(default = "FeatureNurse::default_enable_nat_type_collection")]
    pub enable_nat_type_collection: bool,
    /// Enable/disable Relay connection data. Enabled by default.
    #[serde(default = "FeatureNurse::default_enable_relay_conn_data")]
    pub enable_relay_conn_data: bool,
    /// Enable/disable NAT-traversal connections data. Enabled by default.
    #[serde(default = "FeatureNurse::default_enable_nat_traversal_conn_data")]
    pub enable_nat_traversal_conn_data: bool,
    /// How long a session can be before it is forcibly reported, in seconds. Default value is 24h.
    #[serde(default = "FeatureNurse::default_state_duration_cap_in_seconds")]
    pub state_duration_cap: u64,
}

impl FeatureNurse {
    fn default_heartbeat_interval() -> u64 {
        60 * 60
    }

    fn default_initial_heartbeat_interval() -> u64 {
        5 * 60
    }

    fn default_qos() -> Option<FeatureQoS> {
        Some(Default::default())
    }

    fn default_enable_nat_type_collection() -> bool {
        false
    }

    fn default_enable_relay_conn_data() -> bool {
        true
    }

    fn default_enable_nat_traversal_conn_data() -> bool {
        true
    }

    // The state duration cap was originally hardcoded at 24h, which is now the default value
    fn default_state_duration_cap_in_seconds() -> u64 {
        60 * 60 * 24
    }
}

impl Default for FeatureNurse {
    fn default() -> Self {
        Self {
            heartbeat_interval: Self::default_heartbeat_interval(),
            initial_heartbeat_interval: Self::default_initial_heartbeat_interval(),
            qos: Self::default_qos(),
            enable_nat_type_collection: Self::default_enable_nat_type_collection(),
            enable_relay_conn_data: Self::default_enable_relay_conn_data(),
            enable_nat_traversal_conn_data: Self::default_enable_nat_traversal_conn_data(),
            state_duration_cap: Self::default_state_duration_cap_in_seconds(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
/// QoS configuration options
pub struct FeatureQoS {
    /// How often to collect rtt data in seconds. Default value is 300.
    #[serde(default = "FeatureQoS::default_rtt_interval")]
    pub rtt_interval: u64,
    /// Number of tries for each node. Default value is 3.
    #[serde(default = "FeatureQoS::default_rtt_tries")]
    pub rtt_tries: u32,
    /// Types of rtt analytics. Default is Ping.
    #[serde(default = "FeatureQoS::default_rtt_types")]
    pub rtt_types: Vec<RttType>,
    /// Number of buckets used for rtt and throughput. Default value is 5.
    #[serde(default = "FeatureQoS::default_buckets")]
    pub buckets: u32,
}

impl FeatureQoS {
    fn default_rtt_interval() -> u64 {
        5 * 60
    }

    fn default_rtt_tries() -> u32 {
        3
    }

    fn default_rtt_types() -> Vec<RttType> {
        vec![RttType::Ping]
    }

    fn default_buckets() -> u32 {
        5
    }
}

impl Default for FeatureQoS {
    fn default() -> Self {
        Self {
            rtt_interval: FeatureQoS::default_rtt_interval(),
            rtt_tries: FeatureQoS::default_rtt_tries(),
            rtt_types: FeatureQoS::default_rtt_types(),
            buckets: FeatureQoS::default_buckets(),
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeatureDirect {
    /// Endpoint providers [default all]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_providers")]
    pub providers: Option<EndpointProviders>,
    /// Polling interval for endpoints [default 10s]
    pub endpoint_interval_secs: Option<u64>,
    /// Configuration options for skipping unresponsive peers
    #[serde(default = "FeatureDirect::default_skip_unresponsive_peers")]
    pub skip_unresponsive_peers: Option<FeatureSkipUnresponsivePeers>,
    /// Parameters to optimize battery lifetime
    #[serde(default)]
    pub endpoint_providers_optimization: Option<FeatureEndpointProvidersOptimization>,
}

impl FeatureDirect {
    fn default_skip_unresponsive_peers() -> Option<FeatureSkipUnresponsivePeers> {
        Some(Default::default())
    }
}

impl Default for FeatureDirect {
    fn default() -> Self {
        Self {
            providers: Default::default(),
            endpoint_interval_secs: Default::default(),
            skip_unresponsive_peers: Self::default_skip_unresponsive_peers(),
            endpoint_providers_optimization: Default::default(),
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeatureSkipUnresponsivePeers {
    /// Time after which peers is considered unresponsive if it didn't receive any packets
    #[serde(default = "FeatureSkipUnresponsivePeers::default_no_rx_threshold_secs")]
    pub no_rx_threshold_secs: u64,
}

impl FeatureSkipUnresponsivePeers {
    const fn default_no_rx_threshold_secs() -> u64 {
        180
    }
}

impl Default for FeatureSkipUnresponsivePeers {
    fn default() -> Self {
        Self {
            no_rx_threshold_secs: Self::default_no_rx_threshold_secs(),
        }
    }
}

/// Control which battery optimizations are turned on
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeatureEndpointProvidersOptimization {
    /// Controls whether Stun endpoint provider should be turned off when there are no proxying peers
    #[serde(default = "FeatureEndpointProvidersOptimization::default_optimization_variant")]
    pub optimize_direct_upgrade_stun: bool,
    /// Controls whether Upnp endpoint provider should be turned off when there are no proxying peers
    #[serde(default = "FeatureEndpointProvidersOptimization::default_optimization_variant")]
    pub optimize_direct_upgrade_upnp: bool,
}

impl FeatureEndpointProvidersOptimization {
    /// Turning optimizations on by default if feature itself is enabled
    pub fn default_optimization_variant() -> bool {
        true
    }
}

impl Default for FeatureEndpointProvidersOptimization {
    fn default() -> Self {
        Self {
            optimize_direct_upgrade_stun: true,
            optimize_direct_upgrade_upnp: true,
        }
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct FeaturePostQuantumVPN {
    /// Initial handshake retry interval in seconds
    #[serde(default = "FeaturePostQuantumVPN::default_handshake_retry_interval_s")]
    pub handshake_retry_interval_s: u32,

    /// Rekey interval in seconds
    #[serde(default = "FeaturePostQuantumVPN::default_rekey_interval_s")]
    pub rekey_interval_s: u32,
}

impl FeaturePostQuantumVPN {
    const fn default_handshake_retry_interval_s() -> u32 {
        8
    }

    const fn default_rekey_interval_s() -> u32 {
        90
    }
}

impl Default for FeaturePostQuantumVPN {
    fn default() -> Self {
        Self {
            handshake_retry_interval_s: Self::default_handshake_retry_interval_s(),
            rekey_interval_s: Self::default_rekey_interval_s(),
        }
    }
}

/// Turns on the no link detection mechanism
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeatureLinkDetection {
    /// Configurable rtt in seconds
    #[serde(default = "FeatureLinkDetection::default_configurable_rtt")]
    pub rtt_seconds: u64,

    /// Check the link state before reporting it as down
    #[serde(default = "FeatureLinkDetection::default_no_of_pings")]
    pub no_of_pings: u32,

    /// Use link detection for downgrade logic
    #[serde(default = "FeatureLinkDetection::default_use_for_downgrade")]
    pub use_for_downgrade: bool,
}

impl FeatureLinkDetection {
    const fn default_configurable_rtt() -> u64 {
        15
    }

    const fn default_no_of_pings() -> u32 {
        0
    }

    const fn default_use_for_downgrade() -> bool {
        false
    }
}

impl Default for FeatureLinkDetection {
    fn default() -> Self {
        Self {
            rtt_seconds: Self::default_configurable_rtt(),
            no_of_pings: Self::default_no_of_pings(),
            use_for_downgrade: Self::default_use_for_downgrade(),
        }
    }
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FeaturePmtuDiscovery {
    /// A timeout for wait for the ICMP response packet
    #[serde(default = "FeaturePmtuDiscovery::default_response_wait_timeout_s")]
    pub response_wait_timeout_s: u32,
}

impl FeaturePmtuDiscovery {
    const fn default_response_wait_timeout_s() -> u32 {
        5
    }

    fn serde_default() -> Option<Self> {
        Some(Self::default())
    }
}

impl Default for FeaturePmtuDiscovery {
    fn default() -> Self {
        Self {
            response_wait_timeout_s: Self::default_response_wait_timeout_s(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::from_str;

    use super::*;

    mod deserialization {
        use super::*;

        #[test]
        fn test_empty_json() {
            let json = "{}";
            let features = from_str::<Features>(json).unwrap();
            assert_eq!(features, Features::default());
        }

        #[test]
        fn test_all_fields_with_non_default_values() {
            let json = r#"
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
            "multicast": true
        }
        "#;
            let actual = from_str::<Features>(json).unwrap();

            let mut endpoint_providers = HashSet::new();
            endpoint_providers.insert(EndpointProvider::Local);
            let expected = Features {
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
                    providers: Some(endpoint_providers),
                    endpoint_interval_secs: Some(11),
                    skip_unresponsive_peers: Some(FeatureSkipUnresponsivePeers {
                        no_rx_threshold_secs: 12,
                    }),
                    endpoint_providers_optimization: Some(FeatureEndpointProvidersOptimization {
                        optimize_direct_upgrade_stun: false,
                        optimize_direct_upgrade_upnp: false,
                    }),
                }),
                is_test_env: Some(true),
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
            };

            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_wireguard() {
            let json = r#"{"wireguard": {}}"#;
            let actual = from_str::<Features>(json).unwrap().wireguard;
            let expected = FeatureWireguard::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_wireguard_persistent_keepalive() {
            let json = r#"{"wireguard": {"persistent_keepalive": {}}}"#;
            let actual = from_str::<Features>(json)
                .unwrap()
                .wireguard
                .persistent_keepalive;
            let expected = FeaturePersistentKeepalive::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_nurse() {
            let json = r#"{"nurse": {"fingerprint": ""}}"#;
            let actual = from_str::<Features>(json).unwrap().nurse.unwrap();
            let expected = FeatureNurse::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_nurse_qos() {
            let json = r#"{"nurse": {"fingerprint": "", "qos": {}}}"#;
            let actual = from_str::<Features>(json)
                .unwrap()
                .nurse
                .unwrap()
                .qos
                .unwrap();
            let expected = FeatureQoS::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_paths() {
            let json = r#"{"paths": {"priority": []}}"#;
            let actual = from_str::<Features>(json).unwrap().paths.unwrap();
            let expected = FeaturePaths::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_direct() {
            let json = r#"{"direct": {}}"#;
            let actual = from_str::<Features>(json).unwrap().direct.unwrap();
            let expected = FeatureDirect::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_direct_skip_unresponsive_peers() {
            let json = r#"{"direct": {"skip_unresponsive_peers": {}}}"#;
            let actual = from_str::<Features>(json)
                .unwrap()
                .direct
                .unwrap()
                .skip_unresponsive_peers
                .unwrap();
            let expected = FeatureSkipUnresponsivePeers::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_direct_endpoint_providers_optimization() {
            let json = r#"{"direct": {"endpoint_providers_optimization": {}}}"#;
            let actual = from_str::<Features>(json)
                .unwrap()
                .direct
                .unwrap()
                .endpoint_providers_optimization
                .unwrap();
            let expected = FeatureEndpointProvidersOptimization::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_derp() {
            let json = r#"{"derp": {}}"#;
            let actual = from_str::<Features>(json).unwrap().derp.unwrap();
            let expected = FeatureDerp::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_firewall() {
            let json = r#"{"firewall": {}}"#;
            let actual = from_str::<Features>(json).unwrap().firewall;
            let expected = FeatureFirewall::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_post_quantum_vpn() {
            let json = r#"{"post_quantum_vpn": {}}"#;
            let actual = from_str::<Features>(json).unwrap().post_quantum_vpn;
            let expected = FeaturePostQuantumVPN::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_link_detection() {
            let json = r#"{"link_detection": {}}"#;
            let actual = from_str::<Features>(json).unwrap().link_detection.unwrap();
            let expected = FeatureLinkDetection::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_dns() {
            let json = r#"{"dns": {}}"#;
            let actual = from_str::<Features>(json).unwrap().dns;
            let expected = FeatureDns::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_dns_exit_dns() {
            let json = r#"{"dns": {"exit_dns": {}}}"#;
            let actual = from_str::<Features>(json).unwrap().dns.exit_dns.unwrap();
            let expected = FeatureExitDns::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_empty_pmtu_discovery() {
            let json = r#"{"pmtu_discovery": {}}"#;
            let actual = from_str::<Features>(json).unwrap().pmtu_discovery.unwrap();
            let expected = FeaturePmtuDiscovery::default();
            assert_eq!(actual, expected);
        }

        #[test]
        fn test_json_direct_accepts_arbitrary_providers() {
            let json = r#"{"providers": ["local", "stun", "stun", "stun", "other", "none"]}"#;

            let actual = from_str::<FeatureDirect>(json).unwrap();
            let expected = FeatureDirect {
                providers: Some(
                    vec![EndpointProvider::Local, EndpointProvider::Stun]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            };

            assert_eq!(actual, expected);
        }

        #[test]
        fn test_json_allow_null_for_wireguard() {
            let json = r#"{"wireguard": null}"#;
            let actual = from_str::<Features>(json).unwrap().wireguard;
            let expected = FeatureWireguard::default();
            assert_eq!(actual, expected);
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
