//! Object descriptions of various
//! telio configurable features via API

use std::{collections::HashSet, fmt, net::IpAddr, str::FromStr, time::Duration};

use base64::{prelude::BASE64_STANDARD, Engine};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serialize};
use smart_default::SmartDefault;
use strum_macros::EnumCount;
use telio_utils::{exponential_backoff::ExponentialBackoffBounds, telio_log_warn};

/// Type alias for UniFFI
pub type EndpointProviders = HashSet<EndpointProvider>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
    /// Control if IP addresses and domains should be hidden in logs
    #[serde(alias = "hide_ips")] // Old name
    #[default(true)]
    pub hide_user_data: bool,
    /// Control if thread IDs should be shown in the logs
    #[default(true)]
    pub hide_thread_id: bool,
    /// Derp server specific configuration
    pub derp: Option<FeatureDerp>,
    /// Flag to specify if keys should be validated
    pub validate_keys: FeatureValidateKeys,
    /// IPv6 support
    pub ipv6: bool,
    /// Nicknames support
    pub nicknames: bool,
    /// Firewall configuration. When None, the firewall is disabled.
    pub firewall: Option<FeatureFirewall>,
    /// If and for how long to flush events when stopping telio. Setting to Some(0) means waiting until all events have been flushed, regardless of how long it takes
    pub flush_events_on_stop_timeout_seconds: Option<u64>,
    /// Post quantum VPN tunnel configuration
    pub post_quantum_vpn: FeaturePostQuantumVPN,
    /// No link detection mechanism
    pub link_detection: Option<FeatureLinkDetection>,
    /// Feature configuration for DNS.
    pub dns: FeatureDns,
    /// Multicast support
    pub multicast: bool,
    /// Configuration for the Error Notification Service
    pub error_notification_service: Option<FeatureErrorNotificationService>,
}

impl Features {
    /// Serialize the features to a json string
    pub fn serialize(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Configurable features for Wireguard peers
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureWireguard {
    /// Configurable persistent keepalive periods for wireguard peers
    #[serde(default)]
    pub persistent_keepalive: FeaturePersistentKeepalive,
    /// Configurable wireguard polling period
    #[serde(default)]
    pub polling: FeaturePolling,
    /// Configurable up/down behavior of WireGuard-NT adapter. See RFC LLT-0089 for details
    #[serde(default)]
    pub enable_dynamic_wg_nt_control: bool,
    /// Configurable socket buffer size for NepTUN
    #[serde(default)]
    pub skt_buffer_size: Option<u32>,
    /// Configurable socket buffer size for NepTUN
    #[serde(default)]
    pub inter_thread_channel_size: Option<u32>,
    /// Configurable socket buffer size for NepTUN
    #[serde(default)]
    pub max_inter_thread_batched_pkts: Option<u32>,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeaturePersistentKeepalive {
    /// Persistent keepalive period given for VPN peers (in seconds) [default 25s]
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

/// Configurable Wireguard polling period
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeaturePolling {
    /// Wireguard state polling period (in milliseconds) [default 1000ms]
    #[default(1000)]
    pub wireguard_polling_period: u32,
    /// Wireguard state polling period after state change (in milliseconds) [default 50ms]
    #[default(50)]
    pub wireguard_polling_period_after_state_change: u32,
}

/// Configurable features for Nurse module
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
/// QoS configuration options
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[repr(u32)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum RttType {
    /// Simple ping request.
    Ping,
}

/// Configurable features for Lana module
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum PathType {
    /// Nodes connected via a middle-man relay
    #[default]
    Relay,
    /// Nodes connected directly via WG
    Direct,
}

/// Enable meshent direct connection
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureDirect {
    /// Endpoint providers [default all]
    #[serde(deserialize_with = "deserialize_providers")]
    pub providers: Option<EndpointProviders>,
    /// Polling interval for endpoints [default 25s]
    #[default = 25]
    pub endpoint_interval_secs: u64,
    /// Configuration options for skipping unresponsive peers
    #[default(Some(Default::default()))]
    pub skip_unresponsive_peers: Option<FeatureSkipUnresponsivePeers>,
    /// Parameters to optimize battery lifetime
    #[default(Some(Default::default()))]
    pub endpoint_providers_optimization: Option<FeatureEndpointProvidersOptimization>,
    /// Configurable features for UPNP endpoint provider
    #[default(Some(Default::default()))]
    pub upnp_features: Option<FeatureUpnp>,
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
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EndpointProvider {
    /// Use local interface ips as possible endpoints
    Local = 1,
    /// Use stun and wg-stun results as possible endpoints
    Stun = 2,
    /// Use IGD and upnp to generate endpoints
    Upnp = 3,
}

/// Avoid sending periodic messages to peers with no traffic reported by wireguard
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureSkipUnresponsivePeers {
    /// Time after which peers is considered unresponsive if it didn't receive any packets
    #[default = 180]
    pub no_rx_threshold_secs: u64,
}

/// Control which battery optimizations are turned on
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureEndpointProvidersOptimization {
    /// Controls whether Stun endpoint provider should be turned off when there are no proxying peers
    #[default = true]
    pub optimize_direct_upgrade_stun: bool,
    /// Controls whether Upnp endpoint provider should be turned off when there are no proxying peers
    #[default = true]
    pub optimize_direct_upgrade_upnp: bool,
}

/// Configure derp behaviour
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureDerp {
    /// Tcp keepalive set on derp server's side [default 15s]
    pub tcp_keepalive: Option<u32>,
    /// Derp will send empty messages after this many seconds of not sending/receiving any data [default 60s]
    pub derp_keepalive: Option<u32>,
    /// Poll Keepalive: Application level keepalives meant to replace the TCP keepalives
    /// They will use derp_keepalive as interval
    #[serde(default)]
    pub poll_keepalive: Option<bool>,
    /// Enable polling of remote peer states to reduce derp traffic
    pub enable_polling: Option<bool>,
    /// Use Mozilla's root certificates instead of OS ones [default false]
    #[serde(default)]
    pub use_built_in_root_certificates: bool,
}

/// Whether to validate keys
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureValidateKeys(pub bool);

impl Default for FeatureValidateKeys {
    fn default() -> Self {
        Self(true)
    }
}

/// Next layer protocol for IP packet
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum IpProtocol {
    /// UDP protocol
    UDP,
    /// TCP protocol
    TCP,
}

/// Tuple used to blacklist outgoing connections in Telio firewall
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FirewallBlacklistTuple {
    /// Protocol of the packet to be blacklisted
    pub protocol: IpProtocol,
    /// Destination IP address of the packet
    pub ip: IpAddr,
    /// Destination port of the packet
    pub port: u16,
}

/// Ip v4 network representation
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Ipv4Net(#[cfg_attr(test, proptest(strategy = "ipv4_net_strategy()"))] ipnet::Ipv4Net);

impl From<Ipv4Net> for ipnet::Ipv4Net {
    fn from(value: Ipv4Net) -> Self {
        value.0
    }
}

impl From<ipnet::Ipv4Net> for Ipv4Net {
    fn from(value: ipnet::Ipv4Net) -> Self {
        Self(value)
    }
}

impl FromStr for Ipv4Net {
    type Err = ipnet::AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
fn ipv4_net_strategy() -> impl proptest::strategy::Strategy<Value = ipnet::Ipv4Net> {
    use proptest::prelude::*;
    let prefix = 0u8..=32; // This is a requirement checked in the Ipv4Net::new
    let addr = any::<u32>();
    (addr, prefix).prop_map(|(addr, prefix)| ipnet::Ipv4Net::new(addr.into(), prefix).unwrap())
}

/// Feature config for firewall
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureFirewall {
    /// Turns on connection resets upon VPN server change
    #[serde(default)]
    pub neptun_reset_conns: bool,
    /// Turns on connection resets upon VPN server change (Deprecated alias for neptun_reset_conns)
    #[serde(default)]
    pub boringtun_reset_conns: bool,
    /// Customizable private IP range to treat certain private IP ranges
    /// as public IPs for testing purposes.
    pub exclude_private_ip_range: Option<Ipv4Net>,
    /// Blackist for outgoing connections
    #[serde(default)]
    pub outgoing_blacklist: Vec<FirewallBlacklistTuple>,
}

impl FeatureFirewall {
    /// For legacy reasons, this struct has two fields that have to coexist even though they mean the same thing
    /// This function gives you the relevant value of those fields without having to check both
    ///
    /// Note: Use this function instead of direct field access
    pub fn neptun_reset_conns(&self) -> bool {
        self.neptun_reset_conns || self.boringtun_reset_conns
    }
}

/// Turns on post quantum VPN tunnel
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeaturePostQuantumVPN {
    /// Initial handshake retry interval in seconds
    #[default = 8]
    pub handshake_retry_interval_s: u32,

    /// Rekey interval in seconds
    #[default = 90]
    pub rekey_interval_s: u32,

    /// Post-quantum protocol version, currently supported versions: 1, 2
    #[default = 1]
    pub version: u32,
}

/// Turns on the no link detection mechanism
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureLinkDetection {
    /// Configurable rtt in seconds
    #[default = 15]
    pub rtt_seconds: u64,

    /// Use link detection for downgrade logic
    #[default = false]
    pub use_for_downgrade: bool,
}

/// Feature configuration for DNS.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureDns {
    /// TTL for SOA record and for A and AAAA records.
    #[serde(default)]
    pub ttl_value: TtlValue,
    /// Configure options for exit dns
    #[serde(default)]
    pub exit_dns: Option<FeatureExitDns>,
}

/// Newtype for TTL value to ensure that the default function returns the actual default value and not 0.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct TtlValue(pub u32);

impl Default for TtlValue {
    fn default() -> Self {
        Self(60)
    }
}

/// Configurable features for exit Dns
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureExitDns {
    /// Controls if it is allowed to reconfigure DNS peer when exit node is
    /// (dis)connected.
    pub auto_switch_dns_ips: Option<bool>,
}

/// Configurable features for UPNP endpoint provider
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureUpnp {
    /// The upnp lease_duration parameter, in seconds. A value of 0 is infinite. Default: 3600
    #[default = 3600]
    pub lease_duration_s: u32,
}

/// Configuration for the Error Notification Service
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[serde(default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct FeatureErrorNotificationService {
    /// Size of the internal queue of received and to-be-published vpn error notifications
    #[default = 5]
    pub buffer_size: u32,

    /// Allow only post-quantum safe key exchange algorithm for the ENS HTTPS connection
    #[default = true]
    pub allow_only_pq: bool,

    /// Configuration of the backoff algorithm used by ENS
    #[serde(default)]
    pub backoff: Backoff,

    /// DER encoded root certificate to be used for verification of all TLS connections
    /// to gRPC ENS endpoint in place of the hardcoded one
    pub root_certificate_override: Option<Vec<u8>>,
}

impl std::fmt::Debug for FeatureErrorNotificationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FeatureErrorNotificationService")
            .field("buffer_size", &self.buffer_size)
            .field("allow_only_pq", &self.allow_only_pq)
            .field("backoff", &self.backoff)
            .field(
                "root_certificate_override",
                &self
                    .root_certificate_override
                    .as_ref()
                    .map(|cert| BASE64_STANDARD.encode(cert)),
            )
            .finish()
    }
}

/// Exponential backoff bounds
///
/// A pair of bounds for the exponential backoffs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, SmartDefault)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Backoff {
    /// Initial bound
    ///
    /// Used as the first backoff value after ExponentialBackoff creation or reset
    #[default(2)]
    pub initial_s: u32,
    /// Maximal bound
    ///
    /// A maximal backoff value which might be achieved during exponential backoff
    /// - if set to None there will be no upper bound for the penalty duration
    #[default(Some(120))]
    #[serde(default = "default_maximal_s")]
    pub maximal_s: Option<u32>,
}

fn default_maximal_s() -> Option<u32> {
    Some(120)
}

impl From<Backoff> for ExponentialBackoffBounds {
    fn from(value: Backoff) -> Self {
        Self {
            initial: Duration::from_secs(value.initial_s as u64),
            maximal: value.maximal_s.map(|m| Duration::from_secs(m as u64)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

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
                },
                "polling": {
                    "wireguard_polling_period": 1000,
                    "wireguard_polling_period_after_state_change": 50
                },
                "enable_dynamic_wg_nt_control": true,
                "skt_buffer_size": 123456,
                "inter_thread_channel_size": 123456,
                "max_inter_thread_batched_pkts": 123456
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
                },
                "upnp_features": {
                    "lease_duration_s": 60
                }
            },
            "is_test_env": true,
            "hide_user_data": false,
            "hide_thread_id": false,
            "derp": {
                "tcp_keepalive": 13,
                "derp_keepalive": 14,
                "poll_keepalive": true,
                "enable_polling": true,
                "use_built_in_root_certificates": true
            },
            "validate_keys": false,
            "ipv6": true,
            "nicknames": true,
            "firewall": {
                "neptun_reset_conns": true,
                "boringtun_reset_conns": true,
                "exclude_private_ip_range": "74.155.187.240/25",
                "outgoing_blacklist": [{
                    "protocol": "UDP",
                    "ip": "8.8.4.4",
                    "port": 30
                }]
            },
            "flush_events_on_stop_timeout_seconds": 15,
            "post_quantum_vpn": {
                "handshake_retry_interval_s": 15,
                "rekey_interval_s": 16,
                "version": 1
            },
            "link_detection": {
                "rtt_seconds": 17,
                "use_for_downgrade": true
            },
            "dns": {
                "ttl_value": 19,
                "exit_dns": {
                    "auto_switch_dns_ips": true
                }
            },
            "multicast": true,
            "error_notification_service": {
                "buffer_size": 42
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
                        polling: FeaturePolling {
                            wireguard_polling_period: 1000,
                            wireguard_polling_period_after_state_change: 50
                        },
                        enable_dynamic_wg_nt_control: true,
                        skt_buffer_size: Some(123456),
                        inter_thread_channel_size: Some(123456),
                        max_inter_thread_batched_pkts: Some(123456),
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
                        upnp_features: Some(FeatureUpnp {
                            lease_duration_s: 60
                        }),
                    }),
                    is_test_env: Some(true),
                    hide_user_data: false,
                    hide_thread_id: false,
                    derp: Some(FeatureDerp {
                        tcp_keepalive: Some(13),
                        derp_keepalive: Some(14),
                        poll_keepalive: Some(true),
                        enable_polling: Some(true),
                        use_built_in_root_certificates: true,
                    }),
                    validate_keys: FeatureValidateKeys(false),
                    ipv6: true,
                    nicknames: true,
                    firewall: Some(FeatureFirewall {
                        neptun_reset_conns: true,
                        boringtun_reset_conns: true,
                        exclude_private_ip_range: Some(Ipv4Net(
                            "74.155.187.240/25".parse().unwrap()
                        )),
                        outgoing_blacklist: vec![FirewallBlacklistTuple {
                            protocol: IpProtocol::UDP,
                            ip: IpAddr::from_str("8.8.4.4").unwrap(),
                            port: 30,
                        }],
                    }),
                    flush_events_on_stop_timeout_seconds: Some(15),
                    post_quantum_vpn: FeaturePostQuantumVPN {
                        handshake_retry_interval_s: 15,
                        rekey_interval_s: 16,
                        version: 1,
                    },
                    link_detection: Some(FeatureLinkDetection {
                        rtt_seconds: 17,
                        use_for_downgrade: true,
                    }),
                    dns: FeatureDns {
                        ttl_value: TtlValue(19),
                        exit_dns: Some(FeatureExitDns {
                            auto_switch_dns_ips: Some(true),
                        }),
                    },
                    multicast: true,
                    error_notification_service: Some(FeatureErrorNotificationService {
                        buffer_size: 42,
                        allow_only_pq: true,
                        backoff: Default::default(),
                        root_certificate_override: None
                    })
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
        fn test_empty_direct_upnp_features() {
            assert_json!(
                r#"{"direct": {"upnp_features": {}}}"#,
                FeatureUpnp::default(),
                direct.unwrap().upnp_features.unwrap()
            );
        }

        #[test]
        fn test_empty_derp() {
            assert_json!(r#"{"derp": {}}"#, FeatureDerp::default(), derp.unwrap());
        }

        #[test]
        fn test_empty_firewall() {
            assert_json!(
                r#"{"firewall": {}}"#,
                Some(FeatureFirewall::default()),
                firewall
            );
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
        fn test_post_quantum_vpn_version() {
            assert_json!(
                r#"{"post_quantum_vpn": {"version": 2}}"#,
                2,
                post_quantum_vpn.version
            );
        }

        #[test]
        fn test_post_quantum_vpn_version_default() {
            assert_json!(r#"{"post_quantum_vpn": {}}"#, 1, post_quantum_vpn.version);
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
        fn test_hide_user_data() {
            assert_json!(r#"{}"#, true, hide_user_data);
            assert_json!(r#"{"hide_ips": false}"#, false, hide_user_data);
            assert_json!(r#"{"hide_ips": true}"#, true, hide_user_data);
            assert_json!(r#"{"hide_user_data": false}"#, false, hide_user_data);
            assert_json!(r#"{"hide_user_data": true}"#, true, hide_user_data);
        }

        #[test]
        fn test_ens_is_turned_off_by_default() {
            assert_json!(r#"{}"#, None, error_notification_service);
        }

        #[test]
        fn test_ens_backoff() {
            assert_json!(
                r#"{"error_notification_service": {}}"#,
                Some(FeatureErrorNotificationService {
                    buffer_size: 5,
                    allow_only_pq: true,
                    backoff: Backoff {
                        initial_s: 2,
                        maximal_s: Some(120),
                    },
                    root_certificate_override: None,
                }),
                error_notification_service
            );
            assert_json!(
                r#"{"error_notification_service": {
                    "backoff": {
                        "initial_s": 2,
                        "maximal_s": 120
                    }
                }}"#,
                Some(FeatureErrorNotificationService {
                    buffer_size: 5,
                    allow_only_pq: true,
                    backoff: Default::default(),
                    root_certificate_override: None,
                }),
                error_notification_service
            );
            assert_json!(
                r#"{"error_notification_service": {
                    "backoff": {
                        "initial_s": 42
                    }
                }}"#,
                Some(FeatureErrorNotificationService {
                    buffer_size: 5,
                    allow_only_pq: true,
                    backoff: Backoff {
                        initial_s: 42,
                        maximal_s: Some(120),
                    },
                    root_certificate_override: None,
                }),
                error_notification_service
            );
            assert_json!(
                r#"{"error_notification_service": {
                    "backoff": {
                        "initial_s": 42,
                        "maximal_s": null
                    }
                }}"#,
                Some(FeatureErrorNotificationService {
                    buffer_size: 5,
                    allow_only_pq: true,
                    backoff: Backoff {
                        initial_s: 42,
                        maximal_s: None
                    },
                    root_certificate_override: None,
                }),
                error_notification_service
            );
            assert_json!(
                r#"{"error_notification_service": {
                    "backoff": {
                        "initial_s": 12345,
                        "maximal_s": 67890
                    }
                }}"#,
                Some(FeatureErrorNotificationService {
                    buffer_size: 5,
                    allow_only_pq: true,
                    backoff: Backoff {
                        initial_s: 12345,
                        maximal_s: Some(67890)
                    },
                    root_certificate_override: None,
                }),
                error_notification_service
            );
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

    proptest::proptest! {
        #[test]
        fn prop_test_features_deserialization(features: super::Features) {
            let s = features.serialize().unwrap();
            let deserialized : Features = serde_json::from_str(&s).unwrap();
            assert_eq!(features, deserialized);
        }
    }
}
