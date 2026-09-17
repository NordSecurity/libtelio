//! Types for TP-Lite stats collection

use std::net::{IpAddr, SocketAddrV4};

use serde::{Deserialize, Serialize};

/// Pair of DNS server endpoints describing how a single DNS-redirect rule
/// should rewrite outbound DNS traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DnsRedirect {
    /// DNS server that would otherwise drop non-whitelisted queries.
    pub blocking: SocketAddrV4,
    /// DNS server to which whitelisted queries are redirected.
    pub standard: SocketAddrV4,
}

/// Config options for the TP-Lite stats collection
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpLiteStatsOptions {
    #[serde(default)]
    /// DNS servers from which responses are analyzed to collect TP-Lite stats
    /// At least one must be configured, otherwise stats collection will be considered disabled
    pub dns_server_ips: Vec<IpAddr>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// When a domain has been blocked it is added to a buffer to not invoke the stats callback for every response
    ///
    /// The  maximum number of blocked domains (not unique) that will be buffered
    /// If the buffer fills up the oldest entries will be overwritten
    ///
    /// Default value: 100
    pub blocked_domains_buffer_size: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// After how long stats will be passed to the callback, in seconds
    /// The interval this controls starts when the collected stats goes from empty to not empty
    ///
    /// Default value: 5
    pub callback_interval_s: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// libfirewall disables OS/client-level caching of blocked domains when stats collection is enabled
    /// To not make extra DNS requests libfirewall has it's own DNS cache for blocked domains
    ///
    /// How many entries the libfirewall-specific DNS cache can hold
    ///
    /// Default value: 512
    pub cache_size: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// When TP-Lite stats collection is enabled libfirewall keeps track of open DNS requests
    ///
    /// How many requests libfirewall can keep track of
    ///
    /// Default value: same as blocked_domains_buffer_size
    pub max_open_requests: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The stats collection can only operate on plaintext DNS packets
    /// Setting this flag will block DoT and DoH packets, causing the client to fallback to plaintext
    /// Note: Some clients can be configured with no plaintext fallback, which would then break if this flag is set
    ///
    /// Default value: false
    pub force_plaintext_dns: Option<bool>,
}

/// A callback for getting TP-Lite stats from libfirewall
pub trait TpLiteStatsCallback: Send + Sync + std::fmt::Debug {
    /// Get the blocked domains that have been buffered so far
    /// Blocking this callback can result in losing blocked domains from subsequent calls
    fn collect(&self, domains: Vec<BlockedDomain>, metrics: DnsMetrics);
}

#[derive(Debug)]
/// Empty callback to use when feature is disabled, or as temporary value when setting new callback
pub struct NoopCallback;
impl TpLiteStatsCallback for NoopCallback {
    fn collect(&self, _domains: Vec<BlockedDomain>, _metrics: DnsMetrics) {}
}

/// LibfwDnsMetrics but with nicer types
#[derive(Debug)]
pub struct DnsMetrics {
    /// Total number of DNS requests
    pub num_requests: u32,
    /// Total number of DNS responses
    pub num_responses: u32,
    /// How many responses were served from the libfirewall DNS cache
    pub num_cache_hits: u32,
}

/// LibfwBlockedDomain but with nicer types
#[derive(Debug, Clone)]
pub struct BlockedDomain {
    /// The domain name that was blocked
    pub domain_name: String,
    /// Timestamp of the response
    pub timestamp: u64,
    /// Which blocking category the domain falls under
    pub category: String,
}
