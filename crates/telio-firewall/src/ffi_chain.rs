use num_enum::TryFromPrimitive;
use std::mem::ManuallyDrop;

/// Data for LIBFW_FLITER_NEXT_LVL_PROTO matching TCP packets
pub const LIBFW_NEXT_PROTO_TCP: u8 = 0;
/// Data for LIBFW_FLITER_NEXT_LVL_PROTO matching UDP packets
pub const LIBFW_NEXT_PROTO_UDP: u8 = 1;
/// Data for LIBFW_FLITER_NEXT_LVL_PROTO matching ICMP packets
pub const LIBFW_NEXT_PROTO_ICMP: u8 = 2;
/// Data for LIBFW_FLITER_NEXT_LVL_PROTO matching ICMPv6 packets
pub const LIBFW_NEXT_PROTO_ICMPV6: u8 = 3;

/// Data for LIBFW_FILTER_ICMP_TYPE matching ECHO_REPLY ICMP packets
pub const LIBFW_ICMP_TYPE_ECHO_REPLY: u8 = 0;
/// Data for LIBFW_FILTER_ICMP_TYPE matching DESTINATION_UNREACHABLE ICMP packets
pub const LIBFW_ICMP_TYPE_DESTINATION_UNREACHABLE: u8 = 3;
/// Data for LIBFW_FILTER_ICMP_TYPE matching REDIRECT_MESSAGE ICMP packets
pub const LIBFW_ICMP_TYPE_REDIRECT_MESSAGE: u8 = 5;
/// Data for LIBFW_FILTER_ICMP_TYPE matching ECHO_REQUEST ICMP packets
pub const LIBFW_ICMP_TYPE_ECHO_REQUEST: u8 = 8;
/// Data for LIBFW_FILTER_ICMP_TYPE matching ROUTER_ADVERTISEMENT ICMP packets
pub const LIBFW_ICMP_TYPE_ROUTER_ADVERTISEMENT: u8 = 9;
/// Data for LIBFW_FILTER_ICMP_TYPE matching ROUTER_SOLICITATION ICMP packets
pub const LIBFW_ICMP_TYPE_ROUTER_SOLICITATION: u8 = 10;
/// Data for LIBFW_FILTER_ICMP_TYPE matching TIME_EXCEEDED ICMP packets
pub const LIBFW_ICMP_TYPE_TIME_EXCEEDED: u8 = 11;
/// Data for LIBFW_FILTER_ICMP_TYPE matching PARAMETER_PROBLEM ICMP packets
pub const LIBFW_ICMP_TYPE_PARAMETER_PROBLEM: u8 = 12;
/// Data for LIBFW_FILTER_ICMP_TYPE matching TIMESTAMP ICMP packets
pub const LIBFW_ICMP_TYPE_TIMESTAMP: u8 = 13;
/// Data for LIBFW_FILTER_ICMP_TYPE matching TIMESTAMP_REPLY ICMP packets
pub const LIBFW_ICMP_TYPE_TIMESTAMP_REPLY: u8 = 14;

/// Verdict implying that the packet should be accepted
pub const LIBFW_VERDICT_ACCEPT: u8 = 0;
/// Verdict implying that the packet should be dropped
pub const LIBFW_VERDICT_DROP: u8 = 1;
/// Verdict implying that the packet should be rejected
pub const LIBFW_VERDICT_REJECT: u8 = 2;

///
/// Possible verdicts for packets.
///
/// Note: From the libfw integrators perspective, LibfwVerdictReject is the same as
/// packet injection + drop. Reject is here just for informational purposes, therefore
/// anytime libfw returns LibfwVerdictReject - relevant packet should be dropped in the
/// same manner as LibfwVerdictDrop. But differentiating these two may be useful for
/// logging or metrics or similar kind of purposes.
///
#[allow(clippy::enum_variant_names)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum LibfwVerdict {
    LibfwVerdictAccept = LIBFW_VERDICT_ACCEPT,
    LibfwVerdictDrop = LIBFW_VERDICT_DROP,
    LibfwVerdictReject = LIBFW_VERDICT_REJECT,
}

///
/// Filter by the associate data
///
#[repr(C)]
#[derive(Debug)]
pub struct LibfwAssociatedData {
    /// Associated data
    pub associated_data: *const u8,
    /// Associated data length
    pub associated_data_len: usize,
}

impl From<&LibfwAssociatedData> for Vec<u8> {
    fn from(value: &LibfwAssociatedData) -> Self {
        unsafe { std::slice::from_raw_parts(value.associated_data, value.associated_data_len) }
            .to_owned()
    }
}

/// Data for LIBFW_FILTER_CONTRACK_STATE matching packets from new connections
pub const LIBFW_CONTRACK_STATE_NEW: u8 = 0;
/// Data for LIBFW_FILTER_CONTRACK_STATE matching packets from established connections
pub const LIBFW_CONTRACK_STATE_ESTABLISHED: u8 = 1;
/// Data for LIBFW_FILTER_CONTRACK_STATE matching invalid packets
pub const LIBFW_CONTRACK_STATE_INVALID: u8 = 2;
/// Data for LIBFW_FILTER_CONTRACK_STATE matching packets related to different connections
pub const LIBFW_CONTRACK_STATE_RELATED: u8 = 3;
/// Data for LIBFW_FILTER_CONTRACK_STATE matching packets from closed connections
pub const LIBFW_CONTRACK_STATE_CLOSED: u8 = 4;

/// Data for LIBFW_FILTER_DIRECTION matching outbound packets
pub const LIBFW_DIRECTION_OUTBOUND: u8 = 0;
/// Data for LIBFW_FILTER_DIRECTION matching inbound packets
pub const LIBFW_DIRECTION_INBOUND: u8 = 1;

/// Type of LibfwIpAddr for IPv4
pub const LIBFW_IP_TYPE_V4: u8 = 0;
/// Type of LibfwIpAddr for IPv6
pub const LIBFW_IP_TYPE_V6: u8 = 1;

///
/// IP data
///
#[repr(C)]
#[derive(Copy, Clone)]
pub union LibfwIpData {
    /// Data for IPv4
    pub ipv4_bytes: [u8; 4],
    /// Data for IPv6
    pub ipv6_bytes: [u8; 16],
}

///
/// IP representation
///
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LibfwIpAddr {
    /// Type of the IP data:
    ///  - LIBFW_IP_TYPE_V4 - for IPv4 addresses
    ///  - LIBFW_IP_TYPE_V6 - for IPv6 addresses
    pub ip_type: u8,
    /// Data for the IP packet
    pub ip_data: LibfwIpData,
}

///
/// Filter by subnet and port range
///
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LibfwNetworkFilter {
    /// Network IP address
    pub network_addr: LibfwIpAddr,
    /// Network mask prefix
    pub network_prefix: u8,
    /// Minimum port accepted by the filter
    pub port_range_start: u16,
    /// Maximum port accepted by the filter
    pub port_range_end: u16,
}

/// Match packets with particular associated data
pub const LIBFW_FILTER_ASSOCIATED_DATA: u8 = 0;
/// Match packets with particular connection state
pub const LIBFW_FILTER_CONNTRACK_STATE: u8 = 1;
/// Match packets with certain source network
pub const LIBFW_FILTER_SRC_NETWORK: u8 = 2;
/// Match packets with certain destination network
pub const LIBFW_FILTER_DST_NETWORK: u8 = 3;
/// Match inbound or outbound packets
pub const LIBFW_FILTER_DIRECTION: u8 = 4;
/// Match packets with specific next level protocol
pub const LIBFW_FILTER_NEXT_LVL_PROTO: u8 = 5;
/// Match TCP packets with certain flags
pub const LIBFW_FILTER_TCP_FLAGS: u8 = 6;
/// Match ICMP packets with certain type
pub const LIBFW_FILTER_ICMP_TYPE: u8 = 7;

///
/// Data for the certain filter type
///
#[repr(C)]
pub union LibfwFilterData {
    /// Checked associated data
    /// Use when filter_type = LibfwFilterAssociatedData
    pub associated_data_filter: ManuallyDrop<LibfwAssociatedData>,
    /// Checked conntrack state
    /// Use when filter_type = LibfwFilterConntrackState
    pub conntrack_state_filter: u8,
    /// Checked conntrack state
    /// Use when filter_type = LibfwFilterConntrackState
    pub network_filter: LibfwNetworkFilter,
    /// Checked packet direction
    /// Use when filter_type = LibfwFilterDirection
    pub direction_filter: u8,
    /// Checked next level protocol (UDP, TCP, ICMP and ICMPv6 are allowed)
    /// Use when filter_type = LibfwFilterNextLvlProto
    pub next_level_protocol: u8,
    /// Checked set of TCP flags - packet matches the filter if any of its flags matches any of `tcp_flags`
    /// Use when filter_type = LibfwFilterTcpFlags
    pub tcp_flags: u8,
    /// Checked ICMP types, only ICMP packets can match this filter
    /// Use when filter_type = LibfwFilterConntrackState
    pub icmp_type: u8,
}

///
/// Struct describing a single Libfw filter
///
#[repr(C)]
pub struct LibfwFilter {
    /// Filter may be inverted, meaning, that it is considered
    /// a match only if filter does *not* match
    pub inverted: bool,

    /// Defines a type of filter to match the packets against.
    /// There are a few possible filter types:
    /// * LIBFW_FILTER_ASSOCIATED_DATA - matches packets based on their associated data.
    ///   This Normally means public key for NordLynx
    /// * LIBFW_FILTER_CONNTRACK_STATE - matches connection tracking table state.
    ///   This can be either "new connection" or "established connection"
    /// * LIBFW_FILTER_[SRC|DST]_NETWORK - matches against either source or destination IP network
    /// * LIBFW_FILTER_DIRECTION - matches either inbound or outbound packet direction.
    /// * LIBFW_FILTER_NEXT_LVL_PROTO - matches next level protocol, which can be:
    ///    - TCP - when `filter` is equal to LIBFW_NEXT_PROTO_TCP
    ///    - UDP - when `filter` is equal to LIBFW_NEXT_PROTO_UDP
    ///    - ICMP - when `filter` is equal to LIBFW_NEXT_PROTO_ICMP
    ///    - ICMPv6 - when filter is equal to LIBFW_NEXT_PROTO_ICMPV6
    /// * LIBFW_FILTER_TCP_FLAGS - TCP packets with certain flags - data should be a logic sum of
    ///   the considered TCP flags, the packet matches it when any of its flags and any flag in
    ///   the provided filter set are the same
    /// * LIBFW_FILTER_ICMP_TYPE - ICMP packets with certain type:
    ///    - EchoReply when `filter` is equal to LIBFW_ICMP_TYPE_ECHO_REPLY
    ///    - DestinationUnreachable when `filter` is equal to LIBFW_ICMP_TYPE_DESTINATION_UNREACHABLE
    ///    - RedirectMessage when `filter` is equal to LIBFW_ICMP_TYPE_REDIRECT_MESSAGE
    ///    - EchoRequest when `filter` is equal to LIBFW_ICMP_TYPE_ECHO_REQUEST
    ///    - ReouterAdvertisement when `filter` is equal to LIBFW_ICMP_TYPE_ROUTER_ADVERTISEMENT
    ///    - RouterSolicitation when `filter` is equal to LIBFW_ICMP_TYPE_ROUTER_SOLICITATION
    ///    - TimeExceeded when `filter` is equal to LIBFW_ICMP_TYPE_TIME_EXCEEDED
    ///    - ParameterProblem when `filter` is equal to LIBFW_ICMP_TYPE_PARAMETER_PROBLEM
    ///    - Timestamp when `filter` is equal to LIBFW_ICMP_TYPE_TIMESTAMP
    ///    - TimestampReply when `filter` is equal to LIBFW_ICMP_TYPE_TIMESTAMP_REPLY
    pub filter_type: u8,

    /// Contains corresponding filter data
    pub filter: LibfwFilterData,
}

/// A definition of firewall rule it consists of filters which determine whether rule
/// applies to packet being processed and action, which determins what to do with the packet
#[repr(C)]
pub struct LibfwRule {
    /// List of filters all of which match in order to consider rule's action
    pub filters: *const LibfwFilter,

    /// Length of the filter list
    pub filter_count: usize,

    /// Defines an action to be taken when filter matches packet. Generally either accept
    /// and stop processing rule chain or drop and stop processing rule chain.
    ///
    /// Should have one of the LIBFW_VERDICT_* values:
    ///  - LIBFW_VERDICT_ACCEPT - packet matching the rule will be accepted
    ///  - LIBFW_VERDICT_DROP - packet matching the rule will be dropped
    ///  - LIBFW_VERDICT_REJECT - packet matching the rule should be dropped and reject
    ///                           packet will be sent to the packet source
    pub action: u8,
}

/// A chain of rules.
///
/// Rules are processed in order specified in the chain.
/// If _some_ rule in the chain matches and a verdict is
/// determined - the chain processing terminated.
#[repr(C)]
#[derive(Debug)]
pub struct LibfwChain {
    /// Chain size
    pub rule_count: usize,

    /// List of the rules
    pub rules: *const LibfwRule,
}
