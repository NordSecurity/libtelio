use std::ffi::{c_void, CString};
use std::net::SocketAddrV4;
use std::os::raw::c_char;
use std::pin::Pin;
use std::{fmt::Debug, net::IpAddr};

use ipnet::IpNet;
use telio_utils::telio_log_warn;

use crate::libfirewall::{
    LibfwAssociatedData, LibfwChainV2, LibfwDnatTarget, LibfwDnsDomainSet, LibfwFilter,
    LibfwFilterData, LibfwIpAddr, LibfwIpData, LibfwNetworkFilter, LibfwRuleV2,
    LIBFW_ACTION_ACCEPT, LIBFW_ACTION_DNAT, LIBFW_ACTION_DROP, LIBFW_ACTION_REJECT,
    LIBFW_CONTRACK_STATE_ESTABLISHED, LIBFW_CONTRACK_STATE_INVALID, LIBFW_CONTRACK_STATE_NEW,
    LIBFW_CONTRACK_STATE_RELATED, LIBFW_DIRECTION_INBOUND, LIBFW_DIRECTION_OUTBOUND,
    LIBFW_FILTER_ASSOCIATED_DATA, LIBFW_FILTER_CONNTRACK_STATE, LIBFW_FILTER_DIRECTION,
    LIBFW_FILTER_DNS_QUERY_DOMAIN, LIBFW_FILTER_DST_NETWORK, LIBFW_FILTER_ICMP_TYPE,
    LIBFW_FILTER_NEXT_LVL_PROTO, LIBFW_FILTER_ORIG_SRC_IP, LIBFW_FILTER_SRC_NETWORK,
    LIBFW_FILTER_TCP_FLAGS, LIBFW_ICMP_TYPE_DESTINATION_UNREACHABLE, LIBFW_ICMP_TYPE_ECHO_REPLY,
    LIBFW_ICMP_TYPE_ECHO_REQUEST, LIBFW_ICMP_TYPE_PARAMETER_PROBLEM,
    LIBFW_ICMP_TYPE_REDIRECT_MESSAGE, LIBFW_ICMP_TYPE_ROUTER_ADVERTISEMENT,
    LIBFW_ICMP_TYPE_ROUTER_SOLICITATION, LIBFW_ICMP_TYPE_TIMESTAMP,
    LIBFW_ICMP_TYPE_TIMESTAMP_REPLY, LIBFW_ICMP_TYPE_TIME_EXCEEDED, LIBFW_IP_TYPE_V4,
    LIBFW_IP_TYPE_V6, LIBFW_NEXT_PROTO_ICMP, LIBFW_NEXT_PROTO_ICMPV6, LIBFW_NEXT_PROTO_TCP,
    LIBFW_NEXT_PROTO_UDP,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetworkFilterData {
    pub(crate) network: IpNet,
    pub(crate) port_range: (u16, u16),
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum NextLevelProtocol {
    Tcp = LIBFW_NEXT_PROTO_TCP,
    Udp = LIBFW_NEXT_PROTO_UDP,
    Icmp = LIBFW_NEXT_PROTO_ICMP,
    Icmpv6 = LIBFW_NEXT_PROTO_ICMPV6,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum IcmpType {
    EchoReply = LIBFW_ICMP_TYPE_ECHO_REPLY,
    DestinationUnreachable = LIBFW_ICMP_TYPE_DESTINATION_UNREACHABLE,
    Redirect = LIBFW_ICMP_TYPE_REDIRECT_MESSAGE,
    Echo = LIBFW_ICMP_TYPE_ECHO_REQUEST,
    Routeradvertisement = LIBFW_ICMP_TYPE_ROUTER_ADVERTISEMENT,
    Routersolicitation = LIBFW_ICMP_TYPE_ROUTER_SOLICITATION,
    TimeExceeded = LIBFW_ICMP_TYPE_TIME_EXCEEDED,
    ParameterProblem = LIBFW_ICMP_TYPE_PARAMETER_PROBLEM,
    Timestamp = LIBFW_ICMP_TYPE_TIMESTAMP,
    TimestampReply = LIBFW_ICMP_TYPE_TIMESTAMP_REPLY,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Direction {
    /// Outgoing packets
    Outbound = LIBFW_DIRECTION_OUTBOUND,
    /// Incoming packets
    Inbound = LIBFW_DIRECTION_INBOUND,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    /// Connection established
    Established = LIBFW_CONTRACK_STATE_ESTABLISHED,
    /// Outgoing packets
    New = LIBFW_CONTRACK_STATE_NEW,
    /// Packets related to existing connections
    Related = LIBFW_CONTRACK_STATE_RELATED,
    /// Invalid packets
    Invalid = LIBFW_CONTRACK_STATE_INVALID,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FilterData {
    AssociatedData(Option<Vec<u8>>),
    ConntrackState(ConnectionState),
    SrcNetwork(NetworkFilterData),
    DstNetwork(NetworkFilterData),
    Direction(Direction),
    NextLevelProtocol(NextLevelProtocol),
    TcpFlags(u8),
    IcmpType(IcmpType),
    DnsQueryDomain(Vec<String>),
    OrigSrcIp(IpAddr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Filter {
    pub(crate) filter_data: FilterData,
    pub(crate) inverted: bool,
}

/// Rule action. Uses libfirewall's V2 action set (LIBFW_ACTION_*) so DNAT
/// can carry a target endpoint as action data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuleAction {
    Accept,
    Drop,
    Reject,
    Dnat(SocketAddrV4),
}

impl From<&[u8]> for LibfwAssociatedData {
    fn from(value: &[u8]) -> Self {
        LibfwAssociatedData {
            associated_data: value.as_ptr(),
            associated_data_len: value.len(),
        }
    }
}

impl From<IpAddr> for LibfwIpAddr {
    fn from(value: IpAddr) -> Self {
        let (ip_type, ip_data) = match value {
            IpAddr::V4(ipv4_addr) => (
                LIBFW_IP_TYPE_V4,
                LibfwIpData {
                    ipv4_bytes: ipv4_addr.octets(),
                },
            ),
            IpAddr::V6(ipv6_addr) => (
                LIBFW_IP_TYPE_V6,
                LibfwIpData {
                    ipv6_bytes: ipv6_addr.octets(),
                },
            ),
        };
        LibfwIpAddr { ip_type, ip_data }
    }
}

impl From<&NetworkFilterData> for LibfwNetworkFilter {
    fn from(value: &NetworkFilterData) -> Self {
        LibfwNetworkFilter {
            network_addr: value.network.network().into(),
            network_prefix: value.network.prefix_len(),
            port_range_start: value.port_range.0,
            port_range_end: value.port_range.1,
        }
    }
}

type PinnedAssocData = Pin<Box<Vec<u8>>>;
type PinnedDomainSet = Pin<Box<(Vec<CString>, Vec<*const c_char>)>>;

#[allow(dead_code)]
pub(crate) enum FilterExtraData {
    AssocData(PinnedAssocData),
    DomainSet(PinnedDomainSet),
}

type PinnedFilters = Pin<Box<Vec<LibfwFilter>>>;
type PinnedDnatTarget = Pin<Box<LibfwDnatTarget>>;
type PinnedRuleData = (
    PinnedFilters,
    Vec<Option<FilterExtraData>>,
    Option<PinnedDnatTarget>,
);
type PinnedRules = Pin<Box<Vec<LibfwRuleV2>>>;

impl From<&Filter> for (LibfwFilter, Option<FilterExtraData>) {
    fn from(value: &Filter) -> Self {
        let (filter, filter_type, extra) = match &value.filter_data {
            FilterData::AssociatedData(assoc_data) => {
                if let Some(assoc_data) = assoc_data {
                    let cloned_assoc_data = Box::pin(assoc_data.to_vec());
                    (
                        LibfwFilterData {
                            associated_data_filter: LibfwAssociatedData {
                                associated_data: cloned_assoc_data.as_ptr(),
                                associated_data_len: cloned_assoc_data.len(),
                            },
                        },
                        LIBFW_FILTER_ASSOCIATED_DATA,
                        Some(FilterExtraData::AssocData(cloned_assoc_data)),
                    )
                } else {
                    (
                        LibfwFilterData {
                            associated_data_filter: LibfwAssociatedData {
                                associated_data: std::ptr::null_mut(),
                                associated_data_len: 0,
                            },
                        },
                        LIBFW_FILTER_ASSOCIATED_DATA,
                        None,
                    )
                }
            }
            FilterData::ConntrackState(connection_state) => (
                LibfwFilterData {
                    conntrack_state_filter: *connection_state as u8,
                },
                LIBFW_FILTER_CONNTRACK_STATE,
                None,
            ),
            FilterData::SrcNetwork(network_filter) => (
                LibfwFilterData {
                    network_filter: network_filter.into(),
                },
                LIBFW_FILTER_SRC_NETWORK,
                None,
            ),
            FilterData::DstNetwork(network_filter) => (
                LibfwFilterData {
                    network_filter: network_filter.into(),
                },
                LIBFW_FILTER_DST_NETWORK,
                None,
            ),
            FilterData::Direction(direction) => (
                LibfwFilterData {
                    direction_filter: *direction as u8,
                },
                LIBFW_FILTER_DIRECTION,
                None,
            ),
            FilterData::NextLevelProtocol(next_level_protocol) => (
                LibfwFilterData {
                    next_level_protocol: *next_level_protocol as u8,
                },
                LIBFW_FILTER_NEXT_LVL_PROTO,
                None,
            ),
            FilterData::TcpFlags(tcp_flags) => (
                LibfwFilterData {
                    tcp_flags: *tcp_flags,
                },
                LIBFW_FILTER_TCP_FLAGS,
                None,
            ),
            FilterData::IcmpType(icmp_type) => (
                LibfwFilterData {
                    icmp_type: *icmp_type as u8,
                },
                LIBFW_FILTER_ICMP_TYPE,
                None,
            ),
            FilterData::DnsQueryDomain(domains) => {
                let cstrings: Vec<CString> = domains
                    .iter()
                    .filter_map(|d| match CString::new(d.as_str()) {
                        Ok(cstring) => Some(cstring),
                        Err(err) => {
                            telio_log_warn!("Skipping invalid DNS whitelist domain {d:?}: {err}");
                            None
                        }
                    })
                    .collect();
                let ptrs: Vec<*const c_char> = cstrings.iter().map(|c| c.as_ptr()).collect();
                let pinned: PinnedDomainSet = Box::pin((cstrings, ptrs));
                let (domains_ptr, num_domains) = (pinned.1.as_ptr(), pinned.1.len());
                (
                    LibfwFilterData {
                        dns_domain_set: LibfwDnsDomainSet {
                            domains: domains_ptr,
                            num_domains,
                        },
                    },
                    LIBFW_FILTER_DNS_QUERY_DOMAIN,
                    Some(FilterExtraData::DomainSet(pinned)),
                )
            }
            FilterData::OrigSrcIp(ip) => (
                LibfwFilterData {
                    orig_src_ip: (*ip).into(),
                },
                LIBFW_FILTER_ORIG_SRC_IP,
                None,
            ),
        };
        (
            LibfwFilter {
                inverted: value.inverted,
                filter_type,
                filter,
            },
            extra,
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) filters: Vec<Filter>,
    pub(crate) action: RuleAction,
}

fn dnat_target_for(target: &SocketAddrV4) -> LibfwDnatTarget {
    LibfwDnatTarget {
        addr: LibfwIpAddr {
            ip_type: LIBFW_IP_TYPE_V4,
            ip_data: LibfwIpData {
                ipv4_bytes: target.ip().octets(),
            },
        },
        port: target.port(),
    }
}

impl From<&Rule> for (LibfwRuleV2, PinnedRuleData) {
    fn from(value: &Rule) -> Self {
        let (ffi_filters, additional_data): (Vec<_>, Vec<_>) =
            value.filters.iter().map(|filter| filter.into()).unzip();
        let ffi_filters = Box::pin(ffi_filters);

        let (action, action_data_ptr, pinned_target): (
            u8,
            *const c_void,
            Option<PinnedDnatTarget>,
        ) = match &value.action {
            RuleAction::Accept => (LIBFW_ACTION_ACCEPT, std::ptr::null(), None),
            RuleAction::Drop => (LIBFW_ACTION_DROP, std::ptr::null(), None),
            RuleAction::Reject => (LIBFW_ACTION_REJECT, std::ptr::null(), None),
            RuleAction::Dnat(target) => {
                let pinned = Box::pin(dnat_target_for(target));
                let ptr = (&*pinned) as *const LibfwDnatTarget as *const c_void;
                (LIBFW_ACTION_DNAT, ptr, Some(pinned))
            }
        };

        (
            LibfwRuleV2 {
                filters: ffi_filters.as_ptr(),
                filter_count: ffi_filters.len(),
                action,
                action_data: action_data_ptr,
            },
            (ffi_filters, additional_data, pinned_target),
        )
    }
}

// Helper structure for LibfwChainV2 - it keeps all of the allocated stuff and the chain
// remains usable as long as it's not dropped.
pub(crate) struct FfiChainGuard {
    pub(crate) ffi_chain: LibfwChainV2,
    _ffi_rules: PinnedRules,
    _ffi_rule_data: Vec<PinnedRuleData>,
}

impl From<&[Rule]> for FfiChainGuard {
    fn from(value: &[Rule]) -> Self {
        let (ffi_rules, _ffi_rule_data): (Vec<LibfwRuleV2>, Vec<PinnedRuleData>) =
            value.iter().map(|rule| rule.into()).unzip();
        let _ffi_rules = Box::pin(ffi_rules);

        FfiChainGuard {
            ffi_chain: LibfwChainV2 {
                rule_count: value.len(),
                rules: _ffi_rules.as_ptr(),
            },
            _ffi_rules,
            _ffi_rule_data,
        }
    }
}

#[cfg(test)]
#[allow(missing_docs, unused)]
pub mod tests {
    use std::{
        ffi::{CStr, CString},
        mem::ManuallyDrop,
        net::{Ipv4Addr, SocketAddrV4},
        os::raw::c_char,
    };

    use ipnet::Ipv4Net;
    use pnet_packet::tcp::TcpFlags;
    use smallvec::ToSmallVec;

    use crate::{
        chain_helpers::{
            ConnectionState, Direction, FfiChainGuard, Filter, FilterData, IcmpType,
            NetworkFilterData, NextLevelProtocol, Rule, RuleAction,
        },
        libfirewall::{
            LibfwAssociatedData, LibfwChainV2, LibfwDnatTarget, LibfwDnsDomainSet, LibfwFilter,
            LibfwFilterData, LibfwIpAddr, LibfwIpData, LibfwNetworkFilter, LibfwRuleV2,
            LIBFW_ACTION_ACCEPT, LIBFW_ACTION_DNAT, LIBFW_ACTION_DROP, LIBFW_ACTION_REJECT,
            LIBFW_CONTRACK_STATE_ESTABLISHED, LIBFW_DIRECTION_INBOUND, LIBFW_DIRECTION_OUTBOUND,
            LIBFW_FILTER_ASSOCIATED_DATA, LIBFW_FILTER_CONNTRACK_STATE, LIBFW_FILTER_DIRECTION,
            LIBFW_FILTER_DNS_QUERY_DOMAIN, LIBFW_FILTER_DST_NETWORK, LIBFW_FILTER_ICMP_TYPE,
            LIBFW_FILTER_NEXT_LVL_PROTO, LIBFW_FILTER_ORIG_SRC_IP, LIBFW_FILTER_SRC_NETWORK,
            LIBFW_FILTER_TCP_FLAGS, LIBFW_ICMP_TYPE_ECHO_REPLY, LIBFW_IP_TYPE_V4, LIBFW_IP_TYPE_V6,
            LIBFW_NEXT_PROTO_UDP,
        },
    };

    #[test]
    fn test_conversion_correctness() {
        let dnat_target = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
        let rules = vec![
            Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::AssociatedData(None),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::Direction(Direction::Inbound),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::SrcNetwork(NetworkFilterData {
                            network: ipnet::IpNet::V4(
                                Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap(),
                            ),
                            port_range: (1000, 1200),
                        }),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::ConntrackState(ConnectionState::Established),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::NextLevelProtocol(NextLevelProtocol::Udp),
                        inverted: true,
                    },
                ],
                action: RuleAction::Accept,
            },
            Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::Direction(Direction::Outbound),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::IcmpType(IcmpType::EchoReply),
                        inverted: true,
                    },
                    Filter {
                        filter_data: FilterData::OrigSrcIp(std::net::IpAddr::V4(Ipv4Addr::new(
                            10, 0, 0, 5,
                        ))),
                        inverted: false,
                    },
                ],
                action: RuleAction::Drop,
            },
            Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::AssociatedData(Some([1; 32].to_vec())),
                        inverted: true,
                    },
                    Filter {
                        filter_data: FilterData::TcpFlags(TcpFlags::ACK | TcpFlags::SYN),
                        inverted: false,
                    },
                ],
                action: RuleAction::Reject,
            },
            Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::Direction(Direction::Outbound),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::NextLevelProtocol(NextLevelProtocol::Udp),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::DnsQueryDomain(vec![
                            "example.com".into(),
                            "foo.bar".into(),
                        ]),
                        inverted: false,
                    },
                ],
                action: RuleAction::Dnat(dnat_target),
            },
        ];

        let chain_guard: FfiChainGuard = rules.as_slice().into();
        let test_chain_conv = &chain_guard.ffi_chain;

        let test_chain_conv_rules = unsafe {
            std::slice::from_raw_parts(test_chain_conv.rules, test_chain_conv.rule_count)
        };

        let filters1 = vec![
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_ASSOCIATED_DATA,
                filter: LibfwFilterData {
                    associated_data_filter: LibfwAssociatedData {
                        associated_data: std::ptr::null_mut(),
                        associated_data_len: 0,
                    },
                },
            },
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_DIRECTION,
                filter: LibfwFilterData {
                    direction_filter: LIBFW_DIRECTION_INBOUND,
                },
            },
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_SRC_NETWORK,
                filter: LibfwFilterData {
                    network_filter: LibfwNetworkFilter {
                        network_addr: LibfwIpAddr {
                            ip_type: LIBFW_IP_TYPE_V4,
                            ip_data: LibfwIpData {
                                ipv4_bytes: [10, 0, 0, 0],
                            },
                        },
                        network_prefix: 16,
                        port_range_start: 1000,
                        port_range_end: 1200,
                    },
                },
            },
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_CONNTRACK_STATE,
                filter: LibfwFilterData {
                    conntrack_state_filter: LIBFW_CONTRACK_STATE_ESTABLISHED,
                },
            },
            LibfwFilter {
                inverted: true,
                filter_type: LIBFW_FILTER_NEXT_LVL_PROTO,
                filter: LibfwFilterData {
                    next_level_protocol: LIBFW_NEXT_PROTO_UDP,
                },
            },
        ];

        let filters2 = vec![
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_DIRECTION,
                filter: LibfwFilterData {
                    direction_filter: LIBFW_DIRECTION_OUTBOUND,
                },
            },
            LibfwFilter {
                inverted: true,
                filter_type: LIBFW_FILTER_ICMP_TYPE,
                filter: LibfwFilterData {
                    icmp_type: LIBFW_ICMP_TYPE_ECHO_REPLY,
                },
            },
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_ORIG_SRC_IP,
                filter: LibfwFilterData {
                    orig_src_ip: LibfwIpAddr {
                        ip_type: LIBFW_IP_TYPE_V4,
                        ip_data: LibfwIpData {
                            ipv4_bytes: [10, 0, 0, 5],
                        },
                    },
                },
            },
        ];

        let assoc_data = vec![1u8; 32];
        let filters3 = vec![
            LibfwFilter {
                inverted: true,
                filter_type: LIBFW_FILTER_ASSOCIATED_DATA,
                filter: LibfwFilterData {
                    associated_data_filter: LibfwAssociatedData {
                        associated_data_len: assoc_data.len(),
                        associated_data: assoc_data.as_ptr(),
                    },
                },
            },
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_TCP_FLAGS,
                filter: LibfwFilterData {
                    tcp_flags: TcpFlags::ACK | TcpFlags::SYN,
                },
            },
        ];

        let dns_cstrings = [
            CString::new("example.com").unwrap(),
            CString::new("foo.bar").unwrap(),
        ];
        let dns_ptrs: Vec<*const c_char> = dns_cstrings.iter().map(|c| c.as_ptr()).collect();
        let filters4 = vec![
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_DIRECTION,
                filter: LibfwFilterData {
                    direction_filter: LIBFW_DIRECTION_OUTBOUND,
                },
            },
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_NEXT_LVL_PROTO,
                filter: LibfwFilterData {
                    next_level_protocol: LIBFW_NEXT_PROTO_UDP,
                },
            },
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_DNS_QUERY_DOMAIN,
                filter: LibfwFilterData {
                    dns_domain_set: LibfwDnsDomainSet {
                        domains: dns_ptrs.as_ptr(),
                        num_domains: dns_ptrs.len(),
                    },
                },
            },
        ];

        let expected_actions = [
            LIBFW_ACTION_ACCEPT,
            LIBFW_ACTION_DROP,
            LIBFW_ACTION_REJECT,
            LIBFW_ACTION_DNAT,
        ];

        assert_eq!(test_chain_conv.rule_count, expected_actions.len());

        for (rule_idx, expected_filters) in
            [filters1, filters2, filters3, filters4].iter().enumerate()
        {
            let rule = &test_chain_conv_rules[rule_idx];
            assert_eq!(
                rule.filter_count,
                expected_filters.len(),
                "rule {rule_idx} filter count"
            );
            let conv_filters =
                unsafe { std::slice::from_raw_parts(rule.filters, rule.filter_count) };
            for (conv, expected) in conv_filters.iter().zip(expected_filters.iter()) {
                assert_filter_eq(conv, expected);
            }

            let expected_action = expected_actions[rule_idx];
            assert_eq!(test_chain_conv_rules[rule_idx].action, expected_action);
            if expected_action == LIBFW_ACTION_DNAT {
                assert!(!test_chain_conv_rules[rule_idx].action_data.is_null());
                let target = unsafe {
                    &*(test_chain_conv_rules[rule_idx].action_data as *const LibfwDnatTarget)
                };
                assert_eq!(target.addr.ip_type, LIBFW_IP_TYPE_V4);
                assert_eq!(unsafe { target.addr.ip_data.ipv4_bytes }, [1, 1, 1, 1]);
                assert_eq!(target.port, 53);
            } else {
                assert!(test_chain_conv_rules[rule_idx].action_data.is_null());
            }
        }
    }

    /// Asserts that a converted FFI filter matches the expected one, comparing
    /// the payload of whichever union variant the `filter_type` selects.
    fn assert_filter_eq(conv: &LibfwFilter, expected: &LibfwFilter) {
        assert_eq!(conv.filter_type, expected.filter_type, "filter type");
        assert_eq!(conv.inverted, expected.inverted, "filter inverted flag");
        match conv.filter_type {
            LIBFW_FILTER_ASSOCIATED_DATA => {
                let c = unsafe { conv.filter.associated_data_filter };
                let e = unsafe { expected.filter.associated_data_filter };
                assert_eq!(c.associated_data_len, e.associated_data_len);
                if e.associated_data.is_null() {
                    assert!(c.associated_data.is_null());
                } else {
                    assert!(!c.associated_data.is_null());
                    let c_bytes = unsafe {
                        std::slice::from_raw_parts(c.associated_data, c.associated_data_len)
                    };
                    let e_bytes = unsafe {
                        std::slice::from_raw_parts(e.associated_data, e.associated_data_len)
                    };
                    assert_eq!(c_bytes, e_bytes, "associated data bytes");
                }
            }
            LIBFW_FILTER_DIRECTION => assert_eq!(unsafe { conv.filter.direction_filter }, unsafe {
                expected.filter.direction_filter
            }),
            LIBFW_FILTER_SRC_NETWORK | LIBFW_FILTER_DST_NETWORK => {
                let c = unsafe { conv.filter.network_filter };
                let e = unsafe { expected.filter.network_filter };
                assert_eq!(c.network_addr.ip_type, e.network_addr.ip_type);
                match c.network_addr.ip_type {
                    LIBFW_IP_TYPE_V4 => {
                        assert_eq!(unsafe { c.network_addr.ip_data.ipv4_bytes }, unsafe {
                            e.network_addr.ip_data.ipv4_bytes
                        })
                    }
                    LIBFW_IP_TYPE_V6 => {
                        assert_eq!(unsafe { c.network_addr.ip_data.ipv6_bytes }, unsafe {
                            e.network_addr.ip_data.ipv6_bytes
                        })
                    }
                    _ => unreachable!("Unknown IP type"),
                };
                assert_eq!(c.network_prefix, e.network_prefix);
                assert_eq!(c.port_range_start, e.port_range_start);
                assert_eq!(c.port_range_end, e.port_range_end);
            }
            LIBFW_FILTER_CONNTRACK_STATE => {
                assert_eq!(unsafe { conv.filter.conntrack_state_filter }, unsafe {
                    expected.filter.conntrack_state_filter
                })
            }
            LIBFW_FILTER_NEXT_LVL_PROTO => {
                assert_eq!(unsafe { conv.filter.next_level_protocol }, unsafe {
                    expected.filter.next_level_protocol
                })
            }
            LIBFW_FILTER_TCP_FLAGS => assert_eq!(unsafe { conv.filter.tcp_flags }, unsafe {
                expected.filter.tcp_flags
            }),
            LIBFW_FILTER_ICMP_TYPE => assert_eq!(unsafe { conv.filter.icmp_type }, unsafe {
                expected.filter.icmp_type
            }),
            LIBFW_FILTER_DNS_QUERY_DOMAIN => {
                let c = unsafe { conv.filter.dns_domain_set };
                let e = unsafe { expected.filter.dns_domain_set };
                assert_eq!(c.num_domains, e.num_domains, "domain count");
                let c_ptrs = unsafe { std::slice::from_raw_parts(c.domains, c.num_domains) };
                let e_ptrs = unsafe { std::slice::from_raw_parts(e.domains, e.num_domains) };
                for (cp, ep) in c_ptrs.iter().zip(e_ptrs.iter()) {
                    assert_eq!(unsafe { CStr::from_ptr(*cp) }, unsafe {
                        CStr::from_ptr(*ep)
                    });
                }
            }
            LIBFW_FILTER_ORIG_SRC_IP => {
                let c = unsafe { conv.filter.orig_src_ip };
                let e = unsafe { expected.filter.orig_src_ip };
                assert_eq!(c.ip_type, e.ip_type);
                match c.ip_type {
                    LIBFW_IP_TYPE_V4 => assert_eq!(unsafe { c.ip_data.ipv4_bytes }, unsafe {
                        e.ip_data.ipv4_bytes
                    }),
                    LIBFW_IP_TYPE_V6 => assert_eq!(unsafe { c.ip_data.ipv6_bytes }, unsafe {
                        e.ip_data.ipv6_bytes
                    }),
                    _ => unreachable!("Unknown IP type"),
                };
            }
            _ => unreachable!("Unexpected filter type"),
        }
    }
}
