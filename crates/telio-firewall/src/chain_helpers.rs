use std::pin::Pin;
use std::{fmt::Debug, net::IpAddr};

use ipnet::IpNet;

use crate::libfirewall::{
    LibfwAssociatedData, LibfwChain, LibfwFilter, LibfwFilterData, LibfwIpAddr, LibfwIpData,
    LibfwNetworkFilter, LibfwRule, LibfwVerdict, LIBFW_CONTRACK_STATE_CLOSED,
    LIBFW_CONTRACK_STATE_ESTABLISHED, LIBFW_CONTRACK_STATE_INVALID, LIBFW_CONTRACK_STATE_NEW,
    LIBFW_CONTRACK_STATE_RELATED, LIBFW_DIRECTION_INBOUND, LIBFW_DIRECTION_OUTBOUND,
    LIBFW_FILTER_ASSOCIATED_DATA, LIBFW_FILTER_CONNTRACK_STATE, LIBFW_FILTER_DIRECTION,
    LIBFW_FILTER_DST_NETWORK, LIBFW_FILTER_ICMP_TYPE, LIBFW_FILTER_NEXT_LVL_PROTO,
    LIBFW_FILTER_SRC_NETWORK, LIBFW_FILTER_TCP_FLAGS, LIBFW_ICMP_TYPE_DESTINATION_UNREACHABLE,
    LIBFW_ICMP_TYPE_ECHO_REPLY, LIBFW_ICMP_TYPE_ECHO_REQUEST, LIBFW_ICMP_TYPE_PARAMETER_PROBLEM,
    LIBFW_ICMP_TYPE_REDIRECT_MESSAGE, LIBFW_ICMP_TYPE_ROUTER_ADVERTISEMENT,
    LIBFW_ICMP_TYPE_ROUTER_SOLICITATION, LIBFW_ICMP_TYPE_TIMESTAMP,
    LIBFW_ICMP_TYPE_TIMESTAMP_REPLY, LIBFW_ICMP_TYPE_TIME_EXCEEDED, LIBFW_IP_TYPE_V4,
    LIBFW_IP_TYPE_V6, LIBFW_NEXT_PROTO_ICMP, LIBFW_NEXT_PROTO_ICMPV6, LIBFW_NEXT_PROTO_TCP,
    LIBFW_NEXT_PROTO_UDP, LIBFW_VERDICT_ACCEPT, LIBFW_VERDICT_DROP, LIBFW_VERDICT_REJECT,
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
    /// Finished connections
    Closed = LIBFW_CONTRACK_STATE_CLOSED,
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
    #[allow(dead_code)]
    SrcNetwork(NetworkFilterData),
    DstNetwork(NetworkFilterData),
    Direction(Direction),
    NextLevelProtocol(NextLevelProtocol),
    TcpFlags(u8),
    IcmpType(IcmpType),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Filter {
    pub(crate) filter_data: FilterData,
    pub(crate) inverted: bool,
}

impl From<&[u8]> for LibfwAssociatedData {
    fn from(value: &[u8]) -> Self {
        LibfwAssociatedData {
            associated_data: value.as_ptr(),
            associated_data_len: value.len(),
        }
    }
}

impl From<&NetworkFilterData> for LibfwNetworkFilter {
    fn from(value: &NetworkFilterData) -> Self {
        let (ip_type, ip_data) = match value.network.network() {
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
        LibfwNetworkFilter {
            network_addr: LibfwIpAddr { ip_type, ip_data },
            network_prefix: value.network.prefix_len(),
            port_range_start: value.port_range.0,
            port_range_end: value.port_range.1,
        }
    }
}

type PinnedAssocData = Pin<Box<Vec<u8>>>;
type PinnedFilters = Pin<Box<Vec<LibfwFilter>>>;
type PinnedRuleData = (PinnedFilters, Vec<Option<PinnedAssocData>>);
type PinnedRules = Pin<Box<Vec<LibfwRule>>>;

impl From<&Filter> for (LibfwFilter, Option<PinnedAssocData>) {
    fn from(value: &Filter) -> Self {
        let (filter, filter_type, assoc_data) = match &value.filter_data {
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
                        Some(cloned_assoc_data),
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
        };
        (
            LibfwFilter {
                inverted: value.inverted,
                filter_type,
                filter,
            },
            assoc_data,
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) filters: Vec<Filter>,
    pub(crate) action: LibfwVerdict,
}

impl From<&Rule> for (LibfwRule, (PinnedFilters, Vec<Option<PinnedAssocData>>)) {
    fn from(value: &Rule) -> Self {
        let (ffi_filters, additional_data): (Vec<_>, Vec<_>) =
            value.filters.iter().map(|filter| filter.into()).unzip();
        let ffi_filters = Box::pin(ffi_filters);
        (
            LibfwRule {
                filters: ffi_filters.as_ptr(),
                filter_count: ffi_filters.len(),
                action: match value.action {
                    LibfwVerdict::LibfwVerdictAccept => LIBFW_VERDICT_ACCEPT,
                    LibfwVerdict::LibfwVerdictDrop => LIBFW_VERDICT_DROP,
                    LibfwVerdict::LibfwVerdictReject => LIBFW_VERDICT_REJECT,
                },
            },
            (ffi_filters, additional_data),
        )
    }
}

// Helper structure for LibfwChain - it keeps all of the allocated stuff and the chain
// remains usable as long as it's not dropped
pub(crate) struct FfiChainGuard {
    pub(crate) ffi_chain: LibfwChain,
    _ffi_rules: PinnedRules,
    _ffi_filters: Vec<(PinnedFilters, Vec<Option<PinnedAssocData>>)>,
}

impl From<&[Rule]> for FfiChainGuard {
    fn from(value: &[Rule]) -> Self {
        let (ffi_rules, _ffi_filters): (Vec<LibfwRule>, Vec<PinnedRuleData>) =
            value.iter().map(|rule| rule.into()).unzip();
        let _ffi_rules = Box::pin(ffi_rules);

        FfiChainGuard {
            ffi_chain: LibfwChain {
                rule_count: value.len(),
                rules: _ffi_rules.as_ptr(),
            },
            _ffi_rules,
            _ffi_filters,
        }
    }
}

#[cfg(test)]
#[allow(missing_docs, unused)]
pub mod tests {
    use std::{mem::ManuallyDrop, net::Ipv4Addr};

    use ipnet::Ipv4Net;
    use pnet_packet::tcp::TcpFlags;
    use smallvec::ToSmallVec;

    use crate::{
        chain_helpers::{
            ConnectionState, Direction, FfiChainGuard, Filter, FilterData, IcmpType,
            NetworkFilterData, NextLevelProtocol, Rule,
        },
        libfirewall::{
            LibfwAssociatedData, LibfwChain, LibfwFilter, LibfwFilterData, LibfwIpAddr,
            LibfwIpData, LibfwNetworkFilter, LibfwRule, LibfwVerdict,
            LIBFW_CONTRACK_STATE_ESTABLISHED, LIBFW_DIRECTION_INBOUND, LIBFW_DIRECTION_OUTBOUND,
            LIBFW_FILTER_ASSOCIATED_DATA, LIBFW_FILTER_CONNTRACK_STATE, LIBFW_FILTER_DIRECTION,
            LIBFW_FILTER_DST_NETWORK, LIBFW_FILTER_ICMP_TYPE, LIBFW_FILTER_NEXT_LVL_PROTO,
            LIBFW_FILTER_SRC_NETWORK, LIBFW_FILTER_TCP_FLAGS, LIBFW_ICMP_TYPE_ECHO_REPLY,
            LIBFW_IP_TYPE_V4, LIBFW_IP_TYPE_V6, LIBFW_NEXT_PROTO_UDP, LIBFW_VERDICT_ACCEPT,
            LIBFW_VERDICT_DROP, LIBFW_VERDICT_REJECT,
        },
    };

    #[test]
    fn test_conversion_correctness() {
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
                action: LibfwVerdict::LibfwVerdictAccept,
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
                ],
                action: LibfwVerdict::LibfwVerdictDrop,
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
                action: LibfwVerdict::LibfwVerdictReject,
            },
        ];

        let chain_guard: FfiChainGuard = rules.as_slice().into();
        let test_chain_conv = &chain_guard.ffi_chain;

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
        ];

        let mut assoc_data = vec![1u8; 32];
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

        let rules = vec![
            LibfwRule {
                filter_count: filters1.len(),
                filters: filters1.as_ptr(),
                action: LIBFW_VERDICT_ACCEPT,
            },
            LibfwRule {
                filter_count: filters2.len(),
                filters: filters2.as_ptr(),
                action: LIBFW_VERDICT_DROP,
            },
            LibfwRule {
                filter_count: filters3.len(),
                filters: filters3.as_ptr(),
                action: LIBFW_VERDICT_REJECT,
            },
        ];

        let test_ffi_chain = LibfwChain {
            rule_count: rules.len(),
            rules: rules.as_ptr(),
        };

        let test_chain_conv_rules = unsafe {
            std::slice::from_raw_parts(test_chain_conv.rules, test_chain_conv.rule_count)
        };
        let test_ffi_chain_rules =
            unsafe { std::slice::from_raw_parts(test_ffi_chain.rules, test_ffi_chain.rule_count) };

        assert_eq!(test_chain_conv.rule_count, test_ffi_chain.rule_count);

        for i in 0..test_chain_conv.rule_count {
            assert_eq!(
                test_chain_conv_rules[i].filter_count,
                test_ffi_chain_rules[i].filter_count
            );

            let test_chain_conv_filters = unsafe {
                std::slice::from_raw_parts(
                    test_chain_conv_rules[i].filters,
                    test_chain_conv_rules[i].filter_count,
                )
            };
            let test_ffi_chain_filters = unsafe {
                std::slice::from_raw_parts(
                    test_ffi_chain_rules[i].filters,
                    test_ffi_chain_rules[i].filter_count,
                )
            };

            for j in 0..test_chain_conv_rules[i].filter_count {
                assert_eq!(
                    test_chain_conv_filters[j].filter_type,
                    test_ffi_chain_filters[j].filter_type
                );

                match test_chain_conv_filters[j].filter_type {
                    LIBFW_FILTER_ASSOCIATED_DATA => {
                        assert_eq!(
                            unsafe {
                                test_chain_conv_filters[j]
                                    .filter
                                    .associated_data_filter
                                    .associated_data_len
                            },
                            unsafe {
                                test_ffi_chain_filters[j]
                                    .filter
                                    .associated_data_filter
                                    .associated_data_len
                            }
                        );
                        if unsafe {
                            test_chain_conv_filters[j]
                                .filter
                                .associated_data_filter
                                .associated_data
                                .is_null()
                        } {
                            assert!(unsafe {
                                test_ffi_chain_filters[j]
                                    .filter
                                    .associated_data_filter
                                    .associated_data
                                    .is_null()
                            });
                        } else {
                            assert!(!unsafe {
                                test_ffi_chain_filters[j]
                                    .filter
                                    .associated_data_filter
                                    .associated_data
                                    .is_null()
                            });
                            let test_chain_conv_assoc_data = unsafe {
                                std::slice::from_raw_parts(
                                    test_chain_conv_filters[j]
                                        .filter
                                        .associated_data_filter
                                        .associated_data,
                                    test_chain_conv_filters[j]
                                        .filter
                                        .associated_data_filter
                                        .associated_data_len,
                                )
                            };
                            let test_ffi_chain_assoc_data = unsafe {
                                std::slice::from_raw_parts(
                                    test_ffi_chain_filters[j]
                                        .filter
                                        .associated_data_filter
                                        .associated_data,
                                    test_ffi_chain_filters[j]
                                        .filter
                                        .associated_data_filter
                                        .associated_data_len,
                                )
                            };

                            for k in 0..test_ffi_chain_assoc_data.len() {
                                assert_eq!(
                                    test_ffi_chain_assoc_data[k],
                                    test_chain_conv_assoc_data[k]
                                );
                            }
                        }
                    }
                    LIBFW_FILTER_CONNTRACK_STATE => assert_eq!(
                        unsafe { test_chain_conv_filters[j].filter.conntrack_state_filter },
                        unsafe { test_ffi_chain_filters[j].filter.conntrack_state_filter }
                    ),
                    LIBFW_FILTER_SRC_NETWORK | LIBFW_FILTER_DST_NETWORK => {
                        let conv_network_filter =
                            unsafe { test_chain_conv_filters[j].filter.network_filter };
                        let ffi_network_filter =
                            unsafe { test_ffi_chain_filters[j].filter.network_filter };
                        assert_eq!(
                            conv_network_filter.network_addr.ip_type,
                            ffi_network_filter.network_addr.ip_type
                        );
                        match conv_network_filter.network_addr.ip_type {
                            LIBFW_IP_TYPE_V4 => {
                                assert_eq!(
                                    unsafe { conv_network_filter.network_addr.ip_data.ipv4_bytes },
                                    unsafe { ffi_network_filter.network_addr.ip_data.ipv4_bytes }
                                );
                            }
                            LIBFW_IP_TYPE_V6 => {
                                assert_eq!(
                                    unsafe { conv_network_filter.network_addr.ip_data.ipv6_bytes },
                                    unsafe { ffi_network_filter.network_addr.ip_data.ipv6_bytes }
                                );
                            }
                            _ => unreachable!("Unknown IP type"),
                        };

                        assert_eq!(
                            conv_network_filter.network_prefix,
                            ffi_network_filter.network_prefix
                        );
                        assert_eq!(
                            conv_network_filter.port_range_start,
                            ffi_network_filter.port_range_start
                        );
                        assert_eq!(
                            conv_network_filter.port_range_end,
                            ffi_network_filter.port_range_end
                        );
                    }
                    LIBFW_FILTER_DIRECTION => assert_eq!(
                        unsafe { test_chain_conv_filters[j].filter.direction_filter },
                        unsafe { test_ffi_chain_filters[j].filter.direction_filter }
                    ),
                    LIBFW_FILTER_NEXT_LVL_PROTO => assert_eq!(
                        unsafe { test_chain_conv_filters[j].filter.next_level_protocol },
                        unsafe { test_ffi_chain_filters[j].filter.next_level_protocol }
                    ),
                    LIBFW_FILTER_TCP_FLAGS => assert_eq!(
                        unsafe { test_chain_conv_filters[j].filter.tcp_flags },
                        unsafe { test_ffi_chain_filters[j].filter.tcp_flags }
                    ),
                    LIBFW_FILTER_ICMP_TYPE => assert_eq!(
                        unsafe { test_chain_conv_filters[j].filter.icmp_type },
                        unsafe { test_ffi_chain_filters[j].filter.icmp_type }
                    ),
                    _ => unreachable!("Unexpected filter type"),
                }
            }
        }
    }
}
