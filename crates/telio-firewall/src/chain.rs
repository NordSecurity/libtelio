//! Firewall chain implementation

use std::{
    convert::{TryFrom, TryInto},
    iter::FromIterator,
    mem::{forget, ManuallyDrop},
    net::IpAddr,
};

use ipnet::IpNet;
use pnet_packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket, udp::UdpPacket};

use crate::{
    conntrack::{Conntracker, LibfwConnectionState, LibfwDirection, LibfwVerdict},
    error::LibfwError,
    firewall::IpPacket,
};

///
/// IP type
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwIpVersion {
    /// IP v4
    LibfwIptypeIpv4 = 0,
    /// IP v4
    LibfwIptypeIpv6 = 1,
}

///
/// IP data
///
#[repr(C)]
#[derive(Copy, Clone)]
pub union LibfwIpData {
    /// Data for IPv4
    pub ipv4_bytes: [u8; 4],
    /// Data for IPv6
    pub ipv6_octets: [u8; 16],
}

///
/// IP representation
///
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LibfwIpAddr {
    /// Version of this IP addr
    pub ip_version: LibfwIpVersion,
    /// Actual IP bytes
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

///
/// Filter by the associate data
///
#[repr(C)]
#[derive(Clone, Debug)]
pub struct LibfwAssociatedData {
    /// Associated data
    associated_data: *mut u8,
    /// Associated data length
    associated_data_len: usize,
}

impl From<&[u8]> for LibfwAssociatedData {
    fn from(value: &[u8]) -> Self {
        let mut cloned_value = value.to_owned();
        let associated_data = cloned_value.as_mut_ptr();
        let associated_data_len = cloned_value.len();
        forget(cloned_value);
        LibfwAssociatedData {
            associated_data,
            associated_data_len,
        }
    }
}

impl From<&LibfwAssociatedData> for Vec<u8> {
    fn from(value: &LibfwAssociatedData) -> Self {
        unsafe { std::slice::from_raw_parts(value.associated_data, value.associated_data_len) }
            .to_owned()
    }
}

impl Drop for LibfwAssociatedData {
    fn drop(&mut self) {
        let _ = unsafe {
            Vec::from_raw_parts(
                self.associated_data,
                self.associated_data_len,
                self.associated_data_len,
            )
        };
    }
}

///
/// Filter types
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwFilterType {
    /// Only packets with particular associated data
    LibfwFilterAssociatedData = 0,
    /// Only packets with particular connection state
    LibfwFilterConntrackState = 1,
    /// Only packets with certain source network
    LibfwFilterSrcNetwork = 2,
    /// Only packets with certain destination network
    LibfwFilterDstNetwork = 3,
    /// Only inbound or outbound packets
    LibfwFilterDirection = 4,
}

///
/// Data for the certain filter type
///
#[repr(C)]
pub union LibfwFilterData {
    associated_data_filter: ManuallyDrop<LibfwAssociatedData>,
    conntrack_state_filter: LibfwConnectionState,
    network_filter: LibfwNetworkFilter,
    direction_filter: LibfwDirection,
}

///
/// Struct describing a single Libfw filter
///
#[repr(C)]
pub struct LibfwFilter {
    /// Filter may be inverted, meaning, that it is considered
    /// a match only if filter does *not* match
    inverted: bool,

    /// Defines a type of filter to match
    /// the packets against. There are a few
    /// possible filter types:
    /// * LIBFW_FILTER_ASSOCIATED_DATA - matches
    ///   packets based on their associated data.
    ///   This Normally means public key for NordLynx
    /// * LIBFW_FILTER_CONNTRACK_STATE - matches
    ///   connection tracking table state. This can be
    ///   either "new connection" or "established connection"
    /// * LIBFW_FILTER_[SRC|DST]_NETWORK - matches against
    ///   either source or destination network or IP address
    /// * LIBFW_FILTER_DIRECTION - matches either inbound or
    ///   outbound packet direction.
    filter_type: LibfwFilterType,

    /// Contains corresponding filter data
    filter: LibfwFilterData,
}

impl Drop for LibfwFilter {
    fn drop(&mut self) {
        if let LibfwFilterType::LibfwFilterAssociatedData = self.filter_type {
            unsafe {
                ManuallyDrop::drop(&mut self.filter.associated_data_filter);
            }
        }
    }
}

/// A definition of firewall rule it consists of filters which
/// determine whether rule applies to packet being processed.
/// And action, which determins what to do with the rule
#[repr(C)]
pub struct LibfwRule {
    /// List of filters all of which match
    /// in order to consider rule's action
    pub filters: *mut LibfwFilter,

    /// Length of the filter list
    pub filter_count: usize,

    /// Defines an action to be taken when filter
    /// matches packet. Generally either accept and
    /// stop processing rule chain or drop and stop
    /// processing rule chain.
    pub action: LibfwVerdict,
}

impl Drop for LibfwRule {
    fn drop(&mut self) {
        let _ = unsafe { Vec::from_raw_parts(self.filters, self.filter_count, self.filter_count) };
    }
}

/// A chain of rules.
///
/// Rules are processed in order specified in the chain.
/// If _some_ rule in the chain matches and a verdict is
/// determined - the chain processing terminated.
#[repr(C)]
pub struct LibfwChain {
    /// Chain size
    pub rule_count: usize,

    /// List of the rules
    pub rules: *mut LibfwRule,
}

impl Drop for LibfwChain {
    fn drop(&mut self) {
        let _ = unsafe { Vec::from_raw_parts(self.rules, self.rule_count, self.rule_count) };
    }
}

#[derive(Clone, Debug)]
struct NetworkFilterData {
    pub network: IpNet,
    pub port_range: (u16, u16),
}

enum NetworkFilterType {
    Src,
    Dst,
}

impl TryFrom<&LibfwNetworkFilter> for NetworkFilterData {
    type Error = LibfwError;

    fn try_from(value: &LibfwNetworkFilter) -> Result<Self, Self::Error> {
        Ok(NetworkFilterData {
            network: IpNet::new(
                match value.network_addr.ip_version {
                    LibfwIpVersion::LibfwIptypeIpv4 => {
                        IpAddr::V4(unsafe { value.network_addr.ip_data.ipv4_bytes }.into())
                    }
                    LibfwIpVersion::LibfwIptypeIpv6 => {
                        IpAddr::V6(unsafe { value.network_addr.ip_data.ipv6_octets }.into())
                    }
                },
                value.network_prefix,
            )
            .map_err(|_| LibfwError::LibfwErrorInvalidChain)?,
            port_range: (value.port_range_start, value.port_range_end),
        })
    }
}

impl From<&NetworkFilterData> for LibfwNetworkFilter {
    fn from(value: &NetworkFilterData) -> Self {
        let (ip_type, ip_data) = match value.network.network() {
            IpAddr::V4(ipv4_addr) => (
                LibfwIpVersion::LibfwIptypeIpv4,
                LibfwIpData {
                    ipv4_bytes: ipv4_addr.octets(),
                },
            ),
            IpAddr::V6(ipv6_addr) => (
                LibfwIpVersion::LibfwIptypeIpv6,
                LibfwIpData {
                    ipv6_octets: ipv6_addr.octets(),
                },
            ),
        };
        LibfwNetworkFilter {
            network_addr: LibfwIpAddr {
                ip_version: ip_type,
                ip_data,
            },
            network_prefix: value.network.prefix_len(),
            port_range_start: value.port_range.0,
            port_range_end: value.port_range.1,
        }
    }
}

impl NetworkFilterData {
    fn match_pkt<'a>(&self, packet: &impl IpPacket<'a>, filter_type: NetworkFilterType) -> bool {
        let packet_addr: crate::firewall::IpAddr = if let NetworkFilterType::Src = filter_type {
            packet.get_source().into()
        } else {
            packet.get_destination().into()
        };

        let std_ip_addr: IpAddr = packet_addr.into();
        if self.network.contains(&std_ip_addr) {
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    if let Some(p) = UdpPacket::new(packet.payload()) {
                        let port = if let NetworkFilterType::Src = filter_type {
                            p.get_source()
                        } else {
                            p.get_destination()
                        };

                        port >= self.port_range.0 && port <= self.port_range.1
                    } else {
                        false
                    }
                }
                IpNextHeaderProtocols::Tcp => {
                    if let Some(p) = TcpPacket::new(packet.payload()) {
                        let port = if let NetworkFilterType::Src = filter_type {
                            p.get_source()
                        } else {
                            p.get_destination()
                        };

                        port >= self.port_range.0 && port <= self.port_range.1
                    } else {
                        false
                    }
                }
                _ => true,
            }
        } else {
            false
        }
    }
}

enum FilterData {
    AssociatedData(Vec<u8>),
    ConntrackState(LibfwConnectionState),
    SrcNetwork(NetworkFilterData),
    DstNetwork(NetworkFilterData),
    Direction(LibfwDirection),
}

impl FilterData {
    fn match_pkt<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        packet_assoc_data: &[u8],
        packet_direction: LibfwDirection,
    ) -> bool {
        match self {
            FilterData::AssociatedData(assoc_data) => assoc_data == packet_assoc_data,
            FilterData::ConntrackState(conn_state) => conntracker
                .get_connection_state(packet, packet_assoc_data, packet_direction)
                .map(|cs| cs == *conn_state)
                .unwrap_or(false),
            FilterData::SrcNetwork(network_filter) => {
                network_filter.match_pkt(packet, NetworkFilterType::Src)
            }
            FilterData::DstNetwork(network_filter) => {
                network_filter.match_pkt(packet, NetworkFilterType::Dst)
            }
            FilterData::Direction(direction) => direction == &packet_direction,
        }
    }
}

struct Filter {
    filter_data: FilterData,
    inverted: bool,
}

impl TryFrom<&LibfwFilter> for Filter {
    type Error = LibfwError;

    fn try_from(value: &LibfwFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            filter_data: match value.filter_type {
                LibfwFilterType::LibfwFilterAssociatedData => {
                    FilterData::AssociatedData(Vec::from_iter(
                        unsafe {
                            std::slice::from_raw_parts::<u8>(
                                value.filter.associated_data_filter.associated_data,
                                value.filter.associated_data_filter.associated_data_len,
                            )
                        }
                        .iter()
                        .cloned(),
                    ))
                }
                LibfwFilterType::LibfwFilterConntrackState => {
                    FilterData::ConntrackState(unsafe { value.filter.conntrack_state_filter })
                }
                LibfwFilterType::LibfwFilterSrcNetwork => {
                    FilterData::SrcNetwork(unsafe { (&value.filter.network_filter).try_into()? })
                }
                LibfwFilterType::LibfwFilterDstNetwork => {
                    FilterData::DstNetwork(unsafe { (&value.filter.network_filter).try_into()? })
                }
                LibfwFilterType::LibfwFilterDirection => {
                    FilterData::Direction(unsafe { value.filter.direction_filter })
                }
            },
            inverted: value.inverted,
        })
    }
}

impl From<&Filter> for LibfwFilter {
    fn from(value: &Filter) -> Self {
        let (filter, filter_type) = match &value.filter_data {
            FilterData::AssociatedData(assoc_data) => (
                LibfwFilterData {
                    associated_data_filter: ManuallyDrop::new(assoc_data.as_slice().into()),
                },
                LibfwFilterType::LibfwFilterAssociatedData,
            ),
            FilterData::ConntrackState(connection_state) => (
                LibfwFilterData {
                    conntrack_state_filter: *connection_state,
                },
                LibfwFilterType::LibfwFilterConntrackState,
            ),
            FilterData::SrcNetwork(network_filter) => (
                LibfwFilterData {
                    network_filter: network_filter.into(),
                },
                LibfwFilterType::LibfwFilterSrcNetwork,
            ),
            FilterData::DstNetwork(network_filter) => (
                LibfwFilterData {
                    network_filter: network_filter.into(),
                },
                LibfwFilterType::LibfwFilterDstNetwork,
            ),

            FilterData::Direction(direction) => (
                LibfwFilterData {
                    direction_filter: *direction,
                },
                LibfwFilterType::LibfwFilterDirection,
            ),
        };
        LibfwFilter {
            inverted: value.inverted,
            filter_type,
            filter,
        }
    }
}

impl Filter {
    fn match_pkt<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        assoc_data: &[u8],
        direction: LibfwDirection,
    ) -> bool {
        let raw_result = self
            .filter_data
            .match_pkt(conntracker, packet, assoc_data, direction);
        if self.inverted {
            !raw_result
        } else {
            raw_result
        }
    }
}

struct Rule {
    filters: Vec<Filter>,
    action: LibfwVerdict,
}

impl Rule {
    fn match_pkt<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        assoc_data: &[u8],
        direction: LibfwDirection,
    ) -> bool {
        self.filters
            .iter()
            .all(|filter| filter.match_pkt(conntracker, packet, assoc_data, direction))
    }
}

impl From<&Rule> for LibfwRule {
    fn from(value: &Rule) -> Self {
        let mut new_filters = value
            .filters
            .iter()
            .map(|filter| filter.into())
            .collect::<Vec<LibfwFilter>>();
        let filters = new_filters.as_mut_ptr();
        forget(new_filters);

        Self {
            filters,
            filter_count: value.filters.len(),
            action: value.action,
        }
    }
}

impl TryFrom<&LibfwRule> for Rule {
    type Error = LibfwError;

    fn try_from(value: &LibfwRule) -> Result<Self, Self::Error> {
        Ok(Self {
            filters: unsafe {
                std::slice::from_raw_parts(value.filters, value.filter_count)
                    .iter()
                    .map(|filter| filter.try_into())
                    .collect::<Result<Vec<Filter>, LibfwError>>()?
            },
            action: value.action,
        })
    }
}

pub(crate) struct Chain {
    rules: Vec<Rule>,
}

impl TryFrom<&LibfwChain> for Chain {
    type Error = LibfwError;

    fn try_from(value: &LibfwChain) -> Result<Self, Self::Error> {
        Ok(Self {
            rules: unsafe {
                std::slice::from_raw_parts(value.rules, value.rule_count)
                    .iter()
                    .map(|rule| rule.try_into())
                    .collect::<Result<Vec<Rule>, LibfwError>>()?
            },
        })
    }
}

impl From<&Chain> for LibfwChain {
    fn from(value: &Chain) -> Self {
        let mut new_rules = value
            .rules
            .iter()
            .map(|rule| rule.into())
            .collect::<Vec<LibfwRule>>();

        let rules = new_rules.as_mut_ptr();
        forget(new_rules);

        Self {
            rule_count: value.rules.len(),
            rules,
        }
    }
}

impl Chain {
    pub(crate) fn process_packet<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        assoc_data: &[u8],
        direction: LibfwDirection,
    ) -> LibfwVerdict {
        for rule in self.rules.iter() {
            if rule.match_pkt(conntracker, packet, assoc_data, direction) {
                return rule.action;
            }
        }

        LibfwVerdict::LibfwVerdictAccept
    }
}

#[cfg(any(test, feature = "test_utils"))]
#[allow(missing_docs, unused)]
pub mod tests {
    use std::{
        convert::TryInto,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    };

    use ipnet::Ipv4Net;
    use pnet_packet::{
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        tcp::MutableTcpPacket,
        udp::MutableUdpPacket,
        MutablePacket,
    };
    use telio_crypto::SecretKey;
    use telio_model::PublicKey;

    use crate::{
        chain::{Filter, NetworkFilterData},
        conntrack::{
            unwrap_option_or_return, Conntracker, LibfwConnectionState, LibfwDirection,
            LibfwVerdict,
        },
        firewall::IpPacket,
    };

    const IPV4_HEADER_MIN: usize = 20; // IPv4 header minimal length in bytes
    const IPV6_HEADER_MIN: usize = 40; // IPv6 header minimal length in bytes
    const TCP_HEADER_MIN: usize = 20; // TCP header minimal length in bytes
    const UDP_HEADER: usize = 8; // UDP header length in bytes
    const ICMP_HEADER: usize = 8; // ICMP header length in bytes

    fn set_ipv4(
        ip: &mut MutableIpv4Packet,
        protocol: IpNextHeaderProtocol,
        header_length: usize,
        total_length: usize,
    ) {
        ip.set_next_level_protocol(protocol);
        ip.set_version(4);
        ip.set_header_length((header_length / 4) as u8);
        ip.set_total_length(total_length.try_into().unwrap());
        ip.set_flags(2);
        ip.set_ttl(64);
        ip.set_source(Ipv4Addr::LOCALHOST);
        ip.set_destination(Ipv4Addr::new(8, 8, 8, 8));
    }

    fn make_random_peer() -> PublicKey {
        SecretKey::gen().public()
    }

    pub fn make_udp(src: &str, dst: &str) -> Vec<u8> {
        let msg: &str = "Some message";
        let msg_len = msg.len();
        let ip_len = IPV4_HEADER_MIN + UDP_HEADER + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("UDP: Bad IP buffer");
        set_ipv4(&mut ip, IpNextHeaderProtocols::Udp, IPV4_HEADER_MIN, ip_len);
        let source: SocketAddrV4 = src
            .parse()
            .expect(&format!("UDPv4: Bad src address: {src}"));
        let destination: SocketAddrV4 = dst
            .parse()
            .expect(&format!("UDPv4: Bad dst address: {dst}"));
        ip.set_source(*source.ip());
        ip.set_destination(*destination.ip());

        let mut udp =
            MutableUdpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("UDP: Bad UDP buffer");
        udp.set_source(source.port());
        udp.set_destination(destination.port());
        udp.set_length((UDP_HEADER + msg_len) as u16);
        udp.set_checksum(0);
        udp.payload_mut().copy_from_slice(msg.as_bytes());

        raw
    }

    #[test]
    fn network_filter() {
        let net_filter = NetworkFilterData {
            network: ipnet::IpNet::V4(Ipv4Net::new(Ipv4Addr::new(168, 72, 0, 0), 16).unwrap()),
            port_range: (1000, 9000),
        };
        let dst_filter = Filter {
            filter_data: super::FilterData::DstNetwork(net_filter.clone()),
            inverted: false,
        };
        let src_filter = Filter {
            filter_data: super::FilterData::SrcNetwork(net_filter),
            inverted: false,
        };

        let pk = make_random_peer();
        let ctk = Conntracker::new(10, 1000);

        // Test UDP with proper source
        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(!dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));

        // Test UDP with proper destination
        let pkt = make_udp("100.0.0.2:5678", "168.72.0.12:1234");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(!src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));

        // Test UDP with proper source port
        let pkt = make_udp("168.72.0.12:1234", "168.72.0.12:10000");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(!dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));

        // Test UDP with proper dst port
        let pkt = make_udp("168.72.0.12:10000", "168.72.0.12:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(!src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!src_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(dst_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
    }

    #[test]
    fn assoc_data_filter() {
        let pk = make_random_peer();
        let another_pk = make_random_peer();
        let ctk = Conntracker::new(10, 1000);

        let data_filter = Filter {
            filter_data: super::FilterData::AssociatedData(pk.clone().to_vec()),
            inverted: false,
        };
        let data_filter_inv = Filter {
            filter_data: super::FilterData::AssociatedData(pk.clone().to_vec()),
            inverted: true,
        };

        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));

        assert!(data_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!data_filter.match_pkt(
            &ctk,
            &ip,
            &another_pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!data_filter_inv.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(data_filter_inv.match_pkt(
            &ctk,
            &ip,
            &another_pk,
            LibfwDirection::LibfwDirectionInbound
        ));
    }

    #[test]
    fn direction_filter() {
        let pk = make_random_peer();
        let ctk = Conntracker::new(10, 1000);

        let direction_filter = Filter {
            filter_data: super::FilterData::Direction(LibfwDirection::LibfwDirectionInbound),
            inverted: false,
        };
        let direction_filter_inv = Filter {
            filter_data: super::FilterData::Direction(LibfwDirection::LibfwDirectionInbound),
            inverted: true,
        };

        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));

        assert!(direction_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!direction_filter.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionOutbound
        ));
        assert!(!direction_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(direction_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionOutbound
        ));
    }

    #[test]
    fn conntrack_filter() {
        let pk = make_random_peer();
        let ctk = Conntracker::new(10, 1000);

        let conn_new_filter = Filter {
            filter_data: super::FilterData::ConntrackState(
                LibfwConnectionState::LibfwConnectionStateNew,
            ),
            inverted: false,
        };
        let conn_new_filter_inv = Filter {
            filter_data: super::FilterData::ConntrackState(
                LibfwConnectionState::LibfwConnectionStateNew,
            ),
            inverted: true,
        };
        let conn_established_filter = Filter {
            filter_data: super::FilterData::ConntrackState(
                LibfwConnectionState::LibfwConnectionStateEstablished,
            ),
            inverted: false,
        };
        let conn_established_filter_inv = Filter {
            filter_data: super::FilterData::ConntrackState(
                LibfwConnectionState::LibfwConnectionStateEstablished,
            ),
            inverted: true,
        };

        let pkt_out = make_udp("168.72.0.12:1234", "168.72.0.11:5678");
        let ip_out = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt_out));

        let pkt = make_udp("168.72.0.11:5678", "168.72.0.12:1234");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));

        assert!(!conn_new_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(conn_new_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!conn_established_filter.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(conn_established_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));

        ctk.handle_outbound_udp(&ip_out, &pk);

        assert!(conn_new_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!conn_new_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!conn_established_filter.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(conn_established_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));

        ctk.handle_inbound_udp(&ip, &pk, LibfwVerdict::LibfwVerdictAccept);

        assert!(!conn_new_filter.match_pkt(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(conn_new_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(conn_established_filter.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!conn_established_filter_inv.match_pkt(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
    }
}
