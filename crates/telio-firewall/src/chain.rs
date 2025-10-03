//! Firewall chain implementation

use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    net::IpAddr,
};

use ipnet::IpNet;
use num_enum::TryFromPrimitive;
use pnet_packet::{
    icmp::IcmpPacket,
    ip::IpNextHeaderProtocols::{self, Icmp, Icmpv6, Tcp, Udp},
    tcp::TcpPacket,
    udp::UdpPacket,
};
use smallvec::ToSmallVec;
use telio_utils::telio_log_warn;

use crate::{
    conntrack::{AssociatedData, ConnectionState, Direction},
    error::Error,
    ffi_chain::{
        LibfwChain, LibfwFilter, LibfwNetworkFilter, LibfwRule, LibfwVerdict,
        LIBFW_FILTER_ASSOCIATED_DATA, LIBFW_FILTER_CONNTRACK_STATE, LIBFW_FILTER_DIRECTION,
        LIBFW_FILTER_DST_NETWORK, LIBFW_FILTER_ICMP_TYPE, LIBFW_FILTER_NEXT_LVL_PROTO,
        LIBFW_FILTER_SRC_NETWORK, LIBFW_FILTER_TCP_FLAGS, LIBFW_ICMP_TYPE_DESTINATION_UNREACHABLE,
        LIBFW_ICMP_TYPE_ECHO_REPLY, LIBFW_ICMP_TYPE_ECHO_REQUEST,
        LIBFW_ICMP_TYPE_PARAMETER_PROBLEM, LIBFW_ICMP_TYPE_REDIRECT_MESSAGE,
        LIBFW_ICMP_TYPE_ROUTER_ADVERTISEMENT, LIBFW_ICMP_TYPE_ROUTER_SOLICITATION,
        LIBFW_ICMP_TYPE_TIMESTAMP, LIBFW_ICMP_TYPE_TIMESTAMP_REPLY, LIBFW_ICMP_TYPE_TIME_EXCEEDED,
        LIBFW_IP_TYPE_V4, LIBFW_IP_TYPE_V6, LIBFW_NEXT_PROTO_ICMP, LIBFW_NEXT_PROTO_ICMPV6,
        LIBFW_NEXT_PROTO_TCP, LIBFW_NEXT_PROTO_UDP,
    },
    firewall::IpPacket,
};

///
/// Necessary data for network filter:
///  * network - range of matching IP addresses
///  * ports - range of matching ports (usually it is either a single port or full range)
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetworkFilter {
    pub(crate) network: IpNet,
    pub(crate) ports: (u16, u16),
}

///
/// Determines whether network filter data should be checked for source or destination packet data
///
#[derive(Debug)]
enum NetworkFilterType {
    Src,
    Dst,
}

macro_rules! get_inner_packet_port {
    ($kind: ty, $packet: expr, $filter_type: expr) => {
        <$kind>::new($packet.payload()).map(|p| match $filter_type {
            NetworkFilterType::Src => p.get_source(),
            NetworkFilterType::Dst => p.get_destination(),
        })
    };
}

impl NetworkFilter {
    ///
    /// Checks whether the packet matches the network filter.
    ///
    /// @param packet       Assumed packet
    /// @param filter_type  Which packet endpoint should be checked - source or destination
    ///
    /// @return             Boolean value, true if packet matches the filter, false otherwise
    ///
    fn is_matching<'a>(&self, packet: &impl IpPacket<'a>, filter_type: NetworkFilterType) -> bool {
        let packet_addr: IpAddr = match filter_type {
            NetworkFilterType::Src => packet.get_source(),
            NetworkFilterType::Dst => packet.get_destination(),
        }
        .into();

        if !self.network.contains(&packet_addr) {
            return false;
        }

        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => get_inner_packet_port!(UdpPacket, packet, filter_type),
            IpNextHeaderProtocols::Tcp => get_inner_packet_port!(TcpPacket, packet, filter_type),
            _ => {
                return true;
            }
        }
        .map(|port| self.ports.0 <= port && port <= self.ports.1)
        .unwrap_or(false)
    }
}

impl TryFrom<&LibfwNetworkFilter> for NetworkFilter {
    type Error = Error;

    fn try_from(value: &LibfwNetworkFilter) -> Result<Self, Self::Error> {
        Ok(NetworkFilter {
            network: IpNet::new(
                match value.network_addr.ip_type {
                    LIBFW_IP_TYPE_V4 => {
                        IpAddr::V4(unsafe { value.network_addr.ip_data.ipv4_bytes }.into())
                    }
                    LIBFW_IP_TYPE_V6 => {
                        IpAddr::V6(unsafe { value.network_addr.ip_data.ipv6_bytes }.into())
                    }
                    unexpected_ip_version => {
                        telio_log_warn!(
                            "Malformed chain: Unexpected IP version: {}",
                            unexpected_ip_version
                        );
                        return Err(Error::InvalidChain);
                    }
                },
                value.network_prefix,
            )
            .map_err(|_| {
                telio_log_warn!(
                    "Malformed IP network: ip_type: {:?} net_mask: {}",
                    value.network_addr.ip_type,
                    value.network_prefix
                );
                Error::InvalidChain
            })?,
            ports: if value.port_range_start <= value.port_range_end {
                (value.port_range_start, value.port_range_end)
            } else {
                telio_log_warn!(
                    "Start of the port range is larger than the end: start: {} end: {}",
                    value.port_range_start,
                    value.port_range_end
                );
                return Err(Error::InvalidChain);
            },
        })
    }
}

///
/// Next level protocol (L4)
///
#[allow(clippy::enum_variant_names)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub(crate) enum NextLevelProtocol {
    Tcp = LIBFW_NEXT_PROTO_TCP,
    Udp = LIBFW_NEXT_PROTO_UDP,
    Icmp = LIBFW_NEXT_PROTO_ICMP,
    Icmpv6 = LIBFW_NEXT_PROTO_ICMPV6,
}

///
/// ICMP Type
///
#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum IcmpType {
    EchoReply = LIBFW_ICMP_TYPE_ECHO_REPLY,
    DestinationUnreachable = LIBFW_ICMP_TYPE_DESTINATION_UNREACHABLE,
    RedirectMessage = LIBFW_ICMP_TYPE_REDIRECT_MESSAGE,
    EchoRequest = LIBFW_ICMP_TYPE_ECHO_REQUEST,
    RouterAdvertisement = LIBFW_ICMP_TYPE_ROUTER_ADVERTISEMENT,
    RouterSolicitation = LIBFW_ICMP_TYPE_ROUTER_SOLICITATION,
    TimeExceeded = LIBFW_ICMP_TYPE_TIME_EXCEEDED,
    ParameterProblem = LIBFW_ICMP_TYPE_PARAMETER_PROBLEM,
    Timestamp = LIBFW_ICMP_TYPE_TIMESTAMP,
    TimestampReply = LIBFW_ICMP_TYPE_TIMESTAMP_REPLY,
}

///
/// Defines a type of filter to match the packets against and the necessary data.
/// There are a few possible filter types:
/// * AssociatedData - matches packets based on their associated data.
///   This Normally means public key for NordLynx
/// * ConntrackState - matches connection tracking table state.
/// * (Src|Dst)Network - matches against either source or destination network
/// * Direction - matches either inbound or outbound packet direction.
/// * NextLevelProtocol - matches the next layer protocol, currently tcp, udp, icmp or icmpv6
/// * TcpFlags - checks whether the packets has any flag from the given set.
/// * IcmpType - matches ICMP packets of a particular type
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FilterData {
    AssociatedData(AssociatedData),
    ConntrackState(ConnectionState),
    #[allow(dead_code)]
    SrcNetwork(NetworkFilter),
    DstNetwork(NetworkFilter),
    Direction(Direction),
    NextLevelProtocol(NextLevelProtocol),
    TcpFlags(u8),
    IcmpType(IcmpType),
}

impl FilterData {
    ///
    /// Checks whether the packet matches the given filter data.
    ///
    /// @param packet_conn_state   State of the matching connection returned by Conntracker
    /// @param packet              Packet itself
    /// @param packet_assoc_data   Data associated with the packet, usually pubkey of the appropriate node
    /// @param packet_direction    Whether the packet is inbound or outbound
    ///
    /// @return                    Boolean, whether the packet matches filter or not (without filter inversion)
    ///
    fn is_matching<'a>(
        &self,
        packet_conn_state: ConnectionState,
        packet: &impl IpPacket<'a>,
        packet_assoc_data: Option<&[u8]>,
        packet_direction: Direction,
    ) -> bool {
        match self {
            FilterData::AssociatedData(assoc_data) => match (assoc_data, packet_assoc_data) {
                (None, None) => true,
                (Some(filter_assoc_data), Some(pkt_assoc_data)) => {
                    filter_assoc_data.as_slice() == pkt_assoc_data
                }
                _ => false,
            },
            FilterData::ConntrackState(conn_state) => packet_conn_state == *conn_state,
            FilterData::SrcNetwork(network_filter) => {
                network_filter.is_matching(packet, NetworkFilterType::Src)
            }
            FilterData::DstNetwork(network_filter) => {
                network_filter.is_matching(packet, NetworkFilterType::Dst)
            }
            FilterData::Direction(direction) => *direction == packet_direction,
            FilterData::NextLevelProtocol(next_level_protocol) => {
                let proto = packet.get_next_level_protocol();
                match next_level_protocol {
                    NextLevelProtocol::Udp => proto == Udp,
                    NextLevelProtocol::Tcp => proto == Tcp,
                    NextLevelProtocol::Icmp => proto == Icmp,
                    NextLevelProtocol::Icmpv6 => proto == Icmpv6,
                }
            }
            FilterData::TcpFlags(flags) if packet.get_next_level_protocol() == Tcp => {
                TcpPacket::new(packet.payload())
                    .map(|pkt| pkt.get_flags() & flags != 0)
                    .unwrap_or(false)
            }
            FilterData::TcpFlags(_) => false,
            FilterData::IcmpType(libfw_icmp_type) if packet.get_next_level_protocol() == Icmp => {
                IcmpPacket::new(packet.payload())
                    .map(|pkt| pkt.get_icmp_type().0 == *libfw_icmp_type as u8)
                    .unwrap_or(false)
            }
            FilterData::IcmpType(_) => false,
        }
    }
}

///
/// Firewall filter type - in practice it is FilterData extended with
/// possibility of inverting fiters with `inverted` flag.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Filter {
    pub(crate) filter_data: FilterData,
    pub(crate) inverted: bool,
}

impl Filter {
    ///
    /// Checks whether the packet matches the given filter. Just applies filter inversion to
    /// the result of `FiltrData::is_matching`
    ///
    /// @param packet_conn_state   State of the matching connection returned by Conntracker
    /// @param packet              Packet itself
    /// @param packet_assoc_data   Data associated with the packet, usually pubkey of the appropriate node
    /// @param packet_direction    Whether the packet is inbound or outbound
    ///
    /// @return                    Boolean, whether the packet matches filter or not (without filter inversion)
    ///
    fn is_matching<'a>(
        &self,
        conn_state: ConnectionState,
        packet: &impl IpPacket<'a>,
        assoc_data: Option<&[u8]>,
        direction: Direction,
    ) -> bool {
        self.filter_data
            .is_matching(conn_state, packet, assoc_data, direction)
            != self.inverted
    }
}

impl TryFrom<&LibfwFilter> for Filter {
    type Error = Error;

    fn try_from(value: &LibfwFilter) -> Result<Self, Self::Error> {
        Ok(Self {
            filter_data: match value.filter_type {
                LIBFW_FILTER_ASSOCIATED_DATA => {
                    let assoc_data = unsafe { &value.filter.associated_data_filter };
                    if assoc_data.associated_data.is_null() {
                        FilterData::AssociatedData(None)
                    } else {
                        FilterData::AssociatedData(Some(unsafe {
                            std::slice::from_raw_parts::<u8>(
                                assoc_data.associated_data,
                                assoc_data.associated_data_len,
                            )
                            .to_smallvec()
                        }))
                    }
                }
                LIBFW_FILTER_CONNTRACK_STATE => FilterData::ConntrackState(
                    // Because we already have some integer value in the union, we reuse it for
                    // enum validation instead of creating a new one for ths purpose
                    ConnectionState::try_from(unsafe { value.filter.conntrack_state_filter })
                        .map_err(|_| {
                            telio_log_warn!(
                                "Invalid chain - wrong value for conntrack state filter: {}",
                                unsafe { value.filter.tcp_flags }
                            );
                            Error::InvalidChain
                        })?,
                ),
                LIBFW_FILTER_SRC_NETWORK => {
                    FilterData::SrcNetwork(unsafe { &value.filter.network_filter }.try_into()?)
                }
                LIBFW_FILTER_DST_NETWORK => {
                    FilterData::DstNetwork(unsafe { &value.filter.network_filter }.try_into()?)
                }
                LIBFW_FILTER_DIRECTION => FilterData::Direction(
                    // Because we already have some integer value in the union, we reuse it for
                    // enum validation instead of creating a new one for ths purpose
                    Direction::try_from(unsafe { value.filter.tcp_flags }).map_err(|_| {
                        telio_log_warn!(
                            "Invalid chain - wrong value for direction filter: {}",
                            unsafe { value.filter.tcp_flags }
                        );
                        Error::InvalidChain
                    })?,
                ),
                LIBFW_FILTER_NEXT_LVL_PROTO => FilterData::NextLevelProtocol(
                    // Because we already have some integer value in the union, we reuse it for
                    // enum validation instead of creating a new one for ths purpose
                    NextLevelProtocol::try_from(unsafe { value.filter.tcp_flags }).map_err(
                        |_| {
                            telio_log_warn!(
                                "Invalid chain - wrong value for next level protocol filter: {}",
                                unsafe { value.filter.tcp_flags }
                            );
                            Error::InvalidChain
                        },
                    )?,
                ),
                LIBFW_FILTER_TCP_FLAGS => FilterData::TcpFlags(unsafe { value.filter.tcp_flags }),
                LIBFW_FILTER_ICMP_TYPE => FilterData::IcmpType(
                    // Because we already have some integer value in the union, we reuse it for
                    // enum validation instead of creating a new one for ths purpose
                    IcmpType::try_from(unsafe { value.filter.tcp_flags }).map_err(|_| {
                        telio_log_warn!(
                            "Invalid chain - wrong value for icmp type filter: {}",
                            unsafe { value.filter.tcp_flags }
                        );
                        Error::InvalidChain
                    })?,
                ),
                _ => {
                    telio_log_warn!(
                        "Invalid chain - wrong value for icmp type filter: {}",
                        unsafe { value.filter.tcp_flags }
                    );
                    return Err(Error::InvalidChain);
                }
            },
            inverted: value.inverted,
        })
    }
}

///
/// A definition of firewall rule it consists of filters which determine whether rule applies to packet
/// being processed and action, which determines what to do with the rule.
///
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) filters: Vec<Filter>,
    pub(crate) action: LibfwVerdict,
}

impl Rule {
    ///
    /// Checks whether the given packet matches all of the rule's filters.
    ///
    /// @param conn_state   State of the matching connection returned by Conntracker
    /// @param packet       Packet itself
    /// @param assoc_data   Data associated with the packet, usually pubkey of the appropriate node
    /// @param direction    Whether the packet is inbound or outbound
    ///
    /// @return             Boolean value, true if packet matched all of the filters, false otherwise
    ///
    fn is_matching<'a>(
        &self,
        conn_state: ConnectionState,
        packet: &impl IpPacket<'a>,
        assoc_data: Option<&[u8]>,
        direction: Direction,
    ) -> bool {
        self.filters
            .iter()
            .all(|filter| filter.is_matching(conn_state, packet, assoc_data, direction))
    }
}

impl TryFrom<&LibfwRule> for Rule {
    type Error = Error;

    fn try_from(value: &LibfwRule) -> Result<Self, Self::Error> {
        let action = match value.action.try_into() {
            Ok(action) => action,
            Err(_) => {
                telio_log_warn!("Malformed chain: invalid rule.action value");
                return Err(Error::InvalidChain);
            }
        };
        if value.filter_count == 0 {
            Ok(Self {
                filters: vec![],
                action,
            })
        } else if value.filters.is_null() {
            telio_log_warn!("Pointer to chain rules is NULL, but rule count is non-zero");
            Err(Error::NullPointer)
        } else {
            Ok(Self {
                filters: unsafe {
                    std::slice::from_raw_parts(value.filters, value.filter_count)
                        .iter()
                        .map(|filter| filter.try_into())
                        .collect::<Result<Vec<Filter>, Error>>()?
                },
                action,
            })
        }
    }
}

///
/// Rust representation of the firewall chain.
/// Decides packets destiny with `process_packet` method.
///
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Chain {
    pub(crate) rules: Vec<Rule>,
}

impl Chain {
    ///
    /// Function for processing packets which iterates over the rules and returns the action of the first matching rule.
    /// When there is no rule matching, returns Drop.
    ///
    /// @param conn_state   State of the matching connection returned by Conntracker
    /// @param packet       Packet itself
    /// @param assoc_data   Data associated with the packet, usually pubkey of the appropriate node
    /// @param direction    Whether the packet is inbound or outbound
    ///
    /// @return             Verdict for the packet: Accept, Drop or Reject
    ///
    pub(crate) fn process_packet<'a>(
        &self,
        conn_state: ConnectionState,
        packet: &impl IpPacket<'a>,
        assoc_data: Option<&[u8]>,
        direction: Direction,
    ) -> LibfwVerdict {
        self.rules
            .iter()
            .find(|rule| rule.is_matching(conn_state, packet, assoc_data, direction))
            .map(|rule| rule.action)
            .unwrap_or(LibfwVerdict::LibfwVerdictDrop)
    }
}

impl TryFrom<&LibfwChain> for Chain {
    type Error = Error;

    fn try_from(value: &LibfwChain) -> Result<Self, Self::Error> {
        if value.rule_count == 0 {
            Ok(Self { rules: vec![] })
        } else if value.rules.is_null() {
            telio_log_warn!("Pointer to chain rules is NULL, but rule count is non-zero");
            Err(Error::NullPointer)
        } else {
            Ok(Self {
                rules: unsafe {
                    std::slice::from_raw_parts(value.rules, value.rule_count)
                        .iter()
                        .map(|rule| rule.try_into())
                        .collect::<Result<Vec<Rule>, Error>>()?
                },
            })
        }
    }
}

#[cfg(test)]
#[allow(missing_docs, unused)]
pub mod tests {
    use std::{
        convert::TryInto,
        mem::ManuallyDrop,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
        ptr::{null, null_mut, slice_from_raw_parts},
        time::Duration,
    };

    use ipnet::Ipv4Net;
    use pnet_packet::{
        icmp::{IcmpType, IcmpTypes, MutableIcmpPacket},
        icmpv6::{Icmpv6Type, Icmpv6Types, MutableIcmpv6Packet},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        tcp::{MutableTcpPacket, TcpFlags},
        udp::MutableUdpPacket,
        MutablePacket,
    };
    use rand::prelude::*;
    use smallvec::ToSmallVec;

    use crate::{
        chain::{
            Chain, Filter, FilterData, IcmpType as OurIcmpType, LibfwChain, LibfwFilter,
            LibfwNetworkFilter, LibfwRule, LibfwVerdict, NetworkFilter, NextLevelProtocol, Rule,
        },
        conntrack::{unwrap_option_or_return, ConnectionState, Conntrack, Direction},
        error::Error,
        ffi_chain::{
            LibfwAssociatedData, LibfwFilterData, LibfwIpAddr, LibfwIpData,
            LIBFW_CONTRACK_STATE_ESTABLISHED, LIBFW_DIRECTION_INBOUND, LIBFW_DIRECTION_OUTBOUND,
            LIBFW_FILTER_ASSOCIATED_DATA, LIBFW_FILTER_CONNTRACK_STATE, LIBFW_FILTER_DIRECTION,
            LIBFW_FILTER_DST_NETWORK, LIBFW_FILTER_ICMP_TYPE, LIBFW_FILTER_NEXT_LVL_PROTO,
            LIBFW_FILTER_SRC_NETWORK, LIBFW_FILTER_TCP_FLAGS, LIBFW_ICMP_TYPE_ECHO_REPLY,
            LIBFW_IP_TYPE_V4, LIBFW_NEXT_PROTO_UDP, LIBFW_VERDICT_ACCEPT, LIBFW_VERDICT_DROP,
            LIBFW_VERDICT_REJECT,
        },
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
        ip.set_flags(2); // Don't fragment flag
        ip.set_ttl(64);
    }

    fn make_random_peer() -> Vec<u8> {
        let mut result = vec![0, 16];
        rand::thread_rng().fill_bytes(&mut result);

        return result;
    }

    pub fn make_udp(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let msg: &str = "Some message";
        let msg_len = msg.len();
        let ip_len = IPV4_HEADER_MIN + UDP_HEADER + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("UDP: Bad IP buffer");
        set_ipv4(&mut ip, IpNextHeaderProtocols::Udp, IPV4_HEADER_MIN, ip_len);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);

        let mut udp =
            MutableUdpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("UDP: Bad UDP buffer");
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length((UDP_HEADER + msg_len) as u16);
        udp.set_checksum(0);
        udp.payload_mut().copy_from_slice(msg.as_bytes());

        raw
    }

    pub fn make_tcp(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let msg: &str = "Some message";
        let msg_len = msg.as_bytes().len();
        let ip_len = IPV4_HEADER_MIN + TCP_HEADER_MIN + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("TCP: Bad IP buffer");
        set_ipv4(&mut ip, IpNextHeaderProtocols::Tcp, IPV4_HEADER_MIN, ip_len);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);

        let mut tcp =
            MutableTcpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("TCP: Bad TCP buffer");
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_checksum(0);
        tcp.payload_mut().copy_from_slice(msg.as_bytes());
        tcp.set_flags(flags);

        raw
    }

    fn make_icmp4_with_body(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        icmp_type: IcmpType,
        body: &[u8],
    ) -> Vec<u8> {
        let additional_body_len = body.len().saturating_sub(14);
        let ip_len = IPV4_HEADER_MIN + ICMP_HEADER + 10 + additional_body_len;
        let mut raw = vec![0u8; ip_len];

        let mut packet =
            MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(icmp_type);

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Icmp,
            IPV4_HEADER_MIN,
            ip_len,
        );
        ip.set_source(src);
        ip.set_destination(dst);

        let body_start = 14.max(body.len());
        for (i, b) in body.iter().enumerate() {
            raw[ip_len - (body_start - i)] = *b;
        }

        raw
    }

    fn make_icmp4(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: IcmpType) -> Vec<u8> {
        make_icmp4_with_body(src, dst, icmp_type, &[])
    }

    // Ipv6 packets creation
    fn set_ipv6(
        ip: &mut MutableIpv6Packet,
        protocol: IpNextHeaderProtocol,
        header_length: usize,
        total_length: usize,
    ) {
        ip.set_next_header(protocol);
        ip.set_version(6);
        ip.set_traffic_class(0);
        ip.set_flow_label(0);
        ip.set_payload_length((total_length - header_length).try_into().unwrap());
        ip.set_hop_limit(64);
        ip.set_source(Ipv6Addr::LOCALHOST);
        ip.set_destination(Ipv6Addr::new(2001, 4860, 4860, 0, 0, 0, 0, 8888));
    }

    fn make_icmp6_with_body(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        icmp_type: Icmpv6Type,
        body: &[u8],
    ) -> Vec<u8> {
        let additional_body_len = body.len().saturating_sub(14);
        let ip_len = IPV6_HEADER_MIN + ICMP_HEADER + 10 + additional_body_len;
        let mut raw = vec![0u8; ip_len];

        let mut packet =
            MutableIcmpv6Packet::new(&mut raw[IPV6_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmpv6_type(icmp_type);

        let mut ip = MutableIpv6Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv6(
            &mut ip,
            IpNextHeaderProtocols::Icmpv6,
            IPV6_HEADER_MIN,
            ip_len,
        );
        ip.set_source(src);
        ip.set_destination(dst);

        let body_start = 14.max(body.len());
        for (i, b) in body.iter().enumerate() {
            raw[ip_len - (body_start - i)] = *b;
        }

        raw
    }

    fn make_icmp6(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: Icmpv6Type) -> Vec<u8> {
        make_icmp6_with_body(src, dst, icmp_type, &[])
    }

    #[test]
    fn test_network_filter() {
        let net_filter = NetworkFilter {
            network: ipnet::IpNet::V4(Ipv4Net::new(Ipv4Addr::new(168, 72, 0, 0), 16).unwrap()),
            ports: (1000, 9000),
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

        // Test UDP with matching source
        let pkt = make_udp(
            Ipv4Addr::new(168, 72, 0, 12),
            1234,
            Ipv4Addr::new(100, 0, 0, 2),
            5678,
        );
        let ip = unwrap_option_or_return!(Ipv4Packet::new(&pkt));
        assert!(src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));
        assert!(!dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(!dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));

        // Test UDP with matching destination
        let pkt = make_udp(
            Ipv4Addr::new(100, 0, 0, 2),
            5678,
            Ipv4Addr::new(168, 72, 0, 12),
            1234,
        );
        let ip = unwrap_option_or_return!(Ipv4Packet::new(&pkt));
        assert!(!src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(!src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));
        assert!(dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));

        // Test UDP with matching source port
        let pkt = make_udp(
            Ipv4Addr::new(168, 72, 0, 12),
            1234,
            Ipv4Addr::new(100, 0, 0, 2),
            10000,
        );
        let ip = unwrap_option_or_return!(Ipv4Packet::new(&pkt));
        assert!(src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));
        assert!(!dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(!dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));

        // Test UDP with matching dst port
        let pkt = make_udp(
            Ipv4Addr::new(100, 0, 0, 2),
            10000,
            Ipv4Addr::new(168, 72, 0, 12),
            5678,
        );
        let ip = unwrap_option_or_return!(Ipv4Packet::new(&pkt));
        assert!(!src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(!src_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));
        assert!(dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(dst_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Outbound));
    }

    #[test]
    fn test_assoc_data_filter() {
        let pk = make_random_peer();
        let another_pk = make_random_peer();

        let data_filter = Filter {
            filter_data: super::FilterData::AssociatedData(Some(pk.clone().to_smallvec())),
            inverted: false,
        };
        let data_filter_inv = Filter {
            filter_data: super::FilterData::AssociatedData(Some(pk.clone().to_smallvec())),
            inverted: true,
        };

        let pkt = make_udp(
            Ipv4Addr::new(168, 72, 0, 12),
            1234,
            Ipv4Addr::new(100, 0, 0, 2),
            5678,
        );
        let ip = unwrap_option_or_return!(Ipv4Packet::new(&pkt));

        assert!(data_filter.is_matching(ConnectionState::New, &ip, Some(&pk), Direction::Inbound));
        assert!(!data_filter.is_matching(
            ConnectionState::New,
            &ip,
            Some(&another_pk),
            Direction::Inbound
        ));
        assert!(!data_filter_inv.is_matching(
            ConnectionState::New,
            &ip,
            Some(&pk),
            Direction::Inbound
        ));
        assert!(data_filter_inv.is_matching(
            ConnectionState::New,
            &ip,
            Some(&another_pk),
            Direction::Inbound
        ));
    }

    #[test]
    fn test_direction_filter() {
        let pk = make_random_peer();

        let direction_filter = Filter {
            filter_data: super::FilterData::Direction(Direction::Inbound),
            inverted: false,
        };
        let direction_filter_inv = Filter {
            filter_data: super::FilterData::Direction(Direction::Inbound),
            inverted: true,
        };

        let pkt = make_udp(
            Ipv4Addr::new(168, 72, 0, 12),
            1234,
            Ipv4Addr::new(100, 0, 0, 2),
            5678,
        );
        let ip = unwrap_option_or_return!(Ipv4Packet::new(&pkt));

        assert!(direction_filter.is_matching(
            ConnectionState::New,
            &ip,
            Some(&pk),
            Direction::Inbound
        ));
        assert!(!direction_filter.is_matching(
            ConnectionState::New,
            &ip,
            Some(&pk),
            Direction::Outbound
        ));
        assert!(!direction_filter_inv.is_matching(
            ConnectionState::New,
            &ip,
            Some(&pk),
            Direction::Inbound
        ));
        assert!(direction_filter_inv.is_matching(
            ConnectionState::New,
            &ip,
            Some(&pk),
            Direction::Outbound
        ));
    }

    #[test]
    fn test_conntrack_filter() {
        let pk = make_random_peer();
        let pkt = make_udp(
            Ipv4Addr::new(168, 72, 0, 12),
            1234,
            Ipv4Addr::new(100, 0, 0, 2),
            5678,
        );
        let ip = unwrap_option_or_return!(Ipv4Packet::new(&pkt));

        let all_conn_states = [
            ConnectionState::New,
            ConnectionState::Established,
            ConnectionState::Closed,
        ];

        for conn_state in all_conn_states {
            let conn_filter = Filter {
                filter_data: super::FilterData::ConntrackState(conn_state),
                inverted: false,
            };
            let conn_filter_inv = Filter {
                filter_data: super::FilterData::ConntrackState(conn_state),
                inverted: true,
            };

            for inner_conn_state in all_conn_states {
                if conn_state == inner_conn_state {
                    assert!(conn_filter.is_matching(
                        inner_conn_state,
                        &ip,
                        Some(&pk),
                        Direction::Inbound
                    ));
                    assert!(!conn_filter_inv.is_matching(
                        inner_conn_state,
                        &ip,
                        Some(&pk),
                        Direction::Inbound
                    ));
                } else {
                    assert!(!conn_filter.is_matching(
                        inner_conn_state,
                        &ip,
                        Some(&pk),
                        Direction::Inbound
                    ));
                    assert!(conn_filter_inv.is_matching(
                        inner_conn_state,
                        &ip,
                        Some(&pk),
                        Direction::Inbound
                    ));
                }
            }
        }
    }

    #[test]
    fn test_next_level_proto_filter() {
        let protocols = [
            NextLevelProtocol::Icmp,
            NextLevelProtocol::Icmpv6,
            NextLevelProtocol::Tcp,
            NextLevelProtocol::Udp,
        ];

        let src = Ipv4Addr::new(127, 0, 0, 1);
        let src_port = 1111;
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let dst_port = 8888;
        let udp_packet = make_udp(src, src_port, dst, dst_port);
        let tcp_packet = make_tcp(src, src_port, dst, dst_port, TcpFlags::SYN);
        let icmp_packet = make_icmp4(src, dst, IcmpTypes::EchoReply);
        let proto_packet_pairs_ipv4 = [
            (
                NextLevelProtocol::Icmp,
                Ipv4Packet::new(&icmp_packet).expect("Should be a valid Ipv4 packet"),
            ),
            (
                NextLevelProtocol::Tcp,
                Ipv4Packet::new(&tcp_packet).expect("Should be a valid Ipv4 packet"),
            ),
            (
                NextLevelProtocol::Udp,
                Ipv4Packet::new(&udp_packet).expect("Should be a valid Ipv4 packet"),
            ),
        ];

        for proto in protocols.iter() {
            let proto_filter = Filter {
                inverted: false,
                filter_data: FilterData::NextLevelProtocol(*proto),
            };
            let proto_filter_inv = Filter {
                inverted: true,
                filter_data: FilterData::NextLevelProtocol(*proto),
            };

            for (packet_proto, packet) in proto_packet_pairs_ipv4.iter() {
                if proto == packet_proto {
                    assert!(proto_filter.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                    assert!(!proto_filter_inv.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                } else {
                    assert!(!proto_filter.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                    assert!(proto_filter_inv.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                }
            }
        }

        let src_v6 = Ipv6Addr::new(0xfc, 0x0a, 0, 0, 0, 0, 0, 1);
        let dst_v6 = Ipv6Addr::new(0xfc, 0x0a, 0, 0, 0, 0, 0, 2);
        let icmp6_packet = make_icmp6(src_v6, dst_v6, Icmpv6Types::EchoReply);
        let proto_packet_pairs_ipv6 = [(
            NextLevelProtocol::Icmpv6,
            Ipv6Packet::new(&icmp6_packet).expect("Should be a valid Ipv6 packet"),
        )];

        for proto in protocols.iter() {
            let proto_filter = Filter {
                inverted: false,
                filter_data: FilterData::NextLevelProtocol(*proto),
            };
            let proto_filter_inv = Filter {
                inverted: true,
                filter_data: FilterData::NextLevelProtocol(*proto),
            };

            for (packet_proto, packet) in proto_packet_pairs_ipv6.iter() {
                if proto == packet_proto {
                    assert!(proto_filter.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                    assert!(!proto_filter_inv.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                } else {
                    assert!(!proto_filter.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                    assert!(proto_filter_inv.is_matching(
                        ConnectionState::New,
                        packet,
                        None,
                        Direction::Inbound
                    ));
                }
            }
        }
    }

    #[test]
    fn test_tcp_flags_filter() {
        let tcp_flags = [
            TcpFlags::CWR,
            TcpFlags::ECE,
            TcpFlags::URG,
            TcpFlags::ACK,
            TcpFlags::PSH,
            TcpFlags::RST,
            TcpFlags::SYN,
            TcpFlags::FIN,
        ];

        let src = Ipv4Addr::new(127, 0, 0, 1);
        let src_port = 1111;
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let dst_port = 8888;

        for tcp_flag_filter_set in 0..0xFFu8 {
            for tcp_flag_pkt_set in 0..0xFFu8 {
                let should_match = tcp_flags
                    .iter()
                    .any(|flag| flag & tcp_flag_filter_set != 0 && flag & tcp_flag_pkt_set != 0);

                let pkt = make_tcp(src, src_port, dst, dst_port, tcp_flag_pkt_set);
                let ip_pkt = Ipv4Packet::new(&pkt).expect("Should be a valid Ipv4 packet");

                let filter = Filter {
                    filter_data: FilterData::TcpFlags(tcp_flag_filter_set),
                    inverted: false,
                };
                let matching_result =
                    filter.is_matching(ConnectionState::New, &ip_pkt, None, Direction::Inbound);
                if should_match {
                    assert!(matching_result);
                } else {
                    assert!(!matching_result);
                }
            }
        }
    }

    #[test]
    fn test_icmp_type_filter() {
        let icmp_types_pairs = [
            (OurIcmpType::EchoReply, IcmpTypes::EchoReply),
            (
                OurIcmpType::DestinationUnreachable,
                IcmpTypes::DestinationUnreachable,
            ),
            (OurIcmpType::RedirectMessage, IcmpTypes::RedirectMessage),
            (OurIcmpType::EchoRequest, IcmpTypes::EchoRequest),
            (
                OurIcmpType::RouterAdvertisement,
                IcmpTypes::RouterAdvertisement,
            ),
            (
                OurIcmpType::RouterSolicitation,
                IcmpTypes::RouterSolicitation,
            ),
            (OurIcmpType::TimeExceeded, IcmpTypes::TimeExceeded),
            (OurIcmpType::ParameterProblem, IcmpTypes::ParameterProblem),
            (OurIcmpType::Timestamp, IcmpTypes::Timestamp),
            (OurIcmpType::TimestampReply, IcmpTypes::TimestampReply),
        ];

        let src = Ipv4Addr::new(127, 0, 0, 1);
        let dst = Ipv4Addr::new(8, 8, 8, 8);

        for (libfw_icmp_type, exp_icmp_type) in icmp_types_pairs.iter() {
            for (_, pkt_icmp_type) in icmp_types_pairs.iter() {
                let pkt = make_icmp4(src, dst, *pkt_icmp_type);
                let ip_pkt = Ipv4Packet::new(&pkt).expect("Should be a valid Ipv4 packet");

                let filter = Filter {
                    filter_data: FilterData::IcmpType(*libfw_icmp_type),
                    inverted: false,
                };

                let matching_result =
                    filter.is_matching(ConnectionState::New, &ip_pkt, None, Direction::Inbound);

                if exp_icmp_type == pkt_icmp_type {
                    assert!(matching_result);
                } else {
                    assert!(!matching_result);
                }
            }
        }
    }

    #[test]
    fn test_ffi_conversion() {
        let test_chain = Chain {
            rules: vec![
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
                            filter_data: FilterData::SrcNetwork(NetworkFilter {
                                network: ipnet::IpNet::V4(
                                    Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap(),
                                ),
                                ports: (1000, 1200),
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
                            filter_data: FilterData::IcmpType(OurIcmpType::EchoReply),
                            inverted: true,
                        },
                    ],
                    action: LibfwVerdict::LibfwVerdictDrop,
                },
                Rule {
                    filters: vec![
                        Filter {
                            filter_data: FilterData::AssociatedData(Some([1; 32].to_smallvec())),
                            inverted: true,
                        },
                        Filter {
                            filter_data: FilterData::TcpFlags(TcpFlags::ACK | TcpFlags::SYN),
                            inverted: false,
                        },
                    ],
                    action: LibfwVerdict::LibfwVerdictReject,
                },
            ],
        };

        let filters1 = vec![
            LibfwFilter {
                inverted: false,
                filter_type: LIBFW_FILTER_ASSOCIATED_DATA,
                filter: LibfwFilterData {
                    associated_data_filter: ManuallyDrop::new(LibfwAssociatedData {
                        associated_data: null_mut(),
                        associated_data_len: 0,
                    }),
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
                    associated_data_filter: ManuallyDrop::new(LibfwAssociatedData {
                        associated_data_len: assoc_data.len(),
                        associated_data: assoc_data.as_ptr(),
                    }),
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

        // Compare converted LibfwChain to original Chain
        let test_ffi_chain_conv: Chain = (&test_ffi_chain)
            .try_into()
            .expect("Unexpected conversion error");

        assert_eq!(test_ffi_chain_conv, test_chain);
    }

    #[test]
    fn test_malformed_union_conversions() {
        let malformed_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_DIRECTION,
            filter: LibfwFilterData { tcp_flags: 7 },
        };

        let converted_filter = TryInto::<Filter>::try_into(&malformed_ffi_filter);
        assert_eq!(converted_filter, Err(Error::InvalidChain));

        let correct_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_DIRECTION,
            // This is given in a weird way, but a correct value for LibfwDirection
            filter: LibfwFilterData { tcp_flags: 1 },
        };
        let expected_fitler = Filter {
            inverted: false,
            filter_data: FilterData::Direction(Direction::Inbound),
        };

        let converted_filter = TryInto::<Filter>::try_into(&correct_ffi_filter);
        assert_eq!(converted_filter, Ok(expected_fitler));

        let malformed_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_CONNTRACK_STATE,
            filter: LibfwFilterData { tcp_flags: 121 },
        };

        let converted_filter = TryInto::<Filter>::try_into(&malformed_ffi_filter);
        assert_eq!(converted_filter, Err(Error::InvalidChain));

        let correct_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_CONNTRACK_STATE,
            // This is given in a weird way, but a correct value for LibfwConntrackState
            filter: LibfwFilterData { tcp_flags: 2 },
        };
        let expected_fitler = Filter {
            inverted: false,
            filter_data: FilterData::ConntrackState(ConnectionState::Invalid),
        };

        let converted_filter = TryInto::<Filter>::try_into(&correct_ffi_filter);
        assert_eq!(converted_filter, Ok(expected_fitler));

        let malformed_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_NEXT_LVL_PROTO,
            filter: LibfwFilterData { tcp_flags: 4 },
        };

        let converted_filter = TryInto::<Filter>::try_into(&malformed_ffi_filter);
        assert_eq!(converted_filter, Err(Error::InvalidChain));

        let correct_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_NEXT_LVL_PROTO,
            // This is given in a weird way, but a correct value for LibfwFilterNextLvlProto
            filter: LibfwFilterData { tcp_flags: 3 },
        };
        let expected_fitler = Filter {
            inverted: false,
            filter_data: FilterData::NextLevelProtocol(NextLevelProtocol::Icmpv6),
        };

        let converted_filter = TryInto::<Filter>::try_into(&correct_ffi_filter);
        assert_eq!(converted_filter, Ok(expected_fitler));

        let malformed_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_ICMP_TYPE,
            filter: LibfwFilterData { tcp_flags: 70 },
        };

        let converted_filter = TryInto::<Filter>::try_into(&malformed_ffi_filter);
        assert_eq!(converted_filter, Err(Error::InvalidChain));

        let correct_ffi_filter = LibfwFilter {
            inverted: false,
            filter_type: LIBFW_FILTER_ICMP_TYPE,
            // This is given in a weird way, but a correct value for ICMP request
            filter: LibfwFilterData { tcp_flags: 8 },
        };
        let expected_fitler = Filter {
            inverted: false,
            filter_data: FilterData::IcmpType(OurIcmpType::EchoRequest),
        };

        let converted_filter = TryInto::<Filter>::try_into(&correct_ffi_filter);
        assert_eq!(converted_filter, Ok(expected_fitler));
    }
}
