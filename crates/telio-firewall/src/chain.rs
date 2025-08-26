//! Firewall chain implementation

use std::{net::IpAddr, ops::RangeInclusive};

use ipnet::IpNet;
use pnet_packet::{
    ip::IpNextHeaderProtocols::{self, Icmp, Icmpv6, Tcp, Udp},
    tcp::TcpPacket,
    udp::UdpPacket,
};

use crate::{
    conntrack::{AssociatedData, LibfwConnectionState, LibfwDirection},
    firewall::IpPacket,
};

///
/// Necessary data for network filter:
///  * network - range of matching IP addresses
///  * ports - range of matching ports (usually it is either a single port or full range)
///
#[derive(Clone, Debug)]
pub(crate) struct NetworkFilterData {
    pub(crate) network: IpNet,
    pub(crate) ports: RangeInclusive<u16>,
}

///
/// Determines whether network filter data should be checked for source or destination packet data
///
enum NetworkFilterType {
    Src,
    Dst,
}

///
/// Next level protocol (L4)
///
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwNextLevelProtocol {
    Udp,
    Tcp,
    Icmp,
    Icmp6,
}

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
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LibfwVerdict {
    LibfwVerdictAccept,
    LibfwVerdictDrop,
    LibfwVerdictReject,
}

macro_rules! get_inner_packet_port {
    ($kind: ty, $packet: expr, $filter_type: expr) => {
        <$kind>::new($packet.payload()).map(|p| match $filter_type {
            NetworkFilterType::Src => p.get_source(),
            NetworkFilterType::Dst => p.get_destination(),
        })
    };
}

impl NetworkFilterData {
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
            IpNextHeaderProtocols::Udp => get_inner_packet_port!(UdpPacket, packet, filter_type)
                .map(|port| self.ports.contains(&port))
                .unwrap_or(false),
            IpNextHeaderProtocols::Tcp => get_inner_packet_port!(TcpPacket, packet, filter_type)
                .map(|port| self.ports.contains(&port))
                .unwrap_or(false),
            _ => true,
        }
    }
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
///
#[derive(Clone, Debug)]
pub(crate) enum FilterData {
    AssociatedData(AssociatedData),
    ConntrackState(LibfwConnectionState),
    #[allow(dead_code)]
    SrcNetwork(NetworkFilterData),
    DstNetwork(NetworkFilterData),
    Direction(LibfwDirection),
    NextLevelProtocol(LibfwNextLevelProtocol),
    TcpFlags(u8),
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
        packet_conn_state: LibfwConnectionState,
        packet: &impl IpPacket<'a>,
        packet_assoc_data: Option<&[u8]>,
        packet_direction: LibfwDirection,
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
                    LibfwNextLevelProtocol::Udp => proto == Udp,
                    LibfwNextLevelProtocol::Tcp => proto == Tcp,
                    LibfwNextLevelProtocol::Icmp => proto == Icmp,
                    LibfwNextLevelProtocol::Icmp6 => proto == Icmpv6,
                }
            }
            FilterData::TcpFlags(flags) if packet.get_next_level_protocol() == Tcp => {
                TcpPacket::new(packet.payload())
                    .map(|pkt| pkt.get_flags() & flags != 0)
                    .unwrap_or(false)
            }
            FilterData::TcpFlags(_) => false,
        }
    }
}

///
/// Firewall filter type - in practice it is FilterData extended with
/// possibility of inverting fiters with `inverted` flag.
///
#[derive(Clone, Debug)]
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
        conn_state: LibfwConnectionState,
        packet: &impl IpPacket<'a>,
        assoc_data: Option<&[u8]>,
        direction: LibfwDirection,
    ) -> bool {
        self.filter_data
            .is_matching(conn_state, packet, assoc_data, direction)
            != self.inverted
    }
}

///
/// A definition of firewall rule it consists of filters which determine whether rule applies to packet
/// being processed and action, which determines what to do with the rule.
///
#[derive(Debug)]
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
        conn_state: LibfwConnectionState,
        packet: &impl IpPacket<'a>,
        assoc_data: Option<&[u8]>,
        direction: LibfwDirection,
    ) -> bool {
        self.filters
            .iter()
            .all(|filter| filter.is_matching(conn_state, packet, assoc_data, direction))
    }
}

///
/// Rust representation of the firewall chain.
/// Decides packets destiny with `process_packet` method.
///
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
        conn_state: LibfwConnectionState,
        packet: &impl IpPacket<'a>,
        assoc_data: Option<&[u8]>,
        direction: LibfwDirection,
    ) -> LibfwVerdict {
        self.rules
            .iter()
            .find(|rule| rule.is_matching(conn_state, packet, assoc_data, direction))
            .map(|rule| rule.action)
            .unwrap_or(LibfwVerdict::LibfwVerdictDrop)
    }
}

#[cfg(any(test, feature = "test_utils"))]
#[allow(missing_docs, unused)]
pub mod tests {
    use std::{
        convert::TryInto,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    };

    use enum_map::EnumMap;
    use ipnet::Ipv4Net;
    use pnet_packet::{
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        tcp::MutableTcpPacket,
        udp::MutableUdpPacket,
        MutablePacket,
    };
    use smallvec::ToSmallVec;
    use telio_crypto::SecretKey;
    use telio_model::PublicKey;

    use crate::{
        chain::{Filter, NetworkFilterData},
        conntrack::{unwrap_option_or_return, Conntrack, LibfwConnectionState, LibfwDirection},
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
        ip.set_flags(2); // Don't fragment flag
        ip.set_ttl(64);
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
    fn test_network_filter() {
        let net_filter = NetworkFilterData {
            network: ipnet::IpNet::V4(Ipv4Net::new(Ipv4Addr::new(168, 72, 0, 0), 16).unwrap()),
            ports: 1000..=9000,
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
        let ctk = Conntrack::new(10, 1000);

        // Test UDP with matching source
        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));
        assert!(!dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));

        // Test UDP with matching destination
        let pkt = make_udp("100.0.0.2:5678", "168.72.0.12:1234");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(!src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));
        assert!(dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));

        // Test UDP with matching source port
        let pkt = make_udp("168.72.0.12:1234", "168.72.0.12:10000");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));
        assert!(!dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));

        // Test UDP with matching dst port
        let pkt = make_udp("168.72.0.12:10000", "168.72.0.12:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(!src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!src_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));
        assert!(dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(dst_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));
    }

    #[test]
    fn test_assoc_data_filter() {
        let pk = make_random_peer();
        let another_pk = make_random_peer();
        let ctk = Conntrack::new(10, 1000);

        let data_filter = Filter {
            filter_data: super::FilterData::AssociatedData(Some(pk.clone().to_smallvec())),
            inverted: false,
        };
        let data_filter_inv = Filter {
            filter_data: super::FilterData::AssociatedData(Some(pk.clone().to_smallvec())),
            inverted: true,
        };

        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));

        assert!(data_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!data_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&another_pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!data_filter_inv.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(data_filter_inv.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&another_pk),
            LibfwDirection::LibfwDirectionInbound
        ));
    }

    #[test]
    fn test_direction_filter() {
        let pk = make_random_peer();
        let ctk = Conntrack::new(10, 1000);

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

        assert!(direction_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!direction_filter.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));
        assert!(!direction_filter_inv.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(direction_filter_inv.is_matching(
            LibfwConnectionState::LibfwConnectionStateNew,
            &ip,
            Some(&pk),
            LibfwDirection::LibfwDirectionOutbound
        ));
    }

    #[test]
    fn test_conntrack_filter() {
        let pk = make_random_peer();
        let ctk = Conntrack::new(10, 1000);
        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));

        let all_conn_states = [
            LibfwConnectionState::LibfwConnectionStateNew,
            LibfwConnectionState::LibfwConnectionStateEstablished,
            LibfwConnectionState::LibfwConnectionStateClosed,
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
                        LibfwDirection::LibfwDirectionInbound
                    ));
                    assert!(!conn_filter_inv.is_matching(
                        inner_conn_state,
                        &ip,
                        Some(&pk),
                        LibfwDirection::LibfwDirectionInbound
                    ));
                } else {
                    assert!(!conn_filter.is_matching(
                        inner_conn_state,
                        &ip,
                        Some(&pk),
                        LibfwDirection::LibfwDirectionInbound
                    ));
                    assert!(conn_filter_inv.is_matching(
                        inner_conn_state,
                        &ip,
                        Some(&pk),
                        LibfwDirection::LibfwDirectionInbound
                    ));
                }
            }
        }
    }
}
