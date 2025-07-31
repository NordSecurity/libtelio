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

#[derive(Clone, Debug)]
pub(crate) struct NetworkFilterData {
    pub(crate) network: IpNet,
    pub(crate) ports: RangeInclusive<u16>,
}

enum NetworkFilterType {
    Src,
    Dst,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub(crate) enum LibfwNextLevelProtocol {
    Udp,
    Tcp,
    Icmp,
    Icmp6,
}

///
/// Packet verdict
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
        if let Some(p) = <$kind>::new($packet.payload()) {
            if let NetworkFilterType::Src = $filter_type {
                Some(p.get_source())
            } else {
                Some(p.get_destination())
            }
        } else {
            None
        }
    };
}

impl NetworkFilterData {
    fn is_matching<'a>(&self, packet: &impl IpPacket<'a>, filter_type: NetworkFilterType) -> bool {
        let packet_addr: crate::firewall::IpAddr = if let NetworkFilterType::Src = filter_type {
            packet.get_source().into()
        } else {
            packet.get_destination().into()
        };

        let std_ip_addr: IpAddr = packet_addr.into();

        if !self.network.contains(&std_ip_addr) {
            return false;
        }

        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => get_inner_packet_port!(UdpPacket, packet, filter_type)
                .map(|port| self.ports.contains(&port))
                .unwrap_or_default(),
            IpNextHeaderProtocols::Tcp => get_inner_packet_port!(TcpPacket, packet, filter_type)
                .map(|port| self.ports.contains(&port))
                .unwrap_or_default(),
            _ => true,
        }
    }
}

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

#[derive(Clone, Debug)]
pub(crate) struct Filter {
    pub(crate) filter_data: FilterData,
    pub(crate) inverted: bool,
}

impl Filter {
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

#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) filters: Vec<Filter>,
    pub(crate) action: LibfwVerdict,
}

impl Rule {
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

pub(crate) struct Chain {
    pub(crate) rules: Vec<Rule>,
}

impl Chain {
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
            .unwrap_or_else(|| LibfwVerdict::LibfwVerdictDrop)
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

        // Test UDP with proper source
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

        // Test UDP with proper destination
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

        // Test UDP with proper source port
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

        // Test UDP with proper dst port
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
