//! Firewall chain implementation

use std::{net::IpAddr, ops::RangeInclusive};

use ipnet::IpNet;
use pnet_packet::{
    ip::IpNextHeaderProtocols::{self, Icmp, Icmpv6, Tcp, Udp},
    tcp::{TcpFlags, TcpPacket},
    udp::UdpPacket,
};

use crate::{
    conntrack::{AssociatedData, Conntracker, LibfwConnectionState, LibfwDirection, LibfwVerdict},
    firewall::IpPacket,
};

#[derive(Clone, Debug)]
pub struct NetworkFilterData {
    pub network: IpNet,
    pub ports: RangeInclusive<u16>,
}

enum NetworkFilterType {
    Src,
    Dst,
}

#[derive(Copy, Clone, Debug)]
pub enum LibfwNextLevelProtocol {
    Udp,
    Tcp,
    TcpFinishedAllowed,
    Icmp,
    Icmp6,
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
}

impl FilterData {
    fn is_matching<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        packet_assoc_data: &[u8],
        packet_direction: LibfwDirection,
    ) -> bool {
        match self {
            FilterData::AssociatedData(assoc_data) => &**assoc_data == packet_assoc_data,
            FilterData::ConntrackState(conn_state) => conntracker
                .get_connection_state(packet, packet_assoc_data, packet_direction)
                .map(|cs| cs == *conn_state)
                .unwrap_or_default(),
            FilterData::SrcNetwork(network_filter) => {
                network_filter.is_matching(packet, NetworkFilterType::Src)
            }
            FilterData::DstNetwork(network_filter) => {
                network_filter.is_matching(packet, NetworkFilterType::Dst)
            }
            FilterData::Direction(direction) => direction == &packet_direction,
            FilterData::NextLevelProtocol(next_level_protocol) => {
                let proto = packet.get_next_level_protocol();
                match next_level_protocol {
                    LibfwNextLevelProtocol::Udp => proto == Udp,
                    LibfwNextLevelProtocol::Tcp => proto == Tcp,
                    LibfwNextLevelProtocol::Icmp => proto == Icmp,
                    LibfwNextLevelProtocol::Icmp6 => proto == Icmpv6,
                    LibfwNextLevelProtocol::TcpFinishedAllowed if proto == Tcp => {
                        TcpPacket::new(packet.payload())
                            .map(|pkt| {
                                pkt.get_flags() & (TcpFlags::ACK | TcpFlags::FIN | TcpFlags::RST)
                                    != 0
                            })
                            .unwrap_or_default()
                    }
                    LibfwNextLevelProtocol::TcpFinishedAllowed => false,
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Filter {
    pub filter_data: FilterData,
    pub inverted: bool,
}

impl Filter {
    fn is_matching<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        assoc_data: &[u8],
        direction: LibfwDirection,
    ) -> bool {
        self.filter_data
            .is_matching(conntracker, packet, assoc_data, direction)
            != self.inverted
    }
}

#[derive(Debug)]
pub struct Rule {
    pub filters: Vec<Filter>,
    pub action: LibfwVerdict,
}

impl Rule {
    fn is_matching<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        assoc_data: &[u8],
        direction: LibfwDirection,
    ) -> bool {
        self.filters
            .iter()
            .all(|filter| filter.is_matching(conntracker, packet, assoc_data, direction))
    }
}

pub(crate) struct Chain {
    pub rules: Vec<Rule>,
}

impl Chain {
    pub(crate) fn process_packet<'a>(
        &self,
        conntracker: &Conntracker,
        packet: &impl IpPacket<'a>,
        assoc_data: &[u8],
        direction: LibfwDirection,
    ) -> LibfwVerdict {
        self.rules
            .iter()
            .find(|rule| rule.is_matching(conntracker, packet, assoc_data, direction))
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
        let ctk = Conntracker::new(10, 1000);

        // Test UDP with proper source
        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(!dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));

        // Test UDP with proper destination
        let pkt = make_udp("100.0.0.2:5678", "168.72.0.12:1234");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(!src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));

        // Test UDP with proper source port
        let pkt = make_udp("168.72.0.12:1234", "168.72.0.12:10000");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(!dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));

        // Test UDP with proper dst port
        let pkt = make_udp("168.72.0.12:10000", "168.72.0.12:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));
        assert!(!src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!src_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
        assert!(dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(dst_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionOutbound));
    }

    #[test]
    fn assoc_data_filter() {
        let pk = make_random_peer();
        let another_pk = make_random_peer();
        let ctk = Conntracker::new(10, 1000);

        let data_filter = Filter {
            filter_data: super::FilterData::AssociatedData(pk.clone().to_smallvec()),
            inverted: false,
        };
        let data_filter_inv = Filter {
            filter_data: super::FilterData::AssociatedData(pk.clone().to_smallvec()),
            inverted: true,
        };

        let pkt = make_udp("168.72.0.12:1234", "100.0.0.2:5678");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));

        assert!(data_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!data_filter.is_matching(
            &ctk,
            &ip,
            &another_pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!data_filter_inv.is_matching(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(data_filter_inv.is_matching(
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

        assert!(direction_filter.is_matching(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(!direction_filter.is_matching(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionOutbound
        ));
        assert!(!direction_filter_inv.is_matching(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
        assert!(direction_filter_inv.is_matching(
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

        let conn_filter = Filter {
            filter_data: super::FilterData::ConntrackState(
                LibfwConnectionState::LibfwConnectionStateLocallyInitiated,
            ),
            inverted: false,
        };
        let conn_filter_inv = Filter {
            filter_data: super::FilterData::ConntrackState(
                LibfwConnectionState::LibfwConnectionStateLocallyInitiated,
            ),
            inverted: true,
        };

        let pkt_out = make_udp("168.72.0.12:1234", "168.72.0.11:5678");
        let ip_out = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt_out));

        let pkt = make_udp("168.72.0.11:5678", "168.72.0.12:1234");
        let ip = unwrap_option_or_return!(Ipv4Packet::try_from(&pkt));

        assert!(!conn_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(conn_filter_inv.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));

        ctk.handle_outbound_udp(&ip_out, &pk);

        assert!(conn_filter.is_matching(&ctk, &ip, &pk, LibfwDirection::LibfwDirectionInbound));
        assert!(!conn_filter_inv.is_matching(
            &ctk,
            &ip,
            &pk,
            LibfwDirection::LibfwDirectionInbound
        ));
    }
}
