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
use std::{
    convert::TryInto,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr as StdSocketAddr, SocketAddrV4, SocketAddrV6},
};
use telio_crypto::SecretKey;
use telio_firewall::firewall::{
    Firewall, FirewallDynamicState, Permissions, StatefulFirewall, FILE_SEND_PORT,
};
use telio_model::{
    features::{FeatureFirewall, FirewallBlacklistTuple, IpProtocol},
    PublicKey,
};

type MakeUdp = &'static dyn Fn(&str, &str) -> Vec<u8>;
type MakeTcp = &'static dyn Fn(&str, &str, u8) -> Vec<u8>;
type MakeIcmp = &'static dyn Fn(&str, &str, GenericIcmpType) -> Vec<u8>;
type MakeIcmpEcho = &'static dyn Fn(&str, &str, GenericIcmpType, u16) -> Vec<u8>;
type MakeIcmpError = &'static dyn Fn(&[u8]) -> Vec<u8>;

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

fn make_random_peer() -> PublicKey {
    SecretKey::gen().public()
}

fn make_peer() -> [u8; 32] {
    [1; 32]
}

pub fn make_udp_with_body(src: &str, dst: &str, body: &[u8]) -> Vec<u8> {
    let body_len = body.len();
    let ip_len = IPV4_HEADER_MIN + UDP_HEADER + body_len;
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

    let mut udp = MutableUdpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("UDP: Bad UDP buffer");
    udp.set_source(source.port());
    udp.set_destination(destination.port());
    udp.set_length((UDP_HEADER + body_len) as u16);
    udp.set_checksum(0);
    udp.payload_mut().copy_from_slice(body);
    let checksum =
        pnet_packet::udp::ipv4_checksum(&udp.to_immutable(), source.ip(), destination.ip());
    udp.set_checksum(checksum);

    raw
}

pub fn make_udp(src: &str, dst: &str) -> Vec<u8> {
    let msg: &str = "Some message";
    let msg = msg.as_bytes();
    make_udp_with_body(src, dst, msg)
}

pub fn make_udp6(src: &str, dst: &str) -> Vec<u8> {
    let msg: &str = "Some message";

    let msg_len = msg.as_bytes().len();
    let ip_len = IPV6_HEADER_MIN + UDP_HEADER + msg_len;
    let mut raw = vec![0u8; ip_len];

    let mut ip = MutableIpv6Packet::new(&mut raw).expect("UDP: Bad IP buffer");
    set_ipv6(&mut ip, IpNextHeaderProtocols::Udp, IPV6_HEADER_MIN, ip_len);
    let source: SocketAddrV6 = src
        .parse()
        .expect(&format!("UDPv6: Bad src address: {src}"));
    let destination: SocketAddrV6 = dst
        .parse()
        .expect(&format!("UDPv6: Bad dst address: {dst}"));
    ip.set_source(*source.ip());
    ip.set_destination(*destination.ip());

    let mut udp = MutableUdpPacket::new(&mut raw[IPV6_HEADER_MIN..]).expect("UDP: Bad UDP buffer");
    udp.set_source(source.port());
    udp.set_destination(destination.port());
    udp.set_length((UDP_HEADER + msg_len) as u16);
    udp.set_checksum(0);
    udp.payload_mut().copy_from_slice(msg.as_bytes());
    let checksum =
        pnet_packet::udp::ipv6_checksum(&udp.to_immutable(), source.ip(), destination.ip());
    udp.set_checksum(checksum);

    raw
}

pub fn make_tcp(src: &str, dst: &str, flags: u8) -> Vec<u8> {
    let msg: &str = "Some message";
    let msg_len = msg.as_bytes().len();
    let ip_len = IPV4_HEADER_MIN + TCP_HEADER_MIN + msg_len;
    let mut raw = vec![0u8; ip_len];

    let mut ip = MutableIpv4Packet::new(&mut raw).expect("TCP: Bad IP buffer");
    set_ipv4(&mut ip, IpNextHeaderProtocols::Tcp, IPV4_HEADER_MIN, ip_len);
    let source: SocketAddrV4 = src
        .parse()
        .expect(&format!("TCPv4: Bad src address: {src}"));
    let destination: SocketAddrV4 = dst
        .parse()
        .expect(&format!("TCPv4: Bad dst address: {dst}"));
    ip.set_source(*source.ip());
    ip.set_destination(*destination.ip());

    let mut tcp = MutableTcpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("TCP: Bad TCP buffer");
    tcp.set_source(source.port());
    tcp.set_destination(destination.port());
    tcp.set_checksum(0);
    tcp.payload_mut().copy_from_slice(msg.as_bytes());
    tcp.set_flags(flags);
    let checksum =
        pnet_packet::tcp::ipv4_checksum(&tcp.to_immutable(), source.ip(), destination.ip());
    tcp.set_checksum(checksum);

    raw
}

pub fn make_tcp6(src: &str, dst: &str, flags: u8) -> Vec<u8> {
    let msg: &str = "Some message";
    let msg_len = msg.as_bytes().len();
    let ip_len = IPV6_HEADER_MIN + TCP_HEADER_MIN + msg_len;
    let mut raw = vec![0u8; ip_len];

    let mut ip = MutableIpv6Packet::new(&mut raw).expect("TCP: Bad IP buffer");
    set_ipv6(&mut ip, IpNextHeaderProtocols::Tcp, IPV6_HEADER_MIN, ip_len);
    let source: SocketAddrV6 = src
        .parse()
        .expect(&format!("TCPv6: Bad src address: {src}"));
    let destination: SocketAddrV6 = dst
        .parse()
        .expect(&format!("TCPv6: Bad dst address: {dst}"));
    ip.set_source(*source.ip());
    ip.set_destination(*destination.ip());

    let mut tcp = MutableTcpPacket::new(&mut raw[IPV6_HEADER_MIN..]).expect("TCP: Bad TCP buffer");
    tcp.set_source(source.port());
    tcp.set_destination(destination.port());
    tcp.set_checksum(0);
    tcp.payload_mut().copy_from_slice(msg.as_bytes());
    tcp.set_flags(flags);
    let checksum =
        pnet_packet::tcp::ipv6_checksum(&tcp.to_immutable(), source.ip(), destination.ip());
    tcp.set_checksum(checksum);

    raw
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenericIcmpType {
    V4(IcmpType),
    V6(Icmpv6Type),
}

impl From<IcmpType> for GenericIcmpType {
    fn from(t: IcmpType) -> Self {
        GenericIcmpType::V4(t)
    }
}

impl From<Icmpv6Type> for GenericIcmpType {
    fn from(t: Icmpv6Type) -> Self {
        GenericIcmpType::V6(t)
    }
}

impl GenericIcmpType {
    fn v4(&self) -> IcmpType {
        match self {
            GenericIcmpType::V4(t) => *t,
            GenericIcmpType::V6(t) => panic!("{:?} is not v4", t),
        }
    }

    fn v6(&self) -> Icmpv6Type {
        match self {
            GenericIcmpType::V4(t) => {
                if *t == IcmpTypes::EchoReply {
                    return Icmpv6Types::EchoReply;
                }
                if *t == IcmpTypes::EchoRequest {
                    return Icmpv6Types::EchoRequest;
                }
                if *t == IcmpTypes::DestinationUnreachable {
                    return Icmpv6Types::DestinationUnreachable;
                }
                if *t == IcmpTypes::ParameterProblem {
                    return Icmpv6Types::ParameterProblem;
                }
                if *t == IcmpTypes::RouterSolicitation {
                    return Icmpv6Types::RouterSolicit;
                }
                if *t == IcmpTypes::TimeExceeded {
                    return Icmpv6Types::TimeExceeded;
                }
                if *t == IcmpTypes::RedirectMessage {
                    return Icmpv6Types::Redirect;
                }
                unimplemented!("{:?}", t)
            }
            GenericIcmpType::V6(t) => *t,
        }
    }
}

fn make_icmp4_with_body(src: &str, dst: &str, icmp_type: GenericIcmpType, body: &[u8]) -> Vec<u8> {
    let additional_body_len = body.len().saturating_sub(14);
    let ip_len = IPV4_HEADER_MIN + ICMP_HEADER + 10 + additional_body_len;
    let mut raw = vec![0u8; ip_len];

    let icmp_type: GenericIcmpType = (icmp_type).into();
    let mut packet =
        MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
    packet.set_icmp_type(icmp_type.v4());

    let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
    set_ipv4(
        &mut ip,
        IpNextHeaderProtocols::Icmp,
        IPV4_HEADER_MIN,
        ip_len,
    );
    ip.set_source(src.parse().expect("ICMP: Bad src IP"));
    ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));

    let body_start = 14.max(body.len());
    for (i, b) in body.iter().enumerate() {
        raw[ip_len - (body_start - i)] = *b;
    }

    raw
}

fn make_icmp4(src: &str, dst: &str, icmp_type: GenericIcmpType) -> Vec<u8> {
    make_icmp4_with_body(src, dst, icmp_type, &[])
}

fn make_icmp6_with_body(src: &str, dst: &str, icmp_type: GenericIcmpType, body: &[u8]) -> Vec<u8> {
    let additional_body_len = body.len().saturating_sub(14);
    let ip_len = IPV6_HEADER_MIN + ICMP_HEADER + 10 + additional_body_len;
    let mut raw = vec![0u8; ip_len];

    let icmp_type: GenericIcmpType = (icmp_type).into();
    let mut packet =
        MutableIcmpv6Packet::new(&mut raw[IPV6_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
    packet.set_icmpv6_type(icmp_type.v6());

    let mut ip = MutableIpv6Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
    set_ipv6(
        &mut ip,
        IpNextHeaderProtocols::Icmpv6,
        IPV6_HEADER_MIN,
        ip_len,
    );
    ip.set_source(src.parse().expect("ICMP: Bad src IP"));
    ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));

    let body_start = 14.max(body.len());
    for (i, b) in body.iter().enumerate() {
        raw[ip_len - (body_start - i)] = *b;
    }

    raw
}

fn make_icmp6(src: &str, dst: &str, icmp_type: GenericIcmpType) -> Vec<u8> {
    make_icmp6_with_body(src, dst, icmp_type, &[])
}

// Builds a well-formed ICMP echo (request/reply) packet: the echo identifier is
// written to the first two bytes of the ICMP body and a valid checksum is
// computed. Both are required for libfirewall conntrack to track the connection
// (it keys ICMP flows on the identifier and rejects packets with a bad checksum).
// Request and reply that share an identifier are matched into the same flow.
fn make_icmp4_echo(src: &str, dst: &str, icmp_type: GenericIcmpType, identifier: u16) -> Vec<u8> {
    let ip_len = IPV4_HEADER_MIN + ICMP_HEADER;
    let mut raw = vec![0u8; ip_len];
    {
        let mut packet =
            MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(icmp_type.v4());
        packet.payload_mut()[0..2].copy_from_slice(&identifier.to_ne_bytes());
        let checksum = pnet_packet::icmp::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);
    }
    let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
    set_ipv4(
        &mut ip,
        IpNextHeaderProtocols::Icmp,
        IPV4_HEADER_MIN,
        ip_len,
    );
    ip.set_source(src.parse().expect("ICMP: Bad src IP"));
    ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));
    raw
}

fn make_icmp6_echo(src: &str, dst: &str, icmp_type: GenericIcmpType, identifier: u16) -> Vec<u8> {
    let ip_len = IPV6_HEADER_MIN + ICMP_HEADER;
    let mut raw = vec![0u8; ip_len];
    let src_ip: Ipv6Addr = src.parse().expect("ICMP: Bad src IP");
    let dst_ip: Ipv6Addr = dst.parse().expect("ICMP: Bad dst IP");
    {
        let mut packet =
            MutableIcmpv6Packet::new(&mut raw[IPV6_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmpv6_type(icmp_type.v6());
        packet.payload_mut()[0..2].copy_from_slice(&identifier.to_ne_bytes());
        let checksum = pnet_packet::icmpv6::checksum(&packet.to_immutable(), &src_ip, &dst_ip);
        packet.set_checksum(checksum);
    }
    let mut ip = MutableIpv6Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
    set_ipv6(
        &mut ip,
        IpNextHeaderProtocols::Icmpv6,
        IPV6_HEADER_MIN,
        ip_len,
    );
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);
    raw
}

// Builds an ICMP Destination Unreachable error embedding the `original` datagram
// (IP header + first 8 bytes), the way real ICMP errors carry the offending packet.
// The error's addresses are the original's reversed (it comes back from the original
// destination to the original source). libfirewall matches it to the original flow.
fn make_icmp4_error(original: &[u8]) -> Vec<u8> {
    let orig = Ipv4Packet::new(original).expect("ICMP: bad original packet");
    let (err_src, err_dst) = (orig.get_destination(), orig.get_source());

    let take = (IPV4_HEADER_MIN + 8).min(original.len());
    let mut body = vec![0u8; 4]; // 4 unused header bytes
    body.extend_from_slice(&original[..take]);

    let ip_len = IPV4_HEADER_MIN + 4 + body.len();
    let mut raw = vec![0u8; ip_len];
    {
        let mut packet =
            MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.payload_mut().copy_from_slice(&body);
        let checksum = pnet_packet::icmp::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);
    }
    let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
    set_ipv4(
        &mut ip,
        IpNextHeaderProtocols::Icmp,
        IPV4_HEADER_MIN,
        ip_len,
    );
    ip.set_source(err_src);
    ip.set_destination(err_dst);
    raw
}

fn make_icmp6_error(original: &[u8]) -> Vec<u8> {
    let orig = Ipv6Packet::new(original).expect("ICMP: bad original packet");
    let (err_src, err_dst) = (orig.get_destination(), orig.get_source());

    let take = (IPV6_HEADER_MIN + 8).min(original.len());
    let mut body = vec![0u8; 4]; // 4 unused header bytes
    body.extend_from_slice(&original[..take]);

    let ip_len = IPV6_HEADER_MIN + 4 + body.len();
    let mut raw = vec![0u8; ip_len];
    {
        let mut packet =
            MutableIcmpv6Packet::new(&mut raw[IPV6_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        packet.payload_mut().copy_from_slice(&body);
        let checksum = pnet_packet::icmpv6::checksum(&packet.to_immutable(), &err_src, &err_dst);
        packet.set_checksum(checksum);
    }
    let mut ip = MutableIpv6Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
    set_ipv6(
        &mut ip,
        IpNextHeaderProtocols::Icmpv6,
        IPV6_HEADER_MIN,
        ip_len,
    );
    ip.set_source(err_src);
    ip.set_destination(err_dst);
    raw
}

trait FirewallExt {
    fn process_outbound_packet_sink(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool;
}

impl FirewallExt for StatefulFirewall {
    fn process_outbound_packet_sink(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool {
        Firewall::process_outbound_packet(self, public_key, buffer, &mut &io::sink())
    }
}

#[rustfmt::skip]
#[test]
fn ipv6_blocked() {
    struct TestInput {
        src1: &'static str,
        src2: &'static str,
        src3: &'static str,
        src4: &'static str,
        src5: &'static str,
        dst1: &'static str,
        dst2: &'static str,
        make_udp: MakeUdp,
        is_ipv4: bool
    }

    let test_inputs = vec![
        TestInput{
            src1: "127.0.0.1:1111", src2: "127.0.0.1:2222",
            src3: "127.0.0.1:3333", src4: "127.0.0.1:4444",
            src5: "127.0.0.1:5555",
            dst1: "8.8.8.8:8888", dst2: "8.8.8.8:7777",
            make_udp: &make_udp,
            is_ipv4: true
        },
        TestInput{
            src1: "[::1]:1111", src2: "[::1]:2222",
            src3: "[::1]:3333", src4: "[::1]:4444",
            src5: "[::1]:5555",
            dst1: "[2001:4860:4860::8888]:8888",
            dst2: "[2001:4860:4860::8888]:7777",
            make_udp: &make_udp6,
            is_ipv4: false
        },
    ];
    for TestInput { src1, src2, src3, src4, src5, dst1, dst2, make_udp , is_ipv4} in test_inputs {
        let fw = StatefulFirewall::new(false, FeatureFirewall::default(),).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });

        // Should FAIL (no matching outgoing connections yet)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src1)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src2)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src3)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src4)), false);

        // Should PASS (adds 1111..4444 and drops 2222)
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src2, dst1)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src3, dst1)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src4, dst1)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src1, dst2)), is_ipv4);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src4, dst2)), is_ipv4);

        // Should PASS - connection initiated by the host
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst2, src1)), is_ipv4);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst2, src4)), is_ipv4);

        // Dropped: peer-initiated flows (peer's packets seen first), not host-initiated
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src3)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src4)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src1)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src2)), false);

        // Should FAIL (has no matching outgoing connection)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(dst1, src5)), false);

        // Packet goes in the wrong direction, which results in kinda undefined behavior,
        // so disabling it - that shouldn't happen in the wild
        // assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, dst1)), false);
    }
}

#[rustfmt::skip]
#[test]
fn outgoing_blacklist() {
    struct TestInput {
        src: &'static str,
        dst: &'static str,
        make_udp: MakeUdp,
        make_tcp: MakeTcp,
    }

    let test_inputs = vec![
        TestInput{ src: "127.0.0.1:1111", dst: "8.8.8.8:8888",                make_udp: &make_udp,  make_tcp: &make_tcp },
        TestInput{ src: "[::1]:1111",     dst: "[2001:4860:4860::8888]:8888", make_udp: &make_udp6, make_tcp: &make_tcp6 },
    ];

    let blacklist = vec![
        FirewallBlacklistTuple {protocol: IpProtocol::UDP, ip: "8.8.8.8".parse().unwrap(), port: 8888},
        FirewallBlacklistTuple {protocol: IpProtocol::UDP, ip: "2001:4860:4860::8888".parse().unwrap(), port: 8888 },
        FirewallBlacklistTuple {protocol: IpProtocol::TCP, ip: "8.8.8.8".parse().unwrap(), port: 8888},
        FirewallBlacklistTuple {protocol: IpProtocol::TCP, ip: "2001:4860:4860::8888".parse().unwrap(), port: 8888 }
    ];

    for TestInput { src, dst, make_udp, make_tcp } in test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall {
            outgoing_blacklist: blacklist.clone(),
            ..Default::default()
        },).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ],
            ..Default::default()
        });

        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(src, dst)), false);
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &make_tcp(src, dst, TcpFlags::ACK)), false);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_whitelist() {
    struct TestInput {
        src1: &'static str,
        src2: &'static str,
        src3: &'static str,
        src4: &'static str,
        src5: &'static str,
        dst1: &'static str,
        dst2: &'static str,
        make_udp: MakeUdp,
        make_tcp: MakeTcp,
        make_icmp: MakeIcmp,
    }
    let test_inputs = vec![
        TestInput {
            src1: "100.100.100.100:1234",
            src2: "100.100.100.100:1000",

            src3: "100.100.100.101:1234",
            src4: "100.100.100.101:2222",
            src5: "100.100.100.101:1111",

            dst1: "127.0.0.1:1111",
            dst2: "127.0.0.1:1000",
            make_udp: &make_udp,
            make_tcp: &make_tcp,
            make_icmp: &make_icmp4,
        },
        TestInput {
            src1: "[2001:4860:4860::8888]:1234",
            src2: "[2001:4860:4860::8888]:1000",

            src3: "[2001:4860:4860::8844]:1234",
            src4: "[2001:4860:4860::8844]:2222",
            src5: "[2001:4860:4860::8844]:1111",

            dst1: "[::1]:1111",
            dst2: "[::1]:1000",
            make_udp: &make_udp6,
            make_tcp: &make_tcp6,
            make_icmp: &make_icmp6,
        }
    ];

    for TestInput { src1, src2, src3, src4, src5, dst1, dst2, make_udp, make_tcp, make_icmp } in &test_inputs {
        let mut feature = FeatureFirewall::default();
        feature.neptun_reset_conns = true;
        let fw = StatefulFirewall::new(true, feature).expect("Failed to load libfirewall");
        let mut state = fw.get_dynamic_state();
        state.ip_addresses = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))];
        fw.apply_dynamic_state(state.clone());
        let peer1 = make_random_peer();
        let peer2 = make_random_peer();

        assert!(state.whitelist.peer_whitelists[Permissions::IncomingConnections].is_empty());

        assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_udp(src1, dst1,)), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_udp(src2, dst1,)), false);

        state.whitelist.port_whitelist.insert(peer2, 1111);
        fw.apply_dynamic_state(state.clone());
        assert_eq!(fw.get_dynamic_state().whitelist.port_whitelist.len(), 1);

        assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_udp(src1, dst1,)), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_udp(src2, dst1,)), true);


        assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_tcp(src3, dst2, TcpFlags::SYN)), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_tcp(src4, dst1, TcpFlags::SYN | TcpFlags::ACK)), true);
        // only this one should be added to cache
        assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_tcp(src5, dst1, TcpFlags::SYN)), true);

        state.whitelist.peer_whitelists[Permissions::IncomingConnections].insert(peer2);
        fw.apply_dynamic_state(state.clone());
        let src = src1.parse::<StdSocketAddr>().unwrap().ip().to_string();
        let dst = dst1.parse::<StdSocketAddr>().unwrap().ip().to_string();
        assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_icmp(&src, &dst, IcmpTypes::EchoRequest.into())), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_icmp(&src, &dst, IcmpTypes::EchoRequest.into())), true);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_vpn_peer() {
    struct TestInput {
        src1: &'static str,
        src2: &'static str,
        dst1: &'static str,
        make_udp: MakeUdp,
        make_tcp: MakeTcp,
    }
    let test_inputs = vec![
        TestInput {
            src1: "100.100.100.100:1234",
            src2: "100.100.100.100:1000",
            dst1: "127.0.0.1:1111",
            make_udp: &make_udp,
            make_tcp: &make_tcp,
        },
        TestInput {
            src1: "[2001:4860:4860::8888]:1234",
            src2: "[2001:4860:4860::8888]:1000",
            dst1: "[::1]:1111",
            make_udp: &make_udp6,
            make_tcp: &make_tcp6,
        }
    ];
    let synack : u8 = TcpFlags::SYN | TcpFlags::ACK;
    let syn : u8 = TcpFlags::SYN;
        for TestInput { src1, src2, dst1, make_udp, make_tcp } in &test_inputs {
            let feature = FeatureFirewall::default();
            let fw = StatefulFirewall::new(true, feature).expect("Failed to load libfirewall");
            let mut state = fw.get_dynamic_state();
            state.ip_addresses = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))];
            fw.apply_dynamic_state(state.clone());

            let peer1 = make_random_peer();
            let peer2 = make_random_peer();

            assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_udp(src1, dst1,)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_udp(src2, dst1,)), false);
            assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_tcp(src1, dst1, synack)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_tcp(src2, dst1, synack)), false);

            state.whitelist.vpn_peer = Some(peer1);
            fw.apply_dynamic_state(state.clone());
            assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_udp(src1, dst1,)), true);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_udp(src2, dst1,)), false);

            assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_tcp(src1, dst1, syn)), true);
            assert_eq!(fw.process_outbound_packet_sink(&peer1.0, &make_tcp(dst1, src1, synack)), true);

            state.whitelist.vpn_peer = None;
            fw.apply_dynamic_state(state.clone());
            assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_udp(src1, dst1,)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_udp(src2, dst1,)), false);
            // Peer-initiated established TCP: no longer accepted once the vpn-peer rule is gone
            assert_eq!(fw.process_inbound_packet(&peer1.0, &mut make_tcp(src1, dst1, TcpFlags::ACK)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &mut make_tcp(src2, dst1, TcpFlags::ACK)), false);
        }
}

#[rustfmt::skip]
#[test]
fn firewall_whitelist_change_icmp() {
    struct TestInput {
        us: &'static str,
        them: &'static str,
        make_icmp: MakeIcmp,
        is_v4: bool,
    }

    let test_inputs = vec![
        TestInput{ us: "127.0.0.1", them: "8.8.8.8",              make_icmp: &make_icmp4, is_v4: true },
        TestInput{ us: "::1",       them: "2001:4860:4860::8888", make_icmp: &make_icmp6, is_v4: false },
    ];

    for TestInput { us, them, make_icmp, is_v4 } in &test_inputs {
        let feature = FeatureFirewall::default();
        // Set number of conntrack entries to 0 to test only the whitelist
        let fw = StatefulFirewall::new(true, feature).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });

        let mut state = fw.get_dynamic_state();
        let peer = make_random_peer();
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp(them, us, IcmpTypes::EchoReply.into())), false);

        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp(them, us, IcmpTypes::EchoRequest.into())), false);
        if *is_v4 {
            assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp4(them, us, IcmpTypes::Timestamp.into())), false);
            assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp4(them, us, IcmpTypes::InformationRequest.into())), false);
            assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp4(them, us, IcmpTypes::AddressMaskRequest.into())), false);
        }

        state.whitelist.peer_whitelists[Permissions::IncomingConnections].insert(peer);
        fw.apply_dynamic_state(state.clone());
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp(them, us, IcmpTypes::EchoRequest.into())), true);
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp(them, us, IcmpTypes::EchoReply.into())), true);
        if *is_v4 {
            assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp4(them, us, IcmpTypes::Timestamp.into())), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp4(them, us, IcmpTypes::InformationRequest.into())), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp4(them, us, IcmpTypes::AddressMaskRequest.into())), true);
        }
    }
}

#[rustfmt::skip]
#[test]
fn firewall_orig_src_ip_peer_initiated_blocked_after_removal() {
    // A peer that is whitelisted for incoming connections pings the host, and the
    // host answers with ICMP echo replies. While the peer is whitelisted, the
    // pings are accepted and a conntrack entry is opened whose *original*
    // direction source is the peer's IP (the peer initiated the connection).
    //
    // Once the peer is removed from the incoming whitelist, further pings must be
    // dropped: the incoming-peer rule is gone, and the OrigSrcIp rule only accepts
    // packets for connections initiated *from the host's own IP*. Here the
    // connection was initiated by the peer, so OrigSrcIp does not match and the
    // (still ESTABLISHED) conntrack state is not enough to let the pings through.
    struct TestInput {
        us: &'static str,
        them: &'static str,
        make_icmp_echo: MakeIcmpEcho,
    }

    // Echo identifier tying the request and its reply into the same conntrack flow.
    const ID: u16 = 0x4242;

    let test_inputs = vec![
        TestInput{ us: "127.0.0.1", them: "8.8.8.8",              make_icmp_echo: &make_icmp4_echo },
        TestInput{ us: "::1",       them: "2001:4860:4860::8888", make_icmp_echo: &make_icmp6_echo },
    ];

    for TestInput { us, them, make_icmp_echo } in &test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default()).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });

        let mut state = fw.get_dynamic_state();
        let peer = make_random_peer();

        // Not whitelisted yet: the peer's pings are dropped.
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp_echo(them, us, IcmpTypes::EchoRequest.into(), ID)), false);

        // Allow the peer to open incoming connections.
        state.whitelist.peer_whitelists[Permissions::IncomingConnections].insert(peer);
        fw.apply_dynamic_state(state.clone());

        // The peer pings the host -> accepted by the incoming-peer rule. This opens
        // a conntrack entry whose original direction source is the peer's IP.
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp_echo(them, us, IcmpTypes::EchoRequest.into(), ID)), true);
        // The host answers with an echo reply -> accepted outbound; the flow is now ESTABLISHED.
        assert_eq!(fw.process_outbound_packet_sink(&peer.0, &mut make_icmp_echo(us, them, IcmpTypes::EchoReply.into(), ID)), true);
        // The connection is established, so subsequent pings keep flowing.
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp_echo(them, us, IcmpTypes::EchoRequest.into(), ID)), true);

        // Remove the peer from the incoming whitelist.
        state.whitelist.peer_whitelists[Permissions::IncomingConnections].remove(&peer);
        fw.apply_dynamic_state(state.clone());

        // Pings must now fail: not from an allowed peer anymore, and the connection
        // was initiated by the peer (orig src != our IP) so OrigSrcIp doesn't help -
        // the ESTABLISHED state alone no longer accepts the traffic.
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp_echo(them, us, IcmpTypes::EchoRequest.into(), ID)), false);
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp_echo(them, us, IcmpTypes::EchoReply.into(), ID)), false);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_orig_src_ip_host_initiated_allowed_without_whitelist() {
    // Positive control for the OrigSrcIp rule: when the *host* initiates the
    // connection (host pings the peer), the peer's replies must be accepted even
    // though the peer is not on any whitelist, because the connection's original
    // direction source is one of the host's own IPs. This proves the failure in
    // `firewall_orig_src_ip_peer_initiated_blocked_after_removal` is specific to
    // peer-initiated connections rather than a blanket drop.
    struct TestInput {
        us: &'static str,
        them: &'static str,
        make_icmp_echo: MakeIcmpEcho,
    }

    // Echo identifier tying the request and its reply into the same conntrack flow.
    const ID: u16 = 0x1337;

    let test_inputs = vec![
        TestInput{ us: "127.0.0.1", them: "8.8.8.8",              make_icmp_echo: &make_icmp4_echo },
        TestInput{ us: "::1",       them: "2001:4860:4860::8888", make_icmp_echo: &make_icmp6_echo },
    ];

    for TestInput { us, them, make_icmp_echo } in &test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default()).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });

        let peer = make_random_peer();

        // The peer is not whitelisted, so unsolicited inbound pings are dropped.
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp_echo(them, us, IcmpTypes::EchoRequest.into(), ID)), false);

        // The host pings the peer -> accepted outbound, opening a conntrack entry
        // whose original direction source is the host's own IP.
        assert_eq!(fw.process_outbound_packet_sink(&peer.0, &mut make_icmp_echo(us, them, IcmpTypes::EchoRequest.into(), ID)), true);

        // The peer's echo reply is accepted via the OrigSrcIp rule (orig src == us)
        // even though the peer is on no whitelist.
        assert_eq!(fw.process_inbound_packet(&peer.0, &mut make_icmp_echo(them, us, IcmpTypes::EchoReply.into(), ID)), true);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_orig_src_ip_icmp_error_for_host_initiated_connection_allowed() {
    // An ICMP error referring to a connection the host initiated is accepted:
    // libfirewall resolves the embedded original datagram to its conntrack entry,
    // reports the original source (our IP) and marks it Related, so OrigSrcIp accepts.
    // An ICMP error for an unknown connection has no original source and is dropped.
    struct TestInput {
        us: &'static str,
        us_unsent: &'static str,
        them: &'static str,
        make_udp: MakeUdp,
        make_icmp_error: MakeIcmpError,
    }
    let test_inputs = vec![
        TestInput { us: "127.0.0.1:1111", us_unsent: "127.0.0.1:2222", them: "8.8.8.8:8888",               make_udp: &make_udp,  make_icmp_error: &make_icmp4_error },
        TestInput { us: "[::1]:1111",     us_unsent: "[::1]:2222",     them: "[2001:4860:4860::8888]:8888", make_udp: &make_udp6, make_icmp_error: &make_icmp6_error },
    ];

    for TestInput { us, us_unsent, them, make_udp, make_icmp_error } in &test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default()).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });

        // Host initiates an outbound UDP connection (conntrack original source = our IP).
        assert_eq!(fw.process_outbound_packet_sink(&make_peer(), &mut make_udp(us, them)), true);

        // ICMP error carrying that original datagram comes back -> accepted (Related, orig src == us).
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp_error(&make_udp(us, them))), true);

        // ICMP error for a connection we never opened -> no original source -> dropped.
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp_error(&make_udp(us_unsent, them))), false);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_whitelist_change_udp_allow() {
    struct TestInput { us: &'static str, them: &'static str, make_udp: MakeUdp, }
    let test_inputs = vec![
        TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                make_udp: &make_udp, },
        TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888", make_udp: &make_udp6, },
    ];

    for TestInput { us, them, make_udp } in test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default(),).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });
        let mut state = fw.get_dynamic_state();

        let them_peer = make_random_peer();

        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_udp(them, us)), false);
        state.whitelist.port_whitelist.insert(them_peer, 8888);
        fw.apply_dynamic_state(state.clone()); // NOTE: this doesn't change anything about this test
        assert_eq!(fw.process_outbound_packet_sink(&them_peer.0, &make_udp(us, them)), true);
        // Peer-initiated (the peer's packet above was seen first), so OrigSrcIp doesn't accept it
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_udp(them, us)), false);
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_udp(them, us)), false);
        state.whitelist.port_whitelist.remove(&them_peer);
        fw.apply_dynamic_state(state.clone()); // NOTE: also has no impact on this test
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_udp(them, us)), false);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_whitelist_change_udp_block() {
    struct TestInput { us: &'static str, them: &'static str, make_udp: MakeUdp, }
    let test_inputs = vec![
        TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                 make_udp: &make_udp, },
        TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888",  make_udp: &make_udp6, },
    ];

    for TestInput { us, them, make_udp } in test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default(),).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });
        let mut state = fw.get_dynamic_state();
        let them_peer = make_random_peer();

        state.whitelist.port_whitelist.insert(them_peer, 1111);
        fw.apply_dynamic_state(state.clone());
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_udp(them, us)), true);
        assert_eq!(fw.process_outbound_packet_sink(&them_peer.0, &make_udp(us, them)), true);

        // The already started connection should still work
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_udp(them, us)), true);
        state.whitelist.port_whitelist.remove(&them_peer);
        fw.apply_dynamic_state(state.clone());
        // Peer-initiated: dropped after the port whitelist is removed (OrigSrcIp doesn't match)
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_udp(them, us)), false);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_whitelist_change_tcp_allow() {
    struct TestInput { us: &'static str, them: &'static str, make_tcp: MakeTcp, }
    let test_inputs = vec![
        TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                 make_tcp: &make_tcp, },
        TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888",  make_tcp: &make_tcp6, },
    ];
    for TestInput { us, them, make_tcp } in test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default(),).expect("Failed to load libfirewall");
        let mut state = fw.get_dynamic_state();
        state.ip_addresses = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))];
        fw.apply_dynamic_state(state.clone());

        let them_peer = make_random_peer();

        state.whitelist.port_whitelist.insert(them_peer, 8888);
        fw.apply_dynamic_state(state.clone()); // NOTE: this doesn't change anything about the test
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), false);
        assert_eq!(fw.process_outbound_packet_sink(&them_peer.0, &make_tcp(us, them, TcpFlags::SYN)), true);
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);


        // Should PASS because we started the session
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::ACK)), true);
        state.whitelist.port_whitelist.remove(&them_peer);
        fw.apply_dynamic_state(state.clone());
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::ACK)), true);
    }

}

#[rustfmt::skip]
#[test]
fn firewall_whitelist_change_tcp_block() {
    struct TestInput { us: &'static str, them: &'static str, make_tcp: MakeTcp, }
    let test_inputs = vec![
        TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                 make_tcp: &make_tcp, },
        TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888",  make_tcp: &make_tcp6, },
    ];
    for TestInput { us, them, make_tcp } in test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default(),).expect("Failed to load libfirewall");
        let mut state = fw.get_dynamic_state();
        state.ip_addresses = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))];
        fw.apply_dynamic_state(state.clone());

        let them_peer = make_random_peer();

        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::SYN)), false);
        state.whitelist.port_whitelist.insert(them_peer, 1111);
        fw.apply_dynamic_state(state.clone());
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::SYN)), true);
        assert_eq!(fw.process_outbound_packet_sink(&them_peer.0, &make_tcp(us, them, TcpFlags::SYN | TcpFlags::ACK)), true);


        // Firewall allows already established connections while the peer is whitelisted
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::ACK)), true);
        state.whitelist.port_whitelist.remove(&them_peer);
        fw.apply_dynamic_state(state.clone());
        // Peer-initiated: dropped after the port whitelist is removed (OrigSrcIp doesn't match)
        assert_eq!(fw.process_inbound_packet(&them_peer.0, &mut make_tcp(them, us, TcpFlags::ACK)), false);
    }
}

#[rustfmt::skip]
#[test]
fn firewall_whitelist_peer() {
    struct TestInput {
        src1: &'static str,
        src2: &'static str,
        dst: &'static str,
        make_udp: MakeUdp,
        make_tcp: MakeTcp,
        make_icmp: MakeIcmp,
    }
    let test_inputs = vec![
        TestInput {
            src1: "100.100.100.100:1234",
            src2: "100.100.100.101:1234",
            dst: "127.0.0.1:1111",
            make_udp: &make_udp,
            make_tcp: &make_tcp,
            make_icmp: &make_icmp4,
        },
        TestInput {
            src1: "[2001:4860:4860::8888]:1234",
            src2: "[2001:4860:4860::8844]:1234",
            dst: "[::1]:1111",
            make_udp: &make_udp6,
            make_tcp: &make_tcp6,
            make_icmp: &make_icmp6,
        }
    ];
        for TestInput { src1, src2, dst, make_udp, make_tcp, make_icmp } in &test_inputs {
            let feature = FeatureFirewall::default();
            let fw = StatefulFirewall::new(true, feature).expect("Failed to load libfirewall");
            fw.apply_dynamic_state(FirewallDynamicState {
                ip_addresses: vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
                ..Default::default()
            });
            let mut state = fw.get_dynamic_state();
            assert!(state.whitelist.peer_whitelists[Permissions::IncomingConnections].is_empty());

            let src2_ip = src2.parse::<StdSocketAddr>().unwrap().ip().to_string();
            let dst_ip = dst.parse::<StdSocketAddr>().unwrap().ip().to_string();

            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, dst,)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_tcp(src2, dst, TcpFlags::PSH)), false);

            state.whitelist.peer_whitelists[Permissions::IncomingConnections].insert((&make_peer()).into());
            fw.apply_dynamic_state(state.clone());
            assert_eq!(fw.get_dynamic_state().whitelist.peer_whitelists[Permissions::IncomingConnections].len(), 1);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, dst,)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_tcp(src2, dst, TcpFlags::PSH)), true);

            state.whitelist.peer_whitelists[Permissions::IncomingConnections].remove(&(&make_peer()).into());
            fw.apply_dynamic_state(state.clone());
            assert_eq!(fw.get_dynamic_state().whitelist.peer_whitelists[Permissions::IncomingConnections].len(), 0);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, dst,)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_tcp(src2, dst, TcpFlags::PSH)), false);
        }
}

#[test]
fn firewall_test_permissions() {
    struct TestInput {
        src1: &'static str,
        local_dst: &'static str,
        area_dst: &'static str,
        external_dst: &'static str,
        make_udp: MakeUdp,
        make_tcp: MakeTcp,
    }
    let test_inputs = vec![
        TestInput {
            src1: "100.100.100.100:1234",
            local_dst: "127.0.0.1:1111",
            area_dst: "192.168.0.1:1111",
            external_dst: "13.32.4.21:1111",
            make_udp: &make_udp,
            make_tcp: &make_tcp,
        },
        TestInput {
            src1: "[2001:4860:4860::8888]:1234",
            local_dst: "[::1]:1111",
            area_dst: "[fe80:4860:4860::8844]:2222",
            external_dst: "[2001:4860:4860::8888]:8888",
            make_udp: &make_udp6,
            make_tcp: &make_tcp6,
        },
    ];

    for TestInput {
        src1,
        local_dst,
        area_dst,
        external_dst,
        make_udp,
        make_tcp,
    } in &test_inputs
    {
        let mut feature = FeatureFirewall::default();
        feature.neptun_reset_conns = true;
        let fw = StatefulFirewall::new(true, feature).expect("Failed to load libfirewall");
        let mut state = fw.get_dynamic_state();
        state.ip_addresses = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        fw.apply_dynamic_state(state.clone());
        assert!(state.whitelist.peer_whitelists[Permissions::IncomingConnections].is_empty());
        assert!(state.whitelist.peer_whitelists[Permissions::RoutingConnections].is_empty());
        assert!(state.whitelist.peer_whitelists[Permissions::LocalAreaConnections].is_empty());

        // No permissions. Incoming packet should FAIL
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, local_dst,)));
        assert!(
            !fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, local_dst, TcpFlags::PSH))
        );

        // Allow incoming connection
        state.whitelist.peer_whitelists[Permissions::IncomingConnections]
            .insert((&make_peer()).into());
        fw.apply_dynamic_state(state.clone());
        assert_eq!(
            state.whitelist.peer_whitelists[Permissions::IncomingConnections].len(),
            1
        );

        // Packet destined for local node
        assert!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, local_dst,)));
        assert!(
            fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, local_dst, TcpFlags::PSH))
        );
        // Packet destined for foreign node but within local area. Should FAIL
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, area_dst,)));
        assert!(
            !fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, area_dst, TcpFlags::PSH))
        );
        // Packet destined for totally external node. Should FAIL
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, external_dst,)));
        assert!(!fw.process_inbound_packet(
            &make_peer(),
            &mut make_tcp(src1, external_dst, TcpFlags::PSH)
        ));

        // Allow local area connections
        state.whitelist.peer_whitelists[Permissions::LocalAreaConnections]
            .insert((&make_peer()).into());
        fw.apply_dynamic_state(state.clone());
        assert_eq!(
            state.whitelist.peer_whitelists[Permissions::LocalAreaConnections].len(),
            1
        );
        // Packet destined for foreign node but within local area
        assert!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, area_dst,)));
        assert!(
            fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, area_dst, TcpFlags::PSH))
        );
        // Packet destined for totally external node. Should FAIL
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, external_dst,)));
        assert!(!fw.process_inbound_packet(
            &make_peer(),
            &mut make_tcp(src1, external_dst, TcpFlags::PSH)
        ));

        // Allow routing permissiongs but no local area connection
        state.whitelist.peer_whitelists[Permissions::LocalAreaConnections]
            .remove(&(&make_peer()).into());
        fw.apply_dynamic_state(state.clone());
        assert_eq!(
            state.whitelist.peer_whitelists[Permissions::LocalAreaConnections].len(),
            0
        );

        state.whitelist.peer_whitelists[Permissions::RoutingConnections]
            .insert((&make_peer()).into());
        fw.apply_dynamic_state(state.clone());
        assert_eq!(
            state.whitelist.peer_whitelists[Permissions::RoutingConnections].len(),
            1
        );
        // Packet destined for foreign node but within local area. Should FAIL
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, area_dst,)));
        assert!(
            !fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, area_dst, TcpFlags::PSH))
        );
        // Packet destined for totally external node
        assert!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, external_dst,)));
        assert!(fw.process_inbound_packet(
            &make_peer(),
            &mut make_tcp(src1, external_dst, TcpFlags::PSH)
        ));

        // Allow only routing
        state.whitelist.peer_whitelists[Permissions::IncomingConnections]
            .remove(&(&make_peer()).into());
        fw.apply_dynamic_state(state.clone());
        assert_eq!(
            state.whitelist.peer_whitelists[Permissions::IncomingConnections].len(),
            0
        );

        // Packet destined for local node. Should FAIL
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, local_dst,)));
        assert!(
            !fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, local_dst, TcpFlags::PSH))
        );
        // Packet destined for totally external node
        assert!(fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, external_dst,)));
        assert!(fw.process_inbound_packet(
            &make_peer(),
            &mut make_tcp(src1, external_dst, TcpFlags::PSH)
        ));

        state.whitelist.peer_whitelists[Permissions::RoutingConnections]
            .remove(&(&make_peer()).into());
        fw.apply_dynamic_state(state.clone());
        assert_eq!(
            state.whitelist.peer_whitelists[Permissions::RoutingConnections].len(),
            0
        );

        // All packets should FAIL
        // Packet destined for local node
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, local_dst,)));
        assert!(
            !fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, local_dst, TcpFlags::PSH))
        );
        // Packet destined for foreign node but within local area
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, area_dst,)));
        assert!(
            !fw.process_inbound_packet(&make_peer(), &mut make_tcp(src1, area_dst, TcpFlags::PSH))
        );
        // Packet destined for totally external node
        assert!(!fw.process_inbound_packet(&make_peer(), &mut make_udp(src1, external_dst,)));
        assert!(!fw.process_inbound_packet(
            &make_peer(),
            &mut make_tcp(src1, external_dst, TcpFlags::PSH)
        ));
    }
}

#[rustfmt::skip]
#[test]
fn firewall_whitelist_port() {
    struct TestInput {
        src: &'static str,
        dst: &'static str,
        make_udp: MakeUdp,
        make_tcp: MakeTcp,
        make_icmp: MakeIcmp,
    }
    impl TestInput {
        fn src_socket(&self, port: u16) -> String {
            StdSocketAddr::new(self.src.parse().unwrap(), port).to_string()
        }
        fn dst_socket(&self, port: u16) -> String {
            StdSocketAddr::new(self.dst.parse().unwrap(), port).to_string()
        }
    }
    let test_inputs = vec![
        TestInput {
            src: "100.100.100.100", dst: "127.0.0.1",
            make_udp: &make_udp, make_tcp: &make_tcp, make_icmp: &make_icmp4,
        },
        TestInput {
            src: "2001:4860:4860::8888", dst: "::1",
            make_udp: &make_udp6, make_tcp: &make_tcp6, make_icmp: &make_icmp6,
        }
    ];
    for test_input @ TestInput { src: _, dst: _, make_udp, make_tcp, make_icmp } in test_inputs {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default(),).expect("Failed to load libfirewall");
        fw.apply_dynamic_state(FirewallDynamicState {
            ip_addresses: vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        });
        let mut state = fw.get_dynamic_state();
        assert!(fw.get_dynamic_state().whitelist.peer_whitelists[Permissions::IncomingConnections].is_empty());
        assert!(fw.get_dynamic_state().whitelist.port_whitelist.is_empty());

        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp(&test_input.src, &test_input.dst, IcmpTypes::EchoRequest.into())), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), false);

        state.whitelist.port_whitelist.insert(PublicKey(make_peer()), FILE_SEND_PORT);
        fw.apply_dynamic_state(state.clone());
        assert_eq!(fw.get_dynamic_state().whitelist.port_whitelist.len(), 1);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp(&test_input.src, &test_input.dst, IcmpTypes::EchoRequest.into())), false);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), true);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(&test_input.src_socket(11111), &test_input.dst_socket(12345))), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(12345), TcpFlags::PSH)), false);

        state.whitelist.port_whitelist.remove(&PublicKey(make_peer()));
        fw.apply_dynamic_state(state.clone());
        assert_eq!(fw.get_dynamic_state().whitelist.port_whitelist.len(), 0);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_icmp(&test_input.src, &test_input.dst, IcmpTypes::EchoRequest.into())), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &mut make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), false);
    }
}

mod tp_lite_stats {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use pnet_packet::dns::{
        DnsClasses, DnsType, DnsTypes, MutableDnsPacket, MutableDnsResponsePacket, Retcodes,
    };
    use telio_model::tp_lite_stats::{
        BlockedDomain, DnsMetrics, TpLiteStatsCallback, TpLiteStatsOptions,
    };

    use super::*;

    const DNS_HEADER_SIZE: usize = 12;

    // Strings in the DNS message format are encoded as a list of labels followed by a null byte.
    // A label starts with a "len byte" denoting how long the label is, followed by the bytes of the string.
    // DNS labels can only contain ascii code points.
    //
    // This explanation and function does not include the "root record" or compression pointers.
    fn encode_domain_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0x00);
        out
    }

    enum PacketType {
        Query,
        Response,
        BlockedResponse,
    }

    fn dns_packet(tx_id: u16, name: &str, packet_type: PacketType) -> Vec<u8> {
        let mut buf = vec![0; DNS_HEADER_SIZE];
        let mut packet = MutableDnsPacket::new(&mut buf)
            .expect("Creating MutableDnsPacket should be successful");

        packet.set_id(tx_id);
        packet.set_is_recursion_desirable(1);
        packet.set_query_count(1);
        match packet_type {
            PacketType::Query => {}
            PacketType::Response => {
                packet.set_is_response(1);
                packet.set_is_recursion_available(1);
                packet.set_response_count(1);
            }
            PacketType::BlockedResponse => {
                packet.set_is_response(1);
                packet.set_is_recursion_available(1);
                packet.set_rcode(Retcodes::RecordNotExists);
                packet.set_authority_rr_count(1);
            }
        };

        buf.extend_from_slice(&dns_query(name));
        match packet_type {
            PacketType::Query => {}
            PacketType::Response => buf.extend_from_slice(&dns_a_record()),
            PacketType::BlockedResponse => buf.extend_from_slice(&dns_soa_record()),
        }

        buf
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut buf = encode_domain_name(name);
        buf.extend_from_slice(&DnsTypes::A.0.to_be_bytes());
        buf.extend_from_slice(&DnsClasses::IN.0.to_be_bytes());
        buf
    }

    fn dns_rr(rtype: DnsType, rdata: Vec<u8>) -> Vec<u8> {
        let mut buf = vec![0; DNS_HEADER_SIZE];
        let mut packet = MutableDnsResponsePacket::new(&mut buf).unwrap();

        packet.set_name_tag(u16::from_be_bytes([0xC0, 0x0C]));
        packet.set_rtype(rtype);
        packet.set_rclass(DnsClasses::IN);
        packet.set_ttl(3600);
        packet.set_data_len(rdata.len() as u16);

        buf.extend_from_slice(&rdata);

        buf
    }

    fn dns_a_record() -> Vec<u8> {
        // For A records the rdata just contains an IPv4 address
        let rdata = vec![93, 184, 216, 34];
        dns_rr(DnsTypes::A, rdata)
    }

    fn dns_soa_record() -> Vec<u8> {
        let mut rdata = Vec::new();

        rdata.extend_from_slice(&encode_domain_name(
            "dns-malware-cybersec.nordthreatprotection.com",
        )); // MNAME
        rdata.extend_from_slice(&encode_domain_name("hostmaster.example.com")); // RNAME

        // Some fields that are irrelevant for testing purposes. They can all be set to 0
        rdata.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // Serial number
        rdata.extend_from_slice(&[0, 0, 0, 0]); // Refresh interval
        rdata.extend_from_slice(&[0, 0, 0, 0]); // Retry interval
        rdata.extend_from_slice(&[0, 0, 0, 0]); // Expiry
        rdata.extend_from_slice(&[0, 0, 0, 0]); // Minimum

        dns_rr(DnsTypes::SOA, rdata)
    }

    fn make_dns_request(tx_id: u16, name: &str) -> Vec<u8> {
        let dns_payload = dns_packet(tx_id, name, PacketType::Query);
        make_udp_with_body("127.0.0.1:12345", "10.5.0.53:53", &dns_payload)
    }

    fn make_dns_response(tx_id: u16, name: &str, is_blocked: bool) -> Vec<u8> {
        let dns_payload = if is_blocked {
            dns_packet(tx_id, name, PacketType::BlockedResponse)
        } else {
            dns_packet(tx_id, name, PacketType::Response)
        };
        make_udp_with_body("10.5.0.53:53", "127.0.0.1:12345", &dns_payload)
    }

    #[derive(Debug, Default)]
    struct Stats {
        num_invocations: usize,
        num_requests: u32,
        num_responses: u32,
        blocked_domains: Vec<BlockedDomain>,
    }

    #[derive(Debug)]
    struct Callback {
        stats: Arc<Mutex<Stats>>,
    }

    impl TpLiteStatsCallback for Callback {
        fn collect(&self, domains: Vec<BlockedDomain>, metrics: DnsMetrics) {
            let mut stats = self.stats.lock();
            stats.num_invocations += 1;
            stats.num_requests += metrics.num_requests;
            stats.num_responses += metrics.num_responses;
            stats.blocked_domains.extend_from_slice(&domains);
        }
    }

    #[test]
    fn tp_lite_stats_enabled() {
        let fw = StatefulFirewall::new(true, FeatureFirewall::default())
            .expect("Failed to load libfirewall");
        let mut state = fw.get_dynamic_state();
        state.ip_addresses = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        fw.apply_dynamic_state(state.clone());
        let config = TpLiteStatsOptions {
            dns_server_ips: vec![IpAddr::from([10, 5, 0, 53])],
            callback_interval_s: Some(1),
            ..Default::default()
        };
        let stats = Arc::new(Mutex::new(Stats::default()));
        let callback = Callback {
            stats: stats.clone(),
        };
        fw.enable_tp_lite_stats_collection(config, Box::new(callback))
            .unwrap();

        assert!(fw.process_outbound_packet_sink(&make_peer(), &make_dns_request(1, "example.com")));
        assert!(fw.process_inbound_packet(
            &make_peer(),
            &mut make_dns_response(1, "example.com", false)
        ));

        assert!(fw.process_outbound_packet_sink(
            &make_peer(),
            &make_dns_request(2, "blocked1.example.com")
        ));
        assert!(fw.process_inbound_packet(
            &make_peer(),
            &mut make_dns_response(2, "blocked1.example.com", true)
        ));

        assert!(fw.process_outbound_packet_sink(
            &make_peer(),
            &make_dns_request(3, "blocked2.example.com")
        ));
        // Small sleep to make sure stats collection happens
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(fw.process_inbound_packet(
            &make_peer(),
            &mut make_dns_response(4, "blocked2.example.com", true)
        ));

        assert_eq!(stats.lock().num_invocations, 1);
        assert_eq!(stats.lock().num_requests, 3);
        assert_eq!(stats.lock().num_responses, 2);
        assert_eq!(stats.lock().blocked_domains.len(), 1);
        assert_eq!(
            stats.lock().blocked_domains[0].domain_name,
            "blocked1.example.com".to_owned()
        );
    }

    #[test]
    fn test_tp_lite_with_force_plaintext_dns() {
        const SRC_ADDR: &str = "127.0.0.1:12345";
        const OTHER_ADDR: &str = "1.1.1.1:853";
        const PT_DNS_ADDR: &str = "10.5.0.53:53";
        const DOT_DNS_ADDR: &str = "10.5.0.53:853";

        let fw = StatefulFirewall::new(true, FeatureFirewall::default())
            .expect("Failed to load libfirewall");
        let mut state = fw.get_dynamic_state();
        state.ip_addresses = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        fw.apply_dynamic_state(state.clone());

        let stats = Arc::new(Mutex::new(Stats::default()));
        let callback = Callback {
            stats: stats.clone(),
        };

        // Enable TP-Lite stats collection with block_non_dns_traffic = true
        let config = TpLiteStatsOptions {
            dns_server_ips: vec![IpAddr::from([10, 5, 0, 53])],
            ..Default::default()
        };
        fw.enable_tp_lite_stats_collection(config, Box::new(callback))
            .unwrap();

        // Before enabling TP-Lite stats collection, all outbound packets should be accepted
        // regardless of destination IP or port.
        //
        // Packet 1: different IP, non-53 port (DoT port 853) — accepted
        assert!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(SRC_ADDR, OTHER_ADDR)));
        // Packet 2: configured DNS IP, port 53 — accepted
        assert!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(SRC_ADDR, PT_DNS_ADDR)));
        // Packet 3: configured DNS IP, non-53 port (DoT port 853) — accepted (flag not set)
        assert!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(SRC_ADDR, DOT_DNS_ADDR)));

        // Re-enable TP-Lite stats collection with force_plaintext_dns = true
        let config = TpLiteStatsOptions {
            dns_server_ips: vec![IpAddr::from([10, 5, 0, 53])],
            force_plaintext_dns: Some(true),
            ..Default::default()
        };
        let stats = Arc::new(Mutex::new(Stats::default()));
        let callback = Callback {
            stats: stats.clone(),
        };
        fw.enable_tp_lite_stats_collection(config, Box::new(callback))
            .unwrap();

        // After enabling with force_plaintext_dns = true:
        //
        // Packet 1: different IP, non-53 port — still accepted (only the configured DNS IP is restricted)
        assert!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(SRC_ADDR, OTHER_ADDR)));
        // Packet 2: configured DNS IP, port 53 — accepted (standard DNS is allowed)
        assert!(fw.process_outbound_packet_sink(&make_peer(), &make_udp(SRC_ADDR, PT_DNS_ADDR)));
        // Packet 3: configured DNS IP, non-53 port (DoT port 853) — rejected
        assert!(!fw.process_outbound_packet_sink(&make_peer(), &make_udp(SRC_ADDR, DOT_DNS_ADDR)));
        assert!(
            !fw.process_outbound_packet_sink(&make_peer(), &mut make_udp(SRC_ADDR, DOT_DNS_ADDR))
        );

        // Re-enable TP-Lite stats collection with force_plaintext_dns = false
        let config = TpLiteStatsOptions {
            dns_server_ips: vec![IpAddr::from([10, 5, 0, 53])],
            ..Default::default()
        };
        let callback = Callback {
            stats: stats.clone(),
        };
        fw.enable_tp_lite_stats_collection(config, Box::new(callback))
            .unwrap();

        // After enabling with force_plaintext_dns = false:
        //
        // Packet 1: different IP, non-53 port — still accepted (only the configured DNS IP is restricted)
        assert!(fw.process_outbound_packet_sink(&make_peer(), &mut make_udp(SRC_ADDR, OTHER_ADDR)));
        // Packet 2: configured DNS IP, port 53 — accepted (standard DNS is allowed)
        assert!(fw.process_outbound_packet_sink(&make_peer(), &mut make_udp(SRC_ADDR, PT_DNS_ADDR)));
        // Packet 3: configured DNS IP, non-53 port (DoT port 853) should be allowed again
        assert!(
            fw.process_outbound_packet_sink(&make_peer(), &mut make_udp(SRC_ADDR, DOT_DNS_ADDR))
        );
    }
}
