use crate::utils::{checksum, MutableIpPacket};
use pnet_packet::{
    ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet,
    udp::MutableUdpPacket,
};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use telio_utils::{telio_log_warn, LruCache};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The packet is too short to be a valid IP packet
    PacketTooShort,
    /// The packet has an unexpected IP version
    UnexpectedIpVersion,
    /// The packet has an unexpected transport protocol
    UnexpectedTransportProtocol,
    /// Cannot map the packet
    CannotMap,
    /// There is no mapping for the given port
    MappingNotFound,
}

pub trait Nat {
    /// Translate incomming packet (from the transport socket to the multicast peer)
    /// Change the source to the multicast peer's ip and natted port
    fn translate_incomming(&mut self, packet: &mut [u8]) -> Result<(), Error>;
    /// Translate outgoing packet (from the multicast peer to the transport socket)
    /// Change the destination to the peer's original ip and port
    fn translate_outgoing(&mut self, packet: &mut [u8]) -> Result<(), Error>;
}

type Mapper = fn(src_addr: SocketAddr) -> u16;

fn default_mapper(src_addr: SocketAddr) -> u16 {
    let mut hasher = DefaultHasher::new();
    match src_addr.ip() {
        IpAddr::V4(src_ip) => Hash::hash_slice(&src_ip.octets(), &mut hasher),
        IpAddr::V6(src_ip) => Hash::hash_slice(&src_ip.octets(), &mut hasher),
    };
    src_addr.port().hash(&mut hasher);
    hasher.finish() as u16 // TODO: think if we want to use the full 16 bits or maybe some range e.g. >=1024
}

pub struct StarcastNat {
    mappings: LruCache<u16, SocketAddr>,
    vpeer_ipv4_addr: Ipv4Addr,
    vpeer_ipv6_addr: Ipv6Addr,
    mapper: Mapper,
}

impl StarcastNat {
    /// Create new starcast nat with default capcity of 2048 entries and 2 minute timeout
    /// 2min default is taken from (https://datatracker.ietf.org/doc/html/rfc4787#section-4.3)
    pub fn new(vpeer_ipv4: Ipv4Addr, vpeer_ipv6: Ipv6Addr) -> Self {
        const DEFAULT_CACHE_CAPACITY: usize = 2048;
        const DEFAULT_CACHE_TIMEOUT: Duration = Duration::from_secs(120);
        Self::new_custom(
            vpeer_ipv4,
            vpeer_ipv6,
            DEFAULT_CACHE_CAPACITY,
            DEFAULT_CACHE_TIMEOUT,
            default_mapper,
        )
    }

    /// Create new starcast nat with custom capacity and timeout
    fn new_custom(
        vpeer_ipv4_addr: Ipv4Addr,
        vpeer_ipv6_addr: Ipv6Addr,
        cache_capacity: usize,
        cache_timeout: Duration,
        mapper: Mapper,
    ) -> Self {
        Self {
            mappings: LruCache::new(cache_timeout, cache_capacity),
            vpeer_ipv4_addr,
            vpeer_ipv6_addr,
            mapper,
        }
    }

    fn translate_incomming_internal<'a, P: MutableIpPacket<'a>>(
        &mut self,
        packet: &'a mut [u8],
    ) -> Result<(), Error> {
        let mut ip_packet = P::new(packet).ok_or(Error::PacketTooShort)?;
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return Err(Error::UnexpectedTransportProtocol);
        }

        let src_ip = ip_packet.get_source();

        match src_ip {
            IpAddr::V4(src_ip) => {
                ip_packet.set_source(IpAddr::V4(self.vpeer_ipv4_addr));
                let old_checksum = ip_packet.to_immutable_ipv4().get_checksum();
                if old_checksum != 0 {
                    ip_packet.set_checksum(checksum::ipv4_header_update(
                        old_checksum,
                        src_ip,
                        self.vpeer_ipv4_addr,
                    ));
                }
            }
            IpAddr::V6(_) => {
                ip_packet.set_source(IpAddr::V6(self.vpeer_ipv6_addr));
            }
        };

        let mut udp_packet =
            MutableUdpPacket::new(ip_packet.payload_mut()).ok_or(Error::PacketTooShort)?;
        let src_port = udp_packet.get_source();
        let src_addr = SocketAddr::new(src_ip, src_port);
        let mut nat_port = (self.mapper)(src_addr);

        const MAX_ATTEMPTS: u32 = 128;
        let mut loop_guard = 0;
        while let Some(&current_mapping) = self.mappings.peek(&nat_port) {
            if current_mapping != src_addr {
                nat_port = (self.mapper)(SocketAddr::new(src_addr.ip(), nat_port));

                loop_guard += 1;
                if loop_guard > MAX_ATTEMPTS {
                    return Err(Error::CannotMap);
                }
            } else {
                break;
            }
        }

        self.mappings.insert(nat_port, src_addr);

        udp_packet.set_source(nat_port);

        match src_ip {
            IpAddr::V4(src_ip) => {
                let old_checksum = udp_packet.get_checksum();
                if old_checksum != 0 {
                    udp_packet.set_checksum(checksum::ipv4_udp_header_update(
                        old_checksum,
                        src_ip,
                        self.vpeer_ipv4_addr,
                        src_port,
                        nat_port,
                    ))
                }
            }
            IpAddr::V6(src_ip) => {
                let old_checksum = udp_packet.get_checksum();
                if old_checksum != 0 {
                    udp_packet.set_checksum(checksum::ipv6_udp_header_update(
                        old_checksum,
                        src_ip,
                        self.vpeer_ipv6_addr,
                        src_port,
                        nat_port,
                    ))
                }
            }
        };

        Ok(())
    }

    fn translate_outgoing_internal<'a, P: MutableIpPacket<'a>>(
        &mut self,
        packet: &'a mut [u8],
    ) -> Result<(), Error> {
        let mut ip_packet = P::new(packet).ok_or(Error::PacketTooShort)?;
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return Err(Error::UnexpectedTransportProtocol);
        }

        let old_dst_ip = ip_packet.get_destination();

        let mut udp_packet =
            MutableUdpPacket::new(ip_packet.payload_mut()).ok_or(Error::PacketTooShort)?;
        let dst_port = udp_packet.get_destination();

        let new_dst_addr = self.mappings.get(&dst_port).ok_or(Error::MappingNotFound)?;

        udp_packet.set_destination(new_dst_addr.port());
        match (old_dst_ip, new_dst_addr.ip()) {
            (IpAddr::V4(old_dst_ip), IpAddr::V4(new_dst_ip)) => {
                let old_udp_checksum = udp_packet.get_checksum();
                if old_udp_checksum != 0 {
                    udp_packet.set_checksum(checksum::ipv4_udp_header_update(
                        old_udp_checksum,
                        old_dst_ip,
                        new_dst_ip,
                        dst_port,
                        new_dst_addr.port(),
                    ));
                }

                ip_packet.set_destination(IpAddr::V4(new_dst_ip));
                let old_ip_checksum = ip_packet.to_immutable_ipv4().get_checksum();
                if old_ip_checksum != 0 {
                    ip_packet.set_checksum(checksum::ipv4_header_update(
                        old_ip_checksum,
                        old_dst_ip,
                        new_dst_ip,
                    ));
                }
            }
            (IpAddr::V6(old_dst_ip), IpAddr::V6(new_dst_ip)) => {
                let old_udp_checksum = udp_packet.get_checksum();
                if old_udp_checksum != 0 {
                    udp_packet.set_checksum(checksum::ipv6_udp_header_update(
                        old_udp_checksum,
                        old_dst_ip,
                        new_dst_ip,
                        dst_port,
                        new_dst_addr.port(),
                    ))
                }

                ip_packet.set_destination(IpAddr::V6(new_dst_ip));
            }
            _ => return Err(Error::MappingNotFound),
        };

        Ok(())
    }
}

impl Nat for StarcastNat {
    fn translate_incomming(&mut self, packet: &mut [u8]) -> Result<(), Error> {
        match packet.first().ok_or(Error::PacketTooShort)? >> 4 {
            4 => self.translate_incomming_internal::<MutableIpv4Packet>(packet),
            6 => self.translate_incomming_internal::<MutableIpv6Packet>(packet),
            version => {
                telio_log_warn!("Unexpected IP version {version} for inbound packet");
                Err(Error::UnexpectedIpVersion)
            }
        }
    }

    fn translate_outgoing(&mut self, packet: &mut [u8]) -> Result<(), Error> {
        match packet.first().ok_or(Error::PacketTooShort)? >> 4 {
            4 => self.translate_outgoing_internal::<MutableIpv4Packet>(packet),
            6 => self.translate_outgoing_internal::<MutableIpv6Packet>(packet),
            version => {
                telio_log_warn!("Unexpected IP version {version} for outbound packet");
                Err(Error::UnexpectedIpVersion)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::{
        ip::IpNextHeaderProtocol, ipv4, ipv4::Ipv4Packet, ipv6::Ipv6Packet, udp, udp::UdpPacket,
        MutablePacket, Packet,
    };
    use std::{net::{SocketAddrV4, SocketAddrV6}, sync::atomic::{AtomicU16, Ordering}};

    const IPV4_HEADER_MIN_LENGTH: usize = 20;
    const IPV6_HEADER_LENGTH: usize = 40;
    const UDP_HEADER_LENGTH: usize = 8;
    const IPV4_NAT_ADDR: Ipv4Addr = Ipv4Addr::new(0xaa, 0xbb, 0xcc, 0xdd);
    const IPV6_NAT_ADDR: Ipv6Addr = Ipv6Addr::new(0xaaaa, 0, 0, 0, 0, 0, 0, 0xdddd);

    fn set_ipv4(
        buffer: &mut [u8],
        next_level_protocol: IpNextHeaderProtocol,
        total_length: usize,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) {
        let mut ip_packet = MutableIpv4Packet::new(buffer).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length((IPV4_HEADER_MIN_LENGTH / 4) as u8);
        ip_packet.set_total_length(total_length.try_into().unwrap());
        ip_packet.set_next_level_protocol(next_level_protocol);
        ip_packet.set_source(source);
        ip_packet.set_destination(destination);
        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
    }

    fn set_ipv6(
        buffer: &mut [u8],
        next_level_protocol: IpNextHeaderProtocol,
        total_length: usize,
        source: Ipv6Addr,
        destination: Ipv6Addr,
    ) {
        let mut ip_packet = MutableIpv6Packet::new(buffer).unwrap();
        ip_packet.set_version(6);
        ip_packet.set_payload_length((total_length - IPV6_HEADER_LENGTH).try_into().unwrap());
        ip_packet.set_next_header(next_level_protocol);
        ip_packet.set_source(source);
        ip_packet.set_destination(destination);
    }

    fn make_udp_v4(src_addr: &str, dst_addr: &str) -> Vec<u8> {
        let packet_len = IPV4_HEADER_MIN_LENGTH + UDP_HEADER_LENGTH;
        let mut buffer = vec![0u8; packet_len];

        let src_addr: SocketAddrV4 = src_addr.parse().unwrap();
        let dst_addr: SocketAddrV4 = dst_addr.parse().unwrap();

        set_ipv4(
            &mut buffer,
            IpNextHeaderProtocols::Udp,
            packet_len,
            *src_addr.ip(),
            *dst_addr.ip(),
        );

        let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).unwrap();
        udp_packet.set_source(src_addr.port());
        udp_packet.set_destination(dst_addr.port());
        udp_packet.set_length(UDP_HEADER_LENGTH as u16);
        udp_packet.set_checksum(udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &src_addr.ip(),
            &dst_addr.ip(),
        ));

        buffer
    }

    fn make_udp_v4_reply(buffer: &[u8]) -> Vec<u8> {
        let ip_packet = Ipv4Packet::new(&buffer).unwrap();
        let src_ip = ip_packet.get_source().to_string();
        let dst_ip = ip_packet.get_destination().to_string();

        let udp_packet = UdpPacket::new(ip_packet.payload()).unwrap();
        let src_port = udp_packet.get_source().to_string();
        let dst_port = udp_packet.get_destination().to_string();

        make_udp_v4(
            &format!("{dst_ip}:{dst_port}"),
            &format!("{src_ip}:{src_port}"),
        )
    }

    pub fn make_udp_v6(src_addr: &str, dst_addr: &str) -> Vec<u8> {
        let packet_len = IPV6_HEADER_LENGTH + UDP_HEADER_LENGTH;
        let mut buffer = vec![0u8; packet_len];

        let src_addr: SocketAddrV6 = src_addr.parse().unwrap();
        let dst_addr: SocketAddrV6 = dst_addr.parse().unwrap();

        set_ipv6(
            &mut buffer,
            IpNextHeaderProtocols::Udp,
            packet_len,
            *src_addr.ip(),
            *dst_addr.ip(),
        );

        let mut ip_packet = MutableIpv6Packet::new(&mut buffer).unwrap();
        let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).unwrap();
        udp_packet.set_source(src_addr.port());
        udp_packet.set_destination(dst_addr.port());
        udp_packet.set_length(UDP_HEADER_LENGTH as u16);
        udp_packet.set_checksum(udp::ipv6_checksum(
            &udp_packet.to_immutable(),
            &src_addr.ip(),
            &dst_addr.ip(),
        ));

        buffer
    }

    fn make_udp_v6_reply(buffer: &[u8]) -> Vec<u8> {
        let ip_packet = Ipv6Packet::new(&buffer).unwrap();
        let src_ip = ip_packet.get_source().to_string();
        let dst_ip = ip_packet.get_destination().to_string();

        let udp_packet = UdpPacket::new(ip_packet.payload()).unwrap();
        let src_port = udp_packet.get_source().to_string();
        let dst_port = udp_packet.get_destination().to_string();

        make_udp_v6(
            &format!("[{dst_ip}]:{dst_port}"),
            &format!("[{src_ip}]:{src_port}"),
        )
    }

    fn advance_time(time: Duration) {
        sn_fake_clock::FakeClock::advance_time(time.as_millis() as u64);
    }

    macro_rules! assert_src_dst_v4 {
        ($buffer:ident, $src_addr:ident, $dst_addr:ident) => {
            let ip_packet = Ipv4Packet::new(&$buffer).unwrap();
            let src_ip = ip_packet.get_source().to_string();
            let dst_ip = ip_packet.get_destination().to_string();

            let udp_packet = UdpPacket::new(&$buffer[IPV4_HEADER_MIN_LENGTH..]).unwrap();
            let src_port = udp_packet.get_source().to_string();
            let dst_port = udp_packet.get_destination().to_string();

            assert_eq!(
                format!("{src_ip}:{src_port}"),
                $src_addr,
                "Packet's src_addr does not match"
            );
            assert_eq!(
                format!("{dst_ip}:{dst_port}"),
                $dst_addr,
                "Packet's dst_addr does not match"
            );
        };
    }

    macro_rules! assert_src_dst_v6 {
        ($buffer:ident, $src_addr:ident, $dst_addr:ident) => {
            let ip_packet = Ipv6Packet::new(&$buffer).unwrap();
            let src_ip = ip_packet.get_source().to_string();
            let dst_ip = ip_packet.get_destination().to_string();

            let udp_packet = UdpPacket::new(&$buffer[IPV6_HEADER_LENGTH..]).unwrap();
            let src_port = udp_packet.get_source().to_string();
            let dst_port = udp_packet.get_destination().to_string();

            assert_eq!(
                format!("[{src_ip}]:{src_port}"),
                $src_addr,
                "Packet's src_addr does not match"
            );
            assert_eq!(
                format!("[{dst_ip}]:{dst_port}"),
                $dst_addr,
                "Packet's dst_addr does not match"
            );
        };
    }

    macro_rules! assert_checksum_v4 {
        ($buffer:ident) => {
            let ip_packet = Ipv4Packet::new(&$buffer).unwrap();
            let incremental_ip_checksum = ip_packet.get_checksum();
            let full_ip_checksum = ipv4::checksum(&ip_packet);

            let udp_packet = UdpPacket::new(&$buffer[IPV4_HEADER_MIN_LENGTH..]).unwrap();
            let incremental_udp_checksum = udp_packet.get_checksum();
            let full_udp_checksum = udp::ipv4_checksum(
                &udp_packet,
                &ip_packet.get_source(),
                &ip_packet.get_destination(),
            );

            assert_eq!(
                incremental_ip_checksum, full_ip_checksum,
                "Packet's ip checksum does not match"
            );

            assert_eq!(
                incremental_udp_checksum, full_udp_checksum,
                "Packet's udp checksum does not match"
            );
        };
    }

    macro_rules! assert_checksum_v6 {
        ($buffer:ident) => {
            let ip_packet = Ipv6Packet::new(&$buffer).unwrap();
            let udp_packet = UdpPacket::new(&$buffer[IPV6_HEADER_LENGTH..]).unwrap();
            let incremental_udp_checksum = udp_packet.get_checksum();
            let full_udp_checksum = udp::ipv6_checksum(
                &udp_packet,
                &ip_packet.get_source(),
                &ip_packet.get_destination(),
            );

            assert_eq!(
                incremental_udp_checksum, full_udp_checksum,
                "Packet's udp checksum does not match"
            );
        };
    }

    macro_rules! assert_err {
        ($x:expr, $err:pat) => {
            assert!(matches!($x, Err($err)));
        };
    }

    fn nat_addr(src_addr: &str) -> String {
        let src_addr: SocketAddr = src_addr.parse().unwrap();
        match src_addr {
            SocketAddr::V4(_) => {
                let nat_ip = IPV4_NAT_ADDR.to_string();
                let nat_port = default_mapper(src_addr);
                format!("{nat_ip}:{nat_port}")
            }
            SocketAddr::V6(_) => {
                let nat_ip = IPV6_NAT_ADDR.to_string();
                let nat_port = default_mapper(src_addr);
                format!("[{nat_ip}]:{nat_port}")
            }
        }
    }

    #[test]
    fn basic_ipv4_nat_works() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);

        let src_addr = "1.2.3.4:1234";
        let dst_addr = "5.6.7.8:5678";
        let nat_addr = nat_addr(src_addr);

        let mut incomming = make_udp_v4(&src_addr, &dst_addr);
        let mut incomming2 = incomming.clone();
        let mut incomming3 = incomming.clone();

        assert!(nat.translate_incomming(&mut incomming).is_ok());
        assert_src_dst_v4!(incomming, nat_addr, dst_addr);
        assert_checksum_v4!(incomming);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v4_reply(&incomming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr);
        assert_checksum_v4!(outgoing);

        assert!(nat.translate_incomming(&mut incomming2).is_ok());
        assert_src_dst_v4!(incomming2, nat_addr, dst_addr);
        assert_checksum_v4!(incomming2);
        assert!(nat.translate_incomming(&mut incomming3).is_ok());
        assert_src_dst_v4!(incomming3, nat_addr, dst_addr);
        assert_checksum_v4!(incomming3);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v4_reply(&incomming2);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr);
        assert_checksum_v4!(outgoing);

        let mut outgoing = make_udp_v4_reply(&incomming3);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr);
        assert_checksum_v4!(outgoing);
    }

    #[test]
    fn basic_ipv6_nat_works() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);

        let src_addr = "[1234::1234]:1234";
        let dst_addr = "[5678::5678]:5678";
        let nat_addr = nat_addr(src_addr);

        let mut incomming = make_udp_v6(&src_addr, &dst_addr);
        let mut incomming2 = incomming.clone();
        let mut incomming3 = incomming.clone();

        assert!(nat.translate_incomming(&mut incomming).is_ok());
        assert_src_dst_v6!(incomming, nat_addr, dst_addr);
        assert_checksum_v6!(incomming);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v6_reply(&incomming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v6!(outgoing, dst_addr, src_addr);
        assert_checksum_v6!(outgoing);

        assert!(nat.translate_incomming(&mut incomming2).is_ok());
        assert_src_dst_v6!(incomming2, nat_addr, dst_addr);
        assert_checksum_v6!(incomming2);
        assert!(nat.translate_incomming(&mut incomming3).is_ok());
        assert_src_dst_v6!(incomming3, nat_addr, dst_addr);
        assert_checksum_v6!(incomming3);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v6_reply(&incomming2);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v6!(outgoing, dst_addr, src_addr);
        assert_checksum_v6!(outgoing);

        let mut outgoing = make_udp_v6_reply(&incomming3);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v6!(outgoing, dst_addr, src_addr);
        assert_checksum_v6!(outgoing);
    }

    #[test]
    fn zero_length_packet() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);
        let mut packet = vec![0; 0];

        assert_err!(nat.translate_incomming(&mut packet), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut packet), Error::PacketTooShort);
    }

    #[test]
    fn unexpected_ip_version() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);
        let mut packet = vec![0; 1];

        assert_err!(
            nat.translate_incomming(&mut packet),
            Error::UnexpectedIpVersion
        );
        assert_err!(
            nat.translate_outgoing(&mut packet),
            Error::UnexpectedIpVersion
        );
    }

    #[test]
    fn shorter_than_min_ip() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);
        let mut packet = vec![0; 10];
        packet[0] = 4 << 4;

        assert_err!(nat.translate_incomming(&mut packet), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut packet), Error::PacketTooShort);

        packet[0] = 6 << 4;

        assert_err!(nat.translate_incomming(&mut packet), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut packet), Error::PacketTooShort);
    }

    #[test]
    fn wrong_next_level_protocol() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);

        let src_addr = "1.2.3.4:1234";
        let dst_addr = "5.6.7.8:5678";
        let mut udp_v4 = make_udp_v4(&src_addr, &dst_addr);
        let mut udp_v4_mut = MutableIpv4Packet::new(&mut udp_v4).unwrap();
        udp_v4_mut.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        let src_addr = "[1234::1234]:1234";
        let dst_addr = "[5678::5678]:5678";
        let mut udp_v6 = make_udp_v6(&src_addr, &dst_addr);
        udp_v6.pop();
        let mut udp_v6_mut = MutableIpv6Packet::new(&mut udp_v6).unwrap();
        udp_v6_mut.set_next_header(IpNextHeaderProtocols::Tcp);

        assert_err!(
            nat.translate_incomming(&mut udp_v4),
            Error::UnexpectedTransportProtocol
        );
        assert_err!(
            nat.translate_outgoing(&mut udp_v4),
            Error::UnexpectedTransportProtocol
        );

        assert_err!(
            nat.translate_incomming(&mut udp_v6),
            Error::UnexpectedTransportProtocol
        );
        assert_err!(
            nat.translate_outgoing(&mut udp_v6),
            Error::UnexpectedTransportProtocol
        );
    }

    #[test]
    fn shorter_than_min_udp() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);

        let src_addr = "1.2.3.4:1234";
        let dst_addr = "5.6.7.8:5678";
        let mut udp_v4 = make_udp_v4(&src_addr, &dst_addr);
        udp_v4.pop();

        let src_addr = "[1234::1234]:1234";
        let dst_addr = "[5678::5678]:5678";
        let mut udp_v6 = make_udp_v6(&src_addr, &dst_addr);
        udp_v6.pop();

        assert_err!(nat.translate_incomming(&mut udp_v4), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut udp_v4), Error::PacketTooShort);

        assert_err!(nat.translate_incomming(&mut udp_v6), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut udp_v6), Error::PacketTooShort);
    }

    #[test]
    fn no_mapping_error() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);

        let src_addr = "1.2.3.4:1234";
        let dst_addr = "5.6.7.8:5678";
        let mut udp_v4 = make_udp_v4(&src_addr, &dst_addr);

        let src_addr = "[1234::1234]:1234";
        let dst_addr = "[5678::5678]:5678";
        let mut udp_v6 = make_udp_v6(&src_addr, &dst_addr);

        assert_err!(nat.translate_outgoing(&mut udp_v4), Error::MappingNotFound);
        assert_err!(nat.translate_outgoing(&mut udp_v6), Error::MappingNotFound);
    }

    #[test]
    fn mappings_expire_after_lru_timeout() {
        const LRU_TIMEOUT: Duration = Duration::from_millis(10);
        let mut nat =
            StarcastNat::new_custom(IPV4_NAT_ADDR, IPV6_NAT_ADDR, 5, LRU_TIMEOUT, default_mapper);

        let src_addr = "1.2.3.4:1234";
        let dst_addr = "5.6.7.8:5678";
        let nat_addr = nat_addr(src_addr);

        let mut incomming = make_udp_v4(&src_addr, &dst_addr);
        assert!(nat.translate_incomming(&mut incomming).is_ok());
        assert_src_dst_v4!(incomming, nat_addr, dst_addr);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v4_reply(&incomming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr);
        assert_eq!(nat.mappings.len(), 1);

        advance_time(LRU_TIMEOUT + Duration::from_millis(1));
        assert_err!(
            nat.translate_outgoing(&mut outgoing),
            Error::MappingNotFound
        );
        assert_eq!(nat.mappings.len(), 0);
    }

    #[test]
    fn next_port_chosen_when_mapping_collision() {
        const LRU_TIMEOUT: Duration = Duration::from_millis(10);
        let mut nat = StarcastNat::new_custom(
            IPV4_NAT_ADDR,
            IPV6_NAT_ADDR,
            5,
            LRU_TIMEOUT,
            |_: SocketAddr| {
                static COUNTER: AtomicU16 = AtomicU16::new(5);
                COUNTER.fetch_add(1, Ordering::Relaxed)
            },
        );

        let src_addr_1 = "1.2.3.4:1234";
        let src_addr_2 = "1.2.3.4:2345";
        let src_addr_3 = "2.3.4.5:1234";
        let dst_addr = "5.6.7.8:5678";

        let mut incomming = make_udp_v4(&src_addr_1, &dst_addr);
        assert!(nat.translate_incomming(&mut incomming).is_ok());
        assert_eq!(nat.mappings.len(), 1);
        let mut outgoing = make_udp_v4_reply(&incomming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr_1);

        let mut incomming = make_udp_v4(&src_addr_2, &dst_addr);
        assert!(nat.translate_incomming(&mut incomming).is_ok());
        assert_eq!(nat.mappings.len(), 2);
        let mut outgoing = make_udp_v4_reply(&incomming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr_2);

        let mut incomming = make_udp_v4(&src_addr_3, &dst_addr);
        assert!(nat.translate_incomming(&mut incomming).is_ok());
        assert_eq!(nat.mappings.len(), 3);
        let mut outgoing = make_udp_v4_reply(&incomming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr_3);
    }

    #[test]
    fn mapping_error_returned_when_cannot_find_free_port() {
        const LRU_TIMEOUT: Duration = Duration::from_millis(10);
        let mut nat = StarcastNat::new_custom(
            IPV4_NAT_ADDR,
            IPV6_NAT_ADDR,
            5,
            LRU_TIMEOUT,
            |_: SocketAddr| 5,
        );

        let src_addr_1 = "1.2.3.4:1234";
        let src_addr_2 = "1.2.3.4:2345";
        let dst_addr = "5.6.7.8:5678";

        let mut incomming = make_udp_v4(&src_addr_1, &dst_addr);
        assert!(nat.translate_incomming(&mut incomming).is_ok());
        assert_eq!(nat.mappings.len(), 1);
        let mut outgoing = make_udp_v4_reply(&incomming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr_1);

        let mut incomming = make_udp_v4(&src_addr_2, &dst_addr);
        assert_err!(nat.translate_incomming(&mut incomming), Error::CannotMap);
    }
}
