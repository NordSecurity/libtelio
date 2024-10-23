use crate::utils::{DualIpAddr, MutableIpPacket};
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

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    /// The packet is too short to be a valid IP packet
    #[error("The packet is too short to be a valid IP packet")]
    PacketTooShort,
    /// The packet has an unexpected IP version
    #[error("The packet has an unexpected IP version")]
    UnexpectedIpVersion,
    /// The packet has an unexpected transport protocol
    #[error("The packet has an unexpected transport protocol")]
    UnexpectedTransportProtocol,
    /// Cannot map the packet
    #[error("Cannot map the packet")]
    CannotMap,
    /// There is no mapping for the given port
    #[error("There is no mapping for the given port")]
    MappingNotFound,
}

pub trait Nat {
    /// Translate incoming packet (from the transport socket to the multicast peer)
    /// Change the source to the multicast peer's ip and natted port
    fn translate_incoming(&mut self, packet: &mut [u8]) -> Result<IpAddr, Error>;
    /// Translate outgoing packet (from the multicast peer to the transport socket)
    /// Change the destination to the peer's original ip and port
    fn translate_outgoing(&mut self, packet: &mut [u8]) -> Result<IpAddr, Error>;
}

type Mapper = fn(src_addr: SocketAddr) -> u16;

fn default_mapper(src_addr: SocketAddr) -> u16 {
    let mut hasher = DefaultHasher::new();
    match src_addr.ip() {
        IpAddr::V4(src_ip) => Hash::hash_slice(&src_ip.octets(), &mut hasher),
        IpAddr::V6(src_ip) => Hash::hash_slice(&src_ip.octets(), &mut hasher),
    };
    src_addr.port().hash(&mut hasher);
    hasher.finish() as u16
}

pub struct StarcastNat {
    mappings: LruCache<u16, SocketAddr>,
    vpeer_addr: DualIpAddr,
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
            vpeer_addr: DualIpAddr {
                ipv4: vpeer_ipv4_addr,
                ipv6: vpeer_ipv6_addr,
            },
            mapper,
        }
    }

    fn translate_incoming_internal<'a, P: MutableIpPacket<'a>>(
        &mut self,
        packet: &'a mut [u8],
    ) -> Result<IpAddr, Error> {
        let mut ip_packet = P::new(packet).ok_or(Error::PacketTooShort)?;
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return Err(Error::UnexpectedTransportProtocol);
        }

        let old_src_ip = ip_packet.get_source();
        let new_src_ip = P::get_addr(&self.vpeer_addr);
        ip_packet.set_source(new_src_ip);
        ip_packet.fix_ip_header_checksum(old_src_ip, new_src_ip);

        let mut udp_packet =
            MutableUdpPacket::new(ip_packet.payload_mut()).ok_or(Error::PacketTooShort)?;
        let src_port = udp_packet.get_source();
        let old_src_addr = SocketAddr::new(old_src_ip.into(), src_port);
        let mut nat_port = (self.mapper)(old_src_addr);

        const MAX_ATTEMPTS: u32 = 128;
        let mut loop_guard = 0;
        while let Some(&current_mapping) = self.mappings.peek(&nat_port) {
            if current_mapping != old_src_addr {
                nat_port = (self.mapper)(SocketAddr::new(old_src_addr.ip(), nat_port));

                loop_guard += 1;
                if loop_guard > MAX_ATTEMPTS {
                    return Err(Error::CannotMap);
                }
            } else {
                break;
            }
        }

        self.mappings.insert(nat_port, old_src_addr);

        udp_packet.set_source(nat_port);

        let old_udp_checksum = udp_packet.get_checksum();
        if old_udp_checksum != 0 {
            udp_packet.set_checksum(P::calculate_udp_header_checksum_update(
                old_udp_checksum,
                old_src_ip,
                new_src_ip,
                src_port,
                nat_port,
            ))
        }

        Ok(old_src_ip.into())
    }

    fn translate_outgoing_internal<'a, P: MutableIpPacket<'a>>(
        &mut self,
        packet: &'a mut [u8],
    ) -> Result<IpAddr, Error> {
        let mut ip_packet = P::new(packet).ok_or(Error::PacketTooShort)?;
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return Err(Error::UnexpectedTransportProtocol);
        }

        let old_dst_ip = ip_packet.get_destination();

        let mut udp_packet =
            MutableUdpPacket::new(ip_packet.payload_mut()).ok_or(Error::PacketTooShort)?;
        let dst_port = udp_packet.get_destination();

        let new_dst_addr = self.mappings.get(&dst_port).ok_or(Error::MappingNotFound)?;
        let new_dst_ip = P::get_ip_from_addr(new_dst_addr).ok_or(Error::MappingNotFound)?;

        udp_packet.set_destination(new_dst_addr.port());

        let old_udp_checksum = udp_packet.get_checksum();
        if old_udp_checksum != 0 {
            udp_packet.set_checksum(P::calculate_udp_header_checksum_update(
                old_udp_checksum,
                old_dst_ip,
                new_dst_ip,
                dst_port,
                new_dst_addr.port(),
            ));
        }

        ip_packet.set_destination(new_dst_ip);
        ip_packet.fix_ip_header_checksum(old_dst_ip, new_dst_ip);

        Ok(new_dst_ip.into())
    }
}

impl Nat for StarcastNat {
    fn translate_incoming(&mut self, packet: &mut [u8]) -> Result<IpAddr, Error> {
        match packet.first().ok_or(Error::PacketTooShort)? >> 4 {
            4 => self.translate_incoming_internal::<MutableIpv4Packet>(packet),
            6 => self.translate_incoming_internal::<MutableIpv6Packet>(packet),
            version => {
                telio_log_warn!("Unexpected IP version {version} for inbound packet");
                Err(Error::UnexpectedIpVersion)
            }
        }
    }

    fn translate_outgoing(&mut self, packet: &mut [u8]) -> Result<IpAddr, Error> {
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
    use crate::{assert_src_dst_v4, assert_src_dst_v6, utils::test_utils::*};
    use pnet_packet::{ipv4, ipv4::Ipv4Packet, ipv6::Ipv6Packet, udp, udp::UdpPacket};
    use std::sync::atomic::{AtomicU16, Ordering};

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

        let mut incoming = make_udp_v4(&src_addr, &dst_addr);
        let mut incoming2 = incoming.clone();
        let mut incoming3 = incoming.clone();

        assert!(nat.translate_incoming(&mut incoming).is_ok());
        assert_src_dst_v4!(incoming, nat_addr, dst_addr);
        assert_checksum_v4!(incoming);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v4_reply(&incoming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr);
        assert_checksum_v4!(outgoing);

        assert!(nat.translate_incoming(&mut incoming2).is_ok());
        assert_src_dst_v4!(incoming2, nat_addr, dst_addr);
        assert_checksum_v4!(incoming2);
        assert!(nat.translate_incoming(&mut incoming3).is_ok());
        assert_src_dst_v4!(incoming3, nat_addr, dst_addr);
        assert_checksum_v4!(incoming3);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v4_reply(&incoming2);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr);
        assert_checksum_v4!(outgoing);

        let mut outgoing = make_udp_v4_reply(&incoming3);
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

        let mut incoming = make_udp_v6(&src_addr, &dst_addr);
        let mut incoming2 = incoming.clone();
        let mut incoming3 = incoming.clone();

        assert!(nat.translate_incoming(&mut incoming).is_ok());
        assert_src_dst_v6!(incoming, nat_addr, dst_addr);
        assert_checksum_v6!(incoming);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v6_reply(&incoming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v6!(outgoing, dst_addr, src_addr);
        assert_checksum_v6!(outgoing);

        assert!(nat.translate_incoming(&mut incoming2).is_ok());
        assert_src_dst_v6!(incoming2, nat_addr, dst_addr);
        assert_checksum_v6!(incoming2);
        assert!(nat.translate_incoming(&mut incoming3).is_ok());
        assert_src_dst_v6!(incoming3, nat_addr, dst_addr);
        assert_checksum_v6!(incoming3);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v6_reply(&incoming2);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v6!(outgoing, dst_addr, src_addr);
        assert_checksum_v6!(outgoing);

        let mut outgoing = make_udp_v6_reply(&incoming3);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v6!(outgoing, dst_addr, src_addr);
        assert_checksum_v6!(outgoing);
    }

    #[test]
    fn zero_length_packet() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);
        let mut packet = vec![0; 0];

        assert_err!(nat.translate_incoming(&mut packet), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut packet), Error::PacketTooShort);
    }

    #[test]
    fn unexpected_ip_version() {
        let mut nat = StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR);
        let mut packet = vec![0; 1];

        assert_err!(
            nat.translate_incoming(&mut packet),
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

        assert_err!(nat.translate_incoming(&mut packet), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut packet), Error::PacketTooShort);

        packet[0] = 6 << 4;

        assert_err!(nat.translate_incoming(&mut packet), Error::PacketTooShort);
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
            nat.translate_incoming(&mut udp_v4),
            Error::UnexpectedTransportProtocol
        );
        assert_err!(
            nat.translate_outgoing(&mut udp_v4),
            Error::UnexpectedTransportProtocol
        );

        assert_err!(
            nat.translate_incoming(&mut udp_v6),
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

        assert_err!(nat.translate_incoming(&mut udp_v4), Error::PacketTooShort);
        assert_err!(nat.translate_outgoing(&mut udp_v4), Error::PacketTooShort);

        assert_err!(nat.translate_incoming(&mut udp_v6), Error::PacketTooShort);
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

        let mut incoming = make_udp_v4(&src_addr, &dst_addr);
        assert!(nat.translate_incoming(&mut incoming).is_ok());
        assert_src_dst_v4!(incoming, nat_addr, dst_addr);
        assert_eq!(nat.mappings.len(), 1);

        let mut outgoing = make_udp_v4_reply(&incoming);
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

        let mut incoming = make_udp_v4(&src_addr_1, &dst_addr);
        assert!(nat.translate_incoming(&mut incoming).is_ok());
        assert_eq!(nat.mappings.len(), 1);
        let mut outgoing = make_udp_v4_reply(&incoming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr_1);

        let mut incoming = make_udp_v4(&src_addr_2, &dst_addr);
        assert!(nat.translate_incoming(&mut incoming).is_ok());
        assert_eq!(nat.mappings.len(), 2);
        let mut outgoing = make_udp_v4_reply(&incoming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr_2);

        let mut incoming = make_udp_v4(&src_addr_3, &dst_addr);
        assert!(nat.translate_incoming(&mut incoming).is_ok());
        assert_eq!(nat.mappings.len(), 3);
        let mut outgoing = make_udp_v4_reply(&incoming);
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

        let mut incoming = make_udp_v4(&src_addr_1, &dst_addr);
        assert!(nat.translate_incoming(&mut incoming).is_ok());
        assert_eq!(nat.mappings.len(), 1);
        let mut outgoing = make_udp_v4_reply(&incoming);
        assert!(nat.translate_outgoing(&mut outgoing).is_ok());
        assert_src_dst_v4!(outgoing, dst_addr, src_addr_1);

        let mut incoming = make_udp_v4(&src_addr_2, &dst_addr);
        assert_err!(nat.translate_incoming(&mut incoming), Error::CannotMap);
    }
}
