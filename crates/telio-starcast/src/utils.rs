use pnet_packet::{
    ip::IpNextHeaderProtocol, ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet, MutablePacket,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub struct DualIpAddr {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

pub trait MutableIpPacket<'a>: Sized + MutablePacket {
    type IpAddrType: Into<IpAddr> + Copy;

    fn new(buffer: &'a mut [u8]) -> Option<Self>;

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
    fn get_source(&self) -> Self::IpAddrType;
    fn get_destination(&self) -> Self::IpAddrType;

    fn set_source(&mut self, addr: Self::IpAddrType);
    fn set_destination(&mut self, addr: Self::IpAddrType);
    fn fix_ip_header_checksum(&mut self, old_ip: Self::IpAddrType, new_ip: Self::IpAddrType);

    fn get_addr(ip_addr: &DualIpAddr) -> Self::IpAddrType;
    fn get_ip_from_addr(addr: &SocketAddr) -> Option<Self::IpAddrType>;
    fn calculate_udp_header_checksum_update(
        old_checksum: u16,
        old_ip_addr: Self::IpAddrType,
        new_ip_addr: Self::IpAddrType,
        old_port: u16,
        new_port: u16,
    ) -> u16;
}

impl<'a> MutableIpPacket<'a> for MutableIpv4Packet<'a> {
    type IpAddrType = Ipv4Addr;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        Self::new(buffer)
    }

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_level_protocol()
    }

    fn get_destination(&self) -> Self::IpAddrType {
        self.get_destination()
    }

    fn get_source(&self) -> Self::IpAddrType {
        self.get_source()
    }

    fn set_source(&mut self, addr: Self::IpAddrType) {
        self.set_source(addr);
    }

    fn set_destination(&mut self, addr: Self::IpAddrType) {
        self.set_destination(addr);
    }

    fn fix_ip_header_checksum(&mut self, old_ip: Self::IpAddrType, new_ip: Self::IpAddrType) {
        let old_checksum = self.get_checksum();
        if old_checksum != 0 {
            self.set_checksum(checksum::ipv4_header_update(old_checksum, old_ip, new_ip));
        }
    }

    fn get_addr(ip_addr: &DualIpAddr) -> Self::IpAddrType {
        ip_addr.ipv4
    }

    fn get_ip_from_addr(addr: &SocketAddr) -> Option<Self::IpAddrType> {
        match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        }
    }

    fn calculate_udp_header_checksum_update(
        old_checksum: u16,
        old_ip_addr: Self::IpAddrType,
        new_ip_addr: Self::IpAddrType,
        old_port: u16,
        new_port: u16,
    ) -> u16 {
        checksum::ipv4_udp_header_update(old_checksum, old_ip_addr, new_ip_addr, old_port, new_port)
    }
}

impl<'a> MutableIpPacket<'a> for MutableIpv6Packet<'a> {
    type IpAddrType = Ipv6Addr;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        Self::new(buffer)
    }

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_header()
    }

    fn get_destination(&self) -> Self::IpAddrType {
        self.get_destination()
    }

    fn get_source(&self) -> Self::IpAddrType {
        self.get_source()
    }

    fn set_destination(&mut self, addr: Self::IpAddrType) {
        self.set_destination(addr);
    }

    fn set_source(&mut self, addr: Self::IpAddrType) {
        self.set_source(addr);
    }

    fn fix_ip_header_checksum(&mut self, _: Self::IpAddrType, _: Self::IpAddrType) {}

    fn get_addr(ip_addr: &DualIpAddr) -> Self::IpAddrType {
        ip_addr.ipv6
    }

    fn get_ip_from_addr(addr: &SocketAddr) -> Option<Self::IpAddrType> {
        match addr.ip() {
            IpAddr::V6(ip) => Some(ip),
            _ => None,
        }
    }

    fn calculate_udp_header_checksum_update(
        old_checksum: u16,
        old_ip_addr: Self::IpAddrType,
        new_ip_addr: Self::IpAddrType,
        old_port: u16,
        new_port: u16,
    ) -> u16 {
        checksum::ipv6_udp_header_update(old_checksum, old_ip_addr, new_ip_addr, old_port, new_port)
    }
}

pub(crate) mod checksum {
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn fold_checksum(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        sum as u16
    }

    fn add_u16(sum: u32, data: u16) -> u32 {
        sum + data as u32
    }

    fn sub_u16(sum: u32, data: u16) -> u32 {
        sum + !data as u32
    }

    struct AssertEven<const N: usize>;
    impl<const N: usize> AssertEven<N> {
        const OK: () = assert!(N % 2 == 0, "N must be even");
    }

    #[allow(unwrap_check, index_access_check, clippy::unwrap_used)]
    fn op_on_u16s<const N: usize>(mut sum: u32, data: [u8; N], oper: fn(u32, u16) -> u32) -> u32 {
        let () = AssertEven::<N>::OK;
        for i in 0..N / 2 {
            sum = oper(
                sum,
                // Allow unwrap and index access since we know both the exact size of
                // the data array and that it is even at the compile time
                u16::from_be_bytes(data[i * 2..i * 2 + 2].try_into().unwrap()),
            );
        }
        sum
    }

    fn add_bytes<const N: usize>(sum: u32, data: [u8; N]) -> u32 {
        op_on_u16s(sum, data, add_u16)
    }

    fn sub_bytes<const N: usize>(sum: u32, data: [u8; N]) -> u32 {
        op_on_u16s(sum, data, sub_u16)
    }
    /// Calculates ipv4 incremental header checksum.
    /// Based on: [https://datatracker.ietf.org/doc/html/rfc1624] Eqn. 3
    pub fn ipv4_header_update(
        old_checksum: u16,
        old_ip_addr: Ipv4Addr,
        new_ip_addr: Ipv4Addr,
    ) -> u16 {
        let mut sum = !old_checksum as u32;
        sum = sub_bytes(sum, old_ip_addr.octets());
        sum = add_bytes(sum, new_ip_addr.octets());
        !fold_checksum(sum)
    }

    /// Calculates ipv4 udp incremental header checksum.
    /// Based on: [https://datatracker.ietf.org/doc/html/rfc1624] Eqn. 3
    pub fn ipv4_udp_header_update(
        old_checksum: u16,
        old_ip_addr: Ipv4Addr,
        new_ip_addr: Ipv4Addr,
        old_port: u16,
        new_port: u16,
    ) -> u16 {
        let mut sum = !old_checksum as u32;
        sum = sub_bytes(sum, old_ip_addr.octets());
        sum = add_bytes(sum, new_ip_addr.octets());
        sum = sub_u16(sum, old_port);
        sum = add_u16(sum, new_port);
        !fold_checksum(sum)
    }

    /// Calculates ipv6 udp incremental header checksum.
    /// Based on: [https://datatracker.ietf.org/doc/html/rfc1624] Eqn. 3
    pub fn ipv6_udp_header_update(
        old_checksum: u16,
        old_ip_addr: Ipv6Addr,
        new_ip_addr: Ipv6Addr,
        old_port: u16,
        new_port: u16,
    ) -> u16 {
        let mut sum = !old_checksum as u32;
        sum = sub_bytes(sum, old_ip_addr.octets());
        sum = add_bytes(sum, new_ip_addr.octets());
        sum = sub_u16(sum, old_port);
        sum = add_u16(sum, new_port);
        !fold_checksum(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::{
        ipv4::{self, MutableIpv4Packet},
        udp::{self, MutableUdpPacket},
    };
    use rand::RngCore;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_header_update() {
        for _ in 1..100000 {
            let mut data = [0u8; 20];
            rand::thread_rng().fill_bytes(&mut data);
            let mut packet = MutableIpv4Packet::new(&mut data).unwrap();

            let old_checksum = ipv4::checksum(&packet.to_immutable());

            let old_ip_addr = packet.get_destination();
            let new_ip_addr = Ipv4Addr::from(rand::thread_rng().next_u32());

            let new_incremental_checksum =
                checksum::ipv4_header_update(old_checksum, old_ip_addr, new_ip_addr);

            packet.set_destination(new_ip_addr);
            let new_full_checksum = ipv4::checksum(&packet.to_immutable());

            assert_eq!(new_incremental_checksum, new_full_checksum);
        }
    }

    #[test]
    fn ipv4_udp_header_update() {
        for _ in 1..100000 {
            let mut data = [0u8; 80];
            rand::thread_rng().fill_bytes(&mut data);
            let mut packet = MutableUdpPacket::new(&mut data).unwrap();
            let const_ip_addr = Ipv4Addr::from(rand::thread_rng().next_u32());
            let old_ip_addr = Ipv4Addr::from(rand::thread_rng().next_u32());
            let new_ip_addr = Ipv4Addr::from(rand::thread_rng().next_u32());

            let old_checksum =
                udp::ipv4_checksum(&packet.to_immutable(), &const_ip_addr, &old_ip_addr);

            let old_port = packet.get_destination();
            let new_port = rand::thread_rng().next_u32() as u16;

            let new_incremental_checksum = checksum::ipv4_udp_header_update(
                old_checksum,
                old_ip_addr,
                new_ip_addr,
                old_port,
                new_port,
            );

            packet.set_destination(new_port);
            let new_full_checksum =
                udp::ipv4_checksum(&packet.to_immutable(), &const_ip_addr, &new_ip_addr);

            assert_eq!(new_incremental_checksum, new_full_checksum);
        }
    }

    #[test]
    fn ipv6_udp_header_update() {
        for _ in 1..100000 {
            let mut data = [0u8; 80];
            rand::thread_rng().fill_bytes(&mut data);
            let mut packet = MutableUdpPacket::new(&mut data).unwrap();

            let mut data = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut data);
            let const_ip_addr = Ipv6Addr::from(data);
            rand::thread_rng().fill_bytes(&mut data);
            let old_ip_addr = Ipv6Addr::from(data);
            rand::thread_rng().fill_bytes(&mut data);
            let new_ip_addr = Ipv6Addr::from(data);

            let old_checksum =
                udp::ipv6_checksum(&packet.to_immutable(), &const_ip_addr, &old_ip_addr);

            let old_port = packet.get_destination();
            let new_port = rand::thread_rng().next_u32() as u16;

            let new_incremental_checksum = checksum::ipv6_udp_header_update(
                old_checksum,
                old_ip_addr,
                new_ip_addr,
                old_port,
                new_port,
            );

            packet.set_destination(new_port);
            let new_full_checksum =
                udp::ipv6_checksum(&packet.to_immutable(), &const_ip_addr, &new_ip_addr);

            assert_eq!(new_incremental_checksum, new_full_checksum);
        }
    }
}
