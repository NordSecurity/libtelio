use pnet_packet::{
    ip::IpNextHeaderProtocol, ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet, MutablePacket,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::nat::Error;

#[derive(Clone, Copy, Debug)]
pub struct DefaultAddresses {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

pub trait MutableIpPacket<'a>: Sized + MutablePacket {
    type IpAddrType: Into<IpAddr> + Copy;

    fn new(buffer: &'a mut [u8]) -> Option<Self>;

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
    fn get_source(&self) -> Self::IpAddrType;
    fn get_destination(&self) -> Self::IpAddrType;

    fn set_source(&mut self, addrs: Self::IpAddrType);
    fn set_destination(&mut self, addr: Self::IpAddrType);
    fn calculate_udp_header_update(
        old_checksum: u16,
        old_ip_addr: Self::IpAddrType,
        new_ip_addr: Self::IpAddrType,
        old_port: u16,
        new_port: u16,
    ) -> u16;

    fn fix_checksum(&mut self, old_dst_ip: Self::IpAddrType, new_dst_ip: Self::IpAddrType);

    fn get_virtual_address(vaddrs: DefaultAddresses) -> Self::IpAddrType;

    fn get_ip_from_addr(addr: &SocketAddr) -> Result<Self::IpAddrType, Error>;
}

impl<'a> MutableIpPacket<'a> for MutableIpv4Packet<'a> {
    type IpAddrType = Ipv4Addr;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        Self::new(buffer)
    }

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_level_protocol()
    }

    fn get_destination(&self) -> Ipv4Addr {
        self.get_destination().into()
    }

    fn get_source(&self) -> Ipv4Addr {
        self.get_source().into()
    }

    fn set_source(&mut self, addr: Ipv4Addr) {
        self.set_source(addr);
    }

    fn set_destination(&mut self, addr: Ipv4Addr) {
        self.set_destination(addr);
    }

    /// Calculates ipv4 udp incremental header checksum.
    /// Based on: [https://datatracker.ietf.org/doc/html/rfc1624] Eqn. 3
    fn calculate_udp_header_update(
        old_checksum: u16,
        old_ip_addr: Ipv4Addr,
        new_ip_addr: Ipv4Addr,
        old_port: u16,
        new_port: u16,
    ) -> u16 {
        let mut sum = !old_checksum as u32;
        sum = checksum::sub_4_bytes(sum, old_ip_addr.octets());
        sum = checksum::add_4_bytes(sum, new_ip_addr.octets());
        sum = checksum::sub_2_bytes(sum, old_port);
        sum = checksum::add_2_bytes(sum, new_port);
        !checksum::fold_checksum(sum)
    }

    fn get_virtual_address(vaddrs: DefaultAddresses) -> Self::IpAddrType {
        vaddrs.ipv4
    }

    fn fix_checksum(&mut self, old_dst_ip: Self::IpAddrType, new_dst_ip: Self::IpAddrType) {
        let old_ip_checksum = self.to_immutable().get_checksum();
        if old_ip_checksum != 0 {
            self.set_checksum(checksum::ipv4_header_update(
                old_ip_checksum,
                old_dst_ip,
                new_dst_ip,
            ));
        }
    }

    fn get_ip_from_addr(addr: &SocketAddr) -> Result<Self::IpAddrType, Error> {
        match addr.ip() {
            IpAddr::V4(ipv4) => Ok(ipv4),
            IpAddr::V6(_) => Err(Error::UnexpectedIpVersion),
        }
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

    fn get_destination(&self) -> Ipv6Addr {
        self.get_destination().into()
    }

    fn get_source(&self) -> Ipv6Addr {
        self.get_source().into()
    }

    fn set_destination(&mut self, addr: Ipv6Addr) {
        self.set_destination(addr);
    }

    fn set_source(&mut self, addr: Ipv6Addr) {
        self.set_source(addr);
    }

    /// Calculates ipv6 udp incremental header checksum.
    /// Based on: [https://datatracker.ietf.org/doc/html/rfc1624] Eqn. 3
    fn calculate_udp_header_update(
        old_checksum: u16,
        old_ip_addr: Ipv6Addr,
        new_ip_addr: Ipv6Addr,
        old_port: u16,
        new_port: u16,
    ) -> u16 {
        let mut sum = !old_checksum as u32;
        sum = checksum::sub_16_bytes(sum, old_ip_addr.octets());
        sum = checksum::add_16_bytes(sum, new_ip_addr.octets());
        sum = checksum::sub_2_bytes(sum, old_port);
        sum = checksum::add_2_bytes(sum, new_port);
        !checksum::fold_checksum(sum)
    }

    fn get_virtual_address(vaddrs: DefaultAddresses) -> Self::IpAddrType {
        vaddrs.ipv6
    }

    fn fix_checksum(&mut self, _old_dst_ip: Self::IpAddrType, _new_dst_ip: Self::IpAddrType) {}

    fn get_ip_from_addr(addr: &SocketAddr) -> Result<Self::IpAddrType, Error> {
        match addr.ip() {
            IpAddr::V4(_) => Err(Error::UnexpectedIpVersion),
            IpAddr::V6(addr) => Ok(addr),
        }
    }
}

pub(crate) mod checksum {
    use std::net::Ipv4Addr;

    pub(crate) fn fold_checksum(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        sum as u16
    }

    pub(crate) fn add_2_bytes(sum: u32, data: u16) -> u32 {
        sum + data as u32
    }

    pub(crate) fn sub_2_bytes(sum: u32, data: u16) -> u32 {
        sum + !data as u32
    }

    #[allow(unwrap_check)]
    #[allow(index_access_check)]
    pub(crate) fn add_4_bytes(mut sum: u32, data: [u8; 4]) -> u32 {
        for i in 0..2 {
            sum = add_2_bytes(
                sum,
                // Allow unwrap and index access since we know the exact size of the data array
                u16::from_be_bytes(data[i * 2..i * 2 + 2].try_into().unwrap()),
            );
        }
        sum
    }

    #[allow(unwrap_check)]
    #[allow(index_access_check)]
    pub(crate) fn add_16_bytes(mut sum: u32, data: [u8; 16]) -> u32 {
        for i in 0..8 {
            sum = add_2_bytes(
                sum,
                // Allow unwrap and index access since we know the exact size of the data array
                u16::from_be_bytes(data[i * 2..i * 2 + 2].try_into().unwrap()),
            );
        }
        sum
    }

    #[allow(unwrap_check)]
    #[allow(index_access_check)]
    pub(crate) fn sub_4_bytes(mut sum: u32, data: [u8; 4]) -> u32 {
        for i in 0..2 {
            sum = sub_2_bytes(
                sum,
                // Allow unwrap and index access since we know the exact size of the data array
                u16::from_be_bytes(data[i * 2..i * 2 + 2].try_into().unwrap()),
            );
        }
        sum
    }

    #[allow(unwrap_check)]
    #[allow(index_access_check)]
    pub(crate) fn sub_16_bytes(mut sum: u32, data: [u8; 16]) -> u32 {
        for i in 0..8 {
            sum = sub_2_bytes(
                sum,
                // Allow unwrap and index access since we know the exact size of the data array
                u16::from_be_bytes(data[i * 2..i * 2 + 2].try_into().unwrap()),
            );
        }
        sum
    }

    /// Calculates ipv4 incremental header checksum.
    /// Based on: [https://datatracker.ietf.org/doc/html/rfc1624] Eqn. 3
    pub fn ipv4_header_update(
        old_checksum: u16,
        old_ip_addr: Ipv4Addr,
        new_ip_addr: Ipv4Addr,
    ) -> u16 {
        let mut sum = !old_checksum as u32;
        sum = sub_4_bytes(sum, old_ip_addr.octets());
        sum = add_4_bytes(sum, new_ip_addr.octets());
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
        for _ in 1..1000000 {
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
        for _ in 1..1000000 {
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
        for _ in 1..1000000 {
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
