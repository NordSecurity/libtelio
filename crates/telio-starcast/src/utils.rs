use pnet_packet::{
    ip::IpNextHeaderProtocol,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    ipv6::MutableIpv6Packet,
    MutablePacket,
};
use std::net::IpAddr;

pub trait MutableIpPacket<'a>: Sized + MutablePacket {
    fn new(buffer: &'a mut [u8]) -> Option<Self>;

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
    fn get_source(&self) -> IpAddr;
    fn get_destination(&self) -> IpAddr;

    fn set_source(&mut self, addr: IpAddr);
    fn set_destination(&mut self, addr: IpAddr);
    fn set_checksum(&mut self, addr: u16);

    fn to_immutable_ipv4<'p>(&'p self) -> Ipv4Packet<'p>;
}

impl<'a> MutableIpPacket<'a> for MutableIpv4Packet<'a> {
    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        Self::new(buffer)
    }

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_level_protocol()
    }

    fn get_destination(&self) -> IpAddr {
        self.get_destination().into()
    }

    fn get_source(&self) -> IpAddr {
        self.get_source().into()
    }

    fn set_source(&mut self, addr: IpAddr) {
        if let IpAddr::V4(ipv4addr) = addr {
            self.set_source(ipv4addr);
        }
    }

    fn set_destination(&mut self, addr: IpAddr) {
        if let IpAddr::V4(ipv4addr) = addr {
            self.set_destination(ipv4addr);
        }
    }

    fn set_checksum(&mut self, checksum: u16) {
        self.set_checksum(checksum);
    }

    fn to_immutable_ipv4<'p>(&'p self) -> Ipv4Packet<'p> {
        self.to_immutable()
    }
}

impl<'a> MutableIpPacket<'a> for MutableIpv6Packet<'a> {
    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        Self::new(buffer)
    }

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_header()
    }

    fn get_destination(&self) -> IpAddr {
        self.get_destination().into()
    }

    fn get_source(&self) -> IpAddr {
        self.get_source().into()
    }

    fn set_destination(&mut self, addr: IpAddr) {
        if let IpAddr::V6(ipv6addr) = addr {
            self.set_destination(ipv6addr);
        }
    }

    fn set_source(&mut self, addr: IpAddr) {
        if let IpAddr::V6(ipv6addr) = addr {
            self.set_source(ipv6addr);
        }
    }

    fn set_checksum(&mut self, _: u16) {
        unimplemented!()
    }

    fn to_immutable_ipv4<'p>(&'p self) -> Ipv4Packet<'p> {
        unimplemented!()
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

    fn add_2_bytes(sum: u32, data: u16) -> u32 {
        sum + data as u32
    }

    fn sub_2_bytes(sum: u32, data: u16) -> u32 {
        sum + !data as u32
    }

    #[allow(unwrap_check)]
    #[allow(index_access_check)]
    fn add_4_bytes(mut sum: u32, data: [u8; 4]) -> u32 {
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
    fn add_16_bytes(mut sum: u32, data: [u8; 16]) -> u32 {
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
    fn sub_4_bytes(mut sum: u32, data: [u8; 4]) -> u32 {
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
    fn sub_16_bytes(mut sum: u32, data: [u8; 16]) -> u32 {
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
        sum = sub_4_bytes(sum, old_ip_addr.octets());
        sum = add_4_bytes(sum, new_ip_addr.octets());
        sum = sub_2_bytes(sum, old_port);
        sum = add_2_bytes(sum, new_port);
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
        sum = sub_16_bytes(sum, old_ip_addr.octets());
        sum = add_16_bytes(sum, new_ip_addr.octets());
        sum = sub_2_bytes(sum, old_port);
        sum = add_2_bytes(sum, new_port);
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
