use core::fmt::Debug;
use std::net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};

use pnet_packet::{
    ip::IpNextHeaderProtocol, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpFlags, Packet,
};

pub(crate) const TCP_FIRST_PKT_MASK: u8 = TcpFlags::SYN | TcpFlags::ACK;

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub(crate) enum IpAddr {
    Ipv4(u32),
    Ipv6(u128),
}

impl From<StdIpv4Addr> for IpAddr {
    fn from(ipv4_addr: StdIpv4Addr) -> IpAddr {
        IpAddr::Ipv4(ipv4_addr.into())
    }
}

impl From<StdIpv6Addr> for IpAddr {
    fn from(ipv6_addr: StdIpv6Addr) -> IpAddr {
        IpAddr::Ipv6(ipv6_addr.into())
    }
}

impl From<IpAddr> for StdIpAddr {
    fn from(ip_addr: IpAddr) -> Self {
        match ip_addr {
            IpAddr::Ipv4(ipv4) => StdIpAddr::V4(ipv4.into()),
            IpAddr::Ipv6(ipv6) => StdIpAddr::V6(ipv6.into()),
        }
    }
}

pub(crate) trait IpPacket<'a>: Sized + Debug + Packet {
    type Addr: Into<IpAddr> + Into<std::net::IpAddr> + Debug;

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
    fn get_destination(&self) -> Self::Addr;
    fn get_source(&self) -> Self::Addr;
    fn try_from(buffer: &'a [u8]) -> Option<Self>;
}

impl<'a> IpPacket<'a> for Ipv4Packet<'a> {
    type Addr = StdIpv4Addr;

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_level_protocol()
    }

    fn get_destination(&self) -> Self::Addr {
        self.get_destination()
    }

    fn get_source(&self) -> Self::Addr {
        self.get_source()
    }

    fn try_from(buffer: &'a [u8]) -> Option<Self> {
        Self::new(buffer)
    }
}

impl<'a> IpPacket<'a> for Ipv6Packet<'a> {
    type Addr = StdIpv6Addr;

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_header()
    }

    fn get_destination(&self) -> Self::Addr {
        self.get_destination()
    }

    fn get_source(&self) -> Self::Addr {
        self.get_source()
    }

    fn try_from(buffer: &'a [u8]) -> Option<Self> {
        Self::new(buffer)
    }
}
