use core::fmt::Debug;
use std::net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};

use pnet_packet::{
    icmp::{self, IcmpPacket, IcmpType, IcmpTypes},
    icmpv6::{self, Icmpv6Packet, Icmpv6Type, Icmpv6Types},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpFlags,
    Packet,
};

use crate::{error::Error, log::libfw_log_trace};

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
    type IcmpPacketType<'b>: GenericIcmpPacket<'b>
    where
        Self: 'b;

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
    fn get_destination(&self) -> Self::Addr;
    fn get_source(&self) -> Self::Addr;
    fn try_from(buffer: &'a [u8]) -> Option<Self>;
    /// Allows creating IP packet from truncated buffer, disabling some checks done in try_from method.
    fn try_from_truncated(buffer: &'a [u8]) -> Option<Self>;
    fn try_into_icmp_packet<'b>(
        &'b self,
        ignore_checksum: bool,
    ) -> Result<Self::IcmpPacketType<'b>, Error>;
}

impl<'a> IpPacket<'a> for Ipv4Packet<'a> {
    type Addr = StdIpv4Addr;
    type IcmpPacketType<'b>
        = IcmpPacket<'b>
    where
        Self: 'b;

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
        if let Some(4) = buffer.first().map(|first_byte| first_byte >> 4) {
            Self::new(buffer).filter(|packet| {
                let ihl = packet.get_header_length();
                (5..=15).contains(&ihl)
            })
        } else {
            None
        }
    }

    fn try_from_truncated(buffer: &'a [u8]) -> Option<Self> {
        <Self as IpPacket>::try_from(buffer)
    }

    fn try_into_icmp_packet<'b>(
        &'b self,
        ignore_checksum: bool,
    ) -> Result<Self::IcmpPacketType<'b>, Error> {
        match IcmpPacket::new(self.payload()) {
            Some(packet) if ignore_checksum || icmp::checksum(&packet) == packet.get_checksum() => {
                Ok(packet)
            }
            _ => {
                libfw_log_trace!("Could not create ICMP packet from IP packet {:?}", self);
                Err(Error::MalformedIcmpPacket)
            }
        }
    }
}

impl<'a> IpPacket<'a> for Ipv6Packet<'a> {
    type Addr = StdIpv6Addr;
    type IcmpPacketType<'b>
        = Icmpv6Packet<'b>
    where
        Self: 'b;

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
        if let Some(6) = buffer.first().map(|first_byte| first_byte >> 4) {
            Self::new(buffer).filter(|packet| {
                let payload_length = packet.get_payload_length() as usize;
                let total_length = packet.packet().len();
                let header_len = total_length - payload_length;
                header_len == 40
            })
        } else {
            None
        }
    }

    fn try_from_truncated(buffer: &'a [u8]) -> Option<Self> {
        if let Some(6) = buffer.first().map(|first_byte| first_byte >> 4) {
            Self::new(buffer)
        } else {
            None
        }
    }

    fn try_into_icmp_packet<'b>(
        &'b self,
        ignore_checksum: bool,
    ) -> Result<Self::IcmpPacketType<'b>, Error> {
        match Icmpv6Packet::new(self.payload()) {
            Some(packet)
                if ignore_checksum
                    || icmpv6::checksum(&packet, &self.get_source(), &self.get_destination())
                        == packet.get_checksum() =>
            {
                Ok(packet)
            }
            _ => {
                libfw_log_trace!("Could not create ICMP packet from IP packet {:?}", self);
                Err(Error::MalformedIcmpPacket)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpPacketGroup {
    Request,
    Reply,
    Error,
}

pub(crate) trait GenericIcmpType: Sized {
    fn get_packet_group(&self) -> Option<IcmpPacketGroup>;
    fn get_response_type(&self) -> Option<u8>;
}

impl GenericIcmpType for IcmpType {
    fn get_packet_group(&self) -> Option<IcmpPacketGroup> {
        match *self {
            IcmpTypes::EchoRequest
            | IcmpTypes::Timestamp
            | IcmpTypes::InformationRequest
            | IcmpTypes::AddressMaskRequest => Some(IcmpPacketGroup::Request),
            IcmpTypes::EchoReply
            | IcmpTypes::TimestampReply
            | IcmpTypes::InformationReply
            | IcmpTypes::AddressMaskReply => Some(IcmpPacketGroup::Reply),
            IcmpTypes::DestinationUnreachable
            | IcmpTypes::TimeExceeded
            | IcmpTypes::ParameterProblem
            | IcmpTypes::SourceQuench
            | IcmpTypes::RedirectMessage => Some(IcmpPacketGroup::Error),
            _ => None,
        }
    }

    fn get_response_type(&self) -> Option<u8> {
        match *self {
            IcmpTypes::EchoRequest | IcmpTypes::EchoReply => Some(IcmpTypes::EchoReply.0),
            IcmpTypes::Timestamp | IcmpTypes::TimestampReply => Some(IcmpTypes::TimestampReply.0),
            IcmpTypes::AddressMaskRequest | IcmpTypes::AddressMaskReply => {
                Some(IcmpTypes::AddressMaskReply.0)
            }
            IcmpTypes::InformationRequest | IcmpTypes::InformationReply => {
                Some(IcmpTypes::InformationReply.0)
            }
            _ => None,
        }
    }
}

impl GenericIcmpType for Icmpv6Type {
    fn get_packet_group(&self) -> Option<IcmpPacketGroup> {
        match *self {
            Icmpv6Types::EchoRequest => Some(IcmpPacketGroup::Request),
            Icmpv6Types::EchoReply => Some(IcmpPacketGroup::Reply),
            Icmpv6Types::DestinationUnreachable
            | Icmpv6Types::PacketTooBig
            | Icmpv6Types::ParameterProblem
            | Icmpv6Types::TimeExceeded => Some(IcmpPacketGroup::Error),
            _ => None,
        }
    }

    fn get_response_type(&self) -> Option<u8> {
        match *self {
            Icmpv6Types::EchoRequest | Icmpv6Types::EchoReply => Some(Icmpv6Types::EchoReply.0),
            _ => None,
        }
    }
}

pub(crate) trait GenericIcmpPacket<'a>: Packet + Sized {
    type Type: GenericIcmpType;
    type IpPacketType<'b>: IpPacket<'b>
    where
        Self: 'b;
    const ICMP_NEXT_HEADER_ID: IpNextHeaderProtocol;

    fn get_icmp_type(&self) -> Self::Type;
}

impl<'a> GenericIcmpPacket<'a> for IcmpPacket<'a> {
    type Type = IcmpType;
    type IpPacketType<'b>
        = Ipv4Packet<'b>
    where
        Self: 'b;
    const ICMP_NEXT_HEADER_ID: IpNextHeaderProtocol = IpNextHeaderProtocols::Icmp;

    fn get_icmp_type(&self) -> Self::Type {
        self.get_icmp_type()
    }
}

impl<'a> GenericIcmpPacket<'a> for Icmpv6Packet<'a> {
    type Type = Icmpv6Type;
    type IpPacketType<'b>
        = Ipv6Packet<'b>
    where
        Self: 'b;
    const ICMP_NEXT_HEADER_ID: IpNextHeaderProtocol = IpNextHeaderProtocols::Icmpv6;

    fn get_icmp_type(&self) -> Self::Type {
        self.get_icmpv6_type()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pnet_packet::{
        icmp::{
            self, echo_request::IcmpCodes, IcmpCode, IcmpPacket, IcmpType, IcmpTypes,
            MutableIcmpPacket,
        },
        icmpv6::{
            self, echo_reply::Icmpv6Codes, Icmpv6Code, Icmpv6Packet, Icmpv6Type, Icmpv6Types,
            MutableIcmpv6Packet,
        },
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        Packet,
    };

    use crate::packet::IpPacket;

    const IPV4_HEADER_MIN: usize = 20; // IPv4 header minimal length in bytes
    const IPV6_HEADER_MIN: usize = 40; // IPv6 header minimal length in bytes
    const UDP_HEADER: usize = 8; // UDP header length in bytes
    const ICMP_HEADER: usize = 8; // ICMP header length in bytes
    const ICMPV6_HEADER: usize = 4; // ICMPv6 header length in bytes

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
        raw: &mut [u8],
        src: &Ipv6Addr,
        dst: &Ipv6Addr,
        protocol: IpNextHeaderProtocol,
        total_length: usize,
    ) {
        let mut ip = MutableIpv6Packet::new(raw).expect("ICMP: Bad IP buffer");
        ip.set_next_header(protocol);
        ip.set_version(6);
        ip.set_traffic_class(0);
        ip.set_flow_label(0);
        ip.set_payload_length((total_length - IPV6_HEADER_MIN).try_into().unwrap());
        ip.set_hop_limit(64);
        ip.set_source(*src);
        ip.set_destination(*dst);
    }

    fn make_icmp4_with_body(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        icmp_type: IcmpType,
        icmp_code: IcmpCode,
        body: &[u8],
        fix_checksum: bool,
    ) -> Vec<u8> {
        // Because the last 4 bytes of ICMP header may differ depending on the packet type, pnet uses
        // first 4 bytes of payload for them, so they would be counted in the packet lenght twice
        let ip_len = IPV4_HEADER_MIN + ICMP_HEADER + body.len().saturating_sub(4);
        let mut raw = vec![0u8; ip_len];

        let mut packet =
            MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(icmp_type);
        packet.set_icmp_code(icmp_code);
        packet.set_payload(&body);
        packet.set_checksum(0);

        let icmp_packet =
            IcmpPacket::new(packet.packet()).expect("It should be a valid ICMP packet");

        if fix_checksum {
            packet.set_checksum(icmp::checksum(&icmp_packet));
        }

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Icmp,
            IPV4_HEADER_MIN,
            ip_len,
        );
        ip.set_source(src);
        ip.set_destination(dst);

        raw
    }

    fn make_icmp4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        icmp_type: IcmpType,
        icmp_code: IcmpCode,
    ) -> Vec<u8> {
        make_icmp4_with_body(src, dst, icmp_type, icmp_code, &[], true)
    }

    fn make_icmp6_with_body(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        icmp_type: Icmpv6Type,
        icmp_code: Icmpv6Code,
        body: &[u8],
        fix_checksum: bool,
    ) -> Vec<u8> {
        let ip_len = IPV6_HEADER_MIN + ICMPV6_HEADER + body.len();
        let mut raw = vec![0u8; ip_len];

        set_ipv6(&mut raw, &src, &dst, IpNextHeaderProtocols::Icmpv6, ip_len);

        let mut packet =
            MutableIcmpv6Packet::new(&mut raw[IPV6_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmpv6_type(icmp_type);
        packet.set_icmpv6_code(icmp_code);
        packet.set_payload(body);
        packet.set_checksum(0);

        if fix_checksum {
            let icmp_packet =
                Icmpv6Packet::new(packet.packet()).expect("It should be a valid ICMP packet");
            packet.set_checksum(icmpv6::checksum(&icmp_packet, &src, &dst));
        }

        raw
    }

    #[test]
    fn packet_ipv4_packet_validation() {
        let src_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);

        let mut raw = make_icmp4(src_ip, dst_ip, IcmpTypes::EchoRequest, IcmpCodes::NoCode);
        let mut ip = MutableIpv4Packet::new(&mut raw).expect("PRE: Bad IP buffer");

        assert!(<Ipv4Packet as IpPacket>::try_from(ip.packet()).is_some());

        ip.set_version(4);
        assert!(<Ipv4Packet as IpPacket>::try_from(ip.packet()).is_some());

        ip.set_version(0); // Invalid IP version
        assert!(<Ipv4Packet as IpPacket>::try_from(ip.packet()).is_none());

        ip.set_version(6); // Only Ipv4 supported
        assert!(<Ipv4Packet as IpPacket>::try_from(ip.packet()).is_none());

        ip.set_version(4);
        ip.set_header_length(4); // Ipv4->IHL must be [5..15]
        assert!(<Ipv4Packet as IpPacket>::try_from(ip.packet()).is_none());
    }

    #[test]
    fn conntrack_ipv6_packet_validation() {
        let src = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfc, 0x0a, 0, 0, 0, 0, 0, 1);

        let mut raw = make_icmp6_with_body(
            src,
            dst,
            Icmpv6Types::EchoRequest.into(),
            Icmpv6Codes::NoCode,
            &[1, 2, 3, 4],
            true,
        );
        let mut ip = MutableIpv6Packet::new(&mut raw).expect("PRE: Bad IP buffer");

        assert!(<Ipv6Packet as IpPacket>::try_from(ip.packet()).is_some());

        ip.set_version(6);
        assert!(<Ipv6Packet as IpPacket>::try_from(ip.packet()).is_some());

        let payload_len = ip.get_payload_length();
        ip.set_payload_length(payload_len + 1);
        assert!(<Ipv6Packet as IpPacket>::try_from(ip.packet()).is_none());

        ip.set_payload_length(payload_len - 1);
        assert!(<Ipv6Packet as IpPacket>::try_from(ip.packet()).is_none());

        // Return to original payload length
        ip.set_payload_length(payload_len);

        ip.set_version(0); // Invalid IP version
        assert!(<Ipv6Packet as IpPacket>::try_from(ip.packet()).is_none());

        ip.set_version(4); // Only Ipv6 supported
        assert!(<Ipv6Packet as IpPacket>::try_from(ip.packet()).is_none());

        // With original payload length and corrent version it should work again
        ip.set_version(6); // Only Ipv6 supported
        assert!(<Ipv6Packet as IpPacket>::try_from(ip.packet()).is_some());
    }

    #[test]
    fn conntrack_ipv4_validation_max_header() {
        const IPV4_MAX_IHL: usize = 15; //Ipv4->IHL is 4 bits, can be [5..15]
        const HEADER_LENGTH: usize = 4 * IPV4_MAX_IHL;
        const PACKET_LENGTH: usize = HEADER_LENGTH + UDP_HEADER;

        let mut raw = [0u8; PACKET_LENGTH];
        let mut ip = MutableIpv4Packet::new(&mut raw).expect("PRE: Bad IP buffer");

        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Udp,
            HEADER_LENGTH,
            PACKET_LENGTH,
        );

        assert!(<Ipv4Packet as IpPacket>::try_from(&raw).is_some());
    }
}
