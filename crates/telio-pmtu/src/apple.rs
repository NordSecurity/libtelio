use std::{
    ffi::c_int,
    io,
    net::{IpAddr, Ipv6Addr},
    os::fd::AsRawFd,
    time::Duration,
};

use pnet_packet::{icmp, icmpv6, ipv4, Packet};
use telio_utils::telio_log_debug;
use tokio::net::UdpSocket;

pub struct PMTUSocket {
    sock: UdpSocket,
    host: IpAddr,
}

const TIMEOUT: Duration = Duration::from_secs(1);
const RETRIES: u32 = 3;

impl PMTUSocket {
    pub fn new(host: IpAddr) -> io::Result<Self> {
        let sock = crate::create_icmp_socket(&host)?;
        set_dont_frag_flag(&sock, host.is_ipv6())?;
        Ok(Self { sock, host })
    }

    pub async fn probe_pmtu(&self) -> io::Result<u32> {
        self.sock.connect((self.host, 0)).await?;

        let mut msgbuf = vec![0xFF; crate::PMTU_RANGE.end as usize];

        match self.host {
            IpAddr::V6(host) => {
                let src = match self.sock.local_addr()?.ip() {
                    IpAddr::V6(src) => src,
                    _ => unreachable!("Invalid src IP type"),
                };

                let mut pkg = IcmpV6::new(&mut msgbuf, src, host)?;
                self.probe_pmtu_internal(&mut pkg).await
            }
            IpAddr::V4(_) => {
                let mut pkg = IcmpV4::new(&mut msgbuf)?;
                self.probe_pmtu_internal(&mut pkg).await
            }
        }
    }

    async fn probe_pmtu_internal<T: IcmpPkg>(&self, pkg: &mut T) -> io::Result<u32> {
        pkg.set_ident(super::ICMP_ECHO_REQ_IDENT);

        let mut range = crate::PMTU_RANGE;

        let mut pmtu = crate::PMTU_RANGE.end;
        let mut nexthop = None;

        loop {
            match self.is_pmtu_ok(pkg, pmtu).await? {
                PmtuResult::Ok => {
                    telio_log_debug!("PMTU {pmtu} is good");
                    range.start = pmtu;
                }
                PmtuResult::TooBig { nexthop: rnexthop } => {
                    telio_log_debug!("PMTU {pmtu} is too big, got response");
                    range.end = pmtu;
                    nexthop = rnexthop;
                }
                PmtuResult::Silence => {
                    telio_log_debug!("PMTU {pmtu} is too big, no answer received");
                    range.end = pmtu;
                }
            }

            if range.start + 1 >= range.end {
                break;
            }

            pmtu = if let Some(nh) = nexthop {
                if range.contains(&nh) {
                    if pmtu == nh {
                        // Let's check if nexthop is really the upper limit
                        nexthop = None;
                        nh + 1
                    } else {
                        // Let's check nexthop
                        nh
                    }
                } else {
                    (range.start + range.end) / 2
                }
            } else {
                (range.start + range.end) / 2
            };
        }

        let found = range.start;

        if found == super::PMTU_RANGE.start {
            Err(io::ErrorKind::NotConnected.into())
        } else {
            Ok(found)
        }
    }

    async fn recv_internal<T: IcmpPkg>(&self, buf: &mut [u8]) -> io::Result<IcmpResponse> {
        for _ in 0..3 {
            let len = self.sock.recv(buf).await?;
            match T::read_from_ip(&buf[..len]) {
                Ok(response) => return Ok(response),
                Err(err) => telio_log_debug!("Received invalid packet: {err}"),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Received invalid response for 3 times in a row",
        ))
    }

    async fn is_pmtu_ok<T: IcmpPkg>(&self, pkg: &mut T, pmtu: u32) -> io::Result<PmtuResult> {
        let mut recvbuf = [0u8; 1024];

        for count in 0..RETRIES {
            pkg.advance_seq();
            let seq = pkg.seq();

            telio_log_debug!(
                "Sending ICMP Echo Request, dst: {} seq: {seq}, size: {pmtu}",
                self.host
            );

            if let Err(err) = self.sock.send(pkg.bytes(pmtu as _)).await {
                // The kernel might retun this error when the packet size == kernel's estimate of PMTU.
                // But the packet is sent anyway
                if err.raw_os_error() != Some(libc::EMSGSIZE) {
                    return Err(err);
                } else {
                    return Ok(PmtuResult::TooBig { nexthop: None });
                }
            }

            match tokio::time::timeout(TIMEOUT, self.recv_internal::<T>(&mut recvbuf)).await {
                Ok(res) => match res? {
                    IcmpResponse::EchoReply { seq: rseq } => {
                        if rseq == seq {
                            return Ok(PmtuResult::Ok);
                        }
                    }
                    IcmpResponse::TooBig { seq: rseq, nexthop } => {
                        if rseq == seq {
                            return Ok(PmtuResult::TooBig { nexthop });
                        }
                    }
                },
                Err(_timeout) => {
                    // packet was most probably dropped
                    telio_log_debug!("ICMP recv() timeout, pmtu: {pmtu}, counter: {count}");
                }
            }
        }

        Ok(PmtuResult::Silence)
    }
}

impl AsRawFd for PMTUSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.sock.as_raw_fd()
    }
}

#[derive(Debug, Clone, Copy)]
enum PmtuResult {
    Ok,
    TooBig { nexthop: Option<u32> },
    Silence,
}

#[derive(Debug, Clone, Copy)]
enum IcmpResponse {
    EchoReply { seq: u16 },
    TooBig { seq: u16, nexthop: Option<u32> },
}

trait IcmpPkg: Sized {
    fn set_ident(&mut self, ident: u16);
    fn advance_seq(&mut self);
    fn seq(&self) -> u16;
    fn bytes(&mut self, pmtu: usize) -> &[u8];

    fn read_from_ip(buf: &[u8]) -> io::Result<IcmpResponse>;
}

struct IcmpV4<'a>(icmp::echo_request::MutableEchoRequestPacket<'a>);

impl<'a> IcmpV4<'a> {
    fn new(buf: &'a mut [u8]) -> io::Result<Self> {
        let mut pkg = icmp::echo_request::MutableEchoRequestPacket::new(buf).ok_or(
            io::Error::new(io::ErrorKind::Other, "Packet buffer too small"),
        )?;

        pkg.set_icmp_type(icmp::IcmpTypes::EchoRequest);
        pkg.set_icmp_code(icmp::echo_request::IcmpCodes::NoCode);
        pkg.set_sequence_number(0);

        Ok(Self(pkg))
    }
}

impl IcmpPkg for IcmpV4<'_> {
    fn read_from_ip(buf: &[u8]) -> io::Result<IcmpResponse> {
        let ippkg = ipv4::Ipv4Packet::new(buf).ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Packet buffer too small",
        ))?;

        let icmp = icmp::IcmpPacket::new(ippkg.payload()).ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Packet buffer too small",
        ))?;

        match icmp.get_icmp_type() {
            icmp::IcmpTypes::EchoReply => {
                let icmp = icmp::echo_reply::EchoReplyPacket::new(ippkg.payload()).ok_or(
                    io::Error::new(io::ErrorKind::InvalidData, "Packet buffer too small"),
                )?;

                if icmp.get_identifier() != super::ICMP_ECHO_REQ_IDENT {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Ident mismatch"));
                }

                Ok(IcmpResponse::EchoReply {
                    seq: icmp.get_sequence_number(),
                })
            }

            icmp::IcmpTypes::DestinationUnreachable => {
                let icmp = icmp::destination_unreachable::DestinationUnreachablePacket::new(
                    ippkg.payload(),
                )
                .ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Packet buffer too small",
                ))?;

                let mut nexthop = None;
                if let icmp::destination_unreachable::IcmpCodes::FragmentationRequiredAndDFFlagSet =
                    icmp.get_icmp_code()
                {
                    let next_hop_mtu = icmp.get_unused() & 0x0000FFFF;

                    if next_hop_mtu != 0 {
                        nexthop = Some(next_hop_mtu);
                    };
                }

                let orig_ippkg = ipv4::Ipv4Packet::new(icmp.payload()).ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Packet buffer too small",
                ))?;

                let orig_icmp =
                    icmp::echo_request::EchoRequestPacket::new(orig_ippkg.payload()).ok_or(
                        io::Error::new(io::ErrorKind::InvalidData, "Packet buffer too small"),
                    )?;

                if orig_icmp.get_identifier() != super::ICMP_ECHO_REQ_IDENT {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Ident mismatch"));
                }

                Ok(IcmpResponse::TooBig {
                    seq: orig_icmp.get_sequence_number(),
                    nexthop,
                })
            }
            ty => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected ICMP type: {ty:?}"),
            )),
        }
    }

    fn set_ident(&mut self, ident: u16) {
        self.0.set_identifier(ident);
    }

    fn advance_seq(&mut self) {
        self.0.set_sequence_number(self.0.get_sequence_number() + 1);
    }

    fn seq(&self) -> u16 {
        self.0.get_sequence_number()
    }

    fn bytes(&mut self, pmtu: usize) -> &[u8] {
        const IP_HEADER_SIZE: usize = 20;
        let len = pmtu - IP_HEADER_SIZE;

        self.0.set_checksum(0);
        let checksum = {
            let pkg =
                icmp::IcmpPacket::new(&self.0.packet()[..len]).expect("Packet buffer too small");
            icmp::checksum(&pkg)
        };
        self.0.set_checksum(checksum);

        &self.0.packet()[..len]
    }
}

struct IcmpV6<'a>(icmpv6::echo_request::MutableEchoRequestPacket<'a>);

impl<'a> IcmpV6<'a> {
    fn new(buf: &'a mut [u8], src: Ipv6Addr, dst: Ipv6Addr) -> io::Result<Self> {
        let mut pkg = icmpv6::echo_request::MutableEchoRequestPacket::new(buf).ok_or(
            io::Error::new(io::ErrorKind::Other, "Too small initial PMTU guess"),
        )?;

        pkg.set_icmpv6_type(icmpv6::Icmpv6Types::EchoRequest);
        pkg.set_icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode);
        pkg.set_checksum(0);

        let checksum = {
            let pkg = icmpv6::Icmpv6Packet::new(pkg.packet()).ok_or(io::Error::new(
                io::ErrorKind::Other,
                "Packet buffer too small",
            ))?;

            icmpv6::checksum(&pkg, &src, &dst)
        };

        pkg.set_checksum(checksum);
        Ok(Self(pkg))
    }
}

impl IcmpPkg for IcmpV6<'_> {
    fn set_ident(&mut self, ident: u16) {
        self.0.set_identifier(ident);
    }

    fn advance_seq(&mut self) {
        self.0.set_sequence_number(self.0.get_sequence_number() + 1);
    }

    fn seq(&self) -> u16 {
        self.0.get_sequence_number()
    }

    fn bytes(&mut self, pmtu: usize) -> &[u8] {
        const IP_HEADER_SIZE: usize = 40;
        let len = pmtu - IP_HEADER_SIZE;

        self.0.set_checksum(0);
        let checksum = {
            let pkg =
                icmp::IcmpPacket::new(&self.0.packet()[..len]).expect("Packet buffer too small");
            icmp::checksum(&pkg)
        };
        self.0.set_checksum(checksum);

        &self.0.packet()[..len]
    }

    fn read_from_ip(_: &[u8]) -> io::Result<IcmpResponse> {
        todo!()
    }
}

fn set_dont_frag_flag(sock: &impl AsRawFd, is_ipv6: bool) -> io::Result<()> {
    let (lvl, name) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IP_DONTFRAG)
    } else {
        (libc::IPPROTO_IP, libc::IP_DONTFRAG)
    };

    let val: c_int = 1;

    if unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            lvl,
            name,
            &val as *const _ as *const _,
            std::mem::size_of_val(&val) as _,
        )
    } == -1
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
