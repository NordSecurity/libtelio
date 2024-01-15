use std::{ffi::c_int, io, net::IpAddr, os::fd::AsRawFd, time::Duration};

use pnet_packet::{icmp, icmpv6, Packet};
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
        set_pmtu_on(&sock, host.is_ipv6())?;
        Ok(Self { sock, host })
    }
    pub async fn probe_pmtu(&self) -> io::Result<u32> {
        self.sock.connect((self.host, 0)).await?;
        let mut pmtu = read_pmtu(&self.sock, self.host.is_ipv6())?;

        if !super::PMTU_RANGE.contains(&pmtu) {
            // PMTU is not contained within our reasonable range,
            // let's probe from the top of the range
            pmtu = super::PMTU_RANGE.end - 1;
        }

        telio_log_debug!("Initial PMTU estimate: {pmtu}");

        let mut msgbuf = vec![0xFF; super::PMTU_RANGE.end as usize];

        if self.host.is_ipv6() {
            let mut pkg = IcmpV6::new(&mut msgbuf)?;
            self.probe_pmtu_internal(&mut pkg, pmtu).await
        } else {
            let mut pkg = IcmpV4::new(&mut msgbuf)?;
            self.probe_pmtu_internal(&mut pkg, pmtu).await
        }
    }

    async fn probe_pmtu_internal(&self, pkg: &mut impl IcmpPkg, mut pmtu: u32) -> io::Result<u32> {
        pkg.set_ident(super::ICMP_ECHO_REQ_IDENT);

        let mut pmtu_range = super::PMTU_RANGE;

        loop {
            if self.is_pmtu_ok(pkg, pmtu).await? {
                telio_log_debug!("PMTU {pmtu} is good");
                pmtu_range.start = pmtu;
            } else {
                telio_log_debug!("PMTU {pmtu} is too big");
                pmtu_range.end = pmtu;
            }

            if pmtu_range.start + 1 >= pmtu_range.end {
                break;
            }

            pmtu = (pmtu_range.start + pmtu_range.end) / 2;
            let kpmtu = read_pmtu(&self.sock, self.host.is_ipv6())?;
            telio_log_debug!("Kernel PMTU estimate: {kpmtu}");
            if pmtu < kpmtu && kpmtu < pmtu_range.end {
                pmtu = kpmtu;
            }
        }

        let found = pmtu_range.start;

        if found == super::PMTU_RANGE.start {
            Err(io::ErrorKind::NotConnected.into())
        } else {
            Ok(found)
        }
    }

    async fn is_pmtu_ok(&self, pkg: &mut impl IcmpPkg, pmtu: u32) -> io::Result<bool> {
        let mut recvbuf = [0u8; 1024];

        for count in 0..RETRIES {
            pkg.advance_seq();
            let seq = pkg.seq();

            telio_log_debug!(
                "Sending ICMP Echo Request, dst: {} seq: {seq}, size: {pmtu}",
                self.host
            );

            if let Err(err) = self.sock.send(pkg.bytes(pmtu)).await {
                // The kernel might retun this error when the packet size == kernel's estimate of PMTU.
                // But the packet is sent anyway
                if err.raw_os_error() != Some(libc::EMSGSIZE) {
                    return Err(err);
                }
            }

            match tokio::time::timeout(TIMEOUT, self.sock.recv(&mut recvbuf)).await {
                Ok(res) => {
                    if let Err(err) = res {
                        // The kernel might retun this error when the packet size == kernel's estimate of PMTU.
                        if err.raw_os_error() != Some(libc::EMSGSIZE) {
                            return Err(err);
                        }
                    } else {
                        // Success, this PMTU works
                        return Ok(true);
                    }
                }
                Err(_timeout) => {
                    // packet was most probably dropped
                    telio_log_debug!("ICMP recv() timeout, pmtu: {pmtu}, counter: {count}");
                }
            }
        }

        Ok(false)
    }
}

impl AsRawFd for PMTUSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.sock.as_raw_fd()
    }
}

trait IcmpPkg: Sized {
    fn set_ident(&mut self, ident: u16);
    fn advance_seq(&mut self);
    fn seq(&self) -> u16;
    fn bytes(&self, pmtu: u32) -> &[u8];
}

struct IcmpV4<'a>(icmp::echo_request::MutableEchoRequestPacket<'a>);

impl<'a> IcmpV4<'a> {
    fn new(buf: &'a mut [u8]) -> io::Result<Self> {
        let mut pkg = icmp::echo_request::MutableEchoRequestPacket::new(buf).ok_or(
            io::Error::new(io::ErrorKind::Other, "Too small initial PMTU guess"),
        )?;

        pkg.set_icmp_type(icmp::IcmpTypes::EchoRequest);
        pkg.set_icmp_code(icmp::echo_request::IcmpCodes::NoCode);
        pkg.set_sequence_number(0);
        Ok(Self(pkg))
    }
}

impl IcmpPkg for IcmpV4<'_> {
    fn set_ident(&mut self, ident: u16) {
        self.0.set_identifier(ident);
    }

    fn advance_seq(&mut self) {
        self.0.set_sequence_number(self.0.get_sequence_number() + 1);
    }

    fn seq(&self) -> u16 {
        self.0.get_sequence_number()
    }

    fn bytes(&self, pmtu: u32) -> &[u8] {
        const IP_HEADER_SIZE: usize = 20;
        #[allow(index_access_check)]
        &self.0.packet()[..(pmtu as usize - IP_HEADER_SIZE)]
    }
}

struct IcmpV6<'a>(icmpv6::echo_request::MutableEchoRequestPacket<'a>);

impl<'a> IcmpV6<'a> {
    fn new(buf: &'a mut [u8]) -> io::Result<Self> {
        let mut pkg = icmpv6::echo_request::MutableEchoRequestPacket::new(buf).ok_or(
            io::Error::new(io::ErrorKind::Other, "Too small initial PMTU guess"),
        )?;

        pkg.set_icmpv6_type(icmpv6::Icmpv6Types::EchoRequest);
        pkg.set_icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode);
        pkg.set_sequence_number(0);
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

    fn bytes(&self, pmtu: u32) -> &[u8] {
        const IP_HEADER_SIZE: usize = 40;
        #[allow(index_access_check)]
        &self.0.packet()[..(pmtu as usize - IP_HEADER_SIZE)]
    }
}

fn set_pmtu_on(sock: &impl AsRawFd, is_ipv6: bool) -> io::Result<()> {
    let (lvl, name, val) = if is_ipv6 {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_PROBE,
        )
    } else {
        (
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        )
    };

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

fn read_pmtu(sock: &impl AsRawFd, is_ipv6: bool) -> io::Result<u32> {
    let mut mtu: c_int = 0;
    let mut size: libc::socklen_t = std::mem::size_of_val(&mtu) as _;

    let (lvl, name) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU)
    };

    unsafe {
        if libc::getsockopt(
            sock.as_raw_fd(),
            lvl,
            name,
            &mut mtu as *mut _ as *mut _,
            &mut size as *mut _,
        ) == -1
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(mtu as _)
        }
    }
}
