//! This module implements PMTU probing for Linux.
//!
//! It does it in the following way:
//! * The kernel has an estimate of the PMTU, we read it to get a guess of our starting value
//! * We perform the binary search of PMTUs within the `super::PMTU_RANGE` interval
//! * we check the specific PMTU value by sending an ICMP Echo Request of a length equal to PMTU and await the response
//! * there are the following possibilities:
//!   - the response arrives out of order,
//!   - the response is randomly dropped,
//!   - the response is dropped because the true PMTU is lower than our guess,
//!   - or the error message `Fragmentation needed` arrives with or without `Next hop MTU`,
//!   - the proper response arrives indicating that our guess is lower or equal to the true PMTU
//!
//! There are some caveats though, documented in the relevant places in the code:
//! * the kernel does some things in an unpredicted way, for example `send()` and `recv()` calls spuriously report errors when sending packets larger than the kernel's PMTU guess
//! * the kernel can keep multiple error message

#[cfg(target_env = "musl")]
use std::mem::MaybeUninit;
use std::{ffi::c_int, io, net::IpAddr, os::fd::AsRawFd, time::Duration};

use pnet_packet::{icmp, icmpv6, Packet};
use telio_utils::{telio_log_debug, telio_log_warn};
use tokio::net::UdpSocket;

pub struct PMTUSocket {
    sock: UdpSocket,
    host: IpAddr,
    response_timeout: Duration,
}

const RETRIES: u32 = 3;

impl PMTUSocket {
    pub fn new(host: IpAddr, response_timeout: Duration) -> io::Result<Self> {
        let sock = crate::create_icmp_socket(&host)?;
        set_pmtu_on(&sock, host.is_ipv6())?;
        Ok(Self {
            sock,
            host,
            response_timeout,
        })
    }

    pub async fn probe_pmtu(&self) -> io::Result<u32> {
        telio_log_debug!("Connecting to: {}", self.host);
        self.sock.connect((self.host, 0)).await?;

        telio_log_debug!("Connected to: {}", self.host);

        // Read the kernel's PMTU guess
        let mut initial_guess = read_pmtu(&self.sock, self.host.is_ipv6()).unwrap_or_else(|err| {
            telio_log_warn!("Failed to fetch initial kernel PMTU estimate: {err:?}");
            (super::PMTU_RANGE.start + super::PMTU_RANGE.end) / 2
        });

        if !super::PMTU_RANGE.contains(&initial_guess) {
            // PMTU is not contained within our reasonable range,
            // let's probe from the top of the range
            initial_guess = super::PMTU_RANGE.end - 1;
        }

        telio_log_debug!("Initial PMTU estimate: {initial_guess}");

        let mut msgbuf = vec![0xFF; super::PMTU_RANGE.end as usize];

        if self.host.is_ipv6() {
            let mut pkg = IcmpV6::new(&mut msgbuf)?;
            self.probe_pmtu_internal(&mut pkg, initial_guess).await
        } else {
            let mut pkg = IcmpV4::new(&mut msgbuf)?;
            self.probe_pmtu_internal(&mut pkg, initial_guess).await
        }
    }

    async fn probe_pmtu_internal(&self, pkg: &mut impl IcmpPkg, mut pmtu: u32) -> io::Result<u32> {
        pkg.set_ident(super::echo_req_ident());

        // Estimate of the number of iterations +1 (ilog2() is rounded down) + some room for the kernel to mess around
        const MAX_TURNS: u32 = (super::PMTU_RANGE.end - super::PMTU_RANGE.start).ilog2() + 1 + 5;

        let mut pmtu_range = super::PMTU_RANGE;

        for _ in 0..MAX_TURNS {
            let check = self.is_pmtu_ok(pkg, pmtu).await?;
            telio_log_debug!("PMTU {pmtu} result: {check:?}");

            pmtu = match check {
                PmtuResult::Ok => {
                    // the value we checked is less or equal to the true PMTU, let's narrow search space
                    pmtu_range.start = pmtu;
                    (pmtu_range.start + pmtu_range.end) / 2
                }
                PmtuResult::Dropped => {
                    // the value we checked is largen than the true PMTU, let's narrow search space
                    pmtu_range.end = pmtu;
                    (pmtu_range.start + pmtu_range.end) / 2
                }
                PmtuResult::FragNeeded => {
                    // Read the kernel error queue, since the kernel has the knowledge of error ICMP packet.
                    // This can help estimate the true PMTU better than using binary search.
                    // The `mtu` here is equal to the `Frag Needed` error response `Next hop MTU`
                    // and might be equal 0 in case the router does not support `Next hop MTU`.
                    let mtu = read_error_pmtu(&self.sock, self.host.is_ipv6())?;
                    telio_log_debug!("Frag needed next hop MTU: {mtu}");

                    // Sometimes kernel return error for packet of size equal to MTU.
                    // The value may be 0 in case `Frag Needed` does not contain `Next hop MTU`.
                    // We should exclude this values since they are meaningless.
                    if mtu != pmtu && mtu != 0 {
                        // The error was valid, let's narrow the search space
                        pmtu_range.end = pmtu;
                    }

                    if mtu < pmtu_range.start {
                        // Don't trust low values of nexthop MTU and use binary search
                        (pmtu_range.start + pmtu_range.end) / 2
                    } else if pmtu == mtu {
                        // Kernel thinks the PMTU is equal to our packet but returned error.
                        // We cannot trust this value because it is contradiction: if the packet length is equal to PMTU
                        //  it should arrive to the destination without errors.
                        // Try to send packet just above the PMTU limit to see if we can narrow the search space anyway.
                        // This trick prevents us from looping infinitely with the same value.
                        mtu + 1
                    } else if pmtu == mtu + 1 {
                        // We are one iteration after the step above. Continue the binary search.
                        (pmtu_range.start + pmtu_range.end) / 2
                    } else {
                        // All edge cases exhausted. Let's use the estimate for the next probe
                        mtu
                    }
                }
            };

            if pmtu_range.start + 1 >= pmtu_range.end {
                // The search space is narrowed to a single value. It means we've finished
                let found = pmtu_range.start;

                return if found == super::PMTU_RANGE.start {
                    // Found value is suspiciously low. Don't trust it
                    Err(io::ErrorKind::NotConnected.into())
                } else {
                    Ok(found)
                };
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to finish PMTU detection",
        ))
    }

    /// Sends ICMP Echo Request and tries to decide what happend.
    /// Possible outcomes are:
    /// * ICMP was dropped because it is larger than PMTU
    /// * Frag Needed was reported
    /// * the `pmtu` value is below the true PMTU and the response was received
    async fn is_pmtu_ok<I: IcmpPkg>(&self, pkg: &mut I, pmtu: u32) -> io::Result<PmtuResult> {
        // Try sending the request multiple times because it can be dropped randomly
        for count in 0..RETRIES {
            // Use unique sequence number
            pkg.advance_seq();
            let seq = pkg.seq();

            telio_log_debug!(
                "Sending ICMP Echo Request, dst: {} seq: {seq}, size: {pmtu}",
                self.host
            );

            if let Err(err) = self.sock.send(pkg.bytes(pmtu)).await {
                // The kernel might retun this error when the packet size == kernel's estimate of PMTU.
                // But the packet is sent anyway it seems.
                if err.raw_os_error() != Some(libc::EMSGSIZE) {
                    return Err(err);
                }
            }

            match tokio::time::timeout(self.response_timeout, self.recv::<I>(seq)).await {
                Ok(res) => return res,
                Err(_timeout) => {
                    // packet was most probably dropped
                    telio_log_debug!("ICMP recv() timeout, pmtu: {pmtu}, counter: {count}");
                }
            }
        }

        Ok(PmtuResult::Dropped)
    }

    /// Try receive response for the ICMP Echo Request with the specified sequence `seq`
    async fn recv<I: IcmpPkg>(&self, seq: u16) -> io::Result<PmtuResult> {
        let mut recvbuf = [0u8; 1024];

        loop {
            match self.sock.recv(&mut recvbuf).await {
                Err(err) => {
                    // The kernel might retun this error when the packet size == kernel's estimate of PMTU.
                    if err.raw_os_error() == Some(libc::EMSGSIZE) {
                        return Ok(PmtuResult::FragNeeded);
                    } else {
                        return Err(err);
                    }
                }
                Ok(size) => {
                    #[allow(index_access_check)]
                    match I::extract_seq(&recvbuf[..size]) {
                        Ok(rseq) => {
                            // Check the response `seq` number. We might get responses for older packets
                            if rseq == seq {
                                // Success, this PMTU works
                                return Ok(PmtuResult::Ok);
                            } else {
                                telio_log_debug!("Seq number mismatch");
                                // It's not the message we're looking for, let's continue
                            }
                        }
                        Err(err) => {
                            telio_log_debug!("Invalid ICMP message recv: {err:?}");
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum PmtuResult {
    Ok,
    Dropped,
    FragNeeded,
}

impl AsRawFd for PMTUSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.sock.as_raw_fd()
    }
}

/// This trait allows sharing code between IPv4 and IPv6 PMTU probing procedures
trait IcmpPkg: Sized {
    fn set_ident(&mut self, ident: u16);
    fn advance_seq(&mut self);
    fn seq(&self) -> u16;
    fn bytes(&self, pmtu: u32) -> &[u8];
    fn extract_seq(pkg: &[u8]) -> io::Result<u16>;
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

    fn extract_seq(pkg: &[u8]) -> io::Result<u16> {
        let pkg = icmp::echo_request::EchoRequestPacket::new(pkg).ok_or(io::Error::new(
            io::ErrorKind::Other,
            "Too small packet buffer received",
        ))?;

        Ok(pkg.get_sequence_number())
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

    fn extract_seq(pkg: &[u8]) -> io::Result<u16> {
        let pkg = icmpv6::echo_request::EchoRequestPacket::new(pkg).ok_or(io::Error::new(
            io::ErrorKind::Other,
            "Too small packet buffer received",
        ))?;

        Ok(pkg.get_sequence_number())
    }
}

/// Enable PMTU discovery for the socket. It's needed so that the kernel does
/// not fragment packets automatically
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
        return Err(io::Error::last_os_error());
    }

    let (lvl, name) = if is_ipv6 {
        (libc::SOL_IPV6, libc::IPV6_RECVERR)
    } else {
        (libc::SOL_IP, libc::IP_RECVERR)
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
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Read kernel's PMTU estimate
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
            Err(io::Error::last_os_error())
        } else {
            Ok(mtu as _)
        }
    }
}

/// Returns `Next hop MTU` value from last `Frag Needed` error response.
/// It does it by reading the kernel's error queue.
fn read_error_pmtu(sock: &impl AsRawFd, is_ipv6: bool) -> io::Result<u32> {
    let cmsg_lvl = if is_ipv6 {
        libc::SOL_IPV6
    } else {
        libc::SOL_IP
    };

    unsafe {
        let mut iovecbuf = [0u8; 8];

        let mut iovec = libc::iovec {
            iov_base: iovecbuf.as_mut_ptr().cast(),
            iov_len: iovecbuf.len() as _,
        };

        let mut controlbuf = [0u8; 128];

        #[cfg(not(target_env = "musl"))]
        let mut msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
            msg_control: controlbuf.as_mut_ptr().cast(),
            msg_controllen: controlbuf.len() as _,
            msg_flags: 0,
        };
        #[cfg(target_env = "musl")]
        let mut msghdr = MaybeUninit::<libc::msghdr>::zeroed().assume_init();
        #[cfg(target_env = "musl")]
        {
            msghdr.msg_name = std::ptr::null_mut();
            msghdr.msg_iov = &mut iovec;
            msghdr.msg_iovlen = 1;
            msghdr.msg_control = controlbuf.as_mut_ptr().cast();
            msghdr.msg_controllen = controlbuf.len() as _;
        }

        let mut last_value = None;

        loop {
            if libc::recvmsg(
                sock.as_raw_fd(),
                &mut msghdr,
                libc::MSG_DONTWAIT | libc::MSG_ERRQUEUE,
            ) == -1
            {
                let err = io::Error::last_os_error();

                match (err.kind(), last_value) {
                    // Error queue is exhausted. No more data to read
                    (io::ErrorKind::WouldBlock, Some(pmtu)) => return Ok(pmtu),
                    _ => return Err(err),
                }
            } else {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msghdr);

                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == cmsg_lvl && (*cmsg).cmsg_type == libc::IP_RECVERR {
                        let err = *(libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err);

                        telio_log_debug!(
                            "Extended sock error:\n  ee_errno   = {}\n  ee_origin  = {}\n  ee_type  = {}\n  ee_code  = {}\n  ee_pad   = {}\n  ee_info  = {}\n  ee_data  = {}",
                            err.ee_errno,
                            err.ee_origin,
                            err.ee_type,
                            err.ee_code,
                            err.ee_pad,
                            err.ee_info,
                            err.ee_data,
                        );

                        if err.ee_errno == libc::EMSGSIZE as u32 {
                            last_value = Some(err.ee_info);
                        }
                    }

                    cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
                }
            }
        }
    }
}
