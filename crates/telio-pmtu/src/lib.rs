#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "linux.rs"]
mod platform;

use std::ops::Range;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

#[cfg(unix)]
pub use platform::PMTUSocket;

// We assume that 1000 is always supported.
//1500 is the Ethernet MTU so we're not expecting PMTU to be higher than that.
const PMTU_RANGE: Range<u32> = 1000..1501;

const ICMP_ECHO_REQ_IDENT: u16 = 0x6C74; // "lt" (libtelio) in hex

#[cfg(unix)]
fn create_icmp_socket(host: &std::net::IpAddr) -> std::io::Result<UdpSocket> {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        os::fd::{FromRawFd, IntoRawFd},
    };

    let (domain, proto, bind_addr) = match host {
        IpAddr::V4(_) => (
            Domain::IPV4,
            Protocol::ICMPV4,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ),
        IpAddr::V6(_) => (
            Domain::IPV6,
            Protocol::ICMPV6,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ),
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(proto))?;

    let bind_addr = SocketAddr::from((bind_addr, 0));
    sock.bind(&bind_addr.into())?;

    let sock = unsafe { std::net::UdpSocket::from_raw_fd(sock.into_raw_fd()) };
    sock.set_nonblocking(true)?;

    UdpSocket::from_std(sock)
}
