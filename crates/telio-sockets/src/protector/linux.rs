use std::{io, os::fd::BorrowedFd, sync::Mutex};

use nix::sys::socket::{setsockopt, sockopt::Mark};

use crate::native::NativeSocket;

use super::Protector;

pub struct NativeProtector {
    fwmark: Mutex<u32>,
}

impl NativeProtector {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            fwmark: Mutex::new(0),
        })
    }

    pub fn set_fwmark(&self, fwmark: u32) {
        if let Ok(mut my_fwmark) = self.fwmark.lock() {
            *my_fwmark = fwmark;
        }
    }
}

impl Protector for NativeProtector {
    fn make_external(&self, socket: NativeSocket) -> io::Result<()> {
        if let Ok(fwmark) = self.fwmark.lock() {
            if *fwmark != 0 {
                set_fwmark(socket, *fwmark)?;
            }
        }
        Ok(())
    }

    /// This is a no-op on linux.
    fn make_internal(&self, _socket: NativeSocket) -> io::Result<()> {
        Ok(())
    }

    fn clean(&self, _socket: NativeSocket) {
        // Skip, socket will be removed
    }

    fn set_fwmark(&self, fwmark: u32) {
        if let Ok(mut my_fwmark) = self.fwmark.lock() {
            *my_fwmark = fwmark;
        }
    }

    /// This is a no-op on linux.
    fn set_tunnel_interface(&self, _interface: u64) {}

    /// This is a no-op on linux.
    fn set_ext_if_filter(&self, _list: &[String]) {}
}

fn set_fwmark(fd: i32, fwmark: u32) -> io::Result<()> {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    setsockopt(&fd, Mark, &fwmark)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket},
    };

    use crate::native::AsNativeSocket;

    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[case(IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    #[case(IpAddr::V6(Ipv6Addr::LOCALHOST))]
    #[case(IpAddr::V6(Ipv6Addr::UNSPECIFIED))]
    #[ignore = "Requires running as root (setting SO_MARK requires CAP_NET_ADMIN)"]
    fn test_make_external_requires_root(#[case] ip_addr: IpAddr) {
        assert!(nix::unistd::geteuid().is_root());

        let protector = NativeProtector::new().unwrap();
        protector.set_fwmark(telio_utils::LIBTELIO_FWMARK);
        let addr = SocketAddr::new(ip_addr, 0);

        let socket = match UdpSocket::bind(addr) {
            Ok(socket) => socket,
            Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                // host has no interface with ipv4/ipv6
                return;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        };

        assert!(protector.make_external(socket.as_native_socket()).is_ok());

        let socket = match TcpListener::bind(addr) {
            Ok(socket) => socket,
            Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                // host has no interface with ipv4/ipv6
                return;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        };
        assert!(protector.make_external(socket.as_native_socket()).is_ok());
    }
}
