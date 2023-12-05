use std::{io, sync::Mutex};

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

    fn clean(&self, _socket: NativeSocket) {
        // Skip, socket will be removed
    }

    fn set_fwmark(&self, fwmark: u32) {
        if let Ok(mut my_fwmark) = self.fwmark.lock() {
            *my_fwmark = fwmark;
        }
    }
}

fn set_fwmark(fd: i32, fwmark: u32) -> io::Result<()> {
    let fwmark_ptr = &fwmark as *const u32 as *const libc::c_void;

    let res = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, fwmark_ptr, 4_u32) };
    match res {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
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

    #[cfg(not(tarpaulin))]
    #[rstest]
    #[case(IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[case(IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    #[case(IpAddr::V6(Ipv6Addr::LOCALHOST))]
    #[case(IpAddr::V6(Ipv6Addr::UNSPECIFIED))]
    fn test_make_external(#[case] ip_addr: IpAddr) {
        let protector = NativeProtector::new().unwrap();
        protector.set_fwmark(11673110);
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
