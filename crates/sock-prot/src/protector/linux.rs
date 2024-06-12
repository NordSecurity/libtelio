use std::{
    io,
    os::fd::RawFd,
    sync::atomic::{AtomicU32, Ordering},
};

use super::Protector;

pub struct NativeProtector {
    fwmark: AtomicU32,
}

impl NativeProtector {
    // Return `Result` to align with all other protector implementations
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            fwmark: AtomicU32::new(0),
        })
    }

    pub fn with_fwmark(fwmark: u32) -> Self {
        Self {
            fwmark: AtomicU32::new(fwmark),
        }
    }

    pub fn set_fwmark(&self, fwmark: u32) {
        self.fwmark.store(fwmark, Ordering::SeqCst);
    }
}

impl Protector for NativeProtector {
    unsafe fn make_external(&self, socket: RawFd) -> io::Result<()> {
        let fwmark = self.fwmark.load(Ordering::SeqCst);

        if fwmark != 0 {
            set_fwmark(socket, fwmark)?;
        }
        Ok(())
    }
}

unsafe fn set_fwmark(fd: i32, fwmark: u32) -> io::Result<()> {
    let fwmark_ptr = &fwmark as *const u32 as *const libc::c_void;

    let res = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, fwmark_ptr, 4_u32);
    match res {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::{
        io::ErrorKind,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket},
    };

    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[case(IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    #[case(IpAddr::V6(Ipv6Addr::LOCALHOST))]
    #[case(IpAddr::V6(Ipv6Addr::UNSPECIFIED))]
    fn test_make_external(#[case] ip_addr: IpAddr) {
        let protector = NativeProtector::with_fwmark(11673110);

        let socket = match UdpSocket::bind((ip_addr, 0)) {
            Ok(socket) => socket,
            Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                // host has no interface with ipv4/ipv6
                return;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        };

        unsafe { protector.make_external(socket.as_raw_fd()).unwrap() };

        let socket = match TcpListener::bind((ip_addr, 0)) {
            Ok(socket) => socket,
            Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                // host has no interface with ipv4/ipv6
                return;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        };
        unsafe { protector.make_external(socket.as_raw_fd()).unwrap() };
    }
}
