#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

#[cfg(unix)]
pub type NativeSocket = RawFd;

#[cfg(windows)]
pub type NativeSocket = RawSocket;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use std::io;

pub trait AsNativeSocket {
    fn as_native_socket(&self) -> NativeSocket;
}

#[cfg(unix)]
impl<T> AsNativeSocket for T
where
    T: AsRawFd,
{
    fn as_native_socket(&self) -> NativeSocket {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl<T> AsNativeSocket for T
where
    T: AsRawSocket,
{
    fn as_native_socket(&self) -> NativeSocket {
        self.as_raw_socket()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
pub fn interface_index_from_name(name: &str) -> io::Result<u64> {
    Ok(nix::net::if_::if_nametoindex(name)?.into())
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
pub fn interface_index_from_tun(tun_fd: RawFd) -> io::Result<u64> {
    use nix::{
        net::if_::if_nametoindex,
        sys::socket::{getsockopt, sockopt::UtunIfname},
    };
    use std::os::fd::BorrowedFd;

    let fd = unsafe { BorrowedFd::borrow_raw(tun_fd) };
    let name = getsockopt(&fd, UtunIfname)?;
    let index = if_nametoindex(name.as_c_str())?;
    Ok(index.into())
}
