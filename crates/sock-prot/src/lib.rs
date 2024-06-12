mod protector;
mod socket;

pub use protector::*;
pub use socket::*;

#[cfg(unix)]
pub type NativeSocket = std::os::unix::io::RawFd;
#[cfg(windows)]
pub type NativeSocket = std::os::windows::io::RawSocket;

pub trait AsNativeSocket {
    fn as_native_socket(&self) -> NativeSocket;
}

#[cfg(unix)]
impl<T> AsNativeSocket for T
where
    T: std::os::fd::AsRawFd,
{
    fn as_native_socket(&self) -> NativeSocket {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl<T> AsNativeSocket for T
where
    T: std::os::windows::io::AsRawSocket,
{
    fn as_native_socket(&self) -> NativeSocket {
        self.as_raw_socket()
    }
}
