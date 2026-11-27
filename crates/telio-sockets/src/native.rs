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
    use nix::net::if_::if_nametoindex;

    let name = utun_name(tun_fd)?;
    let index = if_nametoindex(name.as_c_str())?;
    Ok(index.into())
}

/// Name of the utun interface behind `tun_fd`.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
pub fn utun_name(tun_fd: RawFd) -> io::Result<std::ffi::CString> {
    use std::ffi::CStr;

    // nix >= 0.31.4 and libc >= 0.2.190 provide these only on macOS, but the
    // utun ABI is the same on iOS and tvOS (<sys/sys_domain.h>, <net/if_utun.h>)
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const UTUN_OPT_IFNAME: libc::c_int = 2;

    let mut name = [0u8; libc::IFNAMSIZ];
    let mut len = name.len() as libc::socklen_t;
    // Safe: `name` and `len` describe a valid, writable buffer
    if unsafe {
        libc::getsockopt(
            tun_fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    CStr::from_bytes_until_nul(&name)
        .map(CStr::to_owned)
        .map_err(io::Error::other)
}
