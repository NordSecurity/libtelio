use std::{io::Result, os};

use crate::native::NativeSocket;
use nix::sys::socket::{getsockname, AddressFamily, SockaddrLike, SockaddrStorage};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};

pub(crate) fn bind_to_tun(sock: NativeSocket, tunnel_interface: u64) -> Result<()> {
    telio_log_debug!(
        "Binding socket {} to tunnel interface: {}",
        sock,
        tunnel_interface
    );
    let res = bind(tunnel_interface as u32, sock);
    if let Err(e) = &res {
        telio_log_error!(
            "failed to bind socket {} to tunnel interface: {}: {}",
            sock,
            tunnel_interface,
            e
        );
    }

    res
}

pub(crate) fn bind(interface_index: u32, socket: i32) -> Result<()> {
    if let Some(sock_addr) = getsockname::<SockaddrStorage>(socket)?.family() {
        let (option, level) = match sock_addr {
            AddressFamily::Inet6 => (libc::IPV6_BOUND_IF, libc::IPPROTO_IPV6),
            AddressFamily::Inet => (libc::IP_BOUND_IF, libc::IPPROTO_IP),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid IP family type",
                ))
            }
        };

        const ARRAY_LEN: libc::size_t = std::mem::size_of::<u32>();
        let array: [i8; ARRAY_LEN] = unsafe { std::mem::transmute(interface_index) };
        unsafe {
            if libc::setsockopt(
                socket,
                level,
                option,
                array.as_ptr() as *const os::raw::c_void,
                std::mem::size_of_val(&array) as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    } else {
        telio_log_warn!("Failed to find sock addr for socket : {}", socket);
    }
    Ok(())
}
