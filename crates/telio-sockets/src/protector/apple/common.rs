use std::{io::Result, os};

use crate::native::NativeSocket;
use telio_utils::{telio_log_debug, telio_log_error};

pub(crate) fn bind_to_tun(sock: NativeSocket, tunnel_interface: u64) -> Result<()> {
    telio_log_debug!(
        "Binding socket {} to tunnel interface: {}",
        sock,
        tunnel_interface
    );
    let res = bind(tunnel_interface as u32, sock, libc::AF_INET);
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

pub(crate) fn bind(interface_index: u32, socket: i32, family: i32) -> Result<()> {
    let option = if family == libc::AF_INET6 {
        libc::IPV6_BOUND_IF
    } else {
        libc::IP_BOUND_IF
    };
    let level = if family == libc::AF_INET6 {
        libc::IPPROTO_IPV6
    } else {
        libc::IPPROTO_IP
    };
    let array: [i8; 4] = unsafe { std::mem::transmute(interface_index) };
    unsafe {
        if libc::setsockopt(
            socket,
            level,
            option,
            array.as_ptr() as *const os::raw::c_void,
            4,
        ) != 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
