//! Utils for binding socket's to tunnel interfaces

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
pub use darwin::set_should_bind;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
pub(crate) use darwin::{bind_to_tun, set_tun};

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
pub use any::set_should_bind;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
pub(crate) use any::{bind_to_tun, set_tun};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos", doc))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos")))
)]
mod darwin {
    use nix::net::if_::if_nametoindex;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    use nix::sys::socket::sockopt::UtunIfname;
    use nix::sys::socket::{getsockopt, setsockopt};
    use nix::{setsockopt_impl, sockopt_impl};
    use std::os::fd::AsFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::{io, sync::Mutex};
    use telio_utils::{telio_log_debug, telio_log_trace, telio_log_warn};

    static SHOULD_BIND: AtomicBool = AtomicBool::new(false);

    sockopt_impl!(
        BindDeviceByIndex,
        SetOnly,
        libc::IPPROTO_IP,
        libc::IP_BOUND_IF,
        u32
    );

    static TUN_INDEX: Mutex<Option<u32>> = Mutex::new(None);

    pub(crate) fn set_tun(tun: Option<impl AsFd>) -> io::Result<()> {
        // For darwin bind socket to tun interface.
        if let Some(tun_fd) = tun {
            let name = getsockopt(&tun_fd, UtunIfname)?;
            let index = if_nametoindex(name.as_c_str())?;
            if index == 0 {
                return Err(io::Error::last_os_error());
            }

            let mut tun = TUN_INDEX
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "TUN_INDEX lock failed"))?;
            *tun = Some(index);
        } else {
            telio_log_warn!("Tunnel file descriptor was not provided.");
        }

        Ok(())
    }

    pub(crate) fn bind_to_tun<T: AsFd>(sock: &T) -> io::Result<()> {
        if !SHOULD_BIND.load(Ordering::Relaxed) {
            telio_log_trace!("skipped binding dns socket due to should_bind = false");
            return Ok(());
        }

        let tun = TUN_INDEX
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "TUN_INDEX lock failed"))?;
        if let Some(index) = tun.as_ref() {
            setsockopt(sock, BindDeviceByIndex, index)?;
        } else {
            telio_log_warn!("Bind attempted on non existing tunnel interface.");
        }

        Ok(())
    }

    /// Controls if sockets should be bound to the tun interface.
    pub fn set_should_bind(should_bind: bool) {
        telio_log_debug!("setting should_bind to {}", should_bind);
        SHOULD_BIND.store(should_bind, Ordering::Relaxed);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
#[cfg_attr(
    docsrs,
    doc(cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos"))))
)]
mod any {
    use std::io;

    use telio_utils::telio_log_trace;

    #[inline]
    pub(crate) fn set_tun<T>(_: T) -> io::Result<()> {
        telio_log_trace!("set_tun SUCESSFULL");
        Ok(())
    }

    #[inline]
    pub(crate) fn bind_to_tun<T>(_: T) -> io::Result<()> {
        telio_log_trace!("bind_to_tun SUCESSFULL");
        Ok(())
    }

    /// Controls if sockets should be bound to the tun interface.
    #[inline]
    pub fn set_should_bind(_: bool) {
        telio_log_trace!("set_should_bind SUCESSFULL");
    }
}
