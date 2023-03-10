//! Utils for binding socket's to tunnel interfaces

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use darwin::set_should_bind;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use darwin::{bind_to_tun, set_tun};

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub use any::set_should_bind;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(crate) use any::{bind_to_tun, set_tun};

#[cfg(any(target_os = "macos", target_os = "ios", doc))]
#[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "ios"))))]
mod darwin {
    use lazy_static::lazy_static;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::{io, os::unix::prelude::AsRawFd, sync::Mutex};
    use telio_utils::{telio_log_debug, telio_log_trace, telio_log_warn};

    static SHOULD_BIND: AtomicBool = AtomicBool::new(false);

    lazy_static! {
        // TODO: since 1.63.0 Mutex::new is const and with that we can get rid
        // of lazy_static here.
        static ref TUN_INDEX: Mutex<Option<i32>> = Mutex::new(None);
    }

    pub(crate) fn set_tun(tun: Option<i32>) -> io::Result<()> {
        // For darwin bind socket to tun interface.
        if let Some(tun_fd) = tun {
            let mut name = [0 as libc::c_char; libc::IFNAMSIZ + 1];
            let mut len = libc::IFNAMSIZ as libc::socklen_t;
            let index = unsafe {
                if libc::getsockopt(
                    tun_fd,
                    2, /* SYSPROTO_CONTROL */
                    2, /* UTUN_OPT_IFNAME */
                    &mut name as *mut libc::c_char as *mut libc::c_void,
                    &mut len as *mut libc::socklen_t,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }

                libc::if_nametoindex(name.as_ptr()) as i32
            };
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

    pub(crate) fn bind_to_tun<T: AsRawFd>(sock: &T) -> io::Result<()> {
        if !SHOULD_BIND.load(Ordering::Relaxed) {
            telio_log_trace!("skipped binding dns socket due to should_bind = false");
            return Ok(());
        }

        let tun = TUN_INDEX
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "TUN_INDEX lock failed"))?;
        if let Some(index) = tun.as_ref() {
            let idx = index as *const i32 as *const libc::c_void;
            unsafe {
                if libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_BOUND_IF,
                    idx,
                    std::mem::size_of_val(index) as u32,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                };
            }
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

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[cfg_attr(docsrs, doc(cfg(not(any(target_os = "macos", target_os = "ios")))))]
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
