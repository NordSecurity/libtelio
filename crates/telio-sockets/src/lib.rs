pub mod socket_params;
mod socket_pool;

use std::{panic::RefUnwindSafe, sync::Arc};

pub use sock_prot::{AsNativeSocket, DummyProtector, NativeProtector, NativeSocket};
pub use socket_params::{SocketBufSizes, TcpParams, UdpParams};
pub use socket_pool::{External, SocketPool};

pub type Protect = Arc<dyn Fn(NativeSocket) + Send + Sync + RefUnwindSafe + 'static>;

pub trait Protector: sock_prot::Protector {
    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, _fwmark: u32) {}

    #[cfg(windows)]
    fn set_tunnel_interface(&self, _interface: u64) {}

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn set_tunnel_from_fd(&self, _tun: std::os::fd::RawFd) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn set_tunnel_from_name(&self, _name: &str) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Protector for NativeProtector {
    fn set_fwmark(&self, fwmark: u32) {
        self.set_fwmark(fwmark);
    }
}

#[cfg(target_os = "android")]
impl Protector for NativeProtector {}

#[cfg(windows)]
impl Protector for NativeProtector {
    fn set_tunnel_interface(&self, interface: u64) {
        unsafe { self.set_tunnel_interface(interface) }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
impl Protector for NativeProtector {
    fn set_tunnel_from_fd(&self, fd: std::os::fd::RawFd) -> std::io::Result<()> {
        unsafe { self.set_tunnel_from_fd(fd) }
    }

    fn set_tunnel_from_name(&self, name: &str) -> std::io::Result<()> {
        self.set_tunnel_from_name(name)
    }
}

impl Protector for DummyProtector {}

pub fn make_external_protector(protect: Protect) -> Arc<(dyn Protector + 'static)> {
    struct ProtectorMakeExternalCb(Protect);

    impl sock_prot::Protector for ProtectorMakeExternalCb {
        unsafe fn make_external(&self, sock: NativeSocket) -> std::io::Result<()> {
            (*self.0)(sock);
            Ok(())
        }
    }

    impl Protector for ProtectorMakeExternalCb {}
    Arc::new(ProtectorMakeExternalCb(protect))
}
