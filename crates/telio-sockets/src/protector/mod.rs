use std::{io, panic::RefUnwindSafe, sync::Arc};

use crate::native::NativeSocket;

#[cfg(windows)]
#[path = "windows.rs"]
pub mod platform;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "apple.rs"]
pub mod platform;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
pub mod platform;

#[cfg(target_os = "android")]
#[path = "unsupported.rs"]
pub mod platform;

pub use platform::NativeProtector;

pub type Protect = Arc<dyn Fn(NativeSocket) + Send + Sync + RefUnwindSafe + 'static>;

pub trait Protector: Send + Sync {
    fn make_external(&self, socket: NativeSocket) -> io::Result<()>;

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn make_internal(&self, socket: NativeSocket) -> io::Result<()>;

    fn clean(&self, socket: NativeSocket);

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, fwmark: u32);

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos", windows))]
    fn set_tunnel_interface(&self, interface: u64);
}

impl Protector for Protect {
    fn make_external(&self, socket: NativeSocket) -> io::Result<()> {
        (self)(socket);
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn make_internal(&self, _socket: NativeSocket) -> io::Result<()> {
        Ok(())
    }

    fn clean(&self, _socket: NativeSocket) {}

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, _fwmark: u32) {}

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos", windows))]
    fn set_tunnel_interface(&self, _: u64) {}
}
