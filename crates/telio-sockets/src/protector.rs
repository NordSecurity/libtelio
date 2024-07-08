use std::{io, panic::RefUnwindSafe, sync::Arc};

use crate::native::NativeSocket;

#[cfg(windows)]
#[path = "protector/windows.rs"]
pub mod platform;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "protector/apple.rs"]
pub mod platform;

#[cfg(target_os = "linux")]
#[path = "protector/linux.rs"]
pub mod platform;

#[cfg(target_os = "android")]
#[path = "protector/unsupported.rs"]
pub mod platform;

pub use platform::NativeProtector;

pub type Protect = Arc<dyn Fn(NativeSocket) + Send + Sync + RefUnwindSafe + 'static>;

pub trait Protector: Send + Sync {
    fn make_external(&self, socket: NativeSocket) -> io::Result<()>;

    fn make_internal(&self, socket: NativeSocket) -> io::Result<()>;

    fn clean(&self, socket: NativeSocket);

    fn set_fwmark(&self, fwmark: u32);

    fn set_tunnel_interface(&self, interface: u64);
}

impl<T: Protector + ?Sized> Protector for Arc<T> {
    fn make_external(&self, socket: NativeSocket) -> io::Result<()> {
        self.as_ref().make_external(socket)
    }

    fn make_internal(&self, socket: NativeSocket) -> io::Result<()> {
        self.as_ref().make_internal(socket)
    }

    fn clean(&self, socket: NativeSocket) {
        self.as_ref().clean(socket)
    }

    fn set_fwmark(&self, fwmark: u32) {
        self.as_ref().set_fwmark(fwmark);
    }

    fn set_tunnel_interface(&self, interface: u64) {
        self.as_ref().set_tunnel_interface(interface)
    }
}

pub fn make_external_protector(protect: Protect) -> Arc<(dyn Protector + 'static)> {
    struct ProtectorMakeExternalCb(Protect);
    impl Protector for ProtectorMakeExternalCb {
        fn make_external(&self, socket: NativeSocket) -> std::io::Result<()> {
            (self.0)(socket);
            Ok(())
        }

        fn make_internal(&self, _socket: NativeSocket) -> std::io::Result<()> {
            Ok(())
        }

        fn clean(&self, _socket: NativeSocket) {}

        fn set_fwmark(&self, _fwmark: u32) {}

        fn set_tunnel_interface(&self, _interface: u64) {}
    }
    Arc::new(ProtectorMakeExternalCb(protect))
}
