//! Provides cross-platform abstractions for managing socket-level protection
//!
//! Operations like binding to an external or internal interface, applying firewall marks,
//! watching for default interface and route changes, etc.
//!
//! Some methods are no_op on specific platforms:
//! - [`Protector::set_fwmark`] on macOS and Windows since they don't have iptables.
//! - [`Protector::set_tunnel_interface`] on Linux since firewall marks are used to route packets.
//! - [`Protector::make_internal`] on Linux and Windows since the sockets by default are bound to the tunnel interface.

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

/// Re-export the implementation for the current platform.
pub use platform::NativeProtector;

/// Alias for a closure that accepts a native socket.
///
/// Used as a callback in the [`make_external_protector`] function.
pub type Protect = Arc<dyn Fn(NativeSocket) + Send + Sync + RefUnwindSafe + 'static>;

/// A trait describing common operations on a socket.
///
/// Used to manage binding, automatic re-binding and routing rules on various platforms.
/// Some of the methods are no-op on specific platforms.
#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
pub trait Protector: Send + Sync {
    /// Configure the provided socket to send packets externally (outside of the tunnel).
    fn make_external(&self, socket: NativeSocket) -> io::Result<()>;

    /// Configure the provided socket to send packets internally (inside of the tunnel).
    fn make_internal(&self, socket: NativeSocket) -> io::Result<()>;

    /// Clean up any references associated with the given socket.
    fn clean(&self, socket: NativeSocket);

    /// Update the firewall mark for this socket used in iptables and routing rules.
    fn set_fwmark(&self, fwmark: u32);

    /// Update the tunnel interface identifier to be applied when making the socket internal.
    fn set_tunnel_interface(&self, interface: u64);

    /// [Windows only] Update the list of interfaces to exclude, when making external calls.
    fn set_ext_if_filter(&self, list: &[String]);
}

/// A blanket implementation of `Arc<Protector>`.
///
/// Used to call [`Protector`] methods directly without having to dereference.
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

    fn set_ext_if_filter(&self, list: &[String]) {
        self.as_ref().set_ext_if_filter(list)
    }
}

/// Construct a [`Protector`] instance that applies a closure.
///
/// The closure is called only during [`Protector::make_external`], all other methods are no-op.
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

        fn set_ext_if_filter(&self, _list: &[String]) {}
    }
    Arc::new(ProtectorMakeExternalCb(protect))
}
