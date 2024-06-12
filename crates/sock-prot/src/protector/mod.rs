#[cfg(windows)]
#[path = "windows.rs"]
mod platform;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "apple.rs"]
mod platform;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;

#[cfg(target_os = "android")]
#[path = "unsupported.rs"]
mod platform;

use std::io;

pub use platform::NativeProtector;

use crate::NativeSocket;

pub trait Protector: Send + Sync {
    /// # Safety
    /// The socket descriptor must be valid
    unsafe fn make_external(&self, _: NativeSocket) -> io::Result<()> {
        Ok(())
    }

    /// # Safety
    /// The socket descriptor must be valid
    unsafe fn make_internal(&self, _: NativeSocket) -> io::Result<()> {
        Ok(())
    }

    /// # Safety
    /// The socket descriptor must be valid
    unsafe fn clean(&self, _: NativeSocket) {}
}

#[derive(Debug, Default)]
pub struct DummyProtector;

impl Protector for DummyProtector {}
