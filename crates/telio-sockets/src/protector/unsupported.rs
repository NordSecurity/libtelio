use std::io;

use crate::native::NativeSocket;

use super::Protector;

pub struct NativeProtector {}

impl NativeProtector {
    pub fn new() -> io::Result<Self> {
        Ok(Self {})
    }
}

impl Protector for NativeProtector {
    fn make_external(&self, _socket: NativeSocket) -> io::Result<()> {
        Ok(())
    }

    fn clean(&self, _socket: NativeSocket) {
        // Skip, socket will be removed
    }
}
