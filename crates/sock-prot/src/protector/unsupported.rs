use std::io;

pub struct NativeProtector;

impl NativeProtector {
    // Return `Result` to align with all other protector implementations
    pub fn new() -> io::Result<Self> {
        Ok(Self {})
    }
}

impl super::Protector for NativeProtector {}
