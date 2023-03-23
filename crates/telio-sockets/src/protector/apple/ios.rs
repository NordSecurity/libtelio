use std::io::{self};

use parking_lot::RwLock;

mod common;
use common::bind_to_tun;

use crate::native::NativeSocket;
use crate::Protector;

pub struct NativeProtector {
    tunnel_interface: RwLock<Option<u64>>,
}

impl NativeProtector {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            tunnel_interface: RwLock::new(None),
        })
    }
}

impl Protector for NativeProtector {
    fn make_external(&self, _socket: NativeSocket) -> io::Result<()> {
        Ok(())
    }

    fn make_internal(&self, socket: NativeSocket) -> io::Result<()> {
        if let Some(tun_if) = *self.tunnel_interface.read() {
            return bind_to_tun(socket, tun_if);
        }
        Ok(())
    }

    fn clean(&self, _socket: NativeSocket) {}

    fn set_tunnel_interface(&self, interface: u64) {
        *self.tunnel_interface.write() = Some(interface);
    }
}
