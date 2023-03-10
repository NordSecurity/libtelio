use std::{
    io::{self},
    sync::Mutex,
};

mod common;
use common::bind_to_tun;

use crate::native::NativeSocket;
use crate::Protector;

pub struct NativeProtector {
    tunnel_interface: Mutex<Option<u64>>,
}

impl NativeProtector {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            tunnel_interface: Mutex::new(None),
        })
    }
}

impl Protector for NativeProtector {
    fn make_external(&self, _socket: NativeSocket) -> io::Result<()> {
        Ok(())
    }

    fn make_internal(&self, socket: NativeSocket) -> io::Result<()> {
        if let Ok(tun_if) = self.tunnel_interface.lock() {
            bind_to_tun(socket, *tun_if);
        }
        Ok(())
    }

    fn clean(&self, _socket: NativeSocket) {}

    fn set_tunnel_interface(&self, interface: u64) {
        if let Ok(mut tun_if) = self.tunnel_interface.lock() {
            *tun_if = Some(interface);
        }
    }
}
