use std::{io, sync::Mutex};

use crate::native::NativeSocket;

use super::Protector;

pub struct NativeProtector {
    fwmark: Mutex<u32>,
}

impl NativeProtector {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            fwmark: Mutex::new(0),
        })
    }

    pub fn set_fwmark(&self, fwmark: u32) {
        if let Ok(mut my_fwmark) = self.fwmark.lock() {
            *my_fwmark = fwmark;
        }
    }
}

impl Protector for NativeProtector {
    fn make_external(&self, socket: NativeSocket) -> io::Result<()> {
        if let Ok(fwmark) = self.fwmark.lock() {
            if *fwmark != 0 {
                set_fwmark(socket, *fwmark)?;
            }
        }
        Ok(())
    }

    fn clean(&self, _socket: NativeSocket) {
        // Skip, socket will be removed
    }

    fn set_fwmark(&self, fwmark: u32) {
        if let Ok(mut my_fwmark) = self.fwmark.lock() {
            *my_fwmark = fwmark;
        }
    }
}

fn set_fwmark(fd: i32, fwmark: u32) -> io::Result<()> {
    let fwmark = fwmark;
    let fwmark_ptr = &fwmark as *const u32 as *const libc::c_void;

    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK as i32,
            fwmark_ptr,
            4_u32,
        )
    };
    match res {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}
