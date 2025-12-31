#![no_std]

/// Packet information shared between eBPF and userspace
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub protocol: u8,
    pub size: u32,
    pub timestamp: u64,
}

/// Packet statistics per flow
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketStats {
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketInfo {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketStats {}
