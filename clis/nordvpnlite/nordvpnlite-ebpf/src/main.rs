#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use nordvpnlite_ebpf_common::{PacketInfo, PacketStats};

// Map to store packet statistics per flow
#[map]
static PACKET_STATS: HashMap<u32, PacketStats> = HashMap::with_max_entries(10240, 0);

// Perf event array for sending packet info to userspace
#[map]
static PACKET_EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::with_max_entries(1024, 0);

/// XDP program to monitor and optimize packet processing
#[xdp]
pub fn nordvpnlite_monitor(ctx: XdpContext) -> u32 {
    match try_nordvpnlite_monitor(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_nordvpnlite_monitor(ctx: XdpContext) -> Result<u32, ()> {
    let packet_size = ctx.data_end() - ctx.data();
    
    // Parse Ethernet header
    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth_proto = u16::from_be(unsafe { (*eth_hdr).ether_type });
    
    // Only process IPv4 packets (0x0800)
    if eth_proto != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Parse IP header
    let ip_hdr = ptr_at::<IpHdr>(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ip_hdr).dst_addr });
    let protocol = unsafe { (*ip_hdr).protocol };
    
    // Create flow key (simple hash of src/dst)
    let flow_key = src_addr ^ dst_addr;
    
    // Update statistics
    let stats = PACKET_STATS.get_ptr_mut(&flow_key).ok_or(())?;
    if stats.is_null() {
        let new_stats = PacketStats {
            packets: 1,
            bytes: packet_size as u64,
            drops: 0,
        };
        PACKET_STATS.insert(&flow_key, &new_stats, 0).map_err(|_| ())?;
    } else {
        unsafe {
            (*stats).packets += 1;
            (*stats).bytes += packet_size as u64;
        }
    }
    
    // Send packet info to userspace for detailed analysis
    let packet_info = PacketInfo {
        src_addr,
        dst_addr,
        protocol,
        size: packet_size as u32,
        timestamp: unsafe { bpf_ktime_get_ns() },
    };
    
    PACKET_EVENTS.output(&ctx, &packet_info, 0);
    
    // Apply optimizations based on packet characteristics
    // For small packets, we can potentially batch them
    if packet_size < 128 {
        // Small packet optimization path
        info!(&ctx, "Small packet detected: {} bytes", packet_size);
    }
    
    Ok(xdp_action::XDP_PASS)
}

#[repr(C)]
struct EthHdr {
    dst_addr: [u8; 6],
    src_addr: [u8; 6],
    ether_type: u16,
}

impl EthHdr {
    const LEN: usize = mem::size_of::<Self>();
}

#[repr(C)]
struct IpHdr {
    _version_ihl: u8,
    _tos: u8,
    _tot_len: u16,
    _id: u16,
    _frag_off: u16,
    _ttl: u8,
    protocol: u8,
    _check: u16,
    src_addr: u32,
    dst_addr: u32,
}

impl IpHdr {
    const LEN: usize = mem::size_of::<Self>();
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// BPF helper function
extern "C" {
    fn bpf_ktime_get_ns() -> u64;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
