use aya::{
    include_bytes_aligned,
    maps::{HashMap, perf::AsyncPerfEventArray},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{info, warn};
use nordvpnlite_ebpf_common::{PacketInfo, PacketStats};
use std::net::Ipv4Addr;
use tokio::{signal, task};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase rlimit");
    }

    // Load the eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/nordvpnlite-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/nordvpnlite-ebpf"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Get the interface name from command line or use default
    let iface = std::env::args().nth(1).unwrap_or_else(|| "tun0".to_string());
    
    // Attach the XDP program to the network interface
    let program: &mut Xdp = bpf.program_mut("nordvpnlite_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())?;

    info!("eBPF program attached to interface: {}", iface);

    // Get references to the maps
    let mut packet_events = AsyncPerfEventArray::try_from(bpf.take_map("PACKET_EVENTS").unwrap())?;
    let packet_stats: HashMap<_, u32, PacketStats> =
        HashMap::try_from(bpf.map("PACKET_STATS").unwrap())?;

    // Spawn tasks to read from perf event array
    for cpu_id in online_cpus()? {
        let mut buf = packet_events.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketInfo;
                    let packet_info = unsafe { ptr.read_unaligned() };
                    
                    let src_ip = Ipv4Addr::from(packet_info.src_addr.to_be());
                    let dst_ip = Ipv4Addr::from(packet_info.dst_addr.to_be());
                    
                    info!(
                        "Packet: {} -> {} | Protocol: {} | Size: {} bytes | Time: {}",
                        src_ip, dst_ip, packet_info.protocol, packet_info.size, packet_info.timestamp
                    );
                }
            }
        });
    }

    // Periodically print statistics
    task::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            
            info!("=== Packet Statistics ===");
            for item in packet_stats.iter() {
                if let Ok((flow_key, stats)) = item {
                    info!(
                        "Flow {}: {} packets, {} bytes, {} drops",
                        flow_key, stats.packets, stats.bytes, stats.drops
                    );
                }
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
