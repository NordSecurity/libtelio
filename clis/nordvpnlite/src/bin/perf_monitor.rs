//! Performance monitoring tool for nordvpnlite
//!
//! This tool monitors CPU usage, memory consumption, network throughput,
//! and latency metrics for the nordvpnlite daemon.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::interval;

#[derive(Debug, Serialize, Deserialize)]
struct PerformanceMetrics {
    timestamp: u64,
    cpu_usage_percent: f64,
    memory_rss_kb: u64,
    memory_vms_kb: u64,
    network_rx_bytes: u64,
    network_tx_bytes: u64,
    network_rx_packets: u64,
    network_tx_packets: u64,
    context_switches: u64,
    open_fds: usize,
}

#[derive(Debug, Default)]
struct ProcessStats {
    utime: u64,
    stime: u64,
    rss: u64,
    vsize: u64,
    num_threads: u64,
    voluntary_ctxt_switches: u64,
    nonvoluntary_ctxt_switches: u64,
}

#[derive(Debug, Default)]
struct NetworkStats {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
}

/// Read process statistics from /proc/[pid]/stat
fn read_proc_stat(pid: u32) -> io::Result<ProcessStats> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&stat_path)?;

    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid stat format",
        ));
    }

    Ok(ProcessStats {
        utime: parts[13].parse().unwrap_or(0),
        stime: parts[14].parse().unwrap_or(0),
        rss: parts[23].parse().unwrap_or(0),
        vsize: parts[22].parse().unwrap_or(0),
        num_threads: parts[19].parse().unwrap_or(0),
        ..Default::default()
    })
}

/// Read process status from /proc/[pid]/status
fn read_proc_status(pid: u32) -> io::Result<ProcessStats> {
    let status_path = format!("/proc/{}/status", pid);
    let file = fs::File::open(&status_path)?;
    let reader = io::BufReader::new(file);

    let mut stats = ProcessStats::default();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("voluntary_ctxt_switches:") {
            stats.voluntary_ctxt_switches = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        } else if line.starts_with("nonvoluntary_ctxt_switches:") {
            stats.nonvoluntary_ctxt_switches = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }

    Ok(stats)
}

/// Count open file descriptors
fn count_open_fds(pid: u32) -> io::Result<usize> {
    let fd_path = format!("/proc/{}/fd", pid);
    Ok(fs::read_dir(&fd_path)?.count())
}

/// Read network statistics from /proc/net/dev
fn read_network_stats(interface: &str) -> io::Result<NetworkStats> {
    let net_dev_path = "/proc/net/dev";
    let file = fs::File::open(net_dev_path)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.contains(interface) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                return Ok(NetworkStats {
                    rx_bytes: parts[1].parse().unwrap_or(0),
                    rx_packets: parts[2].parse().unwrap_or(0),
                    tx_bytes: parts[9].parse().unwrap_or(0),
                    tx_packets: parts[10].parse().unwrap_or(0),
                });
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Interface not found",
    ))
}

/// Calculate CPU usage percentage
fn calculate_cpu_usage(
    prev_stats: &ProcessStats,
    curr_stats: &ProcessStats,
    elapsed_ms: u64,
) -> f64 {
    let total_time_diff =
        (curr_stats.utime + curr_stats.stime) - (prev_stats.utime + prev_stats.stime);
    let clock_ticks_per_sec = 100.0; // Usually 100 on Linux
    let cpu_usage =
        (total_time_diff as f64 / clock_ticks_per_sec) / (elapsed_ms as f64 / 1000.0) * 100.0;
    cpu_usage
}

/// Find nordvpnlite process ID
fn find_nordvpnlite_pid() -> io::Result<u32> {
    let proc_path = Path::new("/proc");

    for entry in fs::read_dir(proc_path)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) {
            if let Ok(pid) = pid_str.parse::<u32>() {
                let cmdline_path = path.join("cmdline");
                if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                    if cmdline.contains("nordvpnlite") {
                        return Ok(pid);
                    }
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "nordvpnlite process not found",
    ))
}

/// Collect performance metrics
async fn collect_metrics(
    pid: u32,
    interface: &str,
    prev_stats: &mut ProcessStats,
    prev_time: &mut Instant,
) -> io::Result<PerformanceMetrics> {
    let curr_stats = read_proc_stat(pid)?;
    let status_stats = read_proc_status(pid)?;
    let network_stats = read_network_stats(interface).unwrap_or_default();
    let open_fds = count_open_fds(pid)?;

    let now = Instant::now();
    let elapsed_ms = now.duration_since(*prev_time).as_millis() as u64;

    let cpu_usage = calculate_cpu_usage(prev_stats, &curr_stats, elapsed_ms);

    let page_size = 4096; // 4KB page size on most systems
    let metrics = PerformanceMetrics {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        cpu_usage_percent: cpu_usage,
        memory_rss_kb: curr_stats.rss * page_size / 1024,
        memory_vms_kb: curr_stats.vsize / 1024,
        network_rx_bytes: network_stats.rx_bytes,
        network_tx_bytes: network_stats.tx_bytes,
        network_rx_packets: network_stats.rx_packets,
        network_tx_packets: network_stats.tx_packets,
        context_switches: status_stats.voluntary_ctxt_switches
            + status_stats.nonvoluntary_ctxt_switches,
        open_fds,
    };

    *prev_stats = curr_stats;
    *prev_time = now;

    Ok(metrics)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("NordVPN Lite Performance Monitor");
    println!("=================================\n");

    let pid = match find_nordvpnlite_pid() {
        Ok(pid) => {
            println!("Found nordvpnlite process with PID: {}", pid);
            pid
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Make sure nordvpnlite daemon is running");
            return Err(e);
        }
    };

    // Determine the network interface (tun0 is common for VPN)
    let interface = "tun0";

    let mut prev_stats = read_proc_stat(pid)?;
    let mut prev_time = Instant::now();
    let mut interval = interval(Duration::from_secs(1));

    // CSV header
    println!(
        "timestamp,cpu_percent,rss_mb,vms_mb,rx_mbps,tx_mbps,rx_pps,tx_pps,ctx_switches,open_fds"
    );

    let mut prev_net_stats: Option<NetworkStats> = None;

    loop {
        interval.tick().await;

        match collect_metrics(pid, interface, &mut prev_stats, &mut prev_time).await {
            Ok(metrics) => {
                // Calculate network throughput
                let (rx_mbps, tx_mbps, rx_pps, tx_pps) = if let Some(ref prev) = prev_net_stats {
                    let rx_mbps =
                        ((metrics.network_rx_bytes - prev.rx_bytes) as f64 * 8.0) / 1_000_000.0;
                    let tx_mbps =
                        ((metrics.network_tx_bytes - prev.tx_bytes) as f64 * 8.0) / 1_000_000.0;
                    let rx_pps = metrics.network_rx_packets.saturating_sub(prev.rx_packets);
                    let tx_pps = metrics.network_tx_packets.saturating_sub(prev.tx_packets);
                    (rx_mbps, tx_mbps, rx_pps, tx_pps)
                } else {
                    (0.0, 0.0, 0, 0)
                };

                prev_net_stats = Some(NetworkStats {
                    rx_bytes: metrics.network_rx_bytes,
                    tx_bytes: metrics.network_tx_bytes,
                    rx_packets: metrics.network_rx_packets,
                    tx_packets: metrics.network_tx_packets,
                });

                println!(
                    "{},{:.2},{:.2},{:.2},{:.2},{:.2},{},{},{},{}",
                    metrics.timestamp,
                    metrics.cpu_usage_percent,
                    metrics.memory_rss_kb as f64 / 1024.0,
                    metrics.memory_vms_kb as f64 / 1024.0,
                    rx_mbps,
                    tx_mbps,
                    rx_pps,
                    tx_pps,
                    metrics.context_switches,
                    metrics.open_fds
                );
            }
            Err(e) => {
                eprintln!("Error collecting metrics: {}", e);
                break;
            }
        }
    }

    Ok(())
}
