pub mod handshake;
pub mod probe;

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};

use probe::ProbeResult;
use probe::wireguard_probe;

use log::debug;

#[derive(Debug, Clone)]
pub struct TracerouteReport {
    source_port: Option<u16>,
    dest: SocketAddr,
    self_private_key: [u8; 32],
    peer_public_key: [u8; 32],
    first_ttl: u8,
    max_ttl: u8,
    queries: usize,
    wait: Duration,
    results: Vec<ProbeResult>,
}

pub async fn traceroute(
    source_port: Option<u16>,
    dest: &SocketAddr,
    self_private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    first_ttl: u8,
    max_ttl: u8,
    queries: usize,
    wait: Duration,
) -> Result<TracerouteReport> {
    let mut results: Vec<ProbeResult> = vec![];

    debug!(
        "Starting wireguard traceroute with: {source_port:?}, {dest:?}, {self_private_key:?}, {peer_public_key:?}, {first_ttl:?}, {max_ttl:?}, {queries:?}, {wait:?}"
    );

    // Traceroute loop
    for ttl in first_ttl..=max_ttl {
        let mut probe_result: ProbeResult = ProbeResult::Timeout;

        // Send multiple queries per hop
        for i in 0..queries {
            debug!("Probing: ttl: {ttl:?}, attempt: {i:?}");
            let result = wireguard_probe(
                source_port,
                &dest,
                ttl,
                &self_private_key,
                &peer_public_key,
                wait,
            )
            .await
            .context("WireGuard traceroute probe failed")?;

            debug!("Result: {result:?}");

            if let ProbeResult::RouterResponse(_) | ProbeResult::DestinationReached(_) = result {
                debug!("Got non-timeout response - bumping TTL");
                probe_result = result.clone();
                break;
            }
        }

        results.push(probe_result.clone());

        if let ProbeResult::DestinationReached(_) = probe_result {
            debug!("Destination has been reached!");
            break;
        }
    }

    Ok(TracerouteReport {
        source_port,
        dest: dest.clone(),
        self_private_key: self_private_key.clone(),
        peer_public_key: peer_public_key.clone(),
        first_ttl,
        max_ttl,
        queries,
        wait,
        results,
    })
}

impl fmt::Display for TracerouteReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Traceroute Report")?;
        writeln!(f, "  destination: {}", self.dest)?;

        if let Some(port) = self.source_port {
            writeln!(f, "  source_port: {}", port)?;
        } else {
            writeln!(f, "  source_port: (random)")?;
        }

        writeln!(f, "  ttl_range: {} - {}", self.first_ttl, self.max_ttl)?;
        writeln!(f, "  queries_per_hop: {}", self.queries)?;
        writeln!(f, "  timeout: {:.1}s", self.wait.as_secs_f64())?;

        writeln!(f, "  private_key_hex:")?;
        write!(f, "    ")?;
        for (i, byte) in self.self_private_key.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                write!(f, "\n    ")?;
            }
            write!(f, "{:02x} ", byte)?;
        }
        writeln!(f)?;

        writeln!(f, "  peer_public_key_hex:")?;
        write!(f, "    ")?;
        for (i, byte) in self.peer_public_key.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                write!(f, "\n    ")?;
            }
            write!(f, "{:02x} ", byte)?;
        }
        writeln!(f)?;

        writeln!(f, "  total_probes: {}", self.results.len())?;
        writeln!(f, "  results:")?;

        for (i, result) in self.results.iter().enumerate() {
            writeln!(f, "[{}] {}", i, result)?;
        }

        Ok(())
    }
}
