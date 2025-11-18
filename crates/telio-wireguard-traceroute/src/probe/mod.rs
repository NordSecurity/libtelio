mod icmp;
mod udp;

use anyhow::{Context, Result};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use log::debug;

use crate::handshake::create_handshake_initiation;

/// Probe attempt
#[derive(Debug, Clone)]
pub struct Probe {
    sent_at: Instant,
    payload: Vec<u8>,
    src: SocketAddr,
    dest: SocketAddr,
    ttl: u8,
}

/// Response
#[derive(Debug, Clone)]
pub struct Response {
    received_at: Instant,
    from: SocketAddr,
    payload: Vec<u8>,
}

/// Result of probing
#[derive(Debug, Clone)]
pub enum ProbeResult {
    RouterResponse((Probe, Response)),
    DestinationReached((Probe, Response)),
    Timeout,
}

pub async fn wireguard_probe(
    source_port: Option<u16>,
    dest: &SocketAddr,
    ttl: u8,
    self_private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    wait: Duration,
) -> Result<ProbeResult> {
    probe(
        source_port,
        dest,
        ttl,
        &create_handshake_initiation(self_private_key, peer_public_key)?,
        wait,
    )
    .await
}

pub async fn probe(
    source_port: Option<u16>,
    dest: &SocketAddr,
    ttl: u8,
    payload: &[u8],
    wait: Duration,
) -> Result<ProbeResult> {
    // Create UDP socket for the probe
    let udp_socket = udp::create_socket(source_port, &dest, ttl)
        .await
        .context("Failed to create UDP socket")?;

    // Create ICMP socket for reading the error messages
    let icmp_socket = icmp::create_socket(&udp_socket.local_addr()?, dest)
        .await
        .context("Failed to create ICMP listening socket")?;

    // send probe
    let probe = udp::send_probe(dest, payload, &udp_socket)
        .await
        .context("Failed to send UDP probe")?;

    // Wait for any response or timeout
    let probing_result = tokio::select! {
        // Destination response
        result = udp::receive_response(&udp_socket) => {
            ProbeResult::DestinationReached((probe.clone(), result.context("Failed to receive UDP response")?))
        }

        // Router response
        result = icmp::receive_response(&icmp_socket, &probe) => {
            ProbeResult::RouterResponse((probe.clone(), result.context("Failed to receive ICMP response")?))
        }

        // Timeout
        _ = tokio::time::sleep(wait) => {
            debug!("Probe {probe:?} has timed out...");
            ProbeResult::Timeout
        }
    };

    Ok(probing_result)
}

impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Probe")?;
        writeln!(f, "  source: {}", self.src)?;
        writeln!(f, "  destination: {}", self.dest)?;
        writeln!(f, "  payload_size: {} bytes", self.payload.len())?;
        writeln!(f, "  ttl: {} hops", self.ttl)?;
        write!(f, "  payload_hex:")?;

        // Print hex dump of payload (16 bytes per line)
        for (i, chunk) in self.payload.chunks(16).enumerate() {
            writeln!(f)?;
            write!(f, "    {:04x}: ", i * 16)?;
            for byte in chunk {
                write!(f, "{:02x} ", byte)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Response")?;
        writeln!(f, "  from: {}", self.from)?;
        writeln!(f, "  payload_size: {} bytes", self.payload.len())?;
        write!(f, "  payload_hex:")?;

        // Print hex dump of payload (16 bytes per line)
        for (i, chunk) in self.payload.chunks(16).enumerate() {
            writeln!(f)?;
            write!(f, "    {:04x}: ", i * 16)?;
            for byte in chunk {
                write!(f, "{:02x} ", byte)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for ProbeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Probing Result:")?;
        match self {
            ProbeResult::RouterResponse((probe, response)) => {
                let rtt = response.received_at.duration_since(probe.sent_at);
                writeln!(f, "  type: Router Response")?;
                writeln!(f, "  rtt: {:.3}ms", rtt.as_secs_f64() * 1000.0)?;
                writeln!(f, "{}", probe)?;
                writeln!(f, "{}", response)?;
            }
            ProbeResult::DestinationReached((probe, response)) => {
                let rtt = response.received_at.duration_since(probe.sent_at);
                writeln!(f, "  rtt: {:.3}ms", rtt.as_secs_f64() * 1000.0)?;
                writeln!(f, "  type: Destination Reached")?;
                writeln!(f, "{}", probe)?;
                writeln!(f, "{}", response)?;
            }
            ProbeResult::Timeout => {
                writeln!(f, "Timeout")?;
            }
        };

        Ok(())
    }
}
