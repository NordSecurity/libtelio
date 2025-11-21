use anyhow::{Context, Result, bail};
use clap::Parser;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use telio_wireguard_traceroute::traceroute;

#[derive(Parser, Debug)]
#[command(
    name = "wg-traceroute",
    author,
    version,
    about = "Traceroute for WireGuard handshake packets",
    long_about = "Sends WireGuard handshake initiation packets with incrementing TTL values\n\
                  to trace the network path to a WireGuard server."
)]
struct Args {
    /// WireGuard server endpoint (host:port or IP:port)
    #[arg(value_name = "DESTINATION")]
    destination: String,

    /// Your WireGuard private key (base64-encoded)
    #[arg(short = 'k', long, value_name = "KEY", env = "WG_SELF_PRIVATE_KEY")]
    self_private_key: String,

    /// Server's WireGuard public key (base64-encoded)
    #[arg(short = 'p', long, value_name = "KEY", env = "WG_PEER_PUBLIC_KEY")]
    peer_public_key: String,

    /// First TTL value to use
    #[arg(short = 'f', long, default_value = "1", value_name = "FIRST_TTL")]
    first_ttl: u8,

    /// Maximum TTL (maximum number of hops)
    #[arg(short = 'm', long, default_value = "30", value_name = "MAX_TTL")]
    max_ttl: u8,

    /// Number of probe packets per hop
    #[arg(short = 'q', long, default_value = "3", value_name = "NQUERIES")]
    queries: usize,

    /// Wait time for response (in seconds)
    #[arg(short = 'w', long, default_value = "5", value_name = "WAIT")]
    wait: u64,

    /// Port to use for receiving ICMP responses
    #[arg(short = 'P', long, value_name = "PORT")]
    source_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Validate arguments
    if args.first_ttl >= args.max_ttl {
        bail!("max TTL must be greater than first TTL");
    }

    // Decode keys
    let self_private_key =
        decode_base64_key(&args.self_private_key).context("Failed to decode private key")?;
    let peer_public_key =
        decode_base64_key(&args.peer_public_key).context("Failed to decode peer public key")?;

    // Resolve destination
    let dest_addr =
        resolve_destination(&args.destination).context("Failed to resolve destination")?;

    let wait = Duration::from_secs(args.wait);

    println!(
        "WireGuard traceroute to {} ({}), {} hops max, {} byte packets",
        args.destination,
        dest_addr.ip(),
        args.max_ttl,
        148 // WireGuard handshake packet size
    );

    let result = traceroute(
        args.source_port,
        &dest_addr,
        &self_private_key,
        &peer_public_key,
        args.first_ttl,
        args.max_ttl,
        args.queries,
        wait,
    )
    .await?;

    println!("{result}");

    Ok(())
}

fn resolve_destination(dest: &str) -> Result<SocketAddr> {
    dest.to_socket_addrs()
        .context("Invalid destination address")?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve destination"))
}

fn decode_base64_key(key_str: &str) -> Result<[u8; 32]> {
    use base64::{Engine as _, engine::general_purpose};

    let decoded = general_purpose::STANDARD
        .decode(key_str.trim())
        .context("Invalid base64 encoding")?;

    if decoded.len() != 32 {
        bail!("Key must be exactly 32 bytes, got {} bytes", decoded.len());
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}
