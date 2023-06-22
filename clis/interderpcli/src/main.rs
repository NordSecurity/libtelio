use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use itertools::Itertools;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::{fs::File, path::PathBuf, sync::Arc, time::Duration};
use telio_crypto::SecretKey;
use telio_relay::{
    derp::Config as DerpConfig,
    http::{connect_http_and_start, DerpConnection},
};
use telio_sockets::{NativeProtector, SocketPool};
use tokio::{net::lookup_host, time::timeout};
use url::{Host, Url};

#[derive(Parser)]
#[command(version)]
struct Opt {
    #[arg(short, long)]
    pub verbose: bool,
    /// Config file. Overridden by the other options.
    #[arg(short, long)]
    pub config_file: Option<PathBuf>,
    /// First derp server
    #[arg(long)]
    pub derp_1: Option<String>,
    /// Second derp server
    #[arg(long)]
    pub derp_2: Option<String>,
    /// First private key
    #[arg(long)]
    pub secret_key_1: Option<SecretKey>,
    /// Second private key
    #[arg(long)]
    pub secret_key_2: Option<SecretKey>,
}

// CLI arguments
#[derive(Serialize, Deserialize)]
pub struct Config {
    // Server list
    pub servers: Vec<String>,
    // Private key 1
    pub private_key_1: SecretKey,
    // Private key 2
    pub private_key_2: SecretKey,
}

impl Config {
    pub fn new(config_file: PathBuf) -> Result<Self> {
        let config_file = File::open(config_file).context("Failed to open config file")?;
        serde_json::from_reader(config_file).context("Error while parsing config file")
    }
}

async fn resolve_domain_name(domain: &str) -> Result<SocketAddr> {
    let url = Url::parse(domain)?;
    let hostname = match url.host() {
        None => {
            return Err(anyhow!("Failed to parse URL domain: {}", domain));
        }
        Some(hostname) => match hostname {
            Host::Domain(hostname) => String::from(hostname),
            Host::Ipv4(hostname) => hostname.to_string(),
            Host::Ipv6(hostname) => hostname.to_string(),
        },
    };
    let port = match url.port() {
        None => match url.scheme() {
            "http" => 80,
            _ => 443,
        },
        Some(port) => port,
    };
    let hostport = format!("{}:{}", hostname, port);

    log::debug!("Resolving {}", hostname);
    let addrs = lookup_host(hostport).await?.collect::<Vec<SocketAddr>>();
    log::debug!("Got Addresses: {:?} for {:?}", addrs, hostname);

    addrs
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("Empty server addr"))
}

async fn connect_client(
    addr: SocketAddr,
    hostname: String,
    private_key: SecretKey,
) -> Result<DerpConnection> {
    log::debug!("Connecting to {:?} ({:?})", hostname, addr);

    let pool = Arc::new(SocketPool::new(NativeProtector::new(
        #[cfg(target_os = "macos")]
        false,
    )?));

    Box::pin(connect_http_and_start(
        pool,
        &hostname,
        addr,
        DerpConfig {
            secret_key: private_key,
            timeout: Duration::from_secs(10),
            ..Default::default()
        },
    ))
    .await
    .map_err(|e| anyhow!(e.to_string()))
}

#[allow(mpsc_blocking_send)]
async fn ping_each_other(
    key_1: &SecretKey,
    client_1: &mut DerpConnection,
    key_2: &SecretKey,
    client_2: &mut DerpConnection,
) -> Result<()> {
    log::info!("Sending client 1 -> client 2...");
    let mut tx_msg1 = vec![0, 1, 2, 3];
    SystemRandom::new()
        .fill(&mut tx_msg1[..])
        .map_err(|e| anyhow!(e.to_string()))?;
    for _ in 0..3 {
        client_1
            .comms
            .tx
            .send((key_2.public(), tx_msg1.clone()))
            .await?;
    }

    log::info!("Sending client 2 -> client 1...");
    let mut tx_msg2 = vec![0; 4];
    SystemRandom::new()
        .fill(&mut tx_msg2[..])
        .map_err(|e| anyhow!(e.to_string()))?;
    for _ in 0..3 {
        client_2
            .comms
            .tx
            .send((key_1.public(), tx_msg2.clone()))
            .await?;
    }

    log::info!("Try to receive message on client 1");
    timeout(Duration::from_secs(3), async move {
        loop {
            let rx_msg1 = client_1
                .comms
                .rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("Receiving channel closed (auth problems?)"))?;
            if rx_msg1 == (key_2.public(), tx_msg2.clone()) {
                break Ok::<(), anyhow::Error>(());
            }
        }
    })
    .await
    .context("First client did not receive the ping message from the second client in 10s")??;

    log::info!("Try to receive message on client 2");
    timeout(Duration::from_secs(3), async move {
        loop {
            let rx_msg2 = client_2
                .comms
                .rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("Receiving channel closed (auth problems?)"))?;
            if rx_msg2 == (key_1.public(), tx_msg1.clone()) {
                break Ok::<(), anyhow::Error>(());
            }
        }
    })
    .await
    .context("Second client did not receive the ping message from the first client in 10s")??;

    Ok(())
}

async fn test_pair(
    host_1: String,
    key_1: SecretKey,
    host_2: String,
    key_2: SecretKey,
) -> Result<()> {
    log::info!("Resolving server domains");
    let addr_1 = resolve_domain_name(&host_1).await?;
    let addr_2 = resolve_domain_name(&host_2).await?;

    log::info!("Starting clients");
    let mut client_1 = Box::pin(connect_client(addr_1, host_1.clone(), key_1))
        .await
        .context("Failed to connect to first server")?;
    let mut client_2 = Box::pin(connect_client(addr_2, host_2.clone(), key_2))
        .await
        .context("Failed to connect to second server")?;

    log::info!("Ping each other");
    ping_each_other(&key_1, &mut client_1, &key_2, &mut client_2).await
}

async fn config_file_scenario(config_file: PathBuf, verbose: bool) -> Result<()> {
    // parse command line params and create config struct
    let config = Config::new(config_file)?;

    println!("Derp connection tester starting");

    for pair in config.servers.iter().combinations_with_replacement(2) {
        match (pair.first(), pair.get(1)) {
            (Some(first), Some(second)) => {
                match Box::pin(test_pair(
                    first.to_string(),
                    config.private_key_1,
                    second.to_string(),
                    config.private_key_2,
                ))
                .await
                {
                    Ok(_) => println!("✔️ {:?} <-> {:?}", first, second),
                    Err(e) => {
                        if verbose {
                            println!("❌ {:?} <-> {:?}. {:?}", first, second, e);
                        } else {
                            println!(
                                "❌ {:?} <-> {:?}. Error: {:?}",
                                first,
                                second,
                                e.to_string()
                                    .lines()
                                    .next()
                                    .ok_or_else(|| anyhow!("empty error"))?
                            );
                        }
                    }
                }
            }
            _ => bail!("Empty server addr"),
        }
    }
    Ok(())
}

async fn single_check_scenario(opt: Opt) -> Result<()> {
    let derp_1 = opt.derp_1.ok_or_else(|| anyhow!("Invalid argument"))?;
    let derp_2 = opt.derp_2.ok_or_else(|| anyhow!("Invalid argument"))?;
    let secret_key_1 = opt
        .secret_key_1
        .ok_or_else(|| anyhow!("Invalid argument"))?;
    let secret_key_2 = opt
        .secret_key_2
        .ok_or_else(|| anyhow!("Invalid argument"))?;

    test_pair(derp_1, secret_key_1, derp_2, secret_key_2).await
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();
    let verbose = opt.verbose;

    if opt.derp_1.is_some()
        || opt.derp_2.is_some()
        || opt.secret_key_1.is_some()
        || opt.secret_key_2.is_some()
    {
        // The single check scenario used for automatic validation
        // This should not print anything and just use the exit code
        // to reveal the result
        log::info!("Single check scenario");
        match single_check_scenario(opt).await {
            Ok(_) => {
                log::info!("Success");
                std::process::exit(0);
            }
            Err(e) => {
                log::info!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // The main scenario this tool has been created for
        log::info!("Config file scenario");
        config_file_scenario(
            opt.config_file
                .ok_or_else(|| anyhow!("Missing config file"))?,
            verbose,
        )
        .await
    }
}
