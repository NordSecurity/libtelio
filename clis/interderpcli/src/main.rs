use anyhow::{anyhow, Context, Result};
use clap::{Arg, Command};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::{fs::File, sync::Arc, time::Duration};
use telio_crypto::SecretKey;
use telio_relay::{
    derp::Config as DerpConfig,
    http::{connect_http_and_start, DerpConnection},
};
use telio_sockets::{NativeProtector, SocketPool};
use tokio::{net::lookup_host, time::timeout};
use url::{Host, Url};

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
    pub fn new() -> Result<(Self, bool)> {
        // initialize command line params parser
        let matches = Command::new("Test DERP connectivty")
            .about("Command line utility to perform DERP tests")
            .version("2.0")
            .arg(
                Arg::new("config file")
                    .help("JSON configuration file")
                    .required(true)
                    .takes_value(true)
                    .long("config")
                    .short('c'),
            )
            .arg(
                Arg::new("verbose")
                    .help("Print detailed errors")
                    .required(false)
                    .takes_value(false)
                    .long("verbose")
                    .short('v'),
            )
            .get_matches();

        let config_path = matches
            .value_of("config file")
            .ok_or_else(|| anyhow!("Config value not provided"))?;
        let config_file = File::open(config_path).context("Failed to open config file")?;
        let config =
            serde_json::from_reader(config_file).context("Error while parsing config file")?;

        Ok((config, matches.is_present("verbose")))
    }
}

#[allow(unwrap_check)]
async fn resolve_domain_name(domain: &str) -> Result<Vec<SocketAddr>> {
    let url = Url::parse(domain).unwrap();
    let hostname = match url.host() {
        None => {
            panic!("Failed to parse URL domain: {}", domain);
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
    let addrs = lookup_host(hostport)
        .await
        .unwrap()
        .collect::<Vec<SocketAddr>>();

    if addrs.len() <= 0 {
        return Err(anyhow!(format!("Empty response for domain {}", hostname)));
    }

    log::debug!("Got Addresses: {:?} for {:?}", addrs, hostname);

    Ok(addrs)
}

async fn connect_client(
    addr: SocketAddr,
    hostname: String,
    private_key: SecretKey,
) -> Result<DerpConnection> {
    log::debug!("Connecting to {:?} ({:?})", hostname, addr);

    let pool = Arc::new(SocketPool::new(NativeProtector::new(
        #[cfg(target_os = "macos")]
        Some(false),
    )?));
    let conn = match connect_http_and_start(
        pool,
        &hostname,
        addr,
        DerpConfig {
            secret_key: private_key,
            timeout: Duration::from_secs(10),
            ..Default::default()
        },
    )
    .await
    {
        Ok(conn) => conn,
        Err(e) => return Err(anyhow!(e.to_string())),
    };

    Ok(conn)
}

#[allow(mpsc_blocking_send)]
async fn ping_each_other(
    key_1: &SecretKey,
    client_1: &mut DerpConnection,
    key_2: &SecretKey,
    client_2: &mut DerpConnection,
) -> Result<()> {
    log::info!("Sending client 1 -> client 2...");
    let tx_msg1 = vec![0, 1, 2, 3];
    client_1
        .comms
        .tx
        .send((key_2.public(), tx_msg1.clone()))
        .await?;

    log::info!("Sending client 2 -> client 1...");
    let tx_msg2 = vec![3, 2, 1, 0];
    client_2
        .comms
        .tx
        .send((key_1.public(), tx_msg2.clone()))
        .await?;

    log::info!("Try to receive message on client 1");
    timeout(Duration::from_secs(3), async move {
        loop {
            let rx_msg1 = client_1
                .comms
                .rx
                .recv()
                .await
                .ok_or(anyhow!("Receiving channel closed (auth problems?)"))?;
            if rx_msg1 == (key_2.public(), tx_msg2.clone()) {
                break Ok::<(), anyhow::Error>(());
            }
        }
    })
    .await
    .context("First client did not receive the ping message from the second client in 10s")??;

    timeout(Duration::from_secs(3), async move {
        loop {
            let rx_msg2 = client_2
                .comms
                .rx
                .recv()
                .await
                .ok_or(anyhow!("Receiving channel closed (auth problems?)"))?;
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
    let mut client_1 = connect_client(addr_1[0], host_1.clone(), key_1)
        .await
        .context("Failed to connect to first server")?;
    let mut client_2 = connect_client(addr_2[0], host_2.clone(), key_2)
        .await
        .context("Failed to connect to second server")?;

    log::info!("Ping each other");
    ping_each_other(&key_1, &mut client_1, &key_2, &mut client_2)
        .await
        .context("Pinging failed")?;

    Ok(())
}

// Executable tool, panics should be transformed into human readable errors, (expect or anyhow)
#[tokio::main]
#[allow(unwrap_check)]
async fn main() {
    // parse command line params and create config struct
    let (config, verbose) = Config::new().expect("Invalid CLI arguments");
    env_logger::init(); // remove?

    println!("Derp connection tester starting");

    for pair in config.servers.iter().combinations_with_replacement(2) {
        match test_pair(
            pair[0].clone(),
            config.private_key_1.clone(),
            pair[1].clone(),
            config.private_key_2.clone(),
        )
        .await
        {
            Ok(_) => println!("✔️ {:?} <-> {:?}", pair[0], pair[1]),
            Err(e) => {
                if verbose {
                    println!("❌ {:?} <-> {:?}. {:?}", pair[0], pair[1], e);
                } else {
                    println!(
                        "❌ {:?} <-> {:?}. Error: {:?}",
                        pair[0],
                        pair[1],
                        e.to_string().lines().next().unwrap()
                    );
                }
            }
        }
    }
}
