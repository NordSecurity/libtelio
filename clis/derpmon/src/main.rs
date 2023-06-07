use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};
use structopt::StructOpt;
use telio_crypto::SecretKey;
use telio_relay::{
    derp::Config as DerpConfig,
    http::{connect_http_and_start, DerpConnection},
};
use telio_sockets::{NativeProtector, SocketPool};
use tokio::{net::lookup_host, time::timeout};
use url::{Host, Url};

#[derive(StructOpt, Debug)]
#[structopt(name = "derpmon")]
struct Config {
    /// First derp server
    #[structopt(long = "derp-1")]
    pub derp_1: String,
    /// Second derp server
    #[structopt(long = "derp-2")]
    pub derp_2: String,
    /// First private key
    #[structopt(long = "secret-key-1")]
    pub secret_key_1: SecretKey,
    /// Second private key
    #[structopt(long = "secret-key-2")]
    pub secret_key_2: SecretKey,
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
    let addrs = lookup_host(hostport).await?.collect::<Vec<SocketAddr>>();

    addrs
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("Empty server addr"))
}

async fn connect_client(
    addr: SocketAddr,
    hostname: String,
    secret_key: SecretKey,
) -> Result<DerpConnection> {
    let pool = Arc::new(SocketPool::new(NativeProtector::new(
        #[cfg(target_os = "macos")]
        Some(false),
    )?));

    Box::pin(connect_http_and_start(
        pool,
        &hostname,
        addr,
        DerpConfig {
            secret_key,
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
    // Sending 3 packets from client_1 -> client_2
    let tx_msg1 = vec![0, 1, 2, 3];
    for _ in 0..3 {
        client_1
            .comms
            .tx
            .send((key_2.public(), tx_msg1.clone()))
            .await?;
    }

    // Sending 3 packets from client_1 -> client_1
    let tx_msg2 = vec![3, 2, 1, 0];
    for _ in 0..3 {
        client_2
            .comms
            .tx
            .send((key_1.public(), tx_msg2.clone()))
            .await?;
    }

    // Wait for at least 1 message on client_1
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
    .await??;

    // Wait for at least 1 message on client_2
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
    .await??;

    Ok(())
}

async fn test_pair(config: &Config) -> Result<()> {
    let addr_1 = resolve_domain_name(&config.derp_1).await?;
    let addr_2 = resolve_domain_name(&config.derp_2).await?;

    let mut client_1 = Box::pin(connect_client(
        addr_1,
        config.derp_1.clone(),
        config.secret_key_1,
    ))
    .await?;

    let mut client_2 = Box::pin(connect_client(
        addr_2,
        config.derp_2.clone(),
        config.secret_key_2,
    ))
    .await?;

    ping_each_other(
        &config.secret_key_1,
        &mut client_1,
        &config.secret_key_2,
        &mut client_2,
    )
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // parse command line params and create config struct
    let config = Config::from_args();

    if Box::pin(test_pair(&config)).await.is_err() {
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}
