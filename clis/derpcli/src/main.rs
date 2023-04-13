//! DERP testing command line interface
//! ```
//! run derpcli -h for usage help
//!
//! DERP cli 2.0
//! Command line utility to perform DERP tests
//!
//! USAGE:
//!     derpcli [FLAGS] [OPTIONS]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -l, --loop       Loop until interrupted
//!     -t, --target     Run as target
//!     -V, --version    Prints version information
//!     -v, --verbose    Verbose output (can use multiple)
//!
//! OPTIONS:
//!     -c, --count <count>            Count of iterations to run [default: 3]
//!     -a, --data <data>              Data text to send, <to be implemented> [default: hello derp!]
//!     -d, --delay <delay>            Delay ms between iterations [default: 100]
//!     -m, --mykey <mykey>            My private key base64 encoded
//!     -s, --server <server>          Server address [default: http://localhost:1234]
//!     -z, --size <size>              Data text size to generate and send
//!     -k, --targetkey <targetkey>    Target peer private key base64 encoded
//!     -f, --config <path>            Path to config file
//!     -o, --output <path>            Path to logs output file [default: ""]
//!     -C, --CA <path>                Path to CA.pem file [default: ""]
//!     {
//!         "clients": [
//!             {
//!                 "private_key": "IDv2SVTGIHar8c1zYEAHf8wQQwvSNZct9bRzSSYiA0Q=",
//!                 "derp_server": "de1047.nordvpn.com:8765",
//!                 "peers": [
//!                     "UBZoCQW06xiFHQLvVgkNYC6pqDluteitq6fLfD4Nc34=",
//!                     "qASVNSYfZTM1AAHHycE3tIGhNs6WP5SU5e6jRaDDzXk="
//!                 ],
//!                 "period": 1000
//!             },
//!         ]
//!     }
//!
//!
//! example cli to run as receiving client:
//!
//! derpcli -s http://myderp:3340 -m MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMQo= -k MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMgo= -t
//!
//! example cli to run as sending client:
//!
//! derpcli -s http://myderp:3340 -m MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMQo= -k MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMgo= -c 20 -d 500
//!
//! ```

#![allow(unwrap_check)]
mod conf;
mod metrics;

use anyhow::{anyhow, bail, Context, Result};
use lazy_static::lazy_static;
use parking_lot::Mutex;
use prometheus::{Encoder, TextEncoder};
use std::{
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use telio_relay::{
    derp::Config,
    http::{connect_http_and_start, DerpConnection},
};
use telio_sockets::{NativeProtector, SocketPool};
use tokio::net::lookup_host;
use url::{Host, Url};
use warp::Filter;

lazy_static! {
    static ref METRICS: Mutex<metrics::Metrics> = Mutex::new(metrics::Metrics::new());
}

async fn resolve_domain_name(domain: &str, verbose: u64) -> Result<Vec<SocketAddr>> {
    let url = Url::parse(domain)?;
    let hostname = match url.host() {
        None => {
            bail!("Failed to parse URL domain: {}", domain);
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
    if verbose >= 1 {
        println!("Resolving {}", hostport);
    }
    let addrs = lookup_host(hostport).await?.collect::<Vec<SocketAddr>>();

    if addrs.is_empty() {
        bail!("Failed to resolve domain: {}", domain);
    }

    Ok(addrs)
}

#[allow(mpsc_blocking_send)]
async fn connect_client(
    pool: Arc<SocketPool>,
    client: &conf::ClientConfig,
    verbosity: u64,
    addrs: Vec<SocketAddr>,
    ca_pem_path: PathBuf,
) -> Result<()> {
    let verbose = verbosity >= 1;
    let DerpConnection { mut comms, .. } = match Box::pin(connect_http_and_start(
        pool,
        &client.derp_server,
        addrs[0],
        Config {
            secret_key: client.private_key,
            timeout: Duration::from_secs(10),
            ca_pem_path: match ca_pem_path != Path::new("").to_path_buf() {
                true => match ca_pem_path.exists() {
                    false => {
                        println!("{:?} - does not exist", ca_pem_path);
                        None
                    }
                    true => Some(ca_pem_path),
                },
                false => None,
            },
            ..Default::default()
        },
    ))
    .await
    {
        Ok(tup) => tup,
        Err(err) => {
            println!(
                "[{}] -> Failed to connect to derp server -> {}",
                client.private_key.public(),
                &err
            );
            bail!("{}", err)
        }
    };

    METRICS.lock().add_client(client.private_key.public())?;

    let _ = tokio::spawn({
        let client = client.clone();
        let comm_tx = comms.tx.clone();
        async move {
            if verbose {
                println!(
                    "[{}] -> Start pinging peers with period {} msec",
                    client.private_key.public(),
                    client.period
                );
            }
            loop {
                for peer in client.peers.iter() {
                    if verbose {
                        println!(
                            "[{}] -> Pinging peer {}",
                            client.private_key.public(),
                            peer.public()
                        );
                    }
                    let public_key = peer.public();
                    if let Err(rc) = comm_tx.send((public_key, vec![0])).await {
                        println!(
                            "[{}] -> Error on sending: {}",
                            client.private_key.public(),
                            rc
                        );
                        process::exit(1);
                    } else if let Err(e) = METRICS
                        .lock()
                        .inc_peer_ping_counter(client.private_key.public(), (*peer).public())
                    {
                        println!("Failed to increment peer ping counter: {}", e);
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(client.period.into())).await;
            }
        }
    });

    let _ = tokio::spawn({
        let client = client.clone();
        async move {
            if verbose {
                println!(
                    "[{}] -> Start receiving pings and responding with pongs",
                    client.private_key.public()
                );
            }
            loop {
                match comms.rx.recv().await {
                    Some((public_key, buf)) => match buf.first() {
                        Some(1) => {
                            if verbose {
                                println!(
                                    "[{}] -> Received pong from {}",
                                    client.private_key.public(),
                                    public_key
                                );
                            }
                            if let Err(e) = METRICS
                                .lock()
                                .inc_peer_pong_counter(client.private_key.public(), public_key)
                            {
                                println!("failed to increment peer pong counter: {}", e);
                                return;
                            }
                            continue;
                        }
                        Some(0) => {
                            if verbose {
                                println!(
                                    "[{}] -> Received ping from {}, sending pong back",
                                    client.private_key.public(),
                                    public_key
                                );
                            }
                            if let Err(rc) = comms.tx.send((public_key, vec![1])).await {
                                println!(
                                    "[{}] -> Error on sending: {}",
                                    client.private_key.public(),
                                    rc
                                );
                                process::exit(1);
                            }
                        }
                        _ => {
                            if verbose {
                                println!(
                                "[{}] -> Received something other than ping / pong -> buf: {:?}",
                                client.private_key.public(),
                                buf
                            );
                            }
                        }
                    },
                    None => {
                        continue;
                    }
                }
            }
        }
    });

    Ok(())
}

async fn run_with_clients_config(config: conf::Config) -> Result<()> {
    config.print_clients()?;

    let clients_config = match config.clients_config {
        Some(conf) => conf,
        None => {
            bail!("No config provided");
        }
    };

    let mut futs = vec![];
    let mut client_count = 0;

    let mut addrs = Vec::new();
    let pool = Arc::new(SocketPool::new(NativeProtector::new()?));

    for client in clients_config.clients.iter() {
        if futs.is_empty() {
            addrs = match resolve_domain_name(&client.derp_server, config.verbose).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    println!(
                        "[{}] -> Failed to resolve domain name -> {}",
                        client.private_key.public(),
                        e
                    );
                    return Ok(());
                }
            };
        }

        futs.push(connect_client(
            pool.clone(),
            client,
            config.verbose,
            addrs.clone(),
            config.ca_pem_path.clone(),
        ));
        if futs.len() == 30
            || client
                == clients_config
                    .clients
                    .last()
                    .ok_or_else(|| anyhow!("no clients"))?
        {
            client_count += futs.len();
            println!("Adding {} clients", futs.len());
            futures::future::join_all(futs.drain(..futs.len())).await;
            println!(
                "Added {} clients. Total connected clients {}",
                futs.len(),
                client_count
            );
        }
    }
    Ok(())
}

#[allow(mpsc_blocking_send)]
async fn run_without_clients_config(config: conf::Config) -> Result<()> {
    config.print();

    let addrs = resolve_domain_name(config.get_server_address(), config.verbose).await?;

    let DerpConnection { mut comms, .. } = match Box::pin(connect_http_and_start(
        Arc::new(SocketPool::new(NativeProtector::new()?)),
        config.get_server_address(),
        addrs[0],
        Config {
            secret_key: config.my_key,
            timeout: Duration::from_secs(5),
            ca_pem_path: match config.ca_pem_path != Path::new("").to_path_buf() {
                true => match config.ca_pem_path.exists() {
                    false => {
                        println!("{:?} - does not exist", config.ca_pem_path);
                        None
                    }
                    true => Some(config.ca_pem_path.clone()),
                },
                false => None,
            },
            ..Default::default()
        },
    ))
    .await
    {
        Ok(tup) => tup,
        Err(err) => {
            println!("CONNECT ERROR: {}", err);
            return Ok(());
        }
    };

    if config.is_target {
        // if running as target - just wait for incomming messages
        if config.verbose > 0 {
            println!("waiting for messages...")
        }

        loop {
            let (public_key, data) = comms
                .rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("rx receive failed"))?;
            match config.verbose {
                v if v == 1 => {
                    print!(".");
                    io::stdout().flush()?;
                }
                v if v > 1 => {
                    println!(
                        "RECEIVED: [{}] / [{}]",
                        base64::encode(public_key),
                        String::from_utf8_lossy(&data)
                    )
                }
                _ => {}
            }
        }
    } else {
        // if running as sender - send series of messages
        let mut n = 1;
        let mut exit = false;

        let pkey = config.target_key.public();

        let mut data_to_send = config.send_data.to_string();
        // if requested, create data to send of given size
        if config.send_size_enabled {
            let arr = vec!['u'; config.send_size.into()];
            data_to_send = arr.into_iter().collect();
        }

        println!("DERP CLI SENDING");

        while !exit {
            let str = format!("{} {}", data_to_send, n);

            if config.verbose == 1 {
                print!(".");
                io::stdout().flush()?;
            } else if config.verbose > 2 {
                println!(
                    "SENDING: [{}] -> [{}] -> [{}]",
                    &config.get_pub_key1_b64(),
                    str,
                    &config.get_pub_key2_b64()
                )
            }

            if let Err(rc) = comms.tx.send((pkey, str.as_bytes().to_vec())).await {
                // error handling
                println!("Error on sending: {}", rc);
                process::exit(1);
            }

            tokio::time::sleep(config.send_delay).await;

            n += 1;

            if config.send_loop {
                exit = false;
            } else {
                exit = n > config.send_count;
            }
        }
    }
    Ok(())
}

pub async fn metrics_handler() -> Result<impl warp::Reply + Clone, warp::Rejection> {
    let encoder = TextEncoder::new();

    let mut buffer = Vec::new();
    let clients = METRICS.lock().to_owned().clients;

    for (_, counters) in clients.iter() {
        let mut tmp_buff = Vec::new();
        if let Err(e) = encoder.encode(&counters.registry.gather(), &mut tmp_buff) {
            eprintln!("could not encode custom metrics: {}", e);
        };
        buffer.append(&mut tmp_buff);
    }

    let res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    Ok(res)
}

// Executable tool, panics should be transformed into human readable errors, (expect or anyhow)
#[tokio::main]
async fn main() -> Result<()> {
    // parse command line params and create config struct
    let config = conf::Config::new().unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(1);
    });

    env_logger::init(); // remove?

    println!("DERP CLI START");

    let verbose = config.verbose;
    let log_file = config.logs_path.clone();

    if config.clients_config.is_some() {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .context("Error setting Ctrl-C handler")?;

        run_with_clients_config(config).await?;

        tokio::spawn(async move {
            let metrics_route = warp::path!("metrics").and_then(metrics_handler);
            warp::serve(metrics_route).run(([0, 0, 0, 0], 8080)).await;
        });

        while running.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        if verbose >= 1 {
            METRICS.lock().to_owned().print_metrics()?;
        }

        METRICS.lock().to_owned().flush_metrics_to_file(log_file)?;
    } else {
        Box::pin(run_without_clients_config(config)).await?;
    }

    println!("DERP CLI FINISHED");
    Ok(())
}
