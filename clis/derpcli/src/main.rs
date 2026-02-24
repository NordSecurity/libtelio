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
//!     -C, --CA <path>                Path to CA.pem file [default: ""]
//!     -f, --config <path>            Path to config file, it is reloaded in runtime
//!
//!
//! #1 Manual test example:
//!
//! example cli to run as receiving client:
//! $ derpcli -s http://myderp:3340 -m MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMQo= -k MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMgo= -t
//!
//! example cli to run as sending client:
//! $ derpcli -s http://myderp:3340 -m MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMQo= -k MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMgo= -c 20 -d 500
//!
//!
//! #2 Stress-test example:
//!
//! $ derpcli --config <path_to_cfg> -C <ca.pem> -v
//!
//! Config file example:
//!     {
//!       "client_count": 4,
//!       "interval_min": 1000,
//!       "interval_max": 2000,
//!       "payload_min": 128,
//!       "payload_max": 386,
//!       "client1_pinger": true,
//!       "client2_pinger": false,
//!       "derp1_increment": 1,
//!       "derp2_offset": 0,
//!       "derps": [
//!         "https://derp-a:8765",
//!         "https://derp-b:8765"
//!       ],
//!       "stats_take_every": 1
//!     }
//!
//! ```

#![allow(unknown_lints)]

mod conf;
mod metrics;

use anyhow::{anyhow, bail, Result};
use atomic_counter::{AtomicCounter, RelaxedCounter};
use base64::prelude::*;
use conf::StressConfig;
use metrics::Metrics;
use rand::RngExt;
use std::{
    io::{self, Write},
    net::SocketAddr,
    process::exit as process_exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use telio_crypto::SecretKey;
use telio_relay::{derp::Config, http::connect_http_and_start};
use telio_sockets::{NativeProtector, SocketPool};
use time::macros::format_description;
use tokio::{
    net::lookup_host,
    sync::{Mutex, RwLock},
    time::Duration,
};

use url::{Host, Url};

fn get_client_debug_key(client: &conf::ClientConfig) -> String {
    let public_key = client.private_key.public();

    if let Some(substring) = public_key.to_string().get(0..4) {
        String::from(substring)
    } else {
        println!("Invalid range for client public key");
        String::from("")
    }
}

fn get_mtime(path: &str) -> u64 {
    fn get_mtime_aux(path: &str) -> Option<u64> {
        let meta = std::fs::metadata(path).ok()?;
        let ftime = meta.modified().ok()?;
        let elapsed = ftime.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some(elapsed.as_millis() as u64)
    }
    get_mtime_aux(path).unwrap_or_default()
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
        println!("* Resolving {}", hostport);
    }
    let addrs = lookup_host(hostport).await?.collect::<Vec<SocketAddr>>();

    if addrs.is_empty() {
        bail!("ERROR: Failed to resolve domain: {}", domain);
    }

    Ok(addrs)
}

#[allow(clippy::too_many_arguments)]
#[allow(mpsc_blocking_send)]
async fn connect_client(
    pool: Arc<SocketPool>,
    client: conf::ClientConfig,
    verbosity: u64,
    addrs: Vec<SocketAddr>,
    stress_cfg: Arc<RwLock<conf::StressConfig>>,
    metrics: Arc<Mutex<Metrics>>,
    pinger: bool,
    rx_packet_counter: Arc<RelaxedCounter>,
) -> Result<()> {
    let verbose = verbosity >= 1;
    let mut derp_conn = match Box::pin(connect_http_and_start(
        pool,
        &client.derp_server,
        *addrs.first().ok_or_else(|| anyhow!("Empty socket Addr"))?,
        Config {
            secret_key: client.private_key.clone(),
            timeout: Duration::from_secs(10),
            ..Default::default()
        },
    ))
    .await
    {
        Ok(tup) => tup,
        Err(err) => {
            println!(
                "ERROR: [{}] -> Failed to connect to derp server -> {}",
                get_client_debug_key(&client),
                &err
            );
            bail!("{}", err)
        }
    };

    metrics.lock().await.inc_clients();
    let stats_take_every = stress_cfg.read().await.stats_take_every;

    let _ = tokio::spawn({
        let client = client.clone();
        let comm_tx = derp_conn.comms_relayed.tx.clone();
        async move {
            if verbose {
                println!("* [{}] -> TX START", get_client_debug_key(&client),);
            }
            let mut prev_interval = 0.0;

            loop {
                if !pinger {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    continue;
                }

                let (interval_len, payload_len) = {
                    let s = stress_cfg.read().await;
                    let mut rng = rand::rng();
                    let interval_len = if s.interval_min < s.interval_max {
                        rng.random_range(s.interval_min..s.interval_max)
                    } else {
                        s.interval_min
                    };
                    let payload_len = if s.payload_min < s.payload_max {
                        rng.random_range(s.payload_min..s.payload_max)
                    } else {
                        s.payload_min
                    };
                    (interval_len as u64, payload_len)
                };

                for peer in client.peers.iter() {
                    if verbose {
                        let receiver_pub_key: telio_crypto::PublicKey = peer.public();
                        println!(
                            "* [{}] -> Send {}B via [{}] to [{}], after {:.3}s",
                            get_client_debug_key(&client),
                            payload_len,
                            client.derp_server.get(8..15).unwrap_or_default(),
                            &receiver_pub_key.to_string().get(0..4).unwrap_or_default(),
                            prev_interval,
                        );
                    }
                    let public_key = peer.public();
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let mut payload = vec![0; payload_len];
                    if payload_len > 7 {
                        // Write 8 bytes Timestamp (ms) into payload
                        payload
                            .get_mut(0..8)
                            .unwrap_or_default()
                            .clone_from_slice(&timestamp.to_ne_bytes());
                    }
                    if payload_len > 16 {
                        // Write 7 chars of first derp name (after https://<7chars>) into payload
                        payload.get_mut(8..15).unwrap_or_default().clone_from_slice(
                            &client.derp_server.as_bytes().get(8..15).unwrap_or_default(),
                        );
                    }

                    if let Err(rc) = comm_tx.send((public_key, payload)).await {
                        println!(
                            "* [{}] -> Error on sending: {}",
                            get_client_debug_key(&client),
                            rc
                        );
                        process_exit(1);
                    }
                }

                tokio::time::sleep(Duration::from_millis(interval_len)).await;
                prev_interval = interval_len as f64 / 1000.0;
            }
        }
    });

    let _ = tokio::spawn({
        let client = client.clone();
        async move {
            if verbose {
                println!("* [{}] -> RX START", get_client_debug_key(&client),);
            }
            loop {
                match derp_conn.comms_relayed.rx.recv().await {
                    Some((sender_pub_key, payload)) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let payload_len = payload.len();
                        let rtt = if payload_len > 7 {
                            // Read 8 byte Timestamp (ms) from payload
                            let mut send_time = [0u8; 8];
                            send_time
                                .get_mut(..8)
                                .unwrap_or_default()
                                .copy_from_slice(&payload.get(..8).unwrap_or_default());
                            now - u64::from_ne_bytes(send_time)
                        } else {
                            0
                        };

                        let first_derp = match payload.get(8..15) {
                            Some(payload) => {
                                String::from_utf8(payload.to_vec()).unwrap_or_default()
                            }
                            None => "unknown".to_owned(),
                        };

                        if stats_take_every > 0 {
                            let counter = (*rx_packet_counter).inc();
                            if counter % stats_take_every == 0 {
                                metrics.lock().await.add_rtt(now, rtt as u16, first_derp);
                            }
                        }

                        if verbose {
                            println!(
                                "* [{}] -> Recv {}B from [{}], RTT: {}ms",
                                get_client_debug_key(&client),
                                payload_len,
                                &sender_pub_key.to_string().get(0..4).unwrap_or_default(),
                                rtt
                            );
                        }
                    }
                    None => {
                        if verbose {
                            println!("WARNING: Received unknown packet, ignoring");
                        }
                        continue;
                    }
                }
            }
        }
    });

    Ok(())
}

#[allow(mpsc_blocking_send)]
async fn run_without_clients_config(config: conf::Config) -> Result<()> {
    config.print();

    let addrs = resolve_domain_name(config.get_server_address(), config.verbose).await?;

    let mut derp_conn = match Box::pin(connect_http_and_start(
        Arc::new(SocketPool::new(NativeProtector::new(
            #[cfg(target_os = "macos")]
            false,
        )?)),
        config.get_server_address(),
        *addrs
            .first()
            .ok_or_else(|| anyhow!("ERR!! Empty server addr"))?,
        Config {
            secret_key: config.my_key.clone(),
            timeout: Duration::from_secs(5),
            use_built_in_root_certificates: config.use_built_in_root_certificates,
            ..Default::default()
        },
    ))
    .await
    {
        Ok(tup) => tup,
        Err(err) => {
            println!("ERROR: Connect to DERP -> {}", err);
            return Ok(());
        }
    };

    if config.is_target {
        // if running as target - just wait for incomming messages
        if config.verbose > 0 {
            println!("Waiting for messages...")
        }

        loop {
            let (public_key, data) = derp_conn
                .comms_relayed
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
                        BASE64_STANDARD.encode(public_key),
                        String::from_utf8_lossy(&data)
                    )
                }
                _ => {}
            }
        }
    } else {
        // if running as sender - send series of messages
        let mut counter = 1;
        let mut exit = false;
        let pkey = config.target_key.public();

        println!("DERP CLI SENDING");

        while !exit {
            let data = if config.send_size_enabled {
                create_buffer(config.send_size as usize, counter)
            } else {
                format!("{} {}", config.send_data.to_string(), counter)
            };

            if config.verbose == 1 {
                print!(".");
                io::stdout().flush()?;
            } else if config.verbose > 2 {
                println!(
                    "SENDING: [{}] -> [{}] -> [{}]",
                    &config.get_pub_key1_b64(),
                    data,
                    &config.get_pub_key2_b64()
                )
            }

            if let Err(rc) = derp_conn
                .comms_relayed
                .tx
                .send((pkey, data.as_bytes().to_vec()))
                .await
            {
                // error handling
                println!("Error on sending: {}", rc);
                process_exit(1);
            }

            tokio::time::sleep(config.send_delay).await;

            counter += 1;

            if config.send_loop {
                exit = false;
            } else {
                exit = counter > config.send_count;
            }
        }
    }
    Ok(())
}

#[allow(clippy::indexing_slicing)]
fn create_buffer(size: usize, counter: i32) -> String {
    let mut buf = format!("{}B", size);
    let middle_point = buf.len();
    buf.insert_str(middle_point, &format!("#{}", counter));
    let filler = ".".repeat(if size > buf.len() {
        size - buf.len()
    } else {
        0
    });
    buf.insert_str(middle_point, &filler);
    buf[buf.len() - size..].to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    // parse command line params and create config struct
    let config = conf::Config::new().unwrap_or_else(|e| {
        println!("{}", e);
        process_exit(1);
    });

    if config.stress_cfg_path.exists() {
        run_stress_test(config).await;
    } else {
        Box::pin(run_without_clients_config(config)).await?;
    }

    Ok(())
}

async fn run_stress_test(config: conf::Config) {
    let app_is_running = Arc::new(AtomicBool::new(true));
    let r = app_is_running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let stress_cfg_path: String = String::from(config.stress_cfg_path.to_string_lossy());
    let metrics = Arc::new(Mutex::new(Metrics::new()));
    let rx_packet_counter = Arc::new(RelaxedCounter::new(0));
    let stress_cfg = Arc::new(RwLock::new(StressConfig::new()));
    let mut last_mtime = 0;

    while app_is_running.load(Ordering::SeqCst) {
        let mtime = get_mtime(&stress_cfg_path);
        if last_mtime == 0 || last_mtime != mtime {
            if let Some(stress_cfg_updated) = conf::Config::load_stress_config(&stress_cfg_path) {
                *stress_cfg.write().await = stress_cfg_updated;
                last_mtime = mtime;
            }
        }

        let res = run_with_clients_config(
            stress_cfg.clone(),
            metrics.clone(),
            app_is_running.clone(),
            config.verbose,
            rx_packet_counter.clone(),
        )
        .await;

        if let Err(e) = res {
            println!("ERROR: {}", e);
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn run_with_clients_config(
    stress_cfg: Arc<RwLock<conf::StressConfig>>,
    metrics: Arc<Mutex<Metrics>>,
    running: Arc<AtomicBool>,
    verbose: u64,
    rx_packet_counter: Arc<RelaxedCounter>,
) -> Result<()> {
    let (client_count_goal, derps, stats_take_every) = {
        let c = stress_cfg.read().await;
        (c.client_count, c.derps.clone(), c.stats_take_every)
    };
    let initial_client_count = metrics.lock().await.get_clients();
    let client_pair_delta = (client_count_goal as isize - initial_client_count as isize) / 2;

    if derps.len() == 0 {
        println!("WARNING: No DERPs defined");
        return Ok(());
    }

    if client_pair_delta == 0 {
        println!(
            "{} Clients: {}",
            time::OffsetDateTime::now_local()?
                .format(format_description!("[hour]:[minute]:[second]"))?,
            initial_client_count
        );
        if stats_take_every > 0 {
            metrics.lock().await.print_rtts();
        }
        return Ok(()); // Expected client count not changed, no action is required
    };

    println!(
        "[{}]  Clients: {}, GOAL: {}",
        time::OffsetDateTime::now_local()?.format(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))?,
        initial_client_count,
        client_count_goal
    );

    if client_pair_delta < 0 {
        println!("WARNING: Client deletion not implemented");
        return Ok(());
    }

    println!("* Adding {} client pairs", client_pair_delta);

    // Resolving DEPRs
    let derps_resolved = {
        let mut resolved = vec![];
        for derp in &derps {
            let addrs = match resolve_domain_name(&derp, verbose).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    println!("Failed to resolve derp name {} -> {}", derp, e);
                    return Err(e);
                }
            };
            resolved.push(addrs);
        }
        resolved
    };
    println!("DERPS resolved: {:?}", derps_resolved);
    if derps_resolved.len() == 0 {
        println!("WARNING: No DERPs resolved");
        return Ok(());
    }

    // Add client pairs
    let pool = Arc::new(SocketPool::new(NativeProtector::new(
        #[cfg(target_os = "macos")]
        false,
    )?));

    let mut additional_client_count = 0;
    let mut remaining_pairs_to_add = client_pair_delta;
    while running.load(Ordering::SeqCst) {
        let pairs_to_add_now = std::cmp::min(remaining_pairs_to_add, 250);

        let mut futs = vec![];
        for _pair_nr in 0..pairs_to_add_now {
            let (client1_pinger, client2_pinger, derp1_increment, derp2_offset) = {
                let s = stress_cfg.read().await;
                (
                    s.client1_pinger,
                    s.client2_pinger,
                    s.derp1_increment,
                    s.derp2_offset,
                )
            };

            let last_client_pair = (initial_client_count + additional_client_count) / 2;
            let derp1_nr = (last_client_pair * derp1_increment) % derps.len();
            let derp2_nr = (derp1_nr + derp2_offset) % derps.len();
            let key1 = SecretKey::gen();
            let key2 = SecretKey::gen();
            let derps1 = derps
                .get(derp1_nr)
                .ok_or_else(|| anyhow!("Err! No derp found"))?
                .to_string();
            let derps2 = derps
                .get(derp2_nr)
                .ok_or_else(|| anyhow!("Err! No derp found"))?
                .to_string();
            let derps_resolved1 = derps_resolved
                .get(derp1_nr)
                .ok_or_else(|| anyhow!("Err! No derp found"))?
                .clone();
            let derps_resolved2 = derps_resolved
                .get(derp2_nr)
                .ok_or_else(|| anyhow!("Err! No derp found"))?
                .clone();
            let client1 = conf::ClientConfig {
                private_key: key1.clone(),
                derp_server: derps1,
                peers: vec![key2.clone()],
            };
            let client2 = conf::ClientConfig {
                private_key: key2,
                derp_server: derps2,
                peers: vec![key1],
            };
            futs.push(connect_client(
                pool.clone(),
                client1,
                verbose,
                derps_resolved1.clone(),
                stress_cfg.clone(),
                metrics.clone(),
                client1_pinger,
                rx_packet_counter.clone(),
            ));
            futs.push(connect_client(
                pool.clone(),
                client2,
                verbose,
                derps_resolved2.clone(),
                stress_cfg.clone(),
                metrics.clone(),
                client2_pinger,
                rx_packet_counter.clone(),
            ));

            additional_client_count += 2;

            if futs.len() == 20 {
                println!("* Adding clients => {}", additional_client_count);
                futures::future::join_all(futs.drain(..)).await;
            }
        }

        println!("* Adding clients => {}", additional_client_count);
        futures::future::join_all(futs.drain(..)).await;

        remaining_pairs_to_add -= pairs_to_add_now;
        if remaining_pairs_to_add > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        } else {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case(00, 001, "")]
    #[case(01, 001, "1")]
    #[case(01, 002, "2")]
    #[case(01, 010, "0")]
    #[case(02, 001, "#1")]
    #[case(02, 002, "#2")]
    #[case(02, 010, "10")]
    #[case(05, 001, "5B.#1")]
    #[case(05, 002, "5B.#2")]
    #[case(05, 010, "5B#10")]
    #[case(10, 001, "10B.....#1")]
    #[case(10, 002, "10B.....#2")]
    #[case(10, 010, "10B....#10")]
    #[case(10, 100, "10B...#100")]
    fn test_create_buffer(#[case] size: usize, #[case] counter: i32, #[case] expected_buf: String) {
        assert_eq!(create_buffer(size, counter), expected_buf);
    }
}
