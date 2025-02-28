use anyhow::anyhow;
use base64::prelude::*;
use clap::{Arg, ArgAction, Command};
use crypto_box::PublicKey as BoxPublicKey;
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use telio_crypto::{SecretKey, KEY_SIZE};

#[derive(Clone)]
pub struct ClientConfig {
    pub private_key: SecretKey,
    pub derp_server: String,
    pub peers: Vec<SecretKey>,
}

#[derive(Deserialize)]
pub struct StressConfig {
    /// Clients to generate (for this app instance), must be even, generated in pairs
    pub client_count: usize,
    /// Interval in seconds lower bound for random
    pub interval_min: usize,
    /// Interval in seconds upper bound for random
    /// If max<=min then min is used, no randomness
    pub interval_max: usize,
    /// Payload size in bytes, lower bound for random
    pub payload_min: usize,
    /// Payload size in bytes, upper bound for random
    /// If max<=min then min is used, no randomness
    pub payload_max: usize,
    /// Should client1 (from pair) send packets
    pub client1_pinger: bool,
    /// Should client2 (from pair) send packets
    pub client2_pinger: bool,
    /// Derp for client1 is selected by incrementing the index of the prev pair client1
    /// 0 => client1 (from pair) will use 0 (first derp) from derps list
    /// 1 => client1 (from pair) will use 0,1,2,.. form derps list (ring)
    /// 2 => client1 (from pair) will use 0,2,4,.. form derps list (ring)
    pub derp1_increment: usize,
    /// Client2 derp index := client1 derp index + derp2_offset
    pub derp2_offset: usize,
    /// Derp list/ring
    pub derps: Vec<String>,
    /// Add RTT from 0=none, 1=every, 2=every 2nd, 3=every 3rd, ... packet into statistics
    pub stats_take_every: usize,
}

pub struct Config {
    // http address to server
    pub server: String,
    // if run as receiving target
    pub is_target: bool,
    // sender private key
    pub my_key: SecretKey,
    // target private key to make public key
    pub target_key: SecretKey,
    // send count
    pub send_count: i32,
    // send dealy ms
    pub send_delay: std::time::Duration,
    // if loop until interrupted
    pub send_loop: bool,
    // what data to send
    pub send_data: String,
    // what data size to generate
    pub send_size: u16,
    // track if end_size param is present
    pub send_size_enabled: bool,
    // verbose output
    pub verbose: u64,
    // Instead of using OS certificate store, use the mozzila built in roots
    pub use_built_in_root_certificates: bool,
    // path to config file used for stress-test
    pub stress_cfg_path: PathBuf,
}

impl StressConfig {
    pub fn new() -> Self {
        Self {
            client_count: 2,
            interval_min: 1000,
            interval_max: 2000,
            payload_min: 128,
            payload_max: 386,
            client1_pinger: true,
            client2_pinger: false,
            derp1_increment: 0,
            derp2_offset: 0,
            derps: vec![],
            stats_take_every: 1,
        }
    }
}

impl Config {
    pub fn get_key1(&self) -> crypto_box::SecretKey {
        self.my_key.clone().into()
    }
    pub fn get_key2(&self) -> crypto_box::SecretKey {
        self.target_key.clone().into()
    }
    pub fn get_pub_key1(&self) -> crypto_box::PublicKey {
        BoxPublicKey::from(&self.get_key1())
    }
    pub fn get_pub_key2(&self) -> crypto_box::PublicKey {
        BoxPublicKey::from(&self.get_key2())
    }
    pub fn get_pub_key1_b64(&self) -> String {
        BASE64_STANDARD.encode(self.get_pub_key1().as_bytes())
    }
    pub fn get_pub_key2_b64(&self) -> String {
        BASE64_STANDARD.encode(self.get_pub_key2().as_bytes())
    }
    pub fn get_server_address(&self) -> &str {
        &self.server
    }
    pub fn print(&self) {
        println!(
            "server address: {}, {}",
            self.get_server_address(),
            if self.is_target {
                "receiving client"
            } else {
                "sending client"
            }
        );
        println!(
            "{}, send delay: {} ms",
            if self.send_loop {
                "loop sending until interrupted".to_string()
            } else {
                format!("send count: {}", self.send_count)
            },
            self.send_delay.as_millis()
        );
        println!("PubKey1/e64 {}", self.get_pub_key1_b64());
        println!("PubKey2/e64 {}", self.get_pub_key2_b64());
    }

    pub fn new() -> anyhow::Result<Self> {
        // initialize command line params parser
        let matches = Command::new("DERP cli")
            .about("Command line utility to perform DERP tests")
            .version("2.0")
            .arg(
                Arg::new("server")
                    .help("Server address")
                    .required(false)
                    .num_args(1)
                    .long("server")
                    .default_value("http://localhost:1234")
                    .short('s'),
            )
            .arg(
                Arg::new("target")
                    .help("Run as target")
                    .required(false)
                    .long("target")
                    .short('t'),
            )
            .arg(
                Arg::new("mykey")
                    .help("My private key base64 encoded")
                    .required(false)
                    .num_args(1)
                    .long("mykey")
                    .short('m'),
            )
            .arg(
                Arg::new("targetkey")
                    .help("Target peer private key base64 encoded")
                    .required(false)
                    .num_args(1)
                    .long("targetkey")
                    .short('k'),
            )
            .arg(
                Arg::new("count")
                    .help("Count of iterations to run")
                    .required(false)
                    .num_args(1)
                    .long("count")
                    .default_value("3")
                    .short('c'),
            )
            .arg(
                Arg::new("loop")
                    .help("Loop until interrupted")
                    .required(false)
                    .long("loop")
                    .short('l'),
            )
            .arg(
                Arg::new("delay")
                    .help("Delay ms between iterations")
                    .required(false)
                    .num_args(1)
                    .long("delay")
                    .default_value("100")
                    .short('d'),
            )
            .arg(
                Arg::new("data")
                    .help("Data text to send, <to be implemented>")
                    .required(false)
                    .num_args(1)
                    .long("data")
                    .default_value("hello derp!")
                    .short('a'),
            )
            .arg(
                Arg::new("size")
                    .help("Data text size to generate and send")
                    .required(false)
                    .num_args(1)
                    .long("size")
                    .short('z'),
            )
            .arg(
                Arg::new("verbose")
                    .help("Verbose output (can use multiple)")
                    .required(false)
                    .action(ArgAction::Count)
                    .long("verbose")
                    .short('v'),
            )
            .arg(
                Arg::new("config")
                    .help("Path to config file")
                    .required(false)
                    .num_args(1)
                    .long("config")
                    .short('f'),
            )
            .arg(
                Arg::new("output")
                    .help("Path to logs output file")
                    .required(false)
                    .num_args(1)
                    .default_value("")
                    .long("output")
                    .short('o'),
            )
            .arg(
                Arg::new("use_built_in_root_certificates")
                    .help("Instead of using OS certificate store, use the mozzila built in roots")
                    .required(false)
                    .long("use_built_in_root_certificates"),
            )
            .get_matches();

        // parse command line params
        let server_addr = matches
            .get_one::<String>("server")
            .cloned()
            .unwrap_or("http://localhost:3340".into());

        let is_target = matches.contains_id("target");

        let count = matches
            .get_one::<String>("count")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(3);

        let delay = matches
            .get_one::<String>("delay")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100);

        let data_str = matches
            .get_one("data")
            .map_or("hello derp!", String::as_str);

        let data_size = matches
            .get_one::<String>("size")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or_default();

        let stress_cfg_path = matches
            .get_one::<String>("config")
            .cloned()
            .unwrap_or_default();

        // keys for peer identification in manual mode
        let mut secret_key1 = [0_u8; KEY_SIZE];
        let mut secret_key2 = [1_u8; KEY_SIZE];

        let mykey_str = matches.get_one("mykey").map_or("", String::as_str);
        let targetkey_str = matches.get_one("targetkey").map_or("", String::as_str);

        // check if my private key is given as param
        if mykey_str.chars().count() > 0 {
            let mykey_bytes = BASE64_STANDARD.decode(mykey_str).unwrap_or_default();
            if mykey_bytes.len() != 32 {
                return Err(anyhow!(
                    "My private key size must be 32 bytes encoded into base64!",
                ));
            }
            secret_key1.copy_from_slice(
                &mykey_bytes
                    .get(0..32)
                    .ok_or_else(|| anyhow!("Out of bounds mykey list"))?,
            );
        }

        if targetkey_str.chars().count() > 0 {
            let tkey_bytes = BASE64_STANDARD.decode(targetkey_str).unwrap_or_default();
            if tkey_bytes.len() != 32 {
                return Err(anyhow!(
                    "Target private key size must be 32 bytes encoded into base64!",
                ));
            }
            secret_key2.copy_from_slice(
                &tkey_bytes
                    .get(0..32)
                    .ok_or_else(|| anyhow!("Out of bounds tkey list"))?,
            );
        }

        // switch keys ir run as target
        if is_target {
            std::mem::swap(&mut secret_key2, &mut secret_key1)
        }

        Ok(Self {
            server: server_addr,
            is_target,
            my_key: SecretKey::new(secret_key1),
            target_key: SecretKey::new(secret_key2),
            send_count: count,
            send_delay: Duration::from_millis(if delay > 5000 { 5000 } else { delay }),
            send_loop: matches.contains_id("loop"),
            send_data: data_str.to_owned(),
            send_size: if data_size > 8000 { 8000 } else { data_size },
            send_size_enabled: matches.contains_id("size"),
            verbose: matches.get_count("verbose") as u64,
            stress_cfg_path: Path::new(&stress_cfg_path).to_path_buf(),
            use_built_in_root_certificates: matches.contains_id("use_built_in_root_certificates"),
        })
    }

    pub fn load_stress_config(path: &str) -> Option<StressConfig> {
        if let Ok(file) = fs::File::open(path) {
            let updated: serde_json::Result<StressConfig> = serde_json::from_reader(file);
            match updated {
                Ok(x) => return Some(x),
                Err(e) => println!("ERROR: {}", e),
            }
        }
        None
    }
}
