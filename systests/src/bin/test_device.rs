use std::{
    io::{BufRead, BufReader},
    net::IpAddr,
    sync::Arc,
};

use parking_lot::Mutex;
use systests::test_device::{Command, TestDeviceConfig};
use telio::{
    defaults_builder::FeaturesDefaultsBuilder,
    device::{Device, DeviceConfig},
};
use telio_crypto::SecretKey;
use telio_model::{
    config::Config,
    event::Event,
    features::PathType,
    mesh::{ExitNode, NodeState},
    PublicKey,
};
use telio_wg::AdapterType;
use tracing::level_filters::LevelFilter;

fn main() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    let id = match reader.next() {
        Some(Ok(line)) => line,
        _ => {
            println!("error");
            return Err(anyhow::anyhow!("Failed to read device id"));
        }
    };

    let (non_blocking_writer, _tracing_worker_guard) =
        tracing_appender::non_blocking(std::fs::File::create(format!("tcli-{}.log", id)).unwrap());
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let mut device: Option<TestDevice> = None;

    for line in reader {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                println!("Failed to read from stdin with error: {e:?}");
                continue;
            }
        };
        match serde_json::from_str::<Command>(&line) {
            Ok(cmd) => match cmd {
                Command::Create { config } => {
                    println!("Create");
                    match device.is_none() {
                        true => {
                            device = Some(TestDevice::create(config));
                            println!("done");
                        }
                        false => {
                            println!("error");
                        }
                    }
                }
                Command::Start { adapter_type } => {
                    println!("Start");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.start(adapter_type);
                            println!("done");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
                Command::SetMeshnetConfig { config } => {
                    println!("SetMeshnetConfig");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.set_meshnet_config(config);
                            println!("done");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
                Command::ConnectToExitNode { node } => {
                    println!("ConnectToExitNode");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.connect_to_exit_node(&node);
                            println!("done");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
                Command::EnableMagicDns { ips } => {
                    println!("EnableMagicDns");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.enable_magic_dns(ips);
                            println!("done");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
                Command::DisableMagicDns => {
                    println!("DisableMagicDns");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.disable_magic_dns();
                            println!("done");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
                Command::WaitForConnectionPeer { pubkey, path_types } => {
                    println!("WaitForConnectionPeer {pubkey:?}");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.wait_for_connection_peer(pubkey, &path_types);
                            println!("connected");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
                Command::Stop => {
                    println!("Stop");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.stop();
                            println!("done");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
                Command::Shutdown => {
                    println!("Shutdown");
                    match &mut device {
                        Some(ref mut dev) => {
                            dev.shutdown();
                            println!("done");
                        }
                        _ => {
                            println!("error");
                        }
                    }
                }
            },
            Err(e) => println!("Failed to deserialize with error {e:?}"),
        }
    }

    Ok(())
}

struct TestDevice {
    pub id: String,
    pub ifc_name: String,
    pub ifc_configured: bool,
    pub private_key: SecretKey,
    pub dev: Device,
    pub events: Arc<Mutex<Vec<Event>>>,
}

impl TestDevice {
    pub fn create(config: TestDeviceConfig) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();
        let event_id = config.id.clone();
        let event_dispatcher = move |event: Box<Event>| {
            println!("Event({event_id}): {event:?}");
            let mut event_vec = events_clone.lock();
            event_vec.push(*event);
        };
        let features = Arc::new(FeaturesDefaultsBuilder::new());
        let features = features.enable_direct().build();
        let dev = Device::new(features, event_dispatcher, None).unwrap();
        Self {
            id: config.id,
            ifc_name: config.ifc_name,
            ifc_configured: false,
            private_key: config.private_key,
            dev,
            events,
        }
    }

    pub fn start(&mut self, adapter: AdapterType) {
        let config = DeviceConfig {
            private_key: self.private_key.clone(),
            adapter,
            fwmark: None,
            name: Some(self.ifc_name.to_owned()),
            tun: None,
        };
        self.dev.start(&config).unwrap();
        self.dev.set_fwmark(11673110).unwrap();
    }

    pub fn set_meshnet_config(&mut self, config: Config) {
        self.dev.set_config(&Some(config)).unwrap();
    }

    pub fn connect_to_exit_node(&mut self, node: &ExitNode) {
        self.dev.connect_exit_node(node).unwrap();
    }

    pub fn enable_magic_dns(&mut self, ips: Vec<IpAddr>) {
        self.dev.enable_magic_dns(&ips).unwrap();
    }

    pub fn disable_magic_dns(&mut self) {
        self.dev.disable_magic_dns().unwrap();
    }

    pub fn wait_for_connection_peer(&mut self, peer_key: PublicKey, path_types: &[PathType]) {
        let iteration_wait_millis = 250;
        loop {
            let mut events = self.events.lock();
            let last_event = events
                .iter()
                .rev()
                .find(|e| matches!(e, Event::Node { body } if body.public_key == peer_key))
                .cloned();
            events.retain(|e| !matches!(e, Event::Node { body } if body.public_key == peer_key));
            if let Some(Event::Node { body }) = last_event {
                if path_types.contains(&body.path) && matches!(body.state, NodeState::Connected) {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(iteration_wait_millis));
        }
    }

    pub fn stop(&mut self) {
        self.dev.stop();
    }

    pub fn shutdown(&mut self) {
        self.dev.shutdown_art();
    }
}
