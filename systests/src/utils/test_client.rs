use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use telio::device::{Device, DeviceConfig};
use telio_crypto::{PublicKey, SecretKey};
use telio_model::{
    config::{Config, Peer, PeerBase},
    event::Event,
    features::{Features, PathType},
    mesh::{ExitNode, NodeState},
};
use telio_utils::Hidden;
use telio_wg::AdapterType;

use super::{derp::get_derp_servers, interface_helper::InterfaceHelper, ip::generate_ipv4};

pub struct TestClient {
    pub ifc_name: String,
    pub ifc_configured: bool,
    pub peer: Peer,
    pub private_key: SecretKey,
    pub ip: IpAddr,
    pub dev: Device,
    pub events: Arc<Mutex<Vec<Event>>>,
}

impl TestClient {
    pub fn generate_clients(
        ids: Vec<&'static str>,
        ifc_helper: &mut InterfaceHelper,
        features: Features,
    ) -> HashMap<&'static str, TestClient> {
        ids.into_iter()
            .map(|id| {
                let private_key = SecretKey::gen();
                let ip = generate_ipv4();
                let peer = Peer {
                    base: PeerBase {
                        identifier: id.to_owned(),
                        public_key: private_key.public(),
                        hostname: Hidden(format!("{id}.nord")),
                        ip_addresses: Some(vec![ip]),
                        nickname: None,
                    },
                    is_local: false,
                    allow_incoming_connections: true,
                    allow_peer_send_files: false,
                    allow_multicast: false,
                    peer_allows_multicast: false,
                };
                let events = Arc::new(Mutex::new(Vec::new()));
                let events_clone = events.clone();
                let event_dispatcher = move |event: Box<Event>| {
                    println!("Event({id}): {event:?}");
                    let mut event_vec = events_clone.lock().unwrap();
                    event_vec.push(*event);
                };
                let dev = Device::new(features.clone(), event_dispatcher, None).unwrap();
                let client = TestClient {
                    ifc_name: ifc_helper.new_ifc_name(),
                    ifc_configured: false,
                    peer,
                    private_key,
                    ip,
                    dev,
                    events,
                };
                (id, client)
            })
            .collect::<HashMap<_, _>>()
    }

    pub fn start(&mut self) {
        self.dev
            .start(&DeviceConfig {
                private_key: self.private_key,
                adapter: AdapterType::BoringTun,
                fwmark: None,
                name: Some(self.ifc_name.to_owned()),
                tun: None,
            })
            .unwrap();
        self.dev.set_fwmark(11673110).unwrap();
    }

    pub fn set_meshnet_config(&mut self, peers: &[&TestClient]) {
        let config = Config {
            this: self.peer.base.clone(),
            peers: Some(
                peers
                    .iter()
                    .filter_map(|client| {
                        if client.peer.base.identifier == self.peer.base.identifier {
                            None
                        } else {
                            Some(client.peer.clone())
                        }
                    })
                    .collect(),
            ),
            derp_servers: Some(get_derp_servers()),
            dns: None,
        };
        self.dev.set_config(&Some(config)).unwrap();
    }

    pub fn connect_to_exit_node(&mut self, node: &ExitNode) {
        self.dev.connect_exit_node(node).unwrap();
    }

    pub fn wait_for_connection_peer(
        &mut self,
        peer_key: PublicKey,
        path_types: &[PathType],
    ) -> Result<(), String> {
        let timeout_millis = 10_000;
        let iteration_wait_millis = 250;
        for _ in 0..(timeout_millis / iteration_wait_millis) {
            std::thread::sleep(std::time::Duration::from_millis(iteration_wait_millis));
            let mut events = self.events.lock().unwrap();
            let last_event = events
                .iter()
                .rev()
                .find(|e| matches!(e, Event::Node { body } if body.public_key == peer_key))
                .cloned();
            events.retain(|e| !matches!(e, Event::Node { body } if body.public_key == peer_key));
            if let Some(Event::Node { body }) = last_event {
                if path_types.contains(&body.path) && matches!(body.state, NodeState::Connected) {
                    return Ok(());
                }
            }
        }
        Err(format!(
            "{} failed to connect to {}",
            self.peer.base.identifier, peer_key
        ))
    }

    pub fn stop(&mut self) {
        self.dev.stop();
    }

    pub fn shutdown(&mut self) {
        self.dev.shutdown_art();
    }
}
