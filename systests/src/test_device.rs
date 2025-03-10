use std::{collections::HashMap, net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use telio_crypto::{PublicKey, SecretKey};
use telio_model::{
    config::{Config, Peer, PeerBase},
    features::PathType,
    mesh::ExitNode,
};
use telio_utils::Hidden;
use telio_wg::AdapterType;

use crate::{
    derp::Derp,
    dns::DnsError,
    utils::{
        interface_helper::InterfaceHelper, ip::generate_ipv4, process_wrapper::ProcessWrapper,
    },
};

#[derive(Serialize, Deserialize)]
pub enum Command {
    Create {
        config: TestDeviceConfig,
    },
    Start {
        adapter_type: AdapterType,
    },
    SetMeshnetConfig {
        config: Config,
    },
    ConnectToExitNode {
        node: ExitNode,
    },
    EnableMagicDns {
        ips: Vec<IpAddr>,
    },
    DisableMagicDns,
    WaitForConnectionPeer {
        pubkey: PublicKey,
        path_types: Vec<PathType>,
    },
    Stop,
    Shutdown,
}

#[derive(Serialize, Deserialize)]
pub struct TestDeviceConfig {
    pub id: String,
    pub ifc_name: String,
    pub private_key: SecretKey,
}

pub struct TestDevice {
    proc: ProcessWrapper,
    pub ifc_name: String,
    pub ip: IpAddr,
    pub peer: Peer,
}

impl TestDevice {
    pub async fn generate_clients(
        ids: Vec<&'static str>,
        ifc_helper: &mut InterfaceHelper,
    ) -> HashMap<&'static str, Self> {
        let mut res = HashMap::with_capacity(ids.len());
        for id in ids {
            res.insert(id, Self::new(id.to_owned(), ifc_helper).await);
        }
        res
    }

    pub async fn new(id: String, ifc_helper: &mut InterfaceHelper) -> Self {
        let private_key = SecretKey::gen();

        let mut proc = ProcessWrapper::new("./target/debug/test_device", id.clone()).unwrap();
        proc.write_stdin(&id).await.unwrap();
        let ifc_name = ifc_helper.new_ifc_name();
        let cmd = Command::Create {
            config: TestDeviceConfig {
                id: id.clone(),
                ifc_name: ifc_name.clone(),
                private_key: private_key.clone(),
            },
        };
        proc.exec_cmd(cmd).await;

        let ip = generate_ipv4();
        let peer = Peer {
            base: PeerBase {
                identifier: id.clone(),
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
            allow_peer_local_network_access: false,
            allow_peer_traffic_routing: false,
        };

        Self {
            proc,
            peer,
            ifc_name,
            ip,
        }
    }

    pub async fn kill(self) {
        self.proc.kill().await;
    }

    pub async fn start(&mut self) {
        let cmd = Command::Start {
            adapter_type: AdapterType::NepTUN,
        };
        self.proc.exec_cmd(cmd).await;
        InterfaceHelper::configure_ifc(&self.ifc_name, self.ip);
    }

    pub fn configure_dns_route(&self) {
        InterfaceHelper::create_meshnet_route(&self.ifc_name);
    }

    pub async fn set_meshnet_config(&mut self, peers: &[&TestDevice]) {
        let config = Config {
            this: self.peer.base.clone(),
            peers: Some(
                peers
                    .iter()
                    .filter_map(|dev| {
                        if self.peer.base.identifier == dev.peer.base.identifier {
                            None
                        } else {
                            Some(dev.peer.clone())
                        }
                    })
                    .collect(),
            ),
            derp_servers: Some(Derp::get_servers()),
            dns: None,
        };
        let cmd = Command::SetMeshnetConfig { config };
        self.proc.exec_cmd(cmd).await;
    }

    pub async fn connect_to_exit_node(&mut self, node: ExitNode) {
        let cmd = Command::ConnectToExitNode { node };
        self.proc.exec_cmd(cmd).await;
    }

    pub async fn enable_magic_dns<A: AsRef<str>>(&mut self, ips: Vec<A>) {
        let ips = ips
            .into_iter()
            .filter_map(|ip| IpAddr::from_str(ip.as_ref()).ok())
            .collect();
        let cmd = Command::EnableMagicDns { ips };
        self.proc.exec_cmd(cmd).await;
    }

    pub async fn disable_magic_dns(&mut self) {
        let cmd = Command::DisableMagicDns;
        self.proc.exec_cmd(cmd).await;
    }

    pub async fn query_dns(&self, host: &str, expected: IpAddr) -> Result<(), DnsError> {
        let result = crate::dns::Dns::send_query(self.ip, host.to_owned()).await?;
        if result != expected {
            return Err(DnsError::WrongIp(result));
        }
        Ok(())
    }

    pub async fn wait_for_connection_peer(
        &mut self,
        peer_key: PublicKey,
        path_types: &[PathType],
    ) -> Result<(), String> {
        let cmd = Command::WaitForConnectionPeer {
            pubkey: peer_key,
            path_types: path_types.to_vec(),
        };
        let cmd = serde_json::to_string(&cmd).unwrap();
        self.proc.write_stdin(&cmd).await.unwrap();
        while let Some(line) = self.proc.read_stdout().await {
            match line.as_str() {
                "connected" => return Ok(()),
                "not connected" => return Err("Could not connect".to_owned()),
                _ => {}
            }
        }
        Ok(())
    }

    pub async fn stop(&mut self) {
        let cmd = Command::Stop;
        self.proc.exec_cmd(cmd).await;
    }

    pub async fn shutdown(&mut self) {
        let cmd = Command::Shutdown;
        self.proc.exec_cmd(cmd).await;
    }
}
