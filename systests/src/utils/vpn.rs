use std::net::IpAddr;

use base64::{prelude::BASE64_STANDARD, Engine};
use telio_crypto::SecretKey;
use telio_model::config::Peer;

use super::process::run_command;

pub struct VpnConfig {
    pub ip: IpAddr,
    pub port: u16,
    pub key: SecretKey,
    pub container: String,
}

impl VpnConfig {
    fn key(&self) -> String {
        let key_bytes = self.key.as_bytes();
        let mut buf = [0u8; 44];
        let _ = BASE64_STANDARD.encode_slice(key_bytes, &mut buf);
        String::from_utf8(buf.to_vec()).unwrap_or_else(|_| "Invalid key".to_owned())
    }
}

impl VpnConfig {
    pub fn get_config() -> Self {
        VpnConfig {
            ip: "10.0.100.1".parse().unwrap(),
            port: 1023,
            key: SecretKey::gen(),
            container: "nat-lab-vpn-01-1".to_owned(),
        }
    }
}

pub fn setup_vpn_servers(peers: &[&Peer], vpn_config: &VpnConfig) {
    let mut wg_conf = format!(
        "[Interface]\nPrivateKey = {}\nListenPort = {}\nAddress = 100.64.0.1/10\n\n",
        vpn_config.key(),
        vpn_config.port
    );
    let peer_config = peers.iter().map(|peer| {
        let allowed_ips = peer
            .base
            .ip_addresses
            .as_ref()
            .map(|ips| {
                ips.iter()
                    .filter_map(|ip| {
                        if matches!(ip, IpAddr::V4(_)) {
                            Some(format!("{ip}/32"))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        format!(
            "[Peer]\nPublicKey = {}\nAllowedIPs = {allowed_ips}\n\n",
            peer.public_key
        )
    });
    wg_conf.extend(peer_config);
    let docker_command = format!("echo \"{}\" > /etc/wireguard/wg0.conf; wg-quick down /etc/wireguard/wg0.conf; wg-quick up /etc/wireguard/wg0.conf", wg_conf);

    run_command(
        &[
            "docker",
            "exec",
            "--privileged",
            vpn_config.container.as_str(),
            "bash",
            "-c",
            docker_command.as_str(),
        ],
        &[],
    )
    .unwrap();
}
