use std::{collections::HashMap, os::fd::AsRawFd, sync::Arc, time::Duration};

use telio_model::PublicKey;

pub struct WgDevice {
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub replace_peers: Option<bool>,
    pub peers: Vec<WgPeer>,
}

pub struct WgInterface {
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub fwmark: u32,
    pub peers: HashMap<String, WgPeer>,
}

pub struct WgResponse {
    pub errno: i32,
    pub interface: Option<WgInterface>,
}

pub struct WgPeer {
    pub public_key: String,
    /// Peer's endpoint with `IP address` and `UDP port` number
    pub endpoint: Option<String>,
    /// At what point in time, was last endpoint changed
    // TODO: pub endpoint_changed_at: Option<(Instant, UpdateReason)>,
    /// Mesh's IP addresses of peer
    pub ip_addresses: Vec<String>,
    /// Keep alive interval, `seconds` or `None`
    pub persistent_keepalive_interval: Option<u32>,
    /// Vector of allowed IPs
    pub allowed_ips: Vec<String>,
    /// Number of bytes received or `None`(unused on Set)
    pub rx_bytes: Option<u64>,
    /// Time since last byte has been received from this peer. This is a synthetic
    /// field, not present in the wireguard natively. It will be filled in in the
    /// wg module when syncthing.
    pub time_since_last_rx_ms: Option<u64 /* Duration */>,
    /// Number of bytes transmitted or `None`(unused on Set)
    pub tx_bytes: Option<u64>,
    /// Time since last handshakeor `None`, differs from WireGuard field meaning
    pub time_since_last_handshake_ms: Option<u64 /* Duration*/>,
    // The peer's preshared key
    // TODO: pub preshared_key: Option<PresharedKey>,
}

impl Into<WgPeer> for wireguard_uapi::xplatform::set::Peer {
    fn into(self) -> WgPeer {
        WgPeer {
            public_key: PublicKey::new(self.public_key).to_string(),
            endpoint: self.endpoint.map(|e| e.to_string()),
            ip_addresses: vec![], // TODO
            persistent_keepalive_interval: self.persistent_keepalive_interval.map(|k| k.into()),
            allowed_ips: self
                .allowed_ips
                .into_iter()
                .map(|ip| format!("{}/{}", ip.ipaddr, ip.cidr_mask))
                .collect(),
            rx_bytes: None,                     // TODO
            time_since_last_rx_ms: None,        // TODO
            tx_bytes: None,                     // TODO
            time_since_last_handshake_ms: None, // TODO
        }
    }
}

impl Into<telio_wg::uapi::Peer> for WgPeer {
    fn into(self) -> telio_wg::uapi::Peer {
        telio_wg::uapi::Peer {
            public_key: self.public_key.parse().unwrap(),
            endpoint: self.endpoint.map(|e| e.parse().unwrap()),
            endpoint_changed_at: None, // TODO
            ip_addresses: self
                .ip_addresses
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect(),
            persistent_keepalive_interval: self.persistent_keepalive_interval,
            allowed_ips: self
                .allowed_ips
                .into_iter()
                .map(|ip| ip.parse().unwrap())
                .collect(),
            rx_bytes: self.rx_bytes,
            time_since_last_rx: self.time_since_last_rx_ms.map(|d| Duration::from_millis(d)),
            tx_bytes: self.tx_bytes,
            time_since_last_handshake: self
                .time_since_last_handshake_ms
                .map(|d| Duration::from_millis(d)),
            preshared_key: None,
        }
    }
}

pub enum WgCmd {
    Get,
    Set { device: WgDevice },
}

pub trait Adapter: Send + Sync {
    fn stop(&self);
    fn get_adapter_luid(&self) -> u64;
    fn send_uapi_cmd(&self, cmd: WgCmd) -> WgResponse;
    fn get_wg_socket(&self, ipv6: bool) -> Option<i32>;
    fn drop_connected_sockets(&self);
    fn inject_reset_packets(&self, exit_pubkey: String);
    fn set_tun(&self, tun_fd: i32);
}

fn convert_cmd(cmd: &telio_wg::uapi::Cmd) -> WgCmd {
    match cmd {
        telio_wg::uapi::Cmd::Get => WgCmd::Get,
        telio_wg::uapi::Cmd::Set(device) => WgCmd::Set {
            device: convert_device(device),
        },
    }
}

fn convert_device(device: &wireguard_uapi::xplatform::set::Device) -> WgDevice {
    WgDevice {
        private_key: device
            .private_key
            .as_ref()
            .map(|k| String::from_utf8(k.to_vec()).unwrap()),
        listen_port: device.listen_port,
        fwmark: device.fwmark,
        replace_peers: device.replace_peers,
        peers: device.peers.iter().map(|p| p.clone().into()).collect(),
    }
}

fn convert_wg_response(response: WgResponse) -> telio_wg::uapi::Response {
    telio_wg::uapi::Response {
        errno: response.errno,
        interface: response.interface.map(convert_wg_interface),
    }
}

fn convert_wg_interface(interface: WgInterface) -> telio_wg::uapi::Interface {
    telio_wg::uapi::Interface {
        private_key: interface.private_key.map(|s| s.parse().unwrap()),
        listen_port: interface.listen_port,
        proxy_listen_port: None, // TODO
        fwmark: interface.fwmark,
        peers: interface
            .peers
            .into_iter()
            .map(|(k, v)| (k.parse().unwrap(), v.into()))
            .collect(),
    }
}

pub struct AdapterAdapter(pub Arc<dyn Adapter>);

#[async_trait::async_trait]
impl telio_wg::Adapter for AdapterAdapter {
    async fn stop(&self) {
        self.0.stop()
    }

    fn get_adapter_luid(&self) -> u64 {
        self.0.get_adapter_luid()
    }

    async fn send_uapi_cmd(
        &self,
        cmd: &telio_wg::uapi::Cmd,
    ) -> Result<telio_wg::uapi::Response, telio_wg::Error> {
        Ok(convert_wg_response(self.0.send_uapi_cmd(convert_cmd(cmd))))
    }

    fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, telio_wg::Error> {
        Ok(self.0.get_wg_socket(ipv6))
    }

    async fn drop_connected_sockets(&self) {
        self.0.drop_connected_sockets();
    }

    async fn inject_reset_packets(&self, exit_pubkey: &PublicKey) {
        self.0.inject_reset_packets(exit_pubkey.to_string());
    }

    async fn set_tun(&self, tun: telio_wg::Tun) -> Result<(), telio_wg::Error> {
        let raw_fd = tun.as_raw_fd();
        self.0.set_tun(raw_fd);
        Ok(())
    }
}
