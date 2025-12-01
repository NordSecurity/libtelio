use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use base64::{prelude::BASE64_STANDARD, Engine};
use ipnet::IpNet;
use telio_crypto::{KeyDecodeError, PresharedKey};
use telio_lana::telio_log_warn;
use telio_model::PublicKey;
use telio_utils::telio_log_debug;
use telio_wg::Adapter;

#[derive(Debug)]
pub struct WgDevice {
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub replace_peers: Option<bool>,
    pub peers: Vec<WgPeer>,
}

#[derive(Debug, Clone)]
pub struct WgInterface {
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub fwmark: u32,
    pub peers: HashMap<String, WgPeer>,
}

#[derive(Debug, Clone)]
pub struct WgResponse {
    pub errno: i32,
    pub interface: Option<WgInterface>,
}

#[derive(Debug, Clone)]
pub struct WgPeer {
    pub public_key: PublicKey,
    /// Peer's endpoint with `IP address` and `UDP port` number
    pub endpoint: Option<String>,
    /// Mesh's IP addresses of peer
    pub ip_addresses: Vec<IpAddr>,
    /// Keep alive interval, `seconds` or `None`
    pub persistent_keepalive_interval: Option<u32>,
    /// Vector of allowed IPs
    pub allowed_ips: Vec<IpNet>,
    /// Number of bytes received or `None`(unused on Set)
    pub rx_bytes: Option<u64>,
    /// Time since last byte has been received from this peer. This is a synthetic
    /// field, not present in the wireguard natively. It will be filled in in the
    /// wg module when syncthing.
    pub time_since_last_rx_ms: Option<u64>,
    /// Number of bytes transmitted or `None`(unused on Set)
    pub tx_bytes: Option<u64>,
    /// Time since last handshakeor `None`, differs from WireGuard field meaning
    pub time_since_last_handshake_ms: Option<u64>,
    // The peer's preshared key
    pub preshared_key: Option<String>,
}

impl From<wireguard_uapi::xplatform::set::Peer> for WgPeer {
    fn from(value: wireguard_uapi::xplatform::set::Peer) -> Self {
        WgPeer {
            public_key: PublicKey::new(value.public_key),
            endpoint: value.endpoint.map(|e| e.to_string()),
            ip_addresses: vec![],
            persistent_keepalive_interval: value.persistent_keepalive_interval.map(|k| k.into()),
            allowed_ips: value
                .allowed_ips
                .into_iter()
                .flat_map(|ip| IpNet::new(ip.ipaddr, ip.cidr_mask))
                .collect(),
            rx_bytes: None,
            time_since_last_rx_ms: None,
            tx_bytes: None,
            time_since_last_handshake_ms: None,
            preshared_key: value
                .preshared_key
                .map(|preshared_key| BASE64_STANDARD.encode(preshared_key)),
        }
    }
}

impl TryFrom<WgPeer> for telio_wg::uapi::Peer {
    type Error = telio_wg::Error;

    fn try_from(value: WgPeer) -> Result<Self, Self::Error> {
        Ok(telio_wg::uapi::Peer {
            public_key: value.public_key,
            endpoint: value.endpoint.map(|e| e.parse()).transpose()?,
            endpoint_changed_at: None,
            ip_addresses: value.ip_addresses,
            persistent_keepalive_interval: value.persistent_keepalive_interval,
            allowed_ips: value.allowed_ips,
            rx_bytes: value.rx_bytes,
            time_since_last_rx: value.time_since_last_rx_ms.map(Duration::from_millis),
            tx_bytes: value.tx_bytes,
            time_since_last_handshake: value
                .time_since_last_handshake_ms
                .map(Duration::from_millis),
            preshared_key: value.preshared_key.and_then(|preshared_key| {
                let decoded = match BASE64_STANDARD.decode(preshared_key) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        telio_log_warn!("Failed to base64-decode preshared key: {e}");
                        return None;
                    }
                };

                let array: [u8; 32] = match decoded.try_into() {
                    Ok(array) => array,
                    Err(e) => {
                        telio_log_warn!("Failed to convert preshared key, wrong size: {}", e.len());
                        return None;
                    }
                };

                Some(PresharedKey::new(array))
            }),
        })
    }
}

#[derive(Debug)]
pub enum WgCmd {
    Get,
    Set { device: WgDevice },
}

pub trait TelioCustomAdapter: Send + Sync {
    fn start(&self);
    fn stop(&self);

    fn send_uapi_cmd(&self, cmd: WgCmd) -> WgResponse;
}

fn convert_cmd(cmd: &telio_wg::uapi::Cmd) -> WgCmd {
    let ret = match cmd {
        telio_wg::uapi::Cmd::Get => WgCmd::Get,
        telio_wg::uapi::Cmd::Set(device) => WgCmd::Set {
            device: convert_device(device),
        },
    };
    telio_log_debug!("Converting a UAPI command to WG: {cmd:?} => {ret:?}");
    ret
}

fn convert_device(device: &wireguard_uapi::xplatform::set::Device) -> WgDevice {
    WgDevice {
        private_key: device
            .private_key
            .as_ref()
            .map(|k| BASE64_STANDARD.encode(k)),
        listen_port: device.listen_port,
        fwmark: device.fwmark,
        replace_peers: device.replace_peers,
        peers: device.peers.iter().map(|p| p.clone().into()).collect(),
    }
}

fn convert_wg_response(response: WgResponse) -> Result<telio_wg::uapi::Response, telio_wg::Error> {
    let tmp = response.clone();
    let ret = telio_wg::uapi::Response {
        errno: response.errno,
        interface: response.interface.map(convert_wg_interface).transpose()?,
    };
    telio_log_debug!("Converting WG response to UAPI: {tmp:?} => {ret:?}");
    Ok(ret)
}

fn convert_wg_interface(
    interface: WgInterface,
) -> Result<telio_wg::uapi::Interface, telio_wg::Error> {
    let tmp = interface.clone();

    let peers: Result<_, _> = interface
        .peers
        .into_iter()
        .map(|(k, v)| match (k.parse(), v.try_into()) {
            (Ok(k), Ok(v)) => Ok((k, v)),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Ok(_)) => Err((e as KeyDecodeError).into()),
            (Err(_), Err(e)) => Err(e),
        })
        .collect();
    let peers = peers?;

    let ret = telio_wg::uapi::Interface {
        private_key: interface.private_key.and_then(|s| s.parse().ok()),
        listen_port: interface.listen_port,
        fwmark: interface.fwmark,
        peers,
    };
    telio_log_debug!("Converting WG interface to UAPI: {tmp:?} => {ret:?}");
    Ok(ret)
}

#[derive(Clone)]
pub struct CustomAdapter(pub Arc<dyn TelioCustomAdapter>);

#[async_trait::async_trait]
impl telio_wg::Adapter for CustomAdapter {
    async fn stop(&self) {
        self.0.stop()
    }

    fn get_adapter_luid(&self) -> u64 {
        telio_log_warn!("This custom adapter doesn't support get_adapter_luid");
        0
    }

    async fn send_uapi_cmd(
        &self,
        cmd: &telio_wg::uapi::Cmd,
    ) -> Result<telio_wg::uapi::Response, telio_wg::Error> {
        convert_wg_response(self.0.send_uapi_cmd(convert_cmd(cmd)))
    }

    async fn drop_connected_sockets(&self) {
        telio_log_warn!("This custom adapter doesn't support drop_connected_sockets");
    }

    async fn inject_reset_packets(&self, _exit_pubkey: &PublicKey) {
        telio_log_warn!("This custom adapter doesn't support inject_reset_packets");
    }

    async fn set_tun(&self, _tun: telio_wg::Tun) -> Result<(), telio_wg::Error> {
        telio_log_warn!("This custom adapter doesn't support set_tun");

        Ok(())
    }

    fn clone_box(&self) -> Option<Box<dyn Adapter>> {
        Some(Box::new(self.clone()))
    }
}
