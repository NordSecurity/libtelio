use crate::{bind_tun, LocalNameServer, NameServer, Records};
use async_trait::async_trait;
use boringtun::crypto::x25519::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::Tunn;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::{net::SocketAddr, sync::Arc};
use telio_crypto::{PublicKey, SecretKey};
use telio_wg::uapi::Peer;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use telio_model::api_config::FeatureExitDns;

//debug tools
use telio_utils::{telio_log_debug, telio_log_error};

/// A trait for managing dns resolver server instance.
#[async_trait]
pub trait DnsResolver {
    /// Start the server.
    async fn start(&self);
    /// Stop the server.
    async fn stop(&self);
    /// Insert or update zone records used by the server.
    async fn upsert(&self, zone: &str, records: &Records) -> Result<(), String>;
    /// Configure list of forward DNS servers for zone '.'.
    async fn forward(&self, to: &[IpAddr]) -> Result<(), String>;
    /// Get public key of this DNS server.
    fn public_key(&self) -> PublicKey;
    /// Get Peer of this DNS server with selected allowed IPs.
    fn get_peer(&self, allowed_ips: Vec<IpNetwork>) -> Peer;
    /// Get default allowed IPs of this DNS server.
    fn get_default_dns_allowed_ips(&self) -> Vec<IpNetwork>;
    /// Get DNS virtual peer addresses.
    fn get_exit_connected_dns_allowed_ips(&self) -> Vec<IpNetwork>;
    /// Get default DNS server IP addresses.
    fn get_default_dns_servers(&self) -> Vec<IpAddr>;
}

/// Dns resolver server that can be run in process.
pub struct LocalDnsResolver {
    socket: Arc<UdpSocket>,
    secret_key: SecretKey,
    peer: Arc<Tunn>,
    socket_port: u16,
    dst_address: SocketAddr,
    nameserver: Arc<RwLock<LocalNameServer>>,
    /// Controls if it is allowed to reconfigure DNS peer when exit node is
    /// (dis)connected.
    pub auto_switch_ips: bool,
}

impl LocalDnsResolver {
    /// Creates new instance of `LocalDnsResolver`.
    pub async fn new(
        public_key: &PublicKey,
        port: u16,
        forward_ips: &[IpAddr],
        tun: Option<i32>,
        exit_dns: Option<FeatureExitDns>,
    ) -> Result<Self, String> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| {
                telio_log_error!("Failed to bind socket: {:?}", e);
                format!("Failed to bind socket: {:?}", e)
            })?;

        let socket_port = socket
            .local_addr()
            .map_err(|e| {
                telio_log_error!("Failed to get socket port: {:?}", e);
                format!("Failed to get socket port: {:?}", e)
            })?
            .port();

        let dst_address: SocketAddr = ([127, 0, 0, 1], port).into();

        bind_tun::set_tun(tun).map_err(|e| {
            telio_log_debug!("Failing setting tun: {:?}", e);
            format!("{}", e)
        })?;

        // DNS secret key
        let dns_secret_key = SecretKey::gen();

        // Telio public key
        let telio_public_key: Arc<X25519PublicKey> =
            Arc::new(X25519PublicKey::from(&public_key[..]));

        let static_private = dns_secret_key.to_string();
        let static_private: Arc<X25519SecretKey> = Arc::new(static_private.parse()?);

        let nameserver = LocalNameServer::new(forward_ips).await?;

        let auto_switch_ips =
            exit_dns.map_or(false, |feature| feature.auto_switch_dns_ips.unwrap_or(true));

        Ok(LocalDnsResolver {
            socket: Arc::new(socket),
            secret_key: dns_secret_key,
            peer: Arc::<Tunn>::from(Tunn::new(
                static_private,
                telio_public_key,
                None,
                None,
                0,
                None,
            )?),
            socket_port,
            dst_address,
            nameserver,
            auto_switch_ips,
        })
    }
}

#[async_trait]
impl DnsResolver for LocalDnsResolver {
    async fn start(&self) {
        self.nameserver
            .start(self.peer.clone(), self.socket.clone(), self.dst_address)
            .await;
    }

    async fn stop(&self) {
        telio_log_debug!("Dns - stop");
        self.nameserver.stop().await;
    }

    async fn upsert(&self, zone: &str, records: &Records) -> Result<(), String> {
        telio_log_debug!("Dns - upsert {:?} {:?}", zone, records);
        Ok(self.nameserver.upsert(zone, records).await?)
    }

    async fn forward(&self, to: &[IpAddr]) -> Result<(), String> {
        telio_log_debug!("Dns - forward {:?}", to);
        Ok(self.nameserver.forward(to).await?)
    }

    fn public_key(&self) -> PublicKey {
        telio_log_debug!("Dns - public_key: {:?}", &self.secret_key.public());
        self.secret_key.public()
    }

    #[allow(unwrap_check)]
    fn get_peer(&self, allowed_ips: Vec<IpNetwork>) -> Peer {
        Peer {
            public_key: self.public_key(),
            endpoint: Some(([127, 0, 0, 1], self.socket_port).into()),
            persistent_keepalive_interval: None,
            allowed_ips,
            rx_bytes: None,
            tx_bytes: None,
            time_since_last_handshake: None,
        }
    }

    #[allow(unwrap_check)]
    fn get_default_dns_allowed_ips(&self) -> Vec<IpNetwork> {
        vec![
            "100.64.0.2/32".parse().unwrap(),
            "100.64.0.3/32".parse().unwrap(),
        ]
    }

    #[allow(unwrap_check)]
    fn get_exit_connected_dns_allowed_ips(&self) -> Vec<IpNetwork> {
        vec!["100.64.0.2/32".parse().unwrap()]
    }

    #[allow(unwrap_check)]
    fn get_default_dns_servers(&self) -> Vec<IpAddr> {
        vec!["100.64.0.3".parse().unwrap()]
    }
}
