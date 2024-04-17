use crate::{bind_tun, LocalNameServer, NameServer, Records};
use async_trait::async_trait;
use boringtun::noise::Tunn;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{net::SocketAddr, sync::Arc};
use telio_crypto::{PublicKey, SecretKey};
use telio_wg::uapi::Peer;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret};

use telio_model::features::{FeatureExitDns, TtlValue};

//debug tools
use telio_utils::{telio_log_debug, telio_log_error};

/// A trait for managing dns resolver server instance.
#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait DnsResolver {
    /// Start the server.
    async fn start(&self);
    /// Stop the server.
    async fn stop(&self);
    /// Insert or update zone records used by the server.
    async fn upsert(
        &self,
        zone: &str,
        records: &Records,
        ttl_value: TtlValue,
    ) -> Result<(), String>;
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
    peer: Arc<Mutex<Tunn>>,
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
                telio_log_error!("Failed to bind dns socket: {:?}", e);
                format!("Failed to bind dns socket: {:?}", e)
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
        let telio_public_key: PublicKeyDalek = PublicKeyDalek::from(public_key.0);

        let nameserver = LocalNameServer::new(forward_ips).await?;

        let auto_switch_ips =
            exit_dns.map_or(false, |feature| feature.auto_switch_dns_ips.unwrap_or(true));

        Ok(LocalDnsResolver {
            socket: Arc::new(socket),
            secret_key: dns_secret_key,
            peer: Arc::new(Mutex::new(Tunn::new(
                StaticSecret::from(dns_secret_key.into_bytes()),
                telio_public_key,
                None,
                None,
                0,
                None,
            )?)),
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

    async fn upsert(
        &self,
        zone: &str,
        records: &Records,
        ttl_value: TtlValue,
    ) -> Result<(), String> {
        telio_log_debug!("Dns - upsert {:?} {:?}", zone, records);
        Ok(self.nameserver.upsert(zone, records, ttl_value).await?)
    }

    async fn forward(&self, to: &[IpAddr]) -> Result<(), String> {
        telio_log_debug!("Dns - forward {:?}", to);
        Ok(self.nameserver.forward(to).await?)
    }

    fn public_key(&self) -> PublicKey {
        let static_secret = &StaticSecret::from(self.secret_key.into_bytes());
        telio_log_debug!(
            "Dns - public_key: {:?}",
            PublicKeyDalek::from(static_secret)
        );
        PublicKey(PublicKeyDalek::from(static_secret).to_bytes())
    }

    fn get_peer(&self, allowed_ips: Vec<IpNetwork>) -> Peer {
        Peer {
            public_key: self.public_key(),
            endpoint: Some(([127, 0, 0, 1], self.socket_port).into()),
            allowed_ips,
            ..Default::default()
        }
    }

    fn get_default_dns_allowed_ips(&self) -> Vec<IpNetwork> {
        vec![
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)).into(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)).into(),
            IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2)).into(),
            IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 3)).into(),
        ]
    }

    fn get_exit_connected_dns_allowed_ips(&self) -> Vec<IpNetwork> {
        vec![
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)).into(),
            IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 2)).into(),
        ]
    }

    fn get_default_dns_servers(&self) -> Vec<IpAddr> {
        vec![
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)),
            IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 3)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telio_crypto::SecretKey;

    #[tokio::test]
    async fn test_get_default_dns_allowed_ips() {
        let resolver = LocalDnsResolver::new(&SecretKey::gen().public(), 42, &[], None, None)
            .await
            .unwrap();
        assert_eq!(
            vec![
                "100.64.0.2/32".parse::<IpNetwork>().unwrap(),
                "100.64.0.3/32".parse::<IpNetwork>().unwrap(),
                "fd74:656c:696f::2/128".parse::<IpNetwork>().unwrap(),
                "fd74:656c:696f::3/128".parse::<IpNetwork>().unwrap(),
            ],
            resolver.get_default_dns_allowed_ips()
        );
    }

    #[tokio::test]
    async fn test_get_exit_connected_dns_allowed_ips() {
        let resolver = LocalDnsResolver::new(&SecretKey::gen().public(), 42, &[], None, None)
            .await
            .unwrap();
        assert_eq!(
            vec![
                "100.64.0.2/32".parse::<IpNetwork>().unwrap(),
                "fd74:656c:696f::2/128".parse::<IpNetwork>().unwrap(),
            ],
            resolver.get_exit_connected_dns_allowed_ips()
        );
    }

    #[tokio::test]
    async fn test_get_default_dns_servers() {
        let resolver = LocalDnsResolver::new(&SecretKey::gen().public(), 42, &[], None, None)
            .await
            .unwrap();
        assert_eq!(
            vec![
                "100.64.0.3".parse::<IpAddr>().unwrap(),
                "fd74:656c:696f::3".parse::<IpAddr>().unwrap(),
            ],
            resolver.get_default_dns_servers()
        );
    }
}
