use std::sync::Arc;

use ipnet::IpNet;
use parking_lot::Mutex;
use std::net::SocketAddr;
use telio_crypto::PublicKey;

/// Helper trait that conditionally applies a transformation when an [`Option`] is [`Some`].
/// Allows fluent builder chains.
/// # Example
/// ```ignore
/// builder
/// .apply_some(opt_value, |b, v| b.with_value(v))
/// .apply_some(opt_other_value, |b, v| b.with_other_value(v))
/// ```
pub trait ApplySome: Sized {
    fn apply_some<T>(self, opt: Option<T>, f: impl FnOnce(Self, T) -> Self) -> Self {
        match opt {
            Some(v) => f(self, v),
            None => self,
        }
    }
}

impl<S> ApplySome for S {}

/// Unified connection configuration used by [`crate::device::Device::connect_exit_node`]
/// and [`crate::device::Device::connect_vpn_post_quantum`].
///
/// Produced by [`VpnConnectionConfigBuilder`] or [`MeshnetConnectionConfigBuilder`].
/// Pass to `Telio::connect_to_exit_node_with_config`.
pub struct ConnectionConfig {
    /// Optional stable identifier for the exit node.
    /// If `None`, a random UUID is generated at connect time.
    pub identifier: Option<String>,
    /// WireGuard public key of the exit node.
    pub public_key: PublicKey,
    /// Subnets routed through the exit node.
    /// `None` is equivalent to `"0.0.0.0/0"`.
    pub allowed_ips: Option<Vec<IpNet>>,
    /// Direct UDP endpoint of the exit node.
    /// Always `Some` for VPN connections; always `None` for meshnet.
    pub endpoint: Option<SocketAddr>,
    /// When `true`, a post-quantum tunnel is established.
    /// Only meaningful for VPN connections.
    pub post_quantum: bool,
}

pub struct VpnConnectionConfigBuilder {
    config: Mutex<ConnectionConfig>,
}

impl VpnConnectionConfigBuilder {
    /// Create a new VPN connection builder.
    ///
    /// # Parameters
    /// - `public_key`: WireGuard public key of the exit node.
    /// - `endpoint`:   Direct UDP socket address of the exit node (IP:port).
    pub fn new(public_key: PublicKey, endpoint: SocketAddr) -> Self {
        Self {
            config: Mutex::new(ConnectionConfig {
                identifier: None,
                public_key,
                allowed_ips: None,
                endpoint: Some(endpoint),
                post_quantum: false,
            }),
        }
    }

    /// Set a stable string identifier for the exit node.
    /// If not called, a random UUID is generated at connect time.
    pub fn with_identifier(self: Arc<Self>, identifier: String) -> Arc<Self> {
        self.config.lock().identifier = Some(identifier);
        self
    }

    /// Set the list of IP subnets that will be routed through the exit node.
    /// If not called, defaults to `0.0.0.0/0` (all traffic).
    pub fn with_allowed_ips(self: Arc<Self>, allowed_ips: Vec<IpNet>) -> Arc<Self> {
        self.config.lock().allowed_ips = Some(allowed_ips);
        self
    }

    /// Enable post-quantum key exchange for this VPN tunnel.
    pub fn force_pq(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().post_quantum = true;
        self
    }

    /// Build the final [`ConnectionConfig`].
    pub fn build(self: Arc<Self>) -> ConnectionConfig {
        let guard = self.config.lock();
        ConnectionConfig {
            identifier: guard.identifier.clone(),
            public_key: guard.public_key,
            allowed_ips: guard.allowed_ips.clone(),
            endpoint: guard.endpoint,
            post_quantum: guard.post_quantum,
        }
    }
}

pub struct MeshnetConnectionConfigBuilder {
    config: Mutex<ConnectionConfig>,
}

impl MeshnetConnectionConfigBuilder {
    /// Create a new Meshnet connection builder.
    ///
    /// # Parameters
    /// - `public_key`: WireGuard public key of the exit node.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            config: Mutex::new(ConnectionConfig {
                identifier: None,
                public_key,
                allowed_ips: None,
                endpoint: None,
                post_quantum: false,
            }),
        }
    }

    /// Set the list of IP subnets that will be routed through the exit peer.
    /// If not called, defaults to `0.0.0.0/0` (all traffic).
    pub fn with_allowed_ips(self: Arc<Self>, allowed_ips: Vec<IpNet>) -> Arc<Self> {
        self.config.lock().allowed_ips = Some(allowed_ips);
        self
    }

    /// Build the final [`ConnectionConfig`].
    pub fn build(self: Arc<Self>) -> ConnectionConfig {
        let guard = self.config.lock();
        ConnectionConfig {
            identifier: guard.identifier.clone(),
            public_key: guard.public_key,
            allowed_ips: guard.allowed_ips.clone(),
            endpoint: None,
            post_quantum: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use telio_crypto::SecretKey;

    fn test_public_key() -> PublicKey {
        SecretKey::gen().public()
    }

    fn test_endpoint() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 51820)
    }

    fn test_allowed_ips() -> Vec<IpNet> {
        vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ]
    }

    // VpnConnectionConfigBuilder

    #[test]
    fn vpn_builder_defaults() {
        let pk = test_public_key();
        let ep = test_endpoint();
        let config = Arc::new(VpnConnectionConfigBuilder::new(pk, ep)).build();

        assert_eq!(config.public_key, pk);
        assert_eq!(config.endpoint, Some(ep));
        assert!(config.identifier.is_none());
        assert!(config.allowed_ips.is_none());
        assert!(!config.post_quantum);
    }

    #[test]
    fn vpn_builder_with_identifier() {
        let pk = test_public_key();
        let ep = test_endpoint();
        let config = Arc::new(VpnConnectionConfigBuilder::new(pk, ep))
            .with_identifier("my-vpn-node".to_string())
            .build();

        assert_eq!(config.identifier.as_deref(), Some("my-vpn-node"));
    }

    #[test]
    fn vpn_builder_with_allowed_ips() {
        let pk = test_public_key();
        let ep = test_endpoint();
        let ips = test_allowed_ips();
        let config = Arc::new(VpnConnectionConfigBuilder::new(pk, ep))
            .with_allowed_ips(ips.clone())
            .build();

        assert_eq!(config.allowed_ips.as_deref(), Some(ips.as_slice()));
    }

    #[test]
    fn vpn_builder_force_pq() {
        let pk = test_public_key();
        let ep = test_endpoint();
        let config = Arc::new(VpnConnectionConfigBuilder::new(pk, ep))
            .force_pq()
            .build();

        assert!(config.post_quantum);
    }

    // MeshnetConnectionConfigBuilder

    #[test]
    fn meshnet_builder_defaults() {
        let pk = test_public_key();
        let config = Arc::new(MeshnetConnectionConfigBuilder::new(pk)).build();

        assert_eq!(config.public_key, pk);
        assert!(
            config.endpoint.is_none(),
            "meshnet must never have a direct endpoint"
        );
        assert!(config.identifier.is_none());
        assert!(config.allowed_ips.is_none());
        assert!(!config.post_quantum, "meshnet must never use post-quantum");
    }

    #[test]
    fn meshnet_builder_with_allowed_ips() {
        let pk = test_public_key();
        let ips = test_allowed_ips();
        let config = Arc::new(MeshnetConnectionConfigBuilder::new(pk))
            .with_allowed_ips(ips.clone())
            .build();

        assert_eq!(config.allowed_ips.as_deref(), Some(ips.as_slice()));
    }

    // ApplySome

    #[test]
    fn apply_some_chaining_some_and_none() {
        let result = 0_i32
            .apply_some(Some(10), |acc, v| acc + v)
            .apply_some(None::<i32>, |acc, v| acc + v);
        assert_eq!(result, 10);
    }
}
