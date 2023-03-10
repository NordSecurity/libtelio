mod meshnet;
mod relay;

use log::debug;
use telio_crypto::{PublicKey, SecretKey};
use telio_lana::*;
use telio_nat_detect::nat_detection::{retrieve_single_nat, NatData};
use telio_sockets::{NativeProtector, Protect, SocketPool};
use telio_task::io::{mc_chan::Tx, Chan, McChan};

#[cfg(any(target_os = "macos", target_os = "ios"))]
use telio_sockets::native;

use telio_firewall::firewall::Firewall;
use telio_nurse::data::MeshConfigUpdateEvent;
use telio_relay::derp::{Config as DerpConfig, Server as DerpServer};
use telio_wg as wg;
use thiserror::Error as TError;
use tokio::{
    runtime::{Builder, Runtime as AsyncRuntime},
    sync::{watch, Mutex},
    task::JoinHandle,
};

use telio_dns::{DnsResolver, LocalDnsResolver, Records};

use telio_dns::bind_tun;

use ipnetwork::IpNetwork;

use std::{
    collections::{HashMap, HashSet},
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use telio_utils::{telio_log_debug, telio_log_info};

use telio_model::{
    api_config::Features,
    config::Config,
    event::{Event, Set},
    mesh::Map as MeshMap,
    mesh::{ExitNode, Node},
    report_event,
};

use self::{meshnet::Meshnet, relay::Config as RelayConfig, relay::Relay};

pub use wg::{AdapterType, DynamicWg, Error as AdapterError, FirewallCb, Tun, WireGuard};

#[derive(Debug, TError)]
pub enum Error {
    #[error("Driver already started.")]
    AlreadyStarted,
    #[error("Driver not started.")]
    NotStarted,
    #[error("Adapter is misconfigured: {0}.")]
    AdapterConfig(String),
    #[error("Private key does not match meshnet config's public key.")]
    BadPrivateKey,
    #[error("Duplicate allowed ips.")]
    BadAllowedIps,
    #[error("Invalid node configuration")]
    InvalidNode,
    #[error("Dublicate exit node")]
    DuplicateExitNode,
    #[error("Deleting non-existant node")]
    InvalidDelete,
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    #[error("Failed to build async runtime {0}")]
    AsyncRuntime(#[from] IoError),
    #[error("Failed to set fwmark for WG socket")]
    WgFwmark,
    #[error("DNS resolver error: {0}")]
    DnsResolverError(String),
    #[error("DNS module should be disabled when executing this operation")]
    DnsNotDisabled,
    #[error("Failed to reconnect to DERP server")]
    FailedToReconnect,
    #[error(transparent)]
    RelayError(#[from] relay::Error),
    #[error("Failed to recover information about NAT")]
    FailedNatInfoRecover(std::io::Error),
    #[error("Failed to initialize libmoose: {0}")]
    LibmooseError(#[from] telio_lana::moose::Error),
}

pub type Result<T = ()> = std::result::Result<T, Error>;

pub trait EventCb: Fn(Box<Event>) + Send + 'static {}
impl<T> EventCb for T where T: Fn(Box<Event>) + Send + 'static {}

#[derive(Clone, Default)]
pub struct DeviceConfig {
    pub private_key: SecretKey,
    pub adapter: AdapterType,
    pub name: Option<String>,
    pub tun: Option<Tun>,
}

pub struct Device {
    art: Option<Arc<AsyncRuntime>>,
    event: Tx<Box<Event>>,
    rt: Option<Mutex<Runtime>>,
    protect: Option<Protect>,
    features: Features,
}

enum ExitNodeType {
    Meshnet,
    Vpn,
    None,
}

#[derive(Default)]
pub struct RequestedState {
    // WireGuard interface configuration
    pub device_config: DeviceConfig,

    // A configuration as requested by libtelio.set_config(...) call, no modifications
    pub meshnet_config: Option<Config>,

    // TODO: It should be removed when WG is moved into Runtime struct
    //
    // A hashmap for keeping cached nodes for the current meshnet config
    pub cached_nodes: HashMap<PublicKey, Node>,

    // The latest exit node passed by libtelio.connected_to_exit(...)
    pub exit_node: Option<ExitNode>,

    // Local DNS resolver config, passed by libtelio.enable_magic_dns(...)
    // this is a last known list of dns forward servers, to change back to in
    // case of disconnecting from non-vpn exit peer
    pub upstream_servers: Option<Vec<IpAddr>>,
}

struct Runtime {
    stop: watch::Sender<bool>,
    meshnet: Meshnet,
    wireguard_interface: Arc<DynamicWg>,
    dns: Option<LocalDnsResolver>,
    tun_for_dns: Option<i32>,
    // save fwmark to use it again when derp conn is recreated
    #[cfg(target_os = "linux")]
    fwmark: u32,
    relay: Arc<Mutex<Relay>>,
    join: JoinHandle<()>,
    firewall: Arc<Firewall>,
    features: Features,
    #[allow(dead_code)]
    socket_pool: Arc<SocketPool>,

    /// Requested user configuration/state
    ///
    /// This represents currently requested user state without any modifications as configured by
    /// various libtelio calls, e.g. libtelio.set_config, libtelio.enable_magic_dns,
    /// libtelio.connect_to_exit_node etc. Note that this is desired state and not actual state,
    /// therefore this state may be different from reality even though the controllers will "try"
    /// their best to ensure that requested and actual state matches
    requested_state: RequestedState,

    /// Used to send local nodes to nurse component when there is a config update
    config_update_ch: Option<Tx<Box<MeshConfigUpdateEvent>>>,
}

impl From<&Config> for RelayConfig {
    fn from(c: &Config) -> Self {
        Self {
            nodes: c
                .peers
                .as_ref()
                .map(|peers| peers.iter().map(|p| p.public_key).collect())
                .unwrap_or_default(),
            servers: c.derp_servers.clone().unwrap_or_default(),
            mesh_ip: c
                .this
                .ip_addresses
                .clone()
                .unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)])
                .get(0)
                .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ip| *ip),
        }
    }
}

impl Device {
    // Incoming changes should fix
    #[allow(unwrap_check)]
    pub fn new<F: EventCb>(
        features: Features,
        event_cb: F,
        protect: Option<Protect>,
    ) -> Result<Self> {
        let version_tag = option_env!("CI_COMMIT_TAG").unwrap_or("dev");
        let commit_sha = option_env!("CI_COMMIT_SHA").unwrap_or("dev");
        telio_log_info!("Created libtelio instance {}, {}", version_tag, commit_sha);

        if let Some(lana) = &features.lana {
            init_lana(lana.event_path.clone(), version_tag.to_string(), lana.prod)?;
        }

        let art = Builder::new_multi_thread()
            .worker_threads(num_cpus::get())
            .enable_io()
            .enable_time()
            .build()?;

        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(256);
        art.spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                event_cb(event);
            }
        });

        Ok(Device {
            features,
            art: Some(Arc::new(art)),
            event: event_tx,
            rt: None,
            protect,
        })
    }

    pub fn is_running(&self) -> bool {
        self.rt.is_some()
    }

    pub fn nodes(&self) -> Result<Vec<Node>> {
        self.art()?.block_on(async {
            let rt = self.rt()?.lock().await;
            Ok(rt.meshnet.nodes().await)
        })
    }

    pub fn external_nodes(&self) -> Result<Vec<Node>> {
        self.art()?.block_on(async {
            let rt = self.rt()?.lock().await;
            Ok(rt.meshnet.external_nodes().await)
        })
    }

    pub fn start(&mut self, config: &DeviceConfig) -> Result {
        if self.is_running() {
            return Err(Error::AlreadyStarted);
        }

        self.rt = Some(Mutex::new(self.art()?.block_on(Runtime::start(
            self.event.clone(),
            config,
            self.features.clone(),
            self.protect.clone(),
        ))?));
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(rt) = self.rt.take() {
            if let Some(art) = &self.art {
                art.block_on(rt.into_inner().stop())
            }
        }
    }

    pub fn get_adapter_luid(&mut self) -> u64 {
        if let Some(art) = &self.art {
            art.block_on(async {
                let mut rt = self.rt()?.lock().await;
                rt.get_adapter_luid().await
            })
            .unwrap_or(0)
        } else {
            0
        }
    }

    pub fn shutdown_art(&mut self) {
        if let Some(art) = self.art.take() {
            if let Ok(art) = Arc::try_unwrap(art) {
                art.shutdown_background();
            }
        }
    }

    pub fn try_shutdown(mut self, timeout: Duration) -> Result {
        let art = self.art.take().ok_or(Error::NotStarted)?;
        let art = Arc::try_unwrap(art);
        match art {
            Ok(art) => {
                art.shutdown_timeout(timeout);
                Ok(())
            }
            _ => Err(Error::AsyncRuntime(IoError::new(
                ErrorKind::Other,
                "cannot aquire async runtime",
            ))),
        }
    }

    pub fn set_private_key(&self, private_key: &SecretKey) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            rt.set_private_key(private_key).await
        })
    }

    pub fn get_private_key(&self) -> Result<SecretKey> {
        self.art()?.block_on(async {
            let rt = self.rt()?.lock().await;
            rt.get_private_key().await
        })
    }

    #[cfg(any(target_os = "linux", doc))]
    #[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
    pub fn set_fwmark(&self, fwmark: u32) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            rt.set_fwmark(fwmark).await
        })
    }

    #[cfg(not(windows))]
    async fn protect_from_vpn(&self, adapter: &impl WireGuard) -> Result {
        if let Some(protect) = self.protect.as_ref() {
            if let Some(fd) = adapter.get_wg_socket(false).await? {
                protect(fd);
            }
            if let Some(fd) = adapter.get_wg_socket(true).await? {
                protect(fd);
            }
        }
        Ok(())
    }

    pub fn set_config(&self, config: &Option<Config>) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            rt.set_config(config).await
        })
    }

    pub fn notify_network_change(&self) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            rt.notify_network_change().await
        })
    }

    pub fn connect_exit_node(&self, node: &ExitNode) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            let ret = rt.connect_exit_node(node).await;
            // todo: delete this as sockets are protected from within boringtun itself
            #[cfg(not(windows))]
            self.protect_from_vpn(&*rt.wireguard_interface).await?;
            ret
        })
    }

    pub fn disconnect_exit_node(&self, node_key: &PublicKey) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            rt.disconnect_exit_node(node_key).await
        })
    }

    pub fn disconnect_exit_nodes(&self) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            rt.disconnect_exit_nodes().await
        })
    }

    fn rt(&self) -> Result<&Mutex<Runtime>> {
        self.rt.as_ref().ok_or(Error::NotStarted)
    }

    fn art(&self) -> Result<&Arc<AsyncRuntime>> {
        self.art.as_ref().ok_or(Error::NotStarted)
    }

    pub fn enable_magic_dns(&self, forward_servers: &[IpAddr]) -> Result {
        self.art()?.block_on(async {
            let mut rt = self.rt()?.lock().await;
            let public_key = rt.get_private_key().await?.public();
            rt.start_dns(&public_key, forward_servers).await
        })
    }

    pub fn disable_magic_dns(&self) -> Result {
        self.art()?
            .block_on(async { self.rt()?.lock().await.stop_dns().await })
    }

    pub fn _panic(&self) -> Result {
        self.art()?
            .block_on(async { self.rt()?.lock().await._panic().await })
    }

    pub fn get_derp_server(&self) -> Result<Option<DerpServer>> {
        self.art()?.block_on(async {
            let rt = self.rt()?.lock().await;
            rt.get_derp_server().await
        })
    }

    pub fn get_derp_config(&self) -> Result<DerpConfig> {
        self.art()?.block_on(async {
            let rt = self.rt()?.lock().await;
            rt.get_derp_config().await
        })
    }

    pub fn get_nat(&self, ip: String) -> Result<NatData> {
        match self.art()?.block_on(retrieve_single_nat(ip)) {
            Ok(data) => Ok(data),
            Err(no_data) => Err(Error::FailedNatInfoRecover(no_data)),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if self.features.lana.is_some() {
            let _ = telio_lana::deinit_lana();
        }
    }
}

impl RequestedState {
    // This function should be used for setting the mesh config field instead of setting it explicitly.
    // Gives the ownership of the previous node mapping.
    pub fn set_mesh_config(&mut self, config: Option<Config>) -> HashMap<PublicKey, Node> {
        self.meshnet_config = config.clone();
        let meshmap: Option<MeshMap> = config.map(|c| (&c).into());
        std::mem::replace(
            &mut self.cached_nodes,
            meshmap.map(|mm| mm.nodes).unwrap_or_default(),
        )
    }

    // Returns the type of the exit node type:
    //  - Meshnet - exit node is a part of the Meshnet
    //  - VPN - exit node is not a part of the Meshnet
    //  - None - currently there is no exit node
    fn get_exit_node_type(&self) -> ExitNodeType {
        match &self.exit_node {
            Some(exit_node) => match self.cached_nodes.get(&exit_node.public_key) {
                Some(_) => ExitNodeType::Meshnet,
                None => ExitNodeType::Vpn,
            },
            None => ExitNodeType::None,
        }
    }

    // A Convenience function to build a DNS records list from the requested meshnet config
    // This function does not take into account whether DNS is enabled or not. It simply builds a
    // list of hostnam<->IP pairs out of currently requested meshnet nodes. If meshnet is disabled,
    // empty list is returned. At this moment any IPv6 addresses are skipped, because internal DNS
    // resolver does not support IPv6
    pub fn collect_dns_records(&self) -> Records {
        let result = self
            .meshnet_config
            .clone()
            .map_or(Vec::new(), |cfg| {
                cfg.peers.map_or(Vec::new(), |peers| peers)
            })
            .iter()
            .filter_map(|v| match &v.ip_addresses {
                Some(ips) if !ips.is_empty() => match ips[0] {
                    IpAddr::V4(addr) => Some((v.hostname.to_owned(), addr)),
                    _ => None,
                },
                _ => None,
            })
            .collect();

        result
    }
}

impl Runtime {
    async fn start(
        event: Tx<Box<Event>>,
        config: &DeviceConfig,
        features: Features,
        protect: Option<Protect>,
    ) -> Result<Self> {
        let (stop, mut stopped) = watch::channel(false);
        let Chan {
            tx: path_change_tx,
            rx: path_change_rx,
        } = Chan::default();
        let firewall = Arc::new(Firewall::new());
        let firewall_filter_inbound_packets = {
            let fw = firewall.clone();
            move |peer: &[u8; 32], packet: &[u8]| fw.process_inbound_packet(peer, packet)
        };
        let firewall_filter_outbound_packets = {
            let fw = firewall.clone();
            move |peer: &[u8; 32], packet: &[u8]| fw.process_outbound_packet(peer, packet)
        };

        let socket_pool = Arc::new({
            if let Some(protect) = protect.clone() {
                SocketPool::new(protect)
            } else {
                SocketPool::new(NativeProtector::new()?)
            }
        });

        let (analytics_ch, config_update_ch) = if features.nurse.is_some() {
            (Some(McChan::default().tx), Some(McChan::default().tx))
        } else {
            (None, None)
        };

        let chan = Chan::default();
        let wireguard_interface = Arc::new(DynamicWg::start(
            wg::Io {
                events: chan.tx,
                analytics_tx: analytics_ch.clone(),
            },
            wg::Config {
                adapter: config.adapter,
                name: config.name.clone(),
                tun: config.tun,
                socket_pool: socket_pool.clone(),
                firewall_process_inbound_callback: Some(Arc::new(firewall_filter_inbound_packets)),
                firewall_process_outbound_callback: Some(Arc::new(
                    firewall_filter_outbound_packets,
                )),
            },
        )?);

        let (meshnet, mut mesh_events) =
            Meshnet::new(path_change_rx, wireguard_interface.clone(), chan.rx)?;

        meshnet.set_private_key(&config.private_key).await;

        #[cfg(windows)]
        {
            let adapter_luid = meshnet.get_adapter_luid().await;
            socket_pool.set_tunnel_interface(adapter_luid);
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        set_tunnel_interface(&socket_pool, config);

        let relay = Arc::new(Mutex::new(
            Relay::start(
                &config.private_key,
                meshnet.port().await.ok(),
                socket_pool.clone(),
                event.clone(),
                path_change_tx,
                analytics_ch.clone(),
                config_update_ch.clone(),
            )
            .await?,
        ));

        let jmesh = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(mesh_event) = mesh_events.recv() => {
                        report_event!(event, Event::new::<Node>().set(*mesh_event));
                    }
                    _ = stopped.changed() => {
                        return;
                    }
                };
            }
        });

        Ok(Runtime {
            stop,
            meshnet,
            wireguard_interface,
            dns: None,
            #[cfg(unix)]
            tun_for_dns: config.tun.map(|fd| fd as i32),
            #[cfg(windows)]
            tun_for_dns: None,
            relay,
            #[cfg(target_os = "linux")]
            fwmark: 0,
            join: jmesh,
            firewall,
            features,
            socket_pool,
            requested_state: RequestedState {
                device_config: config.clone(),
                ..Default::default()
            },
            config_update_ch,
        })
    }

    async fn set_private_key(&mut self, private_key: &SecretKey) -> Result {
        if self.dns.is_some() {
            return Err(Error::DnsNotDisabled);
        }

        self.requested_state.device_config.private_key = *private_key;
        self.meshnet.set_private_key(private_key).await;
        let _ = self.relay.lock().await.set_private_key(private_key).await;
        Ok(())
    }

    async fn get_private_key(&self) -> Result<SecretKey> {
        Ok(self.requested_state.device_config.private_key)
    }

    async fn get_adapter_luid(&mut self) -> Result<u64> {
        Ok(self.meshnet.get_adapter_luid().await)
    }

    #[cfg(target_os = "linux")]
    async fn set_fwmark(&mut self, fwmark: u32) -> Result {
        if !self.meshnet.set_fwmark(fwmark).await {
            return Err(Error::WgFwmark);
        }
        // save fwmark to use it again when relay conn is recreated
        self.fwmark = fwmark;
        self.socket_pool.set_fwmark(fwmark);
        Ok(())
    }

    async fn notify_network_change(&mut self) -> Result {
        self.meshnet.drop_connected_sockets().await;

        let mut relay = self.relay.lock().await;
        if relay.is_runtime_started() {
            match relay.reconnect().await {
                Ok(_) => {
                    drop(relay);
                    self.log_nat().await;
                    Ok(())
                }
                Err(_) => Err(Error::FailedToReconnect),
            }
        } else {
            Ok(())
        }
    }

    async fn start_dns(&mut self, public_key: &PublicKey, dns_servers: &[IpAddr]) -> Result {
        if let Some(dns) = &self.dns {
            dns.forward(dns_servers)
                .await
                .map_err(Error::DnsResolverError)?;
            if dns.auto_switch_ips {
                if let ExitNodeType::Meshnet = self.requested_state.get_exit_node_type() {
                    self.meshnet
                        .upsert_node_ignored(&Node::from(
                            &dns.get_peer(dns.get_default_dns_allowed_ips()),
                        ))
                        .await?;
                }
            }
        } else {
            telio_log_debug!(
                "enabling magic dns with forward servers: {:?}",
                &dns_servers
            );

            let dns = LocalDnsResolver::new(
                public_key,
                self.meshnet.port().await?,
                dns_servers,
                self.tun_for_dns,
                self.features.exit_dns.clone(),
            )
            .await
            .map_err(Error::DnsResolverError)?;

            self.meshnet
                .upsert_node_ignored(&Node::from(
                    &dns.get_peer(dns.get_default_dns_allowed_ips()),
                ))
                .await?;
            dns.start().await;
            self.dns = Some(dns);
        }
        self.upsert_dns_peers().await?;

        self.requested_state.upstream_servers = Some(Vec::from(dns_servers));

        Ok(())
    }

    async fn upsert_dns_peers(&self) -> Result {
        if let (Some(dns), peers) = (&self.dns, &self.requested_state.collect_dns_records()) {
            dns.upsert("nord", peers)
                .await
                .map_err(Error::DnsResolverError)?;
        }

        Ok(())
    }

    async fn reconfigure_dns_peer(
        &self,
        dns: &LocalDnsResolver,
        allowed_ips: Vec<IpNetwork>,
        forward_ips: &[IpAddr],
    ) -> Result {
        if dns.auto_switch_ips {
            telio_log_debug!("dns allowed ips set to: {:?}", &allowed_ips);
            self.meshnet
                .upsert_node_ignored(&Node::from(&dns.get_peer(allowed_ips)))
                .await?;
            telio_log_debug!("forwarding to dns {:?}", forward_ips);
            dns.forward(forward_ips)
                .await
                .map_err(Error::DnsResolverError)?;
        }

        Ok(())
    }

    async fn stop_dns(&mut self) -> Result {
        if let Some(dns) = self.dns.take() {
            self.meshnet.del_node(&dns.public_key()).await?;
            dns.stop().await;
        };

        Ok(())
    }

    async fn set_config(&mut self, config: &Option<Config>) -> Result {
        let old_node_map = self.requested_state.set_mesh_config(config.clone());

        let map = if let Some(config) = config {
            let mut meshmap: MeshMap = config.into();
            let relay: RelayConfig = config.into();
            let endpoints = self
                .relay
                .lock()
                .await
                .set_config(
                    &self.features,
                    Some(relay),
                    Some(self.meshnet.port().await?),
                )
                .await?;

            self.upsert_dns_peers().await?;
            meshmap.set_relay_endpoints(endpoints);
            Some(meshmap)
        } else {
            let _ = self
                .relay
                .lock()
                .await
                .set_config(&self.features, None, None)
                .await?;

            self.upsert_dns_peers().await?;
            None
        };

        match (&self.config_update_ch, config) {
            (Some(ch), Some(config)) => {
                let event = MeshConfigUpdateEvent::from(config);
                if ch.send(Box::new(event)).is_err() {
                    telio_log_warn!("Failed to send MeshConfigUpdateEvent to nurse component");
                }
            }
            (Some(ch), None) => {
                let event = MeshConfigUpdateEvent::default();
                if ch.send(Box::new(event)).is_err() {
                    telio_log_warn!("Failed to send MeshConfigUpdateEvent to nurse component");
                }
            }
            _ => (),
        }

        self.log_nat().await;
        self.update_map(map, old_node_map).await?;

        Ok(())
    }

    /// Logs NAT type of derp server in info log

    async fn log_nat(&self) {
        if let Ok(config) = self.get_derp_config().await {
            // Copy the lowest weight server to log nat in a separate future
            if let Some(server) = config
                .servers
                .iter()
                .min_by_key(|server| server.weight)
                .cloned()
            {
                tokio::spawn(async move {
                    if let Ok(data) = retrieve_single_nat(server.ipv4.to_string()).await {
                        telio_log_info!("Nat Type - {:?}", data.nat_type)
                    }
                });
            }
        }
    }

    async fn connect_exit_node(&mut self, exit_node: &ExitNode) -> Result {
        let mut node: Node = exit_node.into();

        // dns socket for macos should only be bound to tunnel interface when connected to exit,
        // otherwise with no exit dns peer will try to forward packets through tunnel and fail
        bind_tun::set_should_bind(true);

        if let Some(mesh_node) = self.requested_state.cached_nodes.get(&node.public_key) {
            node.is_vpn = false;
            node.endpoints = mesh_node.endpoints.clone();

            //  forward dns traffic to exit peer's dns resolver
            if let Some(dns) = &self.dns {
                self.reconfigure_dns_peer(
                    dns,
                    dns.get_exit_connected_dns_allowed_ips(),
                    &dns.get_default_dns_servers(),
                )
                .await?;
            }
        } else {
            node.is_vpn = true;
            self.firewall.add_to_peer_whitelist(node.public_key);
        }

        self.requested_state.exit_node = Some(exit_node.clone());

        self.meshnet.upsert_node(&node).await
    }

    async fn disconnect_exit_node(&mut self, node_key: &PublicKey) -> Result {
        match self.requested_state.exit_node.as_ref() {
            Some(exit_node) if &exit_node.public_key == node_key => {
                self.disconnect_exit_nodes().await
            }
            _ => Ok(()),
        }
    }

    async fn disconnect_exit_nodes(&mut self) -> Result {
        // for macos dns
        bind_tun::set_should_bind(false);

        if let Some(exit_node) = self.requested_state.exit_node.as_ref() {
            match self.requested_state.cached_nodes.get(&exit_node.public_key) {
                Some(node) => {
                    self.meshnet.upsert_node(node).await?;

                    if let (Some(dns), Some(forward_dns)) =
                        (&self.dns, &self.requested_state.upstream_servers)
                    {
                        self.reconfigure_dns_peer(
                            dns,
                            dns.get_default_dns_allowed_ips(),
                            forward_dns,
                        )
                        .await?;
                    }
                }
                None => {
                    self.meshnet.del_node(&exit_node.public_key).await?;
                    self.firewall
                        .remove_from_peer_whitelist(exit_node.public_key);
                }
            }

            self.requested_state.exit_node = None;
        }

        Ok(())
    }

    async fn update_map(
        &mut self,
        map: Option<MeshMap>,
        old_node_map: HashMap<PublicKey, Node>,
    ) -> Result {
        let to = map.map(|mm| mm.nodes).unwrap_or_default();

        // Create key sets
        let from_keys: HashSet<&PublicKey> = old_node_map.keys().collect();
        let to_keys: HashSet<&PublicKey> = to.keys().collect();

        let delete_keys = &from_keys - &to_keys;
        for key in &delete_keys {
            self.meshnet.del_node(key).await?;
            self.firewall_remove_node(&old_node_map[key]).await;
        }

        for key in &to_keys {
            if self
                .meshnet
                .get_node(key)
                .await
                .map_or(false, |v| v.is_exit)
            {
                continue;
            }

            self.meshnet.upsert_node(&to[key]).await?;
            self.firewall_upsert_node(&to[key]).await;
        }

        Ok(())
    }

    async fn stop(#[allow(unused_mut)] mut self) {
        let _ = self.stop.send(true);
        let _ = self.stop_dns().await;
        let _ = self.join.await;

        // A background task holds a strong reference on Windows, so we await
        // its end and then consume the contained mutex.
        #[cfg(windows)]
        self.stop.closed().await;

        if let Ok(task) = Arc::try_unwrap(self.relay)
            .map(|m| async {
                m.into_inner().stop().await
            })
            .map_err(|_| {
                telio_log_debug!(
                    "Oops, something went wrong! Something is holding a strong reference to the relay instance."
                );
            }) {
            task.await;
        } else {
            telio_log_debug!("Oops, something went wrong while stopping relay tasks.");
        }

        self.requested_state = Default::default();

        self.meshnet.stop().await;

        // This NEEDS to happen after meshnet.stop call. Since Meshnet keeps strong
        // pointer to the same wireguard_interface, try_unwrap will fail unless
        // we stop meshnet (which consumes it).
        if let Ok(task) = Arc::try_unwrap(self.wireguard_interface)
            .map(|m| m.stop())
            .map_err(|arc| {
                debug!(
                    "Oops, smething went wrong! Something (current strong count {}) is holding a strong reference to the wireguard_interface instance.",
                    Arc::strong_count(&arc));
            }) {
            task.await;
        } else {
            debug!("Oops, something went wrong while stopping wireguard_interface tasks.");
        }
    }

    async fn _panic(&mut self) -> Result {
        let _ = tokio::spawn(async {
            panic!("runtime_panic_test");
        })
        .await;

        Ok(())
    }

    async fn firewall_upsert_node(&self, node: &Node) {
        if node.allow_incoming_connections {
            for ip in &node.allowed_ips {
                self.firewall.add_to_network_whitelist(*ip);
            }
        } else {
            self.firewall_remove_node(node).await;
        }
    }

    async fn firewall_remove_node(&self, node: &Node) {
        for ip in &node.allowed_ips {
            self.firewall.remove_from_network_whitelist(*ip);
        }
    }

    async fn get_derp_server(&self) -> Result<Option<DerpServer>> {
        match self.relay.lock().await.get_connected_server().await {
            Ok(server) => Ok(server),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_derp_config(&self) -> Result<DerpConfig> {
        match self.relay.lock().await.get_relay_config().await {
            Ok(config) => Ok(config),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn set_tunnel_interface(socket_pool: &Arc<SocketPool>, config: &DeviceConfig) {
    let mut tunnel_if_index = None;
    if let Some(tun) = config.tun {
        match native::interface_index_from_tun(tun) {
            Ok(index) => tunnel_if_index = Some(index),
            Err(e) => {
                telio_log_warn!(
                    "Could not get tunnel index from tunnel file descriptor: {}",
                    e
                );
            }
        }
    }
    if tunnel_if_index.is_none() {
        if let Some(name) = config.name.as_ref() {
            match native::interface_index_from_name(name) {
                Ok(index) => tunnel_if_index = Some(index),
                Err(e) => {
                    telio_log_warn!(
                        "Could not get tunnel index from tunnel name \"{}\": {}",
                        name,
                        e
                    );
                }
            }
        }
    }
    if let Some(tunnel_if_index) = tunnel_if_index {
        socket_pool.set_tunnel_interface(tunnel_if_index)
    }
}

#[cfg(not(windows))]
#[cfg(test)]
mod tests {
    use super::*;
    use telio_model::config::{Peer, PeerBase};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_disconnect_exit_nodes() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);

        let features = Default::default();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key: SecretKey::gen(),
                adapter: AdapterType::BoringTun,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();
        let pubkey = SecretKey::gen().public();
        let exit_node = ExitNode {
            public_key: pubkey,
            ..Default::default()
        };
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: "hostname".to_owned(),
            ip_addresses: None,
        };
        let get_config = Config {
            this: peer_base.clone(),
            peers: Some(vec![Peer {
                base: peer_base,
                ..Default::default()
            }]),
            derp_servers: None,
            dns: None,
        };

        assert!(rt.set_config(&Some(get_config)).await.is_ok());
        assert!(rt.meshnet.get_node(&pubkey).await.is_some());

        assert!(rt.connect_exit_node(&exit_node).await.is_ok());
        assert!(rt.meshnet.get_node(&pubkey).await.unwrap().is_exit);

        assert!(rt.disconnect_exit_nodes().await.is_ok());
        assert!(!rt.meshnet.get_node(&pubkey).await.unwrap().is_exit);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_duplicate_allowed_ips() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);

        let features = Features::default();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key: SecretKey::gen(),
                adapter: AdapterType::BoringTun,
                name: None,
                tun: None,
            },
            features,
            None,
        )
        .await
        .unwrap();

        let node1 = ExitNode {
            public_key: SecretKey::gen().public(),
            allowed_ips: Some(vec![
                "100.0.0.0/8".parse().unwrap(),
                "1.1.1.1/32".parse().unwrap(),
            ]),
            endpoint: None,
        };

        let node2 = ExitNode {
            public_key: SecretKey::gen().public(),
            allowed_ips: Some(vec!["100.0.0.0/16".parse().unwrap()]),
            endpoint: None,
        };

        let node3 = ExitNode {
            public_key: SecretKey::gen().public(),
            allowed_ips: Some(vec!["1.1.1.1/32".parse().unwrap()]),
            endpoint: None,
        };

        matches!(rt.connect_exit_node(&node1).await, Ok(()));
        matches!(rt.connect_exit_node(&node2).await, Ok(()));
        matches!(
            rt.connect_exit_node(&node3).await,
            Err(Error::BadAllowedIps)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_exit_node_demote() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);

        let features = Default::default();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key: SecretKey::gen(),
                adapter: AdapterType::BoringTun,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();
        let pubkey = SecretKey::gen().public();
        let node2 = ExitNode {
            public_key: pubkey,
            ..Default::default()
        };
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: "hostname".to_owned(),
            ip_addresses: None,
        };
        let config = Some(Config {
            this: peer_base.clone(),
            peers: Some(vec![Peer {
                base: peer_base.clone(),
                ..Default::default()
            }]),
            derp_servers: None,
            dns: None,
        });

        assert!(rt.set_config(&config).await.is_ok());
        assert!(rt.meshnet.get_node(&pubkey).await.is_some());

        assert!(rt.connect_exit_node(&node2).await.is_ok());
        assert!(rt.meshnet.get_node(&pubkey).await.unwrap().is_exit);

        assert!(rt.set_config(&config).await.is_ok());
        assert!(rt.meshnet.get_node(&pubkey).await.unwrap().is_exit);

        assert!(rt.disconnect_exit_node(&pubkey).await.is_ok());
        assert!(!rt.meshnet.get_node(&pubkey).await.unwrap().is_exit);
    }
}
