mod wg_controller;

use async_trait::async_trait;
use telio_crypto::{PublicKey, SecretKey};
use telio_firewall::firewall::{Firewall, StatefullFirewall};
use telio_lana::*;
use telio_nat_detect::nat_detection::{retrieve_single_nat, NatData};
use telio_proxy::{Config as ProxyConfig, Io as ProxyIo, Proxy, UdpProxy};
use telio_relay::{
    derp::{Config as DerpConfig, Server as DerpServer},
    multiplexer::Multiplexer,
    DerpRelay,
};
use telio_sockets::{NativeProtector, Protect, SocketPool};
use telio_task::{
    io::{chan, mc_chan, mc_chan::Tx, Chan, McChan},
    task_exec, BoxAction, Runtime as TaskRuntime, Task,
};
use telio_traversal::{
    connectivity_check,
    cross_ping_check::{CrossPingCheck, CrossPingCheckTrait, Io as CpcIo},
    endpoint_providers::{
        self, local::LocalInterfacesEndpointProvider, stun::StunEndpointProvider, EndpointProvider,
    },
    ping_pong_handler::PingPongHandler,
    wg_stun_controller::{WgStunController, WgStunServer},
    SessionKeeper, UpgradeRequestChangeEvent, UpgradeSync, WireGuardEndpointCandidateChangeEvent,
};

#[cfg(any(target_os = "macos", target_os = "ios"))]
use telio_sockets::native;

use telio_nurse::data::MeshConfigUpdateEvent;
use telio_wg as wg;
use thiserror::Error as TError;
use tokio::{
    runtime::{Builder, Runtime as AsyncRuntime},
    sync::Mutex,
    time::{interval_at, Interval},
};

use telio_dns::{DnsResolver, LocalDnsResolver, Records};

use telio_dns::bind_tun;
use wg::uapi::{self, PeerState};

use std::{
    collections::HashSet,
    future::Future,
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use telio_utils::{telio_log_debug, telio_log_info};

use telio_model::{
    api_config::{Features, PathType, DEFAULT_ENDPOINT_POLL_INTERVAL_SECS},
    config::{Config, Peer},
    event::{Event, Set},
    mesh::{ExitNode, Node},
};

pub use wg::{
    uapi::Event as WGEvent, AdapterType, DynamicWg, Error as AdapterError, FirewallCb, Tun,
    WireGuard,
};

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
    #[error("Meshnet IP is not set for the node")]
    NoMeshnetIP,
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
    #[error("Failed to recover information about NAT")]
    FailedNatInfoRecover(std::io::Error),
    #[error("Failed to initialize libmoose: {0}")]
    LibmooseError(#[from] telio_lana::moose::Error),
    #[error("Failed to parse IP network")]
    IpNetworkError(#[from] ipnetwork::IpNetworkError),
    #[error("Controller error")]
    ControllerError(#[from] wg_controller::Error),
    #[error("Proxy error")]
    ProxyError(#[from] telio_proxy::Error),
    #[error("Connectivity check error")]
    ConnectivityCheckError(#[from] connectivity_check::Error),
    #[error("Endpoint provider error")]
    EndpointProviderError(#[from] endpoint_providers::Error),
    #[error("Multiplexer error")]
    MultiplexerError(#[from] telio_relay::multiplexer::Error),
    #[error("Traversal error")]
    TraversalError(#[from] telio_traversal::Error),
    #[error("Task execution error")]
    TaskExecError(#[from] telio_task::ExecError),
    #[error("Session keeper error")]
    SessionKeeperError(#[from] telio_traversal::session_keeper::Error),
    #[error("Session keeper error")]
    UpgradeSyncError(#[from] telio_traversal::upgrade_sync::Error),
    #[cfg(target_os = "macos")]
    #[error("Socket pool error")]
    SocketPoolError(#[from] telio_sockets::protector::platform::Error),
}

pub type Result<T = ()> = std::result::Result<T, Error>;

pub trait EventCb: Fn(Box<Event>) + Send + 'static {}
impl<T> EventCb for T where T: Fn(Box<Event>) + Send + 'static {}

#[derive(Clone, Default)]
pub struct DeviceConfig {
    pub private_key: SecretKey,
    pub adapter: AdapterType,
    pub fwmark: Option<u32>,
    pub name: Option<String>,
    pub tun: Option<Tun>,
}

pub struct Device {
    art: Option<Arc<AsyncRuntime>>,
    event: Tx<Box<Event>>,
    rt: Option<Task<Runtime>>,
    protect: Option<Protect>,
    features: Features,
}

#[derive(Default)]
pub struct RequestedState {
    // WireGuard interface configuration
    pub device_config: DeviceConfig,

    // A configuration as requested by libtelio.set_config(...) call, no modifications
    pub meshnet_config: Option<Config>,

    // The latest exit node passed by libtelio.connected_to_exit(...)
    pub exit_node: Option<ExitNode>,

    // Private key which allows us to recognize if the incoming node event
    // is disconnection from VPN node
    pub last_exit_node: Option<ExitNode>,

    // Local DNS resolver config, passed by libtelio.enable_magic_dns(...)
    // this is a last known list of dns forward servers, to change back to in
    // case of disconnecting from non-vpn exit peer
    pub upstream_servers: Option<Vec<IpAddr>>,

    // Wireguard stun server that should be currently used
    pub wg_stun_server: Option<WgStunServer>,
}

pub struct Entities {
    // Wireguard interface
    wireguard_interface: Arc<DynamicWg>,

    // Internal DNS server
    dns: Arc<Mutex<DNS>>,

    // Internal firewall
    firewall: Arc<StatefullFirewall>,

    // Multiplexer for inter-node-coms and rendezvous points for other components
    multiplexer: Arc<Multiplexer>,

    // DERP Relay client
    derp: Arc<DerpRelay>,

    // UDP proxy for supporting relayed WireGuard connections
    proxy: Arc<UdpProxy>,

    // Entities for direct wireguard connections
    direct: Option<DirectEntities>,

    // A place to control the sockets used by the libtelio
    // It is handy whenever sockets needs to be bind'ed to some interface, fwmark'ed or just
    // receive/send buffers adjusted
    socket_pool: Arc<SocketPool>,
}

impl Entities {
    pub fn wg_stun_controller(&self) -> Option<&Arc<WgStunController>> {
        self.direct
            .as_ref()
            .and_then(|d| d.wg_stun_controller.as_ref())
    }

    pub fn cross_ping_check(&self) -> Option<&Arc<CrossPingCheck>> {
        self.direct.as_ref().map(|d| &d.cross_ping_check)
    }

    pub fn session_keeper(&self) -> Option<&Arc<SessionKeeper>> {
        self.direct.as_ref().map(|d| &d.session_keeper)
    }

    fn endpoint_providers(&self) -> Vec<&Arc<dyn EndpointProvider>> {
        self.direct
            .as_ref()
            .map(|d| d.endpoint_providers.iter().collect())
            .unwrap_or_default()
    }

    pub fn upgrade_sync(&self) -> Option<&Arc<UpgradeSync>> {
        self.direct.as_ref().map(|d| &d.upgrade_sync)
    }

    fn stun_endpoint_provider(&self) -> Option<&Arc<StunEndpointProvider>> {
        self.direct
            .as_ref()
            .and_then(|d| d.stun_endpoint_provider.as_ref())
    }
}

pub struct DirectEntities {
    // Endpoint providers
    local_interfaces_endpoint_provider: Option<Arc<LocalInterfacesEndpointProvider>>,
    stun_endpoint_provider: Option<Arc<StunEndpointProvider>>,

    // dyn EndpointProvider vector for ease of use
    endpoint_providers: Vec<Arc<dyn EndpointProvider>>,

    // Cross Ping connectivity check
    cross_ping_check: Arc<CrossPingCheck>,

    // Meshnet WG Connection upgrade synchronization
    upgrade_sync: Arc<UpgradeSync>,

    wg_stun_controller: Option<Arc<WgStunController<DynamicWg>>>,

    // Keepalive sender
    session_keeper: Arc<SessionKeeper>,
}

pub struct EventListeners {
    wg_endpoint_publish_event_subscriber: chan::Rx<WireGuardEndpointCandidateChangeEvent>,
    wg_event_subscriber: chan::Rx<Box<WGEvent>>,
    derp_event_subscriber: mc_chan::Rx<Box<DerpServer>>,
    endpoint_upgrade_event_subscriber: chan::Rx<UpgradeRequestChangeEvent>,
    wg_stun_server_subscriber: chan::Rx<WgStunServer>,
}

pub struct EventPublishers {
    libtelio_event_publisher: mc_chan::Tx<Box<Event>>,
}

// All of the instances and state required to run local DNS resolver for NordNames
#[derive(Default)]
pub struct DNS<D: DnsResolver = LocalDnsResolver> {
    // DNS resolver instance
    resolver: Option<D>,

    // A file descriptor for virtual host hosting the DNS server within libtelio used for
    // configuring routing on some platforms
    virtual_host_tun_fd: Option<i32>,
}

struct Runtime {
    features: Features,

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

    /// All device Entities
    ///
    /// Entities represents any component which may need some controlling. And may or may not have
    /// their own dedicated controllers. At the time of writing this comment, only the WireGuard
    /// interface controller existed
    entities: Entities,

    /// Event subscribers
    ///
    /// If any kind of event occurs, entities will announce them using channels. The event_listener
    /// goal is to keep all of the channels for incoming events. And then listen to them
    event_listeners: EventListeners,

    /// Event publishers
    ///
    /// In the same manner as there are event subscribers, which listen for internal events, the
    /// event publishers are used to publish libtelio_wide events to the integrators of the
    /// libtelio itself.
    event_publishers: EventPublishers,

    /// State polling interval
    ///
    /// Some of the events are time based, so just poll the whole state from time to time
    polling_interval: Interval,
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

    pub fn external_nodes(&self) -> Result<Vec<Node>> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |s| Ok(s.external_nodes().await)).await?
        })
    }

    pub fn start(&mut self, config: &DeviceConfig) -> Result {
        if self.is_running() {
            return Err(Error::AlreadyStarted);
        }

        self.rt = Some(self.art()?.block_on(async {
            let t = Task::start(
                Runtime::start(
                    self.event.clone(),
                    config,
                    self.features.clone(),
                    self.protect.clone(),
                )
                .await?,
            );
            Ok::<Task<Runtime>, Error>(t)
        })?);

        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(rt) = self.rt.take() {
            if let Some(art) = &self.art {
                let _ = art.block_on(rt.stop());
            }
        }
    }

    /// [Windows only] Retrive the UUID of the interface
    ///
    /// This methods retreives the UUID of the virtual interface created by device::start() call
    pub fn get_adapter_luid(&mut self) -> u64 {
        if let Some(art) = &self.art {
            let res: Result<u64> = art.block_on(async {
                task_exec!(self.rt()?, async move |rt| Ok(rt.get_adapter_luid().await)).await?
            });
            res.unwrap_or(0)
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

    /// Configure the private key of the WireGuard interface
    ///
    /// This methods sets the private key of the WireGuard interface. Note that it
    /// is only valid to call this method only on device instance which is currently
    /// not running. E.g. either before start()'ing or after stop()'ing it.
    pub fn set_private_key(&self, private_key: &SecretKey) -> Result {
        let private_key = *private_key; //Going into async context, therefore just copy for lifetimes
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| {
                Ok(rt.set_private_key(&private_key).await)
            })
            .await?
        })
    }

    /// Retreives currently configured private key for the interface
    pub fn get_private_key(&self) -> Result<SecretKey> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.get_private_key().await)).await?
        })
    }

    /// [Linux only] Configure the fwmark used for encapsulated packets
    #[cfg(any(target_os = "linux", doc))]
    #[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
    pub fn set_fwmark(&self, fwmark: u32) -> Result {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.set_fwmark(fwmark).await)).await?
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

    /// Configure meshnet
    ///
    /// This method sets the desired meshnet configuration
    pub fn set_config(&self, config: &Option<Config>) -> Result {
        let config = config.clone();
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.set_config(&config).await)).await?
        })
    }

    /// Notify device about network change event
    ///
    /// In some cases integrators may have better knowledge of the network state or state changes,
    /// therefore this method assumes, that a device has migrated from one network to the other,
    /// and adapts whatever is needed
    pub fn notify_network_change(&self) -> Result {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| {
                Ok(rt.notify_network_change().await)
            })
            .await?
        })
    }

    /// Connect to exit node
    ///
    /// Exit node in this case may be the VPN server or another meshnet node. In the former case,
    /// new node is created and WireGuard tunnel is established to that node. In the latter case
    /// the specified (matched by public key) meshnet node is "promoted" to be the exit node
    pub fn connect_exit_node(&self, node: &ExitNode) -> Result {
        self.art()?.block_on(async {
            let node = node.clone();
            let wireguard_interface: Arc<DynamicWg> = task_exec!(self.rt()?, async move |rt| {
                rt.connect_exit_node(&node).await?;
                Ok(rt.entities.wireguard_interface.clone())
            })
            .await
            .map_err(Error::from)?;

            // TODO: delete this as sockets are protected from within boringtun itself
            #[cfg(not(windows))]
            self.protect_from_vpn(&*wireguard_interface).await?;

            Ok(())
        })
    }

    /// Disconnect from exit node
    ///
    /// Undoes the effects of calling device::connect_exit_node(), matching the node by public key
    pub fn disconnect_exit_node(&self, node_key: &PublicKey) -> Result {
        self.art()?.block_on(async {
            let node_key = *node_key;
            task_exec!(self.rt()?, async move |rt| {
                Ok(rt.disconnect_exit_node(&node_key).await)
            })
            .await?
            .map_err(Error::from)
        })
    }

    /// Disconnects from any VPN and/or demotes any meshnet node to be a regular meshnet node
    /// instead of exit node
    pub fn disconnect_exit_nodes(&self) -> Result {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| {
                Ok(rt.disconnect_exit_nodes().await)
            })
            .await?
            .map_err(Error::from)
        })
    }

    fn rt(&self) -> Result<&Task<Runtime>> {
        self.rt.as_ref().ok_or(Error::NotStarted)
    }

    fn art(&self) -> Result<&Arc<AsyncRuntime>> {
        self.art.as_ref().ok_or(Error::NotStarted)
    }

    /// Enables DNS server
    ///
    /// DNS server hosted on a virtual host within device can be used to resolve the domain names
    /// of the meshnet nodes. If the DNS query sent to this server does not fall under .nord
    /// top-level-domain, the query is forwarded to one of the `upstream_servers`.
    pub fn enable_magic_dns(&self, upstream_servers: &[IpAddr]) -> Result {
        self.art()?.block_on(async {
            let upstream_servers = upstream_servers.to_vec();
            task_exec!(self.rt()?, async move |rt| {
                Ok(rt.start_dns(&upstream_servers).await)
            })
            .await?
        })
    }

    /// Disables DNS server
    ///
    /// Undoes the effects of `device::enable_magic_dns()` call
    pub fn disable_magic_dns(&self) -> Result {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.stop_dns().await)).await?
        })
    }

    /// A artificial method causing panics
    ///
    /// Used only for testing purposes
    pub fn _panic(&self) -> Result {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt._panic().await)).await?
        })
    }

    /// Retreives currently connected derp server information
    pub fn get_derp_server(&self) -> Result<Option<DerpServer>> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.get_derp_server().await)).await?
        })
    }

    /// Retreives currently configured derp server information
    pub fn get_derp_config(&self) -> Result<DerpConfig> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.get_derp_config().await)).await?
        })
    }

    /// Retrieves a reference to SocketPool. Use this instead of SocketPool::default() when possible
    pub fn get_socket_pool(&self) -> Result<Arc<SocketPool>> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.get_socket_pool().await)).await?
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
        libtelio_wide_event_publisher: Tx<Box<Event>>,
        config: &DeviceConfig,
        features: Features,
        protect: Option<Protect>,
    ) -> Result<Self> {
        let firewall = Arc::new(StatefullFirewall::new());
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
                SocketPool::new(NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    features.macos_sideload,
                )?)
            }
        });

        // Start multiplexer
        let (multiplexer_derp_chan, derp_multiplexer_chan) = Chan::pipe();
        let multiplexer = Arc::new(Multiplexer::start(multiplexer_derp_chan));

        // Start UDP proxy
        let proxy = Arc::new(UdpProxy::start(ProxyIo {
            relay: multiplexer.get_channel().await?,
        }));

        // Start Derp client
        let derp_events = McChan::default();
        let derp = Arc::new(DerpRelay::start_with(
            derp_multiplexer_chan,
            socket_pool.clone(),
            derp_events.tx.clone(),
        ));

        let (analytics_ch, config_update_ch) = if features.nurse.is_some() {
            (Some(McChan::default().tx), Some(McChan::default().tx))
        } else {
            (None, None)
        };

        let wg_events = Chan::default();
        let wireguard_interface = Arc::new(DynamicWg::start(
            wg::Io {
                events: wg_events.tx.clone(),
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

        wireguard_interface
            .set_secret_key(config.private_key)
            .await?;

        #[cfg(windows)]
        {
            let adapter_luid = wireguard_interface.get_adapter_luid().await?;
            socket_pool.set_tunnel_interface(adapter_luid);
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        set_tunnel_interface(&socket_pool, config);

        let requested_state = RequestedState {
            device_config: config.clone(),
            ..Default::default()
        };

        let dns = Arc::new(Mutex::new(DNS {
            resolver: None,
            #[cfg(unix)]
            virtual_host_tun_fd: config.tun.map(|fd| fd as i32),
            #[cfg(windows)]
            virtual_host_tun_fd: None,
        }));

        // Setup direct connection based on features
        let endpoint_publish_events = Chan::default();
        let pong_rxed_events = Chan::default();
        let wg_endpoint_publish_events = Chan::default();
        let wg_upgrade_sync = Chan::default();
        let wg_stun_server_events = Chan::default();
        let direct = if let Some(direct) = &features.direct {
            // Create endpoint providers
            let has_provider = |provider| {
                // Default is all providers
                direct
                    .providers
                    .as_ref()
                    .map(|p| p.contains(&provider))
                    .unwrap_or(true)
            };

            use telio_model::api_config::EndpointProvider::*;

            let ping_pong_tracker = Arc::new(Mutex::new(PingPongHandler::new(config.private_key)));
            let mut endpoint_providers: Vec<Arc<dyn EndpointProvider>> = Vec::new();

            // Create Local Interface Endpoint Provider
            let local_interfaces_endpoint_provider = if has_provider(Local) {
                let ep = Arc::new(LocalInterfacesEndpointProvider::new(
                    socket_pool
                        .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
                        .await?,
                    wireguard_interface.clone(),
                    Duration::from_secs(
                        direct
                            .endpoint_interval_secs
                            .unwrap_or(DEFAULT_ENDPOINT_POLL_INTERVAL_SECS),
                    ),
                    ping_pong_tracker.clone(),
                ));
                endpoint_providers.push(ep.clone());
                Some(ep)
            } else {
                None
            };

            // Create Stun Endpoint Provider
            let stun_endpoint_provider = if has_provider(Stun) {
                let ep = Arc::new(StunEndpointProvider::start(
                    socket_pool
                        .new_internal_udp((Ipv4Addr::UNSPECIFIED, 0), None)
                        .await?,
                    socket_pool
                        .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
                        .await?,
                    wireguard_interface.clone(),
                    Duration::from_secs(
                        direct
                            .endpoint_interval_secs
                            .unwrap_or(DEFAULT_ENDPOINT_POLL_INTERVAL_SECS),
                    ),
                    ping_pong_tracker.clone(),
                ));
                endpoint_providers.push(ep.clone());
                Some(ep)
            } else {
                None
            };
            let wg_stun_controller = if has_provider(Stun) {
                Some(Arc::new(WgStunController::new(
                    wg_stun_server_events.tx,
                    wireguard_interface.clone(),
                    Duration::from_secs(5),
                )))
            } else {
                None
            };

            // Subscribe to endpoint providers' events
            for endpoint_provider in &endpoint_providers {
                endpoint_provider
                    .subscribe_for_endpoint_candidates_change_events(
                        endpoint_publish_events.tx.clone(),
                    )
                    .await;
                endpoint_provider
                    .subscribe_for_pong_events(pong_rxed_events.tx.clone())
                    .await;
            }

            // Create Cross Ping Check
            let cross_ping_check = Arc::new(CrossPingCheck::start(
                CpcIo {
                    endpoint_change_subscriber: endpoint_publish_events.rx,
                    pong_rx_subscriber: pong_rxed_events.rx,
                    wg_endpoint_publisher: wg_endpoint_publish_events.tx.clone(),
                    intercoms: multiplexer.get_channel().await?,
                },
                endpoint_providers.clone(),
                Duration::from_secs(2),
                ping_pong_tracker,
                Default::default(),
            )?);

            // Create WireGuard connection upgrade synchronizer
            let upgrade_sync = Arc::new(UpgradeSync::new(
                wg_upgrade_sync.tx,
                multiplexer.get_channel().await?,
                Duration::from_secs(5),
            )?);

            let session_keeper = Arc::new(SessionKeeper::start(socket_pool.clone())?);

            Some(DirectEntities {
                local_interfaces_endpoint_provider,
                stun_endpoint_provider,
                endpoint_providers,
                cross_ping_check,
                upgrade_sync,
                wg_stun_controller,
                session_keeper,
            })
        } else {
            None
        };

        Ok(Runtime {
            features,
            requested_state,
            config_update_ch,
            entities: Entities {
                wireguard_interface,
                dns,
                firewall,
                multiplexer,
                derp,
                proxy,
                direct,
                socket_pool,
            },
            event_listeners: EventListeners {
                wg_endpoint_publish_event_subscriber: wg_endpoint_publish_events.rx,
                wg_event_subscriber: wg_events.rx,
                derp_event_subscriber: derp_events.rx,
                endpoint_upgrade_event_subscriber: wg_upgrade_sync.rx,
                wg_stun_server_subscriber: wg_stun_server_events.rx,
            },
            event_publishers: EventPublishers {
                libtelio_event_publisher: libtelio_wide_event_publisher,
            },
            polling_interval: interval_at(tokio::time::Instant::now(), Duration::from_secs(5)),
        })
    }

    async fn external_nodes(&self) -> Result<Vec<Node>> {
        let wgi = self.entities.wireguard_interface.get_interface().await?;
        let mut nodes = Vec::new();
        for peer in wgi.peers.values() {
            if let Some(node) = self.peer_to_node(peer, None).await {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }

    async fn upsert_dns_peers(&self) -> Result {
        if let (Some(dns), peers) = (
            &self.entities.dns.lock().await.resolver,
            &self.requested_state.collect_dns_records(),
        ) {
            dns.upsert("nord", peers)
                .await
                .map_err(Error::DnsResolverError)?;
        }

        Ok(())
    }

    async fn set_private_key(&mut self, private_key: &SecretKey) -> Result {
        // TODO: create a global controll state to consolidate all entities

        if self.entities.dns.lock().await.resolver.is_some() {
            return Err(Error::DnsNotDisabled);
        }

        self.requested_state.device_config.private_key = *private_key;

        self.entities
            .derp
            .configure(self.entities.derp.get_config().await.map(|c| DerpConfig {
                secret_key: *private_key,
                ..c
            }))
            .await;

        if let Some(wsc) = self.entities.wg_stun_controller() {
            wsc.configure(wsc.get_config().await.map(|c| DerpConfig {
                secret_key: *private_key,
                ..c
            }))
            .await;
        }

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities).await?;
        Ok(())
    }

    async fn get_private_key(&self) -> Result<SecretKey> {
        Ok(self.requested_state.device_config.private_key)
    }

    async fn get_adapter_luid(&mut self) -> Result<u64> {
        Ok(self.entities.wireguard_interface.get_adapter_luid().await?)
    }

    #[cfg(target_os = "linux")]
    async fn set_fwmark(&mut self, fwmark: u32) -> Result {
        self.requested_state.device_config.fwmark = Some(fwmark);

        self.entities.socket_pool.set_fwmark(fwmark);
        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities).await?;
        Ok(())
    }

    async fn notify_network_change(&mut self) -> Result {
        self.entities
            .wireguard_interface
            .drop_connected_sockets()
            .await?;

        self.entities.derp.reconnect().await;
        self.log_nat().await;
        Ok(())
    }

    async fn start_dns(&mut self, upstream_dns_servers: &[IpAddr]) -> Result {
        self.requested_state.upstream_servers = Some(Vec::from(upstream_dns_servers));
        {
            let mut dns_entity = self.entities.dns.lock().await;

            //get the public key of the main WG interface
            let itf = self.entities.wireguard_interface.get_interface().await?;
            let public_key = itf
                .private_key
                .ok_or_else(|| {
                    Error::AdapterConfig("Adapter does not have a private key".to_owned())
                })?
                .public();

            if let Some(dns) = &dns_entity.resolver {
                dns.forward(upstream_dns_servers)
                    .await
                    .map_err(Error::DnsResolverError)?;
            } else {
                telio_log_debug!(
                    "enabling magic dns with forward servers: {:?}",
                    &upstream_dns_servers
                );

                let dns = LocalDnsResolver::new(
                    &public_key,
                    self.entities
                        .wireguard_interface
                        .wait_for_listen_port(Duration::from_millis(100))
                        .await?,
                    upstream_dns_servers,
                    dns_entity.virtual_host_tun_fd,
                    self.features.exit_dns.clone(),
                )
                .await
                .map_err(Error::DnsResolverError)?;
                dns.start().await;
                dns_entity.resolver = Some(dns);
            }
        } // Release locks before controller takes over

        self.upsert_dns_peers().await?;

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities).await?;

        Ok(())
    }

    async fn reconfigure_dns_peer(&self, dns: &LocalDnsResolver, forward_ips: &[IpAddr]) -> Result {
        if dns.auto_switch_ips {
            telio_log_debug!("forwarding to dns {:?}", forward_ips);
            dns.forward(forward_ips)
                .await
                .map_err(Error::DnsResolverError)?;
        }

        Ok(())
    }

    async fn stop_dns(&mut self) -> Result {
        self.requested_state.upstream_servers = None;
        if let Some(dns) = self.entities.dns.lock().await.resolver.take() {
            dns.stop().await;
        };

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities).await?;
        Ok(())
    }

    async fn set_config(&mut self, config: &Option<Config>) -> Result {
        self.requested_state.meshnet_config = config.clone();

        let wg_itf = self.entities.wireguard_interface.get_interface().await?;
        let wg_port = self
            .entities
            .wireguard_interface
            .wait_for_listen_port(Duration::from_secs(1))
            .await?;
        let secret_key = if let Some(secret_key) = wg_itf.private_key {
            secret_key
        } else {
            return Err(Error::BadPrivateKey);
        };
        let peers: HashSet<PublicKey> = config
            .clone()
            .and_then(|c| c.peers)
            .unwrap_or_default()
            .iter()
            .map(|p| p.base.public_key)
            .collect();

        // Update for proxy and derp config
        if let Some(config) = config {
            // Retreive meshnet IP address
            let mesh_ip = config
                .clone()
                .this
                .ip_addresses
                .map(|ip| if !ip.is_empty() { Some(ip[0]) } else { None })
                .ok_or(Error::NoMeshnetIP)?
                .ok_or(Error::NoMeshnetIP)?;

            let proxy_config = ProxyConfig {
                wg_port: Some(wg_port),
                peers: peers.clone(),
            };
            self.entities.proxy.configure(proxy_config).await?;

            // Update configuration for DERP client
            let derp_config = DerpConfig {
                secret_key,
                servers: config.derp_servers.clone().unwrap_or_default(),
                allowed_pk: peers,
                timeout: Duration::from_secs(10), //TODO: make configurable
                ca_pem_path: None,
                mesh_ip,
            };

            self.entities
                .derp
                .configure(Some(derp_config.clone()))
                .await;

            // Update wg_stun_controll configuration
            if let Some(wsc) = self.entities.wg_stun_controller() {
                wsc.configure(Some(derp_config)).await;
            }

            self.upsert_dns_peers().await?;
        } else {
            self.entities
                .proxy
                .configure(ProxyConfig {
                    wg_port: None,
                    peers: HashSet::new(),
                })
                .await?;

            self.upsert_dns_peers().await?;

            self.entities.derp.configure(None).await;
            if let Some(wsc) = self.entities.wg_stun_controller() {
                wsc.configure(None).await;
            }
        }

        if let Some(cpc) = self.entities.cross_ping_check() {
            cpc.configure(config.clone()).await?;
        }

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities).await?;
        for ep in self.entities.endpoint_providers().iter() {
            if let Err(err) = ep.trigger_endpoint_candidates_discovery().await {
                // This can fail on first config, because it takes a bit of time to resolve
                // stun endpoint for StunEndpointProvider for WgStunControll
                telio_log_debug!("Failed to trigger: {}", err);
            }
        }

        self.log_nat().await;

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

        let wg_peer = self
            .entities
            .wireguard_interface
            .get_interface()
            .await?
            .peers
            .get(&node.public_key)
            .cloned();

        if let Some(wg_peer) = wg_peer {
            node.is_vpn = false;
            node.endpoint = wg_peer.endpoint;

            //  forward dns traffic to exit peer's dns resolver
            if let Some(dns) = &self.entities.dns.lock().await.resolver {
                self.reconfigure_dns_peer(dns, &dns.get_default_dns_servers())
                    .await?;
            }
        } else {
            node.is_vpn = true;
            self.entities
                .firewall
                .add_to_peer_whitelist(node.public_key);
        }

        self.requested_state.exit_node = Some(exit_node.clone());
        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities).await?;
        Ok(())
    }

    async fn disconnect_exit_node(&mut self, node_key: &PublicKey) -> Result {
        match self.requested_state.exit_node.as_ref() {
            Some(exit_node) if &exit_node.public_key == node_key => {
                self.entities
                    .firewall
                    .remove_from_peer_whitelist(exit_node.public_key);
                self.disconnect_exit_nodes().await
            }
            _ => Err(Error::InvalidNode),
        }
    }

    async fn disconnect_exit_nodes(&mut self) -> Result {
        if let Some(exit_node) = self.requested_state.exit_node.take() {
            self.requested_state.last_exit_node = Some(exit_node);

            // for macos dns
            bind_tun::set_should_bind(false);

            if let (Some(dns), Some(forward_dns)) = (
                &self.entities.dns.lock().await.resolver,
                &self.requested_state.upstream_servers,
            ) {
                self.reconfigure_dns_peer(dns, forward_dns).await?;
            }

            wg_controller::consolidate_wg_state(&self.requested_state, &self.entities).await?;
        }

        Ok(())
    }

    async fn _panic(&mut self) -> Result {
        let _ = tokio::spawn(async {
            panic!("runtime_panic_test");
        })
        .await;

        Ok(())
    }

    async fn get_derp_server(&self) -> Result<Option<DerpServer>> {
        Ok(self.entities.derp.get_connected_server().await)
    }

    async fn get_derp_config(&self) -> Result<DerpConfig> {
        Ok(self.entities.derp.get_config().await.unwrap_or_default())
    }

    async fn get_socket_pool(&self) -> Result<Arc<SocketPool>> {
        Ok(self.entities.socket_pool.clone())
    }

    async fn peer_to_node(&self, peer: &uapi::Peer, state: Option<PeerState>) -> Option<Node> {
        let endpoint = peer.endpoint;

        // Check if ExitNode in requested state matches the node being reported by public
        // key
        let exit_node = if let Some(exit_node) = self.requested_state.exit_node.clone() {
            Some(exit_node)
        } else {
            self.requested_state.last_exit_node.clone()
        }
        .filter(|node| node.public_key == peer.public_key);

        // Find a peer with matching public key in meshnet_config and retreive the needed
        // information about it from there
        let meshnet_peer: Option<Peer> = self
            .requested_state
            .meshnet_config
            .as_ref()
            .and_then(|config| config.peers.clone())
            .and_then(|config_peers| {
                config_peers
                    .iter()
                    .cloned()
                    .filter(|config_peer| config_peer.base.public_key == peer.public_key)
                    .collect::<Vec<Peer>>()
                    .first()
                    .cloned()
            });

        // Resolve what type of path is used
        let path_type = {
            let map = self
                .entities
                .proxy
                .get_endpoint_map()
                .await
                .unwrap_or_else(|err| {
                    telio_log_warn!("Failed to get proxy endpoint map: {}", err);
                    Default::default()
                });
            match &endpoint {
                Some(actual) => map
                    .get(&peer.public_key)
                    .map(|proxy| {
                        if proxy == actual {
                            PathType::Relay
                        } else {
                            PathType::Direct
                        }
                    })
                    .unwrap_or(PathType::Direct),
                None => {
                    // TODO: Maybe we should introduce None state after all ?
                    PathType::Direct
                }
            }
        };

        // Build a node to report event about, we need to report about either meshnet peers
        // or VPN peers. Others (like DNS, or anycast) are considered to be "internal" ones
        // and will not be reported via libtelio events.
        match (meshnet_peer, exit_node) {
            (Some(meshnet_peer), exit_node) => {
                // Meshnet peer
                Some(Node {
                    public_key: meshnet_peer.base.public_key,
                    state: state.or_else(|| Some(peer.state())),
                    is_exit: exit_node.is_some(),
                    is_vpn: false,
                    allowed_ips: peer.allowed_ips.clone(),
                    endpoint,
                    hostname: Some(meshnet_peer.base.hostname.clone()),
                    allow_incoming_connections: meshnet_peer.allow_incoming_connections,
                    path: path_type,
                })
            }
            (None, Some(exit_node)) => {
                // Exit node
                Some(Node {
                    public_key: exit_node.public_key,
                    state: state.or_else(|| Some(peer.state())),
                    is_exit: true,
                    is_vpn: exit_node.endpoint.is_some(),
                    allowed_ips: peer.allowed_ips.clone(),
                    endpoint,
                    hostname: None,
                    allow_incoming_connections: false,
                    path: path_type,
                })
            }
            _ => None,
        }
    }
}

#[async_trait]
impl TaskRuntime for Runtime {
    const NAME: &'static str = "Telio";

    type Err = Error;

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        tokio::select! {
            Some(_) = self.event_listeners.wg_endpoint_publish_event_subscriber.recv() => {
                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("WireGuard controller failure: {:?}. Ignoring", e);
                        });
                Ok(())
            },

            Some(mesh_event) = self.event_listeners.wg_event_subscriber.recv() => {
                let node = self.peer_to_node(&mesh_event.peer, Some(mesh_event.state)).await;

                if let Some(node) = node {
                    // Publish WG event to app
                    let _ = self.event_publishers.libtelio_event_publisher.send(
                        Box::new(Event::new::<Node>().set(node))
                    );
                }

                Ok(())
            },

            Ok(derp_event) = self.event_listeners.derp_event_subscriber.recv() => {
                let _ = self.event_publishers.libtelio_event_publisher.send(
                    Box::new(Event::new::<DerpServer>().set(*derp_event))
                );
                Ok(())
            },

            Some(_) = self.event_listeners.endpoint_upgrade_event_subscriber.recv() => {
                telio_log_info!("Upgrade request, consolidate wg");
                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("WireGuard controller failure: {:?}. Ignoring", e);
                        });
                Ok(())
            },

            Some(wg_stun_server) = self.event_listeners.wg_stun_server_subscriber.recv() => {
                self.requested_state.wg_stun_server = Some(wg_stun_server);
                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("WireGuard controller failure: {:?}. Ignoring", e);
                        });
                Ok(())
            },

            _ = self.polling_interval.tick() => {
                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("WireGuard controller failure: {:?}. Ignoring", e);
                        });
                Ok(())
            },

            update = update => {
                return update(self).await;
            }
            else => {
                return Ok(());
            }
        }
    }

    async fn stop(#[allow(unused_mut)] mut self) {
        macro_rules! stop_entity {
            ($entity: expr, $name: expr) => {{
                if let Ok(task) = $entity
                    .map(|m| m.stop())
                    .map_err(|_| {
                        telio_log_warn!(
                            "Oops, smething went wrong! Something is holding a strong reference to the {:?} instance.",
                            $name
                        );
                    }) {
                    task.await;
                } else {
                    telio_log_warn!("Oops, something went wrong while stopping {:?} tasks.", $name);
                }
            }}
        }
        macro_rules! stop_arc_entity {
            ($entity: expr, $name: expr) => {{
                stop_entity!(Arc::try_unwrap($entity), $name)
            }};
        }

        let _ = self.stop_dns().await;
        if let Some(direct) = self.entities.direct {
            // Arc dependency on endpoint providers
            stop_arc_entity!(direct.cross_ping_check, "CrossPingCheck");
            drop(direct.endpoint_providers);

            // Arc dependency on wrireguard
            if let Some(local) = direct.local_interfaces_endpoint_provider {
                stop_arc_entity!(local, "LocalInterfacesEndpointProvider");
            }
            if let Some(stun) = direct.stun_endpoint_provider {
                stop_arc_entity!(stun, "StunEndpointProvider");
            }

            // No Arc deppendencies
            if let Some(wsc) = direct.wg_stun_controller {
                stop_arc_entity!(wsc, "WgStunController");
            }
            stop_arc_entity!(direct.upgrade_sync, "UpgradeSync");
        }

        stop_arc_entity!(self.entities.wireguard_interface, "WireguardInterface");
        stop_arc_entity!(self.entities.multiplexer, "Multiplexer");
        stop_arc_entity!(self.entities.derp, "Derp");
        stop_arc_entity!(self.entities.proxy, "UdpProxy");

        self.requested_state = Default::default();
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
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
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
        assert!(rt.requested_state.exit_node.is_none());

        assert!(rt.connect_exit_node(&exit_node).await.is_ok());
        assert!(rt.requested_state.exit_node.is_some());

        assert!(rt.disconnect_exit_nodes().await.is_ok());
        assert!(rt.requested_state.exit_node.is_none());
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
                fwmark: None,
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
        let node = ExitNode {
            public_key: pubkey,
            ..Default::default()
        };
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: "hostname".to_owned(),
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
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

        rt.set_config(&config).await.expect("configure");
        assert!(rt.requested_state.exit_node.is_none());

        assert!(rt.connect_exit_node(&node).await.is_ok());
        assert_eq!(
            rt.requested_state.exit_node.as_ref().unwrap().public_key,
            pubkey
        );

        assert!(rt.set_config(&config).await.is_ok());
        assert_eq!(
            rt.requested_state.exit_node.as_ref().unwrap().public_key,
            pubkey
        );

        assert!(rt.disconnect_exit_node(&pubkey).await.is_ok());
        assert!(rt.requested_state.exit_node.is_none());
    }
}
