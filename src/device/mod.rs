mod wg_controller;

use async_trait::async_trait;
use telio_crypto::{PublicKey, SecretKey};
use telio_firewall::firewall::{Firewall, StatefullFirewall};
use telio_lana::init_lana;
use telio_nat_detect::nat_detection::{retrieve_single_nat, NatData};
use telio_pq::PostQuantum;
use telio_proto::HeartbeatMessage;
use telio_proxy::{Config as ProxyConfig, Io as ProxyIo, Proxy, UdpProxy};
use telio_relay::{
    derp::Config as DerpConfig, multiplexer::Multiplexer, DerpKeepaliveConfig, DerpRelay,
    SortedServers,
};
use telio_sockets::{NativeProtector, Protect, SocketPool};
use telio_task::{
    io::{chan, mc_chan, mc_chan::Tx, Chan, McChan},
    task_exec, BoxAction, Runtime as TaskRuntime, Task,
};
use telio_traversal::{
    connectivity_check,
    cross_ping_check::{CrossPingCheck, CrossPingCheckTrait, Io as CpcIo, UpgradeController},
    endpoint_providers::{
        self, local::LocalInterfacesEndpointProvider, stun::StunEndpointProvider, stun::StunServer,
        upnp::UpnpEndpointProvider, EndpointProvider,
    },
    last_rx_time_provider::{TimeSinceLastRxProvider, WireGuardTimeSinceLastRxProvider},
    ping_pong_handler::PingPongHandler,
    SessionKeeper, SessionKeeperTrait, UpgradeRequestChangeEvent, UpgradeSync,
    WireGuardEndpointCandidateChangeEvent,
};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use telio_sockets::native;

use telio_nurse::{
    aggregator::ConnectivityDataAggregator, config::AggregatorConfig,
    config::Config as NurseConfig, data::MeshConfigUpdateEvent,
    MeshnetEntities as NurseMeshnetEntities, Nurse, NurseIo,
};
use telio_wg as wg;
use thiserror::Error as TError;
use tokio::{
    runtime::{Builder, Runtime as AsyncRuntime},
    sync::Mutex,
    time::Interval,
};

use telio_dns::{DnsResolver, LocalDnsResolver, Records};

use telio_dns::bind_tun;
use wg::uapi::{self, AnalyticsEvent, PeerState};

use std::collections::HashMap;
use std::{
    collections::{hash_map::Entry, HashSet},
    future::Future,
    io::{self, Error as IoError, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use cfg_if::cfg_if;
use futures::FutureExt;

use telio_utils::{
    commit_sha,
    exponential_backoff::ExponentialBackoffBounds,
    interval, telio_log_debug, telio_log_error, telio_log_info, telio_log_warn,
    tokio::{Monitor, ThreadTracker},
    version_tag,
};

use telio_model::{
    config::{Config, Peer, PeerBase, Server as DerpServer},
    event::{Event, Set},
    features::{
        FeaturePersistentKeepalive, Features, PathType, DEFAULT_ENDPOINT_POLL_INTERVAL_SECS,
    },
    mesh::{ExitNode, LinkState, Node},
    validation::validate_nickname,
    EndpointMap,
};

pub use wg::{
    uapi::Event as WGEvent, uapi::Interface, AdapterType, DynamicWg, Error as AdapterError,
    FirewallCb, Tun, WireGuard,
};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
static NETWORK_PATH_MONITOR_START: std::sync::Once = std::sync::Once::new();

#[cfg(test)]
use wg::tests::AdapterExpectation;

#[derive(Debug, TError)]
pub enum Error {
    #[error("Driver already started.")]
    AlreadyStarted,
    #[error("Driver not started.")]
    NotStarted,
    #[error("Meshnet not configured.")]
    MeshnetNotConfigured,
    #[error("Adapter is misconfigured: {0}.")]
    AdapterConfig(String),
    #[error("Private key does not match meshnet config's public key.")]
    BadPrivateKey,
    #[error("Public key in requested config does not match the device's private key.")]
    BadPublicKey,
    #[error("Invalid node configuration")]
    InvalidNode,
    #[error("Configured exit node is not a meshnet node and does not have an endpoint set")]
    EndpointNotProvided,
    #[error("Deleting non-existent node")]
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
    #[error("Session keeper error: {0}")]
    SessionKeeperError(#[from] telio_traversal::session_keeper::Error),
    #[error("Upgrade sync error: {0}")]
    UpgradeSyncError(#[from] telio_traversal::upgrade_sync::Error),
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("Socket pool error")]
    SocketPoolError(#[from] telio_sockets::protector::platform::Error),
    #[error(transparent)]
    PostQuantum(#[from] telio_pq::Error),
    #[error("Cannot setup meshnet when the post quantum VPN is set up")]
    MeshnetUnavailableWithPQ,
    #[error(transparent)]
    PmtuProbe(std::io::Error),
    #[error("Connection upgrade failed - there is no session for key {0:?}")]
    NoSessionForKey(PublicKey),
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

    // An old meshnet configuration
    pub old_meshnet_config: Option<Config>,

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
    pub wg_stun_server: Option<StunServer>,

    // Requested keepalive periods
    pub(crate) keepalive_periods: FeaturePersistentKeepalive,
}

pub struct MeshnetEntities {
    // Relay Multiplexer
    multiplexer: Arc<Multiplexer>,

    // DERP Relay client
    derp: Arc<DerpRelay>,

    // UDP proxy for supporting relayed WireGuard connections
    proxy: Arc<UdpProxy>,

    // Entities for direct wireguard connections
    direct: Option<DirectEntities>,
}

#[derive(Default, Debug)]
pub struct MeshnetEntitiesLastState {
    endpoint_map: EndpointMap,
}

pub enum MeshnetState {
    Entities(MeshnetEntities),
    LastState(MeshnetEntitiesLastState),
}

impl MeshnetState {
    fn left(&self) -> Option<&MeshnetEntities> {
        if let Self::Entities(entities) = self {
            Some(entities)
        } else {
            None
        }
    }

    #[cfg(test)]
    #[track_caller]
    fn expect_left(&self, msg: &str) -> &MeshnetEntities {
        self.left().expect(msg)
    }

    #[cfg(test)]
    fn is_right(&self) -> bool {
        matches!(self, Self::LastState(_))
    }
}

pub struct Entities {
    // Wireguard interface
    wireguard_interface: Arc<DynamicWg>,

    // Internal DNS server
    dns: Arc<Mutex<DNS>>,

    // Internal firewall
    firewall: Arc<StatefullFirewall>,

    // Entities for meshnet connections
    meshnet: MeshnetState,

    // A place to control the sockets used by the libtelio
    // It is handy whenever sockets needs to be bound to some interface, fwmark'ed or just
    // receive/send buffers adjusted
    socket_pool: Arc<SocketPool>,

    // Nurse
    nurse: Option<Arc<Nurse>>,

    aggregator: Arc<ConnectivityDataAggregator>,

    postquantum_wg: telio_pq::Entity,

    pmtu_detection: Option<telio_pmtu::Entity>,
}

impl Entities {
    pub fn cross_ping_check(&self) -> Option<&Arc<CrossPingCheck>> {
        self.meshnet
            .left()
            .and_then(|m| m.direct.as_ref().map(|d| &d.cross_ping_check))
    }

    pub fn session_keeper(&self) -> Option<&Arc<SessionKeeper>> {
        self.meshnet
            .left()
            .and_then(|m| m.direct.as_ref().map(|d| &d.session_keeper))
    }

    fn endpoint_providers(&self) -> Vec<&Arc<dyn EndpointProvider>> {
        self.meshnet
            .left()
            .and_then(|m| {
                m.direct
                    .as_ref()
                    .map(|d| d.endpoint_providers.iter().collect())
            })
            .unwrap_or_default()
    }

    pub fn upgrade_sync(&self) -> Option<&Arc<UpgradeSync>> {
        self.meshnet
            .left()
            .and_then(|m| m.direct.as_ref().map(|d| &d.upgrade_sync))
    }
}

pub struct DirectEntities {
    // Endpoint providers
    local_interfaces_endpoint_provider: Option<Arc<LocalInterfacesEndpointProvider>>,
    stun_endpoint_provider: Option<Arc<StunEndpointProvider>>,
    upnp_endpoint_provider: Option<Arc<UpnpEndpointProvider>>,

    // dyn EndpointProvider vector for ease of use
    endpoint_providers: Vec<Arc<dyn EndpointProvider>>,

    // Cross Ping connectivity check
    cross_ping_check: Arc<CrossPingCheck>,

    // Meshnet WG Connection upgrade synchronization
    upgrade_sync: Arc<UpgradeSync>,

    // Keepalive sender
    session_keeper: Arc<SessionKeeper>,
}

pub struct EventListeners {
    wg_endpoint_publish_event_subscriber: chan::Rx<WireGuardEndpointCandidateChangeEvent>,
    wg_event_subscriber: chan::Rx<Box<WGEvent>>,
    derp_event_subscriber: mc_chan::Rx<Box<DerpServer>>,
    endpoint_upgrade_event_subscriber: chan::Rx<UpgradeRequestChangeEvent>,
    stun_server_subscriber: chan::Rx<Option<StunServer>>,
    post_quantum_subscriber: chan::Rx<telio_pq::Event>,
}

pub struct EventPublishers {
    libtelio_event_publisher: mc_chan::Tx<Box<Event>>,

    /// Used to send local nodes to nurse component when there is a config update
    nurse_config_update_publisher: Option<Tx<Box<MeshConfigUpdateEvent>>>,

    /// Used to manually trigger a nurse event collection
    nurse_collection_trigger_publisher: Option<Tx<()>>,

    /// Used to manually trigger a qos collection
    qos_collection_trigger_publisher: Option<Tx<()>>,

    // Saved for meshnet entities
    wg_endpoint_publish_event_publisher: chan::Tx<WireGuardEndpointCandidateChangeEvent>,
    endpoint_upgrade_event_subscriber: chan::Tx<UpgradeRequestChangeEvent>,
    stun_server_publisher: chan::Tx<Option<StunServer>>,
    derp_events_publisher: mc_chan::Tx<Box<DerpServer>>,
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
    /// their best to ensure that requested and actual states match
    requested_state: RequestedState,

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

    #[cfg(test)]
    /// MockedAdapter (tests)
    test_env: telio_wg::tests::Env,
}

impl Device {
    // Incoming changes should fix
    #[allow(unwrap_check)]
    pub fn new<F: EventCb>(
        features: Features,
        event_cb: F,
        protect: Option<Protect>,
    ) -> Result<Self> {
        let version_tag = version_tag();
        let commit_sha = commit_sha();
        telio_log_info!("Created libtelio instance {}, {}", version_tag, commit_sha);

        telio_log_info!("libtelio is starting up with features : {:?}", features);

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        NETWORK_PATH_MONITOR_START
            .call_once(telio_sockets::protector::platform::setup_network_path_monitor);

        if let Some(lana) = &features.lana {
            if init_lana(lana.event_path.clone(), version_tag.to_string(), lana.prod).is_err() {
                telio_log_error!("Failed to initialize lana")
            }
        }

        let thread_tracker = Arc::new(parking_lot::Mutex::new(ThreadTracker::default()));

        let art = Builder::new_multi_thread()
            .worker_threads(num_cpus::get())
            .enable_io()
            .enable_time()
            .on_thread_start({
                let thread_tracker = thread_tracker.clone();
                move || thread_tracker.lock().on_thread_start()
            })
            .on_thread_stop({
                let thread_tracker = thread_tracker.clone();
                move || thread_tracker.lock().on_thread_stop()
            })
            .on_thread_park({
                let thread_tracker = thread_tracker.clone();
                move || thread_tracker.lock().on_thread_park()
            })
            .on_thread_unpark({
                let thread_tracker = thread_tracker.clone();
                move || thread_tracker.lock().on_thread_unpark()
            })
            .build()?;

        thread_tracker.start();

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
                .boxed()
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
                self.flush_events();
            }
        }
    }

    fn flush_events(&self) {
        if let Some(timeout) = self.features.flush_events_on_stop_timeout_seconds {
            let start_time = Instant::now();
            while !self.event.is_empty() {
                std::thread::sleep(Duration::from_millis(100));
                if timeout > 0 && start_time.elapsed().as_secs() >= timeout {
                    break;
                }
            }
        }
    }

    /// [Windows only] Retrieve the UUID of the interface
    ///
    /// This methods retrieves the UUID of the virtual interface created by device::start() call
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

    pub fn try_shutdown(&mut self, timeout: Duration) -> Result {
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

    /// Retrieves currently configured private key for the interface
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
            task_exec!(self.rt()?, async move |rt| Ok(rt
                .set_config(&config)
                .boxed()
                .await))
            .await?
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

    pub fn notify_sleep(&self) -> Result {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.notify_sleep().await)).await?
        })
    }

    pub fn notify_wakeup(&self) -> Result {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.notify_wakeup().await)).await?
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
            let _wireguard_interface: Arc<DynamicWg> = task_exec!(self.rt()?, async move |rt| {
                rt.connect_exit_node(&node).boxed().await?;
                Ok(rt.entities.wireguard_interface.clone())
            })
            .await?;

            // TODO: delete this as sockets are protected from within boringtun itself
            #[cfg(not(windows))]
            self.protect_from_vpn(&*_wireguard_interface).await?;

            Ok(())
        })
    }

    /// Connect to exit node with post-quantum secure tunnel
    ///
    /// Exit node in this case may only be the VPN server.
    /// A new node is created and WireGuard post-quantum tunnel is established to that node.
    /// Meshnet is disallowed when forming a post-quantum tunnel and if it's enabled
    /// this call will error out.
    pub fn connect_vpn_post_quantum(&self, node: &ExitNode) -> Result {
        self.art()?.block_on(async {
            let node = node.clone();
            let _wireguard_interface: Arc<DynamicWg> = task_exec!(self.rt()?, async move |rt| {
                rt.connect_exit_node_pq(&node).boxed().await?;
                Ok(rt.entities.wireguard_interface.clone())
            })
            .await?;

            // TODO: delete this as sockets are protected from within boringtun itself
            #[cfg(not(windows))]
            self.protect_from_vpn(&*_wireguard_interface).await?;

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
                Ok(rt.disconnect_exit_node(&node_key).boxed().await)
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
                Ok(rt.disconnect_exit_nodes().boxed().await)
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
                Ok(rt.start_dns(&upstream_servers).boxed().await)
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

    /// Retrieves a reference to SocketPool. Use this instead of SocketPool::default() when possible
    pub fn get_socket_pool(&self) -> Result<Arc<SocketPool>> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt.get_socket_pool().await)).await?
        })
    }

    pub fn get_nat(&self, skt: SocketAddr) -> Result<NatData> {
        match self.art()?.block_on(retrieve_single_nat(skt)) {
            Ok(data) => Ok(data),
            Err(no_data) => Err(Error::FailedNatInfoRecover(no_data)),
        }
    }

    pub fn trigger_analytics_event(&self) -> Result<()> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt
                .trigger_analytics_event()
                .await))
            .await?
        })
    }

    pub fn trigger_qos_collection(&self) -> Result<()> {
        self.art()?.block_on(async {
            task_exec!(self.rt()?, async move |rt| Ok(rt
                .trigger_qos_collection()
                .await))
            .await?
        })
    }

    /// Used by tcli only
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn probe_pmtu(&self, host: IpAddr) -> Result<u32> {
        use std::os::fd::AsRawFd;

        self.art()?.block_on(async {
            let sock = telio_pmtu::PMTUSocket::new(
                host,
                Duration::from_secs(
                    self.features
                        .pmtu_discovery
                        .unwrap_or_default()
                        .response_wait_timeout_s as _,
                ),
            )?;
            telio_log_debug!("PMTU socket created");

            match self.rt() {
                Ok(rt) => {
                    task_exec!(rt, async move |rt| {
                        let future = async {
                            telio_log_debug!("Making PMTU socket external");
                            rt.entities.socket_pool.make_external(sock.as_raw_fd());
                            sock.probe_pmtu().await
                        };

                        Ok(future.await.map_err(Error::PmtuProbe))
                    })
                    .await?
                }
                Err(_) => {
                    // The device is not started. No need to make socket external
                    sock.probe_pmtu().await.map_err(Error::PmtuProbe)
                }
            }
        })
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
    // list of hostname<->IP pairs out of currently requested meshnet nodes. If meshnet is disabled,
    // empty list is returned.
    pub fn collect_dns_records(&self) -> Records {
        self.meshnet_config
            .clone()
            .map_or(Vec::new(), |cfg| {
                [
                    cfg.peers.map_or(Vec::new(), |peers| peers),
                    vec![Peer {
                        base: cfg.this,
                        ..Default::default()
                    }],
                ]
                .concat()
            })
            .iter()
            .filter_map(|v| {
                v.ip_addresses
                    .as_ref()
                    .map(|ips| (v.hostname.0.to_owned().to_string(), ips.clone()))
            })
            .collect()
    }

    // Same as collect_dns_records() fn but for peers with defined nicknames.
    pub fn collect_dns_nickname_records(&self) -> Records {
        let to_record = |p: &PeerBase| {
            p.nickname
                .as_ref()
                .cloned()
                .and_then(|nick| p.ip_addresses.as_ref().cloned().map(|ips| (nick, ips)))
        };

        self.meshnet_config
            .iter()
            .flat_map(|cfg| {
                to_record(&cfg.this).into_iter().chain(
                    cfg.peers
                        .iter()
                        .flat_map(|peers| peers.iter())
                        .filter_map(|p| to_record(p)),
                )
            })
            .filter(|(nick, _)| validate_nickname(nick))
            .fold(Records::new(), |mut records, (mut nick, ip)| {
                nick += ".nord";

                if let Entry::Vacant(e) = records.entry(nick.to_owned()) {
                    e.insert(ip);
                } else {
                    telio_log_warn!("Nickname is already assigned: {nick:?}. Ignore");
                }

                records
            })
    }
}

impl MeshnetEntities {
    async fn stop(mut self) -> MeshnetEntitiesLastState {
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

        if let Some(direct) = self.direct.take() {
            // Arc dependency on CrossPingCheck
            stop_arc_entity!(direct.upgrade_sync, "UpgradeSync");
            // Arc dependency on endpoint providers
            stop_arc_entity!(direct.cross_ping_check, "CrossPingCheck");
            drop(direct.endpoint_providers);

            // Arc dependency on wireguard
            if let Some(local) = direct.local_interfaces_endpoint_provider {
                stop_arc_entity!(local, "LocalInterfacesEndpointProvider");
            }
            if let Some(stun) = direct.stun_endpoint_provider {
                stop_arc_entity!(stun, "StunEndpointProvider");
            }
            if let Some(upnp) = direct.upnp_endpoint_provider {
                stop_arc_entity!(upnp, "UpnpEndpointProvider");
            }

            stop_arc_entity!(direct.session_keeper, "SessionKeeper");
        }

        stop_arc_entity!(self.multiplexer, "Multiplexer");
        stop_arc_entity!(self.derp, "Derp");
        let endpoint_map = self.proxy.get_endpoint_map().await.unwrap_or_default();
        stop_arc_entity!(self.proxy, "UdpProxy");

        MeshnetEntitiesLastState { endpoint_map }
    }
}

impl Runtime {
    async fn start(
        libtelio_wide_event_publisher: Tx<Box<Event>>,
        config: &DeviceConfig,
        features: Features,
        protect: Option<Protect>,
    ) -> Result<Self> {
        let firewall = Arc::new(StatefullFirewall::new(
            features.ipv6,
            features.boringtun_reset_connections.0,
        ));

        let firewall_filter_inbound_packets = {
            let fw = firewall.clone();
            move |peer: &[u8; 32], packet: &[u8]| fw.process_inbound_packet(peer, packet)
        };
        let firewall_filter_outbound_packets = {
            let fw = firewall.clone();
            move |peer: &[u8; 32], packet: &[u8]| fw.process_outbound_packet(peer, packet)
        };
        let firewall_reset_connections = if features.boringtun_reset_connections.0 {
            let fw = firewall.clone();
            let cb = move |exit_pubkey: &PublicKey,
                           exit_ipv4: Ipv4Addr,
                           sink4: &mut dyn io::Write,
                           sink6: &mut dyn io::Write| {
                if let Err(err) = fw.reset_connections(exit_pubkey, exit_ipv4, sink4, sink6) {
                    telio_log_warn!("Failed to reset all connections: {err:?}");
                }
            };
            Some(Arc::new(cb) as Arc<_>)
        } else {
            None
        };

        let socket_pool = Arc::new({
            if let Some(protect) = protect.clone() {
                SocketPool::new(protect)
            } else {
                SocketPool::new(NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    features.is_test_env.unwrap_or(false),
                )?)
            }
        });

        let derp_events = McChan::default();

        let (config_update_ch, collection_trigger_ch, qos_trigger_ch) = if features.nurse.is_some()
        {
            (
                Some(McChan::<Box<MeshConfigUpdateEvent>>::default().tx),
                Some(McChan::<()>::default().tx),
                Some(McChan::<()>::default().tx),
            )
        } else {
            (None, None, None)
        };

        // tests runtime use wg::MockedAdapter
        cfg_if! {
            if #[cfg(not(test))] {
                let analytics_ch = match features.nurse.is_some() {
                    true => Some(McChan::default().tx),
                    false => None
                };
                let wg_events = Chan::<Box<telio_wg::uapi::Event>>::default();
                let wireguard_interface = Arc::new(DynamicWg::start(
                    wg::Io {
                        events: wg_events.tx.clone(),
                        analytics_tx: analytics_ch.clone(),
                        libtelio_wide_event_publisher: Some(libtelio_wide_event_publisher.clone()),
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
                        firewall_reset_connections,
                    },
                    features.link_detection,
                )?);
                let wg_events = wg_events.rx;
            } else {
                let wg::tests::Env {
                        event: wg_events,
                        analytics: analytics_ch,
                        wg: wireguard_interface,
                        adapter,
                } = wg::tests::setup(
                        wg::Config {
                            adapter: config.adapter,
                            name: config.name.clone(),
                            tun: config.tun,
                            socket_pool: socket_pool.clone(),
                            firewall_process_inbound_callback: Some(Arc::new(firewall_filter_inbound_packets)),
                            firewall_process_outbound_callback: Some(Arc::new(
                                firewall_filter_outbound_packets,
                            )),
                            firewall_reset_connections,
                        }
                    ).await;

                    adapter.expect_send_uapi_cmd_generic_call(1).await;
            }
        }

        wireguard_interface
            .set_secret_key(config.private_key)
            .await?;

        #[cfg(test)]
        adapter.lock().await.checkpoint();

        let aggregator = Arc::new(ConnectivityDataAggregator::new(
            AggregatorConfig::new(
                &features
                    .nurse
                    .clone()
                    .filter(|_| telio_lana::is_lana_initialized())
                    .unwrap_or_default(),
            ),
            wireguard_interface.clone(),
            config.private_key.public(),
        ));

        let nurse = if telio_lana::is_lana_initialized() {
            if let Some(nurse_features) = &features.nurse {
                let nurse_io = NurseIo {
                    wg_event_channel: &libtelio_wide_event_publisher,
                    wg_analytics_channel: analytics_ch.clone(),
                    config_update_channel: config_update_ch.clone(),
                    collection_trigger_channel: collection_trigger_ch.clone(),
                    qos_trigger_channel: qos_trigger_ch.clone(),
                };

                Some(Arc::new(
                    Nurse::start_with(
                        config.private_key.public(),
                        NurseConfig::new(nurse_features),
                        nurse_io,
                        aggregator.clone(),
                    )
                    .await,
                ))
            } else {
                telio_log_debug!("nurse not configured");
                None
            }
        } else {
            telio_log_debug!("lana not initialized");
            None
        };

        #[cfg(windows)]
        {
            let adapter_luid = wireguard_interface.get_adapter_luid().await?;
            socket_pool.set_tunnel_interface(adapter_luid);
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        set_tunnel_interface(&socket_pool, config);

        let requested_state = RequestedState {
            device_config: config.clone(),
            keepalive_periods: features.wireguard.persistent_keepalive.clone(),
            ..Default::default()
        };

        let dns = Arc::new(Mutex::new(DNS {
            resolver: None,
            #[cfg(unix)]
            virtual_host_tun_fd: config.tun,
            #[cfg(windows)]
            virtual_host_tun_fd: None,
        }));

        let wg_endpoint_publish_events = Chan::default();
        let wg_upgrade_sync = Chan::default();
        let stun_server_events = Chan::default();

        let post_quantum = Chan::default();

        let postquantum_wg = telio_pq::Entity::new(
            features.post_quantum_vpn,
            socket_pool.clone(),
            post_quantum.tx,
        );

        let polling_interval = interval(Duration::from_secs(5));

        let pmtu_detection = features.pmtu_discovery.map(|cfg| {
            telio_pmtu::Entity::new(
                socket_pool.clone(),
                Duration::from_secs(cfg.response_wait_timeout_s as _),
            )
        });

        Ok(Runtime {
            features,
            requested_state,
            entities: Entities {
                wireguard_interface: wireguard_interface.clone(),
                dns,
                firewall,
                meshnet: MeshnetState::LastState(Default::default()),
                socket_pool,
                nurse,
                aggregator: aggregator.clone(),
                postquantum_wg,
                pmtu_detection,
            },
            event_listeners: EventListeners {
                wg_endpoint_publish_event_subscriber: wg_endpoint_publish_events.rx,
                wg_event_subscriber: wg_events,
                derp_event_subscriber: derp_events.rx,
                endpoint_upgrade_event_subscriber: wg_upgrade_sync.rx,
                stun_server_subscriber: stun_server_events.rx,
                post_quantum_subscriber: post_quantum.rx,
            },
            event_publishers: EventPublishers {
                libtelio_event_publisher: libtelio_wide_event_publisher,
                nurse_config_update_publisher: config_update_ch,
                nurse_collection_trigger_publisher: collection_trigger_ch,
                qos_collection_trigger_publisher: qos_trigger_ch,
                wg_endpoint_publish_event_publisher: wg_endpoint_publish_events.tx,
                endpoint_upgrade_event_subscriber: wg_upgrade_sync.tx,
                stun_server_publisher: stun_server_events.tx,
                derp_events_publisher: derp_events.tx,
            },
            polling_interval,
            #[cfg(test)]
            test_env: wg::tests::Env {
                analytics: analytics_ch,
                event: Chan::default().rx,
                wg: wireguard_interface,
                adapter,
            },
        })
    }

    async fn start_meshnet_entities(&mut self) -> Result<MeshnetEntities> {
        let endpoint_publish_events = Chan::default();
        let pong_rxed_events = Chan::default();

        // Start multiplexer
        //
        let (multiplexer_derp_chan, derp_multiplexer_chan) = Chan::pipe();
        let multiplexer = Arc::new(Multiplexer::start(multiplexer_derp_chan));

        // Start UDP proxy
        let proxy = Arc::new(UdpProxy::start(ProxyIo {
            relay: multiplexer.get_channel().await?,
        }));

        // Start Derp client
        let derp = Arc::new(DerpRelay::start_with(
            derp_multiplexer_chan,
            self.entities.socket_pool.clone(),
            self.event_publishers.derp_events_publisher.clone(),
            Some(self.entities.aggregator.clone()),
        ));

        if let Some(nurse) = self.entities.nurse.as_ref() {
            nurse
                .configure_meshnet(Some(NurseMeshnetEntities {
                    multiplexer_channel: multiplexer
                        .get_channel::<HeartbeatMessage>()
                        .await
                        .unwrap_or_default(),
                    derp_event_channel: self.event_publishers.derp_events_publisher.clone(),
                }))
                .await;
        }

        // Start Direct entities if "direct" feature is on
        let direct = if let Some(direct) = &self.features.direct {
            // Create endpoint providers
            let has_provider = |provider| {
                // Default is all providers
                match direct.providers.as_ref().map(|p| p.contains(&provider)) {
                    Some(prov) => prov,
                    None => provider != Upnp,
                }
            };

            use telio_model::features::EndpointProvider::*;

            let ping_pong_tracker = Arc::new(Mutex::new(PingPongHandler::new(
                self.requested_state.device_config.private_key,
            )));
            let mut endpoint_providers: Vec<Arc<dyn EndpointProvider>> = Vec::new();

            // Create Local Interface Endpoint Provider
            let local_interfaces_endpoint_provider = if has_provider(Local) {
                let ep = Arc::new(LocalInterfacesEndpointProvider::new(
                    self.entities
                        .socket_pool
                        .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
                        .await?,
                    self.entities.wireguard_interface.clone(),
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
                    self.entities.wireguard_interface.clone(),
                    ExponentialBackoffBounds {
                        initial: Duration::from_secs(
                            direct
                                .endpoint_interval_secs
                                .unwrap_or(DEFAULT_ENDPOINT_POLL_INTERVAL_SECS),
                        ),
                        maximal: Some(Duration::from_secs(120)),
                    },
                    ping_pong_tracker.clone(),
                    self.event_publishers.stun_server_publisher.clone(),
                    self.features
                        .direct
                        .clone()
                        .unwrap_or_default()
                        .endpoint_providers_optimization
                        .unwrap_or_default()
                        .optimize_direct_upgrade_stun,
                )?);
                endpoint_providers.push(ep.clone());
                Some(ep)
            } else {
                None
            };

            // Create Upnp Endpoint Provider
            let upnp_endpoint_provider = if has_provider(Upnp) {
                let ep = Arc::new(UpnpEndpointProvider::start(
                    self.entities
                        .socket_pool
                        .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
                        .await?,
                    self.entities.wireguard_interface.clone(),
                    ExponentialBackoffBounds {
                        initial: Duration::from_secs(
                            direct
                                .endpoint_interval_secs
                                .unwrap_or(DEFAULT_ENDPOINT_POLL_INTERVAL_SECS),
                        ),
                        maximal: Some(Duration::from_secs(120)),
                    },
                    ping_pong_tracker.clone(),
                    self.features
                        .direct
                        .clone()
                        .unwrap_or_default()
                        .endpoint_providers_optimization
                        .unwrap_or_default()
                        .optimize_direct_upgrade_upnp,
                )?);
                endpoint_providers.push(ep.clone());
                Some(ep)
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

            let last_rx_time_provider: Option<Arc<dyn TimeSinceLastRxProvider>> =
                if let Some(skip_unresponsive_peers) = &direct.skip_unresponsive_peers {
                    Some(Arc::new(WireGuardTimeSinceLastRxProvider {
                        wg: self.entities.wireguard_interface.clone(),
                        threshold: Duration::from_secs(
                            skip_unresponsive_peers.no_rx_threshold_secs,
                        ),
                    }))
                } else {
                    None
                };
            // Create Cross Ping Check
            let cross_ping_check = Arc::new(CrossPingCheck::start(
                CpcIo {
                    endpoint_change_subscriber: endpoint_publish_events.rx,
                    pong_rx_subscriber: pong_rxed_events.rx,
                    wg_endpoint_publisher: self
                        .event_publishers
                        .wg_endpoint_publish_event_publisher
                        .clone(),
                    intercoms: multiplexer.get_channel().await?,
                },
                endpoint_providers.clone(),
                last_rx_time_provider.clone(),
                Duration::from_secs(2),
                ping_pong_tracker,
                Default::default(),
            ));

            // Create WireGuard connection upgrade synchronizer
            let upgrade_sync = Arc::new(UpgradeSync::new(
                self.event_publishers
                    .endpoint_upgrade_event_subscriber
                    .clone(),
                multiplexer.get_channel().await?,
                Duration::from_secs(5),
                cross_ping_check.clone(),
                multiplexer.get_channel().await?,
                self.requested_state.device_config.private_key.public(),
                self.entities.aggregator.clone(),
                self.entities.wireguard_interface.clone(),
            )?);

            let session_keeper = Arc::new(SessionKeeper::start(self.entities.socket_pool.clone())?);

            Some(DirectEntities {
                local_interfaces_endpoint_provider,
                stun_endpoint_provider,
                upnp_endpoint_provider,
                endpoint_providers,
                cross_ping_check,
                upgrade_sync,
                session_keeper,
            })
        } else {
            None
        };

        Ok(MeshnetEntities {
            multiplexer,
            derp,
            proxy,
            direct,
        })
    }

    async fn external_nodes(&self) -> Result<Vec<Node>> {
        let wgi = self.entities.wireguard_interface.get_interface().await?;
        let mut nodes = Vec::new();
        for peer in wgi.peers.values() {
            if let Some(node) = self.peer_to_node(peer, None, None).await {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }

    async fn upsert_dns_peers(&self) -> Result {
        if let Some(dns) = &self.entities.dns.lock().await.resolver {
            let mut peers: Records = HashMap::new();
            // Hostnames have priority over nicknames (override if there's any conflict)
            if self.features.nicknames {
                peers = self.requested_state.collect_dns_nickname_records();
            }
            peers.extend(self.requested_state.collect_dns_records());

            // Insert wildcard for subdomains
            let wildcarded_peers: Records = peers
                .iter()
                .map(|(name, ip)| (format!("*.{}", name), ip.clone()))
                .collect();
            peers.extend(wildcarded_peers);

            dns.upsert("nord", &peers, self.features.dns.ttl_value)
                .await
                .map_err(Error::DnsResolverError)?;
        }

        Ok(())
    }

    async fn set_private_key(&mut self, private_key: &SecretKey) -> Result {
        // TODO: create a global controll state to consolidate all entities

        let should_validate_keys = self.features.validate_keys.0;
        let meshnet_is_on = self.requested_state.meshnet_config.is_some();
        let key_is_the_different = self.get_private_key().await? != *private_key;
        if should_validate_keys && meshnet_is_on && key_is_the_different {
            return Err(Error::BadPublicKey);
        }

        if self.entities.dns.lock().await.resolver.is_some() {
            return Err(Error::DnsNotDisabled);
        }

        if let Some(m_entities) = self.entities.meshnet.left() {
            m_entities
                .derp
                .configure(m_entities.derp.get_config().await.map(|c| DerpConfig {
                    secret_key: *private_key,
                    ..c
                }))
                .await;

            if let Some(direct) = m_entities.direct.as_ref() {
                let _ = direct
                    .upgrade_sync
                    .set_public_key(private_key.public())
                    .await;
            }
        }

        self.entities
            .aggregator
            .set_local_key(private_key.public())
            .await;

        self.requested_state.device_config.private_key = *private_key;

        if let Some(nurse) = &self.entities.nurse {
            nurse.set_private_key(*private_key).await;
        }

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
            .await?;
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
        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
            .await?;
        Ok(())
    }

    async fn notify_network_change(&mut self) -> Result {
        self.entities
            .wireguard_interface
            .drop_connected_sockets()
            .await?;

        if let Some(meshnet_entities) = self.entities.meshnet.left() {
            meshnet_entities.proxy.on_network_change().await;
            if let Some(direct) = &meshnet_entities.direct {
                if let Some(stun) = &direct.stun_endpoint_provider {
                    // this unpauses provider if paused
                    stun.reconnect().await;
                }

                if let Some(upnp) = &direct.upnp_endpoint_provider {
                    upnp.unpause().await;
                }
            }

            meshnet_entities.derp.reconnect().await;
        }

        self.log_nat().await;
        Ok(())
    }

    async fn notify_sleep(&mut self) -> Result {
        self.entities
            .aggregator
            .force_save_unacknowledged_segments()
            .await;
        Ok(())
    }

    async fn notify_wakeup(&mut self) -> Result {
        self.entities.aggregator.clear_ongoinging_segments().await;
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
                    self.features.dns.exit_dns.clone(),
                )
                .await
                .map_err(Error::DnsResolverError)?;
                dns.start().await;
                dns_entity.resolver = Some(dns);
            }
        } // Release locks before controller takes over

        self.upsert_dns_peers().await?;

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
            .await?;

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

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
            .await?;
        Ok(())
    }

    async fn set_config(&mut self, config: &Option<Config>) -> Result {
        if self.entities.postquantum_wg.is_rotating_keys() && config.is_some() {
            // Post quantum VPN is enabled and we're trying to set up the meshnet
            return Err(Error::MeshnetUnavailableWithPQ);
        }

        if let Some(cfg) = config {
            let should_validate_keys = self.features.validate_keys.0;
            let keys_match =
                cfg.this.public_key == self.get_private_key().await.map(|key| key.public())?;
            if should_validate_keys && !keys_match {
                return Err(Error::BadPublicKey);
            }
        }

        self.requested_state.old_meshnet_config = self.requested_state.meshnet_config.clone();
        self.requested_state.meshnet_config = config.clone();

        let wg_itf = self.entities.wireguard_interface.get_interface().await?;
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
            let wg_port_for_proxy = self
                .entities
                .wireguard_interface
                .wait_for_proxy_listen_port(Duration::from_secs(1))
                .await?;

            let meshnet_entities: MeshnetEntities = if let MeshnetState::Entities(entities) =
                std::mem::replace(
                    &mut self.entities.meshnet,
                    MeshnetState::LastState(Default::default()),
                ) {
                entities
            } else {
                self.start_meshnet_entities().await?
            };

            let proxy_config = ProxyConfig {
                wg_port: Some(wg_port_for_proxy),
                peers: peers.clone(),
            };

            meshnet_entities.proxy.configure(proxy_config).await?;

            let derp_config = DerpConfig {
                secret_key,
                servers: SortedServers::new(config.derp_servers.clone().unwrap_or_default()),
                allowed_pk: peers,
                timeout: Duration::from_secs(10), //TODO: make configurable
                server_keepalives: DerpKeepaliveConfig::from(&self.features.derp),
                enable_polling: self
                    .features
                    .derp
                    .clone()
                    .unwrap_or_default()
                    .enable_polling
                    .unwrap_or_default(),
                meshnet_peers: config
                    .peers
                    .as_ref()
                    .map(|peers| peers.iter().map(|peer| peer.public_key).collect())
                    .unwrap_or_default(),
                use_built_in_root_certificates: self
                    .features
                    .derp
                    .clone()
                    .unwrap_or_default()
                    .use_built_in_root_certificates,
            };

            // Update configuration for DERP client
            meshnet_entities.derp.configure(Some(derp_config)).await;

            // Refresh the lists of servers for STUN endpoint provider
            if let Some(direct) = meshnet_entities.direct.as_ref() {
                if let Some(stun_ep) = direct.stun_endpoint_provider.as_ref() {
                    let use_ipv6 = self.features.ipv6 && {
                        config
                            .this
                            .ip_addresses
                            .as_ref()
                            .map(|vec| vec.iter().any(|addr| addr.is_ipv6()))
                            .unwrap_or(false)
                    };

                    stun_ep
                        .configure(
                            config.derp_servers.clone().unwrap_or_default(),
                            use_ipv6,
                            self.get_socket_pool().await?,
                        )
                        .await;
                }
            }

            self.entities.meshnet = MeshnetState::Entities(meshnet_entities);

            self.upsert_dns_peers().await?;
        } else {
            // Nurse is keeping Arc to Derp, so we need to get rid of it before stopping Derp
            if let Some(nurse) = self.entities.nurse.as_ref() {
                nurse.configure_meshnet(None).await;
            }

            if let MeshnetState::Entities(meshnet_entities) = std::mem::replace(
                &mut self.entities.meshnet,
                MeshnetState::LastState(Default::default()),
            ) {
                let meshnet_entities_last_state = meshnet_entities.stop().await;
                self.entities.meshnet = MeshnetState::LastState(meshnet_entities_last_state);
            }

            self.requested_state.wg_stun_server = None;

            self.upsert_dns_peers().await?;
        }

        if let Some(cpc) = self.entities.cross_ping_check() {
            cpc.configure(config.clone()).await?;
        }

        // If Disabling meshnet (by calling `set_config()` with `None` as the argument) need to clear exit node
        // so that the controller does not mistake it for a VPN node. See LLT-4266 for more details.
        if self.requested_state.meshnet_config.is_none() {
            if let Some(exit_node) = self.requested_state.exit_node.as_ref() {
                if let Some(Config {
                    peers: Some(peers), ..
                }) = self.requested_state.old_meshnet_config.as_ref()
                {
                    peers
                        .iter()
                        .any(|peer| exit_node.public_key == peer.base.public_key)
                        .then(|| self.requested_state.exit_node = None);
                }
            }
        }

        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
            .await?;

        for ep in self.entities.endpoint_providers().iter() {
            if let Err(err) = ep.trigger_endpoint_candidates_discovery(true).await {
                // This can fail on first config, because it takes a bit of time to resolve
                // stun endpoint for StunEndpointProvider for WgStunControll
                telio_log_debug!("Failed to trigger: {}", err);
            }
        }

        self.log_nat().await;

        if let Some(tx) = &self.event_publishers.nurse_config_update_publisher {
            let event = MeshConfigUpdateEvent::from(config);
            if tx.send(Box::new(event)).is_err() {
                telio_log_warn!("Failed to send MeshConfigUpdateEvent to nurse component");
            }
        }

        Ok(())
    }

    /// Logs NAT type of derp server in info log
    async fn log_nat(&self) {
        if let Some(server) = self.requested_state.meshnet_config.as_ref().and_then(|c| {
            c.derp_servers
                .as_ref()
                .and_then(|servers| servers.iter().min_by_key(|server| server.weight))
        }) {
            // Copy the lowest weight server to log nat in a separate future
            let stun_server_skt =
                SocketAddr::new(IpAddr::V4(server.ipv4), server.stun_plaintext_port);
            tokio::spawn(async move {
                if let Ok(data) = retrieve_single_nat(stun_server_skt).await {
                    telio_log_debug!("Nat Type - {:?}", data.nat_type)
                }
            });
        }
    }

    /// Connect ot exit node with post-quantum tunnel
    async fn connect_exit_node_pq(&mut self, exit_node: &ExitNode) -> Result {
        if self.requested_state.meshnet_config.is_some() {
            // Meshnet is enabled and we're trying to set up the QP VPN connection
            return Err(Error::MeshnetUnavailableWithPQ);
        }

        // This is required to silence the dylint error "error: large future with a size of 2048 bytes"
        let res = self
            .connect_exit_node_internal(exit_node, true)
            .boxed()
            .await;

        if res.is_err() {
            // Stop PQ task
            self.entities.postquantum_wg.stop();
        }

        res
    }

    async fn connect_exit_node(&mut self, exit_node: &ExitNode) -> Result {
        // Silence the nagger warning
        Box::pin(self.connect_exit_node_internal(exit_node, false)).await
    }

    async fn connect_exit_node_internal(
        &mut self,
        exit_node: &ExitNode,
        postquantum: bool,
    ) -> Result {
        let exit_node = exit_node.clone();

        // Stop post quantum key rotation task if it's running
        self.entities.postquantum_wg.stop();

        if postquantum {
            self.entities.postquantum_wg.start(
                exit_node.endpoint.ok_or(Error::EndpointNotProvided)?,
                self.requested_state.device_config.private_key,
                exit_node.public_key,
            );
        }

        // dns socket for macos should only be bound to tunnel interface when connected to exit,
        // otherwise with no exit dns peer will try to forward packets through tunnel and fail
        bind_tun::set_should_bind(true);

        let is_meshnet_exit_node = self
            .requested_state
            .meshnet_config
            .as_ref()
            .and_then(|config| config.peers.as_deref())
            .map(|peers| peers.iter().any(|p| p.public_key == exit_node.public_key))
            .unwrap_or_default();

        if is_meshnet_exit_node {
            if let Some(dns) = &self.entities.dns.lock().await.resolver {
                self.reconfigure_dns_peer(dns, &dns.get_default_dns_servers())
                    .await?;
            }
        } else if let Some(addr) = exit_node.endpoint {
            if let Some(pmtud) = &mut self.entities.pmtu_detection {
                pmtud.run(addr.ip()).await;
            }
        } else {
            return Err(Error::EndpointNotProvided);
        }

        let old_exit_node = self.requested_state.exit_node.replace(exit_node);
        wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
            .await?;

        if let Some(last_exit) = old_exit_node
            .as_ref()
            .or(self.requested_state.last_exit_node.as_ref())
        {
            let ipv4 = if let Some(cfg) = self.requested_state.meshnet_config.as_ref() {
                let find_ip = || {
                    let peers = cfg.peers.as_deref()?;
                    let peer = peers
                        .iter()
                        .find(|pr| pr.public_key == last_exit.public_key)?;

                    peer.ip_addresses
                        .as_deref()?
                        .iter()
                        .find_map(|ip| match ip {
                            IpAddr::V4(ip) => Some(*ip),
                            IpAddr::V6(_) => None,
                        })
                };

                if let Some(ipv4) = find_ip() {
                    // Exit node is a meshnet peer
                    ipv4
                } else {
                    // The meshnet is ON
                    Ipv4Addr::new(100, 64, 0, 1)
                }
            } else {
                // The meshnet is OFF
                Ipv4Addr::new(10, 5, 0, 1)
            };

            self.entities
                .wireguard_interface
                .reset_existing_connections(last_exit.public_key, ipv4)
                .await?;
        }

        Ok(())
    }

    async fn disconnect_exit_node(&mut self, node_key: &PublicKey) -> Result {
        match self.requested_state.exit_node.as_ref() {
            Some(exit_node) if &exit_node.public_key == node_key => {
                self.entities
                    .firewall
                    .remove_from_peer_whitelist(exit_node.public_key);
                self.disconnect_exit_nodes().boxed().await
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

            wg_controller::consolidate_wg_state(
                &self.requested_state,
                &self.entities,
                &self.features,
            )
            .await?;
        }

        self.entities.postquantum_wg.stop();

        if let Some(pmtud) = &mut self.entities.pmtu_detection {
            pmtud.stop().await;
        }

        Ok(())
    }

    #[allow(clippy::panic)]
    async fn _panic(&mut self) -> Result {
        let _ = tokio::spawn(async {
            panic!("runtime_panic_test");
        })
        .await;

        Ok(())
    }

    async fn get_socket_pool(&self) -> Result<Arc<SocketPool>> {
        Ok(self.entities.socket_pool.clone())
    }

    async fn peer_to_node<'a>(
        &'a self,
        peer: &uapi::Peer,
        state: Option<PeerState>,
        link_state: Option<LinkState>,
    ) -> Option<Node> {
        let endpoint = peer.endpoint;

        // Check if ExitNode in requested state matches the node being reported by public
        // key
        let exit_node = self
            .requested_state
            .exit_node
            .as_ref()
            .or(self.requested_state.last_exit_node.as_ref())
            .filter(|node| node.public_key == peer.public_key);

        // Find a peer with matching public key in meshnet_config and retrieve the needed
        // information about it from there
        let get_config_peer = |config: Option<&'a Config>| {
            config
                .and_then(|cfg| cfg.peers.as_ref())?
                .iter()
                .find(|&p| p.base.public_key == peer.public_key)
        };
        let meshnet_peer: Option<&Peer> =
            get_config_peer(self.requested_state.meshnet_config.as_ref())
                .or_else(|| get_config_peer(self.requested_state.old_meshnet_config.as_ref()));

        // Resolve what type of path is used
        let endpoint_map = match &self.entities.meshnet {
            MeshnetState::Entities(meshnet_entities) => meshnet_entities
                .proxy
                .get_endpoint_map()
                .await
                .unwrap_or_else(|err| {
                    telio_log_warn!("Failed to get proxy endpoint map: {}", err);
                    Default::default()
                }),
            MeshnetState::LastState(last_state) => last_state.endpoint_map.clone(),
        };

        let path_type = endpoint_map
            .get(&peer.public_key)
            .and_then(|proxy| endpoint.filter(|actual| proxy.contains(actual)))
            .map_or(PathType::Direct, |_| PathType::Relay);

        // Build a node to report event about, we need to report about either meshnet peers
        // or VPN peers. Others (like DNS, or anycast) are considered to be "internal" ones
        // and will not be reported via libtelio events.
        match (meshnet_peer, exit_node) {
            (Some(meshnet_peer), _) => {
                // Meshnet peer
                Some(Node {
                    identifier: meshnet_peer.base.identifier.clone(),
                    public_key: meshnet_peer.base.public_key,
                    nickname: meshnet_peer.base.nickname.clone(),
                    state: state.unwrap_or_else(|| peer.state()),
                    link_state,
                    is_exit: peer
                        .allowed_ips
                        .iter()
                        .any(|network| network.ip().is_unspecified()),
                    is_vpn: false,
                    ip_addresses: meshnet_peer.base.ip_addresses.clone().unwrap_or_default(),
                    allowed_ips: peer.allowed_ips.clone(),
                    endpoint,
                    hostname: Some(meshnet_peer.base.hostname.0.clone().to_string()),
                    allow_incoming_connections: meshnet_peer.allow_incoming_connections,
                    allow_peer_send_files: meshnet_peer.allow_peer_send_files,
                    path: path_type,
                })
            }
            (None, Some(exit_node)) => {
                // Exit node
                Some(Node {
                    identifier: exit_node.identifier.clone(),
                    public_key: exit_node.public_key,
                    nickname: None,
                    state: state.unwrap_or_else(|| peer.state()),
                    link_state,
                    is_exit: true,
                    is_vpn: exit_node.endpoint.is_some(),
                    ip_addresses: vec![
                        IpAddr::V4(Ipv4Addr::new(10, 5, 0, 1)),
                        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                    ],
                    allowed_ips: peer.allowed_ips.clone(),
                    endpoint,
                    hostname: None,
                    allow_incoming_connections: false,
                    allow_peer_send_files: false,
                    path: path_type,
                })
            }
            _ => None,
        }
    }

    async fn trigger_analytics_event(&self) -> Result<()> {
        if let Some(ch) = &self.event_publishers.nurse_collection_trigger_publisher {
            let _ = ch.send(());
            Ok(())
        } else {
            Err(Error::NotStarted)
        }
    }

    async fn trigger_qos_collection(&self) -> Result<()> {
        if let Some(ch) = &self.event_publishers.qos_collection_trigger_publisher {
            let _ = ch.send(());
            Ok(())
        } else {
            Err(Error::NotStarted)
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
                telio_log_debug!("WG consolidation triggered by endpoint publish event");
                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("WireGuard controller failure: {:?}. Ignoring", e);
                        });
                Ok(())
            },

            Some(mesh_event) = self.event_listeners.wg_event_subscriber.recv() => {
                let public_key = mesh_event.peer.public_key;

                if let Some(mesh_entities) = self.entities.meshnet.left() {
                    if let Some(proxy_endpoints) = mesh_entities.proxy.get_endpoint_map().await.ok().as_mut().and_then(|proxy_map| proxy_map.remove(&public_key)) {
                        let is_proxying = mesh_event.peer.endpoint.map_or(false, |ep| proxy_endpoints.contains(&ep));
                        let was_proxying = mesh_event.old_peer.as_ref().and_then(|peer| peer.endpoint.map(|ep| proxy_endpoints.contains(&ep))).unwrap_or_default();

                        if !was_proxying && is_proxying {
                            if let Some(direct_entities) = mesh_entities.direct.as_ref() {
                                // We have downgraded the connection. Notify cross ping check about that.
                                direct_entities.cross_ping_check.notify_failed_wg_connection(public_key)
                                    .await?;

                                direct_entities.session_keeper.remove_node(&public_key).await?;

                                let mut event = AnalyticsEvent::from_event(&mesh_event);
                                event.peer_state = PeerState::Connected;
                                self.entities.aggregator.change_peer_state_relayed(&event).await;
                            } else {
                                telio_log_warn!("Connection downgraded while direct entities are disabled");
                            }

                            // Unmute pair to allow communication through proxy
                            mesh_entities.proxy.mute_peer(public_key, None).await?;

                            telio_log_info!("Peer {} was downgraded", public_key);
                        }
                    }
                }

                let node = self.peer_to_node(&mesh_event.peer, Some(mesh_event.state), mesh_event.link_state).await;

                if let Some(node) = node {
                    if mesh_event.state != PeerState::Connecting && node.path == PathType::Relay {
                        self.entities.aggregator.change_peer_state_relayed(
                            &AnalyticsEvent::from_event(&mesh_event)
                        ).await;
                    }
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
                telio_log_debug!("WG consolidation triggered by upgrade sync request");
                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("WireGuard controller failure: {:?}. Ignoring", e);
                        });

                Ok(())
            },

            Some(wg_stun_server) = self.event_listeners.stun_server_subscriber.recv() => {
                telio_log_debug!("WG consolidation triggered by STUN server event");

                self.requested_state.wg_stun_server = wg_stun_server;

                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("WireGuard controller failure: {:?}. Ignoring", e);
                        });
                Ok(())
            },

            Some(pq_event) = self.event_listeners.post_quantum_subscriber.recv() => {
                telio_log_debug!("WG consolidation triggered by PQ event");

                self.entities.postquantum_wg.on_event(pq_event);

                if let Err(err) = wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
                    .await
                {
                    telio_log_warn!("WireGuard controller failure: {err:?}. Ignoring");
                }

                Ok(())
            },

            _ = self.polling_interval.tick() => {
                telio_log_debug!("WG consolidation triggered by tick event");
                wg_controller::consolidate_wg_state(&self.requested_state, &self.entities, &self.features)
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

        // Nurse is keeping Arc to Derp, so we need to get rid of it before stopping Derp
        if let Some(nurse) = self.entities.nurse.as_ref() {
            nurse.configure_meshnet(None).await;
        }

        if let MeshnetState::Entities(meshnet_entities) = self.entities.meshnet {
            meshnet_entities.stop().await;
        }

        if let Some(nurse) = self.entities.nurse {
            stop_arc_entity!(nurse, "Nurse");
        }

        drop(self.entities.aggregator);

        stop_arc_entity!(self.entities.wireguard_interface, "WireguardInterface");

        self.requested_state = Default::default();
    }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use std::net::Ipv6Addr;
    use telio_model::config::{Peer, PeerBase};
    use telio_model::features::FeatureDirect;

    fn build_peer_base(
        hostname: String,
        ip_addresses: Option<Vec<IpAddr>>,
        nickname: Option<String>,
    ) -> PeerBase {
        PeerBase {
            hostname: telio_utils::Hidden(hostname),
            ip_addresses,
            nickname,
            ..Default::default()
        }
    }

    fn build_peer(
        hostname: String,
        ip_addresses: Option<Vec<IpAddr>>,
        nickname: Option<String>,
    ) -> Peer {
        Peer {
            base: build_peer_base(hostname, ip_addresses, nickname),
            ..Default::default()
        }
    }

    fn build_mesh_config(peers: Option<Vec<Peer>>) -> Config {
        Config {
            peers,
            ..Default::default()
        }
    }

    #[test]
    fn test_collect_dns_records() {
        let alpha_ipv4 = Ipv4Addr::new(1, 2, 3, 4);
        let alpha_ipv6 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let beta_ipv4 = Ipv4Addr::new(4, 3, 2, 1);
        let gamma_ipv6 = Ipv6Addr::new(8, 7, 6, 5, 4, 3, 2, 1);

        let peers = Some(vec![
            build_peer(
                String::from("alpha.nord"),
                Some(vec![IpAddr::V4(alpha_ipv4), IpAddr::V6(alpha_ipv6)]),
                None,
            ),
            build_peer(
                String::from("beta.nord"),
                Some(vec![IpAddr::V4(beta_ipv4)]),
                None,
            ),
            build_peer(
                String::from("gamma.nord"),
                Some(vec![IpAddr::V6(gamma_ipv6)]),
                None,
            ),
        ]);

        let requested_state = RequestedState {
            meshnet_config: Some(build_mesh_config(peers)),
            ..Default::default()
        };

        let records = requested_state.collect_dns_records();

        assert!(records["alpha.nord"].contains(&IpAddr::V4(alpha_ipv4)));
        assert!(records["alpha.nord"].contains(&IpAddr::V6(alpha_ipv6)));

        assert_eq!(records["beta.nord"].clone(), vec![IpAddr::V4(beta_ipv4)]);
        assert_eq!(records["gamma.nord"].clone(), vec![IpAddr::V6(gamma_ipv6)]);

        assert_eq!(records.len(), 3);
    }

    #[test]
    fn test_collect_dns_nickname_records() {
        let alpha_ipv4 = Ipv4Addr::new(1, 2, 3, 4);
        let alpha_ipv6 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let beta_ipv4 = Ipv4Addr::new(4, 3, 2, 1);
        let gamma_ipv6 = Ipv6Addr::new(8, 7, 6, 5, 4, 3, 2, 1);

        let peers = Some(vec![
            build_peer(
                String::from("alpha.nord"),
                Some(vec![IpAddr::V4(alpha_ipv4), IpAddr::V6(alpha_ipv6)]),
                Some("johnnyrotten".to_owned()),
            ),
            build_peer(
                String::from("beta.nord"),
                Some(vec![IpAddr::V4(beta_ipv4)]),
                Some("bond-jamesbond".to_owned()),
            ),
            build_peer(
                String::from("gaMMa.nord"),
                Some(vec![IpAddr::V6(gamma_ipv6)]),
                None,
            ),
            build_peer(String::from("theta.nord"), None, Some("pluto".to_owned())),
        ]);

        let requested_state = RequestedState {
            meshnet_config: Some(build_mesh_config(peers)),
            ..Default::default()
        };

        let mut records = requested_state.collect_dns_nickname_records();
        records.extend(requested_state.collect_dns_records());

        assert!(records["alpha.nord"].contains(&IpAddr::V4(alpha_ipv4)));
        assert!(records["alpha.nord"].contains(&IpAddr::V6(alpha_ipv6)));
        assert!(records["johnnyrotten.nord"].contains(&IpAddr::V4(alpha_ipv4)));
        assert!(records["johnnyrotten.nord"].contains(&IpAddr::V6(alpha_ipv6)));

        assert_eq!(records["beta.nord"].clone(), vec![IpAddr::V4(beta_ipv4)]);
        assert_eq!(
            records["bond-jamesbond.nord"].clone(),
            vec![IpAddr::V4(beta_ipv4)]
        );

        assert_eq!(records["gaMMa.nord"].clone(), vec![IpAddr::V6(gamma_ipv6)]);

        assert!(!records.contains_key("theta.nord"));

        assert_eq!(records.len(), 5);
    }

    #[test]
    fn test_collect_dns_nickname_records_invalid() {
        let valid_hostname = "alpha.nord";
        let valid_ipv4 = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        let valid_nickname = Some("johnnyrotten".to_owned());

        let requested_state = RequestedState {
            meshnet_config: Some(build_mesh_config(Some(vec![
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    valid_nickname.clone(),
                ),
                // Contains a ' '
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    Some("johnny rotten".to_owned()),
                ),
                // Start with a '-'
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    Some("-johnnyrotten".to_owned()),
                ),
                // Ends with a '-'
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    Some("johnnyrotten-".to_owned()),
                ),
                // Larger than 25 chars
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    Some("johnsomethingsomethingsomething".to_owned()),
                ),
                // Contains '--'
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    Some("johnny--rotten".to_owned()),
                ),
                // Ends with "."
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    Some("johnnyrotten.".to_owned()),
                ),
                // Ends with ".nord"
                build_peer(
                    valid_hostname.to_owned(),
                    valid_ipv4.clone(),
                    Some("johnnyrotten.nord".to_owned()),
                ),
            ]))),
            ..Default::default()
        };

        let mut records = requested_state.collect_dns_nickname_records();
        records.extend(requested_state.collect_dns_records());

        assert!(records[valid_hostname].contains(&valid_ipv4.clone().unwrap()[0]));
        assert!(
            records[format!("{}.nord", valid_nickname.clone().unwrap()).as_str()]
                .contains(&valid_ipv4.clone().unwrap()[0])
        );

        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_collect_dns_nickname_records_duplicated() {
        let alpha_ipv4 = Ipv4Addr::new(1, 2, 3, 4);
        let beta_ipv4 = Ipv4Addr::new(2, 3, 4, 1);
        let gamma_ipv4 = Ipv4Addr::new(3, 4, 1, 2);

        let peers = Some(vec![
            build_peer(
                String::from("alpha.nord"),
                Some(vec![IpAddr::V4(alpha_ipv4)]),
                Some("johnnyrotten".to_owned()),
            ),
            build_peer(
                String::from("beta.nord"),
                Some(vec![IpAddr::V4(beta_ipv4)]),
                Some("johnnyrotten".to_owned()),
            ),
            build_peer(
                String::from("gamma.nord"),
                Some(vec![IpAddr::V4(gamma_ipv4)]),
                Some("beta".to_owned()),
            ),
        ]);

        let requested_state = RequestedState {
            meshnet_config: Some(build_mesh_config(peers)),
            ..Default::default()
        };

        let mut records = requested_state.collect_dns_nickname_records();
        records.extend(requested_state.collect_dns_records());

        assert_eq!(records["alpha.nord"].clone(), vec![IpAddr::V4(alpha_ipv4)]);
        assert_eq!(
            records["johnnyrotten.nord"].clone(),
            vec![IpAddr::V4(alpha_ipv4)]
        );
        assert_eq!(records["beta.nord"].clone(), vec![IpAddr::V4(beta_ipv4)]);
        assert_eq!(records["gamma.nord"].clone(), vec![IpAddr::V4(gamma_ipv4)]);

        assert_eq!(records.len(), 4);
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_mocked_adapter() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let features = Features::default();
        let private_key = SecretKey::gen();

        let rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        assert_eq!(
            Interface {
                private_key: Some(private_key),
                listen_port: Some(1234),
                ..Default::default()
            },
            rt.entities
                .wireguard_interface
                .get_interface()
                .await
                .unwrap()
        );
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_disconnect_exit_nodes() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let features = Features::default();

        let private_key = SecretKey::gen();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        let pubkey = private_key.public();
        let exit_node = ExitNode {
            public_key: pubkey,
            ..Default::default()
        };
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: telio_utils::Hidden("hostname".to_owned()),
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            nickname: Some("nickname".to_owned()),
        };
        let get_config = Config {
            this: peer_base.clone(),
            peers: Some(vec![Peer {
                base: peer_base.clone(),
                ..Default::default()
            }]),
            derp_servers: None,
            dns: None,
        };

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        assert!(rt.set_config(&Some(get_config)).await.is_ok());
        assert!(rt.requested_state.exit_node.is_none());
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        assert!(rt.connect_exit_node(&exit_node).await.is_ok());
        assert!(rt.requested_state.exit_node.is_some());
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        assert!(rt.disconnect_exit_nodes().await.is_ok());
        assert!(rt.requested_state.exit_node.is_none());
        rt.test_env.adapter.lock().await.checkpoint();
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_duplicate_allowed_ips() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let features = Features::default();
        let private_key = SecretKey::gen();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        let first_ip_network = ipnetwork::IpNetwork::from(IpAddr::from(Ipv4Addr::new(1, 2, 3, 4)));
        let second_ip_network = ipnetwork::IpNetwork::from(IpAddr::from(Ipv4Addr::new(4, 3, 2, 1)));

        let config = Config {
            this: PeerBase {
                identifier: "identifier".to_owned(),
                public_key: private_key.public(),
                hostname: telio_utils::Hidden("hostname".to_owned()),
                ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
                nickname: Some("nickname".to_owned()),
            },
            peers: Some(vec![
                Peer {
                    base: PeerBase {
                        public_key: SecretKey::gen().public(),
                        ip_addresses: Some(vec![first_ip_network.ip()]),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Peer {
                    base: PeerBase {
                        public_key: SecretKey::gen().public(),
                        ip_addresses: Some(vec![second_ip_network.ip()]),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ]),
            derp_servers: None,
            dns: None,
        };

        let vpn_node = ExitNode {
            public_key: SecretKey::gen().public(),
            allowed_ips: Some(vec![first_ip_network]),
            ..Default::default()
        };

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(2)
            .await;
        assert!(matches!(rt.set_config(&Some(config)).await, Ok(())));
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(0)
            .await;
        let _expected_error: super::Error = wg_controller::Error::BadAllowedIps.into();
        assert!(matches!(
            rt.connect_exit_node(&vpn_node).await,
            Err(_expected_error)
        ));
        rt.test_env.adapter.lock().await.checkpoint();
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_exit_node_demote() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let features = Default::default();
        let private_key = SecretKey::gen();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        let pubkey = private_key.public();
        let node = ExitNode {
            public_key: pubkey,
            ..Default::default()
        };
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: telio_utils::Hidden("hostname".to_owned()),
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            nickname: Some("nickname".to_owned()),
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

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        assert!(rt.set_config(&config).await.is_ok());
        assert!(rt.requested_state.exit_node.is_none());
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        assert!(rt.connect_exit_node(&node).await.is_ok());
        assert_eq!(
            rt.requested_state.exit_node.as_ref().unwrap().public_key,
            pubkey
        );
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(0)
            .await;
        assert!(rt.set_config(&config).await.is_ok());
        assert_eq!(
            rt.requested_state.exit_node.as_ref().unwrap().public_key,
            pubkey
        );
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        assert!(rt.disconnect_exit_node(&pubkey).await.is_ok());
        assert!(rt.requested_state.exit_node.is_none());
        rt.test_env.adapter.lock().await.checkpoint();
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_default_features_when_direct_is_empty() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let features = Features {
            direct: Some(FeatureDirect {
                providers: None,
                endpoint_interval_secs: None,
                skip_unresponsive_peers: Default::default(),
                endpoint_providers_optimization: None,
            }),
            ..Default::default()
        };

        let private_key = SecretKey::gen();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        assert!(
            rt.entities.meshnet.is_right(),
            "Meshnet is not configured yet"
        );

        let pubkey = private_key.public();
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: telio_utils::Hidden("hostname".to_owned()),
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            nickname: Some("nickname".to_owned()),
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

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.set_config(&config).await.unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        let entities = rt
            .entities
            .meshnet
            .expect_left("Meshnet entities should be available when meshnet was configured")
            .direct
            .as_ref()
            .expect("Direct entities should be available when \"direct\" feature is on");

        assert!(entities.upnp_endpoint_provider.is_none());
        assert!(entities.local_interfaces_endpoint_provider.is_some());
        assert!(entities.stun_endpoint_provider.is_some());
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_default_features_when_provider_is_empty() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let features = Features {
            direct: Some(FeatureDirect {
                providers: Some(HashSet::new()),
                endpoint_interval_secs: None,
                skip_unresponsive_peers: Default::default(),
                endpoint_providers_optimization: None,
            }),
            ..Default::default()
        };

        let private_key = SecretKey::gen();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        assert!(
            rt.entities.meshnet.is_right(),
            "Meshnet is not configured yet"
        );

        let pubkey = private_key.public();
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: telio_utils::Hidden("hostname".to_owned()),
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            nickname: Some("nickname".to_owned()),
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

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.set_config(&config).await.unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        let entities = rt
            .entities
            .meshnet
            .expect_left("Meshnet entities should be available when meshnet was configured")
            .direct
            .as_ref()
            .expect("Direct entities should be available when \"direct\" feature is on");

        assert!(entities.upnp_endpoint_provider.is_none());
        assert!(entities.local_interfaces_endpoint_provider.is_none());
        assert!(entities.stun_endpoint_provider.is_none());
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_enable_all_direct_features() {
        use telio_model::features::FeatureSkipUnresponsivePeers;

        let (sender, _receiver) = tokio::sync::broadcast::channel(1);

        let providers = maplit::hashset! {
            telio_model::features::EndpointProvider::Stun,
            telio_model::features::EndpointProvider::Upnp,
            telio_model::features::EndpointProvider::Local,
        };

        let features = Features {
            direct: Some(FeatureDirect {
                providers: Some(providers),
                endpoint_interval_secs: None,
                skip_unresponsive_peers: Some(FeatureSkipUnresponsivePeers {
                    no_rx_threshold_secs: 42,
                }),
                endpoint_providers_optimization: None,
            }),
            ..Default::default()
        };

        let private_key = SecretKey::gen();

        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        assert!(
            rt.entities.meshnet.is_right(),
            "Meshnet is not configured yet"
        );

        let pubkey = private_key.public();
        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: pubkey,
            hostname: telio_utils::Hidden("hostname".to_owned()),
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            nickname: Some("nickname".to_owned()),
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

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.set_config(&config).await.unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        let entities = rt
            .entities
            .meshnet
            .expect_left("Meshnet entities should be available when meshnet was configured")
            .direct
            .as_ref()
            .expect("Direct entities should be available when \"direct\" feature is on");

        assert!(entities.upnp_endpoint_provider.is_some());
        assert!(entities.local_interfaces_endpoint_provider.is_some());
        assert!(entities.stun_endpoint_provider.is_some());
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_set_config_with_wrong_public_key() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);

        let features = Features::default();
        let private_key = SecretKey::gen();
        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        fn gen_config(public_key: PublicKey) -> Config {
            let peer_base = PeerBase {
                identifier: "identifier".to_owned(),
                public_key,
                hostname: telio_utils::Hidden("hostname".to_owned()),
                ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
                nickname: Some("nickname".to_owned()),
            };
            Config {
                this: peer_base.clone(),
                peers: Some(vec![Peer {
                    base: peer_base.clone(),
                    ..Default::default()
                }]),
                derp_servers: None,
                dns: None,
            }
        }

        let valid_cfg = Some(gen_config(private_key.public()));
        let invalid_cfg = Some(gen_config(SecretKey::gen().public()));

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;

        assert!(rt.set_config(&valid_cfg).await.is_ok());
        assert!(matches!(
            rt.set_config(&invalid_cfg).await.unwrap_err(),
            Error::BadPublicKey
        ));
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_set_private_key_when_meshnet_is_on() {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);

        let features = Features::default();
        let old_private_key = SecretKey::gen();
        let new_private_key = SecretKey::gen();
        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key: old_private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: new_private_key.public(),
            hostname: telio_utils::Hidden("hostname".to_owned()),
            ip_addresses: Some(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            nickname: Some("nickname".to_owned()),
        };
        let config = Config {
            this: peer_base.clone(),
            peers: Some(vec![Peer {
                base: peer_base.clone(),
                ..Default::default()
            }]),
            derp_servers: None,
            dns: None,
        };
        let config = Some(config);

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        assert!(rt.set_private_key(&new_private_key).await.is_ok());
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.set_config(&config).await.unwrap();
        assert!(matches!(
            rt.set_private_key(&SecretKey::gen()).await.unwrap_err(),
            Error::BadPublicKey
        ));
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn test_disabling_meshnet_will_not_fail_if_wg_has_not_listen_port() {
        let sender = tokio::sync::broadcast::channel(1).0;

        let pk = SecretKey::gen();
        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key: pk,
                ..Default::default()
            },
            Default::default(),
            None,
        )
        .await
        .unwrap();

        rt.test_env
            .adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .returning(|_| {
                Ok(uapi::Response {
                    errno: 0,
                    interface: Some(Interface::default()),
                })
            });
        assert!(rt
            .entities
            .wireguard_interface
            .wait_for_listen_port(Duration::from_secs(1))
            .await
            .is_err());

        assert!(rt.set_private_key(&pk).await.is_ok());
        assert!(rt.set_config(&None).await.is_ok());
    }

    #[cfg(not(windows))]
    #[rstest]
    #[case(true)]
    #[case(false)]
    #[tokio::test(start_paused = true)]
    async fn test_ipv6_feature(#[case] ipv6: bool) {
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);

        let mut features = Features::default();
        features.ipv6 = ipv6;
        let private_key = SecretKey::gen();
        let mut rt = Runtime::start(
            sender,
            &DeviceConfig {
                private_key,
                ..Default::default()
            },
            features,
            None,
        )
        .await
        .unwrap();

        let peer_base = PeerBase {
            identifier: "identifier".to_owned(),
            public_key: private_key.public(),
            hostname: telio_utils::Hidden("hostname".to_owned()),
            ip_addresses: Some(vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)),
            ]),
            nickname: Some("nickname".to_owned()),
        };
        let config = Config {
            this: peer_base.clone(),
            peers: Some(vec![Peer {
                base: peer_base.clone(),
                ..Default::default()
            }]),
            derp_servers: None,
            dns: None,
        };

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;
        rt.entities
            .wireguard_interface
            .set_listen_port(1234)
            .await
            .unwrap();
        rt.test_env.adapter.lock().await.checkpoint();

        rt.test_env
            .adapter
            .expect_send_uapi_cmd_generic_call(1)
            .await;

        assert!(rt.set_config(&Some(config)).await.is_ok());

        let has_ipv6_address = rt
            .entities
            .wireguard_interface
            .get_interface()
            .await
            .unwrap()
            .peers
            .values()
            .any(|p| {
                p.allowed_ips.iter().any(|ip| match ip {
                    ipnetwork::IpNetwork::V4(_) => false,
                    ipnetwork::IpNetwork::V6(_) => true,
                })
            });

        assert_eq!(ipv6, has_ipv6_address);
    }
}
