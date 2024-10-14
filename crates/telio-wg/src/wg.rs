use async_trait::async_trait;
use futures::{future::pending, FutureExt};
use ipnet::{AddrParseError, IpNet};
use slog::{o, Drain, Logger, Never};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use telio_model::{
    event::{Error as LibtelioError, ErrorCode, ErrorLevel, Event as LibtelioEvent, EventMsg, Set},
    features::FeatureLinkDetection,
    mesh::{ExitNode, NodeState},
};
use telio_sockets::{NativeProtector, SocketPool};
use telio_utils::{
    dual_target::{DualTarget, DualTargetError},
    get_ip_stack, interval, telio_err_with_log, telio_log_debug, telio_log_error, telio_log_trace,
    telio_log_warn, IpStack,
};
use thiserror::Error as TError;
use tokio::time::{self, sleep, Instant, Interval, MissedTickBehavior};
use wireguard_uapi::xplatform::set;

use telio_crypto::{PublicKey, SecretKey};
use telio_model::{config, mesh::LinkState};
use telio_task::{
    io::chan::{Rx, Tx},
    io::mc_chan,
    task_exec, Runtime, RuntimeExt, StopResult, Task, WaitResponse,
};

use crate::{
    adapter::{self, Adapter, AdapterType, Error, FirewallResetConnsCb, Tun},
    link_detection::{self, LinkDetection, LinkDetectionUpdateResult},
    uapi::{self, AnalyticsEvent, Cmd, Event, Interface, Peer, PeerState, Response},
    FirewallCb,
};

use std::{
    collections::HashSet,
    future::Future,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

/// WireGuard adapter interface
#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait WireGuard: Send + Sync + 'static {
    /// Get adapter handle, returns `None` on fail
    async fn get_interface(&self) -> Result<Interface, Error>;
    /// Get adapter luid (local identifier) if supported by platform, `zero` otherwise
    async fn get_adapter_luid(&self) -> Result<u64, Error>;
    /// wait for listen port to be assigned by the WireGuard implementation, and return it afterwards
    async fn wait_for_listen_port(&self, d: Duration) -> Result<u16, Error>;
    /// wait for listen port that should be used by telio-proxy,
    /// this is required becasuse wiregurad-go windows implementation
    /// has two different ports, for local connections and external connections
    async fn wait_for_proxy_listen_port(&self, d: Duration) -> Result<u16, Error>;
    /// Get adapter file descriptor if supported by platform, `None` otherwise
    async fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, Error>;
    /// Get current link state for a peer
    async fn get_link_state(&self, key: PublicKey) -> Result<Option<LinkState>, Error>;
    /// Set secret key for adapter
    async fn set_secret_key(&self, key: SecretKey) -> Result<(), Error>;
    /// Set adapter fwmark, unix only
    async fn set_fwmark(&self, fwmark: u32) -> Result<(), Error>;
    /// Add Peer to adapter
    async fn add_peer(&self, peer: Peer) -> Result<(), Error>;
    /// Remove Peer from adapter
    async fn del_peer(&self, key: PublicKey) -> Result<(), Error>;
    /// Disconnect from all peers, implemented only in Boringtun
    async fn drop_connected_sockets(&self) -> Result<(), Error>;
    /// Retrieve time since last RXed (and accepted) packet
    async fn time_since_last_rx(&self, public_key: PublicKey) -> Result<Option<Duration>, Error>;
    /// Stop adapter
    async fn stop(self);
    /// Inject apropiate packets into the tunel to reset exising connections.
    /// Used for forcing external clients to reconnect to public servers.
    async fn reset_existing_connections(
        &self,
        exit_pubkey: PublicKey,
        exit_interface_ipv4: Ipv4Addr,
    ) -> Result<(), Error>;
    /// Set the ip stack for the adapter
    async fn set_ip_stack(&self, ip_stack: Option<IpStack>) -> Result<(), Error>;
}

/// WireGuard implementation allowing dynamic selection of implementation.
pub struct DynamicWg {
    task: Task<State>,
}

/// WireGuard configuration
pub struct Config {
    /// Type of WireGuard implementation
    pub adapter: AdapterType,
    /// Name of network interface in readable string
    pub name: Option<String>,
    /// Tunnel file descriptor
    pub tun: Option<Tun>,
    /// Sockets to be protected, in order to avoid loopback
    pub socket_pool: Arc<SocketPool>,
    /// Callback of firewall to process incoming packets
    pub firewall_process_inbound_callback: FirewallCb,
    /// Callback of firewall to process outgoing packets
    pub firewall_process_outbound_callback: FirewallCb,
    /// Callback of firewall to create connection reset packets
    /// for all active connections
    pub firewall_reset_connections: FirewallResetConnsCb,
}

/// Events and analytics transmission channels
pub struct Io {
    /// Channel to transmit peer information
    pub events: Tx<Box<Event>>,
    /// Channel to transmit analytics
    pub analytics_tx: Option<mc_chan::Tx<Box<AnalyticsEvent>>>,
    /// Channel to transmit event to registered event callback
    pub libtelio_wide_event_publisher: Option<mc_chan::Tx<Box<LibtelioEvent>>>,
}

/// Keepalive packets size
pub const KEEPALIVE_PACKET_SIZE: u64 = 32;
/// Default wireguard keepalive duration
pub const WG_KEEPALIVE: Duration = Duration::from_secs(10);

#[derive(Copy, Clone, Debug)]
/// A structure to hold the bytes and timestamps for received and transmitted data.
pub struct BytesAndTimestamps {
    /// Number of received bytes.
    rx_bytes: u64,
    /// Number of transmitted bytes.
    tx_bytes: u64,
    /// Timestamp for the last received data.
    rx_ts: Option<Instant>,
    /// Timestamp for the last transmitted data.
    tx_ts: Option<Instant>,
}

impl BytesAndTimestamps {
    /// Creates a new `BytesAndTimestamps` instance with optional initial values for received and transmitted bytes.
    pub fn new(rx_bytes: Option<u64>, tx_bytes: Option<u64>) -> Self {
        let now = Instant::now();
        let rx_bytes = rx_bytes.unwrap_or_default();
        let tx_bytes = tx_bytes.unwrap_or_default();
        BytesAndTimestamps {
            rx_bytes,
            tx_bytes,
            rx_ts: if rx_bytes > 0 { Some(now) } else { None },
            tx_ts: if tx_bytes > 0 { Some(now) } else { None },
        }
    }

    /// Updates the structure with new values for received and transmitted bytes.
    pub fn update(&mut self, new_rx: u64, new_tx: u64) {
        let now = Instant::now();

        if new_rx > self.rx_bytes {
            self.rx_bytes = new_rx;
            self.rx_ts = Some(now);
        }

        if new_tx > self.tx_bytes {
            // Ignore the keepalive messages
            // This only works in a limited fashion because we poll every second and
            // the detection might not work as intended if there are more packets within that time window.
            // On the sender side persistent-keepalives might interfere as those are emitted regardless the activity,
            // meaning for example if persistent-keepalive is set at 5seconds then it might interfere with the
            // passive-keepalive which is a constant of 10seconds.
            if new_tx - self.tx_bytes != KEEPALIVE_PACKET_SIZE {
                self.tx_ts = Some(now);
            }
            self.tx_bytes = new_tx;
        }
    }

    /// Returns the number of received bytes.
    pub fn get_rx_bytes(self) -> u64 {
        self.rx_bytes
    }

    /// Returns the number of transmitted bytes.
    pub fn get_tx_bytes(self) -> u64 {
        self.tx_bytes
    }

    /// Returns the timestamp of the last received data.
    pub fn get_rx_ts(self) -> Option<Instant> {
        self.rx_ts
    }

    /// Returns the timestamp of the last transmitted data.
    pub fn get_tx_ts(self) -> Option<Instant> {
        self.tx_ts
    }

    /// Checks if the link is up based on the round-trip time (RTT) and WireGuard keepalive interval.
    pub fn is_link_up(&self, rtt: Duration) -> bool {
        telio_log_debug!(
            "is_link_up. rtt={:?} self.rx_ts={:?} self.tx_ts={:?}",
            rtt,
            self.rx_ts,
            self.tx_ts
        );
        match (self.rx_ts, self.tx_ts) {
            (Some(rx_ts), Some(tx_ts)) => {
                telio_log_debug!(
                    "is_link_up:: rx_ts.elapsed: {:?}, rx_ts.elapsed() < WG_KEEPALIVE + rtt: {}",
                    rx_ts.elapsed(),
                    rx_ts.elapsed() < WG_KEEPALIVE + rtt
                );
                tx_ts <= rx_ts || rx_ts.elapsed() < WG_KEEPALIVE + rtt
            }
            _ => false,
        }
    }
}

struct State {
    #[cfg(unix)]
    cfg: Config,
    adapter: Box<dyn Adapter>,
    interval: Interval,
    interface: Interface,
    event: Tx<Box<Event>>,
    analytics_tx: Option<mc_chan::Tx<Box<AnalyticsEvent>>>,

    // Detecting unexpected driver failures, such as a malicious removal
    // We won't be notified of any errors, but a periodic call to get_config_uapi() will return a Win32 error code != 0.
    uapi_fail_counter: i32,

    // Link detection mechanism
    link_detection: Option<LinkDetection>,

    libtelio_event: Option<mc_chan::Tx<Box<LibtelioEvent>>>,

    stats: HashMap<PublicKey, Arc<Mutex<BytesAndTimestamps>>>,

    ip_stack: Option<IpStack>,
}

const POLL_MILLIS: u64 = 1000;
const MAX_UAPI_FAIL_COUNT: i32 = 10;

#[cfg(all(not(any(test, feature = "test-adapter")), windows))]
const DEFAULT_NAME: &str = "NordLynx";

#[cfg(all(
    not(any(test, feature = "test-adapter")),
    any(target_os = "macos", target_os = "ios", target_os = "tvos")
))]
const DEFAULT_NAME: &str = "utun10";

#[cfg(all(
    not(any(test, feature = "test-adapter")),
    any(target_os = "linux", target_os = "android")
))]
const DEFAULT_NAME: &str = "nlx0";

impl DynamicWg {
    /// Starts the WireGuard adapter with the given parameters.
    ///
    /// # Arguments
    ///
    /// * 'io' -  Communication channels for peer info and analytics
    /// * 'cfg' - The WireGuard adapter configuration
    ///
    /// # Returns
    ///
    /// Returns whether the adapter successfully started
    ///
    /// # Example
    /// ```
    /// use std::{sync::Arc, io};
    /// use telio_firewall::firewall::{StatefullFirewall, Firewall};
    /// use telio_sockets::{native::NativeSocket, Protector, SocketPool, Protect};
    /// use telio_task::io::Chan;
    /// pub use telio_wg::{AdapterType, DynamicWg, Tun, Io, Config};
    /// use tokio::runtime::Runtime;
    /// use mockall::mock;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///
    ///     mock! {
    ///         Protector {}
    ///         impl Protector for Protector {
    ///         fn make_external(&self, socket: NativeSocket) -> io::Result<()>;
    ///         fn make_internal(&self, interface: i32) -> Result<(), std::io::Error>;
    ///         fn clean(&self, socket: NativeSocket);
    ///         fn set_fwmark(&self, fwmark: u32);
    ///         fn set_tunnel_interface(&self, interface: u64);
    ///         }
    ///     }
    ///     let firewall = Arc::new(StatefullFirewall::new(true, false));
    ///     let firewall_filter_inbound_packets = {
    ///         let fw = firewall.clone();
    ///         move |peer: &[u8; 32], packet: &[u8]| fw.process_inbound_packet(peer, packet)
    ///     };
    ///     let firewall_filter_outbound_packets = {
    ///         let fw = firewall.clone();
    ///         move |peer: &[u8; 32], packet: &[u8]| fw.process_outbound_packet(peer, packet)
    ///     };
    ///
    ///     let chan = Chan::default();
    ///     let socket_pool = Arc::new(SocketPool::new(MockProtector::default()));
    ///     let wireguard_interface = DynamicWg::start(
    ///         Io {
    ///             events: chan.tx,
    ///             analytics_tx: None,
    ///             libtelio_wide_event_publisher: None,
    ///         },
    ///         Config {
    ///             adapter: AdapterType::default(),
    ///             name: Some("tun10".to_string()),
    ///             tun: Some(Tun::default()),
    ///             socket_pool: socket_pool,
    ///             firewall_process_inbound_callback:
    ///                 Some(Arc::new(firewall_filter_inbound_packets)),
    ///             firewall_process_outbound_callback:
    ///                 Some(Arc::new(firewall_filter_outbound_packets)),
    ///             firewall_reset_connections: None,
    ///         },
    ///         None,
    ///         true,
    ///     );
    /// }
    /// ```
    pub fn start(
        io: Io,
        cfg: Config,
        link_detection: Option<FeatureLinkDetection>,
        ipv6_enabled: bool,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let adapter = Self::start_adapter(cfg.try_clone()?)?;
        #[cfg(unix)]
        return Ok(Self::start_with(
            io,
            adapter,
            link_detection,
            cfg,
            ipv6_enabled,
        ));
        #[cfg(windows)]
        return Ok(Self::start_with(io, adapter, link_detection, ipv6_enabled));
    }

    fn start_with(
        io: Io,
        adapter: Box<dyn Adapter>,
        link_detection: Option<FeatureLinkDetection>,
        #[cfg(unix)] cfg: Config,
        ipv6_enabled: bool,
    ) -> Self {
        let interval = interval(Duration::from_millis(POLL_MILLIS));
        Self {
            task: Task::start(State {
                #[cfg(unix)]
                cfg,
                adapter,
                interval,
                interface: Default::default(),
                event: io.events,
                analytics_tx: io.analytics_tx,
                uapi_fail_counter: 0,
                link_detection: link_detection.map(|ld| LinkDetection::new(ld, ipv6_enabled)),
                libtelio_event: io.libtelio_wide_event_publisher,
                stats: HashMap::new(),
                ip_stack: None,
            }),
        }
    }

    #[cfg(not(any(test, feature = "test-adapter")))]
    fn start_adapter(cfg: Config) -> Result<Box<dyn Adapter>, Error> {
        adapter::start(
            cfg.adapter,
            &cfg.name.unwrap_or_else(|| DEFAULT_NAME.to_owned()),
            cfg.tun,
            cfg.socket_pool,
            cfg.firewall_process_inbound_callback,
            cfg.firewall_process_outbound_callback,
            cfg.firewall_reset_connections,
        )
    }

    #[cfg(any(test, feature = "test-adapter"))]
    fn start_adapter(_cfg: Config) -> Result<Box<dyn Adapter>, Error> {
        use std::sync::Mutex;

        if let Some(adapter) = tests::RUNTIME_ADAPTER.lock().unwrap().take() {
            Ok(adapter)
        } else {
            Err(Error::RestartFailed)
        }
    }
}

#[async_trait]
impl WireGuard for DynamicWg {
    async fn get_interface(&self) -> Result<Interface, Error> {
        Ok(task_exec!(&self.task, async move |s| Ok(s.interface.clone())).await?)
    }

    async fn get_adapter_luid(&self) -> Result<u64, Error> {
        Ok(task_exec!(&self.task, async move |s| Ok(s.adapter.get_adapter_luid())).await?)
    }

    async fn wait_for_listen_port(&self, d: Duration) -> Result<u16, Error> {
        let start = std::time::SystemTime::now();
        loop {
            if let Some(port) = self.get_interface().await?.listen_port {
                if port > 0 {
                    telio_log_debug!("Wireguard using port:{:?}", &port.to_string());
                    break Ok(port);
                }
            }
            let elapsed_time = start.elapsed()?;
            if elapsed_time > d {
                break telio_err_with_log!(Error::PortAssignmentTimeoutError);
            }

            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_proxy_listen_port(&self, d: Duration) -> Result<u16, Error> {
        let start = std::time::SystemTime::now();
        loop {
            let interface = self.get_interface().await?;
            if let Some(port) = interface.proxy_listen_port.or(interface.listen_port) {
                if port > 0 {
                    telio_log_debug!("Wireguard using port:{:?} for proxy", &port.to_string());
                    break Ok(port);
                }
            }
            let elapsed_time = start.elapsed()?;
            if elapsed_time > d {
                break telio_err_with_log!(Error::PortAssignmentTimeoutError);
            }

            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, Error> {
        task_exec!(&self.task, async move |s| Ok(s.adapter.get_wg_socket(ipv6)))
            .await
            .unwrap_or(Ok(None))
    }

    async fn get_link_state(&self, key: PublicKey) -> Result<Option<LinkState>, Error> {
        Ok(task_exec!(&self.task, async move |s| {
            Ok(s.link_detection
                .as_ref()
                .and_then(|ld| ld.get_link_state_for_downgrade(&key)))
        })
        .await?)
    }

    async fn set_secret_key(&self, key: SecretKey) -> Result<(), Error> {
        Ok(task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();
            to.private_key = Some(key);
            let _ = s.update(to, true).await;
            Ok(())
        })
        .await?)
    }

    async fn set_fwmark(&self, fwmark: u32) -> Result<(), Error> {
        Ok(task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();
            to.fwmark = fwmark;
            let _ = s.update(to, true).await;
            Ok(())
        })
        .await?)
    }

    async fn add_peer(&self, mut new_peer: Peer) -> Result<(), Error> {
        Ok(task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();

            // Check if there are any overlapping allowed IPs
            if to
                .peers
                .values()
                .filter(|peer| peer.public_key != new_peer.public_key)
                .any(|peer| {
                    new_peer
                        .allowed_ips
                        .iter()
                        .any(|candidate_allowed_ip| peer.allowed_ips.contains(candidate_allowed_ip))
                })
            {
                telio_log_warn!(
                    "Dublicate Allowed IPs detected for peer {:?}, dumping interface state: {:?}",
                    new_peer,
                    to
                );
                return Err(Error::DuplicateAllowedIPsError);
            }

            if let Some(old_peer) = to.peers.get(&new_peer.public_key) {
                new_peer.time_since_last_handshake = old_peer.time_since_last_handshake;
                new_peer.rx_bytes = old_peer.rx_bytes;
                new_peer.tx_bytes = old_peer.tx_bytes;
            }

            if new_peer.persistent_keepalive_interval.is_none() {
                new_peer.persistent_keepalive_interval = Some(0);
            }

            to.peers.insert(new_peer.public_key, new_peer);
            let _ = s.update(to, true).await;
            Ok(())
        })
        .await?)
    }

    async fn del_peer(&self, key: PublicKey) -> Result<(), Error> {
        Ok(task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();
            to.peers.remove(&key);
            let _ = s.update(to, true).await;
            Ok(())
        })
        .await?)
    }

    async fn drop_connected_sockets(&self) -> Result<(), Error> {
        Ok(task_exec!(&self.task, async move |s| {
            s.adapter.drop_connected_sockets().await;
            Ok(())
        })
        .await?)
    }

    async fn time_since_last_rx(&self, public_key: PublicKey) -> Result<Option<Duration>, Error> {
        Ok(task_exec!(&self.task, async move |s| Ok(
            s.time_since_last_rx(public_key)
        ))
        .await?)
    }

    async fn stop(mut self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    async fn reset_existing_connections(
        &self,
        pubkey: PublicKey,
        ipv4: Ipv4Addr,
    ) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| {
            s.adapter.inject_reset_packets(&pubkey, ipv4).await;
            Ok(())
        })
        .await?;

        Ok(())
    }

    async fn set_ip_stack(&self, ip_stack: Option<IpStack>) -> Result<(), Error> {
        Ok(task_exec!(&self.task, async move |s| {
            s.ip_stack = ip_stack;
            Ok(())
        })
        .await?)
    }
}

impl Config {
    fn try_clone(&self) -> Result<Self, io::Error> {
        #[cfg(unix)]
        let tun = match self.tun {
            Some(fd) => {
                let dup_fd = unsafe { libc::dup(fd as libc::c_int) };
                if dup_fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                Some(dup_fd)
            }
            None => None,
        };
        #[cfg(windows)]
        let tun = None;

        Ok(Self {
            adapter: self.adapter,
            name: self.name.clone(),
            tun,
            socket_pool: self.socket_pool.clone(),
            firewall_process_inbound_callback: self.firewall_process_inbound_callback.clone(),
            firewall_process_outbound_callback: self.firewall_process_outbound_callback.clone(),
            firewall_reset_connections: self.firewall_reset_connections.clone(),
        })
    }
}

#[derive(Debug, Default)]
struct DiffKeys {
    pub delete_keys: HashSet<PublicKey>,
    pub insert_keys: HashSet<PublicKey>,
    pub update_keys: HashSet<PublicKey>,
}

impl State {
    async fn sync(&mut self) -> Result<(), Error> {
        if let Some(to) = self.uapi_request(&uapi::Cmd::Get).await?.interface {
            let _ = self.update(to, false).await;
        }

        Ok(())
    }

    async fn uapi_request(&mut self, cmd: &Cmd) -> Result<Response, Error> {
        let ret = self.adapter.send_uapi_cmd(cmd).await?;
        telio_log_debug!("UAPI request: {}, response: {:?}", &cmd.to_string(), &ret);

        // Count continuous adapter failures.
        // As observed on Windows, a vNIC driver might fail a call right after wake-up,
        // but will properly resume work after that. In order to determine a non-recoverable failure
        // such as a malicious removal, we need to count the successive failed calls.
        // If a certain threshold is reached, cleanup the network config and notify the app about connection loss.
        if 0 == ret.errno {
            self.uapi_fail_counter = 0;
        } else {
            self.uapi_fail_counter += 1;
        }

        if self.uapi_fail_counter >= MAX_UAPI_FAIL_COUNT && ret.interface.is_none() {
            if let Some(libtelio_event) = &self.libtelio_event {
                let err_event = LibtelioEvent::builder::<LibtelioError>()
                    .set(EventMsg::from("Interface gone"))
                    .set(ErrorCode::Unknown)
                    .set(ErrorLevel::Critical)
                    .build();
                if let Some(err_event) = err_event {
                    let _ = libtelio_event.send(Box::new(err_event));
                }
            }
            return Err(Error::InternalError("Interface gone"));
        }

        Ok(ret)
    }

    fn update_calculate_changes(&self, to: &uapi::Interface) -> DiffKeys {
        // Create key sets
        let f_keys: HashSet<&PublicKey> = self.interface.peers.keys().collect();
        let t_keys: HashSet<&PublicKey> = to.peers.keys().collect();

        // Calculate diffed keys
        let delete_key_refs = &f_keys - &t_keys;
        let insert_key_refs = &t_keys - &f_keys;
        let update_key_refs = &f_keys & &t_keys;

        let mut diff_keys = DiffKeys::default();
        for i in delete_key_refs {
            diff_keys.delete_keys.insert(*i);
        }
        for i in insert_key_refs {
            diff_keys.insert_keys.insert(*i);
        }
        for i in update_key_refs {
            diff_keys.update_keys.insert(*i);
        }

        diff_keys
    }

    fn time_since_last_rx(&self, public_key: PublicKey) -> Option<Duration> {
        self.stats.get(&public_key).and_then(|s| match s.lock() {
            Ok(s) => {
                if s.rx_bytes > 0 {
                    Some(s.rx_ts?.elapsed())
                } else {
                    None
                }
            }
            Err(e) => {
                telio_log_error!("poisoned lock - {}", e);
                None
            }
        })
    }

    async fn send_event(
        &self,
        state: PeerState,
        link_state: Option<LinkState>,
        peer: Peer,
        old_peer: Option<Peer>,
    ) -> Result<(), Error> {
        let link_state = link_state.and_then(|s| {
            if self.link_detection.is_none() {
                None
            } else {
                Some(s)
            }
        });

        self.event
            .send(Box::new(Event {
                state,
                link_state,
                peer,
                old_peer,
            }))
            .await
            .map_err(|_| Error::InternalError("Failed to send node event"))
    }

    #[allow(mpsc_blocking_send)]
    async fn update_send_notification_events(
        &mut self,
        to: &uapi::Interface,
        diff_keys: &DiffKeys,
        push: bool,
    ) -> Result<(), Error> {
        let from = &self.interface;

        // Notify all disconnects
        for key in &diff_keys.delete_keys {
            let peer = from.peers.get(key).cloned().ok_or(Error::InternalError(
                "Disconnected peer missing from old list",
            ))?;

            // Remove all disconnected peers from no link detection mechanism
            if let Some(link_detection) = self.link_detection.as_mut() {
                link_detection.remove(key);
            }

            self.send_event(
                PeerState::Disconnected,
                Some(LinkState::Down),
                peer,
                from.peers.get(key).cloned(),
            )
            .await?;
        }

        // Notify all new connections
        for key in &diff_keys.insert_keys {
            let peer = to
                .peers
                .get(key)
                .ok_or(Error::InternalError("New peer missing from new list"))?;

            let stats = self
                .stats
                .get(key)
                .ok_or(Error::InternalError("No stats available for peer"))?;

            // Node is new and default LinkState is down. Save it before sending the event
            if let Some(link_detection) = self.link_detection.as_mut() {
                link_detection.insert(key, stats.clone());
            }

            self.send_event(
                PeerState::Connecting,
                Some(LinkState::Down),
                peer.clone(),
                from.peers.get(key).cloned(),
            )
            .await?;

            if peer.is_connected() {
                self.send_event(
                    PeerState::Connected,
                    Some(LinkState::Up),
                    peer.clone(),
                    from.peers.get(key).cloned(),
                )
                .await?;
            }
        }

        // Check for updates, and notify
        for key in &diff_keys.update_keys {
            if let (Some(old), Some(new)) = (from.peers.get(key), to.peers.get(key)) {
                let old_state = old.state();
                let new_state = new.state();
                let node_addresses = new.ip_addresses.clone();
                let link_detection_update_result = {
                    if let Some(link_detection) = self.link_detection.as_mut() {
                        link_detection
                            .update(key, node_addresses, push, self.ip_stack.clone())
                            .await
                    } else {
                        LinkDetectionUpdateResult {
                            ..Default::default()
                        }
                    }
                };

                if !old.is_same_event(new)
                    || old_state != new_state
                    || link_detection_update_result.should_notify
                {
                    self.send_event(
                        new_state,
                        link_detection_update_result.link_state,
                        new.clone(),
                        Some(old.clone()),
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    fn update_calculate_set_listen_port(
        from_listen_port: Option<u16>,
        to_listen_port: Option<u16>,
    ) -> Option<u16> {
        match (from_listen_port, to_listen_port) {
            (Some(from), Some(to)) => {
                if from != to {
                    Some(to)
                } else {
                    None
                }
            }
            (None, Some(to)) => Some(to),
            _ => None,
        }
    }

    fn update_construct_set_device(
        &self,
        to: &uapi::Interface,
        diff_keys: &DiffKeys,
    ) -> set::Device {
        let from = &self.interface;

        let removed_peers = from
            .peers
            .iter()
            .filter(|(pubkey, _)| diff_keys.delete_keys.contains(pubkey))
            .map(|(pubkey, _)| set::Peer::from_public_key(pubkey.0).remove(true));
        let peers = to.peers.iter().map(|(pubkey, peer)| {
            set::Peer::from(peer)
                .update_only(diff_keys.update_keys.contains(pubkey))
                .replace_allowed_ips(
                    from.peers
                        .get(pubkey)
                        .map(|p| p.allowed_ips != peer.allowed_ips)
                        .unwrap_or(false),
                )
        });

        set::Device {
            private_key: to.private_key.map(|key| key.into_bytes()),
            listen_port: Self::update_calculate_set_listen_port(
                self.interface.listen_port,
                to.listen_port,
            ),
            fwmark: match to.fwmark {
                0 => None,
                x => Some(x),
            },
            replace_peers: None,
            peers: removed_peers.chain(peers).collect(),
        }
    }

    fn update_endpoint_change_timestamps(&self, diff_keys: &DiffKeys, to: &mut uapi::Interface) {
        for key in diff_keys
            .insert_keys
            .iter()
            .chain(diff_keys.update_keys.iter())
        {
            let old_endpoint = self.interface.peers.get(key).and_then(|p| p.endpoint);
            let new_peer = to.peers.get_mut(key);
            let new_endpoint = new_peer.as_ref().and_then(|p| p.endpoint);

            if old_endpoint != new_endpoint {
                telio_log_debug!(
                    "Endpoint change detected {:?} -> {:?}",
                    old_endpoint,
                    new_endpoint
                );
                let at = Instant::now();
                if let Some(p) = new_peer {
                    p.endpoint_changed_at = Some(at);
                }
            }
        }
    }

    #[allow(mpsc_blocking_send)]
    async fn update(&mut self, mut to: uapi::Interface, push: bool) -> Result<bool, Error> {
        for (pk, peer) in &mut to.peers {
            match self.stats.get_mut(pk) {
                Some(stats) => match stats.lock().as_mut() {
                    Ok(s) => {
                        s.update(
                            peer.rx_bytes.unwrap_or_default(),
                            peer.tx_bytes.unwrap_or_default(),
                        );
                    }
                    Err(e) => {
                        telio_log_error!("poisoned lock - {}", e);
                    }
                },
                None => {
                    self.stats.insert(
                        *pk,
                        Arc::new(Mutex::new(BytesAndTimestamps::new(
                            peer.rx_bytes,
                            peer.tx_bytes,
                        ))),
                    );
                }
            }
            peer.time_since_last_rx = self.time_since_last_rx(*pk);
        }
        self.stats.retain(|pk, _| to.peers.contains_key(pk));

        // Diff and report events

        // Adapter doesn't keep track of mesh addresses, or endpoint changes,
        // therefore they are not retrieved from UAPI requests
        // so we need to keep track of it.
        for (pk, peer) in &mut to.peers {
            if peer.ip_addresses.is_empty() {
                if let Some(old_peer) = self.interface.peers.get(pk) {
                    peer.ip_addresses = old_peer.ip_addresses.clone();
                }
            }
            // This forbids changes from outside, endpoint change is always
            // determided by update_endpoint_change function
            peer.endpoint_changed_at = self
                .interface
                .peers
                .get(pk)
                .and_then(|p| p.endpoint_changed_at)
        }

        // We need to track failed driver calls in uapi_request().
        // Because uapi_request() now needs a mut self, the mut borrow for self.uapi_request()
        // would collide with HashSet<&PublicKey> and with from=&self.interface,
        // which was used throughout this function for better readability.
        if Self::is_same_interface(&self.interface, &to) {
            return Err(Error::InternalError(
                "Same interface received in update function",
            ));
        }

        let diff_keys = self.update_calculate_changes(&to);

        self.update_endpoint_change_timestamps(&diff_keys, &mut to);

        self.update_send_notification_events(&to, &diff_keys, push)
            .await?;

        let mut success = true;
        if push {
            let dev = self.update_construct_set_device(&to, &diff_keys);
            // mut self required here
            success = self
                .uapi_request(&Cmd::Set(dev))
                .await
                .map(|r| r.errno == 0)
                .unwrap_or_default();
        }

        if let Some(analytics_tx) = &self.analytics_tx {
            for (pubkey, peer) in &to.peers {
                if peer.endpoint.is_some() {
                    let tx_bytes = peer.tx_bytes.unwrap_or_default();
                    let rx_bytes = peer.rx_bytes.unwrap_or_default();
                    let peer_state = if peer.is_connected() {
                        PeerState::Connected
                    } else if diff_keys.delete_keys.contains(pubkey) {
                        PeerState::Disconnected
                    } else {
                        PeerState::Connecting
                    };

                    let dual_ip_addresses = peer.get_dual_ip_addresses();

                    let event = AnalyticsEvent {
                        public_key: *pubkey,
                        dual_ip_addresses,
                        tx_bytes,
                        rx_bytes,
                        peer_state,
                        timestamp: tokio::time::Instant::now(),
                    };
                    if analytics_tx.send(Box::new(event)).is_err() {
                        telio_log_debug!("Failed to send analytics info for {:?}", pubkey);
                    }
                }
            }
        }

        self.interface = to;

        Ok(success)
    }

    /// This is like the normal '==' but ignores the time_since_last_rx field in peers
    fn is_same_interface(lhs: &Interface, rhs: &Interface) -> bool {
        if lhs.private_key != rhs.private_key
            || lhs.listen_port != rhs.listen_port
            || lhs.proxy_listen_port != rhs.proxy_listen_port
            || lhs.fwmark != rhs.fwmark
        {
            false
        } else {
            for (pk, peer) in &lhs.peers {
                match rhs.peers.get(pk) {
                    Some(other_peer) => {
                        if !Self::is_same_peer(peer, other_peer) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            // check if 'other' had additional keys
            lhs.peers.len() == rhs.peers.len()
        }
    }

    /// This is like the normal '==' but ignores the time_since_last_rx field
    fn is_same_peer(lhs: &Peer, rhs: &Peer) -> bool {
        lhs.public_key == rhs.public_key
                && lhs.endpoint == rhs.endpoint
                && lhs.ip_addresses == rhs.ip_addresses
                && lhs.persistent_keepalive_interval == rhs.persistent_keepalive_interval
                && lhs.allowed_ips == rhs.allowed_ips
                && lhs.rx_bytes == rhs.rx_bytes
                // this is omitted by design: && lhs.time_since_last_rx == rhs.time_since_last_rx
                && lhs.tx_bytes == rhs.tx_bytes
                && lhs.time_since_last_handshake == rhs.time_since_last_handshake
                && lhs.preshared_key == rhs.preshared_key
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Wg";

    type Err = Error;

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        let _ = self.interval.tick().await;
        Self::guard(self.sync())
    }

    async fn stop(self) {
        self.adapter.stop().await;
        if let Some(link_detection) = self.link_detection {
            link_detection.stop().await;
        }
        #[cfg(unix)]
        self.cfg
            .tun
            .map(|tun| unsafe { libc::close(tun as libc::c_int) });
    }
}

#[cfg(any(test, feature = "test-adapter"))]
#[allow(missing_docs)]
pub mod tests {
    use std::{
        collections::BTreeMap,
        net::{Ipv4Addr, SocketAddrV4},
        sync::{Arc, Mutex as StdMutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use ipnet::Ipv4Net;
    use lazy_static::lazy_static;
    use mockall::predicate;
    use rand::{Rng, RngCore, SeedableRng};
    use telio_crypto::PresharedKey;
    use telio_sockets::NativeProtector;
    use tokio::{runtime::Handle, sync::Mutex, task, time::sleep};

    use telio_task::io::{Chan, McChan};

    #[cfg(not(feature = "test-adapter"))]
    use rstest::rstest;

    use super::*;
    use crate::adapter::{Error as AdapterError, MockAdapter};

    lazy_static! {
        pub(super) static ref RUNTIME_ADAPTER: StdMutex<Option<Box<dyn Adapter>>> =
            StdMutex::new(None);
    }

    fn random_interface() -> Interface {
        let mut rng = rand::thread_rng();
        let peers_len = rng.gen_range(1..=3);
        let mut peers = BTreeMap::default();
        for _ in 0..peers_len {
            let key = SecretKey::gen_with(&mut rng).public();
            let peer = Peer {
                public_key: SecretKey::gen_with(&mut rng).public(),
                endpoint: Some(SocketAddr::V4(SocketAddrV4::new(
                    rng.gen::<u32>().into(),
                    rng.gen(),
                ))),
                endpoint_changed_at: Some(tokio::time::Instant::now()),
                ip_addresses: vec![
                    IpAddr::V4(rng.gen::<u32>().into()),
                    IpAddr::V4(rng.gen::<u32>().into()),
                ],
                persistent_keepalive_interval: Some(rng.gen()),
                allowed_ips: vec![IpNet::V4(Ipv4Net::new(rng.gen::<u32>().into(), 0).unwrap())],
                rx_bytes: Some(rng.gen()),
                time_since_last_rx: Some(Duration::from_millis(rng.gen())),
                tx_bytes: Some(rng.gen()),
                time_since_last_handshake: Some(Duration::from_millis(rng.gen())),
                preshared_key: Some(PresharedKey(rng.gen())),
            };
            peers.insert(key, peer);
        }
        Interface {
            private_key: Some(SecretKey::gen_with(&mut rng)),
            listen_port: rng.gen(),
            proxy_listen_port: rng.gen(),
            fwmark: rng.gen(),
            peers,
        }
    }

    impl DynamicWg {
        pub async fn set_listen_port(&self, port: u16) -> Result<(), Error> {
            Ok(task_exec!(&self.task, async move |s| {
                let mut ifc = s.interface.clone();
                ifc.listen_port = Some(port);
                let _ = s.update(ifc, true).await;
                Ok(())
            })
            .await?)
        }
    }

    #[cfg(all(unix, test))]
    impl Config {
        fn new() -> std::io::Result<Self> {
            Ok(Self {
                adapter: Default::default(),
                name: Default::default(),
                tun: Default::default(),
                socket_pool: Arc::new(SocketPool::new(NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    false,
                )?)),
                firewall_process_inbound_callback: Default::default(),
                firewall_process_outbound_callback: Default::default(),
                firewall_reset_connections: None,
            })
        }
    }

    #[async_trait]
    impl Adapter for Arc<Mutex<MockAdapter>> {
        async fn send_uapi_cmd(&self, cmd: &Cmd) -> Result<Response, AdapterError> {
            self.lock().await.send_uapi_cmd(cmd).await
        }

        async fn stop(&self) {
            self.lock().await.stop().await
        }

        fn get_adapter_luid(&self) -> u64 {
            task::block_in_place(|| {
                Handle::current().block_on(async { self.lock().await.get_adapter_luid() })
            })
        }

        fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, Error> {
            task::block_in_place(|| {
                Handle::current().block_on(async { self.lock().await.get_wg_socket(ipv6) })
            })
        }
    }

    #[async_trait]
    pub trait AdapterExpectation {
        async fn expect_send_uapi_cmd_generic_call(&self, times: usize);
    }

    #[async_trait]
    impl AdapterExpectation for Arc<Mutex<MockAdapter>> {
        async fn expect_send_uapi_cmd_generic_call(&self, times: usize) {
            self.lock()
                .await
                .expect_send_uapi_cmd()
                .times(times)
                .returning(|_| {
                    Ok(Response {
                        errno: 0,
                        interface: Some(Interface::default()),
                    })
                });
        }
    }

    pub struct Env {
        pub event: Rx<Box<Event>>,
        pub analytics: Option<mc_chan::Tx<Box<AnalyticsEvent>>>,
        pub adapter: Arc<Mutex<MockAdapter>>,
        #[cfg(test)]
        pub wg: DynamicWg,
        #[cfg(not(test))]
        pub wg: Arc<DynamicWg>,
    }

    pub async fn setup(#[cfg(all(not(test), feature = "test-adapter"))] cfg: Config) -> Env {
        let events_ch = Chan::default();
        let analytics_ch = Some(McChan::default().tx);
        let adapter = Arc::new(Mutex::new(MockAdapter::new()));

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .returning(|_| {
                Ok(Response {
                    errno: 0,
                    interface: Some(Interface::default()),
                })
            });

        let wg = DynamicWg::start_with(
            Io {
                events: events_ch.tx.clone(),
                analytics_tx: analytics_ch.clone(),
                libtelio_wide_event_publisher: None,
            },
            Box::new(adapter.clone()),
            None,
            #[cfg(all(unix, test))]
            Config::new().unwrap(),
            #[cfg(all(unix, not(test)))]
            cfg,
            true,
        );
        time::advance(Duration::from_millis(0)).await;
        adapter.lock().await.checkpoint();

        Env {
            event: events_ch.rx,
            analytics: analytics_ch,
            adapter,
            #[cfg(not(test))]
            wg: Arc::new(wg),
            #[cfg(test)]
            wg,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn wg_setup() {
        let Env { adapter, wg, .. } = setup().await;

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wg_gets_interface() {
        let Env { adapter, wg, .. } = setup().await;
        assert_eq!(Interface::default(), wg.get_interface().await.unwrap());

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wg_sets_secret_key() {
        let Env { adapter, wg, .. } = setup().await;

        let sks = SecretKey::gen();
        let ifa = Interface {
            private_key: Some(sks),
            ..Default::default()
        };
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.set_secret_key(sks).await.unwrap();
        adapter.lock().await.checkpoint();
        assert_eq!(ifa.clone(), wg.get_interface().await.unwrap());

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn wg_sets_fwmark() {
        let Env { adapter, wg, .. } = setup().await;
        let ifa = Interface {
            fwmark: 2,
            ..Default::default()
        };
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.set_fwmark(ifa.fwmark).await.unwrap();
        adapter.lock().await.checkpoint();
        assert_eq!(ifa.clone(), wg.get_interface().await.unwrap());

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wg_adds_peer() {
        let Env {
            adapter,
            wg,
            mut event,
            ..
        } = setup().await;
        let mut ifa = Interface::default();

        let pkc = SecretKey::gen().public();
        let peer = Peer {
            public_key: pkc,
            endpoint: Some(([1, 1, 1, 1], 123).into()),
            persistent_keepalive_interval: Some(25),
            endpoint_changed_at: Some(Instant::now()),
            ..Default::default()
        };

        ifa.peers.insert(pkc, peer.clone());
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.add_peer(peer.clone()).await.unwrap();
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                link_state: None,
                peer: peer.clone(),
                old_peer: None
            })),
            event.recv().await
        );
        adapter.lock().await.checkpoint();
        assert_eq!(ifa.clone(), wg.get_interface().await.unwrap());

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wg_peer_connects() {
        let Env {
            adapter,
            wg,
            mut event,
            ..
        } = setup().await;
        let mut ifa = Interface::default();

        let pkc = SecretKey::gen().public();
        let mut peer = Peer {
            public_key: pkc,
            endpoint: Some(([1, 1, 1, 1], 123).into()),
            endpoint_changed_at: Some(Instant::now()),
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        };
        let old_peer = Some(peer.clone());

        ifa.peers.insert(pkc, peer.clone());
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.add_peer(peer.clone()).await.unwrap();
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                link_state: None,
                peer: peer.clone(),
                old_peer: None
            })),
            event.recv().await
        );
        adapter.lock().await.checkpoint();
        assert_eq!(ifa.clone(), wg.get_interface().await.unwrap());

        // Connect
        peer.time_since_last_handshake = Some(Duration::from_secs(15));
        peer.rx_bytes = Some(1);
        ifa.peers.insert(pkc, peer.clone());
        tokio::time::advance(Duration::from_secs(7)).await;
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .returning(move |_| {
                Ok(Response {
                    errno: 0,
                    interface: Some(ifa.clone()),
                })
            });
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connected,
                link_state: None,
                peer: Peer {
                    time_since_last_rx: Some(Duration::from_secs(0)),
                    ..peer.clone()
                },
                old_peer
            })),
            event.recv().await
        );

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wg_peer_disconnects() {
        let Env {
            adapter,
            wg,
            mut event,
            ..
        } = setup().await;
        let mut ifa = Interface::default();

        let pkc = SecretKey::gen().public();
        let mut peer = Peer {
            public_key: pkc,
            endpoint: Some(([1, 1, 1, 1], 123).into()),
            endpoint_changed_at: Some(Instant::now()),
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        };
        let old_peer = peer.clone();

        ifa.peers.insert(pkc, peer.clone());
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.add_peer(peer.clone()).await.unwrap();

        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                link_state: None,
                peer: peer.clone(),
                old_peer: None
            })),
            event.recv().await
        );
        adapter.lock().await.checkpoint();
        assert_eq!(ifa.clone(), wg.get_interface().await.unwrap());

        // Connects
        peer.time_since_last_handshake = Some(Duration::from_secs(94));
        peer.rx_bytes = Some(1);
        ifa.peers.insert(pkc, peer.clone());
        tokio::time::advance(Duration::from_secs(94)).await;
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .returning({
                let ifa = ifa.clone();
                move |_| {
                    Ok(Response {
                        errno: 0,
                        interface: Some(ifa.clone()),
                    })
                }
            });
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connected,
                link_state: None,
                peer: Peer {
                    time_since_last_rx: Some(Duration::from_secs(0)),
                    ..peer.clone()
                },
                old_peer: Some(old_peer.clone())
            })),
            event.recv().await
        );

        // Disconnects
        peer.time_since_last_handshake = Some(Duration::from_secs(182));
        ifa.peers.insert(pkc, peer.clone());
        tokio::time::advance(Duration::from_secs(182)).await;

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .returning({
                let ifa = ifa.clone();
                move |_| {
                    Ok(Response {
                        errno: 0,
                        interface: Some(ifa.clone()),
                    })
                }
            });

        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                link_state: None,
                peer: Peer {
                    time_since_last_rx: Some(Duration::from_secs(182)),
                    time_since_last_handshake: Some(Duration::from_secs(182)),
                    ..peer.clone()
                },
                old_peer: Some(Peer {
                    time_since_last_rx: Some(Duration::from_secs(0)),
                    time_since_last_handshake: Some(Duration::from_secs(94)),
                    rx_bytes: Some(1),
                    ..old_peer.clone()
                }),
            })),
            event.recv().await
        );

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wg_peer_remove() {
        let Env {
            adapter,
            wg,
            event: _event,
            ..
        } = setup().await;
        let mut iface = Interface::default();
        let pubkey = SecretKey::gen().public();
        let peer = Peer {
            public_key: pubkey,
            persistent_keepalive_interval: Some(0),
            ..Default::default()
        };

        iface.peers.insert(pubkey, peer.clone());

        let cmd_set_device_param1 = set::Device::from(iface.clone());
        let cmd_set_device1 = Cmd::Set(cmd_set_device_param1);
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(cmd_set_device1))
            .times(1)
            .returning(|_| {
                Ok(Response {
                    errno: 0,
                    interface: None,
                })
            });
        wg.add_peer(peer.clone()).await.unwrap();
        adapter.lock().await.checkpoint();

        assert_eq!(iface.clone(), wg.get_interface().await.unwrap());

        let cmd_set_device_param2 = set::Device {
            peers: vec![set::Peer::from_public_key(peer.public_key.0).remove(true)],
            ..set::Device::from(iface.clone())
        };
        let cmd_set_device2 = Cmd::Set(cmd_set_device_param2);
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(cmd_set_device2))
            .times(1)
            .returning(|_| {
                Ok(Response {
                    errno: 0,
                    interface: None,
                })
            });
        wg.del_peer(pubkey).await.unwrap();
        adapter.lock().await.checkpoint();

        iface.peers.remove(&pubkey);

        assert_eq!(iface.clone(), wg.get_interface().await.unwrap());

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    // Check whether updating a peer does not result in a new one being added.
    #[tokio::test(start_paused = true)]
    async fn wg_peer_update() {
        let Env {
            adapter,
            wg,
            event: _event,
            ..
        } = setup().await;
        let mut iface = Interface::default();
        let pubkey = SecretKey::gen().public();

        let mut rng = rand::rngs::StdRng::from_seed(Default::default());
        let preshared1 = PresharedKey::new({
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        });
        let preshared2 = PresharedKey::new({
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        });

        let mut peer = Peer {
            public_key: pubkey,
            endpoint: Some(([1, 1, 1, 1], 123).into()),
            endpoint_changed_at: Some(Instant::now()),
            persistent_keepalive_interval: Some(25),
            preshared_key: Some(preshared1),
            ..Default::default()
        };

        iface.peers.insert(pubkey, peer.clone());

        let cmd_set_device_param1 = set::Device::from(iface.clone());
        let cmd_set_device1 = Cmd::Set(cmd_set_device_param1);
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(cmd_set_device1))
            .times(1)
            .returning(|_| {
                Ok(Response {
                    errno: 0,
                    interface: None,
                })
            });
        wg.add_peer(peer.clone()).await.unwrap();
        adapter.lock().await.checkpoint();

        assert_eq!(iface.clone(), wg.get_interface().await.unwrap());

        peer.endpoint = Some(([1, 1, 1, 1], 124).into());
        peer.preshared_key = Some(preshared2);

        iface.peers.insert(pubkey, peer.clone());

        let cmd_set_device_param2 = set::Device {
            peers: vec![set::Peer::from(&peer).update_only(true)],
            ..set::Device::from(iface.clone())
        };
        let cmd_set_device2 = Cmd::Set(cmd_set_device_param2);
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(cmd_set_device2))
            .times(1)
            .returning(|_| {
                Ok(Response {
                    errno: 0,
                    interface: None,
                })
            });
        wg.add_peer(peer.clone()).await.unwrap();
        adapter.lock().await.checkpoint();

        assert_eq!(iface.clone(), wg.get_interface().await.unwrap());

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wg_peer_time_since_last_rx_update_update() {
        let Env {
            adapter,
            wg,
            mut event,
            ..
        } = setup().await;
        let pkc = SecretKey::gen().public();
        let mut ifa = Interface::default();
        let mut peer = Peer {
            public_key: pkc,
            endpoint: Some(([1, 1, 1, 1], 123).into()),
            endpoint_changed_at: Some(Instant::now()),
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        };

        ifa.peers.insert(pkc, peer.clone());
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.add_peer(peer.clone()).await.unwrap();
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                link_state: None,
                peer: peer.clone(),
                old_peer: None
            })),
            event.recv().await
        );
        adapter.lock().await.checkpoint();
        assert_eq!(ifa.clone(), wg.get_interface().await.unwrap());

        // Connect
        let mut old_peer = peer.clone();
        peer.time_since_last_handshake = Some(Duration::from_secs(15));
        peer.rx_bytes = Some(100);
        ifa.peers.insert(pkc, peer.clone());

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .returning({
                let ifa = ifa.clone();
                move |_| {
                    Ok(Response {
                        errno: 0,
                        interface: Some(ifa.clone()),
                    })
                }
            });
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connected,
                link_state: None,
                peer: Peer {
                    time_since_last_rx: Some(Duration::from_secs(0)),
                    ..peer.clone()
                },
                old_peer: Some(old_peer)
            })),
            event.recv().await
        );

        old_peer = Peer {
            time_since_last_rx: Some(Duration::from_secs(0)),
            ..peer.clone()
        };
        peer.time_since_last_handshake = Some(Duration::from_secs(182));
        time::advance(Duration::from_secs(182)).await;
        ifa.peers.insert(pkc, peer.clone());

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .returning({
                let ifa = ifa.clone();
                move |_| {
                    Ok(Response {
                        errno: 0,
                        interface: Some(ifa.clone()),
                    })
                }
            });
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                link_state: None,
                peer: Peer {
                    time_since_last_rx: Some(Duration::from_secs(182)),
                    ..peer.clone()
                },
                old_peer: Some(old_peer),
            })),
            event.recv().await
        );

        old_peer = Peer {
            time_since_last_handshake: Some(Duration::from_secs(182)),
            time_since_last_rx: Some(Duration::from_secs(182)),
            ..peer.clone()
        };
        peer.time_since_last_handshake = Some(Duration::from_secs(1));
        peer.rx_bytes = Some(200);
        time::advance(Duration::from_secs(1)).await;
        ifa.peers.insert(pkc, peer.clone());

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .returning(move |_| {
                Ok(Response {
                    errno: 0,
                    interface: Some(ifa.clone()),
                })
            });
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connected,
                link_state: None,
                peer: Peer {
                    time_since_last_rx: Some(Duration::from_secs(0)),
                    ..peer.clone()
                },
                old_peer: Some(old_peer),
            })),
            event.recv().await
        );

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn last_endpoint_change() {
        let Env {
            adapter,
            wg,
            event: _event,
            ..
        } = setup().await;

        let pkc = SecretKey::gen().public();
        let get = |i: Result<Interface, _>| {
            i.unwrap()
                .peers
                .get(&pkc)
                .unwrap()
                .endpoint_changed_at
                .unwrap()
        };

        let peer = Peer {
            public_key: pkc,
            endpoint: Some(([1, 1, 1, 1], 123).into()),
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        };

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .times(1)
            .returning(|_| {
                Ok(Response {
                    errno: 0,
                    interface: None,
                })
            });
        wg.add_peer(peer.clone()).await.unwrap();
        adapter.lock().await.checkpoint();

        assert_eq!(
            wg.get_interface().map(get).await.elapsed(),
            Duration::from_millis(0)
        );

        time::advance(Duration::from_millis(100)).await;
        assert_eq!(
            wg.get_interface().map(get).await.elapsed(),
            Duration::from_millis(100)
        );

        // Add the same peer again - endpoint is the same,
        // so it shouldn't change the time
        wg.add_peer(peer.clone()).await.unwrap();
        adapter.lock().await.checkpoint();
        assert_eq!(
            wg.get_interface().map(get).await.elapsed(),
            Duration::from_millis(100)
        );

        // Add a peer with different key, it shouldn't change the
        // time since last endpoint change
        let peer = Peer {
            public_key: SecretKey::gen().public(),
            ..peer
        };
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.add_peer(peer).await.unwrap();
        adapter.lock().await.checkpoint();
        assert_eq!(
            wg.get_interface().map(get).await.elapsed(),
            Duration::from_millis(100)
        );

        // Check if the time is still properly updated
        time::advance(Duration::from_millis(100)).await;
        assert_eq!(
            wg.get_interface().map(get).await.elapsed(),
            Duration::from_millis(200)
        );

        // Let's add a peer with the same pubkey and other endpoint
        // in order to check if it resets the last endpoint change time
        let peer = Peer {
            public_key: pkc,
            endpoint: Some(([2, 2, 2, 2], 123).into()),
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        };
        adapter.expect_send_uapi_cmd_generic_call(1).await;
        wg.add_peer(peer).await.unwrap();
        adapter.lock().await.checkpoint();
        assert_eq!(
            wg.get_interface().map(get).await.elapsed(),
            Duration::from_millis(0)
        );

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }

    #[test]
    fn test_update_calculate_set_listen_port() {
        assert_eq!(State::update_calculate_set_listen_port(None, None), None);
        assert_eq!(State::update_calculate_set_listen_port(Some(1), None), None);
        assert_eq!(
            State::update_calculate_set_listen_port(Some(1), Some(1)),
            None
        );
        assert_eq!(
            State::update_calculate_set_listen_port(None, Some(1)),
            Some(1)
        );
        assert_eq!(
            State::update_calculate_set_listen_port(Some(1), Some(2)),
            Some(2)
        );
    }

    #[test]
    fn test_is_same_interface() {
        for _ in 0..10 {
            let i1 = random_interface();
            assert!(State::is_same_interface(&i1, &i1));
            let mut i1_with_different_time_since_last_rx = i1.clone();
            *i1_with_different_time_since_last_rx
                .peers
                .iter_mut()
                .next()
                .unwrap()
                .1
                .time_since_last_rx
                .as_mut()
                .unwrap() += Duration::from_secs(1);
            assert!(State::is_same_interface(
                &i1,
                &i1_with_different_time_since_last_rx
            ));
            let mut i1_with_modified_other_field = i1.clone();
            *i1_with_modified_other_field
                .peers
                .iter_mut()
                .next()
                .unwrap()
                .1
                .rx_bytes
                .as_mut()
                .unwrap() += 1;
            assert!(!State::is_same_interface(
                &i1,
                &i1_with_modified_other_field
            ));
        }
    }

    #[cfg(not(feature = "test-adapter"))]
    #[rstest]
    #[case(None, None, 0, false)]
    #[case(Some(0), None, 0, false)]
    #[case(None, Some(0), 0, false)]
    #[case(Some(0), Some(0), 0, true)]
    #[case(Some(0), Some(1), 0, true)]
    #[case(Some(1), Some(0), 0, true)]
    #[case(Some(0), Some(11), 0, true)]
    #[case(Some(0), Some(100), 0, true)]
    #[case(Some(0), Some(1000), 0, true)]
    #[case(Some(11), Some(0), 0, false)]
    #[case(Some(11), Some(0), 15, true)]
    fn test_bytes_and_timestamps(
        #[case] rx_sec_ago: Option<u64>,
        #[case] tx_sec_ago: Option<u64>,
        #[case] rtt: u64,
        #[case] expect_link_up: bool,
    ) {
        let now = Instant::now();
        let rx_ts = rx_sec_ago.and_then(|v| now.checked_sub(Duration::from_secs(v)));
        let tx_ts = tx_sec_ago.and_then(|v| now.checked_sub(Duration::from_secs(v)));
        let rtt = Duration::from_secs(rtt);

        let stats = BytesAndTimestamps {
            rx_bytes: 5,
            tx_bytes: 5,
            rx_ts,
            tx_ts,
        };
        assert_eq!(stats.is_link_up(rtt), expect_link_up);
    }
}
