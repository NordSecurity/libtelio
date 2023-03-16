use async_trait::async_trait;
use futures::{future::pending, FutureExt};
use slog::{o, Drain, Logger, Never};
use telio_sockets::SocketPool;
use telio_utils::telio_log_debug;
use thiserror::Error as TError;
use tokio::time::{self, Interval};
use wireguard_uapi::xplatform::set;

use telio_crypto::{PublicKey, SecretKey};
use telio_task::{
    io::chan::{Rx, Tx},
    io::mc_chan,
    task_exec, Runtime, RuntimeExt, StopResult, Task, WaitResponse,
};

#[cfg(test)]
use mockall::automock;

use crate::{
    adapter::{self, Adapter, AdapterType, Error, Tun},
    uapi::{self, AnalyticsEvent, Cmd, Event, Interface, Peer, PeerState, Response},
    FirewallCb,
};

use std::{collections::HashSet, future::Future, io, sync::Arc, time::Duration};

/// WireGuard adapter interface
#[cfg_attr(test, automock)]
#[async_trait]
pub trait WireGuard: Send + Sync + 'static {
    /// Get adapter handle, returns `None` on fail
    async fn get_interface(&self) -> Option<Interface>;
    /// Get adapter luid (local identifier) if supported by platform, `zero` otherwise
    async fn get_adapter_luid(&self) -> u64;
    /// Get adapter file descriptor if supported by platform, `None` otherwise
    async fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, Error>;
    /// Set secret key for adapter
    async fn set_secret_key(&self, key: SecretKey);
    /// Set adapter fwmark, unix only
    async fn set_fwmark(&self, fwmark: u32) -> bool;
    /// Add Peer to adapter
    async fn add_peer(&self, peer: Peer);
    /// Remove Peer from adapter
    async fn del_peer(&self, key: PublicKey);
    /// Disconnect from all peers, implemented only in Boringtun
    async fn drop_connected_sockets(&self);
    /// Stop adapter
    async fn stop(self);
}

/// WireGuard implementation allowing dynamic selection of implementation.
pub struct DynamicWg {
    task: Task<State>,
}

#[derive(Default)]
pub struct Config {
    pub adapter: AdapterType,
    pub name: Option<String>,
    pub tun: Option<Tun>,
    pub socket_pool: Arc<SocketPool>,
    pub firewall_process_inbound_callback: FirewallCb,
    pub firewall_process_outbound_callback: FirewallCb,
}

pub struct Io {
    pub events: Tx<Box<Event>>,
    pub analytics_tx: Option<mc_chan::Tx<Box<AnalyticsEvent>>>,
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
    uapi_failed_last_call: bool,
    uapi_fail_counter: i32,
}

const POLL_MILLIS: u64 = 1000;

#[cfg(all(not(test), windows))]
const DEFAULT_NAME: &str = "NordLynx";

#[cfg(all(not(test), any(target_os = "macos", target_os = "ios")))]
const DEFAULT_NAME: &str = "utun10";

#[cfg(all(not(test), any(target_os = "linux", target_os = "android")))]
const DEFAULT_NAME: &str = "nlx0";

impl DynamicWg {
    pub fn start(io: Io, cfg: Config) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let adapter = Self::start_adapter(cfg.try_clone()?)?;
        #[cfg(unix)]
        return Ok(Self::start_with(io, adapter, cfg));
        #[cfg(windows)]
        return Ok(Self::start_with(io, adapter));
    }

    fn start_with(io: Io, adapter: Box<dyn Adapter>, #[cfg(unix)] cfg: Config) -> Self {
        let interval = time::interval(Duration::from_millis(POLL_MILLIS));

        Self {
            task: Task::start(State {
                #[cfg(unix)]
                cfg,
                adapter,
                interval,
                interface: Default::default(),
                event: io.events,
                analytics_tx: io.analytics_tx,
                uapi_failed_last_call: false,
                uapi_fail_counter: 0,
            }),
        }
    }

    #[cfg(not(test))]
    fn start_adapter(cfg: Config) -> Result<Box<dyn Adapter>, Error> {
        adapter::start(
            cfg.adapter,
            &cfg.name.unwrap_or_else(|| DEFAULT_NAME.to_owned()),
            cfg.tun,
            cfg.socket_pool,
            cfg.firewall_process_inbound_callback,
            cfg.firewall_process_outbound_callback,
        )
    }

    #[cfg(test)]
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
    async fn get_interface(&self) -> Option<Interface> {
        task_exec!(&self.task, async move |s| Ok(s.interface.clone()))
            .await
            .ok()
    }

    async fn get_adapter_luid(&self) -> u64 {
        task_exec!(&self.task, async move |s| Ok(s.adapter.get_adapter_luid()))
            .await
            .ok()
            .unwrap_or(0)
    }

    async fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, Error> {
        task_exec!(&self.task, async move |s| Ok(s.adapter.get_wg_socket(ipv6)))
            .await
            .unwrap_or(Ok(None))
    }

    async fn set_secret_key(&self, key: SecretKey) {
        let _ = task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();
            to.private_key = Some(key);
            s.update(&to, true).await;
            Ok(())
        })
        .await;
    }

    async fn set_fwmark(&self, fwmark: u32) -> bool {
        task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();
            to.fwmark = fwmark;
            Ok(s.update(&to, true).await)
        })
        .await
        .unwrap_or(false)
    }

    async fn add_peer(&self, mut peer: Peer) {
        let _ = task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();

            if let Some(old_peer) = to.peers.get(&peer.public_key) {
                peer.time_since_last_handshake = old_peer.time_since_last_handshake;
                peer.rx_bytes = old_peer.rx_bytes;
                peer.tx_bytes = old_peer.tx_bytes;
            }

            to.peers.insert(peer.public_key, peer);
            s.update(&to, true).await;
            Ok(())
        })
        .await;
    }

    async fn del_peer(&self, key: PublicKey) {
        let _ = task_exec!(&self.task, async move |s| {
            let mut to = s.interface.clone();
            to.peers.remove(&key);
            s.update(&to, true).await;
            Ok(())
        })
        .await;
    }

    async fn drop_connected_sockets(&self) {
        let _ = task_exec!(&self.task, async move |s| {
            s.adapter.drop_connected_sockets().await;
            Ok(())
        })
        .await;
    }

    async fn stop(mut self) {
        let _ = self.task.stop().await.resume_unwind();
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
        })
    }
}

#[derive(Default)]
struct DiffKeys {
    pub delete_keys: HashSet<PublicKey>,
    pub insert_keys: HashSet<PublicKey>,
    pub update_keys: HashSet<PublicKey>,
}

impl State {
    async fn sync(&mut self) {
        if let Some(to) = self.uapi_request(&uapi::Cmd::Get).await.interface {
            let _ = self.update(&to, false).await;
        }
    }

    async fn uapi_request(&mut self, cmd: &Cmd) -> Response {
        let ret = self.adapter.send_uapi_cmd(cmd).await;
        telio_log_debug!("UAPI request: {}, response: {}", &cmd.to_string(), &ret);

        // Count continuous adapter failures.
        // As observed on Windows, a vNIC driver might fail a call right after wake-up,
        // but will properly resume work after that. In order to determine a non-recoverable failure
        // such as a malicious removal, we need to count the successive failed calls.
        // If a certain threshold is reached, cleanup the network config and notify the app about connection loss.
        if 0 == ret.errno {
            self.uapi_failed_last_call = false;
            self.uapi_fail_counter = 0;
        } else {
            self.uapi_failed_last_call = true;
            self.uapi_fail_counter += 1;
            // TODO: check failure count threshold, cleanup network config, destroy adapter, notify app
        }

        ret
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

    #[allow(mpsc_blocking_send)]
    async fn update_send_notification_events(
        &self,
        to: &uapi::Interface,
        diff_keys: &DiffKeys,
    ) -> bool {
        use PeerState::*;

        let from = &self.interface;

        // Setup
        let try_send = |state, peer| {
            self.event
                .send(Box::new(Event { state, peer }))
                .map(|r| r.is_ok())
        };

        // Notify all disconnects
        for key in &diff_keys.delete_keys {
            if !try_send(Disconnected, from.peers[key].clone()).await {
                return false;
            }
        }

        // Notify all new connections
        for key in &diff_keys.insert_keys {
            let peer = &to.peers[key];
            if !try_send(Connecting, peer.clone()).await {
                return false;
            }

            if peer.connected() && !try_send(Connected, peer.clone()).await {
                return false;
            }
        }

        // Check for updates, and notify
        for key in &diff_keys.update_keys {
            let old = &from.peers[key];
            let new = &to.peers[key];
            if old.connected() && !new.connected() {
                if !try_send(Connecting, new.clone()).await {
                    return false;
                }
            } else if !old.connected() && new.connected() && !try_send(Connected, new.clone()).await
            {
                return false;
            }
        }

        true
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
            private_key: to.private_key.map(|key| key.0),
            listen_port: to.listen_port,
            fwmark: match to.fwmark {
                0 => None,
                x => Some(x),
            },
            replace_peers: None,
            peers: removed_peers.chain(peers).collect(),
        }
    }

    #[allow(mpsc_blocking_send)]
    async fn update(&mut self, to: &uapi::Interface, push: bool) -> bool {
        // Diff and report events

        //
        // We need to track failed driver calls in uapi_request().
        // Because uapi_request() now needs a mut self, the mut borrow for self.uapi_request()
        // would collide with HashSet<&PublicKey> and with from=&self.interface,
        // which was used throughout this function for better readability.
        //
        // "from" was eliminated, the HashSets now contain PublicKeys instead of a ref
        // and this function was split into multiple parts retaining the original semantics.
        //
        // PLEASE NOTE the alias: let from = &self.interface;
        //
        if &self.interface == to {
            return false;
        }

        let diff_keys = self.update_calculate_changes(to);

        if !self.update_send_notification_events(to, &diff_keys).await {
            return false;
        }

        let mut success = true;
        if push {
            let dev = self.update_construct_set_device(to, &diff_keys);
            // mut self required here
            success = self.uapi_request(&Cmd::Set(dev)).await.errno == 0;
        }

        if let Some(analytics_tx) = &self.analytics_tx {
            for (pubkey, peer) in &to.peers {
                if let Some(endpoint) = peer.endpoint {
                    let tx_bytes = peer.tx_bytes.unwrap_or_default();
                    let rx_bytes = peer.rx_bytes.unwrap_or_default();
                    let peer_state = if diff_keys.delete_keys.contains(pubkey) {
                        PeerState::Disconnected
                    } else {
                        PeerState::Connected
                    };

                    let event = AnalyticsEvent {
                        public_key: *pubkey,
                        endpoint,
                        tx_bytes,
                        rx_bytes,
                        peer_state,
                        timestamp: std::time::Instant::now(),
                    };
                    if analytics_tx.send(Box::new(event)).is_err() {
                        telio_log_debug!("Failed to send analytics info for {:?}", pubkey);
                    }
                }
            }
        }

        self.interface = to.clone();

        success
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Wg";

    type Err = Error;

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        let _ = self.interval.tick().await;
        Self::guard(async move {
            self.sync().await;
            Ok(())
        })
    }

    async fn stop(self) {
        self.adapter.stop().await;
        #[cfg(unix)]
        self.cfg
            .tun
            .map(|tun| unsafe { libc::close(tun as libc::c_int) });
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex as StdMutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use lazy_static::lazy_static;
    use mockall::predicate;
    use tokio::{runtime::Handle, sync::Mutex, task, time::sleep};

    use telio_task::io::Chan;

    use super::*;
    use crate::adapter::MockAdapter;

    lazy_static! {
        pub(super) static ref RUNTIME_ADAPTER: StdMutex<Option<Box<dyn Adapter>>> =
            StdMutex::new(None);
    }

    #[async_trait]
    impl Adapter for Arc<Mutex<MockAdapter>> {
        async fn send_uapi_cmd(&self, cmd: &Cmd) -> Response {
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

    struct Env {
        event: Rx<Box<Event>>,
        adapter: Arc<Mutex<MockAdapter>>,
        wg: DynamicWg,
    }

    async fn setup() -> Env {
        let chan = Chan::default();

        let adapter = Arc::new(Mutex::new(MockAdapter::new()));

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: Some(Interface::default()),
            });
        let wg = DynamicWg::start_with(
            Io {
                events: chan.tx,
                analytics_tx: None,
            },
            Box::new(adapter.clone()),
            #[cfg(unix)]
            Config::default(),
        );
        time::advance(Duration::from_millis(0)).await;
        adapter.lock().await.checkpoint();

        Env {
            event: chan.rx,
            adapter,
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
        assert_eq!(Some(Interface::default()), wg.get_interface().await);

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

        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.set_secret_key(sks).await;
        adapter.lock().await.checkpoint();
        assert_eq!(Some(ifa.clone()), wg.get_interface().await);

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
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.set_fwmark(ifa.fwmark).await;
        adapter.lock().await.checkpoint();
        assert_eq!(Some(ifa.clone()), wg.get_interface().await);

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
            ..Default::default()
        };

        ifa.peers.insert(pkc, peer.clone());
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.add_peer(peer.clone()).await;
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                peer: peer.clone()
            })),
            event.recv().await
        );
        adapter.lock().await.checkpoint();
        assert_eq!(Some(ifa.clone()), wg.get_interface().await);

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
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        };

        ifa.peers.insert(pkc, peer.clone());
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.add_peer(peer.clone()).await;
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                peer: peer.clone()
            })),
            event.recv().await
        );
        adapter.lock().await.checkpoint();
        assert_eq!(Some(ifa.clone()), wg.get_interface().await);

        // Connect
        peer.time_since_last_handshake = Some(Duration::from_secs(15));
        ifa.peers.insert(pkc, peer.clone());
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: Some(ifa.clone()),
            });
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connected,
                peer: peer.clone()
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
            persistent_keepalive_interval: Some(25),
            ..Default::default()
        };

        ifa.peers.insert(pkc, peer.clone());
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.add_peer(peer.clone()).await;
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                peer: peer.clone()
            })),
            event.recv().await
        );
        adapter.lock().await.checkpoint();
        assert_eq!(Some(ifa.clone()), wg.get_interface().await);

        // Connects
        peer.time_since_last_handshake = Some(Duration::from_secs(94));
        ifa.peers.insert(pkc, peer.clone());
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: Some(ifa.clone()),
            });
        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connected,
                peer: peer.clone()
            })),
            event.recv().await
        );

        // Disconnects
        peer.time_since_last_handshake = Some(Duration::from_secs(182));
        ifa.peers.insert(pkc, peer.clone());
        adapter
            .lock()
            .await
            .expect_send_uapi_cmd()
            .with(predicate::eq(Cmd::Get))
            .times(1)
            .return_const(Response {
                errno: 0,
                interface: Some(ifa.clone()),
            });

        assert_eq!(
            Some(Box::new(Event {
                state: PeerState::Connecting,
                peer: peer.clone()
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
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.add_peer(peer.clone()).await;
        adapter.lock().await.checkpoint();

        assert_eq!(Some(iface.clone()), wg.get_interface().await);

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
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.del_peer(pubkey).await;
        adapter.lock().await.checkpoint();

        iface.peers.remove(&pubkey);

        assert_eq!(Some(iface.clone()), wg.get_interface().await);

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
        let mut peer = Peer {
            public_key: pubkey,
            endpoint: Some(([1, 1, 1, 1], 123).into()),
            persistent_keepalive_interval: Some(25),
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
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.add_peer(peer.clone()).await;
        adapter.lock().await.checkpoint();

        assert_eq!(Some(iface.clone()), wg.get_interface().await);

        peer.endpoint = Some(([1, 1, 1, 1], 124).into());

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
            .return_const(Response {
                errno: 0,
                interface: None,
            });
        wg.add_peer(peer.clone()).await;
        adapter.lock().await.checkpoint();

        assert_eq!(Some(iface.clone()), wg.get_interface().await);

        adapter.lock().await.expect_stop().return_once(|| ());
        wg.stop().await;
    }
}
