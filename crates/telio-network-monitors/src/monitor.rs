//! Module to monitor changes in network.
//! Get notified when network paths change
//! and update local IP address cache
use crate::{local_interfaces::gather_local_interfaces, local_interfaces::GetIfAddrs};
use if_addrs::Interface;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{
    io,
    net::IpAddr,
    sync::{Arc, Weak},
};
use telio_utils::{telio_log_debug, telio_log_trace, telio_log_warn};
use tokio::{sync::broadcast::Sender, task::JoinHandle};
/// Sender to notify if there is a change in OS interface order
pub static PATH_CHANGE_BROADCAST: Lazy<Sender<()>> = Lazy::new(|| Sender::new(10));
#[cfg(all(
    not(test),
    any(target_os = "macos", target_os = "ios", target_os = "tvos")
))]
static NW_PATH_MONITOR_START: std::sync::Once = std::sync::Once::new();

#[derive(Default, Debug)]
struct PausedState {
    is_paused: bool,
    is_path_change_enqueued: bool,
}

/// Trait which should be implemented to receive local address change notifications
pub trait LocalInterfacesObserver: Sync + Send {
    /// Callback which allows to take certain actions when local interfaces changed
    fn notify(&self, addrs: &[IpAddr]);
}

#[derive(Debug)]
/// Struct to monitor network
pub struct NetworkMonitor {
    if_cache_updater_handle: Option<JoinHandle<io::Result<()>>>,
    // Mac and Windows use callbacks, whereas in Linux a socket is registered
    // with netlink multicast group messages
    #[cfg(target_os = "linux")]
    monitor_handle: Option<JoinHandle<io::Result<()>>>,
    #[cfg(target_os = "windows")]
    monitor_handle: crate::windows::SafeHandle,
    paused_state: Arc<Mutex<PausedState>>,
}

/// Result of a gather operation containing interface IPs and change status.
struct GatheredInterfaceIps {
    addrs: Vec<IpAddr>,
    changed: bool,
}

fn gather_and_cache_local_interfaces<G: GetIfAddrs>(
    get_if_addr: &G,
    iface_cache: &Mutex<Vec<Interface>>,
) -> io::Result<GatheredInterfaceIps> {
    telio_log_trace!("Gathering local interfaces list");
    let v = gather_local_interfaces(get_if_addr)?;
    let addrs = v.iter().map(|iface| iface.ip()).collect::<Vec<_>>();

    let mut cache = iface_cache.lock();
    let changed = *cache != v;
    if changed {
        telio_log_debug!("Gathered interfaces list differs from cached one");
        telio_log_debug!("cached interfaces list: {cache:?}");
        telio_log_debug!("new interfaces list: {v:?}");
    }

    *cache = v;
    Ok(GatheredInterfaceIps { addrs, changed })
}

/// Guard that will unpause the network monitoring when dropped
pub struct NetworkMonitorPausedGuard(Arc<Mutex<PausedState>>);

impl NetworkMonitorPausedGuard {
    fn new(paused_state: Arc<Mutex<PausedState>>) -> Self {
        paused_state.lock().is_paused = true;
        Self(paused_state)
    }
}

impl Drop for NetworkMonitorPausedGuard {
    fn drop(&mut self) {
        let is_path_change_enqueued = {
            let mut paused_state = self.0.lock();
            let is_path_change_enqueued = paused_state.is_path_change_enqueued;
            paused_state.is_path_change_enqueued = false;
            paused_state.is_paused = false;
            is_path_change_enqueued
        };
        if is_path_change_enqueued {
            let _ = PATH_CHANGE_BROADCAST.send(());
        }
    }
}

impl NetworkMonitor {
    /// Sets up and spawns network monitor with predefined observers.
    pub async fn new<G: GetIfAddrs>(
        get_if_addr: G,
        observers: Vec<Weak<dyn LocalInterfacesObserver>>,
    ) -> std::io::Result<NetworkMonitor> {
        let paused_state = Arc::new(Mutex::new(PausedState::default()));
        let iface_cache = Arc::new(Mutex::new(Vec::new()));
        match gather_and_cache_local_interfaces(&get_if_addr, &iface_cache) {
            Ok(gathered) => {
                for obs in &observers {
                    if let Some(observer) = obs.upgrade() {
                        observer.notify(&gathered.addrs);
                    }
                }
            }
            Err(e) => telio_log_warn!("Unable to get local interfaces {e}"),
        }

        let paused_state_copy = paused_state.clone();
        let if_cache_updater_handle = Some(tokio::spawn({
            let mut notify = PATH_CHANGE_BROADCAST.subscribe();
            async move {
                loop {
                    match notify.recv().await {
                        Ok(()) => {
                            let is_paused = {
                                let mut paused_state = paused_state_copy.lock();
                                let is_paused = paused_state.is_paused;
                                if is_paused {
                                    paused_state.is_path_change_enqueued = true;
                                }
                                is_paused
                            };
                            if is_paused {
                                telio_log_debug!("Received OS interface change notification but the module is paused.");
                            } else {
                                telio_log_trace!("Received OS interface change notification");
                            }

                            if !is_paused {
                                let gathered = match gather_and_cache_local_interfaces(
                                    &get_if_addr,
                                    &iface_cache,
                                ) {
                                    Ok(gathered) => gathered,
                                    Err(e) => {
                                        telio_log_warn!("Unable to get local interfaces {e}");
                                        continue;
                                    }
                                };
                                if !gathered.changed {
                                    continue;
                                }

                                telio_log_debug!(
                                    "Notifying registered observers about OS interface change"
                                );
                                for obs in &observers {
                                    if let Some(observer) = obs.upgrade() {
                                        observer.notify(&gathered.addrs);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            telio_log_warn!("Failed to receive new path for sockets ({e}): ");
                        }
                    }
                }
            }
        }));

        // Only add in production, otherwise network triggers from OS can occur
        // which can make the test (test_path_change_triggers_regather) flaky sometimes
        #[cfg(all(
            not(test),
            any(target_os = "macos", target_os = "ios", target_os = "tvos")
        ))]
        NW_PATH_MONITOR_START.call_once(crate::apple::setup_network_monitor);

        // TODO (LLT-7082): real OS monitors should not be instantiated in unit tests
        #[cfg(target_os = "linux")]
        let monitor_handle = crate::linux::setup_network_monitor().await;

        #[cfg(target_os = "windows")]
        let monitor_handle = crate::windows::setup_network_monitor();

        Ok(Self {
            if_cache_updater_handle,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            monitor_handle,
            paused_state,
        })
    }

    /// Start the pause of the network monitoring
    pub fn pause(&self) -> NetworkMonitorPausedGuard {
        NetworkMonitorPausedGuard::new(self.paused_state.clone())
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        if let Some(handle) = &self.if_cache_updater_handle {
            handle.abort();
        }
        #[cfg(target_os = "linux")]
        if let Some(handle) = &self.monitor_handle {
            handle.abort();
        }
        #[cfg(target_os = "windows")]
        if !self.monitor_handle.0.is_null() {
            crate::windows::deregister_network_monitor(self.monitor_handle.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::local_interfaces::MockGetIfAddrs;

    use super::*;
    use if_addrs::IfOperStatus;
    use serial_test::serial;
    use std::{
        net::IpAddr,
        net::Ipv4Addr,
        sync::atomic::{AtomicU8, Ordering},
    };

    static CALL_COUNT: AtomicU8 = AtomicU8::new(0);

    fn mk_interface(ip: Ipv4Addr) -> if_addrs::Interface {
        if_addrs::Interface {
            name: "correct".to_owned(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefixlen: 24,
                broadcast: None,
            }),
            index: None,
            oper_status: IfOperStatus::Testing,
            #[cfg(windows)]
            adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
        }
    }

    #[derive(Default)]
    struct LocalAddrsSnapshotObserver {
        notification_history: Mutex<Vec<Vec<IpAddr>>>,
    }

    impl LocalInterfacesObserver for LocalAddrsSnapshotObserver {
        fn notify(&self, addrs: &[IpAddr]) {
            self.notification_history.lock().push(addrs.to_vec());
        }
    }

    async fn setup_network_monitor() -> NetworkMonitor {
        CALL_COUNT.store(0, Ordering::SeqCst);
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock.expect_get().returning(|| {
            CALL_COUNT.fetch_add(1, Ordering::SeqCst);
            Ok(vec![mk_interface(Ipv4Addr::new(10, 0, 0, 1))])
        });
        NetworkMonitor::new(get_if_addrs_mock, Vec::new())
            .await
            .unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn test_path_change_triggers_regather() {
        let _network_monitor = setup_network_monitor().await;
        if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
            panic!("Failed to notify about changed path, error: {}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[serial]
    async fn test_multiple_monitor_instances() {
        let _network_monitor = setup_network_monitor().await;
        let _network_mon = setup_network_monitor().await;

        CALL_COUNT.store(0, Ordering::SeqCst);
        if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
            panic!("Failed to notify about changed path, error: {}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[serial]
    async fn test_monitor_dropping() {
        let _network_monitor = setup_network_monitor().await;
        if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
            panic!("Failed to notify about changed path, error: {}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        drop(_network_monitor);
        let _network_monitor = setup_network_monitor().await;

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_gather_if_error() {
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock
            .expect_get()
            .returning(|| Err(io::ErrorKind::NotFound.into()));

        if let Err(e) = NetworkMonitor::new(get_if_addrs_mock, Vec::new()).await {
            panic!("Network monitor not started with {}", e);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_observer_notified_on_startup_and_path_change() {
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock.expect_get().times(3).returning({
            let mut first = true;
            move || {
                let ip = if first {
                    first = false;
                    Ipv4Addr::new(10, 0, 0, 42)
                } else {
                    Ipv4Addr::new(10, 0, 0, 43)
                };
                Ok(vec![mk_interface(ip)])
            }
        });

        let observer = Arc::new(LocalAddrsSnapshotObserver::default());
        let observer_dyn: Arc<dyn LocalInterfacesObserver> = observer.clone();

        let _network_monitor =
            NetworkMonitor::new(get_if_addrs_mock, vec![Arc::downgrade(&observer_dyn)])
                .await
                .unwrap();

        // Startup gather
        let startup_expected = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))];
        assert_eq!(
            observer.notification_history.lock().last(),
            Some(&startup_expected)
        );

        PATH_CHANGE_BROADCAST.send(()).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Changed interface gather
        let changed_expected = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 43))];
        assert_eq!(
            observer.notification_history.lock().last(),
            Some(&changed_expected)
        );

        // Unchanged interfaces should not trigger observer notification.
        PATH_CHANGE_BROADCAST.send(()).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(
            *observer.notification_history.lock(),
            vec![
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))],
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 43))]
            ]
        );
    }
}
