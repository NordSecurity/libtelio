//! Module to monitor changes in network.
//! Get notified when network paths change
//! and update local IP address cache
use crate::{local_interfaces::gather_local_interfaces, local_interfaces::GetIfAddrs};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{
    io,
    sync::{Arc, Weak},
};
use telio_utils::{telio_log_debug, telio_log_warn};
use tokio::{sync::broadcast::Sender, task::JoinHandle};
/// Sender to notify if there is a change in OS interface order
pub static PATH_CHANGE_BROADCAST: Lazy<Sender<()>> = Lazy::new(|| Sender::new(10));
/// Vector containing all local interfaces
pub static LOCAL_ADDRS_CACHE: Mutex<Vec<if_addrs::Interface>> = Mutex::new(Vec::new());
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
    fn notify(&self);
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
    local_interfaces_observers: Arc<Mutex<Vec<Weak<dyn LocalInterfacesObserver>>>>,
}

fn save_local_interfaces<G: GetIfAddrs>(get_if_addr: &G) -> bool {
    telio_log_debug!("Gathering local interfaces list");
    match gather_local_interfaces(get_if_addr) {
        Ok(v) => {
            let old_v = LOCAL_ADDRS_CACHE.lock().clone();
            if old_v != v {
                telio_log_debug!("Interfaces list differs from the one on cache");
                telio_log_debug!("old interfaces list: {old_v:?}");
                telio_log_debug!("new interfaces list: {v:?}");
                *(LOCAL_ADDRS_CACHE.lock()) = v;
                true
            } else {
                false
            }
        }
        Err(e) => {
            telio_log_warn!("Unable to get local interfaces {e}");
            false
        }
    }
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
    /// Sets up and spawns network monitor
    pub async fn new<G: GetIfAddrs>(get_if_addr: G) -> std::io::Result<NetworkMonitor> {
        let paused_state = Arc::new(Mutex::new(PausedState::default()));
        save_local_interfaces(&get_if_addr);

        let local_interfaces_observers =
            Arc::new(Mutex::new(Vec::<Weak<dyn LocalInterfacesObserver>>::new()));
        let observers_loop_copy = local_interfaces_observers.clone();

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
                                telio_log_debug!(
                                    "Received OS interface change notification"
                                );
                            }

                            if !is_paused && save_local_interfaces(&get_if_addr) {
                                telio_log_debug!(
                                    "Notifying observers with change type"
                                );
                                for observer in observers_loop_copy.lock().iter() {
                                    telio_log_debug!(
                                        "Processing observer at {:p}",
                                        observer.as_ptr()
                                    );
                                    if let Some(observer) = observer.upgrade() {
                                        observer.notify();
                                    } else {
                                        telio_log_debug!("Observer dropped, won't notify");
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
        // which can make the test (test_path_change_notification) flaky sometimes
        #[cfg(all(
            not(test),
            any(target_os = "macos", target_os = "ios", target_os = "tvos")
        ))]
        NW_PATH_MONITOR_START.call_once(crate::apple::setup_network_monitor);
        #[cfg(target_os = "linux")]
        let monitor_handle = crate::linux::setup_network_monitor().await;

        #[cfg(target_os = "windows")]
        let monitor_handle = crate::windows::setup_network_monitor();

        Ok(Self {
            if_cache_updater_handle,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            monitor_handle,
            paused_state,
            local_interfaces_observers,
        })
    }

    /// Start the pause of the network monitoring
    pub fn pause(&self) -> NetworkMonitorPausedGuard {
        NetworkMonitorPausedGuard::new(self.paused_state.clone())
    }

    /// Register a new listener of local addresses changes
    pub fn register_local_interfaces_observer(&self, observer: Weak<dyn LocalInterfacesObserver>) {
        telio_log_debug!("Adding observer at: {:p}", observer.as_ptr());
        self.local_interfaces_observers.lock().push(observer);
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
        net::Ipv4Addr,
        sync::atomic::{AtomicU8, Ordering},
    };

    static CALL_COUNT: AtomicU8 = AtomicU8::new(0);

    async fn setup_network_monitor() -> NetworkMonitor {
        CALL_COUNT.store(0, Ordering::SeqCst);
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock.expect_get().returning(|| {
            CALL_COUNT.fetch_add(1, Ordering::SeqCst);
            Ok(vec![if_addrs::Interface {
                name: "correct".to_owned(),
                addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                    ip: Ipv4Addr::new(10, 0, 0, 1),
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                    prefixlen: 24,
                    broadcast: None,
                }),
                index: None,
                oper_status: IfOperStatus::Testing,
                #[cfg(windows)]
                adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
            }])
        });
        NetworkMonitor::new(get_if_addrs_mock).await.unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn test_path_change_notification() {
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

        if let Err(e) = NetworkMonitor::new(get_if_addrs_mock).await {
            panic!("Network monitor not started with {}", e);
        }
    }
}
