//! Module to monitor changes in network.
//! Get notified about that network path has changed
//! and update local IP address cache
use once_cell::sync::Lazy;
use std::io;
use std::sync::{Arc, Mutex as StdMutex};
use telio_utils::{
    local_interfaces, telio_log_trace, telio_log_warn, GetIFError, GetIfAddrs, SystemGetIfAddrs,
};
use tokio::{sync::broadcast::Sender, task::JoinHandle};

use crate::mac::setup_network_monitor;

/// Sender to notify if there is a change in OS interface order
pub static PATH_CHANGE_BROADCAST: Lazy<Sender<()>> = Lazy::new(|| Sender::new(2));
/// Vector containing all local interfaces
pub static LOCAL_ADDRS_CACHE: Lazy<Arc<StdMutex<Vec<if_addrs::Interface>>>> =
    Lazy::new(|| Arc::new(StdMutex::new(Vec::new())));
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
static NETWORK_PATH_MONITOR_START: std::sync::Once = std::sync::Once::new();

#[derive(Debug, Default)]
/// Struct to monitor network
pub struct NetworkMonitor<G: GetIfAddrs = SystemGetIfAddrs> {
    nw_path_monitor_monitor_handle: Option<JoinHandle<io::Result<()>>>,
    get_if_addr: G,
}

impl<G: GetIfAddrs + Clone> NetworkMonitor<G> {
    /// Sets up and spawns network monitor
    pub fn new(if_addr: G) -> Result<NetworkMonitor<G>, GetIFError> {
        if let Ok(mut guard) = LOCAL_ADDRS_CACHE.lock() {
            *guard = local_interfaces::gather_local_interfaces(&if_addr)?;
        }

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        NETWORK_PATH_MONITOR_START.call_once(setup_network_monitor);

        #[cfg(target_os = "linux")]
        crate::linux::setup_monitor();

        Ok(Self {
            nw_path_monitor_monitor_handle: None,
            get_if_addr: if_addr,
        })
    }

    /// Starts Network Monitoring IP cache
    pub fn start(&mut self) {
        let get_if_addr = self.get_if_addr.clone();
        self.nw_path_monitor_monitor_handle = Some(tokio::spawn({
            let mut notify = PATH_CHANGE_BROADCAST.subscribe();
            async move {
                loop {
                    match notify.recv().await {
                        Ok(()) => match local_interfaces::gather_local_interfaces(&get_if_addr) {
                            Ok(v) => {
                                if let Ok(mut guard) = LOCAL_ADDRS_CACHE.lock() {
                                    telio_log_trace!("Updating local addr cache {:?}", v);
                                    *guard = v;
                                }
                            }
                            Err(e) => telio_log_warn!("Unable to get local interfaces {e}"),
                        },
                        Err(e) => {
                            telio_log_warn!("Failed to receive new path for sockets ({e}): ");
                        }
                    }
                }
            }
        }));
    }
}

impl<G: GetIfAddrs> Drop for NetworkMonitor<G> {
    fn drop(&mut self) {
        if let Some(handle) = &self.nw_path_monitor_monitor_handle {
            handle.abort();
        }
    }
}
