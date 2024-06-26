//! Module to monitor changes in network.
//! Get notified about that network path has changed
//! and update local IP address cache
use once_cell::sync::Lazy;
#[cfg(target_os = "linux")]
use telio_utils::telio_log_error;
#[cfg(target_os = "linux")]
use tokio::sync::oneshot::{self, Sender as OneShotSender};

use std::io;
use std::sync::{Arc, Mutex as StdMutex};
use telio_utils::{local_interfaces, telio_log_trace, telio_log_warn, GetIFError, GetIfAddrs};
use tokio::{sync::broadcast::Sender, task::JoinHandle};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use crate::mac::setup_network_monitor;

/// Sender to notify if there is a change in OS interface order
pub static PATH_CHANGE_BROADCAST: Lazy<Sender<()>> = Lazy::new(|| Sender::new(2));
/// Vector containing all local interfaces
pub static LOCAL_ADDRS_CACHE: Lazy<Arc<StdMutex<Vec<if_addrs::Interface>>>> =
    Lazy::new(|| Arc::new(StdMutex::new(Vec::new())));
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
static NETWORK_PATH_MONITOR_START: std::sync::Once = std::sync::Once::new();

#[derive(Debug)]
/// Struct to monitor network
pub struct NetworkMonitor {
    nw_path_monitor_monitor_handle: Option<JoinHandle<io::Result<()>>>,
    #[cfg(target_os = "linux")]
    termination_channel_tx: Option<OneShotSender<()>>,
}

impl NetworkMonitor {
    /// Sets up and spawns network monitor
    pub fn new<G>(if_addr: G) -> Result<NetworkMonitor, GetIFError>
    where
        G: GetIfAddrs + Clone,
    {
        if let Ok(mut guard) = LOCAL_ADDRS_CACHE.lock() {
            *guard = local_interfaces::gather_local_interfaces(&if_addr)?;
        }

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        NETWORK_PATH_MONITOR_START.call_once(setup_network_monitor);

        #[cfg(target_os = "linux")]
        let (tx, rx) = oneshot::channel::<()>();
        #[cfg(target_os = "linux")]
        crate::linux::setup_network_monitor(rx);

        Ok(Self {
            nw_path_monitor_monitor_handle: None,
            #[cfg(target_os = "linux")]
            termination_channel_tx: Some(tx),
        })
    }

    /// Starts Network Monitoring IP cache
    pub fn start<G>(&mut self, get_if_addr: G)
    where
        G: GetIfAddrs + Clone,
    {
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

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        if let Some(handle) = &self.nw_path_monitor_monitor_handle {
            handle.abort();
        }
        #[cfg(target_os = "linux")]
        if let Some(sender) = self.termination_channel_tx.take() {
            if let Err(e) = sender.send(()) {
                telio_log_error!("Unable to terminate monitor {e:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use telio_utils::local_interfaces::MockGetIfAddrs;

    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_path_change_notification() {
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock.expect_get().return_once(|| {
            Ok(vec![if_addrs::Interface {
                name: "old".to_owned(),
                addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                    ip: Ipv4Addr::new(10, 0, 0, 1),
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                    broadcast: None,
                }),
                index: None,
                #[cfg(windows)]
                adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
            }])
        });

        let mut monitor = NetworkMonitor::new(get_if_addrs_mock).unwrap();
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock.expect_get().return_once(|| {
            Ok(vec![if_addrs::Interface {
                name: "new".to_owned(),
                addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                    ip: Ipv4Addr::new(10, 0, 0, 1),
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                    broadcast: None,
                }),
                index: None,
                #[cfg(windows)]
                adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
            }])
        });
        monitor.start(get_if_addrs_mock);
        {
            let interfaces = LOCAL_ADDRS_CACHE.lock().unwrap();
            assert!(interfaces.len() == 1);
            assert!(interfaces[0].name == "old");
        }

        if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
            println!("Failed to notify about changed path, error: {e}");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let interfaces = LOCAL_ADDRS_CACHE.lock().unwrap();
        assert!(interfaces.len() == 1);
        assert!(interfaces[0].name == "new");
    }
}
