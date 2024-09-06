//! Module to monitor changes in network.
//! Get notified when network paths change
//! and update local IP address cache
use ipnet::Ipv4Net;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{io, net::{IpAddr, Ipv4Addr}};
use telio_utils::{telio_log_debug, telio_log_warn};
use tokio::{sync::broadcast::Sender, task::JoinHandle};
/// Sender to notify if there is a change in OS interface order
pub static PATH_CHANGE_BROADCAST: Lazy<Sender<()>> = Lazy::new(|| Sender::new(2));
/// Vector containing all local interfaces
pub static LOCAL_ADDRS_CACHE: Mutex<Vec<if_addrs::Interface>> = Mutex::new(Vec::new());
#[cfg(all(
    not(test),
    any(target_os = "macos", target_os = "ios", target_os = "tvos")
))]
static NW_PATH_MONITOR_START: std::sync::Once = std::sync::Once::new();


#[cfg(not(test))]
/// Get local interfaces with IPv4 addresses in the meshnet subnet
pub fn gather_local_interfaces() -> io::Result<Vec<if_addrs::Interface>> {
    let shared_range: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10).unwrap_or_default();
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .filter(|x| {
            !x.addr.is_loopback() && {
                match x.addr.ip() {
                    // Filter 100.64/10 libtelio's meshnet network.
                    IpAddr::V4(v4) => !shared_range.contains(&v4),
                    // Filter IPv6
                    _ => false,
                }
            }
        })
        .collect())
}

#[cfg(test)]
use tests::gather_local_interfaces;

#[derive(Debug)]
/// Struct to monitor network
pub struct NetworkMonitor {
    if_cache_updater_handle: Option<JoinHandle<io::Result<()>>>,
    // Mac and Windows use callbacks, whereas in Linux a socket is registered
    // with netlink multicast group messages
    #[cfg(all(not(test), target_os = "linux"))]
    monitor_handle: Option<JoinHandle<io::Result<()>>>,
    #[cfg(all(not(test), target_os = "windows"))]
    monitor_handle: crate::windows::SafeHandle,
}

impl NetworkMonitor {
    /// Sets up and spawns network monitor
    pub async fn new() -> std::io::Result<NetworkMonitor> {
        *(LOCAL_ADDRS_CACHE.lock()) = gather_local_interfaces()?;

        let if_cache_updater_handle = Some(tokio::spawn({
            let mut notify = PATH_CHANGE_BROADCAST.subscribe();
            async move {
                loop {
                    match notify.recv().await {
                        Ok(()) => match gather_local_interfaces() {
                            Ok(v) => {
                                telio_log_debug!("Updating local addr cache");
                                *(LOCAL_ADDRS_CACHE.lock()) = v;
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

        // Only add in production, otherwise network triggers from OS can occur
        // which can make the test (test_path_change_notification) flaky sometimes
        #[cfg(all(
            not(test),
            any(target_os = "macos", target_os = "ios", target_os = "tvos")
        ))]
        NW_PATH_MONITOR_START.call_once(crate::apple::setup_network_monitor);
        #[cfg(all(not(test), target_os = "linux"))]
        let monitor_handle = crate::linux::setup_network_monitor().await;

        #[cfg(all(not(test), target_os = "windows"))]
        let monitor_handle = crate::windows::setup_network_monitor();

        Ok(Self {
            if_cache_updater_handle,
            #[cfg(all(not(test), any(target_os = "linux", target_os = "windows")))]
            monitor_handle,
        })
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        if let Some(handle) = &self.if_cache_updater_handle {
            handle.abort();
        }
        #[cfg(all(not(test), target_os = "linux"))]
        if let Some(handle) = &self.monitor_handle {
            handle.abort();
        }
        #[cfg(all(not(test), target_os = "windows"))]
        if !self.monitor_handle.0.is_null() {
            crate::windows::deregister_network_monitor(self.monitor_handle.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicU8, Ordering},
    };
    use tokio::time::{sleep, Duration};

    static CALL_COUNT: AtomicU8 = AtomicU8::new(0);

    pub fn gather_local_interfaces() -> io::Result<Vec<if_addrs::Interface>> {
        CALL_COUNT.fetch_add(1, Ordering::Relaxed);
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
    }

    #[tokio::test]
    async fn test_path_change_notification() {
        let _network_monitor = NetworkMonitor::new().await.unwrap();
        if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
            println!("Failed to notify about changed path, error: {e}");
        }
        sleep(Duration::from_secs(1)).await;

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
    }
}
