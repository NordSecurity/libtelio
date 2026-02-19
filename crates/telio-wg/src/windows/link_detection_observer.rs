#![cfg(windows)]
/// Module used to check the link state when network changes have been observed.
///
/// When the wireguard NT adapter is disabled the tx counters don't change, thus link detection
/// is not able to detect its status effectively.
/// As a workaround we send an ICMP request and wait for the reply which is reflected in the rx counters.
/// It supports both IPv4 and IPv6 targets.
use async_trait::async_trait;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;

use telio_network_monitors::monitor::LocalInterfacesObserver;
use telio_pinger::Pinger;
use telio_sockets::SocketPool;
use telio_task::{
    io::{chan, Chan},
    task_exec, Runtime, RuntimeExt, Task, WaitResponse,
};
use telio_utils::{ip_stack, telio_log_warn, DualTarget, IpStack};

use telio_utils::telio_log_debug;

const NR_OF_PINGS: u32 = 1;
/// Observer wrapper that forwards network change events from network monitor to LinkDetection
///
/// This spares LinkDetection to be Send+Sync because otherwise a LinkDetection reference would need
/// to be passed to the NetworkMonitor mod (see telio::device::Runtime::start()) just for the sake of
/// accessing the LocalInterfacesObserver::notify() implementation.
pub struct LinkDetectionObserver {
    /// Flag indicating whether a network change has occurred
    pub occurred: AtomicBool,
    /// Pinger instance
    pub pinger: Pinger,
}

impl LocalInterfacesObserver for LinkDetectionObserver {
    fn notify(&self, _addrs: &[IpAddr]) {
        telio_log_debug!("Notified about local interfaces change");
        self.occurred.store(true, Ordering::Release);
    }
}

impl LinkDetectionObserver {
    /// Creates a new `LinkDetectionObserver` instance with the given parameters for Pinger init.
    pub fn new(ipv6: bool, socket_pool: Arc<SocketPool>) -> Result<Self, std::io::Error> {
        Ok(Self {
            occurred: AtomicBool::new(false),
            pinger: Pinger::new(NR_OF_PINGS, ipv6, socket_pool, "link_detection")?,
        })
    }

    pub(crate) async fn ping(&self, node_addresses: Vec<IpAddr>, curr_ip_stack: Option<IpStack>) {
        // We do not want to ping anything, unless we have an IP address/stack assigned
        if let Some(ipstack) = curr_ip_stack.as_ref() {
            for target in node_addresses {
                let t = match target {
                    IpAddr::V4(v4) => (Some(v4), None),
                    IpAddr::V6(v6) => (None, Some(v6)),
                };
                // Skip unsupported combinations
                match (ipstack, target) {
                    (IpStack::IPv4, IpAddr::V6(_)) | (IpStack::IPv6, IpAddr::V4(_)) => continue,
                    // Supported combo, nothing to do here
                    _ => (),
                }
                if let Ok(t) = DualTarget::new(t) {
                    telio_log_debug!("Pinging {:?}", t);
                    if let Err(e) = self.pinger.send_ping(&t).await {
                        telio_log_warn!("Failed to ping peer: {:?}", e);
                    }
                }
            }
        }
        telio_log_debug!("No targets left to ping");
    }
}
