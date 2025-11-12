#![cfg(windows)]

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

/// Observer implementation that forwards network change events to LinkDetection
impl LocalInterfacesObserver for EnhancedLinkDetection {
    fn notify(&self) {
        telio_log_debug!("Notified about local interfaces change");
        self.nw_change_flag.store(true, Ordering::Release);
    }
}

/// Component used to check the link state when it might be down.
///
/// This component is a workaround to improve wireguardNT link detection effectiveness due to
/// adapter behaviour. When it's disabled its state becomes undetectable, so this component
/// sends an ICMP request and the adapter's rx/tx counters observed.
///
/// Can be used with both IPv4 and IPv6 addresses.
pub struct EnhancedLinkDetection {
    task: Task<State>,
    /// Channel sender for triggering ping
    pub pinger_tx: chan::Tx<(Vec<IpAddr>, Option<IpStack>)>,
    /// Flag indicating whether a network change has occurred
    pub nw_change_flag: Arc<AtomicBool>,
}

impl EnhancedLinkDetection {
    /// Starts the enhanced link detection component with the specified configuration.
    pub fn start_with(
        no_of_pings: u32,
        ipv6_enabled: bool,
        socket_pool: Arc<SocketPool>,
    ) -> std::io::Result<Self> {
        let ping_channel = Chan::default();
        Ok(Self {
            task: Task::start(State::new(
                ping_channel.rx,
                no_of_pings,
                ipv6_enabled,
                socket_pool,
            )?),
            pinger_tx: ping_channel.tx,
            nw_change_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Stops the enhanced link detection component and waits for cleanup.
    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

pub struct State {
    pub ping_channel: chan::Rx<(Vec<IpAddr>, Option<IpStack>)>,
    pinger: Pinger,
}

impl State {
    pub fn new(
        ping_channel: chan::Rx<(Vec<IpAddr>, Option<IpStack>)>,
        no_of_pings: u32,
        ipv6_enabled: bool,
        socket_pool: Arc<SocketPool>,
    ) -> std::io::Result<Self> {
        Ok(State {
            ping_channel,
            pinger: Pinger::new(no_of_pings, ipv6_enabled, socket_pool, "link_detection")?,
        })
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Link detection pinger";

    type Err = ();

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        if let Some(targets) = self.ping_channel.recv().await {
            telio_log_debug!("{} received a trigger", Self::NAME);
            Self::guard(async move {
                let curr_ip_stack = targets.1;
                // We do not want to ping anything, unless we have an IP address/stack assigned
                if let Some(ipstack) = curr_ip_stack.as_ref() {
                    for target in targets.0 {
                        let t = match target {
                            IpAddr::V4(v4) => (Some(v4), None),
                            IpAddr::V6(v6) => (None, Some(v6)),
                        };
                        // Skip unsupported combinations
                        match (ipstack, target) {
                            (IpStack::IPv4, IpAddr::V6(_)) | (IpStack::IPv6, IpAddr::V4(_)) => {
                                continue
                            }
                            // Supported combo, nothing to do here
                            _ => (),
                        }
                        if let Ok(t) = DualTarget::new(t) {
                            if let Err(e) = self.pinger.send_ping(&t).await {
                                telio_log_warn!("Failed to ping peer: {:?}", e);
                            }
                        }
                    }
                }
                telio_log_debug!("No targets left to ping");

                Ok(())
            })
        } else {
            Self::next()
        }
    }
}
