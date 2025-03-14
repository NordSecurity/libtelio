use async_trait::async_trait;
use std::{net::IpAddr, sync::Arc};

use telio_pinger::Pinger;
use telio_sockets::SocketPool;
use telio_task::{io::chan, task_exec, Runtime, RuntimeExt, Task, WaitResponse};
use telio_utils::{ip_stack, telio_log_warn, DualTarget, IpStack};

use telio_utils::telio_log_debug;
/// Component used to check the link state when we think it's down.
///
/// Can be used with both IPv4 and IPv6 addresses.
pub struct EnhancedDetection {
    task: Task<State>,
}

impl EnhancedDetection {
    pub fn start_with(
        ping_channel: chan::Rx<(Vec<IpAddr>, Option<IpStack>)>,
        no_of_pings: u32,
        ipv6_enabled: bool,
        socket_pool: Arc<SocketPool>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            task: Task::start(State::new(
                ping_channel,
                no_of_pings,
                ipv6_enabled,
                socket_pool,
            )?),
        })
    }

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
            telio_log_debug!("ping channel received trigger");
            Self::guard(async move {
                let curr_ip_stack = targets.1;

                // We do not want to ping anything, unless we have an IP address assigned
                if let Some(ips) = curr_ip_stack.as_ref() {
                    for target in targets.0 {
                        let t = match target {
                            IpAddr::V4(v4) => (Some(v4), None),
                            IpAddr::V6(v6) => (None, Some(v6)),
                        };
                        // Skip unsupported combinations
                        match (ips, target) {
                            (IpStack::IPv4, IpAddr::V6(_)) | (IpStack::IPv6, IpAddr::V4(_)) => {
                                continue
                            }
                            _ => telio_log_debug!("Unsupported target combination"),
                        }
                        if let Ok(t) = DualTarget::new(t) {
                            if let Err(e) = self.pinger.send_ping(&t).await {
                                telio_log_warn!("Failed to ping peer: {:?}", e);
                            }
                        }
                    }
                } else {
                    telio_log_debug!("No targets to ping");
                }
                Ok(())
            })
        } else {
            Self::next()
        }
    }
}
