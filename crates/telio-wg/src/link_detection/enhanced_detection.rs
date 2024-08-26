use async_trait::async_trait;
use std::net::IpAddr;

use telio_task::{io::chan, task_exec, Runtime, RuntimeExt, Task, WaitResponse};
use telio_utils::{ip_stack, DualTarget, IpStack, Pinger};

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
    ) -> std::io::Result<Self> {
        Ok(Self {
            task: Task::start(State::new(ping_channel, no_of_pings, ipv6_enabled)?),
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
    ) -> std::io::Result<Self> {
        Ok(State {
            ping_channel,
            pinger: Pinger::new(no_of_pings, ipv6_enabled)?,
        })
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Link detection pinger";

    type Err = ();

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        if let Some(targets) = self.ping_channel.recv().await {
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
                            _ => (),
                        }
                        if let Ok(t) = DualTarget::new(t) {
                            let _ = self.pinger.perform(t).await;
                        }
                    }
                }
                Ok(())
            })
        } else {
            Self::next()
        }
    }
}
