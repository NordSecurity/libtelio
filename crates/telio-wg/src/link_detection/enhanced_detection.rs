use async_trait::async_trait;
use std::net::IpAddr;

use telio_task::{io::chan, task_exec, Runtime, RuntimeExt, Task, WaitResponse};
use telio_utils::{DualTarget, Pinger};

/// Component used to check the link state when we think it's down.
///
/// Can be used with both IPv4 and IPv6 addresses.
pub struct EnhancedDetection {
    task: Task<State>,
}

impl EnhancedDetection {
    pub fn start_with(
        ping_channel: chan::Rx<Vec<IpAddr>>,
        no_of_pings: u32,
    ) -> std::io::Result<Self> {
        Ok(Self {
            task: Task::start(State::new(ping_channel, no_of_pings)?),
        })
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

pub struct State {
    pub ping_channel: chan::Rx<Vec<IpAddr>>,
    pinger: Pinger,
}

impl State {
    pub fn new(ping_channel: chan::Rx<Vec<IpAddr>>, no_of_pings: u32) -> std::io::Result<Self> {
        Ok(State {
            ping_channel,
            pinger: Pinger::new(no_of_pings)?,
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
                for target in targets {
                    let t = match target {
                        IpAddr::V4(v4) => (Some(v4), None),
                        IpAddr::V6(v6) => (None, Some(v6)),
                    };
                    if let Ok(t) = DualTarget::new(t) {
                        let _ = self.pinger.perform(t).await;
                    }
                }
                Ok(())
            })
        } else {
            Self::next()
        }
    }
}
