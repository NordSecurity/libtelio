use async_trait::async_trait;
use socket2::Type;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use std::{convert::TryInto, net::IpAddr};
use surge_ping::{
    Client, Config as PingerConfig, ConfigBuilder, PingIdentifier, PingSequence, ICMP,
};

use telio_crypto::PublicKey;
use telio_task::{
    io::{chan, mc_chan, Chan, McChan},
    task_exec, ExecError, Runtime, RuntimeExt, Task, WaitResponse,
};
use telio_utils::{telio_log_debug, telio_log_error, DualTarget};

/// Component used to check the link state when we think it's down.
/// We can check it before we announce it as down.
///
/// Can be used with both IPv4 and IPv6 addresses.
pub struct Pinger {
    task: Task<State>,
}

impl Pinger {
    pub fn start_with(ping_channel: chan::Rx<IpAddr>) -> std::io::Result<Self> {
        Ok(Self {
            task: Task::start(State::new(ping_channel)?),
        })
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

pub struct State {
    pub ping_channel: chan::Rx<IpAddr>,
    client_v4: Arc<Client>,
    client_v6: Arc<Client>,
}

impl State {
    const PING_TIMEOUT: Duration = Duration::from_secs(3);

    pub fn new(ping_channel: chan::Rx<IpAddr>) -> std::io::Result<Self> {
        Ok(State {
            ping_channel,
            client_v4: Arc::new(Client::new(&Self::make_builder(ICMP::V4).build())?),
            client_v6: Arc::new(Client::new(&Self::make_builder(ICMP::V6).build())?),
        })
    }

    pub async fn perform(&self, target: IpAddr) {
        telio_log_debug!("Trying to ping {:?} host", target);

        let mut pinger = match target {
            IpAddr::V4(_) => {
                self.client_v4
                    .clone()
                    .pinger(target, PingIdentifier(rand::random()))
                    .await
            }
            IpAddr::V6(_) => {
                self.client_v6
                    .clone()
                    .pinger(target, PingIdentifier(rand::random()))
                    .await
            }
        };

        pinger.timeout(Self::PING_TIMEOUT);

        match pinger.ping(PingSequence(0), &[0; 56]).await {
            Ok(_) => telio_log_debug!("Ping to {} succeeded", target),
            Err(e) => telio_log_debug!("Ping to {} failed: {}", target, e.to_string()),
        }
    }

    fn make_builder(proto: ICMP) -> ConfigBuilder {
        let mut config_builder = PingerConfig::builder().kind(proto);
        if cfg!(any(
            target_os = "ios",
            target_os = "macos",
            target_os = "tvos",
        )) {
            config_builder = config_builder.sock_type_hint(Type::RAW);
        }
        if cfg!(not(target_os = "android")) {
            match proto {
                ICMP::V4 => {
                    config_builder = config_builder.bind((Ipv4Addr::UNSPECIFIED, 0).into());
                }
                ICMP::V6 => {
                    config_builder = config_builder.bind((Ipv6Addr::UNSPECIFIED, 0).into());
                }
            }
        }
        config_builder
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Link detection pinger";

    type Err = ();

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        if let Some(target) = self.ping_channel.recv().await {
            Self::guard(async move {
                self.perform(target).await;
                Ok(())
            })
        } else {
            Self::next()
        }
    }
}
