use async_trait::async_trait;
use futures::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use surge_ping::{
    Client as PingerClient, Config as PingerConfig, PingIdentifier, PingSequence, SurgeError, ICMP,
};
use telio_crypto::PublicKey;
use telio_sockets::SocketPool;
use telio_task::{task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    dual_target, repeated_actions, telio_log_debug, telio_log_trace, telio_log_warn, DualTarget,
    RepeatedActions,
};

const PING_PAYLOAD_SIZE: usize = 56;

/// Possible [SessionKeeper] errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// `UdpProxy` `IoError`
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Task encountered an error while running
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
    /// Repeated action errors
    #[error(transparent)]
    RepeatedActionError(#[from] repeated_actions::RepeatedActionError),
    /// Pinger errors
    #[error(transparent)]
    PingerError(#[from] SurgeError),
    // Target error
    #[error(transparent)]
    DualTargetError(#[from] dual_target::DualTargetError),
}

type Result<T> = std::result::Result<T, Error>;

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait SessionKeeperTrait {
    async fn add_node(
        &self,
        public_key: &PublicKey,
        target: dual_target::Target,
        interval: Duration,
    ) -> Result<()>;
    async fn update_interval(&self, public_key: &PublicKey, interval: Duration) -> Result<()>;
    async fn remove_node(&self, public_key: &PublicKey) -> Result<()>;
}

pub struct SessionKeeper {
    task: Task<State>,
    use_ipv6: bool,
}

impl SessionKeeper {
    pub fn start(sock_pool: Arc<SocketPool>, use_ipv6: bool) -> Result<Self> {
        let mut config_builder = PingerConfig::builder();
        config_builder = config_builder.kind(ICMP::V4);
        if cfg!(not(target_os = "android")) {
            config_builder = config_builder.bind((Ipv4Addr::UNSPECIFIED, 0).into());
        }

        let pinger_client = PingerClient::new(&config_builder.build())?;

        sock_pool.make_internal(pinger_client.get_socket().get_native_sock())?;

        Ok(Self {
            task: Task::start(State {
                pinger_client,
                keepalive_actions: RepeatedActions::default(),
            }),
            use_ipv6,
        })
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    #[cfg(test)]
    async fn get_pinger_client(&self) -> Result<PingerClient> {
        task_exec!(&self.task, async move |s| Ok(s.pinger_client.clone()))
            .await
            .map_err(Error::Task)
    }

    // TODO: add_nodes(), remove_nodes(), update_nodes()
}

#[async_trait]
impl SessionKeeperTrait for SessionKeeper {
    async fn add_node(
        &self,
        public_key: &PublicKey,
        target: dual_target::Target,
        interval: Duration,
    ) -> Result<()> {
        let public_key = *public_key;
        let dual_target = DualTarget::new(target, self.use_ipv6)?;

        task_exec!(&self.task, async move |s| {
            if s.keepalive_actions.contains_action(&public_key) {
                let _ = s.keepalive_actions.remove_action(&public_key);
            }

            Ok(s.keepalive_actions.add_action(
                public_key,
                interval,
                Arc::new(move |c| {
                    Box::pin(async move {
                        let (primary, secondary) = dual_target.get_targets()?;
                        telio_log_debug!(
                            "Pinging primary target {:?} on {:?}",
                            public_key,
                            primary
                        );

                        if let Err(e) = c
                            .pinger_client
                            .pinger(primary, PingIdentifier(112))
                            .await
                            .send_ping(PingSequence(211), &[0; PING_PAYLOAD_SIZE])
                            .await
                        {
                            telio_log_warn!("Primary target failed: {}", e.to_string());

                            if let Some(second) = secondary {
                                telio_log_debug!(
                                    "Pinging secondary target {:?} on {:?}",
                                    public_key,
                                    second
                                );
                                let _ = c
                                    .pinger_client
                                    .pinger(second, PingIdentifier(112))
                                    .await
                                    .send_ping(PingSequence(211), &[0; PING_PAYLOAD_SIZE])
                                    .await?;
                            }
                        }
                        Ok(())
                    })
                }),
            ))
        })
        .await
        .map_err(Error::Task)?
        .map_err(Error::RepeatedActionError)
        .map(|_| ())
    }

    async fn update_interval(&self, public_key: &PublicKey, interval: Duration) -> Result<()> {
        let public_key = *public_key;
        task_exec!(&self.task, async move |s| {
            let _ = s.keepalive_actions.update_interval(&public_key, interval);
            Ok(())
        })
        .await
        .map_err(Error::Task)
    }

    async fn remove_node(&self, public_key: &PublicKey) -> Result<()> {
        // FIXME: error handling with task_exec! seems to suck a lot. Need to fix that.
        let public_key = *public_key;
        task_exec!(&self.task, async move |s| {
            let _ = s.keepalive_actions.remove_action(&public_key);
            Ok(())
        })
        .await
        .map_err(Error::Task)
    }
}
struct State {
    pinger_client: PingerClient,
    keepalive_actions: RepeatedActions<PublicKey, Self, Result<()>>,
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "SessionKeeper";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        tokio::select! {
            Ok((pk, action)) = self.keepalive_actions.select_action() => {
                let pk = *pk;

                telio_log_trace!("({}) name: \"{}\", action = actions.select_action()", Self::NAME, pk);

                action(self)
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error sending keepalive to {} node: {}", Self::NAME, pk, e.to_string());
                        Ok(())
                    }, |_| Ok(()))?;
            }
            update = update => {
                return update(self).await;
            }
            else => {
                return Ok(());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use telio_sockets::NativeProtector;
    use telio_test::assert_elapsed;
    use tokio::time;

    #[tokio::test(start_paused = false)]
    #[ignore = "cannot recv on internal ICMP socket"]
    async fn send_keepalives() {
        const PERIOD: Duration = Duration::from_millis(100);

        let socket_pool = Arc::new(SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));
        let sess_keep = SessionKeeper::start(socket_pool, true).unwrap();

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        sess_keep
            .add_node(
                &pk,
                (Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST)),
                PERIOD,
            )
            .await
            .unwrap();

        let sock = sess_keep.get_pinger_client().await.unwrap().get_socket();

        // Drop the pinger client explicitly, for it to stop listening on ICMP socket
        drop(sess_keep.get_pinger_client().await.unwrap());

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(Duration::from_secs(1));
            tokio::pin!(timeout);

            let mut rx_buff = [0; 1024];
            let mut start = None;
            let mut cnt = 0;

            loop {
                tokio::select! {
                    Ok(_) = sock.recv_from(&mut rx_buff) => {
                        // assert_eq!(len, 0);
                        // assert_eq!(addr, sess_keep_addr);

                        println!("Hello");

                        if cnt == 0 {
                            start = Some(time::Instant::now());
                            // time::advance(PERIOD).await;
                        } else {
                            assert_elapsed!(
                                start.unwrap(),
                                PERIOD,
                                Duration::from_millis(10)
                            );
                            break;
                        }

                        cnt += 1;

                        continue;
                    }
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = sess_keep.stop().await;
        })
        .await
        .unwrap();
    }
}
