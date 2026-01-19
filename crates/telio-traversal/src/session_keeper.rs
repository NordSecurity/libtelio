use async_trait::async_trait;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use surge_ping::SurgeError;
use telio_crypto::PublicKey;
use telio_pinger::Pinger;
use telio_sockets::SocketPool;
use telio_task::{task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    dual_target, repeated_actions, telio_log_debug, telio_log_warn, DualTarget, RepeatedActions,
};

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
    /// Pinger creation error
    #[error("Pinger creation for {0:?} error: {1}")]
    PingerCreationError(surge_ping::ICMP, std::io::Error),
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
        public_key: PublicKey,
        target: dual_target::Target,
        interval: Duration,
    ) -> Result<()>;
    async fn remove_node(&self, key: &PublicKey) -> Result<()>;
}

pub struct SessionKeeper {
    task: Task<State>,
}

impl SessionKeeper {
    pub fn start(sock_pool: Arc<SocketPool>) -> Result<Self> {
        let pinger = Pinger::new(1, true, sock_pool, "session_keeper")?;

        Ok(Self {
            task: Task::start(State {
                pinger,
                actions: RepeatedActions::default(),
            }),
        })
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    #[cfg(test)]
    async fn get_pinger(&self) -> Result<Pinger> {
        task_exec!(&self.task, async move |s| Ok(s.pinger.clone()))
            .await
            .map_err(Error::Task)
    }
}

#[async_trait]
impl SessionKeeperTrait for SessionKeeper {
    async fn add_node(
        &self,
        public_key: PublicKey,
        target: dual_target::Target,
        interval: Duration,
    ) -> Result<()> {
        let dual_target = DualTarget::new(target).map_err(Error::DualTargetError)?;

        telio_log_debug!("Add peer: {} with interval: {:?}", public_key, interval);

        task_exec!(&self.task, async move |s| {
            if s.actions.contains_action(&public_key) {
                let _ = s.actions.remove_action(&public_key);
            }

            Ok(s.actions.add_action(
                public_key,
                interval,
                Arc::new(move |c| {
                    Box::pin(async move {
                        if let Err(e) = c.pinger.send_ping(&dual_target).await {
                            telio_log_warn!(
                                "Failed to ping, peer with key: {:?}, error: {:?}",
                                public_key,
                                e
                            );
                        }
                        Ok(())
                    })
                }),
            ))
        })
        .await
        .map_err(Error::Task)?
        .map_err(Error::RepeatedActionError)?;

        telio_log_debug!("Added {}", public_key);
        Ok(())
    }

    async fn remove_node(&self, key: &PublicKey) -> Result<()> {
        let pk = *key;
        task_exec!(&self.task, async move |s| {
            let _ = s.actions.remove_action(&pk);
            Ok(())
        })
        .await?;

        Ok(())
    }
}

struct State {
    pinger: Pinger,
    actions: RepeatedActions<PublicKey, Self, Result<()>>,
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
            Ok((pk, action)) = self.actions.select_action() => {
                let pk = *pk;
                action(self)
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error sending keepalive to {} node: {}", Self::NAME, pk, e.to_string());
                        Ok::<(), ()>(())
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
    use telio_crypto::PublicKey;
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
        let sess_keep = SessionKeeper::start(socket_pool).unwrap();

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        sess_keep
            .add_node(
                pk,
                (Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST)),
                PERIOD,
            )
            .await
            .unwrap();

        // Take the pinger socket
        let (sock, _) = sess_keep.get_pinger().await.unwrap().take_sockets();

        // Runtime
        tokio::spawn(async move {
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
