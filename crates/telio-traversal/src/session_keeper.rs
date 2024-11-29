use crate::batcher::{Batcher, BatcherTrait, BatchingOptions};
use async_trait::async_trait;
use socket2::Type;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use surge_ping::{
    Client as PingerClient, Config as PingerConfig, ConfigBuilder, PingIdentifier, PingSequence,
    SurgeError, ICMP,
};
use telio_crypto::PublicKey;
use telio_model::features::FeatureBatching;
use telio_sockets::SocketPool;
use telio_task::{task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    dual_target, repeated_actions, telio_log_debug, telio_log_warn, DualTarget, RepeatedActions,
};
use tokio::sync::watch;
use tokio::time::Instant;

use futures::future::{pending, BoxFuture};
use futures::FutureExt;

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
        threshold: Option<Duration>,
    ) -> Result<()>;
    async fn remove_node(&self, key: &PublicKey) -> Result<()>;
    async fn get_interval(&self, key: &PublicKey) -> Option<u32>;
}

pub struct SessionKeeper {
    task: Task<State>,
}

impl SessionKeeper {
    pub fn start(
        sock_pool: Arc<SocketPool>,
        batching_feature: FeatureBatching,
        network_activity: Option<watch::Receiver<Instant>>,

        #[cfg(test)] batcher: Box<dyn BatcherTrait<PublicKey, State>>,
    ) -> Result<Self> {
        telio_log_debug!(
            "Starting SessionKeeper with network subscriber: {}",
            network_activity.is_some()
        );
        let (client_v4, client_v6) = (
            PingerClient::new(&Self::make_builder(ICMP::V4).build())
                .map_err(|e| Error::PingerCreationError(ICMP::V4, e))?,
            PingerClient::new(&Self::make_builder(ICMP::V6).build())
                .map_err(|e| Error::PingerCreationError(ICMP::V6, e))?,
        );

        sock_pool.make_internal(client_v4.get_socket().get_native_sock())?;
        sock_pool.make_internal(client_v6.get_socket().get_native_sock())?;

        Ok(Self {
            task: Task::start(State {
                pingers: Pingers {
                    pinger_client_v4: client_v4,
                    pinger_client_v6: client_v6,
                },

                #[cfg(test)]
                batched_actions: batcher,

                #[cfg(not(test))]
                batched_actions: Box::new(Batcher::new(batching_feature.into())),

                nonbatched_actions: RepeatedActions::default(),

                network_activity,
            }),
        })
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

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    #[cfg(test)]
    async fn get_pinger_client(&self, proto: ICMP) -> Result<PingerClient> {
        task_exec!(&self.task, async move |s| {
            Ok(match proto {
                ICMP::V4 => s.pingers.pinger_client_v4.clone(),
                ICMP::V6 => s.pingers.pinger_client_v6.clone(),
            })
        })
        .await
        .map_err(Error::Task)
    }
}

async fn ping(pingers: &Pingers, targets: (&PublicKey, &DualTarget)) -> Result<()> {
    let (primary, secondary) = targets.1.get_targets()?;
    let public_key = targets.0;

    telio_log_debug!("Pinging primary target {:?} on {:?}", public_key, primary);

    let primary_client = match primary {
        IpAddr::V4(_) => &pingers.pinger_client_v4,
        IpAddr::V6(_) => &pingers.pinger_client_v6,
    };

    let ping_id = PingIdentifier(rand::random());
    if let Err(e) = primary_client
        .pinger(primary, ping_id)
        .await
        .send_ping(PingSequence(0), &[0; PING_PAYLOAD_SIZE])
        .await
    {
        telio_log_warn!("Primary target failed: {}", e.to_string());

        if let Some(second) = secondary {
            telio_log_debug!("Pinging secondary target {:?} on {:?}", public_key, second);

            let secondary_client = match second {
                IpAddr::V4(_) => &pingers.pinger_client_v4,
                IpAddr::V6(_) => &pingers.pinger_client_v6,
            };

            secondary_client
                .pinger(second, PingIdentifier(rand::random()))
                .await
                .send_ping(PingSequence(0), &[0; PING_PAYLOAD_SIZE])
                .await?;
        }
    }

    Ok(())
}

#[async_trait]
impl SessionKeeperTrait for SessionKeeper {
    async fn add_node(
        &self,
        public_key: PublicKey,
        target: dual_target::Target,
        interval: Duration,
        threshold: Option<Duration>,
    ) -> Result<()> {
        telio_log_debug!("Add {}", public_key);

        let dual_target = DualTarget::new(target).map_err(Error::DualTargetError)?;
        match threshold {
            Some(t) => task_exec!(&self.task, async move |s| {
                s.batched_actions.add(
                    public_key,
                    interval,
                    t,
                    Arc::new(move |c: &mut State| {
                        Box::pin(async move {
                            telio_log_debug!("Batch-Pinging: {:?}", public_key);
                            if let Err(e) = ping(&c.pingers, (&public_key, &dual_target)).await {
                                telio_log_warn!(
                                    "Failed to batch-ping, peer with key: {:?}, error: {:?}",
                                    public_key,
                                    e
                                );
                            }
                            Ok(())
                        })
                    }),
                );

                Ok(())
            })
            .await
            .map_err(Error::Task)?,

            None => task_exec!(&self.task, async move |s| {
                if s.nonbatched_actions.contains_action(&public_key) {
                    let _ = s.nonbatched_actions.remove_action(&public_key);
                }

                Ok(s.nonbatched_actions.add_action(
                    public_key,
                    interval,
                    Arc::new(move |c| {
                        Box::pin(async move {
                            if let Err(e) = ping(&c.pingers, (&public_key, &dual_target)).await {
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
            .map_err(Error::RepeatedActionError)
            .map(|_| ())?,
        }

        Ok(())
    }

    async fn remove_node(&self, key: &PublicKey) -> Result<()> {
        let pk = *key;
        task_exec!(&self.task, async move |s| {
            let _ = s.nonbatched_actions.remove_action(&pk);
            let _ = s.batched_actions.remove(&pk);
            Ok(())
        })
        .await?;

        Ok(())
    }

    // TODO: SK calls batched and nonbatched actions interchangibly, however call sites in general
    // should be aware which one to call
    async fn get_interval(&self, key: &PublicKey) -> Option<u32> {
        let pk = *key;
        task_exec!(&self.task, async move |s| {
            if let Some(interval) = s.batched_actions.get_interval(&pk) {
                Ok(Some(interval.as_secs() as u32))
            } else {
                Ok(s.nonbatched_actions.get_interval(&pk))
            }
        })
        .await
        .unwrap_or(None)
    }
}

impl From<FeatureBatching> for BatchingOptions {
    fn from(f: FeatureBatching) -> Self {
        Self {
            trigger_effective_duration: Duration::from_secs(f.trigger_effective_duration.into()),
            trigger_cooldown_duration: Duration::from_secs(f.trigger_cooldown_duration.into()),
        }
    }
}

struct Pingers {
    pinger_client_v4: PingerClient,
    pinger_client_v6: PingerClient,
}

struct State {
    pingers: Pingers,
    batched_actions: Box<dyn BatcherTrait<PublicKey, Self>>,
    nonbatched_actions: RepeatedActions<PublicKey, Self, Result<()>>,
    network_activity: Option<watch::Receiver<Instant>>,
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "SessionKeeper";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        let last_network_activity = self
            .network_activity
            .as_mut()
            .map(|receiver| *receiver.borrow_and_update());

        let network_change_fut: BoxFuture<
            '_,
            std::result::Result<(), telio_utils::sync::watch::error::RecvError>,
        > = {
            match self.network_activity {
                Some(ref mut na) => na.changed().boxed(),
                None => pending::<()>().map(|_| Ok(())).boxed(),
            }
        };

        tokio::select! {
            _ = network_change_fut => {
                return Ok(());
            }
            Ok((pk, action)) = self.nonbatched_actions.select_action() => {
                let pk = *pk;
                action(self)
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error sending keepalive to {} node: {}", Self::NAME, pk, e.to_string());
                        Ok(())
                    }, |_| Ok(()))?;
            }
            Ok(batched_actions) = self.batched_actions.get_actions(last_network_activity) => {
                for (pk, action) in batched_actions {
                    action(self).await.map_or_else(|e| {
                        telio_log_warn!("({}) Error sending batch-keepalive to {}: {:?}", Self::NAME, pk, e);
                        Ok(())
                    }, |_| Ok(()))?;
                }
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
    use crate::batcher::{BatcherError, MockBatcherTrait};
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
        let sess_keep = SessionKeeper::start(
            socket_pool,
            FeatureBatching::default(),
            None,
            Box::new(Batcher::new(FeatureBatching::default().into())),
        )
        .unwrap();

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        sess_keep
            .add_node(
                pk,
                (Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST)),
                PERIOD,
                None,
            )
            .await
            .unwrap();

        let sock = sess_keep
            .get_pinger_client(ICMP::V4)
            .await
            .unwrap()
            .get_socket();

        // Drop the pinger client explicitly, for it to stop listening on ICMP socket
        drop(sess_keep.get_pinger_client(ICMP::V4).await.unwrap());

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

    #[tokio::test]
    async fn test_batcher_invocation() {
        const PERIOD: Duration = Duration::from_secs(20);

        const THRESHOLD: Duration = Duration::from_secs(10);
        let socket_pool = Arc::new(SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));

        let mut batcher = Box::new(MockBatcherTrait::<telio_crypto::PublicKey, State>::new());

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        use mockall::predicate::{always, eq};
        batcher
            .expect_add()
            .once()
            .with(eq(pk), eq(PERIOD), eq(THRESHOLD), always())
            .return_once(|_, _, _, _| ());
        batcher
            .expect_remove()
            .once()
            .with(eq(pk))
            .return_once(|_| ());

        // it's hard to mock the exact return since it involves a complex type, however we
        // can at least verify that the batcher's actions were queried
        batcher
            .expect_get_actions()
            .times(..)
            .returning(|_| Err(BatcherError::NoActions));

        let sess_keep = SessionKeeper::start(
            socket_pool,
            FeatureBatching::default().into(),
            None,
            batcher,
        )
        .unwrap();

        sess_keep
            .add_node(
                pk,
                (Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST)),
                PERIOD,
                Some(THRESHOLD),
            )
            .await
            .unwrap();

        sess_keep.remove_node(&pk).await.unwrap();

        // courtesy wait to be sure the runtime polls everything
        sess_keep.stop().await;
    }
}
