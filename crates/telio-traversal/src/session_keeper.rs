use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use futures::Future;
use futures::StreamExt;
use socket2::Type;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use surge_ping::{
    Client as PingerClient, Config as PingerConfig, ConfigBuilder, PingIdentifier, PingSequence,
    SurgeError, ICMP,
};
use telio_batcher::batcher;
use telio_batcher::batcher::{Batcher, BatcherTrait};
use telio_crypto::PublicKey;
use telio_sockets::SocketPool;
use telio_task::{task_exec, BoxAction, Runtime, Task};
use telio_utils::{dual_target, telio_log_debug, telio_log_warn, DualTarget};

const PING_PAYLOAD_SIZE: usize = 56;

/// Possible [SessionKeeper] errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Batcher error
    #[error(transparent)]
    BatcherError(#[from] batcher::Error),
    /// `UdpProxy` `IoError`
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Task encountered an error while running
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
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
        public_key: &PublicKey,
        target: dual_target::Target,
        interval: Duration,
        threshold: Duration,
    ) -> Result<()>;
    async fn remove_node(&self, public_key: &PublicKey) -> Result<()>;
}

pub struct SessionKeeper {
    task: Task<State>,
    batcher: Arc<Batcher>,
}

impl SessionKeeper {
    pub fn start(sock_pool: Arc<SocketPool>, batcher: Arc<Batcher>) -> Result<Self> {
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
                ping_data: HashMap::new(),
            }),
            batcher,
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
        public_key: &PublicKey,
        target: dual_target::Target,
        interval: Duration,
        threshold: Duration,
    ) -> Result<()> {
        let public_key = *public_key;
        let dual_target = DualTarget::new(target).map_err(Error::DualTargetError)?;

        let rx = self
            .batcher
            .add(public_key.to_string(), interval, threshold)
            .await?;

        task_exec!(&self.task, async move |s| {
            s.ping_data.insert(
                public_key,
                PingData {
                    trigger_rx: rx,
                    targets: dual_target,
                },
            );

            Ok(())
        })
        .await?;

        Ok(())
    }

    async fn remove_node(&self, public_key: &PublicKey) -> Result<()> {
        // FIXME: error handling with task_exec! seems to suck a lot. Need to fix that.
        let public_key = *public_key;

        task_exec!(&self.task, async move |s| {
            s.ping_data.remove(&public_key);
            Ok(())
        })
        .await?;

        let _ = self.batcher.remove(public_key.to_string()).await;

        Ok(())
    }
}
struct Pingers {
    pinger_client_v4: PingerClient,
    pinger_client_v6: PingerClient,
}

struct PingData {
    trigger_rx: tokio::sync::watch::Receiver<()>,
    targets: DualTarget,
}
struct State {
    pingers: Pingers,
    ping_data: HashMap<PublicKey, PingData>,
}
#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "SessionKeeper";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        let mut batcher_futures: FuturesUnordered<_> = self
            .ping_data
            .iter_mut()
            .map(|(pk, data)| async move {
                if data.trigger_rx.changed().await.is_err() {
                    // transmitter was dropped
                    return None;
                }
                Some(*pk)
            })
            .collect();

        tokio::select! {
            // TODO: an improvement would be to return all keys that should be pinged, thus reducing the latency
            Some(fut) = batcher_futures.next() => {
                if let Some(pk) = fut {
                    drop(batcher_futures);
                    match self.ping_data.get(&pk) {
                        Some(data) => {
                            if let Err(e) = ping(&self.pingers, (&pk, &data.targets)).await {
                                telio_log_warn!("Failed to ping, peer with key: {:?}, error: {:?}", pk, e);
                            }
                        }
                        None => {
                            telio_log_warn!("Peer key mapping doesn't exist for returned key: {:?}", pk);
                        }
                    }
                }
            }
            update = update => {
                drop(batcher_futures);
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
        let batcher = Arc::new(Batcher::start());
        let sess_keep = SessionKeeper::start(socket_pool, batcher).unwrap();

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        sess_keep
            .add_node(
                &pk,
                (Some(Ipv4Addr::LOCALHOST), Some(Ipv6Addr::LOCALHOST)),
                PERIOD,
                Duration::from_secs(0),
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
}
