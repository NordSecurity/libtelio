use async_trait::async_trait;
use futures::Future;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use telio_crypto::PublicKey;
use telio_proto::UpgradeMsg;
use telio_task::{io::chan, io::Chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{telio_log_info, telio_log_warn};
use tokio::{
    sync::mpsc::error::SendError,
    time::{interval_at, Instant, Interval},
};

/// Possible [UpgradeSync] errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Channel error
    #[error(transparent)]
    SendUpgradeMsgErr(#[from] SendError<(PublicKey, UpgradeMsg)>),
    /// Channel error
    #[error(transparent)]
    SendUpgradeRequestChangeEventErr(#[from] SendError<UpgradeRequestChangeEvent>),
    /// Task encountered an error while running
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
    #[error("Upgrade request not found or expired")]
    NotFound,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UpgradeRequest {
    pub endpoint: SocketAddr,
    pub requested_at: Instant,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UpgradeRequestChangeEvent {
    old_request: Option<UpgradeRequest>,
    new_request: Option<UpgradeRequest>,
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait UpgradeSyncTrait {
    async fn get_upgrade_requests(&self) -> Result<HashMap<PublicKey, UpgradeRequest>>;
    async fn request_upgrade(
        &self,
        public_key: &PublicKey,
        remote_endpoint: SocketAddr,
        local_endpoint: SocketAddr,
    ) -> Result<()>;
    async fn remove_upgrade(&self, public_key: &PublicKey) -> Result<()>;
}

pub struct UpgradeSync {
    task: Task<State>,
}

pub struct State {
    upgrade_request_publisher: chan::Tx<UpgradeRequestChangeEvent>,
    intercoms: Chan<(PublicKey, UpgradeMsg)>,
    upgrade_requests: HashMap<PublicKey, UpgradeRequest>,
    expiration_period: Duration,
    poll_timer: Interval,
}

impl UpgradeSync {
    pub fn new(
        upgrade_request_publisher: chan::Tx<UpgradeRequestChangeEvent>,
        intercoms: Chan<(PublicKey, UpgradeMsg)>,
        expiration_period: Duration,
    ) -> Result<Self> {
        telio_log_info!("Starting Upgrade sync module");
        Ok(Self {
            task: Task::start(State {
                upgrade_request_publisher,
                intercoms,
                upgrade_requests: Default::default(),
                expiration_period,
                poll_timer: interval_at(Instant::now(), expiration_period / 2),
            }),
        })
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

#[async_trait]
impl UpgradeSyncTrait for UpgradeSync {
    async fn get_upgrade_requests(&self) -> Result<HashMap<PublicKey, UpgradeRequest>> {
        // FIXME: error handling with task_exec! seems to suck a lot. Need to fix that.
        task_exec!(&self.task, async move |s| {
            // TODO: update logic to maintain all endpoints instead of last one
            Ok(s.upgrade_requests.clone())
        })
        .await
        .map_err(|e| e.into())
    }

    async fn request_upgrade(
        &self,
        public_key: &PublicKey,
        remote_endpoint: SocketAddr, // The endpoint which will be added to local WG and points to
        // remote node
        local_endpoint: SocketAddr, // The endpoint which will be added to remote WG and points to
                                    // our local node
    ) -> Result<()> {
        let public_key = *public_key;
        task_exec!(&self.task, async move |s| {
            s.request_upgrade(&public_key, remote_endpoint, local_endpoint)
                .await
                .unwrap_or_else(|e| {
                    telio_log_warn!("Failed to send ping {:?}", e);
                });
            Ok(())
        })
        .await
        .map_err(Error::Task)
    }

    async fn remove_upgrade(&self, public_key: &PublicKey) -> Result<()> {
        // TODO: error handling with task_exec! seems to suck a lot. Need to fix that.
        let public_key = *public_key;
        task_exec!(&self.task, async move |s| {
            Ok(s.upgrade_requests.remove(&public_key))
        })
        .await
        .map_err(Error::Task)?
        .ok_or(Error::NotFound)
        .map(|_| ())
    }
}

impl State {
    async fn request_upgrade(
        &mut self,
        public_key: &PublicKey,
        remote_endpoint: SocketAddr,
        local_endpoint: SocketAddr,
    ) -> Result<()> {
        telio_log_info!(
            "Requesting {:?} to upgrade endpoint to local WG: {:?}, remote WG: {:?}",
            public_key,
            remote_endpoint,
            local_endpoint,
        );

        // Send message to remote end
        #[allow(mpsc_blocking_send)]
        self.intercoms
            .tx
            .send((
                *public_key,
                UpgradeMsg {
                    endpoint: local_endpoint,
                },
            ))
            .await
            .map_err(Error::SendUpgradeMsgErr)?;

        // Insert endpoint to local end to force our side to keep the endpoint too
        self.upgrade_requests.insert(
            *public_key,
            UpgradeRequest {
                endpoint: remote_endpoint,
                requested_at: Instant::now(),
            },
        );

        Ok(())
    }

    async fn handle_upgrade_request_msg(
        &mut self,
        public_key: &PublicKey,
        upgrade_msg: &UpgradeMsg,
    ) -> Result<()> {
        telio_log_info!(
            "{:?} has requested us to upgrade endpoint to {:?}",
            public_key,
            upgrade_msg.endpoint
        );

        let new_request = UpgradeRequest {
            endpoint: upgrade_msg.endpoint,
            requested_at: Instant::now(),
        };

        // Format upgrade request event
        let upgrade_req_event = UpgradeRequestChangeEvent {
            old_request: self.upgrade_requests.get(public_key).cloned(),
            new_request: Some(new_request.clone()),
        };

        // Store the upgrade request
        self.upgrade_requests.insert(*public_key, new_request);

        // Notify device about this upgrade request
        #[allow(mpsc_blocking_send)]
        self.upgrade_request_publisher
            .send(upgrade_req_event)
            .await
            .map_err(Error::SendUpgradeRequestChangeEventErr)?;

        Ok(())
    }

    async fn handle_tick(&mut self) -> Result<()> {
        let expiry_period = self.expiration_period;
        let is_expired = |upgrade_request: &UpgradeRequest| -> bool {
            Instant::now() - upgrade_request.requested_at > expiry_period
        };

        // Iterate over all expired events and publish change for them
        for (key, expired_request) in self.upgrade_requests.iter().filter(|(_, v)| is_expired(v)) {
            telio_log_info!(
                "Upgrade to endpoint {:?} request from {:?} expired",
                expired_request.endpoint,
                key
            );
            #[allow(mpsc_blocking_send)]
            self.upgrade_request_publisher
                .send(UpgradeRequestChangeEvent {
                    old_request: Some(expired_request.clone()),
                    new_request: None,
                })
                .await
                .map_err(Error::SendUpgradeRequestChangeEventErr)?;
        }

        // Remove all expired events from our state
        self.upgrade_requests.retain(|_, v| !is_expired(v));

        Ok(())
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "UpgradeSync";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        tokio::select! {
            Some((public_key, upgrade_msg)) = self.intercoms.rx.recv() => {
                self.handle_upgrade_request_msg(&public_key, &upgrade_msg)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("Failed to parse upgrade request: {:?}", e);
                        });
            }
            _ = self.poll_timer.tick() => {
                self.handle_tick()
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("Failed to parse upgrade request: {:?}", e);
                        });
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
    use tokio::time;

    fn setup(
        expiry: Duration,
    ) -> (
        UpgradeSync,
        chan::Rx<UpgradeRequestChangeEvent>,
        Chan<(PublicKey, UpgradeMsg)>,
    ) {
        let (intercoms_them, intercoms_us) = Chan::pipe();
        let Chan {
            tx: upg_rq_tx,
            rx: upg_rq_rx,
        } = Chan::default();

        let upg_sync = UpgradeSync::new(upg_rq_tx, intercoms_us, expiry).unwrap();

        (upg_sync, upg_rq_rx, intercoms_them)
    }

    #[ignore]
    #[tokio::test]
    async fn handle_request_expiration() {
        const EXPIRY: Duration = Duration::from_millis(100);

        let (upg_sync, mut upg_rq_rx, mut intercoms_them) = setup(EXPIRY);

        let upg_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
        };

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        intercoms_them.tx.send((pk, upg_msg.clone())).await.unwrap();

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(Duration::from_secs(1));
            tokio::pin!(timeout);

            let mut start = None;
            let mut expecting_old_rq = false;

            loop {
                tokio::select! {
                    _ = intercoms_them.rx.recv() => {
                        assert!(false, "Should not rx here");
                    }
                    Some(upg_rq) = upg_rq_rx.recv() => {
                        if !expecting_old_rq {
                            assert!(upg_rq.old_request.is_none());
                            assert_eq!(upg_rq.new_request.unwrap().endpoint, upg_msg.endpoint);
                            expecting_old_rq = true;
                            start = Some(Instant::now());
                            continue;
                        } else {
                            assert!(upg_rq.new_request.is_none());
                            assert_eq!(upg_rq.old_request.unwrap().endpoint, upg_msg.endpoint);
                            let elapsed_time = start.unwrap().elapsed();
                            assert!(elapsed_time >= EXPIRY, "Elapsed time: {:?} EXPIRY: {:?}", elapsed_time, EXPIRY);
                            break;
                        }
                    }
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = upg_sync.stop().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handle_request_and_removal() {
        const EXPIRY: Duration = Duration::from_millis(100);
        let (upg_sync, mut upg_rq_rx, mut intercoms_them) = setup(EXPIRY);

        let upg_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
        };

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        intercoms_them
            .tx
            .send((pk.clone(), upg_msg.clone()))
            .await
            .unwrap();

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(Duration::from_secs(1));
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    _ = intercoms_them.rx.recv() => {
                        assert!(false, "Should not rx here");
                    }
                    Some(upg_rq) = upg_rq_rx.recv() => {
                        assert!(upg_rq.old_request.is_none());
                        assert_eq!(upg_rq.new_request.unwrap().endpoint, upg_msg.endpoint);

                        time::sleep(EXPIRY / 2).await;

                        let _ = upg_sync.remove_upgrade(&pk).await;
                        assert!(upg_sync.get_upgrade_requests().await.unwrap().is_empty());
                        break;
                    }
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = upg_sync.stop().await;
        })
        .await
        .unwrap();
    }
}
