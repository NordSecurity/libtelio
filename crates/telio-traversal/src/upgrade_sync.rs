use async_trait::async_trait;
use futures::Future;
use std::net::SocketAddr;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use telio_crypto::PublicKey;
use telio_proto::{Decision, Session, UpgradeDecisionMsg, UpgradeMsg};
use telio_task::{io::chan, io::Chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};
use tokio::{
    sync::mpsc::error::SendError,
    time::{interval_at, Instant, Interval, MissedTickBehavior},
};

use crate::cross_ping_check::UpgradeController;

/// Possible [UpgradeSync] errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Channel error
    #[error(transparent)]
    SendUpgradeMsgErr(#[from] SendError<(PublicKey, UpgradeMsg)>),
    #[error(transparent)]
    SendUpgradeDecisionMsgErr(#[from] SendError<(PublicKey, UpgradeDecisionMsg)>),
    /// Channel error
    #[error(transparent)]
    SendUpgradeRequestChangeEventErr(#[from] SendError<UpgradeRequestChangeEvent>),
    /// Task encountered an error while running
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
    #[error("Upgrade request rejected")]
    Rejected,
    #[error("Upgrade request not found or expired")]
    NotFound,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UpgradeRequest {
    pub endpoint: SocketAddr,
    pub requested_at: Instant,
    pub session: Session,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UpgradeRequestChangeEvent {}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait UpgradeSyncTrait {
    async fn get_upgrade_requests(&self) -> Result<HashMap<PublicKey, UpgradeRequest>>;
    async fn request_upgrade(
        &self,
        public_key: &PublicKey,
        remote_endpoint: SocketAddr,
        local_direct_endpoint: (SocketAddr, Session),
    ) -> Result<()>;
}

pub struct UpgradeSync {
    task: Task<State>,
}

pub struct State {
    upgrade_request_publisher: chan::Tx<UpgradeRequestChangeEvent>,
    upgrade_intercoms: Chan<(PublicKey, UpgradeMsg)>,
    upgrade_requests: HashMap<PublicKey, UpgradeRequest>,
    expiration_period: Duration,
    upgrade_controller: Arc<dyn UpgradeController>,
    poll_timer: Interval,
    upgrade_decision_intercoms: Chan<(PublicKey, UpgradeDecisionMsg)>,
}

impl UpgradeSync {
    pub fn new(
        upgrade_request_publisher: chan::Tx<UpgradeRequestChangeEvent>,
        upgrade_intercoms: Chan<(PublicKey, UpgradeMsg)>,
        expiration_period: Duration,
        upgrade_verifier: Arc<dyn UpgradeController>,
        upgrade_decision_intercoms: Chan<(PublicKey, UpgradeDecisionMsg)>,
    ) -> Result<Self> {
        telio_log_info!("Starting Upgrade sync module");
        let mut poll_timer = interval_at(Instant::now(), expiration_period / 2);
        poll_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Ok(Self {
            task: Task::start(State {
                upgrade_request_publisher,
                upgrade_intercoms,
                upgrade_requests: Default::default(),
                expiration_period,
                upgrade_controller: upgrade_verifier,
                poll_timer,
                upgrade_decision_intercoms,
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
        local_direct_endpoint: (SocketAddr, Session), // The endpoint which will be added to remote WG and points to
                                                      // our local node with associated session
    ) -> Result<()> {
        let public_key = *public_key;
        task_exec!(&self.task, async move |s| {
            s.request_upgrade(&public_key, remote_endpoint, local_direct_endpoint)
                .await
                .unwrap_or_else(|e| {
                    telio_log_warn!("Failed to send ping {:?}", e);
                });
            Ok(())
        })
        .await
        .map_err(Error::Task)
    }
}

impl State {
    async fn request_upgrade(
        &mut self,
        public_key: &PublicKey,
        remote_endpoint: SocketAddr,
        local_direct_endpoint: (SocketAddr, Session),
    ) -> Result<()> {
        telio_log_info!(
            "Requesting {:?} to upgrade endpoint to local WG: {:?}, remote WG: {:?}, for session: {}",
            public_key,
            remote_endpoint,
            local_direct_endpoint.0,
            local_direct_endpoint.1,
        );

        // Send message to remote end
        #[allow(mpsc_blocking_send)]
        self.upgrade_intercoms
            .tx
            .send((
                *public_key,
                UpgradeMsg {
                    endpoint: local_direct_endpoint.0,
                    session: local_direct_endpoint.1,
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
                session: local_direct_endpoint.1,
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
            "{:?} has requested us to upgrade endpoint to {:?} for session {}",
            public_key,
            upgrade_msg.endpoint,
            upgrade_msg.session,
        );

        match self
            .upgrade_controller
            .check_if_upgrade_is_allowed(upgrade_msg.session, *public_key)
            .await
        {
            Ok(true) => {
                // TODO: in LLT-4858 check if we have already sent our own upgrade request
                // and if so compare keys to decide who should win

                telio_log_debug!("sending upgrade decision: Accepted");

                #[allow(mpsc_blocking_send)]
                self.upgrade_decision_intercoms
                    .tx
                    .send((
                        *public_key,
                        UpgradeDecisionMsg {
                            decision: telio_proto::Decision::Accepted,
                            session: upgrade_msg.session,
                        },
                    ))
                    .await
                    .map_err(Error::SendUpgradeDecisionMsgErr)?;
            }
            Ok(false) => {
                // We might have restarted in the middle of upgrade procedure and have
                // lost the state needed to verify the incoming request. Not a big deal,
                // upgrade procedure will be restarted shortly either way.
                telio_log_warn!(
                    "Upgrade request from {public_key} for unknown session {} rejected",
                    upgrade_msg.session
                );

                #[allow(mpsc_blocking_send)]
                self.upgrade_decision_intercoms
                    .tx
                    .send((
                        *public_key,
                        UpgradeDecisionMsg {
                            decision: telio_proto::Decision::RejectedDueToUnknownSession,
                            session: upgrade_msg.session,
                        },
                    ))
                    .await
                    .map_err(Error::SendUpgradeDecisionMsgErr)?;
                return Err(Error::Rejected);
            }
            Err(e) => {
                telio_log_warn!(
                    "Upgrade request from {public_key} for session {} rejected: {e}",
                    upgrade_msg.session
                );

                #[allow(mpsc_blocking_send)]
                self.upgrade_decision_intercoms
                    .tx
                    .send((
                        *public_key,
                        UpgradeDecisionMsg {
                            decision: telio_proto::Decision::RejectedDueToUnknownSession,
                            session: upgrade_msg.session,
                        },
                    ))
                    .await
                    .map_err(Error::SendUpgradeDecisionMsgErr)?;
                return Err(Error::Rejected);
            }
        }

        let new_request = UpgradeRequest {
            endpoint: upgrade_msg.endpoint,
            session: upgrade_msg.session,
            requested_at: Instant::now(),
        };

        // Format upgrade request event
        let upgrade_req_event = UpgradeRequestChangeEvent {};

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
                .send(UpgradeRequestChangeEvent {})
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
            Some((public_key, upgrade_msg)) = self.upgrade_intercoms.rx.recv() => {
                self.handle_upgrade_request_msg(&public_key, &upgrade_msg)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("Failed to parse upgrade request: {:?}", e);
                        });
            }
            Some((_pk, msg)) = self.upgrade_decision_intercoms.rx.recv() => {
                telio_log_debug!("Upgrade decision received: {msg:?}");
                match msg.decision {
                    Decision::Accepted => {},
                    Decision::RejectedDueToUnknownSession => {
                        if let Some(pk) = self.upgrade_requests.iter().find(|(_, req)| req.session == msg.session).map(|(pk,_)| *pk) {
                            let _ = self.upgrade_controller.notify_failed_wg_connection(pk).await;
                        }
                    }
                    Decision::RejectedDueToConcurrentUpgrade => {
                        // TODO: in LLT-4858
                    }
                }
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
    use std::sync::Arc;

    use super::*;
    use telio_proto::Decision;
    use tokio::{
        sync::{
            mpsc::{channel, Receiver, Sender},
            Mutex,
        },
        time,
    };

    struct KnowsAllSessions {
        notifications_sender: Sender<PublicKey>,
        notifications_receiver: Mutex<Receiver<PublicKey>>,
    }

    impl KnowsAllSessions {
        fn new() -> Self {
            let (sender, receiver) = channel(1);
            Self {
                notifications_sender: sender,
                notifications_receiver: Mutex::new(receiver),
            }
        }
    }

    #[async_trait]
    impl UpgradeController for KnowsAllSessions {
        async fn check_if_upgrade_is_allowed(
            &self,
            _session: Session,
            _public_key: PublicKey,
        ) -> std::result::Result<bool, crate::connectivity_check::Error> {
            Ok(true)
        }

        async fn notify_failed_wg_connection(
            &self,
            public_key: PublicKey,
        ) -> std::result::Result<(), crate::connectivity_check::Error> {
            self.notifications_sender.send(public_key).await.unwrap();
            Ok(())
        }
    }

    struct KnowsNoSessions;

    #[async_trait]
    impl UpgradeController for KnowsNoSessions {
        async fn check_if_upgrade_is_allowed(
            &self,
            _session: Session,
            _public_key: PublicKey,
        ) -> std::result::Result<bool, crate::connectivity_check::Error> {
            Ok(false)
        }

        async fn notify_failed_wg_connection(
            &self,
            _public_key: PublicKey,
        ) -> std::result::Result<(), crate::connectivity_check::Error> {
            Ok(())
        }
    }

    fn setup(
        expiry: Duration,
        upgrade_verifier: Arc<dyn UpgradeController>,
    ) -> (
        UpgradeSync,
        chan::Rx<UpgradeRequestChangeEvent>,
        Chan<(PublicKey, UpgradeMsg)>,
        Chan<(PublicKey, UpgradeDecisionMsg)>,
    ) {
        let (intercoms_them, intercoms_us) = Chan::pipe();
        let Chan {
            tx: upg_rq_tx,
            rx: upg_rq_rx,
        } = Chan::default();
        let (upg_decision_them, upg_decision_us) = Chan::pipe();

        let upg_sync = UpgradeSync::new(
            upg_rq_tx,
            intercoms_us,
            expiry,
            upgrade_verifier,
            upg_decision_us,
        )
        .unwrap();

        (upg_sync, upg_rq_rx, intercoms_them, upg_decision_them)
    }

    #[ignore]
    #[tokio::test]
    async fn handle_request_expiration() {
        const EXPIRY: Duration = Duration::from_millis(100);

        let (upg_sync, mut upg_rq_rx, mut intercoms_them, _) =
            setup(EXPIRY, Arc::new(KnowsAllSessions::new()));

        let upg_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
            session: 42,
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
                    Some(_upg_rq) = upg_rq_rx.recv() => {
                        if !expecting_old_rq {
                            expecting_old_rq = true;
                            start = Some(Instant::now());
                            continue;
                        } else {
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
        let (upg_sync, mut upg_rq_rx, mut intercoms_them, mut upgrade_decision_them) =
            setup(EXPIRY, Arc::new(KnowsAllSessions::new()));

        let upg_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
            session: 42,
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
                    _msg = intercoms_them.rx.recv() => {
                        assert!(false, "Should not rx here");
                    }
                    Some(_upg_rq) = upg_rq_rx.recv() => {
                        break;
                    }
                    Some(decision_msg) = upgrade_decision_them.rx.recv() => {
                        assert_eq!(decision_msg.0, pk);
                        assert_eq!(decision_msg.1.decision, telio_proto::Decision::Accepted);
                        continue;
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
    async fn handle_upgrade_rejection_due_to_unknown_session() {
        const EXPIRY: Duration = Duration::from_millis(100);
        let upgrade_controller = Arc::new(KnowsAllSessions::new());
        let (upg_sync, _upg_rq_rx, _intercoms_them, upgrade_decision_them) =
            setup(EXPIRY, upgrade_controller.clone());

        let public_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();
        let endpoint = "127.0.0.1:6666".parse().unwrap();
        let session: Session = 42;

        upg_sync
            .request_upgrade(&public_key, endpoint, (endpoint, session))
            .await
            .unwrap();

        upgrade_decision_them
            .tx
            .send((
                public_key,
                UpgradeDecisionMsg {
                    decision: Decision::RejectedDueToUnknownSession,
                    session,
                },
            ))
            .await
            .unwrap();

        assert_eq!(
            public_key,
            upgrade_controller
                .notifications_receiver
                .lock()
                .await
                .recv()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn unknown_requests_are_rejected() {
        const EXPIRY: Duration = Duration::from_millis(100);
        let (_upg_sync, mut _upg_rq_rx, intercoms_them, mut upgrade_decision_them) =
            setup(EXPIRY, Arc::new(KnowsNoSessions));
        let public_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();
        let upgrade_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
            session: 42,
        };

        intercoms_them
            .tx
            .send((public_key, upgrade_msg))
            .await
            .unwrap();

        assert_eq!(
            upgrade_decision_them.rx.recv().await.unwrap().1.decision,
            Decision::RejectedDueToUnknownSession
        );
    }
}
