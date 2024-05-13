use async_trait::async_trait;
use futures::Future;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::SocketAddr;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use telio_crypto::{smaller_key_in_meshnet_canonical_order, PublicKey};
use telio_model::features::EndpointProvider;
use telio_nurse::aggregator::ConnectivityDataAggregator;
use telio_proto::{Decision, Session, UpgradeDecisionMsg, UpgradeMsg};
use telio_task::{io::chan, io::Chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{interval, telio_log_debug, telio_log_info, telio_log_warn, LruCache};
use telio_wg::uapi::{AnalyticsEvent, PeerState};
use telio_wg::WireGuard;
use tokio::{
    sync::mpsc::error::SendError,
    time::{Instant, Interval},
};

use crate::cross_ping_check::UpgradeController;

const MAX_PENDING_SESSIONS: usize = 512;

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
    Rejected(telio_proto::Decision),
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

/// Used to indicate if the inner value was received from the other peer, or
/// sent to it.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum Direction<T: Debug + PartialEq + Eq + Hash + Clone + Copy> {
    Sent(T),
    Received(T),
}

impl<T: Debug + PartialEq + Eq + Hash + Clone + Copy> Direction<T> {
    fn into(self) -> T {
        match self {
            Direction::Sent(t) => t,
            Direction::Received(t) => t,
        }
    }
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
        remote_endpoint: (SocketAddr, EndpointProvider),
        local_direct_endpoint: (SocketAddr, EndpointProvider),
        session: Session,
    ) -> Result<bool>;
}

pub struct UpgradeSync {
    task: Task<State>,
}

struct PendingSessionData {
    local_ep: EndpointProvider,
    remote_ep: EndpointProvider,
}

pub struct State {
    upgrade_request_publisher: chan::Tx<UpgradeRequestChangeEvent>,
    upgrade_intercoms: Chan<(PublicKey, UpgradeMsg)>,
    upgrade_requests: HashMap<Direction<PublicKey>, UpgradeRequest>,
    expiration_period: Duration,
    upgrade_controller: Arc<dyn UpgradeController>,
    poll_timer: Interval,
    upgrade_decision_intercoms: Chan<(PublicKey, UpgradeDecisionMsg)>,
    // Collection of not yet confirmed Upgrade requests
    pending_direct_sessions: LruCache<Session, PendingSessionData>,
    our_public_key: PublicKey,
    connectivity_data_aggregator: Arc<ConnectivityDataAggregator>,
    wireguard: Arc<dyn WireGuard>,
}

impl UpgradeSync {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upgrade_request_publisher: chan::Tx<UpgradeRequestChangeEvent>,
        upgrade_intercoms: Chan<(PublicKey, UpgradeMsg)>,
        expiration_period: Duration,
        upgrade_verifier: Arc<dyn UpgradeController>,
        upgrade_decision_intercoms: Chan<(PublicKey, UpgradeDecisionMsg)>,
        our_public_key: PublicKey,
        connectivity_data_aggregator: Arc<ConnectivityDataAggregator>,
        wireguard: Arc<dyn WireGuard>,
    ) -> Result<Self> {
        telio_log_info!("Starting Upgrade sync module");
        let poll_timer = interval(expiration_period / 2);
        Ok(Self {
            task: Task::start(State {
                upgrade_request_publisher,
                upgrade_intercoms,
                upgrade_requests: Default::default(),
                expiration_period,
                upgrade_controller: upgrade_verifier,
                poll_timer,
                upgrade_decision_intercoms,
                pending_direct_sessions: LruCache::new(
                    Duration::from_secs(15),
                    MAX_PENDING_SESSIONS,
                ),
                our_public_key,
                connectivity_data_aggregator,
                wireguard,
            }),
        })
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    pub async fn set_public_key(&self, public_key: PublicKey) -> Result<()> {
        task_exec!(&self.task, async move |s| {
            s.set_public_key(public_key);
            Ok(())
        })
        .await
        .map_err(|e| e.into())
    }
}

#[async_trait]
impl UpgradeSyncTrait for UpgradeSync {
    async fn get_upgrade_requests(&self) -> Result<HashMap<PublicKey, UpgradeRequest>> {
        // FIXME: error handling with task_exec! seems to suck a lot. Need to fix that.
        task_exec!(&self.task, async move |s| {
            Ok(s.upgrade_requests
                .iter()
                .map(|(pk, req)| ((*pk).into(), req.clone()))
                .collect())
        })
        .await
        .map_err(|e| e.into())
    }

    async fn request_upgrade(
        &self,
        public_key: &PublicKey,
        remote_endpoint: (SocketAddr, EndpointProvider), // The endpoint which will be added to local WG and points to
        // remote node
        local_direct_endpoint: (SocketAddr, EndpointProvider), // The endpoint which will be added to remote WG and points to
        // our local node with associated session
        session: Session,
    ) -> Result<bool> {
        let public_key = *public_key;
        task_exec!(&self.task, async move |s| {
            Ok(
                s.request_upgrade(&public_key, remote_endpoint, local_direct_endpoint, session)
                    .await
                    .unwrap_or_default(),
            )
        })
        .await
        .map_err(Error::Task)
    }
}

impl State {
    async fn request_upgrade(
        &mut self,
        public_key: &PublicKey,
        remote_endpoint: (SocketAddr, EndpointProvider),
        local_direct_endpoint: (SocketAddr, EndpointProvider),
        session: Session,
    ) -> Result<bool> {
        telio_log_info!(
            "Requesting {:?} to upgrade endpoint to local WG: {:?}, remote WG: {:?}, for session: {}",
            public_key,
            remote_endpoint,
            local_direct_endpoint,
            session,
        );

        if let Some(upgrade_request) = self.upgrade_requests.get(&Direction::Received(*public_key))
        {
            if !Self::is_expired(self.expiration_period, upgrade_request) {
                // We have just accepted an upgrade request from that peer, so
                // there is no point sending in our own request for upgrade. If
                // we send it now, we can cause other side to accept if they have
                // a losing key.
                telio_log_debug!("Upgrade request accepted recently from {public_key:?}, will not send an upgrade request to it now");
                return Ok(false);
            }
        }

        // Send message to remote end
        #[allow(mpsc_blocking_send)]
        self.upgrade_intercoms
            .tx
            .send((
                *public_key,
                UpgradeMsg {
                    endpoint: local_direct_endpoint.0,
                    endpoint_type: local_direct_endpoint.1,
                    receiver_endpoint_type: remote_endpoint.1,
                    session,
                },
            ))
            .await
            .map_err(Error::SendUpgradeMsgErr)?;

        // Insert endpoint to local end to force our side to keep the endpoint too

        let val = UpgradeRequest {
            endpoint: remote_endpoint.0,
            requested_at: Instant::now(),
            session,
        };
        self.upgrade_requests
            .insert(Direction::Sent(*public_key), val);
        self.pending_direct_sessions.insert(
            session,
            PendingSessionData {
                local_ep: local_direct_endpoint.1,
                remote_ep: remote_endpoint.1,
            },
        );

        Ok(true)
    }

    async fn handle_upgrade_request_msg(
        &mut self,
        public_key: &PublicKey,
        upgrade_msg: &UpgradeMsg,
    ) -> Result<()> {
        telio_log_info!(
            "{:?} has requested us to upgrade endpoint to {:?} ({:?} - {:?}) for session {}",
            public_key,
            upgrade_msg.endpoint,
            upgrade_msg.endpoint_type,
            upgrade_msg.receiver_endpoint_type,
            upgrade_msg.session,
        );

        match self
            .upgrade_controller
            .check_if_upgrade_is_allowed(upgrade_msg.session, *public_key)
            .await
        {
            Ok(true) => {
                let decision = match self.upgrade_requests.get(&Direction::Sent(*public_key)) {
                    Some(v) => {
                        if Self::is_expired(self.expiration_period, v) {
                            telio_proto::Decision::Accepted
                        } else if &self.our_public_key
                            == smaller_key_in_meshnet_canonical_order(
                                &self.our_public_key,
                                public_key,
                            )
                        {
                            // We reject this request, because we sent our own which is not
                            // yet expired and our key is winning - the other side should accept
                            // our request instead.
                            telio_proto::Decision::RejectedDueToConcurrentUpgrade
                        } else {
                            telio_proto::Decision::Accepted
                        }
                    }
                    None => telio_proto::Decision::Accepted,
                };

                telio_log_debug!(
                    "Sending upgrade decision: {decision:?} ({} {})",
                    upgrade_msg.endpoint,
                    upgrade_msg.session
                );

                #[allow(mpsc_blocking_send)]
                self.upgrade_decision_intercoms
                    .tx
                    .send((
                        *public_key,
                        UpgradeDecisionMsg {
                            decision,
                            session: upgrade_msg.session,
                        },
                    ))
                    .await
                    .map_err(Error::SendUpgradeDecisionMsgErr)?;

                if decision != telio_proto::Decision::Accepted {
                    return Err(Error::Rejected(decision));
                }

                if let Some(event) = self.make_nat_event(*public_key).await {
                    let local_ep = upgrade_msg.receiver_endpoint_type;
                    let remote_ep = upgrade_msg.endpoint_type;
                    self.connectivity_data_aggregator
                        .change_peer_state_direct(&event, local_ep, remote_ep)
                        .await;
                }
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
                let decision = telio_proto::Decision::RejectedDueToUnknownSession;
                self.upgrade_decision_intercoms
                    .tx
                    .send((
                        *public_key,
                        UpgradeDecisionMsg {
                            decision,
                            session: upgrade_msg.session,
                        },
                    ))
                    .await
                    .map_err(Error::SendUpgradeDecisionMsgErr)?;
                return Err(Error::Rejected(decision));
            }
            Err(e) => {
                telio_log_warn!(
                    "Upgrade request from {public_key} for session {} rejected: {e}",
                    upgrade_msg.session
                );
                let decision = telio_proto::Decision::RejectedDueToUnknownSession;

                #[allow(mpsc_blocking_send)]
                self.upgrade_decision_intercoms
                    .tx
                    .send((
                        *public_key,
                        UpgradeDecisionMsg {
                            decision,
                            session: upgrade_msg.session,
                        },
                    ))
                    .await
                    .map_err(Error::SendUpgradeDecisionMsgErr)?;
                return Err(Error::Rejected(decision));
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
        self.upgrade_requests
            .insert(Direction::Received(*public_key), new_request);

        // Notify device about this upgrade request
        #[allow(mpsc_blocking_send)]
        self.upgrade_request_publisher
            .send(upgrade_req_event)
            .await
            .map_err(Error::SendUpgradeRequestChangeEventErr)?;

        Ok(())
    }

    async fn handle_tick(&mut self) -> Result<()> {
        // Iterate over all expired events and publish change for them
        for (key, expired_request) in self
            .upgrade_requests
            .iter()
            .filter(|(_, v)| Self::is_expired(self.expiration_period, v))
        {
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
        let expiration_period = self.expiration_period;
        self.upgrade_requests
            .retain(|_, v| !Self::is_expired(expiration_period, v));

        Ok(())
    }

    async fn make_nat_event(&self, public_key: PublicKey) -> Option<AnalyticsEvent> {
        if let Some(peer) = self
            .wireguard
            .get_interface()
            .await
            .ok()
            .and_then(|w| w.peers.get(&public_key).cloned())
        {
            Some(AnalyticsEvent {
                public_key,
                dual_ip_addresses: peer.get_dual_ip_addresses(),
                tx_bytes: peer.rx_bytes.unwrap_or_default(),
                rx_bytes: peer.tx_bytes.unwrap_or_default(),
                peer_state: PeerState::Connected,
                timestamp: Instant::now().into_std(),
            })
        } else {
            None
        }
    }

    pub fn set_public_key(&mut self, public_key: PublicKey) {
        self.our_public_key = public_key;
    }

    fn is_expired(expiration_period: Duration, upgrade_request: &UpgradeRequest) -> bool {
        Instant::now() - upgrade_request.requested_at > expiration_period
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
                            telio_log_warn!("Failed to process upgrade request: {:?}", e);
                        });
            }
            Some((public_key, msg)) = self.upgrade_decision_intercoms.rx.recv() => {
                telio_log_debug!("Upgrade decision received: {msg:?}");
                match msg.decision {
                    Decision::Accepted => {
                        if let Some(data) = self.pending_direct_sessions.remove(&msg.session) {
                            if let Some(event) = self.make_nat_event(public_key).await {
                                self.connectivity_data_aggregator.
                                    change_peer_state_direct(&event, data.local_ep, data.remote_ep).await;
                            } else {
                                telio_log_warn!("Received upgrade decision from peer {public_key:?} to which we didn't send a request: {msg:?}");
                            }
                        } else {
                            telio_log_warn!("Received upgrade decision from {public_key:?} for unknow session: {msg:?}");
                        }

                    },
                    Decision::RejectedDueToUnknownSession => {
                        if let Some(pk) = self.upgrade_requests.iter().find(|(_, req)| req.session == msg.session).map(|(pk,_)| *pk) {
                            let _ = self.upgrade_controller.notify_failed_wg_connection(pk.into()).await;
                        }
                    }
                    Decision::RejectedDueToConcurrentUpgrade => {
                        self.upgrade_requests.retain(|pk, req| !(pk == &Direction::Sent(public_key) && req.session == msg.session));
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
    use std::{collections::BTreeMap, sync::Arc};

    use super::*;
    use telio_crypto::SecretKey;
    use telio_nurse::config::AggregatorConfig;
    use telio_proto::Decision;
    use telio_wg::{uapi::Interface, MockWireGuard};
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
        wg: Arc<dyn WireGuard>,
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

        let our_public_key = SecretKey::gen().public();

        let upg_sync = UpgradeSync::new(
            upg_rq_tx,
            intercoms_us,
            expiry,
            upgrade_verifier,
            upg_decision_us,
            our_public_key,
            Arc::new(ConnectivityDataAggregator::new(
                AggregatorConfig::default(),
                wg.clone(),
                our_public_key,
            )),
            wg,
        )
        .unwrap();

        (upg_sync, upg_rq_rx, intercoms_them, upg_decision_them)
    }

    #[ignore]
    #[tokio::test]
    async fn handle_request_expiration() {
        const EXPIRY: Duration = Duration::from_millis(100);

        let wg = Arc::new(MockWireGuard::new());

        let (upg_sync, mut upg_rq_rx, mut intercoms_them, _) =
            setup(EXPIRY, Arc::new(KnowsAllSessions::new()), wg);

        let upg_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
            session: 42,
            endpoint_type: telio_model::features::EndpointProvider::Local,
            receiver_endpoint_type: telio_model::features::EndpointProvider::Local,
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
        let mut wg = MockWireGuard::new();
        wg.expect_get_interface().returning(|| {
            Ok(Interface {
                private_key: None,
                listen_port: None,
                proxy_listen_port: None,
                fwmark: 42,
                peers: BTreeMap::default(),
            })
        });
        let (upg_sync, mut upg_rq_rx, mut intercoms_them, mut upgrade_decision_them) =
            setup(EXPIRY, Arc::new(KnowsAllSessions::new()), Arc::new(wg));

        let upg_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
            session: 42,
            endpoint_type: telio_model::features::EndpointProvider::Stun,
            receiver_endpoint_type: telio_model::features::EndpointProvider::Stun,
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
                    msg = intercoms_them.rx.recv() => {
                        assert!(false, "Should not rx here, msg: {:?}", msg);
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
        let wg = Arc::new(MockWireGuard::new());
        let (upg_sync, _upg_rq_rx, _intercoms_them, upgrade_decision_them) =
            setup(EXPIRY, upgrade_controller.clone(), wg);

        let public_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();
        let endpoint: (SocketAddr, EndpointProvider) = (
            "127.0.0.1:6666".parse().unwrap(),
            telio_model::features::EndpointProvider::Upnp,
        );
        let session: Session = 42;

        upg_sync
            .request_upgrade(&public_key, endpoint, endpoint, session)
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
    async fn handle_upgrade_rejection_due_to_concurrent_upgrade() {
        const EXPIRY: Duration = Duration::from_millis(100);
        let upgrade_controller = Arc::new(KnowsAllSessions::new());
        let wg = Arc::new(MockWireGuard::new());
        let (upg_sync, _upg_rq_rx, _intercoms_them, upgrade_decision_them) =
            setup(EXPIRY, upgrade_controller.clone(), wg);

        let public_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();
        let endpoint: (SocketAddr, EndpointProvider) = (
            "127.0.0.1:6666".parse().unwrap(),
            telio_model::features::EndpointProvider::Upnp,
        );
        let session: Session = 42;

        upg_sync
            .request_upgrade(&public_key, endpoint, endpoint, session)
            .await
            .unwrap();

        upgrade_decision_them
            .tx
            .send((
                public_key,
                UpgradeDecisionMsg {
                    decision: Decision::RejectedDueToConcurrentUpgrade,
                    session,
                },
            ))
            .await
            .unwrap();

        wait_for(Duration::from_secs(15), || async {
            upg_sync.get_upgrade_requests().await.unwrap().is_empty()
        })
        .await;
    }

    async fn wait_for<Fut>(timeout: Duration, pred: impl Fn() -> Fut)
    where
        Fut: Future<Output = bool>,
    {
        let start = Instant::now();
        loop {
            if pred().await {
                break;
            }
            if start.elapsed() > timeout {
                panic!("Failed to reach desired state after {:?}", timeout);
            }
        }
    }

    #[tokio::test]
    async fn unknown_requests_are_rejected() {
        const EXPIRY: Duration = Duration::from_millis(100);
        let wg = Arc::new(MockWireGuard::new());
        let (_upg_sync, mut _upg_rq_rx, intercoms_them, mut upgrade_decision_them) =
            setup(EXPIRY, Arc::new(KnowsNoSessions), wg);
        let public_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();
        let upgrade_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
            session: 42,
            endpoint_type: telio_model::features::EndpointProvider::Stun,
            receiver_endpoint_type: telio_model::features::EndpointProvider::Stun,
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

    #[tokio::test]
    async fn handle_request_during_an_ongoing_upgrade() {
        const EXPIRY: Duration = Duration::from_millis(100);
        let mut wg = MockWireGuard::new();
        wg.expect_get_interface().returning(|| {
            Ok(Interface {
                private_key: None,
                listen_port: None,
                proxy_listen_port: None,
                fwmark: 42,
                peers: BTreeMap::default(),
            })
        });
        let (upg_sync, mut upg_rq_rx, mut intercoms_them, mut upgrade_decision_them) =
            setup(EXPIRY, Arc::new(KnowsAllSessions::new()), Arc::new(wg));

        let upg_msg = UpgradeMsg {
            endpoint: "127.0.0.1:6666".parse().unwrap(),
            session: 42,
            endpoint_type: telio_model::features::EndpointProvider::Stun,
            receiver_endpoint_type: telio_model::features::EndpointProvider::Stun,
        };

        let pk = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();

        intercoms_them
            .tx
            .send((pk.clone(), upg_msg.clone()))
            .await
            .unwrap();

        wait_for(Duration::from_secs(15), || async {
            !upg_sync.get_upgrade_requests().await.unwrap().is_empty()
        })
        .await;

        let public_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap();
        let endpoint: (SocketAddr, EndpointProvider) = (
            "127.0.0.1:6666".parse().unwrap(),
            telio_model::features::EndpointProvider::Upnp,
        );
        let session: Session = 42;
        assert!(!upg_sync
            .request_upgrade(&public_key, endpoint, endpoint, session)
            .await
            .unwrap());
    }
}
