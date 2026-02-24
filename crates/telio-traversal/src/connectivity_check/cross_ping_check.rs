use super::{Error, WireGuardEndpointCandidateChangeEvent};
use crate::{
    do_state_transition,
    endpoint_providers::{
        EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, EndpointProviderType,
        Error as EndPointError, PongEvent,
    },
    endpoint_state::{EndpointState, EndpointStateMachine, Event},
    last_rx_time_provider::{is_peer_alive, TimeSinceLastRxProvider},
    ping_pong_handler::PingPongHandler,
};
use async_trait::async_trait;
use enum_map::EnumMap;
use futures::Future;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    fmt::Formatter,
};
use telio_crypto::PublicKey;
use telio_model::{config::Config, features::EndpointProvider as ApiEndpointProvider, SocketAddr};
use telio_proto::{CallMeMaybeMsg, CallMeMaybeType, Session};
use telio_task::{io::chan, io::Chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    exponential_backoff::{Backoff, ExponentialBackoff, ExponentialBackoffBounds},
    interval, telio_log_debug, telio_log_info, telio_log_trace, telio_log_warn, Instant, LruCache,
};
use tokio::sync::Mutex;
use tokio::time::Interval;

const CPC_TIMEOUT: Duration = Duration::from_secs(10);
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SESSION_CANDIDATES: usize = 512;

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait UpgradeController: Send + Sync {
    async fn check_if_upgrade_is_allowed(
        &self,
        session: Session,
        public_key: PublicKey,
    ) -> Result<bool, Error>;
    async fn notify_failed_wg_connection(&self, public_key: PublicKey) -> Result<(), Error>;
}

#[async_trait]
pub trait CrossPingCheckTrait: UpgradeController {
    async fn configure(&self, config: Option<Config>) -> Result<(), Error>;
    async fn get_validated_endpoints(
        &self,
    ) -> Result<HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent>, Error>;
    async fn notify_successfull_wg_connection_upgrade(
        &self,
        public_key: PublicKey,
    ) -> Result<(), Error>;
}

#[cfg(any(test, feature = "mockall"))]
mockall::mock! {
    pub CrossPingCheckTrait {}

    #[async_trait]
    impl CrossPingCheckTrait for CrossPingCheckTrait {
        async fn configure(&self, config: Option<Config>) -> Result<(), Error>;
        async fn get_validated_endpoints(
            &self,
        ) -> Result<HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent>, Error>;
        async fn notify_successfull_wg_connection_upgrade(
            &self,
            public_key: PublicKey,
        ) -> Result<(), Error>;
    }

    #[async_trait]
    impl UpgradeController for CrossPingCheckTrait {
        async fn check_if_upgrade_is_allowed(
            &self,
            session: Session,
            public_key: PublicKey,
        ) -> Result<bool, Error>;
        async fn notify_failed_wg_connection(&self, public_key: PublicKey) -> Result<(), Error>;
    }
}

pub struct CrossPingCheck<E: Backoff = ExponentialBackoff> {
    task: Task<State<E>>,
}

pub struct Io {
    /// Endpoint provider event subscribers
    ///
    /// All of the endpoint providers will publish endpoint changes, these channels receives those
    /// endpoint changes
    pub endpoint_change_subscriber: chan::Rx<EndpointCandidatesChangeEvent>,
    pub pong_rx_subscriber: chan::Rx<PongEvent>,

    /// A publisher for new validated WireGuard endpoints
    ///
    /// In case connectivity check passes succesffuly for specific local endpoint, this channel is
    /// used to publish the corresponding endpoint (note that not the testing endpoint is
    /// published, but rather the WG one) to any subscribers listening. In telio case this is
    /// generally monitored_state within the src/device/mod.rs Runtime.
    pub wg_endpoint_publisher: chan::Tx<WireGuardEndpointCandidateChangeEvent>,

    /// intercoms (over DERP) communication channel
    ///
    /// EndpointConnectivityCheck instance is in communication with instances on other nodes, for
    /// that we are using all of the relay/multiplexer etc. modules which provides with a nicely
    /// packet Pipes for sending messages to each other. Therefore this stores the instance of
    /// those channels
    pub intercoms: Chan<(PublicKey, CallMeMaybeMsg)>,
}

type ExponentialBackoffProvider<E> = Box<dyn Fn() -> Result<E, Error> + Send>;

pub struct State<E: Backoff> {
    /// Input and output channels
    io: Io,

    /// Endpoint providers
    ///
    /// It sends us some events through channels, but we also use it directly for sending pings
    pub endpoint_providers: Vec<Arc<dyn EndpointProvider>>,

    /// Last wireguard handshake time provider
    last_rx_time_provider: Option<Arc<dyn TimeSinceLastRxProvider>>,

    /// All of the per-session needed information for connectivity checks
    ///
    /// Connectivity checks are performed for each pair of (local_endpoint, peer) separately, each
    /// of this pair gets their own session ID, which uniquely maps to it. Session IDs are
    /// exchanged either through ping or CallMeMaybe messages. As each session involves exchanging
    /// a few messages - we have to track the state of that
    endpoint_connectivity_check_state: HashMap<Session, EndpointConnectivityCheckState<E>>,

    /// Cache of the all known nodes
    node_cache: HashSet<PublicKey>,

    /// Local cache of the all known endpoints
    local_endpoint_cache: EnumMap<EndpointProviderType, HashSet<EndpointCandidate>>,

    /// Periodic actions helper
    ///
    /// Due to the nature of NAT-traversal, we have to rely on some timeouts to declare a pair of
    /// endpoints invalid at some point to retry then eventually. This member helps keep track of
    /// periodic actions we have to perform.
    poll_timer: Interval,

    /// Ping Pong tracker
    ///
    /// Used by endpoint providers to send and receive Pinger and Ponger messages. Cross ping check
    /// is responsible for configuring it with allowed sessions and public keys.
    ping_pong_handler: Arc<Mutex<PingPongHandler>>,

    /// Exponential backoff helper provider
    ///
    /// A closure which produces exponential backoff helpers for the cross ping check sessions.
    exponential_backoff_helper_provider: ExponentialBackoffProvider<E>,

    /// Session IDs received from other nodes in CMM requests
    session_id_candidates: LruCache<Session, PublicKey>,
}

impl<E: Backoff> CrossPingCheck<E> {
    fn start_with_backoff_provider(
        io: Io,
        endpoint_providers: Vec<Arc<dyn EndpointProvider>>,
        last_rx_time_provider: Option<Arc<dyn TimeSinceLastRxProvider>>,
        poll_period: Duration,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        exponential_backoff_helper_provider: ExponentialBackoffProvider<E>,
    ) -> Self {
        let poll_timer = interval(poll_period);
        Self {
            task: Task::start(State {
                io,
                endpoint_providers,
                last_rx_time_provider,
                endpoint_connectivity_check_state: Default::default(),
                node_cache: Default::default(),
                local_endpoint_cache: Default::default(),
                poll_timer,
                ping_pong_handler,
                exponential_backoff_helper_provider,
                session_id_candidates: LruCache::new(UPGRADE_TIMEOUT, MAX_SESSION_CANDIDATES),
            }),
        }
    }
}

impl CrossPingCheck {
    pub fn start(
        io: Io,
        endpoint_providers: Vec<Arc<dyn EndpointProvider>>,
        last_rx_time_provider: Option<Arc<dyn TimeSinceLastRxProvider>>,
        poll_period: Duration,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        exponential_backoff_bounds: ExponentialBackoffBounds,
    ) -> Self {
        telio_log_info!("Starting cross ping check");

        Self::start_with_backoff_provider(
            io,
            endpoint_providers,
            last_rx_time_provider,
            poll_period,
            ping_pong_handler,
            Box::new(move || {
                ExponentialBackoff::new(exponential_backoff_bounds).map_err(Error::from)
            }),
        )
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    fn compare_candidate_preference(
        a: &WireGuardEndpointCandidateChangeEvent,
        b: &WireGuardEndpointCandidateChangeEvent,
    ) -> std::cmp::Ordering {
        let ep_preference_score = |ep| match ep {
            ApiEndpointProvider::Local => 4,
            ApiEndpointProvider::Upnp => 2,
            ApiEndpointProvider::Stun => 1,
        };

        let ep_pair_preference_score =
            |ep1, ep2| ep_preference_score(ep1) + ep_preference_score(ep2);

        let a_score = ep_pair_preference_score(a.remote_endpoint.1, a.local_endpoint.1);
        let b_score = ep_pair_preference_score(b.remote_endpoint.1, b.local_endpoint.1);

        a_score.cmp(&b_score)
    }
}

#[async_trait]
impl CrossPingCheckTrait for CrossPingCheck {
    async fn get_validated_endpoints(
        &self,
    ) -> Result<HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent>, Error> {
        let res: Result<HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent>, Error> =
            task_exec!(&self.task, async move |s| {
                // Gather all validated endpoints per peer
                let validated_candidates_per_peer =
                    s.endpoint_connectivity_check_state.iter().fold(
                        HashMap::new(),
                        |mut acc: HashMap<
                            PublicKey,
                            Vec<WireGuardEndpointCandidateChangeEvent>,
                        >,
                         v| {
                            if let (EndpointState::Published, Some(ep)) =
                                (v.1.state.get(), v.1.last_validated_endpoint)
                            {
                                acc.entry(v.1.public_key).or_default().push(
                                    WireGuardEndpointCandidateChangeEvent {
                                        public_key: v.1.public_key,
                                        remote_endpoint: ep,
                                        local_endpoint: (
                                            v.1.local_endpoint_candidate.wg,
                                            v.1.provider_type,
                                        ),
                                        session: *v.0,
                                        changed_at: v.1.last_state_transition,
                                    },
                                );
                            }
                            acc
                        },
                    );

                // Select most prefered endpoint candidate according to
                // preference defined by compare_candidate_preference()
                Ok(validated_candidates_per_peer
                    .into_iter()
                    .filter_map(|(pubkey, events)| {
                        events
                            .into_iter()
                            .max_by(Self::compare_candidate_preference)
                            .map(|event| (pubkey, event))
                    })
                    .collect())
            })
            .await
            .map_err(|e| e.into());
        res
    }

    async fn notify_successfull_wg_connection_upgrade(
        &self,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        let res: Result<(), Error> = task_exec!(&self.task, async move |s| {
            let sessions = s
                .endpoint_connectivity_check_state
                .values_mut()
                .filter(|v| v.public_key == public_key);
            for session in sessions {
                session.handle_endpoint_successful_notification();
            }
            Ok(())
        })
        .await
        .map_err(|e| e.into());
        res
    }

    async fn configure(&self, config: Option<Config>) -> Result<(), Error> {
        let _ = task_exec!(&self.task, async move |s| {
            // FIXME: error handling with task_exec! seems to suck a lot. Need to fix that.
            s.configure(config).await.unwrap_or_else(|e| {
                telio_log_warn!("Failed to send ping {:?}", e);
            });
            Ok(())
        })
        .await;
        Ok(())
    }
}

impl<E: Backoff> State<E> {
    fn get_connectivty_check_state<'a>(
        ep_connectivity_state: &'a mut HashMap<Session, EndpointConnectivityCheckState<E>>,
        session_id: &Session,
    ) -> Result<&'a mut EndpointConnectivityCheckState<E>, Error> {
        ep_connectivity_state
            .get_mut(session_id)
            .ok_or(Error::UnkownSessionForRxedPongPacket)
    }

    fn gather_all_local_endpoints(&self) -> Result<HashSet<EndpointCandidate>, Error> {
        Ok(self
            .local_endpoint_cache
            .iter()
            .flat_map(|(_, per_provider)| per_provider.iter())
            .cloned()
            .collect())
    }

    pub fn gather_provider_local_endpoints(
        &self,
        provider: EndpointProviderType,
    ) -> HashSet<EndpointCandidate> {
        if let Some(hmap) = self.local_endpoint_cache.as_array().get(provider as usize) {
            (*hmap).clone()
        } else {
            HashSet::new()
        }
    }

    fn gather_all_nodes(&self) -> Result<HashSet<PublicKey>, Error> {
        Ok(self.node_cache.iter().cloned().collect())
    }

    pub async fn configure(&mut self, config: Option<Config>) -> Result<(), Error> {
        let old_nodes = self.gather_all_nodes()?;
        let new_nodes: HashSet<PublicKey> = config
            .and_then(|c| c.peers)
            .unwrap_or_default()
            .iter()
            .map(|p| p.base.public_key)
            .collect();

        // Calculate peer difference
        let added_nodes = &new_nodes - &old_nodes;
        let removed_nodes = &old_nodes - &new_nodes;

        // Remove sessions for all deleted nodes
        self.endpoint_connectivity_check_state.retain(|k, v| {
            let retain = !removed_nodes.contains(&v.public_key);
            if !retain {
                telio_log_debug!("Terminating session {:?} -> {:?}", k, v)
            }
            retain
        });

        // Create sessions for all new nodes
        for added_node in added_nodes {
            for (provider_type, endpoints) in &self.local_endpoint_cache {
                for endpoint in endpoints {
                    let session_id = rand::random::<Session>();
                    let session = EndpointConnectivityCheckState {
                        public_key: added_node,
                        local_endpoint_candidate: endpoint.clone(),
                        state: EndpointStateMachine::default(),
                        last_state_transition: Instant::now(),
                        last_validated_endpoint: None,
                        last_rx_time_provider: self.last_rx_time_provider.clone(),
                        exponential_backoff: (self.exponential_backoff_helper_provider)()?,
                        local_session: session_id,
                        provider_type: provider_type.into(),
                    };

                    // Store freshly created connectivity check session
                    telio_log_debug!("New session created: {:?} -> {:?}", session_id, session);
                    self.endpoint_connectivity_check_state
                        .insert(session_id, session);
                }
            }
        }

        // Update known sessions for ping pong handler
        let known_sessions: HashMap<Session, PublicKey> = self
            .endpoint_connectivity_check_state
            .iter()
            .map(|(k, v)| (*k, v.public_key))
            .collect();
        self.ping_pong_handler
            .lock()
            .await
            .configure(known_sessions);

        self.node_cache = new_nodes;

        Ok(())
    }

    async fn handle_endpoint_change_event(
        &mut self,
        event: EndpointCandidatesChangeEvent,
    ) -> Result<(), Error> {
        // Calculate diff of the local endpoints
        let (provider, candidates) = event;
        let old_endpoints: HashSet<EndpointCandidate> =
            self.gather_provider_local_endpoints(provider);
        let new_endpoints: HashSet<EndpointCandidate> = candidates.iter().cloned().collect();
        let added_endpoints = &new_endpoints - &old_endpoints;
        let removed_endpoints = &old_endpoints - &new_endpoints;

        telio_log_trace!("Endpoint diff, added: {:?}", added_endpoints);
        telio_log_trace!("Endpoint diff, removed: {:?}", removed_endpoints);

        // Remove all sessions which is working with removed local endpoint
        self.endpoint_connectivity_check_state.retain(|k, v| {
            let retain = !removed_endpoints.contains(&v.local_endpoint_candidate);
            if !retain {
                telio_log_debug!("Terminating session {:?} -> {:?}", k, v);
            }
            retain
        });

        // Create new sessions for all added endpoints
        for added_endpoint in added_endpoints {
            for node in self.gather_all_nodes()? {
                let session_id = rand::random::<Session>();
                let session = EndpointConnectivityCheckState {
                    public_key: node,
                    local_endpoint_candidate: added_endpoint.clone(),
                    local_session: session_id,
                    state: EndpointStateMachine::default(),
                    last_state_transition: Instant::now(),
                    last_validated_endpoint: None,
                    last_rx_time_provider: self.last_rx_time_provider.clone(),
                    exponential_backoff: (self.exponential_backoff_helper_provider)()?,
                    provider_type: event.0.into(),
                };

                // Store freshly created connectivity check session
                telio_log_debug!("New session created: {:?} -> {:?}", session_id, session);
                self.endpoint_connectivity_check_state
                    .insert(session_id, session);
            }
        }

        // Update knon sessions for ping pong handler
        let known_sessions: HashMap<Session, PublicKey> = self
            .endpoint_connectivity_check_state
            .iter()
            .map(|(k, v)| (*k, v.public_key))
            .collect();
        self.ping_pong_handler
            .lock()
            .await
            .configure(known_sessions);

        *(self
            .local_endpoint_cache
            .as_mut_array()
            .get_mut(provider as usize)
            .ok_or(Error::EndpointProviderError(EndPointError::LocalCacheError))?) = new_endpoints;

        Ok(())
    }

    async fn handle_pong_rx_event(&mut self, event: PongEvent) -> Result<(), Error> {
        let session_id = event.msg.get_session();
        let session = State::get_connectivty_check_state(
            &mut self.endpoint_connectivity_check_state,
            &session_id,
        )?;
        session
            .handle_pong_rx_event(event, self.io.wg_endpoint_publisher.clone())
            .await
    }

    async fn handle_call_me_maybe_rxed_event(
        &mut self,
        (public_key, message): (PublicKey, CallMeMaybeMsg),
    ) -> Result<(), Error> {
        match message.get_message_type() {
            Ok(CallMeMaybeType::INITIATOR) => {
                // First send UDP pings to all of the received endpoints via endpoint providers
                let endpoints = message.get_addrs();
                let (_, local_session_id) = self
                    .endpoint_connectivity_check_state
                    .iter()
                    .map(|(k, v)| (v.public_key, *k))
                    .find(|(pk, _)| *pk == public_key)
                    .ok_or(Error::UnexpectedPeer(public_key))?;

                for endpoint in endpoints {
                    Self::send_ping_via_all_endpoint_providers(
                        &self.endpoint_providers,
                        endpoint,
                        local_session_id,
                        public_key,
                    )
                    .await?;
                }

                let remote_session_id = message.get_session();
                self.session_id_candidates
                    .insert(remote_session_id, public_key);

                // Next format and exchange CallMeMabe response message
                let call_me_maybe_response = CallMeMaybeMsg::new(
                    false,
                    self.gather_all_local_endpoints()?.iter().map(|e| e.udp),
                    remote_session_id,
                );
                #[allow(mpsc_blocking_send)]
                self.io
                    .intercoms
                    .tx
                    .send((public_key, call_me_maybe_response))
                    .await?;
            }

            Ok(CallMeMaybeType::RESPONDER) => {
                // Find session and forward the call me maybe message there
                let session_id = message.get_session();
                let session = State::get_connectivty_check_state(
                    &mut self.endpoint_connectivity_check_state,
                    &session_id,
                )?;
                session
                    .handle_call_me_maybe_response_rxed_event(
                        session_id,
                        (public_key, message),
                        self.endpoint_providers.clone(),
                    )
                    .await?;
            }

            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    async fn handle_tick_event(&mut self) -> Result<(), Error> {
        // Tick over all currently ongoing sessions
        for (session, state) in self.endpoint_connectivity_check_state.iter_mut() {
            state
                .handle_tick_event(*session, self.io.intercoms.tx.clone())
                .await?;
        }
        Ok(())
    }

    // Ping other node via all endpoint providers. Single Endpoint provider failure should not
    // prevent others from attempting the ping.
    async fn send_ping_via_all_endpoint_providers(
        ep_providers: &Vec<Arc<dyn EndpointProvider>>,
        target: SocketAddr,
        session_id: Session,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        for ep in ep_providers {
            telio_log_trace!(
                "Pinging {:?} endpoint {:?}, via {:?} endpoint provider",
                public_key,
                target,
                ep.name()
            );
            if ep.send_ping(target, session_id, public_key).await.is_err() {
                telio_log_warn!(
                    "Endpoint provider {:?} failed to ping via {:?}. Will retry later",
                    ep.name(),
                    target
                );
            }
        }

        Ok(())
    }

    pub fn check_if_upgrade_is_allowed(&mut self, session: Session, public_key: PublicKey) -> bool {
        // We can't just remove a session here, because the other side might trigger wg consolidation
        // due to 'tick event' and in that case there will be no CMM with sesssion id sent before.
        match self.session_id_candidates.get(&session) {
            Some(pk) => pk == &public_key,
            None => false,
        }
    }
}

#[async_trait]
impl UpgradeController for CrossPingCheck {
    async fn check_if_upgrade_is_allowed(
        &self,
        session: Session,
        public_key: PublicKey,
    ) -> Result<bool, Error> {
        task_exec!(&self.task, async move |s| Ok(
            s.check_if_upgrade_is_allowed(session, public_key)
        ))
        .await
        .map_err(|e| e.into())
    }

    async fn notify_failed_wg_connection(&self, public_key: PublicKey) -> Result<(), Error> {
        let res: Result<(), Error> = task_exec!(&self.task, async move |s| {
            let sessions = s
                .endpoint_connectivity_check_state
                .values_mut()
                .filter(|v| v.public_key == public_key);
            for session in sessions {
                session.handle_endpoint_gone_notification().await?;

                for e in s.endpoint_providers.iter() {
                    if let Some(current_endpoints) = e.get_current_endpoints().await {
                        if current_endpoints.iter().any(|current_endpoint| {
                            *current_endpoint == session.local_endpoint_candidate
                        }) {
                            e.handle_endpoint_gone_notification().await;
                        }
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| e.into());
        res
    }
}

#[async_trait]
impl<E: Backoff> Runtime for State<E> {
    const NAME: &'static str = "CrossPingCheck";

    type Err = Error;

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        tokio::select! {
            Some(endpoint_change_event) = self.io.endpoint_change_subscriber.recv() => {
                telio_log_trace!("Endpoint change event occured: {:?}", endpoint_change_event);
                self
                    .handle_endpoint_change_event(endpoint_change_event)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("Failed to handle enpoind change event: {:?}, ignoring", e);
                        });
                Ok(())
            }

            Some(pong_rx_event) = self.io.pong_rx_subscriber.recv() => {
                telio_log_trace!("Pong RX event occured: {:?}", pong_rx_event);
                self
                    .handle_pong_rx_event(pong_rx_event)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("Failed to handle pong rx event: {:?}, ignoring", e);
                        });

                Ok(())
            }

            Some(call_me_maybe_msg) = self.io.intercoms.rx.recv() => {
                telio_log_debug!("CallMeMaybe event occured: {:?}, {:?}", call_me_maybe_msg, call_me_maybe_msg.1.get_message_type());
                self
                    .handle_call_me_maybe_rxed_event(call_me_maybe_msg)
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("Failed to handle call me maybe message: {:?}, ignoring", e);
                        });

                Ok(())
            }

            _ = self.poll_timer.tick() => {
                telio_log_trace!("tick event occured");
                self
                    .handle_tick_event()
                    .await
                    .unwrap_or_else(
                        |e| {
                            telio_log_warn!("Failed to handle tick event: {:?}, ignoring", e);
                        });

                Ok(())
            }

            // Incoming task
            update = update => {
                return update(self).await;
            }
            else => {
                return Ok(());
            }
        }
    }
}

/// The State processing of each (endpoint, remote node) pair.
pub struct EndpointConnectivityCheckState<E: Backoff> {
    public_key: PublicKey,
    local_endpoint_candidate: EndpointCandidate,
    local_session: Session,
    state: EndpointStateMachine,
    last_state_transition: Instant,
    last_validated_endpoint: Option<(SocketAddr, ApiEndpointProvider)>,
    last_rx_time_provider: Option<Arc<dyn TimeSinceLastRxProvider>>,
    exponential_backoff: E,
    provider_type: ApiEndpointProvider,
}

impl<E: Backoff> Debug for EndpointConnectivityCheckState<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointConnectivityCheckState")
            .field("public_key", &self.public_key)
            .field("local_endpoint_candidate", &self.local_endpoint_candidate)
            .field("state", &self.state)
            .field("last_state_transition", &self.last_state_transition)
            .field("last_validate_endpoint", &self.last_validated_endpoint)
            .field("exponential_backoff", &self.exponential_backoff)
            .field(
                "last_rx_time_provider",
                if self.last_rx_time_provider.is_some() {
                    &"Some"
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

impl<E: Backoff> EndpointConnectivityCheckState<E> {
    async fn send_call_me_maybe_request(
        &mut self,
        session: Session,
        intercoms: chan::Tx<(PublicKey, CallMeMaybeMsg)>,
    ) -> Result<(), Error> {
        let call_me_maybe_init = CallMeMaybeMsg::new(
            true,
            [self.local_endpoint_candidate.udp].iter().cloned(),
            session,
        );

        telio_log_debug!(
            "Sending a CMM request to {:?}: {:?}",
            self.public_key,
            call_me_maybe_init
        );

        #[allow(mpsc_blocking_send)]
        intercoms
            .send((self.public_key, call_me_maybe_init))
            .await?;
        Ok(())
    }

    async fn handle_endpoint_gone_notification(&mut self) -> Result<(), Error> {
        if self.state.get() == EndpointState::Published {
            telio_log_info!(
                "Endpoint gone, next retry after {}s",
                self.exponential_backoff.get_backoff().as_secs_f64()
            );
            do_state_transition!(self, Event::EndpointGone);
        }
        Ok(())
    }

    fn handle_endpoint_successful_notification(&mut self) {
        if self.state.get() == EndpointState::Published {
            self.exponential_backoff.reset();
        }
    }

    async fn handle_call_me_maybe_response_rxed_event(
        &mut self,
        session_id: Session,
        (public_key, message): (PublicKey, CallMeMaybeMsg),
        ep_providers: Vec<Arc<dyn EndpointProvider>>,
    ) -> Result<(), Error> {
        match self.state.get() {
            EndpointState::EndpointGathering => {
                telio_log_debug!(
                    "Received a CMM response from {:?}: {:?}",
                    public_key,
                    message
                );

                for addr in message.get_addrs() {
                    State::<E>::send_ping_via_all_endpoint_providers(
                        &ep_providers,
                        addr,
                        session_id,
                        public_key,
                    )
                    .await?;
                }

                do_state_transition!(self, Event::ReceiveCallMeMaybeResponse);
            }
            _ => {
                telio_log_warn!("Received a CMM response for session {:?} during non-gather state {:?}. Ignoring", message.get_session(), self.state);
            }
        };
        Ok(())
    }

    #[allow(mpsc_blocking_send)]
    async fn handle_pong_rx_event(
        &mut self,
        event: PongEvent,
        wg_ep_publisher: chan::Tx<WireGuardEndpointCandidateChangeEvent>,
    ) -> Result<(), Error> {
        match self.state.get() {
            EndpointState::Ping => {
                let nice_ep_provider = matches!(
                    event.msg.get_ponging_ep_provider(),
                    Ok(Some(telio_model::features::EndpointProvider::Local))
                        | Ok(Some(telio_model::features::EndpointProvider::Upnp))
                );
                if let Ok(ping_source) = event.msg.get_ping_source_address() {
                    if ping_source == self.local_endpoint_candidate.udp.ip() || nice_ep_provider {
                        let remote_endpoint =
                            SocketAddr::new(event.addr.ip(), event.msg.get_wg_port().0);
                        let remote_endpoint_type = match event.msg.get_ponging_ep_provider() {
                            Ok(Some(ep)) => ep,
                            other => {
                                telio_log_warn!(
                                    "Received unsupported ponging ep provider: {other:?}, defaulting to Local"
                                );
                                ApiEndpointProvider::Local
                            }
                        };

                        do_state_transition!(self, Event::Publish);

                        // Reset exponential backoff on succesfull endpoint verification
                        self.exponential_backoff.reset();

                        let wg_publish_event = WireGuardEndpointCandidateChangeEvent {
                            public_key: self.public_key,
                            remote_endpoint: (remote_endpoint, remote_endpoint_type),
                            local_endpoint: (self.local_endpoint_candidate.wg, self.provider_type),
                            session: self.local_session,
                            changed_at: self.last_state_transition,
                        };
                        telio_log_info!("Publishing validated WG endpoint: {:?}, local ep type: {:?}, remote ep type: {:?}",
                            wg_publish_event, self.provider_type, event.msg.get_ponging_ep_provider());
                        self.last_validated_endpoint =
                            Some((remote_endpoint, remote_endpoint_type));
                        wg_ep_publisher
                            .send(wg_publish_event)
                            .await
                            .map_err(Box::new)?;
                    } else {
                        telio_log_debug!(
                            "Received a pong for session {:?} for a different candidate {:?} on stun socket, ignoring.",
                            event.msg.get_session(),
                            event.msg.get_ping_source_address(),
                        );
                    }
                } else {
                    telio_log_warn!(
                        "Received a pong for session {:?} without ping_source_address. Ignoring",
                        event.msg.get_session(),
                    );
                }
            }

            _ => {
                telio_log_warn!(
                    "Received a pong for session {:?} during non-pinging state {:?}. Ignoring",
                    event.msg.get_session(),
                    self.state
                );
            }
        };
        Ok(())
    }

    async fn should_resend_call_me_maybe_request(
        &self,
        duration_in_state: Duration,
    ) -> ShouldSendCMMResult {
        if duration_in_state > self.exponential_backoff.get_backoff() {
            if let Some(last_rx_time_provider) = &self.last_rx_time_provider {
                if is_peer_alive(&**last_rx_time_provider, &self.public_key).await {
                    ShouldSendCMMResult::Yes
                } else {
                    telio_log_debug!(
                        "Peer {:?} has not rxed anything for: {:?}, threshold: {:?}",
                        self.public_key,
                        last_rx_time_provider.last_rx_time(&self.public_key).await,
                        last_rx_time_provider.max_no_rx_time().await
                    );
                    ShouldSendCMMResult::Unresponsive
                }
            } else {
                ShouldSendCMMResult::Yes
            }
        } else {
            telio_log_debug!(
                "Peer {:?} is in backoff for: {:?}, threshold: {:?}",
                self.public_key,
                duration_in_state,
                self.exponential_backoff.get_backoff()
            );
            ShouldSendCMMResult::Backoff
        }
    }

    async fn handle_tick_event(
        &mut self,
        session: Session,
        intercoms: chan::Tx<(PublicKey, CallMeMaybeMsg)>,
    ) -> Result<(), Error> {
        let duration_in_state = Instant::now() - self.last_state_transition;
        let timeout = CPC_TIMEOUT; // TODO: make configurable

        match self.state.get() {
            EndpointState::EndpointGathering => {
                if duration_in_state > timeout {
                    // Timeout occured
                    telio_log_debug!(
                        "Timeout waiting for CMM response, next retry after {}s",
                        self.exponential_backoff.get_backoff().as_secs_f64()
                    );
                    do_state_transition!(self, Event::Timeout);
                }
            }
            EndpointState::Ping => {
                if duration_in_state > timeout {
                    // Timeout occured
                    telio_log_debug!(
                        "Timeout waiting for pongs, next retry after {}s",
                        self.exponential_backoff.get_backoff().as_secs_f64()
                    );
                    do_state_transition!(self, Event::Timeout);
                }
            }
            EndpointState::Disconnected(Event::StartUp) => {
                self.send_call_me_maybe_request(session, intercoms).await?;
                do_state_transition!(self, Event::SendCallMeMaybeRequest);
            }
            EndpointState::Disconnected(Event::Timeout) => {
                match self
                    .should_resend_call_me_maybe_request(duration_in_state)
                    .await
                {
                    ShouldSendCMMResult::Yes => {
                        self.exponential_backoff.next_backoff();
                        self.send_call_me_maybe_request(session, intercoms).await?;
                        do_state_transition!(self, Event::SendCallMeMaybeRequest);
                    }
                    reason => {
                        telio_log_debug!(
                            "Skipping sending CMM to peer {} ({reason:?})",
                            self.public_key,
                        );
                    }
                }
            }
            EndpointState::Disconnected(Event::EndpointGone) => {
                match self
                    .should_resend_call_me_maybe_request(duration_in_state)
                    .await
                {
                    ShouldSendCMMResult::Yes => {
                        self.exponential_backoff.next_backoff();
                        self.send_call_me_maybe_request(session, intercoms).await?;
                        do_state_transition!(self, Event::SendCallMeMaybeRequest);
                    }
                    reason => {
                        telio_log_debug!(
                            "Skipping sending CMM to peer {} ({reason:?})",
                            self.public_key
                        );
                    }
                }
            }
            _ => {}
        };

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ShouldSendCMMResult {
    Yes,
    Backoff,
    Unresponsive,
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::Duration,
    };

    use itertools::Itertools;
    use mockall::predicate::eq;
    use rstest::rstest;
    use tokio::{
        sync::mpsc::{Receiver, Sender},
        time,
    };

    use telio_crypto::{PublicKey, SecretKey};
    use telio_model::{
        config::{Config, Peer, PeerBase},
        SocketAddr,
    };
    use telio_proto::{PingerMsg, WGPort};

    use crate::last_rx_time_provider::{self, MockTimeSinceLastRxProvider};
    use telio_task::io::Chan;
    use telio_utils::exponential_backoff::MockBackoff;

    use super::*;
    use crate::{
        cross_ping_check::CrossPingCheck, cross_ping_check::CrossPingCheckTrait,
        endpoint_providers, endpoint_providers::EndpointCandidate,
        endpoint_providers::EndpointProviderType, endpoint_providers::MockEndpointProvider,
    };

    struct TestChannels {
        endpoint_change_subscriber: Sender<(EndpointProviderType, Vec<EndpointCandidate>)>,
        pong_rx_events: Sender<PongEvent>,
        wg_endpoint_publish_events: Receiver<WireGuardEndpointCandidateChangeEvent>,
        intercoms: Chan<(PublicKey, CallMeMaybeMsg)>,
    }
    const SESSION_ID: u64 = 0;

    fn prepare_checker_test() -> Result<(CrossPingCheck, TestChannels), Error> {
        let mut endpoint_provider_mock = MockEndpointProvider::new();
        endpoint_provider_mock
            .expect_send_ping()
            .returning(|_, _, _| Ok(()));
        endpoint_provider_mock
            .expect_handle_endpoint_gone_notification()
            .returning(|| ());
        endpoint_provider_mock
            .expect_get_current_endpoints()
            .returning(|| None);
        let endpoint_change_subscriber = Chan::default();
        let pong_rx_events = Chan::default();
        let wg_endpoint_publish_events = Chan::default();
        let (checker_intercoms, intercoms) = Chan::pipe();

        let checker = CrossPingCheck::start(
            Io {
                endpoint_change_subscriber: endpoint_change_subscriber.rx,
                pong_rx_subscriber: pong_rx_events.rx,
                wg_endpoint_publisher: wg_endpoint_publish_events.tx,
                intercoms: checker_intercoms,
            },
            vec![Arc::new(endpoint_provider_mock)],
            Some(Arc::new(MockTimeSinceLastRxProvider::new())),
            Duration::from_secs(2),
            Arc::new(Mutex::new(PingPongHandler::new(SecretKey::gen()))),
            ExponentialBackoffBounds::default(),
        );

        let channels = TestChannels {
            endpoint_change_subscriber: endpoint_change_subscriber.tx,
            pong_rx_events: pong_rx_events.tx,
            wg_endpoint_publish_events: wg_endpoint_publish_events.rx,
            intercoms,
        };

        Ok((checker, channels))
    }

    async fn validate_endpoint(
        channels: &mut TestChannels,
        endpoint: SocketAddr,
        original_pub_key: PublicKey,
        local_ep_provider: EndpointProviderType,
        remote_ep_provider: EndpointProviderType,
    ) {
        channels
            .endpoint_change_subscriber
            .send((
                local_ep_provider,
                vec![EndpointCandidate {
                    wg: endpoint,
                    udp: endpoint,
                }],
            ))
            .await
            .unwrap();
        let (_, cmm_init) = channels.intercoms.rx.recv().await.unwrap();
        channels
            .intercoms
            .tx
            .send((
                original_pub_key,
                CallMeMaybeMsg::new(false, vec![endpoint].into_iter(), cmm_init.get_session()),
            ))
            .await
            .unwrap();
        wait_for_tick().await;
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let msg = PingerMsg::ping(WGPort(2), cmm_init.get_session(), 10_u64)
            .pong(WGPort(2), &endpoint.ip(), remote_ep_provider.into())
            .unwrap();
        channels
            .pong_rx_events
            .send(PongEvent {
                addr: endpoint,
                rtt: Duration::from_millis(100),
                msg,
            })
            .await
            .unwrap();
        channels.wg_endpoint_publish_events.recv().await.unwrap();
    }

    fn prepare_test_session_in_state(
        state: EndpointStateMachine,
        endpoint: SocketAddr,
        last_rx_time_provider: Arc<dyn TimeSinceLastRxProvider>,
    ) -> EndpointConnectivityCheckState<MockBackoff> {
        EndpointConnectivityCheckState {
            public_key: PublicKey::default(),
            local_endpoint_candidate: EndpointCandidate {
                wg: endpoint,
                udp: endpoint,
            },
            local_session: rand::random(),
            state,
            last_state_transition: Instant::now(),
            last_validated_endpoint: None,
            last_rx_time_provider: Some(last_rx_time_provider),
            exponential_backoff: MockBackoff::default(),
            provider_type: telio_model::features::EndpointProvider::Stun,
        }
    }

    async fn wait_for_tick() {
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn get_validated_endpoints() {
        let (checker, mut channels) = prepare_checker_test().unwrap();
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let lower_prio_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8080);
        let mut peer = Peer::default();
        let original_pub_key = PublicKey(*b"ABBBBBBBBBBBBBBBBBBBAAAAAAAAAAAA");
        peer.base.public_key = original_pub_key;

        checker
            .configure(Some(Config {
                this: PeerBase::default(),
                peers: Some(vec![peer]),
                derp_servers: None,
                dns: None,
            }))
            .await
            .unwrap();

        assert!(checker.get_validated_endpoints().await.unwrap().is_empty());
        validate_endpoint(
            &mut channels,
            endpoint,
            original_pub_key,
            EndpointProviderType::LocalInterfaces,
            EndpointProviderType::LocalInterfaces,
        )
        .await;
        validate_endpoint(
            &mut channels,
            lower_prio_endpoint,
            original_pub_key,
            EndpointProviderType::Upnp,
            EndpointProviderType::Upnp,
        )
        .await;
        let change_event = &checker.get_validated_endpoints().await.unwrap()[&original_pub_key];

        assert_eq!(change_event.public_key, original_pub_key);
        assert_eq!(change_event.local_endpoint.0, endpoint);
        assert_eq!(
            change_event.local_endpoint.1,
            telio_model::features::EndpointProvider::Local
        );
    }

    #[tokio::test]
    async fn notify_failed_wg_connection() {
        let (checker, mut channels) = prepare_checker_test().unwrap();
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let mut peer = Peer::default();
        let original_pub_key = PublicKey(*b"ABBBBBBBBBBBBBBBBBBBAAAAAAAAAAAA");
        peer.base.public_key = original_pub_key;

        checker
            .configure(Some(Config {
                this: PeerBase::default(),
                peers: Some(vec![peer]),
                derp_servers: None,
                dns: None,
            }))
            .await
            .unwrap();

        assert!(checker.get_validated_endpoints().await.unwrap().is_empty());
        validate_endpoint(
            &mut channels,
            endpoint,
            original_pub_key,
            EndpointProviderType::LocalInterfaces,
            EndpointProviderType::LocalInterfaces,
        )
        .await;
        assert!(!checker.get_validated_endpoints().await.unwrap().is_empty());
        checker
            .notify_failed_wg_connection(original_pub_key)
            .await
            .unwrap();

        assert!(checker.get_validated_endpoints().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_send_cmm_request() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::Disconnected(Event::StartUp)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            last_rx_time_provider_mock,
        );
        let intercoms = Chan::default();

        endpoint_connectivity_check_state
            .handle_tick_event(0, intercoms.tx)
            .await
            .unwrap();

        assert_eq!(
            endpoint_connectivity_check_state.state,
            EndpointState::EndpointGathering,
        );
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_receive_cmm_response() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let mut endpoint_provider_mock = MockEndpointProvider::new();
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        endpoint_provider_mock
            .expect_send_ping()
            .returning(|_, _, _| Ok(()));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::EndpointGathering),
            endpoint,
            last_rx_time_provider_mock.clone(),
        );

        let cmm_msg = CallMeMaybeMsg::new(false, vec![endpoint].into_iter(), 1);
        endpoint_connectivity_check_state
            .handle_call_me_maybe_response_rxed_event(
                1,
                (PublicKey::default(), cmm_msg),
                vec![Arc::new(endpoint_provider_mock)],
            )
            .await
            .unwrap();

        assert_eq!(endpoint_connectivity_check_state.state, EndpointState::Ping);
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_publish() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::Ping),
            endpoint,
            last_rx_time_provider_mock.clone(),
        );

        endpoint_connectivity_check_state
            .exponential_backoff
            .expect_reset()
            .times(1)
            .returning(|| ());

        let msg = PingerMsg::ping(WGPort(2), 1, 10_u64)
            .pong(
                WGPort(2),
                &endpoint.ip(),
                telio_model::features::EndpointProvider::Local,
            )
            .unwrap();
        endpoint_connectivity_check_state
            .handle_pong_rx_event(
                PongEvent {
                    addr: endpoint,
                    rtt: Duration::from_millis(100),
                    msg,
                },
                Chan::default().tx,
            )
            .await
            .unwrap();

        assert_eq!(
            endpoint_connectivity_check_state.state,
            EndpointState::Published
        );
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_endpoint_gone() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::Published),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            last_rx_time_provider_mock.clone(),
        );

        endpoint_connectivity_check_state
            .handle_endpoint_gone_notification()
            .await
            .unwrap();

        assert_eq!(
            endpoint_connectivity_check_state.state,
            (EndpointState::Disconnected(Event::EndpointGone))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn endpoint_connectivity_check_state_timeout_endpoint_gathering() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::EndpointGathering),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            last_rx_time_provider_mock.clone(),
        );

        time::advance(Duration::from_secs(11)).await;
        endpoint_connectivity_check_state
            .handle_tick_event(0, Chan::default().tx)
            .await
            .unwrap();

        assert_eq!(
            endpoint_connectivity_check_state.state,
            (EndpointState::Disconnected(Event::Timeout))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn endpoint_connectivity_check_state_timeout_ping() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::EndpointGathering),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            last_rx_time_provider_mock.clone(),
        );

        time::advance(Duration::from_secs(11)).await;
        endpoint_connectivity_check_state
            .handle_tick_event(0, Chan::default().tx)
            .await
            .unwrap();

        assert_eq!(
            endpoint_connectivity_check_state.state,
            (EndpointState::Disconnected(Event::Timeout))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn exponential_backoff_on_failure() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        last_rx_time_provider_mock
            .lock()
            .await
            .expect_max_no_rx_time()
            .return_const(Duration::from_secs(180));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::Disconnected(Event::StartUp)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            last_rx_time_provider_mock.clone(),
        );
        last_rx_time_provider_mock
            .lock()
            .await
            .expect_last_rx_time()
            .with(eq(endpoint_connectivity_check_state.public_key))
            .times(4)
            .returning(|_| Ok(Some(Duration::from_secs(1))));

        let Chan {
            rx: mut intercoms_rx,
            tx: intercoms_tx,
        } = Chan::default();

        // Let's send the initial CMM message
        endpoint_connectivity_check_state
            .handle_tick_event(0, intercoms_tx.clone())
            .await
            .unwrap();
        intercoms_rx.try_recv().unwrap();

        // Check if CPC waits for the periods returned by the backoff helper
        for millis in [23412, 1222, 500, 1444444].iter() {
            endpoint_connectivity_check_state
                .exponential_backoff
                .expect_get_backoff()
                .return_const(Duration::from_millis(*millis));
            endpoint_connectivity_check_state
                .exponential_backoff
                .expect_next_backoff()
                .return_once(|| ());

            // Let's fire up CMM response timeout
            time::advance(CPC_TIMEOUT + Duration::from_millis(1)).await;

            // Enter Disconnected state
            endpoint_connectivity_check_state
                .handle_tick_event(0, intercoms_tx.clone())
                .await
                .unwrap();

            // Skip the expected time
            let time_to_skip = Duration::from_millis(*millis - 1);
            time::advance(time_to_skip).await;

            // Nothing should happen here
            endpoint_connectivity_check_state
                .handle_tick_event(0, intercoms_tx.clone())
                .await
                .unwrap();
            intercoms_rx
                .try_recv()
                .expect_err("CMM message should not be sent yet");

            // Advance 2ms to exceed the penalty time
            // After that we should be ready to send next CMM message
            time::advance(Duration::from_millis(2)).await;

            // Here another CMM message should be sent
            endpoint_connectivity_check_state
                .handle_tick_event(0, intercoms_tx.clone())
                .await
                .unwrap();
            intercoms_rx
                .try_recv()
                .expect("We should be able to receive a CMM message");

            endpoint_connectivity_check_state
                .exponential_backoff
                .checkpoint();
        }
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_send_ping_to_all_providers_even_if_one_fails() {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);

        let mut endpoint_provider_mock_1 = MockEndpointProvider::new();
        endpoint_provider_mock_1
            .expect_send_ping()
            .returning(|_, _, _| Err(endpoint_providers::Error::NoWGListenPort));

        let mut endpoint_provider_mock_2 = MockEndpointProvider::new();
        endpoint_provider_mock_2
            .expect_send_ping()
            .returning(|_, _, _| Ok(()));

        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::EndpointGathering),
            endpoint,
            last_rx_time_provider_mock.clone(),
        );

        let cmm_msg = CallMeMaybeMsg::new(false, vec![endpoint].into_iter(), 1);
        endpoint_connectivity_check_state
            .handle_call_me_maybe_response_rxed_event(
                1,
                (PublicKey::default(), cmm_msg),
                vec![
                    Arc::new(endpoint_provider_mock_1),
                    Arc::new(endpoint_provider_mock_2),
                ],
            )
            .await
            .unwrap();

        assert_eq!(endpoint_connectivity_check_state.state, EndpointState::Ping);
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[tokio::test(start_paused = true)]
    async fn failure_to_get_last_rx_time_means_peer_is_dead(#[case] which_error: u8) {
        let last_rx_time_provider_mock = Arc::new(Mutex::new(MockTimeSinceLastRxProvider::new()));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            EndpointStateMachine::new(EndpointState::Disconnected(Event::StartUp)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            last_rx_time_provider_mock.clone(),
        );
        last_rx_time_provider_mock
            .lock()
            .await
            .expect_last_rx_time()
            .with(eq(endpoint_connectivity_check_state.public_key))
            .times(1)
            .returning(move |_| match which_error {
                0 => Err(last_rx_time_provider::Error::UnableToCommunicateWithWG(
                    telio_wg::Error::UnsupportedOperationError,
                )),
                1 => Ok(None),

                _ => unreachable!(),
            });

        let Chan {
            rx: mut intercoms_rx,
            tx: intercoms_tx,
        } = Chan::default();

        // Let's send the initial CMM message
        endpoint_connectivity_check_state
            .handle_tick_event(SESSION_ID, intercoms_tx.clone())
            .await
            .unwrap();
        intercoms_rx.try_recv().unwrap();

        let backoff = 20_000;

        endpoint_connectivity_check_state
            .exponential_backoff
            .expect_get_backoff()
            .return_const(Duration::from_millis(backoff));
        endpoint_connectivity_check_state
            .exponential_backoff
            .expect_next_backoff()
            .return_once(|| ());

        // Let's fire up CMM response timeout
        time::advance(CPC_TIMEOUT + Duration::from_millis(1)).await;

        // Enter Disconnected state
        endpoint_connectivity_check_state
            .handle_tick_event(SESSION_ID, intercoms_tx.clone())
            .await
            .unwrap();

        assert_eq!(
            endpoint_connectivity_check_state.state,
            (EndpointState::Disconnected(Event::Timeout))
        );

        // Skip the expected time
        let time_to_skip = Duration::from_millis(backoff + 1);
        time::advance(time_to_skip).await;

        // Nothing should happen here
        endpoint_connectivity_check_state
            .handle_tick_event(0, intercoms_tx.clone())
            .await
            .unwrap();
        intercoms_rx
            .try_recv()
            .expect_err("CMM message should not be sent");
    }

    #[tokio::test]
    async fn upgrade_is_allowed_only_for_sessions_received_in_cmm() {
        let (checker, channels) = prepare_checker_test().unwrap();
        let addrs = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let session: Session = 42;
        let pub_key = PublicKey(*b"ABBBBBBBBBBBBBBBBBBBAAAAAAAAAAAA");
        assert!(!checker
            .check_if_upgrade_is_allowed(session, pub_key)
            .await
            .unwrap());
        channels
            .endpoint_change_subscriber
            .send((
                EndpointProviderType::LocalInterfaces,
                vec![EndpointCandidate {
                    wg: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                    udp: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                }],
            ))
            .await
            .unwrap();

        wait_for_tick().await;

        let mut peer = Peer::default();

        peer.base.public_key = pub_key;

        checker
            .configure(Some(Config {
                this: PeerBase::default(),
                peers: Some(vec![peer]),
                derp_servers: None,
                dns: None,
            }))
            .await
            .unwrap();

        let msg = CallMeMaybeMsg::new(true, [addrs].iter().cloned(), session);
        channels.intercoms.tx.send((pub_key, msg)).await.unwrap();
        wait_for_tick().await;
        assert!(checker
            .check_if_upgrade_is_allowed(session, pub_key)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn upgrade_is_rejected_when_session_is_correct_but_key_is_wrong() {
        let (checker, channels) = prepare_checker_test().unwrap();
        let addrs = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let session: Session = 42;
        let pub_key = PublicKey(*b"ABBBBBBBBBBBBBBBBBBBAAAAAAAAAAAA");
        assert!(!checker
            .check_if_upgrade_is_allowed(session, pub_key)
            .await
            .unwrap());
        channels
            .endpoint_change_subscriber
            .send((
                EndpointProviderType::LocalInterfaces,
                vec![EndpointCandidate {
                    wg: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                    udp: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                }],
            ))
            .await
            .unwrap();

        wait_for_tick().await;

        let mut peer = Peer::default();

        peer.base.public_key = pub_key;

        checker
            .configure(Some(Config {
                this: PeerBase::default(),
                peers: Some(vec![peer]),
                derp_servers: None,
                dns: None,
            }))
            .await
            .unwrap();

        let msg = CallMeMaybeMsg::new(true, [addrs].iter().cloned(), session);
        channels.intercoms.tx.send((pub_key, msg)).await.unwrap();
        wait_for_tick().await;
        let other_pub_key = PublicKey(*b"CCCCBBBBBBBBBBBBBBBBAAAAAAAAAAAA");
        assert!(!checker
            .check_if_upgrade_is_allowed(session, other_pub_key)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_endpoint_candidate_preference() {
        let mut session_counter = 0;
        let mut make_ep_cand = |local_ep, remote_ep| {
            session_counter += 1;
            WireGuardEndpointCandidateChangeEvent {
                public_key: PublicKey(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                remote_endpoint: ("127.0.0.1:1234".parse().unwrap(), remote_ep),
                local_endpoint: ("127.0.0.1:4321".parse().unwrap(), local_ep),
                session: session_counter,
                changed_at: Instant::now(),
            }
        };

        // Define useful shorthands
        use ApiEndpointProvider::Local as epLocal;
        use ApiEndpointProvider::Stun as epStun;
        use ApiEndpointProvider::Upnp as epUpnp;

        let expected_candidates = vec![
            make_ep_cand(epStun, epStun),
            make_ep_cand(epStun, epUpnp),
            make_ep_cand(epUpnp, epUpnp),
            make_ep_cand(epStun, epLocal),
            make_ep_cand(epUpnp, epLocal),
            make_ep_cand(epLocal, epLocal),
        ];

        // Verify all possible permutations are sorted in defined order
        for mut candidate_permutation in expected_candidates
            .iter()
            .permutations(expected_candidates.len())
        {
            let mut candidates: Vec<_> = candidate_permutation.into_iter().cloned().collect();
            candidates.sort_by(CrossPingCheck::compare_candidate_preference);
            assert_eq!(expected_candidates, candidates);
        }

        // And now check the same, but with reversed candidate list
        let expected_candidates = vec![
            make_ep_cand(epStun, epStun),
            make_ep_cand(epUpnp, epStun),
            make_ep_cand(epUpnp, epUpnp),
            make_ep_cand(epLocal, epStun),
            make_ep_cand(epLocal, epUpnp),
            make_ep_cand(epLocal, epLocal),
        ];

        // Verify all possible permutations are sorted in defined order again
        for mut candidate_permutation in expected_candidates
            .iter()
            .permutations(expected_candidates.len())
        {
            let mut candidates: Vec<_> = candidate_permutation.into_iter().cloned().collect();
            candidates.sort_by(CrossPingCheck::compare_candidate_preference);
            assert_eq!(expected_candidates, candidates);
        }
    }
}
