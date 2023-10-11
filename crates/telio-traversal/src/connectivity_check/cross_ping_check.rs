use super::{Error, WireGuardEndpointCandidateChangeEvent};
use crate::{
    endpoint_providers::{
        EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, EndpointProviderType,
        Error as EndPointError, PongEvent,
    },
    ping_pong_handler::PingPongHandler,
};
use async_trait::async_trait;
use enum_map::EnumMap;
use futures::Future;
use sm::sm;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use telio_crypto::PublicKey;
use telio_model::{config::Config, SocketAddr};
use telio_proto::{CallMeMaybeMsg, CallMeMaybeType, Session};
use telio_task::{io::chan, io::Chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    exponential_backoff::{Backoff, ExponentialBackoff, ExponentialBackoffBounds},
    telio_log_debug, telio_log_info, telio_log_trace, telio_log_warn,
};
use tokio::sync::Mutex;
use tokio::time::{interval_at, Instant, Interval};

const CPC_TIMEOUT: Duration = Duration::from_secs(10);

// Cross ping state machine definintion
sm! {
    EndpointState {
        InitialStates { Disconnected }

        SendCallMeMaybeRequest {
            Disconnected => EndpointGathering
        }

        ReceiveCallMeMaybeResponse {
            EndpointGathering => Ping
        }

        Publish {
            Ping => Published
        }

        Timeout {
            EndpointGathering => Disconnected
            Ping => Disconnected
        }

        EndpointGone {
            Published => Disconnected
        }
    }
}
use EndpointState::Variant::*;
use EndpointState::*;
macro_rules! do_state_transition {
    ($machine: expr, $event: expr, $ep: expr) => {{
        if $machine.state() == EndpointState::Published || $event == EndpointState::Publish {
            do_state_transition!($machine, $event, $ep, telio_log_info);
        } else {
            do_state_transition!($machine, $event, $ep, telio_log_debug);
        }
    }};
    ($machine: expr, $event: expr, $ep: expr, $log: ident) => {{
        $log!(
            "Node's {:?} EP {:?} state transition {:?} -> {:?}",
            $ep.public_key,
            $ep.local_endpoint_candidate.udp,
            $machine.state(),
            $event
        );
        $ep.last_state_transition = Instant::now();
        $ep.state = $machine.transition($event).as_enum();
    }};
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait CrossPingCheckTrait {
    async fn configure(&self, config: Option<Config>) -> Result<(), Error>;
    async fn get_validated_endpoints(
        &self,
    ) -> Result<HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent>, Error>;
    async fn notify_failed_wg_connection(&self, public_key: PublicKey) -> Result<(), Error>;
    async fn notify_successfull_wg_connection_upgrade(
        &self,
        public_key: PublicKey,
    ) -> Result<(), Error>;
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
}

impl<E: Backoff> CrossPingCheck<E> {
    fn start_with_backoff_provider(
        io: Io,
        endpoint_providers: Vec<Arc<dyn EndpointProvider>>,
        poll_period: Duration,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        exponential_backoff_helper_provider: ExponentialBackoffProvider<E>,
    ) -> Self {
        Self {
            task: Task::start(State {
                io,
                endpoint_providers,
                endpoint_connectivity_check_state: Default::default(),
                node_cache: Default::default(),
                local_endpoint_cache: Default::default(),
                poll_timer: interval_at(tokio::time::Instant::now(), poll_period),
                ping_pong_handler,
                exponential_backoff_helper_provider,
            }),
        }
    }
}

impl CrossPingCheck {
    pub fn start(
        io: Io,
        endpoint_providers: Vec<Arc<dyn EndpointProvider>>,
        poll_period: Duration,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        exponential_backoff_bounds: ExponentialBackoffBounds,
    ) -> Self {
        telio_log_info!("Starting cross ping check");

        Self::start_with_backoff_provider(
            io,
            endpoint_providers,
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
}

#[async_trait]
impl CrossPingCheckTrait for CrossPingCheck {
    async fn get_validated_endpoints(
        &self,
    ) -> Result<HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent>, Error> {
        let res: Result<HashMap<PublicKey, WireGuardEndpointCandidateChangeEvent>, Error> =
            task_exec!(&self.task, async move |s| {
                // TODO: update logic to maintain all endpoints instead of last one
                Ok(s.endpoint_connectivity_check_state
                    .values()
                    .filter_map(|v| match (v.state.clone(), v.last_validated_enpoint) {
                        (PublishedByPublish(_), Some(ep)) => Some((
                            v.public_key,
                            WireGuardEndpointCandidateChangeEvent {
                                public_key: v.public_key,
                                remote_endpoint: ep,
                                local_endpoint: v.local_endpoint_candidate.wg,
                            },
                        )),
                        _ => None,
                    })
                    .collect())
            })
            .await
            .map_err(|e| e.into());
        res
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
                session.handle_endpoint_succesfull_notification();
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
        let endpoints = self.gather_all_local_endpoints()?;
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
            for endpoint in endpoints.iter() {
                let session = EndpointConnectivityCheckState {
                    public_key: added_node,
                    local_endpoint_candidate: endpoint.clone(),
                    state: Machine::new(Disconnected).as_enum(),
                    last_state_transition: Instant::now(),
                    last_validated_enpoint: None,
                    exponential_backoff: (self.exponential_backoff_helper_provider)()?,
                };
                let session_id = rand::random::<Session>();

                // Store freshly created connectivity check session
                telio_log_debug!("New session created: {:?} -> {:?}", session_id, session);
                self.endpoint_connectivity_check_state
                    .insert(session_id, session);
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
                let session = EndpointConnectivityCheckState {
                    public_key: node,
                    local_endpoint_candidate: added_endpoint.clone(),
                    state: Machine::new(Disconnected).as_enum(),
                    last_state_transition: Instant::now(),
                    last_validated_enpoint: None,
                    exponential_backoff: (self.exponential_backoff_helper_provider)()?,
                };
                let session_id = rand::random::<Session>();

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
            CallMeMaybeType::INITIATOR => {
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

            CallMeMaybeType::RESPONDER => {
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
                telio_log_trace!("CallMeMaybe event occured: {:?}", call_me_maybe_msg);
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
#[derive(Debug)]
pub struct EndpointConnectivityCheckState<E: Backoff> {
    public_key: PublicKey,
    local_endpoint_candidate: EndpointCandidate,
    state: EndpointState::Variant,
    last_state_transition: Instant,
    last_validated_enpoint: Option<SocketAddr>,
    exponential_backoff: E,
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
        if let PublishedByPublish(m) = self.state.clone() {
            telio_log_info!(
                "Endpoint gone, next retry after {}s",
                self.exponential_backoff.get_backoff().as_secs_f64()
            );
            do_state_transition!(m, EndpointGone, self);
        }
        Ok(())
    }

    fn handle_endpoint_succesfull_notification(&mut self) {
        if let PublishedByPublish(_) = self.state.clone() {
            self.exponential_backoff.reset();
        }
    }

    async fn handle_call_me_maybe_response_rxed_event(
        &mut self,
        session_id: Session,
        (public_key, message): (PublicKey, CallMeMaybeMsg),
        ep_providers: Vec<Arc<dyn EndpointProvider>>,
    ) -> Result<(), Error> {
        match self.state.clone() {
            EndpointGatheringBySendCallMeMaybeRequest(m) => {
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

                do_state_transition!(m, ReceiveCallMeMaybeResponse, self);
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
        match self.state.clone() {
            PingByReceiveCallMeMaybeResponse(m) => {
                let nice_ep_provider = matches!(
                    event.msg.get_ponging_ep_provider(),
                    Ok(Some(telio_model::api_config::EndpointProvider::Local))
                        | Ok(Some(telio_model::api_config::EndpointProvider::Upnp))
                );
                if let Ok(ping_source) = event.msg.get_ping_source_address() {
                    if ping_source == self.local_endpoint_candidate.udp.ip() || nice_ep_provider {
                        let remote_endpoint =
                            SocketAddr::new(event.addr.ip(), event.msg.get_wg_port().0);
                        let wg_publish_event = WireGuardEndpointCandidateChangeEvent {
                            public_key: self.public_key,
                            remote_endpoint,
                            local_endpoint: self.local_endpoint_candidate.wg,
                        };
                        telio_log_info!("Publishing validated WG endpoint: {:?}", wg_publish_event);
                        wg_ep_publisher.send(wg_publish_event).await?;
                        self.last_validated_enpoint = Some(remote_endpoint);
                        do_state_transition!(m, Publish, self);
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

    async fn handle_tick_event(
        &mut self,
        session: Session,
        intercoms: chan::Tx<(PublicKey, CallMeMaybeMsg)>,
    ) -> Result<(), Error> {
        let duration_in_state = Instant::now() - self.last_state_transition;
        let timeout = CPC_TIMEOUT; // TODO: make configurable

        match self.state.clone() {
            EndpointGatheringBySendCallMeMaybeRequest(m) => {
                if duration_in_state > timeout {
                    // Timeout occured
                    telio_log_debug!(
                        "Timeout waiting for CMM response, next retry after {}s",
                        self.exponential_backoff.get_backoff().as_secs_f64()
                    );
                    do_state_transition!(m, Timeout, self);
                }
            }
            PingByReceiveCallMeMaybeResponse(m) => {
                if duration_in_state > timeout {
                    // Timeout occured
                    telio_log_debug!(
                        "Timeout waiting for pongs, next retry after {}s",
                        self.exponential_backoff.get_backoff().as_secs_f64()
                    );
                    do_state_transition!(m, Timeout, self);
                }
            }
            InitialDisconnected(m) => {
                self.send_call_me_maybe_request(session, intercoms).await?;
                do_state_transition!(m, SendCallMeMaybeRequest, self);
            }
            DisconnectedByTimeout(m) => {
                if duration_in_state > self.exponential_backoff.get_backoff() {
                    self.exponential_backoff.next_backoff();
                    self.send_call_me_maybe_request(session, intercoms).await?;
                    do_state_transition!(m, SendCallMeMaybeRequest, self);
                }
            }
            DisconnectedByEndpointGone(m) => {
                if duration_in_state > self.exponential_backoff.get_backoff() {
                    self.exponential_backoff.next_backoff();
                    self.send_call_me_maybe_request(session, intercoms).await?;
                    do_state_transition!(m, SendCallMeMaybeRequest, self);
                }
            }
            _ => {}
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::Duration,
    };

    use tokio::{
        sync::mpsc::{Receiver, Sender},
        time::{self, Instant},
    };

    use assert_matches::assert_matches;

    use telio_crypto::{PublicKey, SecretKey};
    use telio_model::{
        config::{Config, Peer, PeerBase},
        SocketAddr,
    };
    use telio_proto::{PingerMsg, WGPort};

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
            Duration::from_secs(2),
            Arc::new(Mutex::new(PingPongHandler::new(SecretKey::gen()))),
            ExponentialBackoffBounds::default(),
        );

        let channels = TestChannels {
            endpoint_change_subscriber: endpoint_change_subscriber.tx,
            pong_rx_events: pong_rx_events.tx,
            wg_endpoint_publish_events: wg_endpoint_publish_events.rx,
            intercoms: intercoms,
        };

        Ok((checker, channels))
    }

    async fn validate_endpoint(
        channels: &mut TestChannels,
        endpoint: SocketAddr,
        original_pub_key: PublicKey,
    ) {
        channels
            .endpoint_change_subscriber
            .send((
                EndpointProviderType::LocalInterfaces,
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
            .pong(
                WGPort(2),
                &endpoint.ip(),
                telio_model::api_config::EndpointProvider::Local,
            )
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
        state: EndpointState::Variant,
        endpoint: SocketAddr,
    ) -> EndpointConnectivityCheckState<MockBackoff> {
        EndpointConnectivityCheckState {
            public_key: PublicKey::default(),
            local_endpoint_candidate: EndpointCandidate {
                wg: endpoint,
                udp: endpoint,
            },
            state,
            last_state_transition: Instant::now(),
            last_validated_enpoint: None,
            exponential_backoff: MockBackoff::default(),
        }
    }

    async fn wait_for_tick() {
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn get_validated_endpoints() {
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
        validate_endpoint(&mut channels, endpoint, original_pub_key).await;
        let change_event = &checker.get_validated_endpoints().await.unwrap()[&original_pub_key];

        assert!(change_event.public_key == original_pub_key);
        assert!(change_event.local_endpoint == endpoint);
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
        validate_endpoint(&mut channels, endpoint, original_pub_key).await;
        assert!(!checker.get_validated_endpoints().await.unwrap().is_empty());
        checker
            .notify_failed_wg_connection(original_pub_key)
            .await
            .unwrap();

        assert!(checker.get_validated_endpoints().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_send_cmm_request() {
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            Machine::new(Disconnected).as_enum(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        );
        let intercoms = Chan::default();

        endpoint_connectivity_check_state
            .handle_tick_event(0, intercoms.tx)
            .await
            .unwrap();

        assert_matches!(
            endpoint_connectivity_check_state.state,
            EndpointGatheringBySendCallMeMaybeRequest(_)
        );
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_receive_cmm_response() {
        let mut endpoint_provider_mock = MockEndpointProvider::new();
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        endpoint_provider_mock
            .expect_send_ping()
            .returning(|_, _, _| Ok(()));
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            Machine::new(Disconnected)
                .transition(SendCallMeMaybeRequest)
                .as_enum(),
            endpoint,
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

        assert_matches!(
            endpoint_connectivity_check_state.state,
            PingByReceiveCallMeMaybeResponse(_)
        );
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_publish() {
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            Machine::new(Disconnected)
                .transition(SendCallMeMaybeRequest)
                .transition(ReceiveCallMeMaybeResponse)
                .as_enum(),
            endpoint,
        );

        let msg = PingerMsg::ping(WGPort(2), 1, 10_u64)
            .pong(
                WGPort(2),
                &endpoint.ip(),
                telio_model::api_config::EndpointProvider::Local,
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

        assert_matches!(
            endpoint_connectivity_check_state.state,
            PublishedByPublish(_)
        );
    }

    #[tokio::test]
    async fn endpoint_connectivity_check_state_endpoint_gone() {
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            Machine::new(Disconnected)
                .transition(SendCallMeMaybeRequest)
                .transition(ReceiveCallMeMaybeResponse)
                .transition(Publish)
                .as_enum(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        );

        endpoint_connectivity_check_state
            .handle_endpoint_gone_notification()
            .await
            .unwrap();

        assert_matches!(
            endpoint_connectivity_check_state.state,
            DisconnectedByEndpointGone(_)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn endpoint_connectivity_check_state_timeout_endpoint_gathering() {
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            Machine::new(Disconnected)
                .transition(SendCallMeMaybeRequest)
                .as_enum(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        );

        time::advance(Duration::from_secs(11)).await;
        endpoint_connectivity_check_state
            .handle_tick_event(0, Chan::default().tx)
            .await
            .unwrap();

        assert_matches!(
            endpoint_connectivity_check_state.state,
            DisconnectedByTimeout(_)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn endpoint_connectivity_check_state_timeout_ping() {
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            Machine::new(Disconnected)
                .transition(SendCallMeMaybeRequest)
                .as_enum(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        );

        time::advance(Duration::from_secs(11)).await;
        endpoint_connectivity_check_state
            .handle_tick_event(0, Chan::default().tx)
            .await
            .unwrap();

        assert_matches!(
            endpoint_connectivity_check_state.state,
            DisconnectedByTimeout(_)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn exponential_backoff_on_failure() {
        let mut endpoint_connectivity_check_state = prepare_test_session_in_state(
            Machine::new(Disconnected).as_enum(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        );

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
            Machine::new(Disconnected)
                .transition(SendCallMeMaybeRequest)
                .as_enum(),
            endpoint,
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

        assert_matches!(
            endpoint_connectivity_check_state.state,
            PingByReceiveCallMeMaybeResponse(_)
        );
    }
}
