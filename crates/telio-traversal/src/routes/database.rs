use sm::sm;

use multi_map::MultiMap;
use telio_crypto::PublicKey;
use telio_proto::{PeerId, Session, Timestamp};

use std::{
    collections::HashMap,
    fmt, iter,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error as ThisError;
use tokio::{
    net::UdpSocket,
    sync::mpsc::{error::TrySendError as ChanTrySendError, OwnedPermit},
    time::{Duration, Instant},
};

use telio_proto::{CallMeMaybeMsgDeprecated, Codec, DataMsg, PingerMsgDeprecated};
use telio_task::io::{chan::*, Chan, ChanSendError};
use telio_utils::telio_log_debug;

use crate::RouteError;

pub type TxPeerId = PeerId;
pub type RxPeerId = PeerId;

type Result<T> = std::result::Result<T, Error>;

/// Posible [Database] errors.
#[derive(ThisError, Debug)]
pub enum Error {
    /// Current peer's state is invalid for selected action
    #[error("Current state is invalid")]
    InvalidCurrentState,
    /// Control channel is closed (or overflowed)
    #[error(transparent)]
    ControlChanErr(#[from] ChanSendError<(PublicKey, CallMeMaybeMsgDeprecated)>),
    #[error(transparent)]
    ControlChanTryErr(#[from] ChanTrySendError<(PublicKey, CallMeMaybeMsgDeprecated)>),
    /// TxPeerId is not populated on peer's entry
    #[error("No TxPeerId info")]
    NoTxPeerId,
    /// Haven't received any endpoints of remote node yet
    #[error("Endpoint's candidate list is empty")]
    EndpointCandidateMissing,
    /// Packet's address invalid
    #[error("Unexpected packet's address")]
    EndpointMismatch,
    /// Negative or zero timestamp
    #[error("Received with invalid timestamp")]
    InvalidTimestamp,
    /// Received with bad session number
    #[error("Current and received session mismatch")]
    SessionMismatch,
    /// Received packet, that wasn't expected at this state
    #[error("Received unexpected packet")]
    UnexpectedPacket,
    /// UDP socket error
    #[error(transparent)]
    Socket(#[from] std::io::Error),
    /// Data channel is closed (or overflowed)
    #[error(transparent)]
    DataChanErr(#[from] ChanSendError<(PublicKey, DataMsg)>),
    /// Event channel is closed (or overflowed)
    #[error(transparent)]
    EventChanErr(#[from] ChanSendError<(PublicKey, bool)>),
    /// Event channel is closed (or overflowed)
    #[error(transparent)]
    EventChanTryErr(#[from] ChanTrySendError<(PublicKey, bool)>),
    /// Peer is not present in Route module
    #[error("Node's public key not found")]
    PublicKeyNotFound,
    /// Route is yet to be activated
    #[error("Path to node not connected")]
    PathDisconnected,
    /// Route error
    #[error(transparent)]
    Route(#[from] RouteError),
    /// Someting is wrong with serializing/deserializing packet
    #[error(transparent)]
    PacketCodec(#[from] telio_proto::CodecError),
}

macro_rules! log_state_change {
    ($pk:expr, $previous:literal, $current:literal, $action:literal) => {{
        telio_log_debug!(
            "Peer ({:?}) state transition: {} --> {}, by action: {}",
            $pk,
            $previous,
            $current,
            $action
        );
    }};
}

// State machine definition
sm! {
    RouteState {
        InitialStates { Disconnected }

        Start {
            Disconnected => SentCallMeMaybe
        }

        Ping {
            SentCallMeMaybe => Pinging
        }

        Activate {
            Disconnected, SentCallMeMaybe, Pinging, => Connected
        }

        Break {
            SentCallMeMaybe, Pinging, Connected => Disconnected
        }
    }

    // Disconnected - node was just added or path was just broken
    // SentCallMeMaybe - we've sent a CallMeMaybe message as initiator to other node and waiting for reply
    // Pinging - we've received CallMeMaybe response and sent PingMsg packets to all remote_endpoints
    // Connected -
    //      (Scenario 1 - initiator) we've received all pings, decided which remote endpoint to use.
    //      (Scenario 2 - repsonder) - we've received DataMsg packet from remote peer, update remote endpoint and started communicating.
}

pub type AbsRouteState = RouteState::Variant;
pub type CurrentRouteState = (RouteState::Variant, Duration);

#[derive(Debug, Clone, Copy)]
pub enum Latency {
    Unknown,
    Measured(Duration),
}

#[derive(Clone)]
pub struct Metric {
    /// Current ping session (Some() - if it is ongoing)
    ping_session: Option<Session>,
    /// Start of ping session or actual measure update
    last_measure: Instant,
    /// Actual measured latency
    latency: Latency,
}

impl Default for Metric {
    fn default() -> Self {
        Self {
            ping_session: None,
            last_measure: Instant::now(),
            latency: Latency::Unknown,
        }
    }
}

impl fmt::Debug for Metric {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ping session: {:?}, ", self.ping_session)?;
        write!(
            f,
            "Last measure: {} secs, ",
            self.last_measure.elapsed().as_secs()
        )?;
        write!(f, "Latency: {:?}, ", self.latency)
    }
}

/// Entry of nodes database.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Peer ID, that is added to packet when TX'ing (created by 'them')
    tx_peer_id: Option<TxPeerId>,
    /// Peer ID, that is looked when RX'ing (created by 'us')
    rx_peer_id: RxPeerId,
    /// Remote address of node
    remote_endpoint: Option<SocketAddr>,
    /// Timestamp of last received packet from node
    last_rx: Instant,
    /// Timestamp of last state transition event
    last_sm_transition: Instant,
    /// Current status of path to node
    state: RouteState::Variant,
    /// Current traversal session
    trav_session: Option<Session>,
    /// Candidates for current traversal session, to be delegated as endpoint
    candidates: Option<HashMap<SocketAddr, Option<Duration>>>,
    /// Peer's public key
    pub pk: PublicKey,
    /// Peer's path's metric
    metric: Option<Metric>,
}

impl Entry {
    /// Entry's constructor
    pub fn new(rx_peer_id: RxPeerId, pk: PublicKey) -> Self {
        Entry {
            tx_peer_id: None,
            rx_peer_id,
            remote_endpoint: None,
            last_rx: Instant::now(),
            last_sm_transition: Instant::now(),
            state: RouteState::Machine::new(RouteState::Disconnected).as_enum(),
            trav_session: None,
            candidates: None,
            pk,
            metric: None,
        }
    }

    pub async fn start_sent_call_me_maybe<N: Iterator<Item = SocketAddr>>(
        &mut self,
        chan: &Chan<(PublicKey, CallMeMaybeMsgDeprecated)>,
        addrs: N,
        events: &Tx<(PublicKey, bool)>,
    ) -> Result<()> {
        // Sanity check
        if self.is_disconnected().is_none() {
            self.disconnect_route(events)?;
        }

        // Changing state
        self.state = match self.state.clone() {
            RouteState::Variant::DisconnectedByBreak(m) => {
                log_state_change!(self.pk, "DisconnectedByBreak", "SentCallMeMaybe", "Start");
                m.transition(RouteState::Start).as_enum()
            }
            RouteState::Variant::InitialDisconnected(m) => {
                log_state_change!(self.pk, "InitialDisconnected", "SentCallMeMaybe", "Start");
                m.transition(RouteState::Start).as_enum()
            }
            _ => {
                return Err(Error::InvalidCurrentState);
            }
        };

        self.last_sm_transition = Instant::now();

        // Creating new traverse session
        let session = self.trav_session.insert(Self::new_session());

        // Creating and sending CallMeMaybe request
        let msg = CallMeMaybeMsgDeprecated::new(true, addrs, *session, self.rx_peer_id);

        chan.tx
            .try_send((self.pk, msg))
            .map_or_else(|e| Err(Error::ControlChanTryErr(e)), |_| Ok(()))
    }

    pub async fn start_pinging<N: Iterator<Item = SocketAddr>>(
        &mut self,
        endpoints: N,
        socket: &UdpSocket,
    ) -> Result<()> {
        // Sanity check
        if self.is_sent_cmm().is_none() {
            return Err(Error::InvalidCurrentState);
        }

        // Changing state
        self.state = match self.state.clone() {
            RouteState::Variant::SentCallMeMaybeByStart(m) => {
                log_state_change!(self.pk, "SentCallMeMaybeByStart", "Pinging", "Ping");
                self.last_sm_transition = Instant::now();
                m.transition(RouteState::Ping).as_enum()
            }
            _ => {
                return Err(Error::InvalidCurrentState);
            }
        };

        // Creating candidates list
        let candidates_map = self.candidates.insert(HashMap::new());
        for endpoint in endpoints {
            candidates_map.insert(endpoint, None);
        }

        // Fetching session id
        let session = self.trav_session.get_or_insert(Self::new_session());

        // Pinging endpoints
        let _ = Self::ping_endpoints(
            self.tx_peer_id.ok_or(Error::NoTxPeerId)?,
            candidates_map.iter_mut().map(|(addr, _)| *addr),
            socket,
            *session,
        )
        .await;

        Ok(())
    }

    /// Change route's state to [`RouteState::Variant::Connected`] and update endpoint
    pub async fn connect_route(
        &mut self,
        endpoint: &SocketAddr,
        latency: Latency,
        events: &Tx<(PublicKey, bool)>,
        socket: &UdpSocket,
    ) -> Result<()> {
        if !self.is_cmm_handshake_complete() {
            return Err(Error::NoTxPeerId);
        }

        let _ = self.remote_endpoint.insert(*endpoint);

        self.trav_session = None;
        self.candidates = None;
        self.switch_route(true);
        self.last_rx = Instant::now();

        self.metric = Some(Metric::default());
        self.update_metric(latency)?;

        let _ = events.try_send((self.pk, true));

        // So we've connected a route with no knowledge
        // about its performance, so let's measure it
        if matches!(latency, Latency::Unknown) {
            self.start_measuring_metric(socket).await?;
        }

        Ok(())
    }

    /// Change route's state to [`RouteState::Variant::Disconnected`]
    pub fn disconnect_route(&mut self, events: &Tx<(PublicKey, bool)>) -> Result<()> {
        self.remote_endpoint = None;
        self.trav_session = None;
        self.candidates = None;
        self.metric = None;
        self.switch_route(false);
        let _ = events.try_send((self.pk, false));

        Ok(())
    }

    /// Chooses the route from a candidates list, if the peer is currently in [`RouteState::Variant::Pinging`] state,
    /// and already received some 'Pongs'
    pub async fn choose_route(
        &mut self,
        events: &Tx<(PublicKey, bool)>,
        socket: &UdpSocket,
    ) -> Result<()> {
        if self.is_pinging().is_none() {
            return Err(Error::InvalidCurrentState);
        }

        let (mut remote_endpoint, mut latency) = (None, Latency::Unknown);

        // Choosing which endpoint has lowest latency, filtering out the ones, which haven't rx'ed pings
        if let Some(candidates) = &mut self.candidates {
            let (re, lt) = candidates
                .iter_mut()
                .filter(|(_, dur)| dur.is_some())
                .min_by(|x, y| {
                    x.1.clone()
                        .get_or_insert(Duration::MAX)
                        .cmp(&(y.1.clone().get_or_insert(Duration::MAX)))
                })
                .ok_or(Error::EndpointCandidateMissing)?;

            remote_endpoint = Some(*re);

            // TODO we need to make sure that it is not Duration::MAX
            latency = match *lt {
                Some(l) => Latency::Measured(l),
                None => Latency::Unknown,
            };

            telio_log_debug!(
                "Peer {:?} choosing endpoint {} with latency {:?}",
                self.pk,
                re,
                latency,
            );
        }

        if let Some(endp) = remote_endpoint {
            return self.connect_route(&endp, latency, events, socket).await;
        }

        telio_log_debug!("Peer {:?} failed to choose route", self.pk);

        Err(Error::EndpointCandidateMissing)
    }

    /// Returns [`Some(Duration)`] since measuring started if it is in actually measuring,
    /// otherwise - [`None`]
    pub async fn start_measuring_metric(&mut self, socket: &UdpSocket) -> Result<()> {
        // Stop current measurement, if we decided to fire up a new one
        if self.is_measuring_metric().is_some() {
            self.update_metric(Latency::Unknown)?;
        }

        if self.is_connected().is_some() {
            if let Some(metric) = &mut self.metric {
                // Fetching session id
                let session = metric.ping_session.get_or_insert(Self::new_session());

                telio_log_debug!("Peer {:?} starting to measure latency ...", self.pk);

                // Pinging endpoints
                return Self::ping_endpoints(
                    self.tx_peer_id.ok_or(Error::NoTxPeerId)?,
                    iter::once(
                        self.remote_endpoint
                            .ok_or(Error::EndpointCandidateMissing)?,
                    ),
                    socket,
                    *session,
                )
                .await;
            }
        }

        Err(Error::InvalidCurrentState)
    }

    /// Returns [`Some(Duration , Session)`] since measuring started if it is actually measuring,
    /// otherwise - [`None`]
    pub fn is_measuring_metric(&self) -> Option<(Duration, Session)> {
        if self.is_connected().is_some() {
            if let Some(metric) = &self.metric {
                if let Some(sess) = metric.ping_session {
                    return Some((metric.last_measure.elapsed(), sess));
                }
            }
        }

        None
    }

    /// Returns [`Some(Duration)`] since last completed metric measurement,
    /// otherwise - [`None`]
    pub fn last_metric_measure(&self) -> Option<Duration> {
        //  We should be connected and not in progress of measuring metric
        if self.is_connected().is_some() && self.is_measuring_metric().is_none() {
            if let Some(metric) = &self.metric {
                return Some(metric.last_measure.elapsed());
            }
        }

        None
    }

    /// Update state of metric, end the metric measurement phase
    pub fn update_metric(&mut self, latency: Latency) -> Result<()> {
        if let Some(metric) = &mut self.metric {
            metric.latency = latency;
            metric.ping_session = None;
            metric.last_measure = Instant::now();

            return Ok(());
        }

        Err(Error::InvalidCurrentState)
    }

    /// Returns [`Some(Duration)`] since transition to [`RouteState::Variant::Pinging`] if it is in that state,
    /// otherwise [`None`] if it is other state
    pub fn is_pinging(&self) -> Option<Duration> {
        if matches!(self.state, RouteState::Variant::PingingByPing(_))
            && self.remote_endpoint.is_none()
            && self.trav_session.is_some()
            && self.candidates.is_some()
            && self.is_cmm_handshake_complete()
            && self.metric.is_none()
        {
            return Some(self.last_sm_transition.elapsed());
        }

        None
    }

    /// Returns [`Some(Duration)`] since transition to [`RouteState::Variant::SentCallMeMaybe`] if it is in that state,
    /// otherwise [`None`] if it is other state
    pub fn is_sent_cmm(&self) -> Option<Duration> {
        if matches!(self.state, RouteState::Variant::SentCallMeMaybeByStart(_))
            && self.trav_session.is_some()
            && self.remote_endpoint.is_none()
            && self.candidates.is_none()
            && self.metric.is_none()
        {
            return Some(self.last_sm_transition.elapsed());
        }

        None
    }

    /// Returns [`Some(Duration)`] since last rx'ed packet if entry's route is enabled,
    /// otherwise [`None`] if it isn't connected
    pub fn is_connected(&self) -> Option<Duration> {
        if matches!(self.state, RouteState::Variant::ConnectedByActivate(_))
            && self.trav_session.is_none()
            && self.candidates.is_none()
            && self.remote_endpoint.is_some()
            && self.is_cmm_handshake_complete()
            && self.metric.is_some()
        {
            return Some(self.last_rx.elapsed());
        }

        None
    }

    /// Returns [`Some(Duration)`] since transition to disconnected if it is disconnected,
    /// otherwise [`None`] if it is connected
    pub fn is_disconnected(&self) -> Option<Duration> {
        if matches!(
            self.state,
            RouteState::Variant::DisconnectedByBreak(_)
                | RouteState::Variant::InitialDisconnected(_)
        ) && self.remote_endpoint.is_none()
            && self.trav_session.is_none()
            && self.candidates.is_none()
            && self.metric.is_none()
        {
            return Some(self.last_sm_transition.elapsed());
        }

        None
    }

    /// Returns [`true`] if peer has received cmm init or response,
    /// and updated its tx_peer_id
    pub fn is_cmm_handshake_complete(&self) -> bool {
        self.tx_peer_id.is_some()
    }

    /// Returns [`Some(Latency)`] of entry in microseconds, if the entry is connected
    pub fn get_metric(&self) -> Option<Latency> {
        if self.is_connected().is_some() {
            if let Some(m) = &self.metric {
                return Some(m.latency);
            }
        }

        None
    }

    /// Returns [`CurrentRouteState`] of entry (actual state + duration since last transition)
    pub fn get_state(&self) -> CurrentRouteState {
        (self.state.clone(), self.last_sm_transition.elapsed())
    }

    /// Returns [`Option<Session>`] of entry
    pub fn get_traversal_session(&self) -> Option<Session> {
        self.trav_session
    }

    /// Returns [`Option<Session>`] of entry
    pub fn get_tx_peer_id(&self) -> Result<TxPeerId> {
        self.tx_peer_id.ok_or(Error::NoTxPeerId)
    }

    /// Update state of entry, if it has received a packet from other end
    pub async fn handle_data_packet_rx(
        &mut self,
        remote_addr: &SocketAddr,
        events: &Tx<(PublicKey, bool)>,
        socket: &UdpSocket,
    ) -> Result<()> {
        if self.is_connected().is_none() {
            return self
                .connect_route(remote_addr, Latency::Unknown, events, socket)
                .await;
        }

        if let Some(endp) = self.remote_endpoint {
            if endp == *remote_addr {
                self.last_rx = Instant::now();
                return Ok(());
            }

            return Err(Error::EndpointMismatch);
        }

        // Shouldn't happen
        Err(Error::InvalidCurrentState)
    }

    pub fn handle_pong_rx(
        &mut self,
        remote_addr: &SocketAddr,
        pong_sess: Session,
        pong_ts: Timestamp,
    ) -> Result<()> {
        let curr_ts = Self::get_timestamp();

        // Sanity check
        if pong_ts >= curr_ts {
            return Err(Error::InvalidTimestamp);
        }

        let latency = Duration::from_micros(curr_ts - pong_ts);

        // [`Pong`] is expected while [`RouteState::Variant::Pinging`] or [`RouteState::Variant::Connected`]
        if self.is_pinging().is_some() {
            // Handle Pong from `RouteState::Variant::Pinging` state
            if Some(pong_sess) != self.get_traversal_session() {
                return Err(Error::SessionMismatch);
            }

            let _ = self
                .candidates
                .as_mut()
                .and_then(|c| c.get_mut(remote_addr))
                .ok_or(Error::UnexpectedPacket)?
                .insert(latency);

            telio_log_debug!(
                "Peer {:?} received PingerMsgDeprecated::Pong from {} endpoint, latency: {} millis",
                self.pk,
                remote_addr,
                latency.as_millis()
            );

            self.last_rx = Instant::now();

            return Ok(());
        } else if let Some((_, expected_session)) = self.is_measuring_metric() {
            // Handle Pong from metrics measurement
            if pong_sess != expected_session {
                return Err(Error::SessionMismatch);
            }

            telio_log_debug!(
                "Peer's {:?} current metric is {} millis",
                self.pk,
                latency.as_millis()
            );

            self.last_rx = Instant::now();

            return self.update_metric(Latency::Measured(latency));
        }

        Err(Error::InvalidCurrentState)
    }

    pub async fn handle_cmm_init_rx<'a, N: Iterator<Item = SocketAddr>>(
        &self,
        offered_addrs: N,
        our_addrs: N,
        sess: Session,
        socket: &UdpSocket,
        permit: OwnedPermit<(PublicKey, CallMeMaybeMsgDeprecated)>,
    ) -> Result<()> {
        // Pinging endpoints (session is `0`, because this `Ping` is only serving a prupose to punch a hole in 'our' NAT)
        let _ = Self::ping_endpoints(
            self.tx_peer_id.ok_or(Error::NoTxPeerId)?,
            offered_addrs,
            socket,
            0,
        )
        .await;

        // Creating and sending CallMeMaybe request
        let msg = CallMeMaybeMsgDeprecated::new(false, our_addrs, sess, self.rx_peer_id);

        // Sending CallMeMaybe response
        permit.send((self.pk, msg));

        Ok(())
    }

    // Ping a list of endpoints
    async fn ping_endpoints<N: Iterator<Item = SocketAddr>>(
        tx_peer_id: TxPeerId,
        endpoints: N,
        socket: &UdpSocket,
        sess: Session,
    ) -> Result<()> {
        // Pinging endpoints
        for endpoint in endpoints {
            let msg =
                PingerMsgDeprecated::ping(tx_peer_id, sess, Self::get_timestamp()).encode()?;
            socket.send_to(&msg, endpoint).await?;
        }

        Ok(())
    }

    /// Connect or disconnect route
    fn switch_route(&mut self, connected: bool) {
        self.trav_session = None;

        let _old_state = self.state.clone();

        match &mut self.state {
            RouteState::Variant::InitialDisconnected(m) => {
                if connected {
                    log_state_change!(self.pk, "InitialDisconnected", "Connected", "Activate");
                    self.state = m.clone().transition(RouteState::Activate).as_enum();
                }
            }
            RouteState::Variant::SentCallMeMaybeByStart(m) => {
                self.state = if connected {
                    log_state_change!(self.pk, "SentCallMeMaybeByStart", "Connected", "Activate");
                    m.clone().transition(RouteState::Activate).as_enum()
                } else {
                    log_state_change!(self.pk, "SentCallMeMaybeByStart", "Disconnected", "Break");
                    m.clone().transition(RouteState::Break).as_enum()
                };
            }
            RouteState::Variant::PingingByPing(m) => {
                self.state = if connected {
                    log_state_change!(self.pk, "PingingByPing", "Connected", "Activate");
                    m.clone().transition(RouteState::Activate).as_enum()
                } else {
                    log_state_change!(self.pk, "PingingByPing", "Disconnected", "Break");
                    m.clone().transition(RouteState::Break).as_enum()
                };
            }
            RouteState::Variant::ConnectedByActivate(m) => {
                if !connected {
                    log_state_change!(self.pk, "ConnectedByActivate", "Disconnected", "Break");
                    self.state = m.clone().transition(RouteState::Break).as_enum();
                }
            }
            RouteState::Variant::DisconnectedByBreak(m) => {
                if connected {
                    log_state_change!(self.pk, "DisconnectedByBreak", "Connected", "Activate");
                    self.state = m.clone().transition(RouteState::Activate).as_enum();
                }
            }
        }

        if !matches!(self.state.clone(), _old_state) {
            self.last_sm_transition = Instant::now();
        }
    }

    /// Get time in microseconds since UNIX_EPOCH
    fn get_timestamp() -> Timestamp {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }

    /// Get new session ID unique in app instance scope
    fn new_session() -> Session {
        rand::random::<Session>()
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TxPeerId: {:?}, ", self.tx_peer_id)?;
        write!(f, "RxPeerId: {:?}, ", self.rx_peer_id)?;
        write!(f, "Remote: {:?}, ", self.remote_endpoint)?;
        write!(
            f,
            "LastRx: {} secs. ago, ",
            self.last_rx.elapsed().as_secs()
        )?;
        write!(f, "Traversal session: {:?}, ", self.trav_session)?;
        write!(f, "PublicKey: {:?}, ", self.pk)?;
        write!(f, "Metrics: {:?}, ", self.metric)?;
        write!(f, "State: ")?;

        match &mut self.get_state() {
            (RouteState::Variant::DisconnectedByBreak(_), d) => {
                write!(f, "'Disconnected' for {}", d.as_secs())?;
            }
            (RouteState::Variant::InitialDisconnected(_), d) => {
                write!(f, "'Initially disconnected' for {}", d.as_secs())?;
            }
            (RouteState::Variant::SentCallMeMaybeByStart(_), d) => {
                write!(f, "'Sent CallMeMaybe' for {}", d.as_secs())?;
            }
            (RouteState::Variant::PingingByPing(_), d) => {
                write!(f, "'Pinging' for {}", d.as_secs())?;
            }
            (RouteState::Variant::ConnectedByActivate(_), d) => {
                write!(f, "'Connected' for {}", d.as_secs())?;
            }
        }

        write!(f, " secs")
    }
}

#[derive(Debug)]
pub struct Database {
    /// Next assignable peer_id
    pid_cnt: u16,
    /// Cache, for assigning peer ids
    pid_cache: HashMap<PublicKey, RxPeerId>,
    /// Nodes storage
    entries: MultiMap<PublicKey, RxPeerId, Entry>,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            // Naively reserving "0" for debug purposes
            pid_cnt: 1,
            pid_cache: HashMap::new(),
            entries: MultiMap::new(),
        }
    }
}

impl Database {
    /// Inserts a bunch of entries to db and start traversal procedure
    pub fn insert<N: Iterator<Item = PublicKey>>(&mut self, pks: N) {
        // Filter-out existing keys
        let keys: Vec<PublicKey> = pks.filter(|key| !self.entries.contains_key(key)).collect();

        for key in keys {
            let rx_peer_id = self.generate_rx_peer_id(&key);
            self.entries
                .insert(key, rx_peer_id, Entry::new(rx_peer_id, key));
        }
    }

    /// Deletes one entry from db
    pub fn remove(&mut self, pk: &PublicKey) -> Option<Entry> {
        self.entries.remove(pk)
    }

    /// Get entries count
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Deletes all entries
    pub fn flush(&mut self) {
        self.entries = MultiMap::new();
    }

    pub fn iter_mut(&mut self) -> multi_map::IterMut<'_, PublicKey, RxPeerId, Entry> {
        self.entries.iter_mut()
    }

    pub fn iter(&self) -> multi_map::Iter<'_, PublicKey, RxPeerId, Entry> {
        self.entries.iter()
    }

    pub fn contains_key(&self, key: &PublicKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Get mutable entry by public key
    pub fn get_mut_entry_by_pk(&mut self, pk: &PublicKey) -> Result<&mut Entry> {
        self.entries.get_mut(pk).ok_or(Error::PublicKeyNotFound)
    }

    /// Get mutable entry by public key
    pub fn get_entry_by_pk(&self, pk: &PublicKey) -> Result<&Entry> {
        self.entries.get(pk).ok_or(Error::PublicKeyNotFound)
    }

    /// Get mutable entry by rx_peer_id
    pub fn get_mut_entry_by_pid(&mut self, peer_id: RxPeerId) -> Result<&mut Entry> {
        self.entries
            .get_mut_alt(&peer_id)
            .ok_or(Error::PublicKeyNotFound)
    }

    /// Update entrie's tx_peer_id.
    pub fn update_tx_peer_id(&mut self, pk: &PublicKey, tx_peer_id: TxPeerId) -> Result<()> {
        let _ = self
            .entries
            .get_mut(pk)
            .ok_or(Error::PublicKeyNotFound)?
            .tx_peer_id
            .insert(tx_peer_id);

        telio_log_debug!("Associated peer {:?} with {:?}", pk, tx_peer_id);

        Ok(())
    }

    /// Information for Tx'ing packet
    pub fn get_packet_info_tx(&self, pub_key: &PublicKey) -> Result<(SocketAddr, TxPeerId)> {
        match self.entries.get(pub_key) {
            Some(entry) => {
                if entry.is_connected().is_some() {
                    return Ok((
                        entry.remote_endpoint.ok_or(Error::InvalidCurrentState)?,
                        entry.tx_peer_id.ok_or(Error::NoTxPeerId)?,
                    ));
                }

                Err(Error::PathDisconnected)
            }
            None => Err(Error::PublicKeyNotFound),
        }
    }

    /// Information for Rx'ing packet
    pub async fn get_packet_info_rx(
        &mut self,
        net_tuple: &(RxPeerId, SocketAddr),
        events: &Tx<(PublicKey, bool)>,
        socket: &UdpSocket,
    ) -> Result<PublicKey> {
        match self.entries.get_mut_alt_with_key(&net_tuple.0) {
            Some((key, entry)) => {
                entry
                    .handle_data_packet_rx(&net_tuple.1, events, socket)
                    .await?;
                Ok(*key)
            }
            None => Err(Error::PublicKeyNotFound),
        }
    }

    /// Get current traversal state for node
    pub fn get_state(&self, pub_key: &PublicKey) -> Result<()> {
        if let Some(ent) = self.entries.get(pub_key) {
            return ent
                .is_connected()
                .map_or_else(|| Err(Error::PathDisconnected), |_| Ok(()));
        }

        Err(Error::PublicKeyNotFound)
    }

    /// Get current metric for node
    pub fn get_rtt(&self, pub_key: &PublicKey) -> Result<Duration> {
        if let Some(ent) = self.entries.get(pub_key) {
            return ent.get_metric().map_or_else(
                || Err(Error::PathDisconnected),
                |m| match m {
                    Latency::Measured(d) => Ok(d),
                    Latency::Unknown => Err(Error::Route(RouteError::LatencyUnknown)),
                },
            );
        }

        Err(Error::Route(RouteError::NodeNotFound))
    }

    /// Generate Tx peer id
    fn generate_rx_peer_id(&mut self, pk: &PublicKey) -> RxPeerId {
        match self.pid_cache.get(pk) {
            Some(rpid) => *rpid,
            None => {
                let res = PeerId(self.pid_cnt);
                let _ = self.pid_cache.insert(*pk, res);
                self.pid_cnt += 1;
                res
            }
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    #[test]
    fn db_generate_peer_id() {
        let pubkey_list_0 = vec![
            "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
                .parse::<PublicKey>()
                .unwrap(),
            "GB2q5nJA3PUm/U5u3PAtLLmsLQ7nwCYo7YzfyYcjWzY="
                .parse::<PublicKey>()
                .unwrap(),
        ];

        let mut db = Database::default();

        // Checking, if it starts counting from 1
        db.insert(pubkey_list_0.clone().into_iter());
        let entry_0 = db.remove(&pubkey_list_0[0]).unwrap();
        let entry_1 = db.remove(&pubkey_list_0[1]).unwrap();

        assert_eq!(entry_0.rx_peer_id, PeerId(1));
        assert_eq!(entry_1.rx_peer_id, PeerId(2));

        // Checking, if it retains value after removal
        let pubkey_list_1 = vec!["GB2q5nJA3PUm/U5u3PAtLLmsLQ7nwCYo7YzfyYcjWzY="
            .parse::<PublicKey>()
            .unwrap()];
        db.insert(pubkey_list_1.clone().into_iter());
        let entry_2 = db.remove(&pubkey_list_1[0]).unwrap();

        assert_eq!(entry_1.rx_peer_id, entry_2.rx_peer_id);
    }

    #[tokio::test]
    async fn db_get_tx_rx_packet_info() {
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        // Creating a socket, from which this test will send packet to 'UdpHolePunch' obj
        let our_sock = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("Cannot create UdpSocket: ");

        let mut db = Database::default();

        let Chan { tx, mut rx } = Chan::default();

        tokio::spawn(async move { while let Some(_) = rx.recv().await {} });

        // tx_peer_id should 1
        db.insert(pubkey_list.clone().into_iter());

        // "Received" CallMeMaybeMsgDeprecated and updating peer_id on our end
        let _ = db.update_tx_peer_id(&pubkey_list[0], PeerId(3));

        // "Received" packet
        let rx_inf = db
            .get_packet_info_rx(
                &(PeerId(1), "127.0.0.1:8080".parse().unwrap()),
                &tx,
                &our_sock,
            )
            .await
            .unwrap();

        assert_eq!(rx_inf, pubkey_list[0]);

        // "Tx'ing" packet to a peer, packet info should be ready by now
        let (dst_addr, tx_peer_id) = db.get_packet_info_tx(&pubkey_list[0]).unwrap();

        assert_eq!(dst_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(tx_peer_id, PeerId(3));
    }
}
