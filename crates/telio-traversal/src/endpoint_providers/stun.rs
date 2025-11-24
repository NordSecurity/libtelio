use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{net::SocketAddr, sync::Arc, time::Duration};

use std::ops::Deref;

use async_trait::async_trait;
use futures::{future::pending, Future};
use stun_codec::TransactionId;
use telio_crypto::PublicKey;
use telio_model::config::Server;
use telio_proto::{Session, WGPort};
use telio_sockets::SocketPool;
use telio_sockets::{native::AsNativeSocket, External};
use telio_task::{io::chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    exponential_backoff::{Backoff, ExponentialBackoff, ExponentialBackoffBounds},
    telio_log_debug, telio_log_error, telio_log_info, telio_log_warn, PinnedSleep,
};
use telio_wg::{DynamicWg, WireGuard};
use tokio::{net::UdpSocket, pin, sync::Mutex};

use crate::{endpoint_providers::EndpointProviderType, ping_pong_handler::PingPongHandler};

use super::{EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, Error, PongEvent};

pub type StunServer = telio_model::config::Server;

const STUN_TIMEOUT_PAUSED: Duration = Duration::from_secs(600);
#[cfg(not(test))]
const STUN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const STUN_TIMEOUT: Duration = Duration::from_millis(300);

const MAX_PACKET_SIZE: usize = 1500;
const STUN_SOFTWARE: &str = "libtelio";

pub struct StunEndpointProvider<Wg: WireGuard = DynamicWg, E: Backoff = ExponentialBackoff> {
    task: Task<State<Wg, E>>,
}

/// Stack in-use by node
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum IpProto {
    /// Node can be reached only through IPv4 address
    IPv4,
    /// Node can be reached only through IPv6 address
    #[default]
    IPv6,
}

impl<Wg: WireGuard> StunEndpointProvider<Wg> {
    /// Start stun endpoint provider,
    /// # Params
    /// - `tun_socket` - udp socket bound to tun interface
    /// - `ext_socket` - udp socket bound to external interface
    /// - `wg` - wireguard controll
    /// - `exponential_backoff_bounds` - Config for exponential backoff
    ///   controlling intervals between consequtive queries to the STUN server
    pub fn start(
        wg: Arc<Wg>,
        exponential_backoff_bounds: ExponentialBackoffBounds,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        stun_peer_publisher: chan::Tx<Option<StunServer>>,
        is_battery_optimization_on: bool,
    ) -> Result<Self, Error> {
        Ok(Self::start_with_exp_backoff(
            wg,
            ExponentialBackoff::new(exponential_backoff_bounds)?,
            ping_pong_handler,
            stun_peer_publisher,
            is_battery_optimization_on,
        ))
    }

    /// Force STUN endpoint provider to reconnect
    pub async fn reconnect(&self) {
        let _ = task_exec!(&self.task, async move |s| {
            let _ = s.reconnect().await;
            Ok(())
        })
        .await;
    }
}

impl<Wg: WireGuard, E: Backoff> StunEndpointProvider<Wg, E> {
    fn start_with_exp_backoff(
        wg: Arc<Wg>,
        exponential_backoff: E,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        stun_peer_publisher: chan::Tx<Option<StunServer>>,
        is_battery_optimization_on: bool,
    ) -> Self {
        telio_log_info!("Starting stun endpoint provider");
        Self {
            task: Task::start(State {
                servers: vec![],
                current_server_index: 0,
                current_proto: IpProto::IPv6,
                wg,
                ping_pong_tracker: ping_pong_handler,
                change_event: None,
                pong_event: None,
                stun_session: None,
                exponential_backoff,
                current_timeout: PinnedSleep::new(STUN_TIMEOUT, ()),
                last_candidates: Vec::new(),
                stun_state: StunState::WaitingForWg,
                is_battery_optimization_on,
                stun_peer_publisher,
                sockets: None,
            }),
        }
    }

    pub async fn configure(
        &self,
        servers: Vec<Server>,
        use_ipv6: bool,
        socket_pool: Arc<SocketPool>,
    ) {
        self.configure_with_ext_socket_addr(servers, use_ipv6, socket_pool, Ipv4Addr::UNSPECIFIED)
            .await
    }

    async fn configure_with_ext_socket_addr(
        &self,
        mut servers: Vec<Server>,
        use_ipv6: bool,
        socket_pool: Arc<SocketPool>,
        ext_socket_addr: Ipv4Addr,
    ) {
        let _ = task_exec!(&self.task, async move |s| {
            // Check if we are running on the same IP stack
            // as is requested by new config
            let ip_version_changed = s.ipv6_is_enabled() != use_ipv6;

            // Create internal and external socket for STUN operation
            if s.sockets.is_none() || ip_version_changed {
                s.sockets = {
                    let tun_socket_v4 = match socket_pool
                        .new_internal_udp((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), None)
                        .await
                    {
                        Ok(tun_socket_v4) => {
                            telio_log_debug!(
                                "tun_socket_v4: {:?}",
                                tun_socket_v4.as_native_socket()
                            );
                            Some(Arc::new(tun_socket_v4))
                        }
                        Err(err) => {
                            telio_log_debug!("Could not create tun_socket_v4 for stun: {:?}", err);
                            None
                        }
                    };

                    let tun_socket_v6 = if use_ipv6 {
                        match socket_pool
                            .new_internal_udp((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0), None)
                            .await
                        {
                            Ok(tun_socket_v6) => {
                                telio_log_debug!(
                                    "tun_socket_v6: {:?}",
                                    tun_socket_v6.as_native_socket()
                                );
                                Some(Arc::new(tun_socket_v6))
                            }
                            Err(err) => {
                                telio_log_debug!(
                                    "Could not create tun_socket_v6 for stun: {:?}",
                                    err
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };

                    match socket_pool
                        .new_external_udp((ext_socket_addr, 0), None)
                        .await
                    {
                        Ok(ext_socket) => {
                            telio_log_debug!(
                                "ext_socket: {}",
                                ext_socket.deref().as_native_socket()
                            );

                            Some(StunSockets {
                                tun_socket_v4,
                                tun_socket_v6,
                                ext_socket,
                            })
                        }
                        Err(err) => {
                            telio_log_debug!("Could not create ext_socket for stun: {:?}", err);
                            None
                        }
                    }
                };
            }

            s.current_proto = if use_ipv6 {
                IpProto::IPv6
            } else {
                IpProto::IPv4
            };

            // Update server list
            servers.sort_by_key(|s| (s.weight, s.public_key));
            if s.servers != servers {
                servers.retain(|server| {
                    if server.stun_plaintext_port == 0 {
                        telio_log_warn!(
                            "Stun plaintext port was not provided for server {}!",
                            server.public_key
                        );
                        return false;
                    }
                    true
                });
                s.servers = servers;
                s.current_server_index = 0;

                if s.stun_peer_publisher
                    .send(s.servers.get(s.current_server_index).cloned())
                    .await
                    .is_err()
                {
                    telio_log_error!("Could not publish the STUN peer");
                }
            }

            if s.stun_state == StunState::Paused {
                return Ok(());
            }

            // Update STUN state
            s.exponential_backoff.reset();
            s.transition_to_wait_for_wg();
            s.try_transition_to_searching_for_server().await;

            Ok(())
        })
        .await;
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    #[cfg(test)]
    pub async fn get_ext_socket_addr(&self) -> Option<SocketAddr> {
        task_exec!(&self.task, async move |s| {
            s.sockets.as_ref().ok_or(()).and_then(
                |StunSockets {
                     tun_socket_v4: _,
                     tun_socket_v6: _,
                     ext_socket,
                 }| ext_socket.local_addr().map_err(|_| ()),
            )
        })
        .await
        .ok()
    }
}

#[async_trait]
impl<Wg: WireGuard, E: Backoff + 'static> EndpointProvider for StunEndpointProvider<Wg, E> {
    fn name(&self) -> &'static str {
        "stun"
    }

    async fn subscribe_for_pong_events(&self, tx: chan::Tx<PongEvent>) {
        let _ = task_exec!(&self.task, async move |s| {
            s.pong_event = Some(tx);
            Ok(())
        })
        .await;
    }

    async fn subscribe_for_endpoint_candidates_change_events(
        &self,
        tx: chan::Tx<EndpointCandidatesChangeEvent>,
    ) {
        let _ = task_exec!(&self.task, async move |s| {
            s.change_event = Some(tx);
            Ok(())
        })
        .await;
    }

    async fn trigger_endpoint_candidates_discovery(&self, force: bool) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| {
            // A guard, to prevent waking up from 'BackingOff', when stun peer is published
            if force {
                if let StunState::BackingOff = s.stun_state {
                    s.transition_to_wait_for_wg();
                }
            }

            if let StunState::WaitingForWg = s.stun_state {
                s.try_transition_to_searching_for_server().await;
            }

            if let StunState::HasEndpoints = s.stun_state {
                if s.stun_session.is_none() {
                    let err = s.start_stun_session().await;
                    if err.is_err() {
                        telio_log_warn!("Starting session failed: {:?}", err)
                    }
                }
            }

            Ok(Ok(()))
        })
        .await?
    }

    async fn handle_endpoint_gone_notification(&self) {
        task_exec!(&self.task, async move |s| {
            s.stun_session = None;
            Ok(())
        })
        .await
        .unwrap_or_default();
    }

    async fn send_ping(
        &self,
        addr: SocketAddr,
        session_id: Session,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        telio_log_debug!(
            "STUN sending ping to {:?} {:?} {:?}",
            addr,
            public_key,
            session_id
        );
        task_exec!(&self.task, async move |s| Ok(s
            .send_ping(addr, session_id, &public_key)
            .await))
        .await?
    }

    async fn get_current_endpoints(&self) -> Option<Vec<EndpointCandidate>> {
        task_exec!(&self.task, async move |s| Ok(Some(
            s.last_candidates.clone()
        )))
        .await
        .unwrap_or(None)
    }

    async fn pause(&self) {
        let _ = task_exec!(&self.task, async move |s| {
            if !s.is_battery_optimization_on {
                telio_log_debug!("Skipping pause, battery optimization not set");
                return Ok(());
            }
            s.stun_state = StunState::Paused;
            s.current_timeout = PinnedSleep::new(STUN_TIMEOUT_PAUSED, ());
            Ok(())
        })
        .await;
    }

    async fn unpause(&self) {
        let _ = task_exec!(&self.task, async move |s| {
            if s.stun_state == StunState::Paused {
                s.exponential_backoff.reset();
                s.transition_to_wait_for_wg();
                s.try_transition_to_searching_for_server().await;
            }
            Ok(())
        })
        .await;
    }

    async fn is_paused(&self) -> bool {
        task_exec!(&self.task, async move |s| Ok(
            s.stun_state == StunState::Paused
        ))
        .await
        .unwrap_or(false)
    }
}

//                                -------------
//                                |           |
//                                v           |
// +------------------+     +--------------+  |
// |SearchingForServer|---->| HasEndpoints |---
// +------------------+     +--------------+
//          ^     ^  |            |       |
//          |     |  |            |       v
// +--------------+  |            |     +--------------+
// | WaitingForWG |<-|------------| ----|    Paused    |
// +--------------+  |            |     +--------------+
//          ^        |            |
//          |        |            |
//          v        V            |
//      +-------------+           |
//      | BackingOff  |<-----------
//      +-------------+
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum StunState {
    WaitingForWg,
    SearchingForServer,
    BackingOff,
    HasEndpoints,
    Paused,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum StunSkipReason {
    NotConfigured,
    ModulePaused,
}

pub struct StunSockets {
    pub tun_socket_v4: Option<Arc<UdpSocket>>,
    pub tun_socket_v6: Option<Arc<UdpSocket>>,
    pub ext_socket: External<UdpSocket>,
}

struct State<Wg: WireGuard, E: Backoff> {
    servers: Vec<Server>,
    sockets: Option<StunSockets>,

    current_server_index: usize,
    current_proto: IpProto,

    wg: Arc<Wg>,
    ping_pong_tracker: Arc<Mutex<PingPongHandler>>,

    change_event: Option<chan::Tx<EndpointCandidatesChangeEvent>>,
    pong_event: Option<chan::Tx<PongEvent>>,

    stun_session: Option<StunSession>,
    exponential_backoff: E,
    current_timeout: PinnedSleep<()>,
    last_candidates: Vec<EndpointCandidate>,
    stun_state: StunState,
    is_battery_optimization_on: bool,

    stun_peer_publisher: chan::Tx<Option<StunServer>>,
}

impl<Wg: WireGuard, E: Backoff> State<Wg, E> {
    async fn start_stun_session(&mut self) -> Result<(), Error> {
        if let Some(sockets) = self.sockets.as_ref() {
            if self.stun_session.is_none() {
                let (wg, udp) = self.get_stun_endpoints().await?;
                let int_socket = self.get_socket().ok_or(Error::StunNotConfigured)?;
                self.stun_session =
                    Some(StunSession::start(int_socket, wg, &sockets.ext_socket, udp).await?);
                self.current_timeout = PinnedSleep::new(STUN_TIMEOUT, ());
            }

            Ok(())
        } else {
            Err(Error::StunNotConfigured)
        }
    }

    async fn send_ping(
        &self,
        addr: SocketAddr,
        session_id: Session,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        if let Some(sockets) = self.sockets.as_ref() {
            self.ping_pong_tracker
                .lock()
                .await
                .send_ping(
                    addr,
                    self.get_wg_port(),
                    &sockets.ext_socket,
                    session_id,
                    public_key,
                )
                .await
        } else {
            Err(Error::StunNotConfigured)
        }
    }

    async fn reconnect(&mut self) {
        match self.stun_state {
            StunState::BackingOff | StunState::Paused => {
                self.transition_to_wait_for_wg();
                self.exponential_backoff.reset();
                self.try_transition_to_searching_for_server().await;
            }
            _ => {}
        };
    }

    /// Get wg port identified by stun
    fn get_wg_port(&self) -> WGPort {
        if let Some(wg_port) = self.last_candidates.first().map(|c| c.wg.port()) {
            WGPort(wg_port)
        } else {
            telio_log_warn!("Trying to get WGPort before stun.");
            Default::default()
        }
    }

    // Move to the next server, returns 'true' on server list reset
    async fn next_server(&mut self) -> bool {
        let last_server_index = self.current_server_index;
        self.current_server_index = if !self.servers.is_empty() {
            (self.current_server_index + 1) % self.servers.len()
        } else {
            0
        };

        if self
            .stun_peer_publisher
            .send(self.servers.get(self.current_server_index).cloned())
            .await
            .is_err()
        {
            telio_log_warn!("Sending new server failed");

            // When sending the new server fails we fallback to the old one
            self.current_server_index = last_server_index;
        }

        if last_server_index >= self.current_server_index {
            telio_log_warn!("No more stun servers to try");
            return true;
        }

        false
    }

    /// Get endpoint's for stuns (WgStun, PlaintextStun)
    async fn get_stun_endpoints(&self) -> Result<(SocketAddr, SocketAddr), Error> {
        if self.sockets.is_some() {
            if let Some(server) = self.servers.get(self.current_server_index) {
                let interface = self.wg.get_interface().await?;

                let stun_peer = interface
                    .peers
                    .get(&server.public_key)
                    .ok_or(Error::NoStunPeer)?;

                let wg_ip = stun_peer
                    .allowed_ips
                    .iter()
                    .find(|addr: &&telio_model::mesh::IpNet| {
                        if self.is_in_ipv6_mode() {
                            addr.addr().is_ipv6()
                        } else {
                            addr.addr().is_ipv4()
                        }
                    })
                    .ok_or(Error::BadStunPeer)?
                    .addr();

                let udp_ip = stun_peer.endpoint.ok_or(Error::BadStunPeer)?.ip();

                Ok((
                    (wg_ip, server.stun_port).into(),
                    (udp_ip, server.stun_plaintext_port).into(),
                ))
            } else {
                Err(Error::NoStunPeer)
            }
        } else {
            Err(Error::StunNotConfigured)
        }
    }

    /// NOTE: This method is not cancel safe
    async fn handle_rx(&mut self, payload: &[u8], src_addr: &SocketAddr) -> Result<(), Error> {
        if self.try_handle_stun_rx(payload, src_addr).await? {
            return Ok(());
        }

        self.handle_ping_rx(payload, src_addr).await
    }

    async fn try_handle_stun_rx(
        &mut self,
        payload: &[u8],
        src_addr: &SocketAddr,
    ) -> Result<bool, Error> {
        if let Some(mut session) = self.stun_session.take() {
            match session.try_consume(payload, src_addr)? {
                // Candidate resolved, session is consumed.
                StunResult::Final(candidate) => {
                    self.transition_to_has_endpoints_state(candidate).await;
                    return Ok(true);
                }
                // Session resolved one of endpoints, session continues
                StunResult::Consumed => {
                    self.stun_session = Some(session);
                    return Ok(true);
                }
                // Packet not for stun session
                StunResult::Skipped => self.stun_session = Some(session),
            }
        }
        Ok(false)
    }

    async fn handle_ping_rx(
        &mut self,
        encrypted_buf: &[u8],
        addr: &SocketAddr,
    ) -> Result<(), Error> {
        if let Some(sockets) = self.sockets.as_ref() {
            let wg_port = self.get_wg_port();
            self.ping_pong_tracker
                .lock()
                .await
                .handle_rx_packet(
                    encrypted_buf,
                    addr,
                    wg_port,
                    &sockets.ext_socket,
                    &self.pong_event,
                    telio_model::features::EndpointProvider::Stun,
                )
                .await
        } else {
            Err(Error::StunNotConfigured)
        }
    }

    fn transition_to_wait_for_wg(&mut self) {
        self.stun_state = StunState::WaitingForWg;
        self.current_timeout = PinnedSleep::new(STUN_TIMEOUT, ());
    }

    async fn try_transition_to_searching_for_server(&mut self) {
        if !self.servers.is_empty()
            && self.stun_state != StunState::Paused
            && self.is_wg_ready().await
        {
            self.stun_state = StunState::SearchingForServer;
            let err = self.start_stun_session().await;
            if err.is_err() {
                telio_log_warn!("Starting session failed: {:?}", err)
            }
        }
    }

    async fn transition_to_has_endpoints_state(&mut self, candidate: EndpointCandidate) {
        // Announce the new candidates
        let candidates = vec![candidate];
        if self.last_candidates != candidates {
            self.last_candidates = candidates.clone();
            if let Some(change_event) = &self.change_event {
                let _ = change_event
                    .send((EndpointProviderType::Stun, candidates))
                    .await;
            } else {
                telio_log_warn!("{} does not have endpoint provider sender.", Self::NAME)
            }
        }

        // Transition to HasEndpoints state
        self.stun_state = StunState::HasEndpoints;
        self.exponential_backoff.reset();
        // Current backoff should be one derived from features
        self.current_timeout = PinnedSleep::new(self.exponential_backoff.get_backoff(), ());
    }

    async fn transition_to_backing_off_state_or_change_proto(&mut self) {
        // We failed so we clear the candidates if there are any
        if !self.last_candidates.is_empty() {
            self.last_candidates.clear();
            if let Some(ce) = &self.change_event {
                let _ = ce.send((EndpointProviderType::Stun, vec![])).await;
            } else {
                telio_log_warn!("{} does not have endpoint provider sender.", Self::NAME)
            }
        }

        // Clear the session so we can start the next search after backing off
        self.stun_session = None;
        // If we have IPv6 and we failed to get IPv6 endpoint we should fallback to IPv4
        if self.is_in_ipv6_mode() {
            telio_log_warn!("Fallback to IPv4");
            self.current_proto = IpProto::IPv4;
            // Start new session in new protocol
            self.transition_to_wait_for_wg();
            self.try_transition_to_searching_for_server().await;
            return;
        }
        // Selecting IPv6 for next attempt (if applicable)
        if self.ipv6_is_enabled() {
            self.current_proto = IpProto::IPv6;
        } else {
            self.current_proto = IpProto::IPv4;
        }
        // Set the timeout according to the exponential backoff
        self.current_timeout = PinnedSleep::new(self.exponential_backoff.get_backoff(), ());

        // Transition to backing off state
        self.stun_state = StunState::BackingOff;
        // Move to the next server
        if self.next_server().await {
            // Update next backoff on server list reset
            self.exponential_backoff.next_backoff();
        }
    }

    async fn is_wg_ready(&self) -> bool {
        self.wg
            .get_interface()
            .await
            .ok()
            .and_then(|wg| {
                self.servers
                    .get(self.current_server_index)
                    .map(|server| wg.peers.contains_key(&server.public_key))
            })
            .unwrap_or(false)
    }

    fn ipv6_is_enabled(&self) -> bool {
        if let Some(sockets) = self.sockets.as_ref() {
            return sockets.tun_socket_v6.is_some();
        }

        false
    }

    fn is_in_ipv6_mode(&self) -> bool {
        self.ipv6_is_enabled() && self.current_proto == IpProto::IPv6
    }

    fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        if let Some(sockets) = self.sockets.as_ref() {
            if self.is_in_ipv6_mode() {
                sockets.tun_socket_v6.clone()
            } else {
                sockets.tun_socket_v4.clone()
            }
        } else {
            None
        }
    }
}

#[async_trait]
impl<Wg: WireGuard, E: Backoff> Runtime for State<Wg, E> {
    const NAME: &'static str = "StunEndpointProvider";

    type Err = ();

    async fn wait_with_update<F>(&mut self, updated: F) -> Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
    {
        let mut ext_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut tun_buf = vec![0u8; MAX_PACKET_SIZE];

        pin!(updated);

        // We must ensure that sockets are created and that we have a populated
        // server list, before we can continue doing anything.
        let sockets = match (
            self.sockets.as_ref(),
            self.servers.is_empty() || self.stun_state == StunState::Paused,
        ) {
            (Some(sockets), false) => sockets,
            (_, _) => {
                let reason = if self.stun_state == StunState::Paused {
                    StunSkipReason::ModulePaused
                } else {
                    StunSkipReason::NotConfigured
                };
                telio_log_debug!(
                    "Skipping getting endpoint via STUN endpoint provider({reason:?})"
                );
                //If no STUN servers or sockets are configured -> nothing to do.
                //NOTE: this will get cancelled on reconfiguration attempt
                tokio::select! {
                    _ = pending() => {},
                    update = &mut updated => {
                        return update(self).await;
                    }
                }
                return Ok(());
            }
        };

        let int_socket = {
            match self.get_socket() {
                Some(socket) => socket,
                None => {
                    tokio::select! {
                        _ = pending() => {},
                        update = &mut updated => {
                            return update(self).await;
                        }
                    }
                    return Ok(());
                }
            }
        };

        tokio::select! {
            // Reading data from UDP socket (passed by node, that is awaiting on socket's receive)
            Ok((size, src_addr)) = sockets.ext_socket.recv_from(&mut ext_buf) => {
                let _ = self.handle_rx(ext_buf.get(..size).ok_or(())?, &src_addr).await;
            }
            Ok((size, src_addr)) = int_socket.recv_from(&mut tun_buf) => {
                // We will not pinging through wireguard.
                let _ = self.try_handle_stun_rx(tun_buf.get(..size).ok_or(())?, &src_addr).await;
            }
            // We are waiting either for stun session to timeout, or for the end of penalty
            _ = &mut self.current_timeout => {
                telio_log_debug!("Processing timeout in {:?} state", self.stun_state);
                match self.stun_state {
                    StunState::SearchingForServer | StunState::WaitingForWg => {
                        // This is a stun timeout. We should back off.
                        self.transition_to_backing_off_state_or_change_proto().await;
                    },
                    StunState::BackingOff => {
                        // Backoff timeout is over. We should try again.
                        // Transition to waiting for WG peers to include our stun server
                        self.transition_to_wait_for_wg();
                        self.try_transition_to_searching_for_server().await;
                    },
                    StunState::HasEndpoints => {
                        if self.stun_session.take().is_some() {
                            // This is a stun timeout. We should back off and move to the next server.
                            self.transition_to_backing_off_state_or_change_proto().await;
                        } else {
                            // This is a poll interval. We're still in HasEndpoints state
                            let res = self.start_stun_session().await;
                            if let Err(err) = res {
                                telio_log_warn!("Starting STUN session failed with error: {:?}", err);
                                self.transition_to_backing_off_state_or_change_proto().await;
                            }
                        }
                    },
                    StunState::Paused => {
                        telio_log_debug!("Skipping the processing of STUN request (paused)");
                    },
                }
            }
            update = &mut updated => {
                return update(self).await;
            }
            else => {
                return Ok(());
            },
        }

        Ok(())
    }
}

#[derive(Debug)]
struct StunSession {
    wg: StunRequest,
    udp: StunRequest,
}

#[derive(Debug)]
enum StunResult {
    Final(EndpointCandidate),
    Consumed,
    Skipped,
}

#[derive(Debug)]
enum StunRequest {
    Waiting(SocketAddr, TransactionId),
    Result(SocketAddr),
}

impl StunSession {
    async fn start(
        socket_via_wg: Arc<UdpSocket>,
        wg: SocketAddr,
        socket_via_ext: &UdpSocket,
        udp: SocketAddr,
    ) -> Result<Self, Error> {
        let wg_stun = stun_msg::new_request()?;
        let udp_stun = stun_msg::new_request()?;
        telio_log_debug!(
            "Sending stun: {} for ses: {:?}",
            &udp,
            udp_stun.0.as_bytes()
        );
        telio_log_debug!(
            "Sending wg-stun: {} for ses: {:?}",
            &wg,
            wg_stun.0.as_bytes(),
        );

        if let Err(err) = socket_via_wg.send_to(&wg_stun.1, wg).await {
            telio_log_debug!("wg stun send_to error");
            return Err(Error::IOError(err));
        }

        if let Err(err) = socket_via_ext.send_to(&udp_stun.1, udp).await {
            telio_log_debug!("plain stun send_to error");
            return Err(Error::IOError(err));
        }

        Ok(Self {
            wg: StunRequest::Waiting(wg, wg_stun.0),
            udp: StunRequest::Waiting(udp, udp_stun.0),
        })
    }

    fn try_consume(&mut self, payload: &[u8], src_addr: &SocketAddr) -> Result<StunResult, Error> {
        let consumed =
            self.wg.try_update(payload, src_addr)? || self.udp.try_update(payload, src_addr)?;

        // Check if packet was consumed by any of stun requests
        if !consumed {
            return Ok(StunResult::Skipped);
        }

        match (&self.wg, &self.udp) {
            (StunRequest::Result(wg), StunRequest::Result(udp)) => {
                Ok(StunResult::Final(EndpointCandidate { wg: *wg, udp: *udp }))
            }
            _ => Ok(StunResult::Consumed),
        }
    }
}

impl StunRequest {
    /// Tries to get stun endpoint from payload.
    /// Returns true on success, false if not for this request,
    /// error on parsing failure.
    fn try_update(&mut self, payload: &[u8], src_addr: &SocketAddr) -> Result<bool, Error> {
        let sa = match self {
            StunRequest::Waiting(addr, tid) => {
                if addr != src_addr {
                    // packet is not for this stun request
                    return Ok(false);
                }

                let (sa, id) = stun_msg::decode_response(payload)?;

                if &id != tid {
                    telio_log_warn!("Unexpected stun packet from {}", src_addr);
                    return Ok(false);
                }
                telio_log_debug!(
                    "Got stun response from {} for session {:?} -> {}",
                    src_addr,
                    tid.as_bytes(),
                    &sa,
                );

                sa
            }
            StunRequest::Result(_) => return Ok(false),
        };

        *self = Self::Result(sa);

        Ok(true)
    }
}

/// Stun message encoding/decoding
mod stun_msg {
    use std::{io, net::SocketAddr};

    use bytecodec::{DecodeExt, EncodeExt};
    use rand::Rng;
    use stun_codec::{
        rfc5389::{
            attributes::{Fingerprint, MappedAddress, Software, XorMappedAddress},
            methods::BINDING,
            Attribute,
        },
        Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
    };

    use super::STUN_SOFTWARE;

    pub fn new_request() -> bytecodec::Result<(TransactionId, Vec<u8>)> {
        let tid = TransactionId::new(rand::thread_rng().gen::<[u8; 12]>());
        let mut msg = Message::<Attribute>::new(MessageClass::Request, BINDING, tid);

        msg.add_attribute(Attribute::Software(Software::new(
            STUN_SOFTWARE.to_string(),
        )?));

        msg.add_attribute(Attribute::Fingerprint(Fingerprint::new(&msg)?));

        let packet = MessageEncoder::new().encode_into_bytes(msg)?;

        Ok((tid, packet))
    }

    pub fn decode_response(payload: &[u8]) -> bytecodec::Result<(SocketAddr, TransactionId)> {
        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder.decode_from_bytes(payload)??;

        let tid = decoded.transaction_id();

        let x_m_addr = decoded
            .get_attribute::<XorMappedAddress>()
            .map(|x| x.address());
        let m_addr = decoded
            .get_attribute::<MappedAddress>()
            .map(|x| x.address());
        // Failed to retrieve stun endpoint, just return NotFound
        let addr = x_m_addr
            .or(m_addr)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

        Ok((addr, tid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashmap;
    use mockall::mock;
    use std::{
        cell::RefCell,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        rc::Rc,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use stun_codec::rfc5389::{
        self,
        attributes::{MappedAddress, XorMappedAddress},
    };
    use telio_crypto::{
        encryption::{decrypt_request, decrypt_response, encrypt_request, encrypt_response},
        PublicKey, SecretKey,
    };
    use telio_model::mesh::{IpNet, LinkState};
    use telio_proto::{CodecError, PacketRelayed, PartialPongerMsg, PingerMsg};
    use telio_sockets::NativeProtector;
    use telio_sockets::SocketPool;
    use telio_task::io::Chan;
    use telio_test::await_timeout;
    use telio_utils::exponential_backoff::MockBackoff;
    use telio_utils::ip_stack::IpStack;
    use telio_wg::{
        uapi::{Interface, Peer},
        Error,
    };
    use tokio::{
        task,
        time::{self, sleep, timeout},
    };

    #[tokio::test]
    async fn timeouts_on_happy_path() {
        const DEFAULT_POLL_INTERVAL_MILLIS: u64 = 1000;
        let mut env = prepare_test_env(Some([DEFAULT_POLL_INTERVAL_MILLIS; 6]), false).await;
        env.configure_env().await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(
            candidates,
            vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }]
        );

        for _ in 0..2 {
            timeout(
                Duration::from_millis(DEFAULT_POLL_INTERVAL_MILLIS - 50),
                async {
                    let mut buf = [0; MAX_PACKET_SIZE];
                    let _ = env.peers[0].stun_sock.recv(&mut buf).await;
                    let _ = env.peers[0].peer_sock_v4.recv(&mut buf).await;
                },
            )
            .await
            .expect_err("Should not receive stun requests yet");

            // Poll interval should expire already so we try to complete the requests
            await_timeout!(stun_reply(
                &env.peers[0].stun_sock,
                XorMappedAddress::new(udp_endpoint)
            ));
            await_timeout!(stun_reply(
                &env.peers[0].peer_sock_v4,
                MappedAddress::new(wg_endpoint)
            ));
        }

        env.stun_provider.stop().await;
    }

    #[tokio::test]
    async fn collect_stun_endpoints_on_configure() {
        let mut env = prepare_test_env(None, false).await;

        env.configure_env().await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(
            candidates,
            vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }]
        );

        env.stun_provider.stop().await;
    }

    #[tokio::test]
    async fn collect_stun_endpoints_on_configure_ipv6() {
        // Just to make sure that it works well when given IPv6 socket
        let mut env = prepare_test_env(None, true).await;

        env.configure_env().await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            env.peers[0].peer_sock_v6.as_ref().expect("peer_sock_v6"),
            MappedAddress::new(wg_endpoint)
        ));

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(
            candidates,
            vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }]
        );

        env.stun_provider.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn stun_ipv6v4_fallback() {
        let poll_interval = Duration::from_millis(10000);
        let mut env = prepare_test_env_with_server_weights(None, vec![100, 110], true).await;
        env.configure_env().await;

        tokio::task::yield_now().await;

        // Receive first server
        let received = env
            .stun_peer_subscriber
            .try_recv()
            .expect("Some server should be published just after configure");
        assert!(received == Some(env.stun_servers[0].clone()));

        // IPv6 attempt
        env.timeout_both_sockets(0, IpProto::IPv6).await;
        jump_to_next_session_start(STUN_TIMEOUT).await;

        // IPv4 attempt
        env.timeout_both_sockets(0, IpProto::IPv4).await;
        jump_to_next_session_start(STUN_TIMEOUT).await;

        // Receive next server attempt
        let received = env
            .stun_peer_subscriber
            .try_recv()
            .expect("Another server should be published by now");
        assert!(received == Some(env.stun_servers[1].clone()));

        jump_to_next_session_start(poll_interval).await;

        env.reply_on_both_sockets(1, IpProto::IPv6).await;

        env.stun_peer_subscriber
            .try_recv()
            .expect_err("Should not happen!");

        env.stun_provider.stop().await;
    }

    #[tokio::test]
    async fn collect_stun_endpoints_on_change() {
        let mut env = prepare_test_env(None, false).await;
        env.configure_env().await;

        // Triggered by configuration
        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(
            candidates,
            vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }]
        );

        // Trigger for same env does not send
        env.stun_provider
            .trigger_endpoint_candidates_discovery(false)
            .await
            .expect("triggered");

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));

        timeout(Duration::from_millis(200), env.change_event.recv())
            .await
            .expect_err("should timeout");

        // Triggered for different env
        let udp_endpoint = SocketAddr::new([3, 3, 3, 3].into(), 33333);
        let wg_endpoint = SocketAddr::new([4, 4, 4, 4].into(), 44444);

        env.stun_provider
            .trigger_endpoint_candidates_discovery(false)
            .await
            .expect("tiggered");

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(
            candidates,
            vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }]
        );

        env.stun_provider.stop().await;
    }

    #[tokio::test]
    async fn report_empty_candidate_list_on_stun_failure() {
        let ipv6 = false;
        let mut env = prepare_test_env(None, ipv6).await;
        let mut buf = [0; MAX_PACKET_SIZE];

        env.configure_env().await;

        // Timeout at first, no reporting as init state is assumed [];

        // Consume msg without reply
        await_timeout!(async {
            env.peers[0]
                .stun_sock
                .recv_from(&mut buf)
                .await
                .expect("sent");
            if ipv6 {
                env.peers[0]
                    .peer_sock_v6
                    .as_ref()
                    .expect("peer_sock_v6")
                    .recv_from(&mut buf)
                    .await
                    .expect("sentv6");
            }
            env.peers[0]
                .peer_sock_v4
                .recv_from(&mut buf)
                .await
                .expect("sent");
        });
        // Wait for stun timeout
        time::pause();
        time::advance(STUN_TIMEOUT * 2).await;
        time::resume();

        timeout(Duration::from_millis(200), env.change_event.recv())
            .await
            .expect_err("should timeout");

        // Trigger and receive endpoints
        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        env.stun_provider
            .trigger_endpoint_candidates_discovery(true)
            .await
            .expect("triggered");

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        if ipv6 {
            await_timeout!(stun_reply(
                env.peers[0].peer_sock_v6.as_ref().expect("peer_sock_v6"),
                MappedAddress::new(wg_endpoint)
            ));
        } else {
            await_timeout!(stun_reply(
                &env.peers[0].peer_sock_v4,
                MappedAddress::new(wg_endpoint)
            ));
        }

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(
            candidates,
            vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }]
        );

        // Trigger again and receive timeout
        env.stun_provider
            .trigger_endpoint_candidates_discovery(true)
            .await
            .expect("triggered");

        // Consume msg without reply
        await_timeout!(async {
            env.peers[0]
                .stun_sock
                .recv_from(&mut buf)
                .await
                .expect("sent");
            if ipv6 {
                env.peers[0]
                    .peer_sock_v6
                    .as_ref()
                    .expect("peer_sock_v6")
                    .recv_from(&mut buf)
                    .await
                    .expect("sentv6");
            } else {
                env.peers[0]
                    .peer_sock_v4
                    .recv_from(&mut buf)
                    .await
                    .expect("sent");
            }
        });
        time::pause();
        time::advance(STUN_TIMEOUT * 2).await;
        time::resume();

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(candidates, vec![]);

        env.stun_provider.stop().await;
    }

    #[tokio::test]
    async fn pongs_propagated_through_the_channel() {
        let mut env = prepare_test_env(None, false).await;

        env.configure_env().await;

        let session_id = 456;
        let ping_addr = env.peers[0].ping_sock.local_addr().expect("local_addr");

        let remote_sk = SecretKey::gen();
        let remote_pk = remote_sk.public();

        env.ping_pong_handler
            .lock()
            .await
            .configure(hashmap! { session_id => remote_pk });
        env.stun_provider
            .send_ping(ping_addr, session_id, remote_pk)
            .await
            .unwrap();

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = await_timeout!(env.peers[0].ping_sock.recv_from(&mut buf)).unwrap();
        let decrypt_transform = |_packet_type, b: &[u8]| {
            Ok(decrypt_request(b, &remote_sk, |_| true)
                .map(|(buf, pk)| (buf, Some(pk)))
                .unwrap())
        };
        if let (PacketRelayed::Pinger(msg), _) =
            PacketRelayed::decode_and_decrypt(&buf[..len], decrypt_transform).unwrap()
        {
            let resp = msg
                .pong(
                    msg.get_wg_port(),
                    &addr.ip(),
                    telio_model::features::EndpointProvider::Stun,
                )
                .unwrap();

            let mut rng = rand::thread_rng();
            let encrypt_transform = |b: &[u8]| {
                Ok(encrypt_response(b, &mut rng, &remote_sk, &env.local_sk.public()).unwrap())
            };

            let buf = resp.encode_and_encrypt(encrypt_transform).unwrap();
            env.peers[0].ping_sock.send_to(&buf, addr).await.unwrap();
        } else {
            panic!("Incorrect packet type in place of ping");
        }

        let pong = await_timeout!(env.pong_event.recv());
        assert!(pong.is_some());
        let pong = pong.unwrap();
        // Stun peer not configured and no stun info yet defaulting to 0
        assert_eq!(pong.msg.get_wg_port(), WGPort(0));
        assert_eq!(pong.msg.get_session(), session_id);
        assert_eq!(pong.addr, ping_addr);

        // Configure and reply to stun
        env.configure_env().await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));

        // Give time for provider to recieve and sore local endpoints
        sleep(Duration::from_millis(100)).await;

        let session_id = 789;

        env.ping_pong_handler
            .lock()
            .await
            .configure(hashmap! { session_id => remote_pk });

        env.stun_provider
            .send_ping(ping_addr, session_id, remote_pk)
            .await
            .unwrap();

        let (len, addr) = await_timeout!(env.peers[0].ping_sock.recv_from(&mut buf)).unwrap();
        let decrypt_transform = |_packet_type, b: &[u8]| {
            Ok(decrypt_request(b, &remote_sk, |_| true)
                .map(|(buf, pk)| (buf, Some(pk)))
                .unwrap())
        };
        if let (PacketRelayed::Pinger(msg), _) =
            PacketRelayed::decode_and_decrypt(&buf[..len], decrypt_transform).unwrap()
        {
            let resp = msg
                .pong(
                    msg.get_wg_port(),
                    &addr.ip(),
                    telio_model::features::EndpointProvider::Stun,
                )
                .unwrap();

            let mut rng = rand::thread_rng();
            let encrypt_transform = |b: &[u8]| {
                Ok(encrypt_response(b, &mut rng, &remote_sk, &env.local_sk.public()).unwrap())
            };

            let buf = resp.encode_and_encrypt(encrypt_transform).unwrap();
            env.peers[0].ping_sock.send_to(&buf, addr).await.unwrap();
        } else {
            panic!("Incorrect packet type in place of ping");
        }

        let pong = await_timeout!(env.pong_event.recv());
        assert!(pong.is_some());
        let pong = pong.unwrap();
        // Stun peer not configured and no stun info yet defaulting to 0
        assert_eq!(pong.msg.get_wg_port(), WGPort(22222));
        assert_eq!(pong.msg.get_session(), session_id);
        assert_eq!(pong.addr, ping_addr);

        env.stun_provider.stop().await;
    }

    #[tokio::test]
    async fn provider_replies_to_ping() {
        let env = prepare_test_env(None, false).await;

        env.configure_env().await;

        let provider_ext_addr = env
            .stun_provider
            .get_ext_socket_addr()
            .await
            .expect("Socket address should be available");

        let wg_port = WGPort(123);
        let session_id = 456;

        let ping = PingerMsg::ping(wg_port, session_id, 6969);
        let local_sk = SecretKey::gen();
        let remote_sk = env.local_sk.clone();
        let transform = |b: &[u8]| {
            Ok(
                encrypt_request(b, &mut rand::thread_rng(), &local_sk, &remote_sk.public())
                    .unwrap(),
            )
        };
        let encrypted_buf = ping.clone().encode_and_encrypt(transform).unwrap();

        env.ping_pong_handler
            .lock()
            .await
            .configure(hashmap! { session_id => local_sk.public() });

        env.peers[0]
            .ping_sock
            .send_to(&encrypted_buf, provider_ext_addr)
            .await
            .expect("ping");

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = env.peers[0].ping_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(addr, provider_ext_addr);

        let pong = PartialPongerMsg::decode_and_decrypt(&buf[..len], |_, b| Ok((b.to_vec(), None)))
            .unwrap();
        let decrypt_transform = |b: &[u8]| {
            decrypt_response(b, &local_sk, &remote_sk.public())
                .map_err(|_| CodecError::DecodeFailed)
        };
        let pong = pong.decrypt(decrypt_transform).unwrap();

        // When ping is send before stun response it default to 0
        assert_eq!(pong.get_wg_port(), WGPort(0));
        assert_eq!(pong.get_session(), session_id);

        env.configure_env().await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));

        // Give time for provider to recieve and sore local endpoints
        sleep(Duration::from_millis(100)).await;

        let session_id = 789;

        env.ping_pong_handler
            .lock()
            .await
            .configure(hashmap! { session_id => local_sk.public() });

        let ping = PingerMsg::ping(wg_port, session_id, 6969);
        let encrypt_transform = |b: &[u8]| {
            Ok(
                encrypt_request(b, &mut rand::thread_rng(), &local_sk, &remote_sk.public())
                    .unwrap(),
            )
        };
        let encrypted_buf = ping.clone().encode_and_encrypt(encrypt_transform).unwrap();

        env.peers[0]
            .ping_sock
            .send_to(&encrypted_buf, provider_ext_addr)
            .await
            .expect("ping");

        let (len, addr) = await_timeout!(env.peers[0].ping_sock.recv_from(&mut buf)).unwrap();

        assert_eq!(addr, provider_ext_addr);

        let pong = PartialPongerMsg::decode_and_decrypt(&buf[..len], |_, b| Ok((b.to_vec(), None)))
            .unwrap();
        let decrypt_transform = |b: &[u8]| {
            decrypt_response(b, &local_sk, &remote_sk.public())
                .map_err(|_| CodecError::DecodeFailed)
        };
        let pong = pong.decrypt(decrypt_transform).unwrap();

        assert_eq!(pong.get_wg_port(), WGPort(22222));
        assert_eq!(pong.get_session(), session_id);

        env.stun_provider.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn server_changed_when_current_connection_is_broken() {
        let mut env = prepare_test_env_with_server_weights(None, vec![100, 200, 10], false).await;
        let poll_interval = Duration::from_secs(10000);

        env.configure_env().await;

        tokio::task::yield_now().await;

        let received = env
            .stun_peer_subscriber
            .try_recv()
            .expect("Some server should be published just after configure");
        assert_eq!(received, Some(env.stun_servers[2].clone()));

        env.expect_server_after_session_timeout(0).await;

        jump_to_next_session_start(poll_interval).await;

        env.expect_server_after_session_timeout(1).await;

        jump_to_next_session_start(poll_interval).await;

        env.expect_server_after_session_timeout(2).await;

        env.stun_provider.stop().await;
    }

    #[tokio::test(start_paused = true)]
    #[cfg(not(target_os = "macos"))]
    async fn server_maintained_when_current_connection_is_active() {
        let mut env = prepare_test_env_with_server_weights(None, vec![100, 200, 10], false).await;
        let poll_interval = Duration::from_millis(10000);

        env.configure_env().await;

        tokio::task::yield_now().await;

        let received = env
            .stun_peer_subscriber
            .try_recv()
            .expect("Some server should be published just after configure");
        assert_eq!(received, Some(env.stun_servers[2].clone()));

        env.reply_on_both_sockets(2, IpProto::IPv4).await;

        jump_to_next_session_start(poll_interval).await;

        env.stun_peer_subscriber
            .try_recv()
            .expect_err("Should not happen!");

        env.reply_on_both_sockets(2, IpProto::IPv4).await;

        jump_to_next_session_start(poll_interval).await;

        env.stun_peer_subscriber
            .try_recv()
            .expect_err("Should not happen!");

        env.stun_provider.stop().await;
    }

    #[tokio::test(start_paused = true)]
    #[cfg(not(target_os = "macos"))]
    async fn exponential_backoff() {
        // We need to prepare some more complex mock to test if it is used properly
        let backoff_array = [4000, 12000, 44444, 7654, 10000, 765432];
        let env = prepare_test_env(Some(backoff_array), false).await;

        env.configure_env().await;

        task::yield_now().await;

        let expect_successful_receive = |msg| {
            let mut buf = [0; MAX_PACKET_SIZE];
            env.peers[0].peer_sock_v4.try_recv(&mut buf).expect(msg);
        };

        let expect_receive_failure = |msg| {
            let mut buf = [0; MAX_PACKET_SIZE];
            env.peers[0].peer_sock_v4.try_recv(&mut buf).expect_err(msg);
        };

        expect_successful_receive("First receive should be successful");

        for backoff in backoff_array.iter() {
            // Exceed the timeout to start the penalty
            time::advance(STUN_TIMEOUT).await;
            task::yield_now().await;

            expect_receive_failure("Shouldn't receive immediately after timeout");

            time::advance(Duration::from_millis(backoff - 1)).await;
            task::yield_now().await;

            expect_receive_failure("The penalty should be not over yet");

            time::advance(Duration::from_millis(2)).await;
            task::yield_now().await;

            expect_successful_receive("Next request should be already sent");
        }

        env.stun_provider.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn exponential_backoff_is_applied_even_if_session_start_failed() {
        let mut wg = MockWg::new();

        // Expect a single call to get_interface when we enter the loop first and
        // and a second in the finished backoff
        wg.expect_get_interface()
            .returning(move || Err(telio_wg::Error::UnsupportedOperationError))
            .times(2);

        // We need to prepare some more complex mock to test if it is used properly
        let backoff_array = [100, 200, 300, 400, 500, 600];
        let public_key = SecretKey::gen().public();
        let env = prepare_test_env_with_server_weights_and_mockwg(
            Some(backoff_array),
            vec![Server {
                public_key,
                stun_port: 3479,
                stun_plaintext_port: 3478,
                weight: 0,
                ..Default::default()
            }],
            Vec::new(),
            wg,
            false,
        )
        .await;

        env.configure_env().await;

        // Ensure that get_interface is not called multiple times in one backoff period
        // Expectation of single call is already set in mock wg
        jump_to_next_session_start(STUN_TIMEOUT).await;
        task::yield_now().await;
        time::advance(Duration::from_millis(100)).await;
        task::yield_now().await;
        time::advance(Duration::from_millis(10)).await;
        task::yield_now().await;

        env.stun_provider.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn wait_with_session_start_until_stun_server_wg_peer_is_available() {
        let mut wg = MockWg::default();
        let wg_port = 12345;

        let peer_sock_v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("peer sock v4");

        let peer_sock_v6 = None;

        let stun_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stun sock");

        let ping_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("ping sock");

        let public_key = SecretKey::gen().public();

        // Stun peer can be locked
        let allowed_ip = IpNet::new(peer_sock_v4.local_addr().unwrap().ip(), 32).unwrap();
        let endpoint: SocketAddr = (stun_sock.local_addr().unwrap().ip(), 55555).into();

        let stun_servers = vec![Server {
            public_key,
            stun_port: peer_sock_v4.local_addr().unwrap().port(),
            stun_plaintext_port: stun_sock.local_addr().unwrap().port(),
            weight: 1,
            ..Default::default()
        }];

        let stun_peers = vec![StunPeerSockets {
            stun_sock,
            peer_sock_v4,
            peer_sock_v6,
            ping_sock,
        }];

        let wg_peers = vec![(
            public_key,
            Peer {
                public_key,
                // Allowed ip is used to get ip of remote peer, in this case the fake it to be 127.0.0.1
                // since we don't provide entire wirguard tunnel for testing.
                allowed_ips: vec![allowed_ip],
                // Endpoint would be peer's public ip and wg listen_port that we fake here.
                endpoint: Some(endpoint),
                ..Default::default()
            },
        )];

        // In the beginning we don't have any peers, so the session should not be started.
        // There should be three calls to WG interface:
        //  - in the beginning,
        //  - after first backoff,
        //  - after trigger.
        // In the end we should be asked twice:
        //  - when the peer is added and is_wg_ready check finally passes
        //  - when we get the interface while starting the session
        let run_no = AtomicUsize::new(0);
        wg.expect_get_interface()
            .returning(move || {
                run_no.fetch_add(1, Ordering::Relaxed);
                if run_no.load(Ordering::Relaxed) <= 3 {
                    Ok(Interface {
                        listen_port: Some(wg_port),
                        peers: Default::default(),
                        ..Default::default()
                    })
                } else {
                    Ok(Interface {
                        listen_port: Some(wg_port),
                        peers: wg_peers.clone().into_iter().collect(),
                        ..Default::default()
                    })
                }
            })
            .times(5);

        const DEFAULT_POLL_INTERVAL_MILLIS: u64 = 1000;
        let env = prepare_test_env_with_server_weights_and_mockwg(
            Some([DEFAULT_POLL_INTERVAL_MILLIS; 6]),
            stun_servers,
            stun_peers,
            wg,
            false,
        )
        .await;

        env.configure_env().await;

        let expect_receive_failure = |msg| {
            let mut buf = [0; MAX_PACKET_SIZE];
            env.peers[0].peer_sock_v4.try_recv(&mut buf).expect_err(msg);
        };

        // First try should simply timeout
        expect_receive_failure("Nothing should be sent in the beginning");

        // There should be no session started after backoff
        time::advance(STUN_TIMEOUT + Duration::from_millis(1)).await;
        task::yield_now().await;
        time::advance(Duration::from_millis(DEFAULT_POLL_INTERVAL_MILLIS)).await;
        task::yield_now().await;
        expect_receive_failure("Session should not be started when there is no WG peer corresponding to the selected stun server");

        // There should be no session started after explicit trigger
        env.stun_provider
            .trigger_endpoint_candidates_discovery(false)
            .await
            .expect("tiggered");
        expect_receive_failure("Session should not be started when there is no WG peer corresponding to the selected stun server");

        // After adding a peer to WG mock, the session should finally appear
        env.stun_provider
            .trigger_endpoint_candidates_discovery(false)
            .await
            .expect("tiggered");

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.peers[0].stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(
            &env.peers[0].peer_sock_v4,
            MappedAddress::new(wg_endpoint)
        ));
    }

    // Test helpers

    mock! {
        Wg {}
        #[async_trait]
        impl WireGuard for Wg {
            async fn get_interface(&self) -> Result<Interface, Error>;
            async fn get_adapter_luid(&self) -> Result<u64, Error>;
            async fn wait_for_listen_port(&self, d: Duration) -> Result<u16, Error>;
            async fn get_link_state(&self, key: PublicKey) -> Result<Option<LinkState>, Error>;
            async fn set_secret_key(&self, key: SecretKey) -> Result<(), Error>;
            async fn set_fwmark(&self, fwmark: u32) -> Result<(), Error>;
            async fn add_peer(&self, peer: Peer) -> Result<(), Error>;
            async fn del_peer(&self, key: PublicKey) -> Result<(), Error>;
            async fn drop_connected_sockets(&self) -> Result<(), Error>;
            async fn time_since_last_rx(&self, public_key: PublicKey) -> Result<Option<Duration>, Error>;
            async fn stop(self);
            async fn reset_existing_connections(&self, exit_pubkey: PublicKey) -> Result<(), Error>;
            async fn set_ip_stack(&self, ip_stack: Option<IpStack>) -> Result<(), Error>;
        }
    }

    struct StunPeerSockets {
        /// This socket represent a socket that is listening in remote peer.
        /// We will not fake entire tunnel, as it correct behavior would basically
        /// give a new alias(ip) for wg_stun. Basically packet to 100.64.0.8:12345,
        /// would be received on 0.0.0.0:12345 on remote peer's socket/
        peer_sock_v4: UdpSocket,
        peer_sock_v6: Option<UdpSocket>,
        ping_sock: UdpSocket,
        stun_sock: UdpSocket,
    }

    #[allow(dead_code)]
    struct Env {
        // Dependencies
        socket_pool: Arc<SocketPool>,

        // Tested system
        stun_provider: StunEndpointProvider<MockWg, MockBackoff>,
        ipv6: bool,

        // External behavior
        stun_peer_subscriber: chan::Rx<Option<StunServer>>,
        change_event: chan::Rx<EndpointCandidatesChangeEvent>,
        pong_event: chan::Rx<PongEvent>,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,

        // Internals
        peers: Vec<StunPeerSockets>,
        stun_servers: Vec<Server>,
        local_sk: SecretKey,
    }

    async fn prepare_test_env(backoff_array: Option<[u64; 6]>, ipv6: bool) -> Env {
        prepare_test_env_with_server_weights(backoff_array, vec![100], ipv6).await
    }

    async fn prepare_test_env_with_server_weights(
        backoff_array: Option<[u64; 6]>,
        server_weights: Vec<u32>,
        ipv6: bool,
    ) -> Env {
        let mut wg = MockWg::default();
        let wg_port = 12345;

        let mut stun_servers = Vec::<Server>::new();
        let mut stun_peers = Vec::<StunPeerSockets>::new();
        let mut wg_peers = Vec::<(PublicKey, Peer)>::new();

        for weight in server_weights {
            let peer_sock_v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("peer sock v4");
            let peer_sock_v6 = if ipv6 {
                Some(
                    UdpSocket::bind((
                        Ipv6Addr::LOCALHOST,
                        peer_sock_v4.local_addr().unwrap().port(),
                    ))
                    .await
                    .expect("peer sock v6"),
                )
            } else {
                None
            };

            let stun_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("stun sock");

            let ping_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("ping sock");

            let public_key = SecretKey::gen().public();

            // Stun peer can be locked
            let allowed_ip_v4 = IpNet::new(peer_sock_v4.local_addr().unwrap().ip(), 32).unwrap();
            let mut allowed_ips = vec![allowed_ip_v4];
            if ipv6 {
                allowed_ips.push(
                    IpNet::new(
                        peer_sock_v6.as_ref().unwrap().local_addr().unwrap().ip(),
                        128,
                    )
                    .unwrap(),
                );
            }

            let endpoint: SocketAddr = (stun_sock.local_addr().unwrap().ip(), 55555).into();

            stun_servers.push(Server {
                public_key,
                stun_port: peer_sock_v4.local_addr().unwrap().port(),
                stun_plaintext_port: stun_sock.local_addr().unwrap().port(),
                weight,
                ..Default::default()
            });

            stun_peers.push(StunPeerSockets {
                stun_sock,
                peer_sock_v4,
                peer_sock_v6,
                ping_sock,
            });

            wg_peers.push((
                public_key,
                Peer {
                    public_key,
                    // Allowed ip is used to get ip of remote peer, in this case the fake it to be 127.0.0.1
                    // since we don't provide entire wirguard tunnel for testing.
                    allowed_ips,
                    // Endpoint would be peer's public ip and wg listen_port that we fake here.
                    endpoint: Some(endpoint),
                    ..Default::default()
                },
            ));
        }

        wg.expect_get_interface().returning(move || {
            Ok(Interface {
                listen_port: Some(wg_port),
                peers: wg_peers.clone().into_iter().collect(),
                ..Default::default()
            })
        });

        wg.expect_get_link_state().returning(|_| Ok(None));

        prepare_test_env_with_server_weights_and_mockwg(
            backoff_array,
            stun_servers,
            stun_peers,
            wg,
            ipv6,
        )
        .await
    }

    async fn prepare_test_env_with_server_weights_and_mockwg(
        backoff_array: Option<[u64; 6]>,
        stun_servers: Vec<Server>,
        stun_peers: Vec<StunPeerSockets>,
        wg: MockWg,
        ipv6: bool,
    ) -> Env {
        let socket_pool = SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        );

        let Chan {
            rx: stun_peer_subscriber,
            tx: stun_peer_publisher,
        } = Chan::default();

        let secret_key = SecretKey::gen();
        let ping_pong_handler = Arc::new(Mutex::new(PingPongHandler::new(secret_key.clone())));

        let backoff_array = backoff_array.unwrap_or([10000, 10000, 10000, 10000, 10000, 10000]);

        let stun_provider = StunEndpointProvider::start_with_exp_backoff(
            Arc::new(wg),
            {
                let mut result = MockBackoff::default();
                let backoff_array_idx = Rc::new(RefCell::new(0));
                let backoff_array_idx_a = backoff_array_idx.clone();
                result.expect_get_backoff().returning_st(move || {
                    Duration::from_millis(backoff_array[*backoff_array_idx_a.borrow()])
                });
                let backoff_array_idx_b = backoff_array_idx.clone();
                result.expect_next_backoff().returning_st(move || {
                    backoff_array_idx_b.replace_with(|idx| *idx + 1);
                });
                result.expect_reset().returning_st(move || {
                    backoff_array_idx.replace(0);
                });
                result
            },
            ping_pong_handler.clone(),
            stun_peer_publisher,
            false,
        );

        let candidates_channel = Chan::<EndpointCandidatesChangeEvent>::default();
        let pongs_channel = Chan::<PongEvent>::default();

        stun_provider
            .subscribe_for_endpoint_candidates_change_events(candidates_channel.tx.clone())
            .await;

        stun_provider
            .subscribe_for_pong_events(pongs_channel.tx.clone())
            .await;

        Env {
            socket_pool: Arc::new(socket_pool),

            stun_provider,
            ipv6,

            local_sk: secret_key,

            change_event: candidates_channel.rx,
            pong_event: pongs_channel.rx,
            stun_peer_subscriber,

            ping_pong_handler,

            peers: stun_peers,
            stun_servers,
        }
    }

    async fn stun_reply<A: Into<rfc5389::Attribute>>(sock: &UdpSocket, attribute: A) {
        use bytecodec::{DecodeExt, EncodeExt};
        use stun_codec::{
            rfc5389::{attributes::Software, methods::BINDING, Attribute},
            Message, MessageClass, MessageDecoder, MessageEncoder,
        };

        // Recv and decode
        let mut buf = [0; MAX_PACKET_SIZE];
        let (size, addr) = await_timeout!(sock.recv_from(&mut buf)).expect("stun_recv");
        let payload = &buf[..size];

        let mut decoder = MessageDecoder::<Attribute>::new();
        let request = decoder
            .decode_from_bytes(payload)
            .expect("decode bytes")
            .expect("broken stun msg");

        assert_eq!(request.class(), MessageClass::Request);

        assert_eq!(request.method(), BINDING);

        let software = request.get_attribute::<Software>().expect("software field");
        assert_eq!(software.description(), STUN_SOFTWARE);

        // Reply
        let mut msg = Message::<Attribute>::new(
            MessageClass::SuccessResponse,
            BINDING,
            request.transaction_id(),
        );
        msg.add_attribute(attribute.into());

        let packet = MessageEncoder::new()
            .encode_into_bytes(msg)
            .expect("encode");

        sock.send_to(&packet, addr).await.expect("ok");
    }

    async fn jump_to_next_session_start(poll_interval: Duration) {
        // Jump to penalty timeout
        tokio::time::advance(poll_interval + Duration::from_millis(1)).await;

        // Start new session
        tokio::task::yield_now().await;
    }

    impl Env {
        async fn configure_env(&self) {
            self.stun_provider
                .configure_with_ext_socket_addr(
                    self.stun_servers.clone(),
                    self.ipv6,
                    self.socket_pool.clone(),
                    Ipv4Addr::LOCALHOST,
                )
                .await;
        }

        async fn expect_server_after_session_timeout(&mut self, server_num: usize) {
            // Jupm to the session timeout
            tokio::time::advance(STUN_TIMEOUT + Duration::from_millis(1)).await;

            // Timeout session
            tokio::task::yield_now().await;

            let received = self
                .stun_peer_subscriber
                .try_recv()
                .expect("Should receive a STUN peer");
            assert_eq!(received, Some(self.stun_servers[server_num].clone()));
        }

        async fn reply_on_both_sockets(&self, server_num: usize, peer_sock_proto: IpProto) {
            let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
            let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

            await_timeout!(stun_reply(
                &self.peers[server_num].stun_sock,
                XorMappedAddress::new(udp_endpoint)
            ));

            match peer_sock_proto {
                IpProto::IPv6 => await_timeout!(stun_reply(
                    self.peers[server_num]
                        .peer_sock_v6
                        .as_ref()
                        .expect("peer_sock_v6"),
                    MappedAddress::new(wg_endpoint)
                )),
                IpProto::IPv4 => await_timeout!(stun_reply(
                    &self.peers[server_num].peer_sock_v4,
                    MappedAddress::new(wg_endpoint)
                )),
            }

            // Two yields are needed to handle both packages
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }

        async fn timeout_both_sockets(&self, server_num: usize, peer_sock_proto: IpProto) {
            let mut buf = [0; MAX_PACKET_SIZE];

            await_timeout!(async {
                self.peers[server_num]
                    .stun_sock
                    .recv_from(&mut buf)
                    .await
                    .expect("sent");
            });

            match peer_sock_proto {
                IpProto::IPv6 => await_timeout!(async {
                    self.peers[server_num]
                        .peer_sock_v6
                        .as_ref()
                        .expect("peer_sock_v6")
                        .recv_from(&mut buf)
                        .await
                        .expect("sentv6");
                }),
                IpProto::IPv4 => await_timeout!(async {
                    self.peers[server_num]
                        .peer_sock_v4
                        .recv_from(&mut buf)
                        .await
                        .expect("sentv4");
                }),
            }

            // Two yields are needed to handle both packages
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }
    }
}
