use async_trait::async_trait;
use futures::Future;

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use telio_crypto::PublicKey;
use telio_proto::{
    CallMeMaybeDeprecatedType, CallMeMaybeMsgDeprecated, Codec, DataMsg, Generation, Packet,
    PingerMsgDeprecated,
};
use telio_sockets::External;
use telio_task::{
    io::{chan::*, wait_for_tx, Chan, ChanSendError},
    task_exec, BoxAction,
};
use telio_task::{Runtime, Task};
use telio_utils::{
    repeated_actions::Error as RAError, telio_log_debug, telio_log_trace, telio_log_warn,
    RepeatedActions,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{error::TrySendError as ChanTrySendError, OwnedPermit},
    time::Duration,
};

use crate::{
    route::Configure,
    routes::database::{AbsRouteState, Database, Error as DatabaseError},
    routes::stunner::{Error as StunnerError, StunPacket},
    Route, RouteError, RouteResult,
};

#[cfg(not(test))]
use crate::routes::stunner::{Config as StunConfig, Stunner};

#[cfg(test)]
use {
    crate::routes::{
        database::CurrentRouteState,
        stunner::{Config as StunConfig, Result as StunnerResult, Results as StunResponse},
    },
    mockall::mock,
    std::net::Ipv4Addr,
    telio_proto::PeerId,
};

// Time constants of state machine
mod constants {
    use tokio::time::Duration;

    pub const MAX_PACKET: usize = u16::MAX as usize;
    pub const USE_PLAINTEXT_STUN: bool = true;

    #[cfg(test)]
    pub mod test {
        use super::*;

        pub const PING_METRIC_INTERVAL: Duration = Duration::from_secs(150);
        pub const PING_TIMEOUT: Duration = Duration::from_millis(100);
        pub const NO_DATA_TIMEOUT: Duration = Duration::from_millis(300);
        pub const CHECK_PEER_STATES_INTERVAL: Duration = Duration::from_millis(100);
        pub const STUN_INTERVAL: Duration = Duration::from_millis(200);
        pub const CALL_ME_MAYBE_TIMEOUT: Duration = Duration::from_millis(200);
        pub const DISCONNECTED_GRACE_PERIOD: Duration = Duration::from_millis(200);
    }

    #[allow(dead_code)]
    pub mod prod {
        use super::*;

        pub const PING_METRIC_INTERVAL: Duration = Duration::from_secs(25);
        pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
        pub const NO_DATA_TIMEOUT: Duration = Duration::from_secs(60);
        pub const CHECK_PEER_STATES_INTERVAL: Duration = Duration::from_secs(5);
        // TODO: STUN_INTERVAL should be minimized to ~60 seconds, after succesful STUN response
        pub const STUN_INTERVAL: Duration = Duration::from_secs(60);
        pub const CALL_ME_MAYBE_TIMEOUT: Duration = Duration::from_secs(5);
        pub const DISCONNECTED_GRACE_PERIOD: Duration = Duration::from_secs(5);
    }
}

#[cfg(test)]
use constants::test::*;

#[cfg(not(test))]
use constants::prod::*;

// Include common ones
use constants::*;

/// Posible [UdpHolePunch] errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Received packet, that wasn't expected at this state
    #[error("Received unexpected packet")]
    UnexpectedPacket,
    /// UDP socket error
    #[error(transparent)]
    SocketError(#[from] std::io::Error),
    /// Repeated action errors
    #[error(transparent)]
    RepeatedActionError(#[from] RAError),
    /// Someting is wrong with serializing/deserializing packet
    #[error(transparent)]
    PacketCodecError(#[from] telio_proto::CodecError),
    /// Control channel is closed (or overflowed)
    #[error(transparent)]
    ControlChanErr(#[from] ChanSendError<(PublicKey, CallMeMaybeMsgDeprecated)>),
    #[error(transparent)]
    ControlChanTryErr(#[from] ChanTrySendError<(PublicKey, CallMeMaybeMsgDeprecated)>),
    /// Data channel is closed (or overflowed)
    #[error(transparent)]
    DataChanErr(#[from] ChanSendError<(PublicKey, DataMsg)>),
    /// Event channel is closed (or overflowed)
    #[error(transparent)]
    EventChanErr(#[from] ChanSendError<(PublicKey, bool)>),
    /// Event channel is closed (or overflowed)
    #[error(transparent)]
    EventChanTryErr(#[from] ChanTrySendError<(PublicKey, bool)>),
    /// Stunner tx channel is closed (or overflowed)
    #[error(transparent)]
    StunnerChanErr(#[from] ChanSendError<(StunPacket, SocketAddr)>),
    /// Stunner tx channel is closed (or overflowed)
    #[error(transparent)]
    StunnerChanTryErr(#[from] ChanTrySendError<(StunPacket, SocketAddr)>),
    /// Stunner side error
    #[error(transparent)]
    StunnerErr(#[from] StunnerError),
    /// Task encountered an error while running
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
    /// Route error
    #[error(transparent)]
    RouteError(#[from] RouteError),
    /// Database error
    #[error(transparent)]
    DbError(#[from] DatabaseError),
}

type Result<T> = std::result::Result<T, Error>;

pub struct UdpHolePunch {
    task: Task<State>,
}

#[async_trait]
impl Configure for UdpHolePunch {
    async fn configure(&self, config: telio_relay::Config) {
        let _ = task_exec!(&self.task, async move |s| {
            s.stunner_srv_list =
                Some({
                    let mut list: HashSet<SocketAddr> = config
                        .servers
                        .iter()
                        .map(|srv| SocketAddr::new(IpAddr::V4(srv.ipv4), srv.stun_port))
                        .collect();

                    if USE_PLAINTEXT_STUN {
                        list.extend(config.servers.iter().map(|srv| {
                            SocketAddr::new(IpAddr::V4(srv.ipv4), srv.stun_plaintext_port)
                        }));
                    }

                    list
                });

            s.stunner
                .configure(Some(StunConfig {
                    plain_text_fallback: USE_PLAINTEXT_STUN,
                    servers: config,
                }))
                .await;

            s.reset_peers_states(true);
            Ok(())
        })
        .await;
    }
}

#[async_trait]
impl Route for UdpHolePunch {
    async fn set_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
        task_exec!(&self.task, async move |s| {
            s.db.flush();
            s.db.insert(nodes.into_iter());
            let _ = s.handle_peer_states();
            Ok(())
        })
        .await
        .map_err(|_| RouteError::SetNodesFailed)
    }

    async fn update_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
        task_exec!(&self.task, async move |s| {
            // Borrow checker happy thingy
            let curr_db: Vec<_> = s.db.iter().map(|(n, _)| *n).collect();

            for curr_node in curr_db.iter() {
                // Remove keys that is excluded in current config
                if !nodes.contains(curr_node) {
                    let _ = s.db.remove(curr_node);
                }
            }

            // Add only new nodes, not disruptint current nodes' states
            let mut nodes = nodes;
            nodes.retain(|v| !s.db.contains_key(v));

            s.db.insert(nodes.into_iter());
            let _ = s.handle_peer_states();

            Ok(())
        })
        .await
        .map_err(|_| RouteError::SetNodesFailed)
    }

    async fn reset_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
        task_exec!(&self.task, async move |s| {
            for node in nodes.iter() {
                if let Ok(entry) = s.db.get_mut_entry_by_pk(node) {
                    let _ = entry.disconnect_route(&s.events_tx);
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| RouteError::SetNodesFailed)
    }

    async fn is_reachable(&self, node: PublicKey) -> bool {
        task_exec!(&self.task, async move |s| Ok(s.db.get_state(&node)))
            .await
            .map_or(false, |r| r.is_ok())
    }

    async fn rtt(&self, node: PublicKey) -> RouteResult<Duration> {
        task_exec!(&self.task, async move |s| Ok(s.db.get_rtt(&node)))
            .await
            .map_err(RouteError::Task)?
            .map_err(|e| match e {
                DatabaseError::Route(re) => re,
                _ => RouteError::LatencyUnknown,
            })
    }
}

impl UdpHolePunch {
    /// UdpHolePunch constructor
    pub fn start(
        udp_socket: External<UdpSocket>,
        data: Chan<(PublicKey, DataMsg)>,
        control: Chan<(PublicKey, CallMeMaybeMsgDeprecated)>,
        events_tx: Tx<(PublicKey, bool)>,
        #[cfg(test)] stunner_fail_cnt: i32,
    ) -> Result<Self> {
        let udp_socket = Arc::new(udp_socket);

        let mut actions = RepeatedActions::<State, Result<()>>::new();
        actions.add_action(String::from("Do Stun"), STUN_INTERVAL, |s| {
            Box::pin(async move { s.stunner.do_stun().await.map_err(Error::StunnerErr) })
        })?;
        actions.add_action(
            String::from("Check peers' states"),
            CHECK_PEER_STATES_INTERVAL,
            |s| Box::pin(async move { s.handle_peer_states().await }),
        )?;

        #[cfg(not(test))]
        let (stunner, stunner_tx) = Stunner::start(udp_socket.clone(), None);

        #[cfg(test)]
        let (stunner, stunner_tx) = {
            let Chan {
                tx: stunner_tx,
                rx: _,
            } = Chan::default();

            let mut stunner = Stunner::new();

            let mut addr = udp_socket
                .clone()
                .local_addr()
                .expect("Cannot get udp_socket address");
            addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            stunner.expect_do_stun().returning(|| Ok(()));
            stunner.expect_handle_stun_rx().returning(|_| Ok(()));
            stunner.expect_fetch_endpoints().returning({
                let mut count = 0;
                move || {
                    count += 1;
                    if count >= stunner_fail_cnt {
                        return Ok(StunResponse {
                            remote: Some(addr),
                            local: None,
                        });
                    }
                    Err(StunnerError::NoResults)
                }
            });

            (stunner, stunner_tx)
        };

        Ok(Self {
            task: Task::start(State {
                data,
                control,
                events_tx,
                stunner_srv_list: None,
                db: Database::default(),
                actions,
                stunner,
                stunner_tx,
                rx_buff: [0u8; MAX_PACKET],
                udp_socket,
            }),
        })
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }

    #[cfg(test)]
    pub async fn get_sock_addr(&self) -> Result<SocketAddr> {
        task_exec!(&self.task, async move |s| Ok(s.udp_socket.local_addr()))
            .await
            .map_err(|e| Error::Task(e))?
            .map_err(|e| Error::SocketError(e))
    }

    #[cfg(test)]
    async fn get_node_state(&self, node: PublicKey) -> Result<CurrentRouteState> {
        task_exec!(&self.task, async move |s| {
            Ok(s.db
                .get_mut_entry_by_pk(&node)
                .map(|entry| entry.get_state())
                .map_err(Error::DbError))
        })
        .await
        .map_err(|e| Error::Task(e))?
    }
}

struct State {
    /// Channel, that sends and receives actual WireGuard and IP data
    data: Chan<(PublicKey, DataMsg)>,
    // Channel, used to send CallMeMaybe Messages between two UDP Hole Punching route instances
    control: Chan<(PublicKey, CallMeMaybeMsgDeprecated)>,
    /// Events for owner module
    events_tx: Tx<(PublicKey, bool)>,
    /// Stunner ip list
    stunner_srv_list: Option<HashSet<SocketAddr>>,
    /// Peer states database
    db: Database,
    /// Task list, that occurs every interval
    actions: RepeatedActions<Self, Result<()>>,
    /// Stunner instance
    stunner: Stunner,
    /// Receive bufferfor UDP socket
    rx_buff: [u8; MAX_PACKET],
    /// Stunner's packet upstream
    stunner_tx: Tx<(StunPacket, SocketAddr)>,
    /// Main socket for UDP communication, shared for all peers and UDP-hole punching
    udp_socket: Arc<External<UdpSocket>>,
}

impl State {
    // Check for changes in peers
    async fn handle_peer_states(&mut self) -> Result<()> {
        telio_log_trace!("({}) handle_peer_states()", Self::NAME);

        for (_, (_, entry)) in self.db.iter_mut() {
            match entry.get_state() {
                (AbsRouteState::DisconnectedByBreak(_), d) => {
                    if d >= DISCONNECTED_GRACE_PERIOD {
                        telio_log_debug!("({}) Starting CMM for entry: {}", Self::NAME, entry);

                        entry
                            .start_sent_call_me_maybe(
                                &self.control,
                                self.stunner.fetch_endpoints().await?.to_vec()?.into_iter(),
                                &self.events_tx,
                            )
                            .await?;
                    }
                }
                (AbsRouteState::InitialDisconnected(_), _) => {
                    telio_log_debug!("({}) Starting CMM for entry: {}", Self::NAME, entry);

                    entry
                        .start_sent_call_me_maybe(
                            &self.control,
                            self.stunner.fetch_endpoints().await?.to_vec()?.into_iter(),
                            &self.events_tx,
                        )
                        .await?;
                }
                (AbsRouteState::SentCallMeMaybeByStart(_), d) => {
                    if d >= CALL_ME_MAYBE_TIMEOUT {
                        telio_log_debug!("({}) Disconnected entry: {}", Self::NAME, entry);

                        let _ = entry.disconnect_route(&self.events_tx)?;
                    }
                }
                (AbsRouteState::PingingByPing(_), d) => {
                    if d >= PING_TIMEOUT {
                        if let Err(_e) = entry.choose_route(&self.events_tx, &self.udp_socket).await
                        {
                            telio_log_debug!("({}) Disconnecting entry: {}", Self::NAME, entry);

                            let _ = entry.disconnect_route(&self.events_tx)?;
                        }
                    }
                }
                (AbsRouteState::ConnectedByActivate(_), _) => {
                    if let Some(last_rx_dur) = entry.is_connected() {
                        if last_rx_dur > NO_DATA_TIMEOUT {
                            telio_log_debug!("({}) Disconnecting entry: {}", Self::NAME, entry);

                            let _ = entry.disconnect_route(&self.events_tx);
                        }
                    } else {
                        telio_log_warn!("({}) Peer's state invalid: {}", Self::NAME, entry,);
                    }

                    if let Some((measure_start, _)) = entry.is_measuring_metric() {
                        if measure_start > PING_TIMEOUT {
                            telio_log_debug!(
                                "({}) Metric measure timeout for peer {:?}, restarting ...",
                                Self::NAME,
                                entry.pk
                            );

                            if let Err(e) = entry.start_measuring_metric(&self.udp_socket).await {
                                telio_log_warn!(
                                    "({}) Error trying to measure peer's {:?} path's metric: {}",
                                    Self::NAME,
                                    entry.pk,
                                    e.to_string()
                                );
                            }
                        }
                    } else if let Some(measure_last) = entry.last_metric_measure() {
                        if measure_last > PING_METRIC_INTERVAL {
                            if let Err(e) = entry.start_measuring_metric(&self.udp_socket).await {
                                telio_log_warn!(
                                    "({}) Error trying to measure peer's {:?} path's metric: {}",
                                    Self::NAME,
                                    entry.pk,
                                    e.to_string()
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Disconnect all peers
    /// not_conn: bool - reset only not connected states
    fn reset_peers_states(&mut self, not_conn: bool) {
        for (_, (_, entry)) in self.db.iter_mut() {
            if !not_conn || entry.is_connected().is_none() {
                let _ = entry.disconnect_route(&self.events_tx);
            }
        }
    }

    async fn handle_rx_packet(
        &mut self,
        rx_len: usize,
        src_addr: &SocketAddr,
        permit: OwnedPermit<(PublicKey, DataMsg)>,
    ) -> Result<()> {
        let buf = &self.rx_buff[..rx_len];

        if let Some(list) = &self.stunner_srv_list {
            if list.contains(src_addr) {
                telio_log_trace!("handle_stun_packet(buf, src_addr: ({:?}))", src_addr);
                self.handle_stun_packet(buf, src_addr).map_or_else(
                    |e| {
                        telio_log_debug!(
                            "({}) Error handling rx Stunner packet: {}",
                            Self::NAME,
                            e.to_string()
                        );
                        Err(e)
                    },
                    |_| Ok(()),
                )?;
                return Ok(());
            }
        }

        match Packet::decode(buf) {
            Ok(Packet::Data(data_msg)) => {
                telio_log_trace!(
                    "handle_rx_data_packet(data_msg, src_addr: ({:?}), permit)",
                    src_addr
                );
                self.handle_rx_data_packet(data_msg, src_addr, permit)
                    .await
                    .map_or_else(
                        |e| {
                            telio_log_debug!(
                                "({}) Error handling rx Data packet: {}",
                                Self::NAME,
                                e.to_string(),
                            );
                            Err(e)
                        },
                        |_| Ok(()),
                    )?;
            }
            Ok(Packet::PingerDeprecated(pinger_msg)) => {
                telio_log_trace!(
                    "handle_rx_pinger_packet(pinger_msg: ({}), src_addr: ({:?}))",
                    pinger_msg,
                    src_addr
                );
                self.handle_rx_pinger_packet(pinger_msg, src_addr)
                    .await
                    .map_or_else(
                        |e| {
                            telio_log_debug!(
                                "({}) Error handling rx Pinger packet: {}",
                                Self::NAME,
                                e.to_string()
                            );
                            Err(e)
                        },
                        |_| Ok(()),
                    )?;
            }
            Err(e) => {
                return Err(Error::PacketCodecError(e));
            }
            _ => {
                return Err(Error::UnexpectedPacket);
            }
        }

        Ok(())
    }

    fn handle_stun_packet(&self, payload: &[u8], src_addr: &SocketAddr) -> Result<()> {
        self.stunner_tx
            .try_send((payload.to_vec(), *src_addr))
            .map_err(Error::StunnerChanTryErr)
    }

    async fn handle_rx_pinger_packet(
        &mut self,
        msg: PingerMsgDeprecated,
        src_addr: &SocketAddr,
    ) -> Result<()> {
        let entry = self.db.get_mut_entry_by_pid(msg.get_peer_id())?;
        let sock = self.udp_socket.clone();

        return match PingerMsgDeprecated::pong(&msg, entry.get_tx_peer_id()?).map(|a| {
            a.encode()
                .map(|buf| async move { sock.send_to(&buf, &src_addr).await })
        }) {
            // Handling Ping message, sending a reply
            Some(m) => match m {
                Ok(x) => {
                    telio_log_debug!(
                        "({}) Rx PingMsg::ping from {:?}, sending reply ...",
                        Self::NAME,
                        src_addr
                    );
                    x.await
                        .map_or_else(|e| Err(Error::SocketError(e)), |_| Ok(()))
                }
                Err(e) => Err(Error::PacketCodecError(e)),
            },
            // Handle Pong message (update database, if it expecting Pong anytime soons)
            None => {
                telio_log_debug!("({}) Rx PingMsg::pong from {:?}", Self::NAME, src_addr);

                entry.handle_pong_rx(src_addr, msg.get_session(), msg.get_start_timestamp())?;

                Ok(())
            }
        };
    }

    async fn handle_rx_data_packet(
        &mut self,
        payload: DataMsg,
        src: &SocketAddr,
        permit: OwnedPermit<(PublicKey, DataMsg)>,
    ) -> Result<()> {
        if payload.get_generation().is_none() {
            return Err(Error::UnexpectedPacket);
        }

        payload
            .get_peer_id()
            .ok_or(Error::UnexpectedPacket)
            .map(|pid| async move {
                self.db
                    .get_packet_info_rx(&(pid, *src), &self.events_tx, &self.udp_socket)
                    .await
                    .map_or_else(Err, |pk| {
                        telio_log_debug!(
                            "Rx Data packet: payload: {}, src: {}, pk: {:?}",
                            payload,
                            src,
                            pk,
                        );
                        permit.send((pk, payload));
                        Ok(())
                    })
            })?
            .await
            .map_err(Error::DbError)
    }

    async fn handle_tx_data_packet(&mut self, mut payload: DataMsg, pk: &PublicKey) -> Result<()> {
        // Check, if it is GenData
        if payload.get_generation().is_none() {
            payload.set_generation(Generation(1));
        }

        let (dst_addr, peer_id) = self.db.get_packet_info_tx(pk)?;

        payload.set_peer_id(peer_id)?;

        telio_log_debug!(
            "Tx Data packet: payload: {}, dst: {}, pk: {:?}",
            payload,
            dst_addr,
            pk,
        );

        self.udp_socket
            .send_to(payload.encode()?.as_slice(), &dst_addr)
            .await?;
        Ok(())
    }

    // TODO: there are 3 search calls to DB in this func, needs overhaul
    async fn handle_call_me_maybe(
        &mut self,
        pk: &PublicKey,
        msg: &CallMeMaybeMsgDeprecated,
        permit: OwnedPermit<(PublicKey, CallMeMaybeMsgDeprecated)>,
    ) -> Result<()> {
        // We didn't expect `this` response
        if msg.get_message_type() == CallMeMaybeDeprecatedType::RESPONDER
            && Some(msg.get_session()) != self.db.get_entry_by_pk(pk)?.get_traversal_session()
        {
            return Err(Error::DbError(DatabaseError::SessionMismatch));
        }

        // Update tx_peer_id, even though the other end (INITIATOR's case) haven't finished the traversal procedure
        self.db.update_tx_peer_id(pk, msg.get_peer_id())?;

        let entry = self.db.get_mut_entry_by_pk(pk)?;

        match msg.get_message_type() {
            CallMeMaybeDeprecatedType::INITIATOR => {
                entry
                    .handle_cmm_init_rx(
                        msg.get_addrs().into_iter(),
                        self.stunner.fetch_endpoints().await?.to_vec()?.into_iter(),
                        msg.get_session(),
                        &self.udp_socket,
                        permit,
                    )
                    .await?;
            }
            CallMeMaybeDeprecatedType::RESPONDER => {
                // Check if we're in `SentCallMeMaybe` state, if not - ignore packet
                entry
                    .start_pinging(msg.get_addrs().into_iter(), &self.udp_socket)
                    .await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "UdpHolePunch";

    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        tokio::select! {
            // Reading data from UDP socket
            Some((permit, Ok((len, src_addr)))) = wait_for_tx(&self.data.tx, self.udp_socket.recv_from(&mut self.rx_buff)) => {
                telio_log_trace!("({}) handle_rx_packet(len: ({}), src_addr: ({}))", Self::NAME, len, src_addr);
                self
                    .handle_rx_packet(len, &src_addr, permit)
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error handling rx packet: {}", Self::NAME, e.to_string());
                        Ok(())
                    }, |_| Ok(()))?;
            }
            // Received CallMeMaybe from another peer
            Some((permit, Some((pk, cmm)))) = wait_for_tx(&self.control.tx, self.control.rx.recv()) => {
                telio_log_trace!("({}) handle_call_me_maybe(pk: ({:?}), cmm: ({}), permit)", Self::NAME, pk, cmm);
                self
                    .handle_call_me_maybe(&pk, &cmm, permit)
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error handling rx CallMeMaybe packet: {}", Self::NAME, e.to_string());
                        Ok(())
                    }, |_| Ok(()))?;
            }
            // Received Data packet on Itf->WG->UDP_proxy->Path_selector -> UdpHolePunch
            Some((pk, data_msg)) = self.data.rx.recv() => {
                telio_log_trace!("({}) handle_tx_data_packet(data_msg: ({}), pk: ({:?}))", Self::NAME, data_msg, pk);
                self
                    .handle_tx_data_packet(data_msg, &pk)
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error handling tx Data packet: {}", Self::NAME, e.to_string());
                        Ok(())
                    }, |_| Ok(()))?;
            }
            // Repeated action
            Ok((name, action)) = self.actions.select_action() => {
                telio_log_trace!("({}) name: \"{}\", action = actions.select_action()", Self::NAME, name);
                action(self)
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error handling repeated action ({}): {}", Self::NAME, name, e.to_string());
                        Ok(())
                    }, |_| Ok(()))?;
            },
            // Incoming task
            update = update => {
                return update(self).await;
            }
            else => {
                return Ok(());
            },
        };

        Ok(())
    }

    async fn stop(self) {
        self.stunner.stop().await;
    }
}

#[cfg(test)]
mock! {
    pub Stunner {
        async fn do_stun(&self) -> StunnerResult<()>;
        async fn handle_stun_rx(&self, _payload: &[u8]) -> StunnerResult<()>;
        async fn fetch_endpoints(&self) -> StunnerResult<StunResponse>;
        async fn configure(&self, config: Option<StunConfig>);
        async fn stop(self);
    }
}

#[cfg(test)]
type Stunner = MockStunner;

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use telio_proto::PingType;
    use telio_sockets::SocketPool;
    use tokio::{sync::mpsc::error, time};

    /// Prepare the [`UdpHolePunch`] object along with its address
    /// ([`SocketAddr`]), events, data, control channels
    /// ([`Rx<(PublicKey, bool)>`], [`Chan<(PublicKey, DataMsg)>`],
    /// [`Chan<(PublicKey, CallMeMaybeMsgDeprecated)>`]),
    /// separate socket [`UdpSocket`] for testing and its address [`SocketAddr`]
    async fn prepare_udp_hole_punch(
        stunner_fail_cnt: i32,
    ) -> (
        UdpHolePunch,
        SocketAddr,
        Rx<(PublicKey, bool)>,
        Chan<(PublicKey, DataMsg)>,
        Chan<(PublicKey, CallMeMaybeMsgDeprecated)>,
        UdpSocket,
        SocketAddr,
        SocketPool,
    ) {
        let Chan {
            tx: events_tx,
            rx: events_rx,
        } = Chan::default();

        let (data_us, data_them) = Chan::pipe();
        let (control_us, control_them) = Chan::pipe();
        let socket_pool = SocketPool::default();
        let punch_sock = socket_pool
            .new_external_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), None)
            .await
            .expect("Cannot create UdpSocket");

        let punch =
            UdpHolePunch::start(punch_sock, data_us, control_us, events_tx, stunner_fail_cnt)
                .expect("Cannot create UdpHolePunch obj: ");

        // Getting target address of 'UdpHolePunch' obj
        let mut punch_addr = punch
            .get_sock_addr()
            .await
            .expect("Cannot get UdpHolePunch socket address: ");
        punch_addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // Creating a socket, from which this test will send packet to 'UdpHolePunch' obj
        let our_sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("Cannot create UdpSocket: ");

        let mut our_addr = our_sock
            .local_addr()
            .expect("Cannot fetch our udp_socket addr");
        our_addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        (
            punch,
            punch_addr,
            events_rx,
            data_them,
            control_them,
            our_sock,
            our_addr,
            socket_pool,
        )
    }

    #[repr(u8)]
    #[derive(Debug, PartialEq)]
    enum State {
        /// Test in construction phase
        Idle = 0x00,
        /// Expecting CallMeMaybeMsgDeprecated to arrive (UdpHolePunch --> Us.Control)
        WaitingCMM = 0x01,
        /// Expecting PingerMsgDeprecated to arrive (UdpHolePunch --> Us.UdpSocket)
        WaitingPings = 0x02,
        /// Expecting event with state `Connected` to arrive (UdpHolePunch --> Us.Events)
        WaitingConnect = 0x03,
        /// Expecting DataMsg payload to arrive (UdpHolePunch --> Us.Data)
        WaitingDataMsg = 0x04,
        /// Expecting data payload to arrive (UdpHolePunch --> Us.UdpSocket)
        WaitingRawData = 0x05,
        /// Expecting event with state `Disconnected` to arrive (UdpHolePunch --> Us.Events)
        WaitingDisconnect = 0x06,
    }

    #[tokio::test]
    async fn connect_disconnect_route() {
        // Rx packet from peer --> Connect
        // Timeout packet --> Disconnect

        let mut state = State::Idle;
        let our_rx_peer_id = PeerId(9);
        let our_tx_peer_id = PeerId(1);

        let (punch, punch_addr, mut events_rx, mut data_us, mut control_us, our_sock, our_addr, _) =
            prepare_udp_hole_punch(0).await;

        // This will have `rx_peer_id = 1`
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        // Sending GenDataMsg to 'UdpHolePunch' obj
        let payload = DataMsg::with_generation(&[0u8; 16], Generation(1u8), our_tx_peer_id)
            .encode()
            .expect("Cannot encode DataMsg: ");

        our_sock
            .send_to(&payload, punch_addr)
            .await
            .expect("Cannot send payload: ");

        // Send CMM as initiators
        control_us
            .tx
            .send((
                pubkey_list[0],
                CallMeMaybeMsgDeprecated::new(
                    true,
                    vec![our_addr].into_iter(),
                    u64::MAX,
                    our_rx_peer_id,
                ),
            ))
            .await
            .expect("Cannot send CallMeMaybeMsgDeprecated request");

        state = State::WaitingConnect;

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(NO_DATA_TIMEOUT * 4);
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    Some((_, connect)) = events_rx.recv() => {
                        if connect && state == State::WaitingConnect {
                            assert!(punch.is_reachable(pubkey_list[0].clone()).await);
                            state = State::WaitingDisconnect;
                            continue;
                        } else if !connect && state == State::WaitingDisconnect {
                            assert!(!punch.is_reachable(pubkey_list[0]).await);
                            break;
                            // Test is a great success!
                        } else {
                            assert!(false, "Invalid state! {:?}", state);
                        }
                    }
                    _ = data_us.rx.recv() => {}
                    _ = control_us.rx.recv() => {}
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = punch.stop().await;
        })
        .await;
    }

    #[tokio::test]
    async fn states_happy_path() {
        // Add peer
        // Receive - Respond CMM
        // Receive - Respond Ping
        // Receive 'Connect' event, send data to socket
        // Receive data in pipe, send data to pipe
        // Receive data in socket
        // Wait for no-data-timeout
        // Receive 'Disconnect' event

        let mut state = State::Idle;
        let our_rx_peer_id = PeerId(9);
        let our_tx_peer_id = PeerId(1);

        let (
            punch,
            punch_addr,
            mut events_rx,
            mut data_us,
            mut control_us,
            our_sock,
            our_addr,
            _pool,
        ) = prepare_udp_hole_punch(0).await;

        // This will have `rx_peer_id = 1`
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        state = State::WaitingCMM;

        // Runtime
        let _ = tokio::spawn(async move {
            // Global test timeout
            let timeout = time::sleep(4 * (NO_DATA_TIMEOUT + PING_TIMEOUT));
            tokio::pin!(timeout);

            let mut rx_buff = [0; MAX_PACKET];

            loop {
                tokio::select! {
                    Some((pk, connect)) = events_rx.recv() => {
                        assert_eq!(pk, pubkey_list[0]);

                        match state {
                            State::WaitingConnect => {
                                if connect {
                                    // Sending GenDataMsg to 'UdpHolePunch' obj
                                    let payload = DataMsg::with_generation(&[0u8; 16], Generation(1u8), our_tx_peer_id)
                                        .encode()
                                        .expect("Cannot encode DataMsg: ");

                                    our_sock.send_to(&payload, punch_addr).await.expect("Cannot send payload: ");

                                    state = State::WaitingDataMsg;
                                    continue;
                                }
                            }
                            State::WaitingDisconnect => {
                                assert!(!punch.is_reachable(pubkey_list[0]).await);
                                break;
                                // Test is a great success!
                            }
                            _ => {
                                assert!(false, "Invalid state! {:?}", state);
                            }
                        }
                    }
                    Some((pk, data)) = data_us.rx.recv() => {
                        assert_eq!(pk, pubkey_list[0]);

                        match state {
                            State::WaitingDataMsg => {
                                assert_eq!(data.get_generation().expect("Cannot get DataMsg generation"), Generation(1u8));

                                let payload = DataMsg::with_generation(&[0u8; 16], Generation(1u8), our_tx_peer_id);
                                data_us.tx.send((pk, payload))
                                    .await
                                    .expect("Cannot send DataMsg response");

                                state = State::WaitingRawData;
                                continue;
                            }
                            _ => {
                                assert!(false, "Invalid state! {:?}", state);
                            }
                        }
                    }
                    Some((pk, cmm)) = control_us.rx.recv() => {
                        assert_eq!(pk, pubkey_list[0]);

                        match state {
                            State::WaitingCMM => {
                                // Check that we're in correct state
                                assert!(matches!(
                                    punch
                                        .get_node_state(pubkey_list[0].clone())
                                        .await
                                        .expect("Cannot get UdpHolePunch node's state: ")
                                        .0,
                                    AbsRouteState::SentCallMeMaybeByStart(_)));

                                // Check that "UdpHolePunch" is initiator
                                assert!(cmm.get_message_type() == CallMeMaybeDeprecatedType::INITIATOR);

                                // Check that MockStunner is producing expected results
                                assert_eq!(vec![punch_addr], cmm.get_addrs());

                                assert_eq!(our_tx_peer_id, cmm.get_peer_id());

                                // Send reply back
                                control_us.tx.send((
                                    pk,
                                    CallMeMaybeMsgDeprecated::new(
                                        false,
                                        vec![our_addr].into_iter(),
                                        cmm.get_session(),
                                        our_rx_peer_id,
                                    ),
                                ))
                                .await
                                .expect("Cannot send CallMeMaybeMsgDeprecated response");

                                state = State::WaitingPings;
                                continue;
                            }
                            _ => {
                                assert!(false, "Invalid state! {:?}", state);
                            }
                        }
                    }
                    Ok((len, addr)) = our_sock.recv_from(&mut rx_buff) => {
                        let buf = &rx_buff[..len];

                        // Check, if this packet from where is supposed to come
                        assert_eq!(addr, punch_addr);

                        match state {
                            State::WaitingPings => {
                                match Packet::decode(buf) {
                                    Ok(Packet::PingerDeprecated(pinger_msg)) => {
                                        assert_eq!(pinger_msg.get_message_type(), PingType::PING);
                                        assert_eq!(pinger_msg.get_peer_id(), our_rx_peer_id);

                                        // Simulating network delay
                                        time::sleep(Duration::from_millis(5)).await;

                                        let reply = pinger_msg.pong(our_tx_peer_id)
                                            .expect("Failed to create PingerMsgDeprecated::Pong: ")
                                            .encode()
                                            .expect("Failed to encode PingerMsgDeprecated: ");

                                        our_sock.send_to(&reply, punch_addr)
                                            .await
                                            .expect("Cannot send payload: ");

                                        state = State::WaitingConnect;

                                        continue;
                                    }
                                    _ => {
                                        assert!(false, "Invalid packet received!");
                                    }
                                }
                            }
                            State::WaitingRawData => {
                                match Packet::decode(buf) {
                                    Ok(Packet::Data(data_msg)) => {
                                        assert_eq!(data_msg.get_generation().expect("Cannot get DataMsg generation"), Generation(1u8));

                                        state = State::WaitingDisconnect;

                                        continue;
                                    }
                                    _ => {
                                        assert!(false, "Invalid packet received!");
                                    }
                                }
                            }
                            _ => {
                                assert!(false, "Invalid state! {:?}", state);
                            }
                        }
                    }
                    _ = &mut timeout => { assert!(false, "Timeout!"); }
                }
            }

            let _ = punch.stop().await;
        }).await;
    }

    #[tokio::test]
    async fn initial_hole_punch_ping() {
        // Add peer
        // Send CMM as initiator
        // Receive init Ping

        let mut state = State::Idle;
        let our_rx_peer_id = PeerId(9);

        let (
            punch,
            punch_addr,
            mut events_rx,
            mut data_us,
            mut control_us,
            our_sock,
            our_addr,
            _pool,
        ) = prepare_udp_hole_punch(0).await;

        // This will have `rx_peer_id = 1`
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        // Send CMM as initiators
        control_us
            .tx
            .send((
                pubkey_list[0],
                CallMeMaybeMsgDeprecated::new(
                    true,
                    vec![our_addr].into_iter(),
                    u64::MAX,
                    our_rx_peer_id,
                ),
            ))
            .await
            .expect("Cannot send CallMeMaybeMsgDeprecated request");

        state = State::WaitingPings;

        // Runtime
        let _ = tokio::spawn(async move {
            // Global test timeout
            let timeout = time::sleep(20 * PING_TIMEOUT);
            tokio::pin!(timeout);

            let mut rx_buff = [0; MAX_PACKET];

            loop {
                tokio::select! {
                    Ok((len, addr)) = our_sock.recv_from(&mut rx_buff) => {
                        let buf = &rx_buff[..len];

                        // Check, if this packet from where is supposed to come
                        assert_eq!(addr, punch_addr, "Addresses does not match");

                        match state {
                            State::WaitingPings => {
                                match Packet::decode(buf) {
                                    Ok(Packet::PingerDeprecated(pinger_msg)) => {
                                        assert_eq!(pinger_msg.get_message_type(), PingType::PING);
                                        assert_eq!(pinger_msg.get_peer_id(), our_rx_peer_id);
                                        break;
                                    }
                                    _ => {
                                        assert!(false, "Invalid packet received!");
                                    }
                                }
                            }
                            _ => {
                                assert!(false, "Invalid state! {:?}", state);
                            }
                        }
                    }
                    _ = events_rx.recv() => {}
                    _ = data_us.rx.recv() => {}
                    _ = control_us.rx.recv() => {}
                    _ = &mut timeout => { assert!(false, "Timeout!"); }
                }
            }

            let _ = punch.stop().await;
        })
        .await;
    }

    #[tokio::test]
    async fn states_fallback() {
        // Add peer
        // Receive - Ignore CMM
        // Receive - Respond CMM
        // Receive - Ignore Ping, expect fallback to begining
        // Receive - Respond CMM
        // Receive - Respond Ping
        // Receive 'Connect' event

        #[derive(PartialEq, Debug)]
        enum Phase {
            IgnoreCMM,
            IgnorePing,
            Connect,
        }

        let mut phase = Phase::IgnoreCMM;
        let mut state = State::Idle;
        let our_rx_peer_id = PeerId(9);
        let our_tx_peer_id = PeerId(1);

        let (
            punch,
            punch_addr,
            mut events_rx,
            mut data_us,
            mut control_us,
            our_sock,
            our_addr,
            _pool,
        ) = prepare_udp_hole_punch(0).await;

        // This will have `rx_peer_id = 1`
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        state = State::WaitingCMM;

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(NO_DATA_TIMEOUT * 20);
            tokio::pin!(timeout);

            let mut rx_buff = [0; MAX_PACKET];

            loop {
                tokio::select! {
                    Some((pk, cmm)) = control_us.rx.recv() => {
                        if state == State::WaitingCMM {
                            assert_eq!(cmm.get_message_type(), CallMeMaybeDeprecatedType::INITIATOR);

                            // First one we ignore
                            match phase {
                                Phase::IgnoreCMM => {
                                    phase = Phase::IgnorePing;
                                    continue;
                                }
                                _ => (),
                            };

                            // Send reply back
                            control_us.tx.send((
                                pk,
                                CallMeMaybeMsgDeprecated::new(
                                    false,
                                    vec![our_addr].into_iter(),
                                    cmm.get_session(),
                                    our_rx_peer_id,
                                ),
                            ))
                            .await
                            .expect("Cannot send CallMeMaybeMsgDeprecated response");

                            // Skipping the UDP punch ping from our side, at this stage, because it shouldn't affect any state in UdpHolePunch obj
                            state = State::WaitingPings;
                            continue;
                        }

                        assert!(false, "Invalid state! {:?}", state);
                    }
                    Ok((len, addr)) = our_sock.recv_from(&mut rx_buff) => {
                        let buf = &rx_buff[..len];

                        // Check, if this packet from where is supposed to come
                        assert_eq!(addr, punch_addr);

                        match Packet::decode(buf) {
                            Ok(Packet::PingerDeprecated(pinger_msg)) => {
                                if state == State::WaitingPings {
                                    assert_eq!(pinger_msg.get_message_type(), PingType::PING);
                                    assert_eq!(pinger_msg.get_peer_id(), our_rx_peer_id);

                                    match phase {
                                        Phase::IgnorePing => {
                                            phase = Phase::Connect;
                                            state = State::WaitingCMM;
                                            continue;
                                        }
                                        _ => (),
                                    };

                                    // Simulating network delay
                                    time::sleep(Duration::from_millis(5)).await;

                                    let reply = pinger_msg.pong(our_tx_peer_id)
                                        .expect("Failed to create PingerMsgDeprecated::Pong: ")
                                        .encode()
                                        .expect("Failed to encode PingerMsgDeprecated: ");

                                    our_sock.send_to(&reply, punch_addr)
                                        .await
                                        .expect("Cannot send payload: ");

                                    state = State::WaitingConnect;
                                    continue;
                                }

                                assert!(false, "Invalid state! {:?}", state);
                            }
                            _ => {
                                assert!(false, "Invalid packet received!");
                            }
                        }
                    }
                    Some((_, connect)) = events_rx.recv() => {
                        if phase == Phase::Connect {
                            if connect && state == State::WaitingConnect {
                                // Success
                                break;
                            }
                        }

                        continue;
                    }
                    _ = data_us.rx.recv() => {}
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = punch.stop().await;
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "Needs a proper mock, that handle UHP states easily"]
    async fn reconnect_from_other_peer() {
        // Add peer and wait for CMM(Init)
        // Send DataMsg and wait for 'Connect' event
        // Send CMM(Init), expect CMM(Response), ignore upcoming Ping
        // Send Ping, expect Pong
        // Send DataMsg, expect data on other end

        let mut state = State::Idle;
        let our_rx_peer_id = PeerId(9);
        let our_tx_peer_id = PeerId(1);

        let (
            punch,
            punch_addr,
            mut events_rx,
            mut data_us,
            mut control_us,
            our_sock,
            our_addr,
            _pool,
        ) = prepare_udp_hole_punch(0).await;

        // This will have `rx_peer_id = 1`
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        // Sending GenDataMsg to 'UdpHolePunch' obj
        let payload = DataMsg::with_generation(&[0u8; 16], Generation(1u8), our_tx_peer_id)
            .encode()
            .expect("Cannot encode DataMsg: ");

        state = State::WaitingCMM;

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(NO_DATA_TIMEOUT * 4);
            tokio::pin!(timeout);

            let mut rx_buff = [0; MAX_PACKET];
            let mut ignore_data: bool = true;
            let mut ignore_ping: bool = false;

            loop {
                tokio::select! {
                    Some((_, connect)) = events_rx.recv() => {
                        if connect && state == State::WaitingConnect {
                            assert!(punch.is_reachable(pubkey_list[0].clone()).await);

                            // Send CMM as initiator
                            control_us.tx.send((
                                pubkey_list[0],
                                CallMeMaybeMsgDeprecated::new(
                                    true,
                                    vec![our_addr].into_iter(),
                                    u64::MAX,
                                    our_rx_peer_id,
                                ),
                            ))
                            .await
                            .expect("Cannot send CallMeMaybeMsgDeprecated request");

                            // Ignoring Ping for UDP punch
                            ignore_ping = true;

                            state = State::WaitingCMM;
                            continue;
                        }

                        assert!(false, "Invalid state or event! state: {:?}, event: {:?}", state, connect);
                    }
                    Some((_, data)) = data_us.rx.recv() => {
                        if !ignore_data && state == State::WaitingDataMsg {
                            assert_eq!(data.get_generation().expect("Cannot get DataMsg generation"), Generation(1u8));
                            assert_eq!(data.get_peer_id().expect("Cannot get DataMsg generation"), our_tx_peer_id);
                            // Success
                            break;
                        }

                        // Clear the flag from 'Connect' event
                        if ignore_data {
                            ignore_data = false;
                            continue;
                        }

                        assert!(false, "Invalid state! {:?}", state);
                    }
                    Some((_, cmm)) = control_us.rx.recv() => {
                        if state == State::WaitingCMM {
                            if cmm.get_message_type() == CallMeMaybeDeprecatedType::INITIATOR {
                                our_sock
                                    .send_to(&payload, punch_addr)
                                    .await
                                    .expect("Cannot send payload: ");

                                state = State::WaitingConnect;
                                continue;
                            }

                            assert_eq!(cmm.get_message_type(), CallMeMaybeDeprecatedType::RESPONDER);
                            assert_eq!(cmm.get_session(), u64::MAX);
                            assert_eq!(cmm.get_peer_id(), our_tx_peer_id);

                            let ping = PingerMsgDeprecated::ping(our_tx_peer_id, u64::MAX, u64::MIN)
                                .encode()
                                .expect("Cannot encode Ping");

                            our_sock.send_to(&ping, cmm.get_addrs()[0])
                                .await
                                .expect("Cannot send payload: ");

                            state = State::WaitingPings;
                            continue;
                        }

                        assert!(false, "Invalid state! {:?}", state);
                    }
                    Ok((len, addr)) = our_sock.recv_from(&mut rx_buff) => {
                        let buf = &rx_buff[..len];

                        // Check, if this packet from where is supposed to come
                        assert_eq!(addr, punch_addr);

                        match Packet::decode(buf) {
                            Ok(Packet::PingerDeprecated(pinger_msg)) => {
                                if state == State::WaitingPings {
                                    // Clear the flag from initial CMM ping
                                    if ignore_ping {
                                        ignore_ping = false;
                                        continue;
                                    }

                                    assert_eq!(pinger_msg.get_message_type(), PingType::PONG);
                                    assert_eq!(pinger_msg.get_peer_id(), our_rx_peer_id);
                                    assert_eq!(pinger_msg.get_session(), u64::MAX);
                                    assert_eq!(pinger_msg.get_start_timestamp(), u64::MIN);

                                    our_sock
                                        .send_to(&payload, addr)
                                        .await
                                        .expect("Cannot send payload: ");

                                    state = State::WaitingDataMsg;
                                    continue;
                                } else {
                                    assert!(false, "Invalid state! {:?}", state);
                                }
                            }
                            _ => {
                                assert!(false, "Invalid packet received!");
                            }
                        }
                    }
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = punch.stop().await;
        })
        .await;
    }

    #[tokio::test]
    async fn tx_rx_peer_disconnected() {
        // Send data for non-existent peer
        // Send data for disconnected peer
        // Receive data from non existent address
        // Receive data from non disconnected address

        let mut state = State::Idle;
        let our_tx_peer_id = PeerId(1);
        let our_rx_peer_id = PeerId(9);
        let mut rx_buff = [0; MAX_PACKET];

        let (punch, punch_addr, mut events_rx, mut data_us, mut control_us, our_sock, our_addr, _) =
            prepare_udp_hole_punch(0).await;

        // This will have `rx_peer_id = 1`
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        let payload = DataMsg::with_generation(&[0u8; 16], Generation(1u8), our_tx_peer_id);

        data_us
            .tx
            .send((
                "GB2q5nJA3PUm/U5u3PAtLLmsLQ7nwCYo7YzfyYcjWzY="
                    .parse::<PublicKey>()
                    .unwrap(),
                payload.clone(),
            ))
            .await
            .expect("Cannot send DataMsg");

        // Case 1: Tx to non - existent peer
        assert!(our_sock.try_recv(&mut rx_buff).is_err());

        data_us
            .tx
            .send((
                "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
                    .parse::<PublicKey>()
                    .unwrap(),
                payload.clone(),
            ))
            .await
            .expect("Cannot send DataMsg");

        // Case 2: Tx to not connected peer
        assert!(our_sock.try_recv(&mut rx_buff).is_err());

        // Send CMM as initiators
        control_us
            .tx
            .send((
                pubkey_list[0],
                CallMeMaybeMsgDeprecated::new(
                    true,
                    vec![our_addr].into_iter(),
                    u64::MAX,
                    our_rx_peer_id,
                ),
            ))
            .await
            .expect("Cannot send CallMeMaybeMsgDeprecated request");

        our_sock
            .send_to(&payload.clone().encode().unwrap(), punch_addr)
            .await
            .expect("Cannot send payload: ");

        let false_sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("Cannot create 2nd UdpSocket: ");

        state = State::WaitingConnect;

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(NO_DATA_TIMEOUT * 4);
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    Some((_, connect)) = events_rx.recv() => {
                        if connect && state == State::WaitingConnect {
                            assert!(punch.is_reachable(pubkey_list[0].clone()).await);
                            assert!(data_us.rx.recv().await.is_some());

                            false_sock.send_to(&payload.clone().encode().unwrap(), punch_addr)
                                .await
                                .expect("Cannot send payload: ");

                            // Case 3: Invalid src address
                            assert_eq!(Err(error::TryRecvError::Empty), data_us.rx.try_recv());

                            // Success
                            break;
                        } else {
                            assert!(false, "Invalid state or event, state: {:?}, event: {:?}", state, connect);
                        }
                    }
                    // _ = data_us.rx.recv() => {}
                    _ = control_us.rx.recv() => {}
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = punch.stop().await;
        })
        .await;
    }

    #[tokio::test]
    async fn stunner_fails_at_init() {
        // Add peer, stunner fails 4 times at start, suceeds at 5

        let mut state = State::Idle;
        let our_tx_peer_id = PeerId(1);

        let (punch, punch_addr, mut events_rx, mut data_us, mut control_us, our_sock, _, _pool) =
            prepare_udp_hole_punch(5).await;

        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        state = State::WaitingCMM;

        // Runtime
        let _ = tokio::spawn(async move {
            // Global test timeout
            let timeout = time::sleep(4 * (NO_DATA_TIMEOUT + PING_TIMEOUT));
            tokio::pin!(timeout);

            let mut rx_buff = [0; MAX_PACKET];

            loop {
                tokio::select! {
                    _ = events_rx.recv() => {}
                    _ = data_us.rx.recv() => {}
                    Some((pk, cmm)) = control_us.rx.recv() => {
                        assert_eq!(pk, pubkey_list[0]);

                        match state {
                            State::WaitingCMM => {
                                // Check that we're in correct state
                                assert!(matches!(
                                    punch
                                        .get_node_state(pubkey_list[0].clone())
                                        .await
                                        .expect("Cannot get UdpHolePunch node's state: ")
                                        .0,
                                    AbsRouteState::SentCallMeMaybeByStart(_)));

                                // Check that "UdpHolePunch" is initiator
                                assert!(cmm.get_message_type() == CallMeMaybeDeprecatedType::INITIATOR);

                                // Check that MockStunner is producing expected results
                                assert_eq!(vec![punch_addr], cmm.get_addrs());
                                assert_eq!(our_tx_peer_id, cmm.get_peer_id());
                                break;
                            }
                            _ => {
                                assert!(false, "Invalid state! {:?}", state);
                            }
                        }
                    }
                    _ = our_sock.recv_from(&mut rx_buff) => {}
                    _ = &mut timeout => { assert!(false, "Timeout!"); }
                }
            }

            let _ = punch.stop().await;
        })
        .await;
    }

    #[tokio::test]
    async fn metrics_collection() {
        // Add peer
        // Receive packet and 'Connect' event
        // Wait for metric pinging to complete
        // get rtt() with some reasonable amount

        let network_delay = Duration::from_millis(5);
        let our_rx_peer_id = PeerId(9);
        let our_tx_peer_id = PeerId(1);
        let mut state = State::Idle;

        let (punch, punch_addr, mut events_rx, mut data_us, mut control_us, our_sock, our_addr, _) =
            prepare_udp_hole_punch(0).await;

        // This will have `rx_peer_id = 1`
        let pubkey_list = vec!["REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
            .parse::<PublicKey>()
            .unwrap()];

        punch
            .set_nodes(pubkey_list.clone())
            .await
            .expect("Cannot set nodes: ");

        // Sending GenDataMsg to 'UdpHolePunch' obj
        let payload = DataMsg::with_generation(&[0u8; 16], Generation(1u8), our_tx_peer_id)
            .encode()
            .expect("Cannot encode DataMsg: ");

        // Send CMM as initiators
        control_us
            .tx
            .send((
                pubkey_list[0],
                CallMeMaybeMsgDeprecated::new(
                    true,
                    vec![our_addr].into_iter(),
                    u64::MAX,
                    our_rx_peer_id,
                ),
            ))
            .await
            .expect("Cannot send CallMeMaybeMsgDeprecated request");

        our_sock
            .send_to(&payload, punch_addr)
            .await
            .expect("Cannot send payload: ");

        state = State::WaitingConnect;

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(NO_DATA_TIMEOUT * 4);
            tokio::pin!(timeout);

            let mut rx_buff = [0; MAX_PACKET];

            let mut ignore_first_ping = true;

            loop {
                tokio::select! {
                    Some((_, connect)) = events_rx.recv() => {
                        if connect && state == State::WaitingConnect {
                            assert!(punch.is_reachable(pubkey_list[0].clone()).await);
                            state = State::WaitingPings;
                            continue;
                        } else if !connect && state == State::WaitingDisconnect {
                            assert!(!punch.is_reachable(pubkey_list[0]).await);
                            break;
                            // Test is a great success!
                        } else {
                            assert!(false, "Invalid state! {:?}", state);
                        }
                    }
                    Ok((len, addr)) = our_sock.recv_from(&mut rx_buff) => {
                        let buf = &rx_buff[..len];

                        // Check, if this packet from where is supposed to come
                        assert_eq!(addr, punch_addr);

                        // Ignoring hole-punch ping
                        if ignore_first_ping {
                            ignore_first_ping = false;
                            continue;
                        }

                        match state {
                            State::WaitingPings => {
                                match Packet::decode(buf) {
                                    Ok(Packet::PingerDeprecated(pinger_msg)) => {
                                        assert_eq!(pinger_msg.get_message_type(), PingType::PING);
                                        assert_eq!(pinger_msg.get_peer_id(), our_rx_peer_id);

                                        // Simulating network delay
                                        time::sleep(network_delay).await;

                                        let reply = pinger_msg.pong(our_tx_peer_id)
                                            .expect("Failed to create PingerMsgDeprecated::Pong: ")
                                            .encode()
                                            .expect("Failed to encode PingerMsgDeprecated: ");

                                        our_sock.send_to(&reply, punch_addr)
                                            .await
                                            .expect("Cannot send payload: ");

                                        // Waiting for other peer to process pong
                                        time::sleep(network_delay).await;

                                        assert!(network_delay <= punch.rtt(pubkey_list[0].clone()).await.unwrap());

                                        state = State::WaitingDisconnect;

                                        continue;
                                    }
                                    _ => {
                                        assert!(false, "Invalid packet received!");
                                    }
                                }
                            }
                            _ => {
                                assert!(false, "Invalid state! {:?}", state);
                            }
                        }
                    }
                    _ = data_us.rx.recv() => {}
                    _ = control_us.rx.recv() => {}
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = punch.stop().await;
        })
        .await;
    }
}
