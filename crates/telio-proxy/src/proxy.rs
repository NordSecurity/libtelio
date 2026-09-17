#![deny(unsafe_code)]
use async_trait::async_trait;
use futures::future::{pending, select_all, FutureExt};
use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use telio_crypto::PublicKey;
use telio_model::EndpointMap;
use telio_proto::{DataMsg, MAX_PACKET_SIZE};
use telio_sockets::{SocketBufSizes, SocketPool, UdpParams};
use telio_task::{
    io::{
        chan::{Rx, Tx},
        wait_for_tx, Chan,
    },
    task_exec, Runtime, RuntimeExt, Task, WaitResponse,
};
use tokio::{net::UdpSocket, sync::mpsc::error::SendTimeoutError};

use telio_utils::{
    exponential_backoff::{Backoff, ExponentialBackoff, ExponentialBackoffBounds},
    telio_log_debug, telio_log_error, telio_log_info, telio_log_warn, PinnedSleep,
};

type SocketMap = HashMap<PublicKey, Arc<UdpSocket>>;
type SocketMuteMap = HashMap<PublicKey, (Arc<UdpSocket>, Option<PinnedSleep<PublicKey>>)>;

const SOCK_BUF_SZ: usize = 212992;

#[derive(Debug, thiserror::Error)]
/// Custom `UdpProxy` error
pub enum Error {
    #[error("UdpProxy Stopped")]
    /// `UdpProxy` Stopped Error
    Stopped,
    #[error("UdpProxy IoError")]
    /// `UdpProxy` `IoError`
    IoError(#[from] std::io::Error),
    /// Task execution failed
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
    /// Send failed
    #[error(transparent)]
    Send(#[from] SendTimeoutError<(PublicKey, DataMsg)>),
    /// Peer not found
    #[error("Peer not found error")]
    PeerNotFound,
}

#[derive(Debug, thiserror::Error)]
/// Mapping proxy errors into 3 broad categories
pub enum ErrorType {
    /// Error will recover automatically
    #[error("Recoverable Error")]
    RecoverableError,
    /// Error cannot be resolved in this module and
    /// has to be handled externally
    #[error("Unrecoverable Error")]
    UnrecoverableError,
    /// Socket IO error. Restart the WG socket and continue
    #[error("Socket IO Error")]
    SocketIOError,
}

impl From<std::io::Error> for ErrorType {
    fn from(f: std::io::Error) -> ErrorType {
        match f.kind() {
            ErrorKind::PermissionDenied | ErrorKind::InvalidInput | ErrorKind::InvalidData => {
                ErrorType::SocketIOError
            }
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::TimedOut
            | ErrorKind::WriteZero
            | ErrorKind::AddrNotAvailable => ErrorType::RecoverableError,
            ErrorKind::BrokenPipe => ErrorType::UnrecoverableError,
            _ => ErrorType::RecoverableError,
        }
    }
}

/// Proxy links incoming and outgoing WG Packets to
/// separate endpoints and by those endpoints identifies public key.
#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait Proxy {
    /// Get currently mapped sockets
    async fn get_endpoint_map(&self) -> Result<EndpointMap, Error>;
    /// Set currently used WG listen port
    async fn set_wg_address(&self, wg_addr: Option<SocketAddr>) -> Result<(), Error>;
    /// Mute peer for duration (or unmute if duration is None)
    async fn mute_peer(&self, pk: PublicKey, dur: Option<Duration>) -> Result<(), Error>;
}

/// `UdpProxy` struct wrapping its state in Task runtime
/// --
/// State contains:
/// * Io channel
/// * WG address
/// * `HashMap` of all Sockets and their associated Public Keys
///
/// WG Packet becomes [DataMsg] payload, and then is sent to and from IO.relay.
pub struct UdpProxy {
    // Packets WG -> Proxy
    task_ingress: Task<StateIngress>,
    // Packets Proxy -> WG
    task_egress: Task<StateEgress>,
}

/// Input/output channel for proxy
pub struct Io {
    /// Channel of PublicKey and Buffer, contains sender and receiver
    pub relay: Chan<(PublicKey, DataMsg)>,
}

/// `UdpProxy` configuration.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// WG port address
    pub wg_port: Option<u16>,
    /// tracked WG peers
    pub peers: HashSet<PublicKey>,
}

struct StateIngress {
    sockets: SocketMap,
    output: Tx<(PublicKey, DataMsg)>,
    read_buf: Box<[u8; MAX_PACKET_SIZE]>,
    updated_socket: Rx<(PublicKey, Arc<UdpSocket>)>,
}

struct StateEgress {
    sockets: SocketMuteMap,
    input: Rx<(PublicKey, DataMsg)>,
    wg_addr: Option<SocketAddr>,
    conn_state: Result<(), std::io::ErrorKind>,
    update_socket: Tx<(PublicKey, Arc<UdpSocket>)>,
    peer_socket_backoffs: HashMap<PublicKey, (ExponentialBackoff, PinnedSleep<PublicKey>)>,
    replaced_sockets: EndpointMap,
}

impl UdpProxy {
    /// Start `UdpProxy`
    pub fn start(io: Io) -> Self {
        let Chan {
            tx: update_socket,
            rx: updated_socket,
        } = Chan::new(16);

        UdpProxy {
            task_ingress: Task::start(StateIngress {
                sockets: HashMap::new(),
                output: io.relay.tx,
                read_buf: Box::new([0u8; MAX_PACKET_SIZE]),
                updated_socket,
            }),
            task_egress: Task::start(StateEgress {
                sockets: HashMap::new(),
                input: io.relay.rx,
                wg_addr: None,
                conn_state: Err(ErrorKind::NotConnected),
                update_socket,
                peer_socket_backoffs: HashMap::new(),
                replaced_sockets: HashMap::new(),
            }),
        }
    }

    /// Update configuration for the background task
    pub async fn configure(&self, config: Config) -> Result<(), Error> {
        let port = config.wg_port;

        let sockets = task_exec!(&self.task_ingress, async move |state| {
            Ok(state.configure(config).await)
        })
        .await??;

        task_exec!(&self.task_egress, async move |state| {
            state.reset_socket_limit().await;
            Ok(state.configure(sockets, port).await)
        })
        .await?
    }

    /// Stop proxy
    pub async fn stop(self) {
        let _ = self.task_egress.stop().await.resume_unwind();
        let _ = self.task_ingress.stop().await.resume_unwind();
    }

    #[cfg(test)]
    /// Stop proxy
    pub async fn stop_reverse(self) {
        let _ = self.task_egress.stop().await.resume_unwind();
        let _ = self.task_ingress.stop().await.resume_unwind();
    }

    /// Notify proxy about network change
    pub async fn on_network_change(&self) {
        let _ = task_exec!(&self.task_egress, async move |state| {
            state.reset_socket_limit().await;
            Ok(())
        })
        .await;
    }
}

#[async_trait]
impl Proxy for UdpProxy {
    async fn get_endpoint_map(&self) -> Result<EndpointMap, Error> {
        task_exec!(&self.task_egress, async move |state| {
            Ok(state.get_endpoints_map().await)
        })
        .await?
    }

    async fn set_wg_address(&self, wg_addr: Option<SocketAddr>) -> Result<(), Error> {
        task_exec!(&self.task_egress, async move |state| {
            if state.wg_addr != wg_addr {
                telio_log_info!(
                    "Updating wg_listen_port from {:?} to {:?}",
                    state.wg_addr,
                    wg_addr
                );
                state.wg_addr = wg_addr;
            }
            Ok(())
        })
        .await?;
        Ok(())
    }

    async fn mute_peer(&self, pk: PublicKey, dur: Option<Duration>) -> Result<(), Error> {
        task_exec!(&self.task_egress, async move |state| {
            match dur {
                Some(d) => Ok(state.try_mute(&pk, d)),
                None => Ok(state.try_unmute(&pk)),
            }
        })
        .await?
    }
}

impl StateIngress {
    async fn configure(&mut self, config: Config) -> Result<SocketMap, Error> {
        telio_log_debug!("Configuring ingress proxy: {:?}", &config);

        let current: HashSet<_> = self.sockets.keys().copied().collect();

        let del = &current - &config.peers;
        for peer in del.iter() {
            self.sockets.remove(peer);
        }

        let add = &config.peers - &current;
        for peer in add.into_iter() {
            let socket = SocketPool::new_udp(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                Some(UdpParams(SocketBufSizes {
                    rx_buf_size: Some(SOCK_BUF_SZ),
                    tx_buf_size: Some(SOCK_BUF_SZ),
                })),
            )
            .await?;

            let socket = Arc::new(socket);
            self.sockets.insert(peer, socket);
        }

        Ok(self.sockets.clone())
    }
}

impl StateEgress {
    async fn configure(&mut self, sockets: SocketMap, wg_port: Option<u16>) -> Result<(), Error> {
        telio_log_debug!("Configuring egress proxy with wg port {:?}", wg_port);

        self.wg_addr = wg_port.map(|p| (Ipv4Addr::LOCALHOST, p).into());

        self.sockets.retain(|&pk, _| sockets.contains_key(&pk));
        for (pk, new_socket) in sockets {
            // Update socket but keep the mute, else insert a new unmuted socket
            if let Some((old_socket, _)) = self.sockets.get_mut(&pk) {
                *old_socket = new_socket;
            } else {
                self.sockets.insert(pk, (new_socket, None));
            }
        }

        Ok(())
    }

    async fn reset_socket_limit(&mut self) {
        self.peer_socket_backoffs.clear();
        self.replaced_sockets.clear();
    }

    async fn get_endpoints_map(&mut self) -> Result<EndpointMap, Error> {
        let mut map = EndpointMap::new();

        for (key, (sock, _)) in self.sockets.iter() {
            let mut peer_endpoints = self.replaced_sockets.remove(key).unwrap_or_default();
            peer_endpoints.insert(0, sock.local_addr()?);
            map.insert(*key, peer_endpoints);
        }

        Ok(map)
    }

    fn try_mute(&mut self, pk: &PublicKey, dur: Duration) -> Result<(), Error> {
        let Some((_, mute)) = self.sockets.get_mut(pk) else {
            return Err(Error::PeerNotFound);
        };
        telio_log_debug!("Muting peer: {:?} for {:?}", pk, dur);
        *mute = Some(PinnedSleep::new(dur, *pk));

        Ok(())
    }

    fn try_unmute(&mut self, pk: &PublicKey) -> Result<(), Error> {
        let Some((_, mute)) = self.sockets.get_mut(pk) else {
            return Err(Error::PeerNotFound);
        };
        telio_log_debug!("Unmuting peer: {:?}", pk);
        *mute = None;

        Ok(())
    }

    async fn send_outbound_data(&mut self, pk: PublicKey, msg: DataMsg) {
        match (self.sockets.get(&pk), self.wg_addr) {
            (Some((socket, None)), Some(wg_addr)) => {
                match socket.send_to(msg.get_payload(), wg_addr).await {
                    Ok(_) => {
                        if self.conn_state.is_err() {
                            self.conn_state = Ok(());
                            telio_log_info!("Outbound conn telio -> WG working!");
                        }
                        self.peer_socket_backoffs.remove(&pk);
                    }
                    Err(err) => {
                        self.handle_error(err, Some(pk)).await;
                    }
                }
            }
            (sock, wg_addr) => {
                self.handle_error(
                    std::io::Error::new(
                        ErrorKind::AddrNotAvailable,
                        format!(
                            "WG Address not available - socket: {}, wg_addr: {wg_addr:?}",
                            sock.is_some()
                        ),
                    ),
                    Some(pk),
                )
                .await;
            }
        }
    }

    async fn handle_error(&mut self, err: std::io::Error, pk: Option<PublicKey>) {
        telio_log_warn!("StateEgress: handling error {err:?} for {pk:?}");

        match self.conn_state {
            Ok(()) => telio_log_error!("Unable to send. {}", err),
            Err(e) if e != err.kind() => telio_log_error!("Unable to send. {}", err),
            Err(_) => (),
        }
        self.conn_state = Err(err.kind());

        match ErrorType::from(err) {
            ErrorType::RecoverableError => (),
            ErrorType::UnrecoverableError => {
                Self::sleep_forever().await;
            }
            ErrorType::SocketIOError => {
                if let Some(pk) = pk {
                    if self.peer_socket_backoffs.get_mut(&pk).is_none() {
                        #[allow(clippy::expect_used)]
                        let backoff = ExponentialBackoff::new(ExponentialBackoffBounds {
                            initial: Duration::from_secs(1),
                            maximal: Some(Duration::from_secs(30)),
                        })
                        .expect("Exponential backoff should be correctly configured");
                        let timeout = PinnedSleep::new(backoff.get_backoff(), pk);
                        self.peer_socket_backoffs.insert(pk, (backoff, timeout));
                    }
                }
            }
        }
    }

    async fn replace_socket(&mut self, pk: PublicKey) {
        let socket = match SocketPool::new_udp(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            Some(UdpParams(SocketBufSizes {
                rx_buf_size: Some(SOCK_BUF_SZ),
                tx_buf_size: Some(SOCK_BUF_SZ),
            })),
        )
        .await
        {
            Ok(skt) => skt,
            Err(err) => {
                telio_log_error!("Cannot open socket. {}", err);
                return;
            }
        };

        let socket = Arc::new(socket);

        if let Err(e) = self.update_socket.send((pk, socket.clone())).await {
            // May happen when they are being closed, but is not critical
            telio_log_warn!("Failed to sync up proxy sockets due to closed channel: {e:?}");
        }

        let peer_sockets = self.replaced_sockets.entry(pk).or_default();
        let old_socket_addr = self
            .sockets
            .get(&pk)
            .and_then(|(old_socket, _)| old_socket.local_addr().ok());
        if let Some(addr) = old_socket_addr {
            peer_sockets.push(addr);
        }
        self.sockets.insert(pk, (socket, None));
        if let Some((backoff, timeout)) = self.peer_socket_backoffs.get_mut(&pk) {
            backoff.next_backoff();
            *timeout = PinnedSleep::new(backoff.get_backoff(), pk);
        }
    }
}

#[async_trait]
impl Runtime for StateIngress {
    /// Task's name
    const NAME: &'static str = "IngressProxy";

    /// Error that may occur in [Task]
    type Err = ();

    /// Wait on state events. Called from an infinite loop.
    ///
    /// Use [RuntimeExt] to create valid responses in an easier manner.
    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        if self.sockets.is_empty() {
            return Self::sleep_forever().await;
        }

        let futures = self
            .sockets
            .clone()
            .into_iter()
            .map(|(pk, socket)| {
                async move {
                    if let Ok(()) = socket.readable().await {
                        (pk, socket.clone())
                    } else {
                        pending().await
                    }
                }
                .boxed()
            })
            .collect::<Vec<_>>();

        // Inbound data (from WG to telio)
        tokio::select! {
            Some((permit, ((pk, socket), _, _))) =
                wait_for_tx(&self.output, select_all(futures)) =>
            {
                match socket.try_recv(self.read_buf.as_mut_slice()) {
                    Ok(n) => {
                        let msg = DataMsg::new(if let Some(buf) = self.read_buf.get(..n) {
                            buf
                        } else {
                            return Self::error(());
                        });
                        let _ = permit.send((pk, msg));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        // Blocking error is not an issue here
                    }
                    Err(e) => {
                        telio_log_warn!("StateIngress: received error {e:?} for {pk:?}");
                    }
                }
            }
            Some((pk, sock)) = self.updated_socket.recv() => {
                telio_log_debug!("Updating socket mapping for {pk} to {sock:?}");

                let _ = self.sockets.insert(pk, sock);
            }
            else => {
                telio_log_warn!("StateIngress: no events to wait on ...");
            },
        }

        Self::next()
    }
}

#[async_trait]
impl Runtime for StateEgress {
    /// Task's name
    const NAME: &'static str = "EgressProxy";

    /// Error that may occur in [Task]
    type Err = ();

    /// Wait on state events. Called from an infinite loop.
    ///
    /// Use [RuntimeExt] to create valid responses in an easier manner.
    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        if self.sockets.is_empty() {
            return Self::sleep_forever().await;
        }

        let mute_futures: Vec<&mut PinnedSleep<PublicKey>> = self
            .sockets
            .iter_mut()
            .filter_map(|(_, (_, mute))| mute.as_mut())
            .collect();

        let sockets_to_update: Vec<&mut PinnedSleep<PublicKey>> = self
            .peer_socket_backoffs
            .iter_mut()
            .map(|(_, (_, timeout))| timeout)
            .collect();

        let mute = if mute_futures.is_empty() {
            futures::future::pending().left_future()
        } else {
            select_all(mute_futures).right_future()
        };

        let update = if sockets_to_update.is_empty() {
            futures::future::pending().left_future()
        } else {
            select_all(sockets_to_update).right_future()
        };

        tokio::select! {
            Some((pk, msg)) = self.input.recv() => {
                self.send_outbound_data(pk, msg).await;
            },
            (pk, _, _) = mute => {
                if let Some((_, muted)) = self.sockets.get_mut(&pk) {
                    telio_log_debug!("Unmuting peer: {:?}", pk);
                    *muted = None;
                }
            },
            (pk, _, _)= update => {
                self.replace_socket(pk).await;
            },
            else => {
                telio_log_warn!("StateEgress: closed input channel");
            },
        }
        Self::next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use self::helper::TestSystem;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_single_endpoint() {
        let mut ts = TestSystem::start().await;

        ts.test_data_flow_sync(
            &[&[(b"ok", DataMsg::new(b"ok"))]],
            &[&[(DataMsg::new(b"my data"), b"my data")]],
        )
        .await;

        ts.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_graceful_shutdown() {
        use telio_crypto::SecretKey;

        for i in 0..1 {
            let TestSystem { wg, proxy, relay } = TestSystem::start().await;

            drop(relay);

            let mut pks = Vec::new();
            for _ in 0..2 {
                let pk = SecretKey::gen().public();
                pks.push(pk);
            }

            proxy
                .configure(Config {
                    wg_port: Some(wg.addr().port()),
                    peers: pks.iter().copied().collect(),
                })
                .await
                .expect("UdpProxy::configure() failed");

            // Shouldn't panic in any order
            if i % 2 == 0 {
                proxy.stop().await;
            } else {
                proxy.stop_reverse().await;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_multiple_endpoints() {
        let mut ts = TestSystem::start().await;

        ts.test_data_flow_concurent(
            // WG -> Relay
            &[
                // Peer 1
                &[(b"a", DataMsg::new(b"a")), (b"aa", DataMsg::new(b"aa"))],
                // Peer 2
                &[(b"c", DataMsg::new(b"c")), (b"cc", DataMsg::new(b"cc"))],
            ],
            // Relay -> WG
            &[
                // Peer 1
                &[(DataMsg::new(b"b"), b"b")],
                // Peer 2
                &[(DataMsg::new(b"d"), b"d"), (DataMsg::new(b"dd"), b"dd")],
            ],
        )
        .await;

        ts.stop().await;
    }

    #[tokio::test]
    async fn test_muting_unmuting() {
        let mut ts = TestSystem::start().await;

        ts.test_data_muted(
            // Relay -> WG
            &[
                // Peer 1
                &[(DataMsg::new(b"b"), b"b"), (DataMsg::new(b"bb"), b"bb")],
                // Peer 2
                &[(DataMsg::new(b"d"), b"d"), (DataMsg::new(b"dd"), b"dd")],
            ],
        )
        .await;

        ts.stop().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[allow(clippy::unwrap_used)]
    async fn test_error_handling() {
        let mut ts = TestSystem::start().await;

        let _ = ts
            .test_egress_recoverable_error_handling(&[
                &[(DataMsg::new(b"my data"), b"my data")],
                &[(DataMsg::new(b"my data"), b"my data")],
            ])
            .await;

        ts.stop().await;
    }

    /// Helper utils for tests
    mod helper {
        use futures::future::join_all;
        use rand::seq::IndexedRandom;
        use std::{panic, thread, time::Duration};
        use tokio::{
            sync::{mpsc::Receiver, mpsc::Sender, Mutex},
            time::{self, timeout},
        };

        use telio_crypto::SecretKey;

        use super::*;

        /// MockWg <--(wg_packet)--> UdpProxy <--(DataMsg)--> MockRelay
        pub struct TestSystem {
            pub wg: MockWg,
            pub proxy: UdpProxy,
            pub relay: MockRelay,
        }

        impl TestSystem {
            pub async fn start() -> Self {
                let wg = MockWg::start().await;
                let (data_l, data_r) = Chan::pipe();
                let proxy = UdpProxy::start(Io { relay: data_l });

                Self {
                    wg,
                    relay: MockRelay::new(data_r),
                    proxy,
                }
            }

            /// Send packets in both directions (wg <-> proxy <-> relay) in a concurrent way.
            ///
            /// wg_to_relay: [ `peer1` - [(test_bytes, expected_data_msg), ...], ... ]
            /// relay_to_wg: [ `peer1` - [(test_data_msg, expected_bytes), ...], ... ]
            pub async fn test_data_flow_concurent(
                &mut self,
                wg_to_relay: &[&[(&[u8], DataMsg)]],
                relay_to_wg: &[&[(DataMsg, &[u8])]],
            ) {
                let peers = wg_to_relay.len().max(relay_to_wg.len());
                let pks = self.create_peers(peers).await;

                let (wg_to_relay, expect_wg_to_relay) = flatten_tests(&pks, wg_to_relay);
                let (relay_to_wg, expect_relay_to_wg) = flatten_tests(&pks, relay_to_wg);

                // panic!(
                //     "wg_to_relay: {:#?}\nexpect: {:#?}",
                //     wg_to_relay, expect_wg_to_relay
                // );

                futures::join!(
                    join_all(
                        wg_to_relay
                            .into_iter()
                            .map(|(pk, buf)| self.wg.send(pk, buf))
                    ),
                    self.relay.expect_recv(&expect_wg_to_relay),
                    join_all(
                        relay_to_wg
                            .into_iter()
                            .map(|(pk, msg)| self.relay.send(pk, msg))
                    ),
                    self.wg.expect_recv(&expect_relay_to_wg),
                );

                self.clear_peers();
            }

            /// Send packets in both directions (wg <-> proxy <-> relay) in a synchronous steps:
            /// - wg -> relay : wg_to_relay[0][0]
            /// - relay -> wg : relay_to_wg[0][0]
            /// - ...
            /// - wg -> relay : wg_to_relay[0][max]
            /// - relay -> wg : relay_to_wg[0][max]
            /// - ...
            /// - wg -> relay : wg_to_relay[max][max]
            /// - relay -> wg : relay_to_wg[max][max]
            /// - ...
            ///
            /// wg_to_realy: [ `peer1` - [(test_bytes, exptected_data_msg), ...], ... ]
            /// realy_to_wg: [ `peer1` - [(test_data_msg, exptected_bytes), ...], ... ]
            pub async fn test_data_flow_sync(
                &mut self,
                wg_to_relay: &[&[(&[u8], DataMsg)]],
                relay_to_wg: &[&[(DataMsg, &[u8])]],
            ) {
                let peers = wg_to_relay.len().max(relay_to_wg.len());
                let pks = self.create_peers(peers).await;

                let (wg_to_relay, expect_wg_to_relay) = flatten_tests(&pks, wg_to_relay);
                let (relay_to_wg, expect_relay_to_wg) = flatten_tests(&pks, relay_to_wg);

                for i in 0..peers {
                    if i < wg_to_relay.len() {
                        let (pk, msg) = wg_to_relay[i];
                        self.wg.send(pk, msg).await;
                        let (pk, msg) = &expect_wg_to_relay[i];
                        self.relay.expect_recv(&[(*pk, msg.clone())]).await;
                    }
                    if i < relay_to_wg.len() {
                        let (pk, msg) = &relay_to_wg[i];
                        self.relay.send(*pk, msg.clone()).await;
                        let (pk, msg) = expect_relay_to_wg[i];
                        self.wg.expect_recv(&[(pk, msg)]).await;
                    }
                }

                self.clear_peers();
            }

            pub async fn test_data_muted(&mut self, relay_to_wg: &[&[(DataMsg, &[u8])]]) {
                let peers = relay_to_wg.len().max(relay_to_wg.len());
                let pks = self.create_peers(peers).await;
                let pk_to_mute = pks.choose(&mut rand::rng()).unwrap();
                let (relay_to_wg, expect_relay_to_wg) = flatten_tests(&pks, relay_to_wg);

                let advance_by_secs_and_yield = |secs| async move {
                    tokio::task::yield_now().await;
                    time::pause();
                    time::advance(Duration::from_secs(secs)).await;
                    time::resume();
                    tokio::task::yield_now().await;
                };

                let unmuted = || async {
                    for i in 0..relay_to_wg.len() {
                        let (pk, msg) = &relay_to_wg[i];
                        self.relay.send(*pk, msg.clone()).await;
                        let (pk, msg) = expect_relay_to_wg[i];
                        self.wg.expect_recv(&[(pk, msg)]).await;
                    }
                };

                let muted = || async {
                    for i in 0..relay_to_wg.len() {
                        let (pk, msg) = &relay_to_wg[i];
                        self.relay.send(*pk, msg.clone()).await;
                        let (pk, msg) = expect_relay_to_wg[i];
                        if pk == *pk_to_mute {
                            // Yield to allow relay to process packet
                            tokio::task::yield_now().await;
                            let mut buf = [0u8; 1024];
                            assert!(self.wg.sock.try_recv_from(&mut buf).is_err());
                        } else {
                            self.wg.expect_recv(&[(pk, msg)]).await;
                        }
                    }
                };

                // Test unmuted initially
                unmuted().await;

                // Mute chosen peer for 10 seconds
                self.proxy
                    .mute_peer(*pk_to_mute, Some(Duration::from_secs(10)))
                    .await
                    .unwrap();

                // Should be muted after 1 second
                advance_by_secs_and_yield(1).await;
                muted().await;
                // And should be unmuted after 10 + 1 seconds
                advance_by_secs_and_yield(10).await;
                unmuted().await;

                // Test unmute manually
                self.proxy
                    .mute_peer(*pk_to_mute, Some(Duration::from_secs(10)))
                    .await
                    .unwrap();
                advance_by_secs_and_yield(1).await;
                muted().await;

                // Unmute manually
                self.proxy.mute_peer(*pk_to_mute, None).await.unwrap();
                advance_by_secs_and_yield(1).await;
                unmuted().await;

                self.clear_peers();
            }

            pub async fn test_egress_recoverable_error_handling(
                &mut self,
                relay_to_wg: &[&[(DataMsg, &[u8])]],
            ) -> anyhow::Result<()> {
                let peers = relay_to_wg.len();
                let pks = self.create_peers(peers).await;

                let (relay_to_wg, _expect_relay_to_wg) = flatten_tests(&pks, relay_to_wg);

                let skt = task_exec!(&self.proxy.task_egress, async move |state| {
                    let p = state.wg_addr;
                    state.wg_addr = None;
                    Ok(p)
                })
                .await?;

                self.send_to_wg_via_relay(peers, &relay_to_wg, Err(ErrorKind::AddrNotAvailable))
                    .await;

                let _ = task_exec!(&self.proxy.task_egress, async move |state| {
                    state.wg_addr = skt;
                    Ok(())
                })
                .await;

                self.send_to_wg_via_relay(peers, &relay_to_wg, Ok(())).await;

                self.clear_peers();
                Ok(())
            }

            pub async fn send_to_wg_via_relay(
                &mut self,
                peers: usize,
                relay_to_wg: &Vec<(PublicKey, DataMsg)>,
                res: Result<(), std::io::ErrorKind>,
            ) {
                for i in 0..peers {
                    if i < relay_to_wg.len() {
                        let (pk, msg) = &relay_to_wg[i];
                        self.relay.send(*pk, msg.clone()).await;
                        let duration = Duration::from_secs(1);
                        thread::sleep(duration);
                        let _ = task_exec!(&self.proxy.task_egress, async move |state| {
                            assert_eq!(state.conn_state, res);
                            Ok(())
                        })
                        .await;
                    }
                }
            }

            pub async fn create_peers(&mut self, peers: usize) -> Vec<PublicKey> {
                let mut pks = Vec::new();
                for _ in 0..peers {
                    let pk = SecretKey::gen().public();
                    pks.push(pk);
                }

                self.proxy
                    .configure(Config {
                        wg_port: Some(self.wg.addr().port()),
                        peers: pks.iter().copied().collect(),
                    })
                    .await
                    .expect("UdpProxy::configure() failed");

                self.wg.peers = self
                    .proxy
                    .get_endpoint_map()
                    .await
                    .expect("get_endpoint_map() failed");

                pks
            }

            pub fn clear_peers(&mut self) {
                self.wg.peers.clear()
            }

            pub async fn stop(self) {
                self.proxy.stop().await;
            }
        }

        fn flatten_tests<T: Clone, E: Clone>(
            key: &[PublicKey],
            data: &[&[(T, E)]],
        ) -> (Vec<(PublicKey, T)>, Vec<(PublicKey, E)>) {
            data.iter()
                .enumerate()
                .flat_map(|(i, packets)| {
                    packets.iter().map(move |(test, expect)| {
                        ((key[i], test.clone()), (key[i], expect.clone()))
                    })
                })
                .unzip()
        }

        pub struct MockWg {
            sock: UdpSocket,
            peers: EndpointMap,
        }

        impl MockWg {
            pub async fn start() -> Self {
                let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("Failed to create WG Socket.");

                Self {
                    sock,
                    peers: Default::default(),
                }
            }

            pub fn addr(&self) -> SocketAddr {
                self.sock.local_addr().expect("Failed to get WG addr.")
            }

            pub async fn send(&self, pk: PublicKey, data: &[u8]) {
                self.sock
                    .send_to(data, self.peers[&pk][0])
                    .await
                    .expect("WG failed to send.");
            }

            pub async fn expect_recv(&self, data: &[(PublicKey, &[u8])]) {
                let mut recv_buf = [0u8; 256];
                let mut data = data.to_vec();
                data.sort();
                while !data.is_empty() {
                    let (size, recvaddr) = timeout(
                        Duration::from_millis(1000),
                        self.sock.recv_from(&mut recv_buf),
                    )
                    .await
                    .expect("wg recv timeout")
                    .expect("failed to recv from wg");
                    let (pk, _) = self
                        .peers
                        .iter()
                        .find(|(_pk, addr)| addr.contains(&recvaddr))
                        .expect("Unknown addr");
                    let answer = (*pk, &recv_buf[..size]);
                    let found = data.binary_search(&answer).unwrap_or_else(|_| {
                        panic!(
                            "Recv WG: did not find : {:?}, \nexpected one of: {:?}",
                            &answer, &data
                        )
                    });
                    data.remove(found);
                }
            }
        }

        pub struct MockRelay {
            tx: Sender<(PublicKey, DataMsg)>,
            rx: Arc<Mutex<Receiver<(PublicKey, DataMsg)>>>,
        }

        impl MockRelay {
            pub fn new(chan: Chan<(PublicKey, DataMsg)>) -> Self {
                Self {
                    tx: chan.tx,
                    rx: Arc::new(Mutex::new(chan.rx)),
                }
            }

            pub async fn send(&self, pk: PublicKey, msg: DataMsg) {
                self.tx
                    .send((pk, msg))
                    .await
                    .unwrap_or_else(|_| panic!("failed to send to public key : {}", pk));
            }

            pub fn expect_recv<'a>(
                &self,
                data: &'a [(PublicKey, DataMsg)],
            ) -> impl std::future::Future + 'a {
                let rx = self.rx.clone();
                async move {
                    let mut data = data.to_vec();
                    while !data.is_empty() {
                        let mut receiver = rx.lock().await;
                        let (pk, msg) = timeout(Duration::from_millis(1000), receiver.recv())
                            .await
                            .expect("relay recv timeout")
                            .expect("failed to recv from relay");
                        let got = (pk, msg);
                        let found = data.iter().position(|ans| ans == &got).unwrap_or_else(|| {
                            panic!(
                                "Recv Relay: did not find : {:?}, \nexpected one of: {:?}",
                                &got, &data
                            )
                        });
                        data.remove(found);
                    }
                }
            }
        }
    }
}
