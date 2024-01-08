use async_trait::async_trait;
use futures::future::{pending, select_all, FutureExt};
use std::{
    collections::{HashMap, HashSet},
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

use telio_utils::{telio_log_debug, PinnedSleep};

type Muted = bool;
type SocketMap = HashMap<PublicKey, Arc<UdpSocket>>;
type SocketMuteMap = HashMap<PublicKey, (Arc<UdpSocket>, Muted)>;
type MuteMap = HashMap<PublicKey, PinnedSleep<PublicKey>>;

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

/// Proxy links incoming and outgoing WG Packets to
/// separate endpoints and by those endpoints identifies public key.
#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait Proxy {
    /// Get currently mapped sockets
    async fn get_endpoint_map(&self) -> Result<EndpointMap, Error>;
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
}

struct StateEgress {
    sockets: SocketMuteMap,
    mutes: MuteMap,
    input: Rx<(PublicKey, DataMsg)>,
    wg_addr: Option<SocketAddr>,
}

impl UdpProxy {
    /// Start `UdpProxy`
    pub fn start(io: Io) -> Self {
        UdpProxy {
            task_ingress: Task::start(StateIngress {
                sockets: HashMap::new(),
                output: io.relay.tx,
                read_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            }),
            task_egress: Task::start(StateEgress {
                sockets: HashMap::new(),
                mutes: HashMap::new(),
                input: io.relay.rx,
                wg_addr: None,
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
            Ok(state.configure(sockets, port).await)
        })
        .await?
    }

    /// Stop proxy
    pub async fn stop(self) {
        let _ = self.task_egress.stop().await.resume_unwind();
        let _ = self.task_ingress.stop().await.resume_unwind();
    }
}

#[async_trait]
impl Proxy for UdpProxy {
    async fn get_endpoint_map(&self) -> Result<EndpointMap, Error> {
        task_exec!(&self.task_ingress, async move |state| {
            Ok(state.get_endpoints_map().await)
        })
        .await?
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

    async fn get_endpoints_map(&self) -> Result<EndpointMap, Error> {
        let mut map = EndpointMap::new();

        for (key, sock) in self.sockets.iter() {
            map.insert(*key, sock.local_addr()?);
        }

        Ok(map)
    }
}

impl StateEgress {
    async fn configure(&mut self, sockets: SocketMap, wg_port: Option<u16>) -> Result<(), Error> {
        telio_log_debug!("Configuring egress proxy with wg port {:?}", wg_port);

        self.wg_addr = wg_port.map(|p| (Ipv4Addr::LOCALHOST, p).into());

        let old_sockets = self.sockets.clone();
        self.sockets = sockets
            .clone()
            .into_iter()
            .map(|(pk, socket)| {
                (
                    pk,
                    (
                        socket,
                        old_sockets
                            .get(&pk)
                            .map(|(_, muted)| *muted)
                            .unwrap_or(false),
                    ),
                )
            })
            .collect();

        Ok(())
    }

    fn try_mute(&mut self, pk: &PublicKey, dur: Duration) -> Result<(), Error> {
        if let Some((_, muted)) = self.sockets.get_mut(pk) {
            telio_log_debug!("Muting peer: {:?} for {:?}", pk, dur);
            self.mutes.insert(*pk, PinnedSleep::new(dur, *pk));
            *muted = true;
            return Ok(());
        }

        Err(Error::PeerNotFound)
    }

    fn try_unmute(&mut self, pk: &PublicKey) -> Result<(), Error> {
        if let Some((_, muted)) = self.sockets.get_mut(pk) {
            telio_log_debug!("Unmuting peer: {:?}", pk);
            *muted = false;
            self.mutes.remove(pk);
            return Ok(());
        }

        Err(Error::PeerNotFound)
    }

    fn cleanup_mutes(&mut self) {
        for (pk, mute) in self.mutes.iter() {
            if mute.is_elapsed() {
                // Cannot try_remove() here because of borrow checker
                if let Some((_, muted)) = self.sockets.get_mut(pk) {
                    telio_log_debug!("Cleaning mute from peer {:?}", pk);
                    *muted = false;
                }
            }
        }
        self.mutes.retain(|_, mute| !mute.is_elapsed());
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
        if let Some((permit, ((pk, socket), _, _))) =
            wait_for_tx(&self.output, select_all(futures)).await
        {
            if let Ok(n) = socket.try_recv(self.read_buf.as_mut_slice()) {
                let msg = DataMsg::new(if let Some(buf) = self.read_buf.get(..n) {
                    buf
                } else {
                    return Self::error(());
                });
                let _ = permit.send((pk, msg));
            }
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

        self.cleanup_mutes();
        let dummy_sleep = &mut PinnedSleep::new(Duration::MAX, PublicKey::default());
        let mute_futures = {
            if self.mutes.is_empty() {
                vec![dummy_sleep]
            } else {
                self.mutes
                    .iter_mut()
                    .map(|(_, mute)| mute)
                    .collect::<Vec<_>>()
            }
        };

        tokio::select! {
            // Outbound data (from telio to WG)
            Some((pk, msg)) = self.input.recv() => {
                if let (Some((socket, muted)), Some(wg_addr)) = (self.sockets.get(&pk), self.wg_addr) {
                    if !*muted {
                        let _ = socket.send_to(msg.get_payload(), wg_addr).await;
                    } else {
                        telio_log_debug!("Peer {:?} is muted", pk);
                    }
                }
            },
            (pk, _, _) = select_all(mute_futures) => {
                if let Some((_, muted)) = self.sockets.get_mut(&pk) {
                    telio_log_debug!("Unmuting peer: {:?}", pk);
                    *muted = false;
                }
            }
        }

        Self::next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use std::time::Duration;
    use telio_crypto::SecretKey;

    use tokio::{
        sync::mpsc::{Receiver, Sender},
        time::timeout,
    };

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

    #[tokio::test(flavor = "current_thread")]
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

    /// Helper utils for tests
    mod helper {
        use rand::seq::SliceRandom;
        use std::panic;
        use tokio::{
            sync::Mutex,
            time::{self, timeout},
        };

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
                let pk_to_mute = pks.choose(&mut rand::thread_rng()).unwrap();
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

                // Test unmute after 10 seconds
                self.proxy
                    .mute_peer(*pk_to_mute, Some(Duration::from_secs(10)))
                    .await
                    .unwrap();
                // Should be muted after 1 second
                advance_by_secs_and_yield(1).await;
                muted().await;
                // Should be unmuted after 10 + 1 seconds
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
            data.into_iter()
                .enumerate()
                .flat_map(|(i, packets)| {
                    packets.into_iter().map(move |(test, expect)| {
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
                    .send_to(data, self.peers[&pk])
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
                        .find(|(_pk, addr)| *addr == &recvaddr)
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
