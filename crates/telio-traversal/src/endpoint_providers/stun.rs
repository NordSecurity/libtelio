use std::{
    future::pending,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures::Future;
use stun_codec::TransactionId;
use telio_crypto::PublicKey;
use telio_proto::{Codec, Packet, PingType, PingerMsg, Session, Timestamp, WGPort};
use telio_sockets::External;
use telio_task::{io::chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_warn, PinnedSleep};
use telio_wg::WireGuard;
use tokio::{
    net::UdpSocket,
    time::{interval, Interval},
};

use super::{EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, Error, PongEvent};

#[cfg(not(test))]
const STUN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const STUN_TIMEOUT: Duration = Duration::from_millis(200);

const MAX_PACKET_SIZE: usize = 1500;
const DEFAULT_STUN_PORT: u16 = 3478;
const STUN_SOFTWARE: &str = "tailnode";

#[derive(Default)]
pub struct Config {
    // Peer in wireguard to be used for stunning.
    pub stun_peer: PublicKey,
    // Port of plaintext stun
    pub plaintext_stun_port: u16,
    // Port of wg stun's inner port
    pub wg_stun_port: Option<u16>,
}

pub struct StunEndpointProvider<Wg: WireGuard> {
    task: Task<State<Wg>>,
}

impl<Wg: WireGuard> StunEndpointProvider<Wg> {
    /// Start stun endpoint provider,
    /// # Params
    /// - `tun_socket` - udp socket bound to tun interface
    /// - `ext_socket` - udp socket bound to external interface
    /// - `wg` - wireguard controll
    /// - `poll_interval` - Duration to recheck for stun changes
    pub fn start(
        tun_socket: UdpSocket,
        ext_socket: External<UdpSocket>,
        wg: Arc<Wg>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            task: Task::start(State {
                config: None,
                tun_socket,
                ext_socket,
                wg,
                change_event: None,
                pong_event: None,
                stun_session: None,
                stun_interval: interval(poll_interval),
                last_candidates: Vec::new(),
            }),
        }
    }

    pub async fn configure(&self, config: Option<Config>) {
        let _ = task_exec!(&self.task, async move |s| {
            s.config = config;
            s.stun_session = None;
            let _ = s.start_stun_session().await;

            Ok(())
        })
        .await;
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

#[async_trait]
impl<Wg: WireGuard> EndpointProvider for StunEndpointProvider<Wg> {
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

    async fn trigger_endpoint_candidates_discovery(&self) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| Ok(s.start_stun_session().await)).await?
    }

    async fn send_ping(
        &self,
        addr: SocketAddr,
        wg_port: WGPort,
        session_id: Session,
    ) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| Ok(s
            .send_ping(addr, wg_port, session_id)
            .await))
        .await?
    }
}

struct State<Wg: WireGuard> {
    config: Option<Config>,
    tun_socket: UdpSocket,
    ext_socket: External<UdpSocket>,
    wg: Arc<Wg>,

    change_event: Option<chan::Tx<EndpointCandidatesChangeEvent>>,
    pong_event: Option<chan::Tx<PongEvent>>,

    stun_session: Option<StunSession>,
    stun_interval: Interval,
    last_candidates: Vec<EndpointCandidate>,
}

impl<Wg: WireGuard> State<Wg> {
    async fn start_stun_session(&mut self) -> Result<(), Error> {
        if self.stun_session.is_some() {
            // Stun request still being processed
            Ok(())
        } else {
            let (wg, udp) = self.get_stun_endpoints().await?;
            self.stun_session =
                Some(StunSession::start(&self.tun_socket, wg, &self.ext_socket, udp).await?);
            Ok(())
        }
    }

    async fn send_ping(
        &self,
        addr: SocketAddr,
        wg_port: WGPort,
        session_id: Session,
    ) -> Result<(), Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        telio_log_debug!("Sending ping to {:?}", addr);
        let ping = PingerMsg::ping(wg_port, session_id, ts);
        let buf = ping.encode()?;
        self.ext_socket.send_to(&buf, addr).await?;
        Ok(())
    }

    async fn get_wg_port(&self) -> Result<u16, Error> {
        if let Some(wg_port) = self.wg.get_interface().await.and_then(|i| i.listen_port) {
            Ok(wg_port)
        } else {
            telio_log_warn!("Skipping local interfaces poll due to missing wg_port");
            Err(Error::NoWGListenPort)
        }
    }

    /// Get endpoint's for stuns (WgStun, PlaintextStun)
    async fn get_stun_endpoints(&self) -> Result<(SocketAddr, SocketAddr), Error> {
        if let Some(config) = &self.config {
            let interface = self.wg.get_interface().await;

            let stun_peer = interface
                .as_ref()
                .and_then(|wgi| wgi.peers.get(&config.stun_peer))
                .ok_or(Error::NoStunPeer)?;

            let wg_ip = stun_peer
                .allowed_ips
                .first()
                .ok_or(Error::BadStunPeer)?
                .ip();

            let udp_ip = stun_peer.endpoint.ok_or(Error::BadStunPeer)?.ip();

            Ok((
                (wg_ip, config.wg_stun_port.unwrap_or(DEFAULT_STUN_PORT)).into(),
                (udp_ip, config.plaintext_stun_port).into(),
            ))
        } else {
            Err(Error::NotConfigured)
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
                    if let Some(change_event) = &self.change_event {
                        let candidates = vec![candidate];
                        if self.last_candidates != candidates {
                            self.last_candidates = candidates.clone();
                            change_event.send(candidates).await?;
                        }
                    } else {
                        telio_log_warn!("{} does not have endpoint provider sender.", Self::NAME)
                    }
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

    async fn handle_ping_rx(&mut self, payload: &[u8], src_addr: &SocketAddr) -> Result<(), Error> {
        if let Packet::Pinger(packet) = Packet::decode(payload)? {
            match packet.get_message_type() {
                PingType::PING => {
                    // Respond with pong
                    telio_log_debug!("Received ping from {:?}, responding", src_addr);
                    let wg_port = self.get_wg_port().await?;
                    let pong = packet
                        .pong(WGPort(wg_port))
                        .ok_or(Error::FailedToBuildPongPacket)?;
                    let buf = pong.encode()?;
                    self.ext_socket.send_to(&buf, src_addr).await?;
                }
                PingType::PONG => {
                    if let Some(pong_event) = self.pong_event.as_ref() {
                        telio_log_debug!("Received pong from {:?}, notifying", src_addr);
                        let ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_micros() as Timestamp;
                        pong_event
                            .send(PongEvent {
                                addr: *src_addr,
                                rtt: Duration::from_millis(ts - packet.get_start_timestamp()),
                                msg: packet.clone(),
                            })
                            .await?;
                    } else {
                        telio_log_warn!(
                            "Received pong from {:?}, No one subscribed for notifications",
                            src_addr
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<Wg: WireGuard> Runtime for State<Wg> {
    const NAME: &'static str = "StunEndpointProvider";

    type Err = ();

    async fn wait_with_update<F>(&mut self, updated: F) -> Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
    {
        let session = &mut self.stun_session;
        let timeout = async move {
            match session {
                Some(ses) => (&mut ses.timeout).await,
                _ => pending().await,
            }
        };

        let mut ext_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut tun_buf = vec![0u8; MAX_PACKET_SIZE];
        tokio::select! {
            // Reading data from UDP socket (passed by node, that is awaiting on socket's receive)
            Ok((size, src_addr)) = self.ext_socket.recv_from(&mut ext_buf) => {
                let _ = self.handle_rx(&ext_buf[..size], &src_addr).await;
            }
            Ok((size, src_addr)) = self.tun_socket.recv_from(&mut tun_buf) => {
                // We will not pinging through wireguard.
                let _ = self.try_handle_stun_rx(&tun_buf[..size], &src_addr).await;
            }
            // Stun session timeout
            _ = timeout => {
                self.stun_session = None;
                if !self.last_candidates.is_empty() {
                    self.last_candidates.clear();
                    if let Some(ce) = &self.change_event {
                        let _ = ce.send(vec![]).await;
                    }
                }
            }
            _ = self.stun_interval.tick() => {
                let _  = self.start_stun_session().await;
            }
            update = updated => {
                return update(self).await;
            }
            else => {
                return Ok(());
            },
        };

        Ok(())
    }
}

#[derive(Debug)]
struct StunSession {
    wg: StunRequest,
    udp: StunRequest,
    timeout: PinnedSleep<()>,
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
        socket_via_wg: &UdpSocket,
        wg: SocketAddr,
        socket_via_ext: &UdpSocket,
        udp: SocketAddr,
    ) -> Result<Self, Error> {
        let wg_stun = stun_msg::new_request()?;
        let udp_stun = stun_msg::new_request()?;

        socket_via_wg.send_to(&wg_stun.1, wg).await?;
        socket_via_ext.send_to(&udp_stun.1, udp).await?;

        Ok(Self {
            wg: StunRequest::Waiting(wg, wg_stun.0),
            udp: StunRequest::Waiting(udp, udp_stun.0),
            timeout: PinnedSleep::new(STUN_TIMEOUT, ()),
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
                    // packet is not for this sun request
                    return Ok(false);
                }

                let (sa, id) = stun_msg::decode_response(payload)?;

                if &id != tid {
                    telio_log_warn!("Unexpected stun packet from {}", src_addr);
                    return Ok(false);
                }

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
            attributes::{MappedAddress, Software, XorMappedAddress},
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
    use mockall::mock;
    use std::net::{Ipv4Addr, SocketAddr};
    use stun_codec::rfc5389::{
        self,
        attributes::{MappedAddress, XorMappedAddress},
    };
    use telio_crypto::{PublicKey, SecretKey};
    use telio_model::mesh::IpNetwork;
    use telio_sockets::SocketPool;
    use telio_task::io::Chan;
    use telio_test::await_timeout;
    use telio_wg::{
        uapi::{Interface, Peer},
        Error,
    };
    use tokio::time::{self, timeout};

    #[tokio::test]
    async fn collect_stun_endpoints_on_configure() {
        let mut env = prepare_test_env().await;

        env.stun_provider
            .configure(Some(Config {
                stun_peer: env.stun_pk,
                plaintext_stun_port: env.stun_sock.local_addr().unwrap().port(),
                wg_stun_port: Some(env.peer_sock.local_addr().unwrap().port()),
            }))
            .await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

        let candidates = await_timeout!(env.change_event.recv());
        assert_eq!(
            candidates,
            Some(vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }])
        );
    }

    #[tokio::test]
    async fn collect_stun_endpoints_on_change() {
        let mut env = prepare_test_env().await;

        env.stun_provider
            .configure(Some(Config {
                stun_peer: env.stun_pk,
                plaintext_stun_port: env.stun_sock.local_addr().unwrap().port(),
                wg_stun_port: Some(env.peer_sock.local_addr().unwrap().port()),
            }))
            .await;

        // Triggered by configuration
        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

        let candidates = await_timeout!(env.change_event.recv());
        assert_eq!(
            candidates,
            Some(vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }])
        );

        // Trigger for same env does not send
        env.stun_provider
            .trigger_endpoint_candidates_discovery()
            .await
            .expect("triggered");

        await_timeout!(stun_reply(&env.stun_sock, MappedAddress::new(udp_endpoint)));
        await_timeout!(stun_reply(
            &env.peer_sock,
            XorMappedAddress::new(wg_endpoint)
        ));

        timeout(Duration::from_millis(200), env.change_event.recv())
            .await
            .expect_err("should timeout");

        // Triggered for different env
        let udp_endpoint = SocketAddr::new([3, 3, 3, 3].into(), 33333);
        let wg_endpoint = SocketAddr::new([4, 4, 4, 4].into(), 44444);

        env.stun_provider
            .trigger_endpoint_candidates_discovery()
            .await
            .expect("tiggered");

        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

        let candidates = await_timeout!(env.change_event.recv());
        assert_eq!(
            candidates,
            Some(vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }])
        );
    }

    #[tokio::test]
    #[ignore = "Flacky"]
    async fn report_empty_candidate_list_on_stun_failure() {
        let mut env = prepare_test_env().await;
        let mut buf = [0; MAX_PACKET_SIZE];

        env.stun_provider
            .configure(Some(Config {
                stun_peer: env.stun_pk,
                plaintext_stun_port: env.stun_sock.local_addr().unwrap().port(),
                wg_stun_port: Some(env.peer_sock.local_addr().unwrap().port()),
            }))
            .await;

        // Timeout at first, no reporting as init state is assumed [];

        // Consume msg without reply
        await_timeout!(async {
            env.stun_sock.recv_from(&mut buf).await.expect("sent");
            env.peer_sock.recv_from(&mut buf).await.expect("sent");
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
            .trigger_endpoint_candidates_discovery()
            .await
            .expect("triggered");
        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

        let candidates = await_timeout!(env.change_event.recv());
        assert_eq!(
            candidates,
            Some(vec![EndpointCandidate {
                udp: udp_endpoint,
                wg: wg_endpoint,
            }])
        );

        // Trigger again and receive timeout
        env.stun_provider
            .trigger_endpoint_candidates_discovery()
            .await
            .expect("tiggered");

        // Consume msg without reply
        await_timeout!(async {
            env.stun_sock.recv_from(&mut buf).await.expect("sent");
            env.peer_sock.recv_from(&mut buf).await.expect("sent");
        });
        time::pause();
        time::advance(STUN_TIMEOUT * 2).await;
        time::resume();

        let candidates = await_timeout!(env.change_event.recv());
        assert_eq!(candidates, Some(vec![]));
    }

    #[tokio::test]
    async fn pongs_propagated_through_the_channel() {
        let mut env = prepare_test_env().await;

        let wg_port = WGPort(123);
        let session_id = 456;
        let peer_addr = env.peer_sock.local_addr().expect("local_addr");

        env.stun_provider
            .send_ping(peer_addr, wg_port, session_id)
            .await
            .unwrap();

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = env.peer_sock.recv_from(&mut buf).await.unwrap();
        if let Packet::Pinger(msg) = Packet::decode(&buf[..len]).unwrap() {
            if msg.get_message_type() == PingType::PING {
                let resp = msg.pong(msg.get_wg_port()).unwrap();
                let buf = resp.encode().unwrap();
                env.peer_sock.send_to(&buf, addr).await.unwrap();
            } else {
                panic!("Incorrect message type inside Pinger message");
            }
        } else {
            panic!("Incorrect packet type in place of ping");
        }

        let pong = env.pong_event.recv().await;
        assert!(pong.is_some());
        let pong = pong.unwrap();
        assert_eq!(pong.msg.get_message_type(), PingType::PONG);
        assert_eq!(pong.msg.get_wg_port(), wg_port);
        assert_eq!(pong.msg.get_session(), session_id);
        assert_eq!(pong.addr, peer_addr);
    }

    #[tokio::test]
    async fn provider_replies_to_ping() {
        let env = prepare_test_env().await;

        let wg_port = WGPort(123);
        let session_id = 456;

        let ping = PingerMsg::ping(wg_port, session_id, 6969);
        env.peer_sock
            .send_to(&ping.encode().expect("encode"), env.provider_ext_addr)
            .await
            .expect("ping");

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = env.peer_sock.recv_from(&mut buf).await.unwrap();

        assert_eq!(addr, env.provider_ext_addr);
        if let Packet::Pinger(pong) = Packet::decode(&buf[..len]).unwrap() {
            assert_eq!(pong.get_message_type(), PingType::PONG);
            assert_eq!(pong.get_wg_port(), WGPort(env.wg_port));
            assert_eq!(pong.get_session(), session_id);
        } else {
            panic!("Incorect packet type in place of ping");
        }
    }

    // Test helpers

    mock! {
        Wg {}
        #[async_trait]
        impl WireGuard for Wg {
            async fn get_interface(&self) -> Option<Interface>;
            async fn get_adapter_luid(&self) -> u64;
            async fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, Error>;
            async fn set_secret_key(&self, key: SecretKey);
            async fn set_fwmark(&self, fwmark: u32) -> bool;
            async fn add_peer(&self, peer: Peer);
            async fn del_peer(&self, key: PublicKey);
            async fn drop_connected_sockets(&self);
            async fn stop(self);
        }
    }

    #[allow(dead_code)]
    struct Env {
        // Dependencies
        socket_pool: SocketPool,

        // Tested system
        provider_tun_addr: SocketAddr,
        provider_ext_addr: SocketAddr,
        stun_provider: StunEndpointProvider<MockWg>,

        // External behavior
        change_event: chan::Rx<EndpointCandidatesChangeEvent>,
        pong_event: chan::Rx<PongEvent>,
        stun_sock: UdpSocket,
        /// This socket represent a socket that is listening in remote peer.
        /// We will not fake entire tunnel, as it correct behavior would basically
        /// give a new alias(ip) for wg_stun. Basically packet to 100.64.0.8:12345,
        /// would be received on 0.0.0.0:12345 on remote peer's socket/
        peer_sock: UdpSocket,
        wg_port: u16,
        stun_pk: PublicKey,
    }

    async fn prepare_test_env() -> Env {
        let mut wg = MockWg::default();
        let wg_port = 12345;

        let socket_pool = SocketPool::default();

        let provider_ext_socket = socket_pool
            .new_external_udp((Ipv4Addr::LOCALHOST, 0), None)
            .await
            .expect("Cannot create UdpSocket");
        let provider_ext_addr = provider_ext_socket.local_addr().expect("provider ext addr");

        let provider_tun_socket = socket_pool
            .new_internal_udp((Ipv4Addr::LOCALHOST, 0), None)
            .await
            .expect("crate tun socket");
        let provider_tun_addr = provider_tun_socket.local_addr().expect("provider tun addr");

        let peer_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("peer sock");
        println!("peer: {}", peer_sock.local_addr().unwrap());

        let stun_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stun sock");
        println!("stun: {}", stun_sock.local_addr().unwrap());

        // Stun peer can be locked
        let stun_pk = SecretKey::gen().public();
        let stun_peer = Peer {
            public_key: stun_pk,
            // Allowed ip is used to get ip of remote peer, in this case the fake it to be 127.0.0.1
            // since we don't provide entire wirguard tunnel for testing.
            allowed_ips: vec![IpNetwork::new(peer_sock.local_addr().unwrap().ip(), 32).unwrap()],
            // Endpoint would be peer's public ip and wg listen_port that we fake here.
            endpoint: Some((stun_sock.local_addr().unwrap().ip(), 55555).into()),
            ..Default::default()
        };

        wg.expect_get_interface().return_const(Interface {
            listen_port: Some(wg_port),
            peers: vec![(stun_pk, stun_peer)].into_iter().collect(),
            ..Default::default()
        });

        let stun_provider = StunEndpointProvider::start(
            provider_tun_socket,
            provider_ext_socket,
            Arc::new(wg),
            Duration::from_secs(10000),
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
            socket_pool,

            stun_provider,
            provider_ext_addr,
            provider_tun_addr,

            wg_port,
            stun_pk,

            change_event: candidates_channel.rx,
            pong_event: pongs_channel.rx,
            peer_sock,
            stun_sock,
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
}
