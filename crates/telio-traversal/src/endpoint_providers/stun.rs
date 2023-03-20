use std::{future::pending, net::SocketAddr, sync::Arc, time::Duration};

use std::ops::Deref;

use async_trait::async_trait;
use futures::Future;
use stun_codec::TransactionId;
use telio_crypto::PublicKey;
use telio_proto::{Session, WGPort};
use telio_relay::Server;
use telio_sockets::{native::AsNativeSocket, External};
use telio_task::{io::chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn, PinnedSleep};
use telio_wg::{DynamicWg, WireGuard};
use tokio::{
    net::UdpSocket,
    sync::Mutex,
    time::{interval, Interval},
};

use crate::{endpoint_providers::EndpointProviderType, ping_pong_handler::PingPongHandler};

use super::{EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, Error, PongEvent};

pub type StunServer = telio_relay::derp::Server;

#[cfg(not(test))]
const STUN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const STUN_TIMEOUT: Duration = Duration::from_millis(300);

const MAX_PACKET_SIZE: usize = 1500;
const STUN_SOFTWARE: &str = "tailnode";

pub struct StunEndpointProvider<Wg: WireGuard = DynamicWg> {
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
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        stun_peer_publisher: chan::Tx<Option<StunServer>>,
    ) -> Self {
        telio_log_info!("Starting stun endpoint provider");
        telio_log_debug!(
            "tun_socket: {:?}, ext_socket: {}",
            tun_socket.as_native_socket(),
            ext_socket.deref().as_native_socket()
        );
        Self {
            task: Task::start(State {
                servers: vec![],
                server_num: 0,
                tun_socket,
                ext_socket,
                wg,
                change_event: None,
                pong_event: None,
                stun_session: None,
                stun_interval: interval(poll_interval),
                last_candidates: Vec::new(),
                ping_pong_tracker: ping_pong_handler,
                stun_peer_publisher,
            }),
        }
    }

    pub async fn configure(&self, servers: Vec<Server>) {
        let _ = task_exec!(&self.task, async move |s| {
            if s.servers != servers {
                s.servers = servers;
                s.server_num = 0;
                s.stun_session = None;
                let _ = s.start_stun_session().await;
            }

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
        session_id: Session,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        telio_log_info!("stun send ping");
        task_exec!(&self.task, async move |s| Ok(s
            .send_ping(addr, session_id, &public_key)
            .await))
        .await?
    }
}

struct State<Wg: WireGuard> {
    servers: Vec<Server>,
    server_num: usize,

    tun_socket: UdpSocket,
    ext_socket: External<UdpSocket>,
    wg: Arc<Wg>,
    ping_pong_tracker: Arc<Mutex<PingPongHandler>>,

    change_event: Option<chan::Tx<EndpointCandidatesChangeEvent>>,
    pong_event: Option<chan::Tx<PongEvent>>,

    stun_session: Option<StunSession>,
    stun_interval: Interval,
    last_candidates: Vec<EndpointCandidate>,

    stun_peer_publisher: chan::Tx<Option<StunServer>>,
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
        session_id: Session,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        self.ping_pong_tracker
            .lock()
            .await
            .send_ping(
                addr,
                self.get_wg_port(),
                &*self.ext_socket,
                session_id,
                public_key,
            )
            .await
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

    async fn next_server(&mut self) -> Result<(), Error> {
        let server = if !self.servers.is_empty() {
            self.server_num = (self.server_num + 1) % self.servers.len();
            self.servers.get(self.server_num)
        } else {
            None
        };

        self.stun_peer_publisher
            .send(server.cloned())
            .await
            .map_err(|e| e.into())
    }

    /// Get endpoint's for stuns (WgStun, PlaintextStun)
    async fn get_stun_endpoints(&mut self) -> Result<(SocketAddr, SocketAddr), Error> {
        if let Some(server) = self.servers.get(self.server_num) {
            let interface = self.wg.get_interface().await?;

            let stun_peer = interface
                .peers
                .get(&server.public_key)
                .ok_or(Error::NoStunPeer)?;

            let wg_ip = stun_peer
                .allowed_ips
                .first()
                .ok_or(Error::BadStunPeer)?
                .ip();

            let udp_ip = stun_peer.endpoint.ok_or(Error::BadStunPeer)?.ip();

            Ok((
                (wg_ip, server.stun_port).into(),
                (udp_ip, server.stun_plaintext_port).into(),
            ))
        } else {
            Err(Error::NoStunPeer)
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
                            change_event
                                .send((EndpointProviderType::Stun, candidates))
                                .await?;
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

    async fn handle_ping_rx(
        &mut self,
        encrypted_buf: &[u8],
        addr: &SocketAddr,
    ) -> Result<(), Error> {
        let wg_port = self.get_wg_port();
        self.ping_pong_tracker
            .lock()
            .await
            .handle_rx_packet(
                encrypted_buf,
                addr,
                wg_port,
                &self.ext_socket,
                &self.pong_event,
            )
            .await
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

                let _ = self.next_server().await;

                if !self.last_candidates.is_empty() {
                    self.last_candidates.clear();
                    if let Some(ce) = &self.change_event {
                        let _ = ce.send((EndpointProviderType::Stun, vec![])).await;
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
                    // packet is not for this stun request
                    return Ok(false);
                }

                let (sa, id) = stun_msg::decode_response(payload)?;

                if &id != tid {
                    telio_log_warn!("Unexpected stun packet from {}", src_addr);
                    return Ok(false);
                }
                telio_log_debug!(
                    "Got stun response from {} for sesion {:?} -> {}",
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
    use std::net::{Ipv4Addr, SocketAddr};
    use stun_codec::rfc5389::{
        self,
        attributes::{MappedAddress, XorMappedAddress},
    };
    use telio_crypto::{
        encryption::{decrypt_request, decrypt_response, encrypt_request, encrypt_response},
        PublicKey, SecretKey,
    };
    use telio_model::mesh::IpNetwork;
    use telio_proto::{CodecError, Packet, PartialPongerMsg, PingerMsg};
    use telio_sockets::SocketPool;
    use telio_task::io::Chan;
    use telio_test::await_timeout;
    use telio_wg::{
        uapi::{Interface, Peer},
        Error,
    };
    use tokio::time::{self, sleep, timeout};

    #[tokio::test]
    async fn collect_stun_endpoints_on_configure() {
        let mut env = prepare_test_env().await;

        configure_env(&mut env).await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

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
    }

    #[tokio::test]
    async fn collect_stun_endpoints_on_change() {
        let mut env = prepare_test_env().await;

        configure_env(&mut env).await;

        // Triggered by configuration
        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

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
    }

    #[tokio::test]
    async fn report_empty_candidate_list_on_stun_failure() {
        let mut env = prepare_test_env().await;
        let mut buf = [0; MAX_PACKET_SIZE];

        configure_env(&mut env).await;

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

        let event = await_timeout!(env.change_event.recv());
        let (provider, candidates) = event.expect("got event");
        assert_eq!(provider, EndpointProviderType::Stun);
        assert_eq!(candidates, vec![]);
    }

    #[tokio::test]
    async fn pongs_propagated_through_the_channel() {
        let mut env = prepare_test_env().await;

        let session_id = 456;
        let ping_addr = env.ping_sock.local_addr().expect("local_addr");

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
        let (len, addr) = await_timeout!(env.ping_sock.recv_from(&mut buf)).unwrap();
        let decrypt_transform = |_packet_type, b: &[u8]| {
            Ok(decrypt_request(b, &remote_sk, |_| true)
                .map(|(buf, pk)| (buf, Some(pk)))
                .unwrap())
        };
        if let (Packet::Pinger(msg), _) =
            Packet::decode_and_decrypt(&buf[..len], decrypt_transform).unwrap()
        {
            let resp = msg.pong(msg.get_wg_port(), &addr.ip()).unwrap();

            let mut rng = rand::thread_rng();
            let encrypt_transform = |b: &[u8]| {
                Ok(encrypt_response(b, &mut rng, &remote_sk, &env.local_sk.public()).unwrap())
            };

            let buf = resp.encode_and_encrypt(encrypt_transform).unwrap();
            env.ping_sock.send_to(&buf, addr).await.unwrap();
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
        configure_env(&mut env).await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

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

        let (len, addr) = await_timeout!(env.ping_sock.recv_from(&mut buf)).unwrap();
        let decrypt_transform = |_packet_type, b: &[u8]| {
            Ok(decrypt_request(b, &remote_sk, |_| true)
                .map(|(buf, pk)| (buf, Some(pk)))
                .unwrap())
        };
        if let (Packet::Pinger(msg), _) =
            Packet::decode_and_decrypt(&buf[..len], decrypt_transform).unwrap()
        {
            let resp = msg.pong(msg.get_wg_port(), &addr.ip()).unwrap();

            let mut rng = rand::thread_rng();
            let encrypt_transform = |b: &[u8]| {
                Ok(encrypt_response(b, &mut rng, &remote_sk, &env.local_sk.public()).unwrap())
            };

            let buf = resp.encode_and_encrypt(encrypt_transform).unwrap();
            env.ping_sock.send_to(&buf, addr).await.unwrap();
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
    }

    #[tokio::test]
    async fn provider_replies_to_ping() {
        let mut env = prepare_test_env().await;

        let wg_port = WGPort(123);
        let session_id = 456;

        let ping = PingerMsg::ping(wg_port, session_id, 6969);
        let local_sk = SecretKey::gen();
        let remote_sk = env.local_sk;
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

        env.ping_sock
            .send_to(&encrypted_buf, env.provider_ext_addr)
            .await
            .expect("ping");

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = env.ping_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(addr, env.provider_ext_addr);

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

        configure_env(&mut env).await;

        let udp_endpoint = SocketAddr::new([1, 1, 1, 1].into(), 11111);
        let wg_endpoint = SocketAddr::new([2, 2, 2, 2].into(), 22222);

        await_timeout!(stun_reply(
            &env.stun_sock,
            XorMappedAddress::new(udp_endpoint)
        ));
        await_timeout!(stun_reply(&env.peer_sock, MappedAddress::new(wg_endpoint)));

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

        env.ping_sock
            .send_to(&encrypted_buf, env.provider_ext_addr)
            .await
            .expect("ping");

        let (len, addr) = await_timeout!(env.ping_sock.recv_from(&mut buf)).unwrap();

        assert_eq!(addr, env.provider_ext_addr);

        let pong = PartialPongerMsg::decode_and_decrypt(&buf[..len], |_, b| Ok((b.to_vec(), None)))
            .unwrap();
        let decrypt_transform = |b: &[u8]| {
            decrypt_response(b, &local_sk, &remote_sk.public())
                .map_err(|_| CodecError::DecodeFailed)
        };
        let pong = pong.decrypt(decrypt_transform).unwrap();

        assert_eq!(pong.get_wg_port(), WGPort(22222));
        assert_eq!(pong.get_session(), session_id);
    }

    // Test helpers

    mock! {
        Wg {}
        #[async_trait]
        impl WireGuard for Wg {
            async fn get_interface(&self) -> Result<Interface, Error>;
            async fn get_adapter_luid(&self) -> Result<u64, Error>;
            async fn wait_for_listen_port(&self, d: Duration) -> Result<u16, Error>;
            async fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, Error>;
            async fn set_secret_key(&self, key: SecretKey) -> Result<(), Error>;
            async fn set_fwmark(&self, fwmark: u32) -> Result<(), Error>;
            async fn add_peer(&self, peer: Peer) -> Result<(), Error>;
            async fn del_peer(&self, key: PublicKey) -> Result<(), Error>;
            async fn drop_connected_sockets(&self) -> Result<(), Error>;
            async fn time_since_last_rx(&self, public_key: PublicKey) -> Result<Option<Duration>, Error>;
            async fn time_since_last_endpoint_change(&self, public_key: PublicKey) -> Result<Option<Duration>, Error>;
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
        ping_sock: UdpSocket,
        local_sk: SecretKey,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,

        stun_peer_subscriber: chan::Rx<Option<StunServer>>,
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
        println!("ext_sock: {}", provider_ext_addr);

        let provider_tun_socket = socket_pool
            .new_internal_udp((Ipv4Addr::LOCALHOST, 0), None)
            .await
            .expect("crate tun socket");
        let provider_tun_addr = provider_tun_socket.local_addr().expect("provider tun addr");
        println!("tun_sock: {}", provider_tun_addr);

        let peer_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("peer sock");
        println!("peer: {}", peer_sock.local_addr().unwrap());

        let stun_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stun sock");
        println!("stun: {}", stun_sock.local_addr().unwrap());

        let ping_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("ping sock");
        println!("ping: {}", ping_sock.local_addr().unwrap());

        // Stun peer can be locked
        let stun_pk = SecretKey::gen().public();
        let allowed_ip = IpNetwork::new(peer_sock.local_addr().unwrap().ip(), 32).unwrap();
        let endpoint: SocketAddr = (stun_sock.local_addr().unwrap().ip(), 55555).into();
        wg.expect_get_interface().returning(move || {
            let stun_peer = Peer {
                public_key: stun_pk,
                // Allowed ip is used to get ip of remote peer, in this case the fake it to be 127.0.0.1
                // since we don't provide entire wirguard tunnel for testing.
                allowed_ips: vec![allowed_ip],
                // Endpoint would be peer's public ip and wg listen_port that we fake here.
                endpoint: Some(endpoint),
                ..Default::default()
            };

            Ok(Interface {
                listen_port: Some(wg_port),
                peers: vec![(stun_pk, stun_peer)].into_iter().collect(),
                ..Default::default()
            })
        });

        let Chan {
            rx: stun_peer_subscriber,
            tx: stun_peer_publisher,
        } = Chan::default();

        let secret_key = SecretKey::gen();
        let ping_pong_handler = Arc::new(Mutex::new(PingPongHandler::new(secret_key)));
        let stun_provider = StunEndpointProvider::start(
            provider_tun_socket,
            provider_ext_socket,
            Arc::new(wg),
            Duration::from_secs(10000),
            ping_pong_handler.clone(),
            stun_peer_publisher,
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
            ping_sock,
            local_sk: secret_key,
            ping_pong_handler,

            stun_peer_subscriber,
        }
    }

    async fn configure_env(env: &mut Env) {
        env.stun_provider
            .configure(vec![Server {
                name: "The only server".to_string(),
                stun_port: env.peer_sock.local_addr().unwrap().port(),
                stun_plaintext_port: env.stun_sock.local_addr().unwrap().port(),
                public_key: env.stun_pk,
                ..Default::default()
            }])
            .await;
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
