use crate::ping_pong_handler::PingPongHandler;

use super::{
    EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, EndpointProviderType,
    Error, PongEvent,
};
use async_trait::async_trait;
use futures::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use telio_crypto::PublicKey;
use telio_network_monitors::local_interfaces::{
    gather_local_interfaces, GetIfAddrs, SystemGetIfAddrs,
};
use telio_proto::{Session, WGPort};
use telio_sockets::External;
use telio_task::{io::chan, task_exec, BoxAction, Runtime, Task};
use telio_utils::{interval, telio_log_debug, telio_log_info, telio_log_warn};
use telio_wg::{DynamicWg, WireGuard};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Interval;

pub struct LocalInterfacesEndpointProvider<
    T: WireGuard = DynamicWg,
    G: GetIfAddrs = SystemGetIfAddrs,
> {
    task: Task<State<T, G>>,
}

pub struct State<T: WireGuard, G: GetIfAddrs> {
    endpoint_candidates_change_publisher: Option<chan::Tx<EndpointCandidatesChangeEvent>>,
    pong_publisher: Option<chan::Tx<PongEvent>>,
    last_endpoint_candidates_event: Vec<EndpointCandidate>,
    poll_timer: Interval,
    wireguard_interface: Arc<T>,
    udp_socket: External<UdpSocket>,
    ping_pong_handler: Arc<Mutex<PingPongHandler>>,
    get_if_addr: G,
}

#[async_trait]
impl<T: WireGuard, G: GetIfAddrs> EndpointProvider for LocalInterfacesEndpointProvider<T, G> {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn subscribe_for_pong_events(&self, tx: chan::Tx<PongEvent>) {
        task_exec!(&self.task, async move |s| {
            s.pong_publisher = Some(tx);
            Ok(())
        })
        .await
        .unwrap_or_default();
    }

    async fn subscribe_for_endpoint_candidates_change_events(
        &self,
        tx: chan::Tx<EndpointCandidatesChangeEvent>,
    ) {
        task_exec!(&self.task, async move |s| {
            s.endpoint_candidates_change_publisher = Some(tx);
            Ok(())
        })
        .await
        .unwrap_or_default();
    }

    async fn trigger_endpoint_candidates_discovery(&self, _force: bool) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| {
            Ok(s.poll_local_endpoints().await)
        })
        .await?
    }

    async fn handle_endpoint_gone_notification(&self) {}

    async fn send_ping(
        &self,
        addr: SocketAddr,
        session_id: Session,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| {
            Ok(s.send_ping(addr, session_id, &public_key).await)
        })
        .await?
    }

    async fn get_current_endpoints(&self) -> Option<Vec<EndpointCandidate>> {
        task_exec!(&self.task, async move |s| Ok(Some(
            s.last_endpoint_candidates_event.clone()
        )))
        .await
        .unwrap_or(None)
    }
}

impl<T: WireGuard> LocalInterfacesEndpointProvider<T> {
    pub fn new(
        udp_socket: External<UdpSocket>,
        wireguard_interface: Arc<T>,
        poll_interval: Duration,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
    ) -> Self {
        LocalInterfacesEndpointProvider::new_with(
            udp_socket,
            wireguard_interface,
            poll_interval,
            ping_pong_handler,
            SystemGetIfAddrs,
        )
    }
}

impl<T: WireGuard, G: GetIfAddrs> LocalInterfacesEndpointProvider<T, G> {
    pub fn new_with(
        udp_socket: External<UdpSocket>,
        wireguard_interface: Arc<T>,
        poll_interval: Duration,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        get_if_addr: G,
    ) -> Self {
        telio_log_info!("Starting local interfaces endpoint provider");
        let poll_timer = interval(poll_interval);
        Self {
            task: Task::start(State {
                endpoint_candidates_change_publisher: None,
                pong_publisher: None,
                last_endpoint_candidates_event: vec![],
                poll_timer,
                wireguard_interface,
                udp_socket,
                ping_pong_handler,
                get_if_addr,
            }),
        }
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

impl<T: WireGuard, G: GetIfAddrs> State<T, G> {
    async fn get_wg_port(&self) -> Result<u16, Error> {
        if let Some(wg_port) = self
            .wireguard_interface
            .get_interface()
            .await
            .ok()
            .and_then(|i| i.listen_port)
        {
            Ok(wg_port)
        } else {
            telio_log_warn!("Skipping local interfaces poll due to missing wg_port");
            Err(Error::NoWGListenPort)
        }
    }

    async fn poll_local_endpoints(&mut self) -> Result<(), Error> {
        if let Some(candidates_publisher) = self.endpoint_candidates_change_publisher.as_ref() {
            let wg_port = self.get_wg_port().await?;
            let udp_port = match self.udp_socket.local_addr() {
                Ok(addr) => addr.port(),
                Err(e) => {
                    telio_log_warn!("Skipping local interfaces poll due to failure to retrieve udp socket addr {:?}", e);
                    return Err(e.into());
                }
            };

            let itfs = gather_local_interfaces(&self.get_if_addr)?;

            let candidates: Vec<_> = itfs
                .iter()
                .map(|itf| EndpointCandidate {
                    wg: SocketAddr::new(itf.addr.ip(), wg_port),
                    udp: SocketAddr::new(itf.addr.ip(), udp_port),
                })
                .collect();

            if self.last_endpoint_candidates_event != candidates {
                telio_log_debug!("published candidates: {:?}", &candidates);
                candidates_publisher
                    .send((EndpointProviderType::LocalInterfaces, candidates.clone()))
                    .await
                    .map(|_| {
                        self.last_endpoint_candidates_event = candidates;
                    })?;
            } else {
                telio_log_debug!("candidates unchanged: {:?}", candidates);
            }
        } else {
            telio_log_debug!("Skipping local interfaces poll. No one subscribed for notifications");
        }
        Ok(())
    }

    async fn send_ping(
        &self,
        addr: SocketAddr,
        session_id: Session,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        let wg_port = WGPort(self.get_wg_port().await?);
        self.ping_pong_handler
            .lock()
            .await
            .send_ping(addr, wg_port, &self.udp_socket, session_id, public_key)
            .await
    }

    async fn handle_rx_packet(&self, encrypted_buf: &[u8], addr: &SocketAddr) -> Result<(), Error> {
        let wg_port = WGPort(self.get_wg_port().await?);
        self.ping_pong_handler
            .lock()
            .await
            .handle_rx_packet(
                encrypted_buf,
                addr,
                wg_port,
                &self.udp_socket,
                &self.pong_publisher,
                telio_model::features::EndpointProvider::Local,
            )
            .await
    }
}

#[async_trait]
impl<T: WireGuard, G: GetIfAddrs> Runtime for State<T, G> {
    const NAME: &'static str = "LocalInterfacesEndpointProvider";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        const MAX_SUPPORTED_PACKET_SIZE: usize = 1500;
        let mut rx_buff = vec![0u8; MAX_SUPPORTED_PACKET_SIZE];
        tokio::select! {
            Ok((len, addr)) = self.udp_socket.recv_from(&mut rx_buff) => {
                let buf = rx_buff.get(..len).ok_or(())?;
                self.handle_rx_packet(buf, &addr).await.unwrap_or_else(
                    |e| {
                        telio_log_warn!("Failed to handle packet received no local interface endpoint provider {:?}", e);
                    });
            }
            _ = self.poll_timer.tick() => {
                self.poll_local_endpoints().await.unwrap_or_else(
                    |e| {
                        telio_log_warn!("Failed to poll local endpoints {:?}", e);
                    });
            },
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

    use super::*;
    use if_addrs::IfOperStatus;
    use maplit::hashmap;
    use std::net::Ipv4Addr;
    use telio_crypto::{
        encryption::{decrypt_request, decrypt_response, encrypt_request, encrypt_response},
        SecretKey,
    };
    use telio_network_monitors::local_interfaces::MockGetIfAddrs;
    use telio_proto::{CodecError, PartialPongerMsg, PingerMsg, MAX_PACKET_SIZE};
    use telio_sockets::NativeProtector;
    use telio_sockets::SocketPool;
    use telio_task::io::Chan;
    use telio_wg::{uapi::Interface, MockWireGuard};
    use tokio::time::timeout;

    async fn create_localhost_socket(pool: &SocketPool) -> (External<UdpSocket>, SocketAddr) {
        let socket = pool
            .new_external_udp((Ipv4Addr::LOCALHOST, 0), None)
            .await
            .expect("Cannot create UdpSocket");
        let addr = socket.local_addr().unwrap();
        (socket, addr)
    }

    async fn prepare_state_test(
        wg_mock: MockWireGuard,
        get_if_addrs_mock: MockGetIfAddrs,
    ) -> (
        State<MockWireGuard, MockGetIfAddrs>,
        SecretKey,
        Arc<Mutex<PingPongHandler>>,
    ) {
        let secret_key = SecretKey::gen();
        let ping_pong_handler = Arc::new(Mutex::new(PingPongHandler::new(secret_key.clone())));
        (
            State {
                endpoint_candidates_change_publisher: None,
                pong_publisher: None,
                last_endpoint_candidates_event: vec![],
                poll_timer: interval(Duration::from_secs(10)),
                wireguard_interface: Arc::new(wg_mock),
                udp_socket: SocketPool::new(
                    NativeProtector::new(
                        #[cfg(target_os = "macos")]
                        false,
                    )
                    .unwrap(),
                )
                .new_external_udp((Ipv4Addr::LOCALHOST, 0), None)
                .await
                .unwrap(),
                ping_pong_handler: ping_pong_handler.clone(),
                get_if_addr: get_if_addrs_mock,
            },
            secret_key,
            ping_pong_handler,
        )
    }

    async fn prepare_local_provider_test(
        wg_mock: MockWireGuard,
        get_if_addrs_mock: MockGetIfAddrs,
    ) -> (
        LocalInterfacesEndpointProvider<MockWireGuard, MockGetIfAddrs>,
        chan::Rx<EndpointCandidatesChangeEvent>,
        chan::Rx<PongEvent>,
        telio_sockets::External<tokio::net::UdpSocket>,
        SocketAddr,
        SocketAddr,
        SecretKey,
        Arc<Mutex<PingPongHandler>>,
    ) {
        let secret_key = SecretKey::gen();
        let socket_pool = SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        );

        async fn create_localhost_socket(pool: &SocketPool) -> (External<UdpSocket>, SocketAddr) {
            let socket = pool
                .new_external_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), None)
                .await
                .expect("Cannot create UdpSocket");
            let addr = socket.local_addr().unwrap();
            (socket, addr)
        }

        let (provider_socket, provider_addr) = create_localhost_socket(&socket_pool).await;
        let (peer_socket, peer_addr) = create_localhost_socket(&socket_pool).await;

        let ping_pong_handler = Arc::new(Mutex::new(PingPongHandler::new(secret_key.clone())));
        let local_provider = LocalInterfacesEndpointProvider::new_with(
            provider_socket,
            Arc::new(wg_mock),
            Duration::from_secs(10000),
            ping_pong_handler.clone(),
            get_if_addrs_mock,
        );

        let candidates_channel = Chan::<EndpointCandidatesChangeEvent>::default();
        let pongs_channel = Chan::<PongEvent>::default();

        local_provider
            .subscribe_for_endpoint_candidates_change_events(candidates_channel.tx.clone())
            .await;
        local_provider
            .subscribe_for_pong_events(pongs_channel.tx.clone())
            .await;

        (
            local_provider,
            candidates_channel.rx,
            pongs_channel.rx,
            peer_socket,
            peer_addr,
            provider_addr,
            secret_key,
            ping_pong_handler,
        )
    }

    fn generate_fake_local_interface(addr_suffix: u8) -> std::io::Result<Vec<if_addrs::Interface>> {
        Ok(vec![if_addrs::Interface {
            name: "random_name".to_owned(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip: Ipv4Addr::new(10, 0, 0, addr_suffix),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefixlen: 24,
                broadcast: None,
            }),
            index: None,
            oper_status: IfOperStatus::Testing,
            is_p2p: false,
            #[cfg(windows)]
            adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
        }])
    }

    #[tokio::test]
    async fn candidates_propagated_through_the_channel_when_changed() {
        let mut wg_mock = MockWireGuard::new();
        wg_mock.expect_get_interface().returning(|| {
            Ok(Interface {
                listen_port: Some(12345),
                ..Default::default()
            })
        });

        fn expect_get_once(
            seq: &mut mockall::Sequence,
            mock: &mut MockGetIfAddrs,
            addr_suffix: u8,
        ) {
            mock.expect_get()
                .times(1)
                .in_sequence(seq)
                .return_once(move || generate_fake_local_interface(addr_suffix));
        }

        let mut seq = mockall::Sequence::new();
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        expect_get_once(&mut seq, &mut get_if_addrs_mock, 1);
        expect_get_once(&mut seq, &mut get_if_addrs_mock, 2);
        expect_get_once(&mut seq, &mut get_if_addrs_mock, 3);
        expect_get_once(&mut seq, &mut get_if_addrs_mock, 3);

        let (local_provider, mut candidates_rx, _, _, _, provider_addr, _, _) =
            prepare_local_provider_test(wg_mock, get_if_addrs_mock).await;

        for i in 1..4 {
            let msg = candidates_rx.recv().await;
            assert!(msg.is_some());

            let (provider, candidates) = msg.unwrap();
            assert_eq!(provider, EndpointProviderType::LocalInterfaces);
            assert!(candidates.len() == 1);
            assert!(
                candidates[0].udp
                    == SocketAddr::new(
                        std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                        provider_addr.port()
                    )
            );
            assert!(
                candidates[0].wg
                    == SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 12345)
            );

            local_provider
                .trigger_endpoint_candidates_discovery(false)
                .await
                .unwrap();
        }

        candidates_rx
            .try_recv()
            .expect_err("Candidates should not be propagated if unchanged");

        local_provider.stop().await;
    }

    #[tokio::test]
    async fn pongs_propagated_through_the_channel() {
        let mut wg_mock = MockWireGuard::new();
        wg_mock.expect_get_interface().returning(|| {
            Ok(Interface {
                listen_port: Some(12345),
                ..Default::default()
            })
        });

        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock
            .expect_get()
            .returning(|| generate_fake_local_interface(1));

        let (
            local_provider,
            _,
            mut pong_rx,
            peer_socket,
            peer_addr,
            _,
            local_sk,
            ping_pong_handler,
        ) = prepare_local_provider_test(wg_mock, get_if_addrs_mock).await;

        let session_id = 456;
        let remote_sk = SecretKey::gen();
        let remote_pk = remote_sk.public();

        ping_pong_handler
            .lock()
            .await
            .configure(hashmap! { 456 => remote_pk });

        local_provider
            .send_ping(peer_addr, session_id, remote_pk)
            .await
            .unwrap();

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = peer_socket.recv_from(&mut buf).await.unwrap();
        let decrypt_transform = |_packet_type, b: &[u8]| {
            Ok(decrypt_request(b, &remote_sk, |_| true)
                .map(|(buf, pk)| (buf, Some(pk)))
                .unwrap())
        };
        let (msg, _) = PingerMsg::decode_and_decrypt(&buf[..len], decrypt_transform).unwrap();
        let resp = msg
            .pong(
                msg.get_wg_port(),
                &addr.ip(),
                telio_model::features::EndpointProvider::Local,
            )
            .unwrap();
        let mut rng = rand::rng();
        let encrypt_transform =
            |b: &[u8]| Ok(encrypt_response(b, &mut rng, &remote_sk, &local_sk.public()).unwrap());

        let buf = resp.encode_and_encrypt(encrypt_transform).unwrap();
        peer_socket.send_to(&buf, addr).await.unwrap();

        let pong = pong_rx.recv().await;
        assert!(pong.is_some());
        let pong = pong.unwrap();
        // Port is allways recieved from actual interface
        assert_eq!(pong.msg.get_wg_port(), WGPort(12345));
        assert!(pong.msg.get_session() == session_id);
        assert!(pong.addr == peer_addr);

        local_provider.stop().await;
    }

    #[tokio::test]
    async fn unexpected_pong_is_not_propagated_through_the_channel() {
        let mut wg_mock = MockWireGuard::new();
        wg_mock.expect_get_interface().returning(|| {
            Ok(Interface {
                listen_port: Some(12345),
                ..Default::default()
            })
        });

        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock
            .expect_get()
            .returning(|| generate_fake_local_interface(1));

        let (local_provider, _, mut pong_rx, peer_socket, peer_addr, _, local_sk, _) =
            prepare_local_provider_test(wg_mock, get_if_addrs_mock).await;

        let session_id = 456;
        let remote_sk = SecretKey::gen();
        let remote_pk = remote_sk.public();

        local_provider
            .send_ping(peer_addr, session_id, remote_pk)
            .await
            .unwrap();

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = peer_socket.recv_from(&mut buf).await.unwrap();
        let decrypt_transform = |_packet_type, b: &[u8]| {
            Ok(decrypt_request(b, &remote_sk, |_| true)
                .map(|(buf, pk)| (buf, Some(pk)))
                .unwrap())
        };
        let (msg, _) = PingerMsg::decode_and_decrypt(&buf[..len], decrypt_transform).unwrap();
        let resp = msg
            .pong(
                msg.get_wg_port(),
                &addr.ip(),
                telio_model::features::EndpointProvider::Local,
            )
            .unwrap();
        let mut rng = rand::rng();
        let encrypt_transform =
            |b: &[u8]| Ok(encrypt_response(b, &mut rng, &remote_sk, &local_sk.public()).unwrap());

        let buf = resp.encode_and_encrypt(encrypt_transform).unwrap();
        peer_socket.send_to(&buf, addr).await.unwrap();

        let pong = timeout(Duration::from_secs(2), pong_rx.recv()).await;
        assert!(pong.is_err());
        local_provider.stop().await;
    }

    #[tokio::test]
    async fn handling_of_received_ping_from_allowed_peer() {
        let wg_port = 12345;
        let mut wg_mock = MockWireGuard::new();
        wg_mock.expect_get_interface().returning({
            move || {
                Ok(Interface {
                    listen_port: Some(wg_port),
                    ..Default::default()
                })
            }
        });

        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock
            .expect_get()
            .returning(|| generate_fake_local_interface(1));

        let (state, remote_sk, ping_pong_handler) =
            prepare_state_test(wg_mock, get_if_addrs_mock).await;

        let socket_pool = SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        );

        let (provider_socket, provider_addr) = create_localhost_socket(&socket_pool).await;
        let ping = PingerMsg::ping(WGPort(wg_port), 2, 3);
        let local_sk = SecretKey::gen();
        let encrypt_transform = |b: &[u8]| {
            Ok(
                encrypt_request(b, &mut rand::rng(), &local_sk.clone(), &remote_sk.public())
                    .unwrap(),
            )
        };
        let encrypted_buf = ping.clone().encode_and_encrypt(encrypt_transform).unwrap();

        let sk_copy = local_sk.clone();
        tokio::spawn(async move {
            ping_pong_handler
                .lock()
                .await
                .configure(hashmap! { 456 => sk_copy.public() });
            state.handle_rx_packet(&encrypted_buf, &provider_addr).await
        });

        let mut output = vec![0u8; MAX_PACKET_SIZE];
        let len = provider_socket.recv(&mut output).await.unwrap();
        let pong =
            PartialPongerMsg::decode_and_decrypt(&output[..len], |_, b| Ok((b.to_vec(), None)))
                .unwrap();
        let decrypt_transform = |b: &[u8]| {
            decrypt_response(b, &local_sk, &remote_sk.public())
                .map_err(|_| CodecError::DecodeFailed)
        };
        let pong = pong.decrypt(decrypt_transform).unwrap();
        assert_eq!(pong.get_wg_port(), WGPort(wg_port));
        assert_eq!(pong.get_ping_source_address().unwrap(), provider_addr.ip());
    }

    #[tokio::test]
    async fn handling_of_received_ping_from_disallowed_peer() {
        let wg_port = 12345;
        let mut wg_mock = MockWireGuard::new();
        wg_mock.expect_get_interface().returning({
            move || {
                Ok(Interface {
                    listen_port: Some(wg_port),
                    ..Default::default()
                })
            }
        });

        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock
            .expect_get()
            .returning(|| generate_fake_local_interface(1));

        let (state, remote_sk, ping_pong_handler) =
            prepare_state_test(wg_mock, get_if_addrs_mock).await;

        let socket_pool = SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        );

        let (provider_socket, provider_addr) = create_localhost_socket(&socket_pool).await;
        let ping = PingerMsg::ping(WGPort(wg_port), 2, 3);
        let local_sk = SecretKey::gen();
        let encrypt_transform = |b: &[u8]| {
            Ok(encrypt_request(b, &mut rand::rng(), &local_sk, &remote_sk.public()).unwrap())
        };
        let encrypted_buf = ping.clone().encode_and_encrypt(encrypt_transform).unwrap();

        tokio::spawn(async move {
            ping_pong_handler.lock().await.configure(Default::default());
            state.handle_rx_packet(&encrypted_buf, &provider_addr).await
        });

        let mut output = vec![0u8; MAX_PACKET_SIZE];
        assert!(
            timeout(Duration::from_secs(2), provider_socket.recv(&mut output))
                .await
                .is_err()
        );
    }
}
