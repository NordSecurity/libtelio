use super::{EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, Error, PongEvent};
use async_trait::async_trait;
use futures::Future;
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use telio_proto::{Codec, Packet, PingType, PingerMsg, Session, Timestamp, WGPort};
use telio_sockets::External;
use telio_task::BoxAction;
use telio_task::{io::chan, task_exec, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};
use telio_wg::WireGuard;
use tokio::net::UdpSocket;
use tokio::time::{interval_at, Interval};

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
pub trait GetIfAddrs: Send + Sync + Default + 'static {
    fn get(&self) -> std::io::Result<Vec<if_addrs::Interface>>;
}

#[derive(Default)]
pub struct SystemGetIfAddrs;
impl GetIfAddrs for SystemGetIfAddrs {
    fn get(&self) -> std::io::Result<Vec<if_addrs::Interface>> {
        if_addrs::get_if_addrs()
    }
}

pub struct LocalInterfacesEndpointProvider<T: WireGuard, G: GetIfAddrs = SystemGetIfAddrs> {
    task: Task<State<T, G>>,
}

pub struct State<T: WireGuard, G: GetIfAddrs> {
    endpoint_candidates_change_publisher: Option<chan::Tx<EndpointCandidatesChangeEvent>>,
    pong_publisher: Option<chan::Tx<PongEvent>>,
    last_endpoint_candidates_event: EndpointCandidatesChangeEvent,
    poll_timer: Interval,
    wireguard_interface: Arc<T>,
    udp_socket: External<UdpSocket>,
    get_if_addr: G,
}

#[async_trait]
impl<T: WireGuard, G: GetIfAddrs> EndpointProvider for LocalInterfacesEndpointProvider<T, G> {
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

    async fn trigger_endpoint_candidates_discovery(&self) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| {
            Ok(s.poll_local_endpoints().await)
        })
        .await?
    }

    async fn send_ping(
        &self,
        addr: SocketAddr,
        wg_port: WGPort,
        session_id: Session,
    ) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| {
            Ok(s.send_ping(addr, wg_port, session_id).await)
        })
        .await?
    }
}

impl<T: WireGuard> LocalInterfacesEndpointProvider<T> {
    pub fn new(
        udp_socket: External<UdpSocket>,
        wireguard_interface: Arc<T>,
        poll_interval: Duration,
    ) -> Self {
        LocalInterfacesEndpointProvider::new_with_get_if_addrs(
            udp_socket,
            wireguard_interface,
            poll_interval,
            SystemGetIfAddrs::default(),
        )
    }
}

impl<T: WireGuard, G: GetIfAddrs> LocalInterfacesEndpointProvider<T, G> {
    pub fn new_with_get_if_addrs(
        udp_socket: External<UdpSocket>,
        wireguard_interface: Arc<T>,
        poll_interval: Duration,
        get_if_addr: G,
    ) -> Self {
        telio_log_info!("Starting local interfaces endpoint provider");
        Self {
            task: Task::start(State {
                endpoint_candidates_change_publisher: None,
                pong_publisher: None,
                last_endpoint_candidates_event: vec![],
                poll_timer: interval_at(tokio::time::Instant::now(), poll_interval),
                wireguard_interface,
                udp_socket,
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
            .and_then(|i| i.listen_port)
        {
            Ok(wg_port)
        } else {
            telio_log_warn!("Skipping local interfaces poll due to missing wg_port");
            Err(Error::NoWGListenPort)
        }
    }

    fn gather_local_interfaces(&self) -> Result<Vec<if_addrs::Interface>, Error> {
        let shared_range: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)?;
        Ok(self
            .get_if_addr
            .get()?
            .into_iter()
            .filter(|x| !x.addr.is_loopback())
            .filter(|x| match x.addr.ip() {
                // Filter 100.64/10 libtelio's meshnet network.
                IpAddr::V4(v4) => !shared_range.contains(&v4),
                // Filter IPv6
                _ => false,
            })
            .collect())
    }

    async fn poll_local_endpoints(&mut self) -> Result<(), Error> {
        if let Some(candidates_publisher) = self.endpoint_candidates_change_publisher.as_ref() {
            let wg_port = self.get_wg_port().await?;
            let udp_port = match self.udp_socket.local_addr() {
                Ok(addr) => addr.port(),
                Err(e) => {
                    telio_log_warn!("Skipping local interfaces poll due to failure to retreive udp socket addr {:?}", e);
                    return Err(e.into());
                }
            };

            let itfs = self.gather_local_interfaces()?;

            let candidates: EndpointCandidatesChangeEvent = itfs
                .iter()
                .map(|itf| EndpointCandidate {
                    wg: SocketAddr::new(itf.addr.ip(), wg_port),
                    udp: SocketAddr::new(itf.addr.ip(), udp_port),
                })
                .collect();

            if self.last_endpoint_candidates_event != candidates {
                telio_log_debug!("published candidates: {:?}", &candidates);
                candidates_publisher
                    .send(candidates.clone())
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
        self.udp_socket.send_to(&buf, addr).await?;
        Ok(())
    }

    async fn handle_rx_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<(), Error> {
        match Packet::decode(buf)? {
            Packet::Pinger(packet) => {
                match packet.get_message_type() {
                    PingType::PING => {
                        // Respond with pong
                        telio_log_debug!("Received ping from {:?}, responding", addr);
                        let wg_port = self.get_wg_port().await?;
                        let pong = packet
                            .pong(WGPort(wg_port))
                            .ok_or(Error::FailedToBuildPongPacket)?;
                        let buf = pong.encode()?;
                        self.udp_socket.send_to(&buf, addr).await?;
                    }
                    PingType::PONG => {
                        if let Some(pong_publisher) = self.pong_publisher.as_ref() {
                            telio_log_debug!("Received pong from {:?}, notifying", addr);
                            let ts = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_micros() as Timestamp;
                            pong_publisher
                                .send(PongEvent {
                                    addr: *addr,
                                    rtt: Duration::from_millis(ts - packet.get_start_timestamp()),
                                    msg: packet.clone(),
                                })
                                .await?;
                        } else {
                            telio_log_warn!(
                                "Received pong from {:?}, No one subscribed for notifications",
                                addr
                            );
                        }
                    }
                }
            }
            p => {
                telio_log_warn!("Received unknown packet on local endpoint provider {:?}", p);
            }
        }

        Ok(())
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
        let mut rx_buff = [0u8; MAX_SUPPORTED_PACKET_SIZE];
        tokio::select! {
            Ok((len, addr)) = self.udp_socket.recv_from(&mut rx_buff) => {
                let buf = &rx_buff[..len];
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
    use mockall::mock;
    use std::net::Ipv6Addr;
    use telio_crypto::{PublicKey, SecretKey};
    use telio_proto::MAX_PACKET_SIZE;
    use telio_sockets::SocketPool;
    use telio_task::io::Chan;
    use telio_wg::{
        uapi::{Interface, Peer},
        Error,
    };

    mock! {
        WG {}
        #[async_trait]
        impl WireGuard for WG {
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

    async fn prepare_state_test(
        wg_mock: MockWG,
        get_if_addrs_mock: MockGetIfAddrs,
    ) -> State<MockWG, MockGetIfAddrs> {
        State {
            endpoint_candidates_change_publisher: None,
            pong_publisher: None,
            last_endpoint_candidates_event: vec![],
            poll_timer: interval_at(tokio::time::Instant::now(), Duration::from_secs(10)),
            wireguard_interface: Arc::new(wg_mock),
            udp_socket: SocketPool::default()
                .new_external_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), None)
                .await
                .unwrap(),
            get_if_addr: get_if_addrs_mock,
        }
    }

    async fn prepare_local_provider_test(
        wg_mock: MockWG,
        get_if_addrs_mock: MockGetIfAddrs,
    ) -> (
        LocalInterfacesEndpointProvider<MockWG, MockGetIfAddrs>,
        chan::Rx<EndpointCandidatesChangeEvent>,
        chan::Rx<PongEvent>,
        telio_sockets::External<tokio::net::UdpSocket>,
        SocketAddr,
        SocketAddr,
        SocketPool,
    ) {
        let socket_pool = SocketPool::default();

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

        let local_provider = LocalInterfacesEndpointProvider::new_with_get_if_addrs(
            provider_socket,
            Arc::new(wg_mock),
            Duration::from_secs(10000),
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
            socket_pool,
        )
    }

    #[tokio::test]
    async fn gather_local_interfaces_filtering() {
        let wg_mock = MockWG::new();
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock.expect_get().return_once(|| {
            Ok(vec![
                if_addrs::Interface {
                    name: "localhost".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(127, 0, 0, 1),
                        netmask: Ipv4Addr::new(255, 0, 0, 0),
                        broadcast: None,
                    }),
                },
                if_addrs::Interface {
                    name: "correct".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(10, 0, 0, 1),
                        netmask: Ipv4Addr::new(255, 255, 255, 0),
                        broadcast: None,
                    }),
                },
                if_addrs::Interface {
                    name: "internal".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(100, 64, 0, 1),
                        netmask: Ipv4Addr::new(255, 192, 0, 0),
                        broadcast: None,
                    }),
                },
                if_addrs::Interface {
                    name: "ipv6".to_owned(),
                    addr: if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                        ip: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 12, 34),
                        netmask: Ipv6Addr::new(255, 255, 255, 255, 0, 0, 0, 0),
                        broadcast: None,
                    }),
                },
            ])
        });

        let state = prepare_state_test(wg_mock, get_if_addrs_mock).await;

        let interfaces = state.gather_local_interfaces().unwrap();
        assert!(interfaces.len() == 1);
        assert!(interfaces[0].name == "correct");
    }

    fn generate_fake_local_interface(addr_suffix: u8) -> std::io::Result<Vec<if_addrs::Interface>> {
        Ok(vec![if_addrs::Interface {
            name: "random_name".to_owned(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip: Ipv4Addr::new(10, 0, 0, addr_suffix),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                broadcast: None,
            }),
        }])
    }

    #[tokio::test]
    async fn candidates_propagated_through_the_channel_when_changed() {
        let mut wg_mock = MockWG::new();
        wg_mock.expect_get_interface().returning(|| {
            Some(Interface {
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

        let (local_provider, mut candidates_rx, _, _, _, provider_addr, _) =
            prepare_local_provider_test(wg_mock, get_if_addrs_mock).await;

        for i in 1..4 {
            let msg = candidates_rx.recv().await;
            assert!(msg.is_some());

            let candidates = msg.unwrap();
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
                .trigger_endpoint_candidates_discovery()
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
        let mut wg_mock = MockWG::new();
        wg_mock.expect_get_interface().returning(|| {
            Some(Interface {
                listen_port: Some(12345),
                ..Default::default()
            })
        });

        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock
            .expect_get()
            .returning(|| generate_fake_local_interface(1));

        let (local_provider, _, mut pong_rx, peer_socket, peer_addr, _, _) =
            prepare_local_provider_test(wg_mock, get_if_addrs_mock).await;

        let wg_port = WGPort(123);
        let session_id = 456;

        local_provider
            .send_ping(peer_addr, wg_port, session_id)
            .await
            .unwrap();

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = peer_socket.recv_from(&mut buf).await.unwrap();
        if let Packet::Pinger(msg) = Packet::decode(&buf[..len]).unwrap() {
            if msg.get_message_type() == PingType::PING {
                let resp = msg.pong(msg.get_wg_port()).unwrap();
                let buf = resp.encode().unwrap();
                peer_socket.send_to(&buf, addr).await.unwrap();
            } else {
                panic!("Incorect message type inside Pinger message");
            }
        } else {
            panic!("Incorect packet type in place of ping");
        }

        let pong = pong_rx.recv().await;
        assert!(pong.is_some());
        let pong = pong.unwrap();
        assert!(pong.msg.get_message_type() == PingType::PONG);
        assert!(pong.msg.get_wg_port() == wg_port);
        assert!(pong.msg.get_session() == session_id);
        assert!(pong.addr == peer_addr);

        local_provider.stop().await;
    }
}
