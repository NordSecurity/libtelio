use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use futures::{future::join_all, TryFutureExt};
use ipnet::IpNet;
use pnet_packet::{ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet};
use telio_model::PublicKey;
use tokio::net::UdpSocket;

use telio_sockets::SocketPool;
use telio_task::{
    io::{wait_for_tx, Chan},
    task_exec, Runtime, RuntimeExt, Task, WaitResponse,
};
use telio_utils::{
    exponential_backoff::{
        Backoff, Error as ExponentialBackoffError, ExponentialBackoff, ExponentialBackoffBounds,
    },
    PinnedSleep,
};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};

use telio_model::constants::{
    IPV4_MULTICAST_NETWORK, IPV4_STARCAST_ADDRESS, IPV6_MULTICAST_NETWORK, IPV6_STARCAST_ADDRESS,
};

use crate::{
    nat::{self, Nat, StarcastNat},
    utils::MutableIpPacket,
};

#[cfg(feature = "test-util")]
const MULTICAST_TRANSPORT_PORT: u16 = 0;
// Randomly chosen port for multicast transport
// Will eventually be replaced with dynamic port selection
#[cfg(not(feature = "test-util"))]
const MULTICAST_TRANSPORT_PORT: u16 = 13569;
const MAX_PACKET_SIZE: usize = u16::MAX as usize;

/// Starcast transport-specific errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Could not bind to socket
    #[error("Could not bind to socket")]
    SocketBindError(String),
    /// Invalid IP Packet
    #[error("Invalid IP Packet")]
    InvalidIpPacket,
    /// Natted IP address does not belong to a peer
    #[error("Natted IP address does not belong to a peer")]
    NoIpForPeer,
    /// Failed to fan out local multicast packet to some peers
    #[error("Failed to fan out local multicast packet to peers {0:?}")]
    FanoutFailed(Vec<PublicKey>),
    /// Failed to send packet over socket
    #[error("Failed to send packet over socket")]
    SocketSendError,
    /// Failed to send packet over channel
    #[error("Failed to send packet over channel")]
    ChannelSendError,
    /// Failed to nat packet
    #[error(transparent)]
    NatError(#[from] nat::Error),
    /// Task execution failed
    #[error(transparent)]
    TaskError(#[from] telio_task::ExecError),
    /// Transport socket isn't open yet, probably because tunnel interface hadn't been configured yet.
    #[error("Transport socket isn't open yet")]
    TransportSocketNotOpen,
    /// Exponential backoff error
    #[error(transparent)]
    ExponentialBackoffError(#[from] ExponentialBackoffError),
}

/// A peer in the meshnet
#[derive(Copy, Clone)]
pub struct Peer {
    /// The IP address of the peer
    pub addr: SocketAddr,
    /// The public key of the peer
    pub public_key: PublicKey,
    /// Whether our node accepts multicast messages from the peer or not.
    pub allow_multicast: bool,
    /// Whether the peer node accepts multicast messages from our node or not.
    pub peer_allows_multicast: bool,
}

/// Config for transport component
/// Contains fields that can change at runtime
pub enum Config {
    /// Simple transport config, has IP of peer but not port
    Simple(Vec<(PublicKey, IpAddr, bool, bool)>),
    /// Full transport config, has full socket address of peer
    Full(Vec<(PublicKey, SocketAddr, bool, bool)>),
}

/// The starcast transport component
/// Manages the task that does the actual transport
pub struct Transport {
    task: Task<State>,
}

impl Transport {
    /// Starts the transport component
    ///
    /// Parameters:
    /// * meshnet_ip - The meshnet IP of the node on which this component is currently running
    /// * socket_pool - To create the transport socket
    /// * packet_chan - A channel to send packets to and receive packets from the virtual peer component
    pub async fn start(
        meshnet_ip: IpAddr,
        socket_pool: Arc<SocketPool>,
        packet_chan: Chan<Vec<u8>>,
    ) -> Result<Self, Error> {
        let multicast_ips = vec![IPV4_MULTICAST_NETWORK.into(), IPV6_MULTICAST_NETWORK.into()];
        let exponential_backoff = ExponentialBackoff::new(ExponentialBackoffBounds {
            initial: Duration::from_secs(2),
            maximal: Some(Duration::from_secs(120)),
        })?;
        // If transport socket cannot be opened right now (for example, if meshnet had been started before
        // the tunnel interface's IP had been configured), transport socket cannot be opened at start and
        // will be opened later. In the mean time the channel between the starcast peer and transport
        // component will buffer the multicast messages until the transport socket will be opened. If the
        // buffers fill up, the messages will be ignored.
        let transport_socket =
            match open_transport_socket(socket_pool.clone(), meshnet_ip, MULTICAST_TRANSPORT_PORT)
                .await
            {
                Ok(transport_socket) => Some(transport_socket),
                Err(_) => {
                    telio_log_warn!(
                        "Starcast will try to open transport socket again in {:?}",
                        exponential_backoff.get_backoff()
                    );
                    None
                }
            };

        Ok(Self {
            task: Task::start(State {
                transport_socket,
                packet_chan,
                multicast_ips,
                recv_buffer: vec![0; MAX_PACKET_SIZE],
                nat: StarcastNat::new(IPV4_STARCAST_ADDRESS, IPV6_STARCAST_ADDRESS),
                peers: Vec::new(),
                socket_pool,
                meshnet_ip,
                exponential_backoff,
            }),
        })
    }

    /// Update runtime values of the transport component
    pub async fn configure(&self, config: Config) -> Result<(), Error> {
        task_exec!(&self.task, async move |state| {
            state.configure(config);
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Stop the transport component
    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

async fn open_transport_socket(
    socket_pool: Arc<SocketPool>,
    ip: IpAddr,
    port: u16,
) -> Result<Arc<UdpSocket>, Error> {
    let transport_socket = socket_pool
        .new_internal_udp(SocketAddr::new(ip, port), None)
        .await
        .map_err(|e| {
            telio_log_warn!("Failed to bind multicast socket: {:?}", e);
            Error::SocketBindError(e.to_string())
        })?;

    Ok(Arc::new(transport_socket))
}

struct State {
    transport_socket: Option<Arc<UdpSocket>>,
    packet_chan: Chan<Vec<u8>>,
    recv_buffer: Vec<u8>,
    nat: StarcastNat,
    peers: Vec<Peer>,
    multicast_ips: Vec<IpNet>,
    socket_pool: Arc<SocketPool>,
    meshnet_ip: IpAddr,
    exponential_backoff: ExponentialBackoff,
}

impl State {
    fn configure(&mut self, config: Config) {
        self.peers = match config {
            Config::Simple(peers) => peers
                .into_iter()
                .map(
                    |(public_key, addr, allow_multicast, peer_allows_multicast)| Peer {
                        public_key,
                        addr: SocketAddr::new(addr, MULTICAST_TRANSPORT_PORT),
                        allow_multicast,
                        peer_allows_multicast,
                    },
                )
                .collect(),
            Config::Full(peers) => peers
                .into_iter()
                .map(
                    |(public_key, addr, allow_multicast, peer_allows_multicast)| Peer {
                        public_key,
                        addr,
                        allow_multicast,
                        peer_allows_multicast,
                    },
                )
                .collect(),
        };
    }

    async fn handle_local_multicast_packet(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        let Some(transport_socket) = self.transport_socket.as_ref() else {
            return Err(Error::TransportSocketNotOpen);
        };
        // If peer_allows_multicast is false for a peer, we cannot send multicast packets to that peer,
        // but we can still receive multicast packets from that peer.
        let failed_peers = join_all(self.peers.iter().filter(|p| p.peer_allows_multicast).map(
            |peer| {
                transport_socket
                    .send_to(&packet, peer.addr)
                    .map_err(|_| peer.public_key)
            },
        ))
        .await
        .into_iter()
        .filter_map(|res| match res {
            Ok(_) => None,
            Err(pk) => Some(pk),
        })
        .collect::<Vec<_>>();

        if failed_peers.is_empty() {
            Ok(())
        } else {
            Err(Error::FanoutFailed(failed_peers))
        }
    }

    async fn handle_mapped_unicast_packet(&mut self, mut packet: Vec<u8>) -> Result<(), Error> {
        let peer_ip = self
            .nat
            .translate_outgoing(&mut packet)
            .map_err(Error::NatError)?;
        let peer_ip = self
            .peers
            .iter()
            .find(|peer| peer.addr.ip() == peer_ip)
            .map(|p| p.addr)
            .ok_or(Error::NoIpForPeer)?;
        self.transport_socket
            .as_ref()
            .ok_or(Error::TransportSocketNotOpen)?
            .send_to(&packet, peer_ip)
            .await
            .map(|_| ())
            .map_err(|_| Error::SocketSendError)
    }

    /// Separate method for handling starcast packets received on the transport socket from other
    /// meshnet nodes and dropping those packets if multicast isn't allowed for those nodes.
    async fn handle_incoming_packet(
        &mut self,
        mut packet: Vec<u8>,
        send_permit: tokio::sync::mpsc::OwnedPermit<Vec<u8>>,
    ) -> Result<(), Error> {
        let peer_ip = self
            .nat
            .translate_incoming(&mut packet)
            .map_err(Error::NatError)?;
        if self
            .peers
            .iter()
            .find(|peer| peer.addr.ip() == peer_ip)
            // If allow_multicast is false for a peer, we drop any multicast packets that were
            // received from that peer, but we can still send multicast packets to that peer.
            .filter(|peer| peer.allow_multicast)
            .is_some()
        {
            // If a starcast packet is received from a peer which is not present in the peer list,
            // we assume that multicast is disallowed for it.
            send_permit.send(packet);
        };

        Ok(())
    }

    fn has_multicast_dst(&self, packet: &mut [u8]) -> Result<bool, Error> {
        let dst = match packet.first().ok_or(Error::InvalidIpPacket)? >> 4 {
            4 => Self::get_packet_dst::<MutableIpv4Packet>(packet),
            6 => Self::get_packet_dst::<MutableIpv6Packet>(packet),
            _ => Err(Error::InvalidIpPacket),
        }?;
        Ok(self
            .multicast_ips
            .iter()
            .any(|network| network.contains(&dst)))
    }

    fn get_packet_dst<'a, P: MutableIpPacket<'a>>(packet: &'a mut [u8]) -> Result<IpAddr, Error> {
        let packet = P::new(packet).ok_or(Error::InvalidIpPacket)?;
        Ok(packet.get_destination().into())
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "StarcastTransport";

    type Err = Error;

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        let transport_socket = match &self.transport_socket {
            Some(transport_socket) => transport_socket.to_owned(),
            None => {
                PinnedSleep::new(self.exponential_backoff.get_backoff(), ()).await;
                let Ok(transport_socket) = open_transport_socket(
                    self.socket_pool.clone(),
                    self.meshnet_ip,
                    MULTICAST_TRANSPORT_PORT,
                )
                .await
                else {
                    telio_log_warn!(
                        "Starcast transport socket still not opened, will retry in {:?}",
                        self.exponential_backoff.get_backoff()
                    );
                    self.exponential_backoff.next_backoff();
                    return Self::next();
                };
                telio_log_info!("Starcast transport socket opened");
                self.transport_socket = Some(transport_socket.clone());
                self.exponential_backoff.reset();
                transport_socket
            }
        };
        let res = tokio::select! {
            Some(mut packet) = self.packet_chan.rx.recv() => {
                match self.has_multicast_dst(&mut packet) {
                    Ok(val) if val => self.handle_local_multicast_packet(packet).await,
                    Ok(_) => self.handle_mapped_unicast_packet(packet).await,
                    Err(e) => Err(e),
                }
            }
            Some((permit, Ok(bytes_read))) = wait_for_tx(&self.packet_chan.tx, transport_socket.recv(&mut self.recv_buffer)) => {
                #[allow(clippy::expect_used)]
                let packet = self.recv_buffer.get(..bytes_read).expect("We know bytes_read bytes should be in the buffer at this point").to_vec();
                self.handle_incoming_packet(packet, permit).await
            }
            else => {
                telio_log_warn!("MutlicastListener: no events to wait on");
                Ok(())
            },
        };
        if let Err(e) = res {
            telio_log_debug!("StarcastTransportError: {e}");
        }
        Self::next()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::time::timeout;

    use pnet_packet::{ipv4::Ipv4Packet, udp::UdpPacket};
    use telio_crypto::SecretKey;

    use super::*;
    use crate::{assert_src_dst_v4, utils::test_utils::*};

    const TEST_MAX_PACKET_SIZE: usize = 2048;

    struct Scaffold {
        task: Task<State>,
        transport_socket: Arc<UdpSocket>,
        channel: Chan<Vec<u8>>,
        peers: Vec<(PublicKey, UdpSocket, bool, bool)>,
    }

    impl Scaffold {
        async fn start() -> Self {
            let transport_socket = Arc::new(Self::bind_local_socket().await);
            // Peers with all the different possible meshnet configurations:
            let peers = vec![
                (
                    SecretKey::gen().public(),
                    Self::bind_local_socket().await,
                    true,
                    true,
                ),
                (
                    SecretKey::gen().public(),
                    Self::bind_local_socket().await,
                    false,
                    true,
                ),
                (
                    SecretKey::gen().public(),
                    Self::bind_local_socket().await,
                    true,
                    false,
                ),
                (
                    SecretKey::gen().public(),
                    Self::bind_local_socket().await,
                    false,
                    false,
                ),
            ];

            let (packet_chan, channel) = Chan::pipe();

            let task_peers = peers
                .iter()
                .map(|(pk, s, allow_multicast, peer_allows_multicast)| Peer {
                    public_key: *pk,
                    addr: s.local_addr().unwrap(),
                    allow_multicast: *allow_multicast,
                    peer_allows_multicast: *peer_allows_multicast,
                })
                .collect();
            let multicast_ips = vec![IpNet::new("224.0.0.0".parse().unwrap(), 4).unwrap()];
            let socket_pool = SocketPool::new(
                telio_sockets::NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    false,
                )
                .unwrap(),
            );

            let exponential_backoff_bounds = ExponentialBackoffBounds {
                initial: Duration::from_secs(2),
                maximal: Some(Duration::from_secs(120)),
            };

            let task = Task::start(State {
                transport_socket: Some(transport_socket.clone()),
                packet_chan,
                recv_buffer: vec![0; TEST_MAX_PACKET_SIZE],
                nat: StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR),
                peers: task_peers,
                exponential_backoff: ExponentialBackoff::new(exponential_backoff_bounds).unwrap(),
                multicast_ips,
                meshnet_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                socket_pool: Arc::new(socket_pool),
            });

            Self {
                task,
                transport_socket,
                channel,
                peers,
            }
        }

        async fn stop(self) {
            let _ = self.task.stop().await;
        }

        async fn bind_local_socket() -> UdpSocket {
            UdpSocket::bind(SocketAddr::new("127.0.0.1".parse().unwrap(), 0))
                .await
                .unwrap()
        }
    }

    #[tokio::test]
    async fn test_transport_socket_wait() {
        let (packet_chan, external_packet_chan) = Chan::pipe();
        // The `transport_socket` field get's abstracted away and becomes inaccessible from the `Scaffold`
        // struct, so just creating the `State` and running `.wait()` manually.
        let mut state = State {
            transport_socket: None,
            packet_chan,
            recv_buffer: vec![0; TEST_MAX_PACKET_SIZE],
            nat: StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR),
            peers: vec![],
            exponential_backoff: ExponentialBackoff::new(ExponentialBackoffBounds {
                initial: Duration::from_millis(10),
                maximal: Some(Duration::from_millis(120)),
            })
            .unwrap(),
            multicast_ips: vec![IpNet::new("224.0.0.0".parse().unwrap(), 4).unwrap()],
            // Using loopback IP here, because it's guaranteed to be available:
            meshnet_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            socket_pool: Arc::new(SocketPool::new(
                telio_sockets::NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    false,
                )
                .unwrap(),
            )),
        };

        // Dropping the packet channel here so the wait loop doesn't wait forever for a packet to arrive
        // since we're only interested in the `transport_socket` field anyway.
        std::mem::drop(external_packet_chan);
        state.wait().await;

        assert!(state.transport_socket.is_some());
    }

    #[tokio::test]
    async fn test_handle_local_multicast_packet() {
        let scaffold = Scaffold::start().await;

        let packet = make_udp_v4("127.0.0.1:12345", "224.0.0.251:5353");

        scaffold.channel.tx.send(packet.clone()).await.unwrap();

        for (_, socket, _, peer_allows_multicast) in &scaffold.peers {
            let mut buffer = vec![0; TEST_MAX_PACKET_SIZE];
            if *peer_allows_multicast {
                let bytes_read = socket.recv(&mut buffer).await.unwrap();
                buffer.truncate(bytes_read);
                assert_eq!(buffer, packet);
            } else {
                // Using timeout here, because otherwise the socket will just wait forever.
                let result =
                    tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buffer))
                        .await;
                assert!(result.is_err());
            }
        }

        scaffold.stop().await;
    }

    #[tokio::test]
    async fn test_handle_mapped_unicast_packet() {
        let mut scaffold = Scaffold::start().await;

        let peer1_addr = scaffold.peers[0].1.local_addr().unwrap();
        let transport_addr = scaffold.transport_socket.local_addr().unwrap();

        let packet = make_udp_v4(&peer1_addr.to_string(), &transport_addr.to_string());

        scaffold.peers[0]
            .1
            .send_to(&packet, transport_addr)
            .await
            .unwrap();

        let packet = scaffold.channel.rx.recv().await.unwrap();
        let ip_packet = Ipv4Packet::new(&packet).unwrap();
        let src_ip = ip_packet.get_source();
        assert_eq!(src_ip, IPV4_NAT_ADDR);

        let packet = make_udp_v4_reply(&packet);
        scaffold.channel.tx.send(packet.clone()).await.unwrap();

        tokio::task::yield_now().await;

        for (_, socket, _, _) in scaffold.peers.iter().skip(1) {
            let mut buffer = vec![0; TEST_MAX_PACKET_SIZE];
            assert!(socket.try_recv(&mut buffer).is_err());
        }

        let mut buffer = vec![0; TEST_MAX_PACKET_SIZE];
        timeout(
            Duration::from_secs(1),
            scaffold.peers[0].1.recv(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();

        assert_src_dst_v4!(buffer, transport_addr.to_string(), peer1_addr.to_string());

        scaffold.stop().await;
    }

    #[tokio::test]
    async fn test_handle_remote_packet() {
        let mut scaffold = Scaffold::start().await;

        let transport_addr = scaffold.transport_socket.local_addr().unwrap();

        let packet = make_udp_v4(
            &scaffold.peers[0].1.local_addr().unwrap().to_string(),
            &transport_addr.to_string(),
        );
        scaffold.peers[0]
            .1
            .send_to(&packet, transport_addr)
            .await
            .unwrap();

        let packet = scaffold.channel.rx.recv().await.unwrap();
        let ip_packet = Ipv4Packet::new(&packet).unwrap();
        assert_eq!(ip_packet.get_destination(), transport_addr.ip());
        assert_eq!(ip_packet.get_source(), IPV4_NAT_ADDR);

        let udp_packet = UdpPacket::new(&packet[IPV4_HEADER_MIN_LENGTH..]).unwrap();
        assert_eq!(udp_packet.get_destination(), transport_addr.port());

        scaffold.stop().await;
    }

    mod has_multicast_dst {
        use pnet_packet::ip::IpNextHeaderProtocols;
        use rstest::rstest;

        use super::*;

        async fn create_state_with_multicast_ips(multicast_ips: Vec<IpNet>) -> State {
            let socket_pool = SocketPool::new(
                telio_sockets::NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    false,
                )
                .unwrap(),
            );
            let exponential_backoff_bounds = ExponentialBackoffBounds {
                initial: Duration::from_secs(2),
                maximal: Some(Duration::from_secs(120)),
            };

            State {
                transport_socket: Some(Arc::new(
                    UdpSocket::bind(SocketAddr::new("127.0.0.1".parse().unwrap(), 0))
                        .await
                        .unwrap(),
                )),
                packet_chan: Chan::new(1),
                recv_buffer: Vec::new(),
                nat: StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR),
                peers: Vec::new(),
                exponential_backoff: ExponentialBackoff::new(exponential_backoff_bounds).unwrap(),
                multicast_ips,
                meshnet_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                socket_pool: Arc::new(socket_pool),
            }
        }

        async fn run_test(state: State, addr: &str, expected: bool) {
            let addr: IpAddr = addr.parse().unwrap();
            let mut packet = match addr {
                IpAddr::V4(addr) => {
                    let packet_len = IPV4_HEADER_MIN_LENGTH + UDP_HEADER_LENGTH;
                    let mut buffer = vec![0u8; packet_len];
                    set_ipv4(
                        &mut buffer,
                        IpNextHeaderProtocols::Udp,
                        packet_len,
                        "127.0.0.1".parse().unwrap(),
                        addr,
                    );
                    buffer
                }
                IpAddr::V6(addr) => {
                    let packet_len = IPV6_HEADER_LENGTH + UDP_HEADER_LENGTH;
                    let mut buffer = vec![0u8; packet_len];
                    set_ipv6(
                        &mut buffer,
                        IpNextHeaderProtocols::Udp,
                        packet_len,
                        "fc00::ff".parse().unwrap(),
                        addr,
                    );
                    buffer
                }
            };

            let actual = state.has_multicast_dst(&mut packet).unwrap();
            assert_eq!(actual, expected);
        }

        #[rstest]
        #[case("127.0.0.1", false)]
        #[case("1.1.1.1", false)]
        #[case("192.168.1.1", false)]
        #[case("224.0.0.251", false)]
        #[case("2606:4700:4700::1111", false)]
        #[case("fc00::1", false)]
        #[case("ff02::fb", false)]
        #[tokio::test]
        async fn test_no_multicast_networks(#[case] addr: &str, #[case] expected: bool) {
            let state = create_state_with_multicast_ips(Vec::new()).await;
            run_test(state, addr, expected).await;
        }

        #[rstest]
        #[case("127.0.0.1", false)]
        #[case("1.1.1.1", false)]
        #[case("192.168.1.1", false)]
        #[case("224.0.0.251", true)]
        #[case("2606:4700:4700::1111", false)]
        #[case("fc00::1", false)]
        #[case("ff02::fb", false)]
        #[tokio::test]
        async fn test_one_ipv4_multicast_network(#[case] addr: &str, #[case] expected: bool) {
            let multicast_ips = vec![IpNet::new("224.0.0.0".parse().unwrap(), 4).unwrap()];
            let state = create_state_with_multicast_ips(multicast_ips).await;
            run_test(state, addr, expected).await;
        }

        #[rstest]
        #[case("127.0.0.1", false)]
        #[case("1.1.1.1", false)]
        #[case("192.168.1.1", false)]
        #[case("224.0.0.251", false)]
        #[case("2606:4700:4700::1111", false)]
        #[case("fc00::1", false)]
        #[case("ff02::1", true)]
        #[tokio::test]
        async fn test_one_ipv6_multicast_network(#[case] addr: &str, #[case] expected: bool) {
            let multicast_ips = vec![IpNet::new("ff00::".parse().unwrap(), 12).unwrap()];
            let state = create_state_with_multicast_ips(multicast_ips).await;
            run_test(state, addr, expected).await;
        }

        #[rstest]
        #[case("127.0.0.1", false)]
        #[case("1.1.1.1", false)]
        #[case("192.168.1.1", false)]
        #[case("224.0.0.251", true)]
        #[case("2606:4700:4700::1111", false)]
        #[case("fc00::1", false)]
        #[case("ff02::1", true)]
        #[tokio::test]
        async fn test_one_ipv4_and_one_ipv6_multicast_network(
            #[case] addr: &str,
            #[case] expected: bool,
        ) {
            let multicast_ips = vec![
                IpNet::new("224.0.0.0".parse().unwrap(), 4).unwrap(),
                IpNet::new("ff00::".parse().unwrap(), 12).unwrap(),
            ];
            let state = create_state_with_multicast_ips(multicast_ips).await;
            run_test(state, addr, expected).await;
        }
    }
}
