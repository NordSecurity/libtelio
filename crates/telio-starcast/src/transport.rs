use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};

use crate::{
    nat::{self, Nat, StarcastNat},
    utils::{DualIpAddr, MutableIpPacket},
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
}

/// A peer in the meshnet
#[derive(Copy, Clone)]
pub struct Peer {
    /// The IP address of the peer
    pub addr: SocketAddr,
    /// The public key of the peer
    pub public_key: PublicKey,
}

/// Config for transport component
/// Contains fields that can change at runtime
pub enum Config {
    /// Simple transport config, has IP of peer but not port
    Simple(Vec<(PublicKey, IpAddr)>),
    /// Full transport config, has full socket address of peer
    Full(Vec<(PublicKey, SocketAddr)>),
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
    /// * vpeer_ip - The IP address of the virtual starcast peer
    /// * meshnet_ip - the meshnet IP of the node on which this component is currently running
    /// * socket_pool - To create the transport socket
    /// * packet_chan - A channel to send packets to and receive packets from the virtual peer component
    /// * multicast_ips - IPs that native multicast packets can be sent to, e.g. 224.0.0.0/4
    pub async fn start(
        vpeer_ip: DualIpAddr,
        meshnet_ip: IpAddr,
        socket_pool: Arc<SocketPool>,
        packet_chan: Chan<Vec<u8>>,
        multicast_ips: Vec<IpNet>,
    ) -> Result<Self, Error> {
        let transport_socket = socket_pool
            .new_internal_udp(SocketAddr::new(meshnet_ip, MULTICAST_TRANSPORT_PORT), None)
            .await
            .map_err(|e| {
                telio_log_error!("Failed to bind multicast socket: {:?}", e);
                Error::SocketBindError(e.to_string())
            })?;
        let transport_socket = Arc::new(transport_socket);

        Ok(Self {
            task: Task::start(State {
                transport_socket,
                packet_chan,
                multicast_ips,
                recv_buffer: vec![0; MAX_PACKET_SIZE],
                nat: StarcastNat::new(vpeer_ip.ipv4, vpeer_ip.ipv6),
                peers: Vec::new(),
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

struct State {
    transport_socket: Arc<UdpSocket>,
    packet_chan: Chan<Vec<u8>>,
    recv_buffer: Vec<u8>,
    nat: StarcastNat,
    peers: Vec<Peer>,
    multicast_ips: Vec<IpNet>,
}

impl State {
    fn configure(&mut self, config: Config) {
        self.peers = match config {
            Config::Simple(peers) => peers
                .into_iter()
                .map(|(public_key, addr)| Peer {
                    public_key,
                    addr: SocketAddr::new(addr, MULTICAST_TRANSPORT_PORT),
                })
                .collect(),
            Config::Full(peers) => peers
                .into_iter()
                .map(|(public_key, addr)| Peer { public_key, addr })
                .collect(),
        };
    }

    async fn handle_local_multicast_packet(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        let failed_peers = join_all(self.peers.iter().map(|peer| {
            self.transport_socket
                .send_to(&packet, peer.addr)
                .map_err(|_| peer.public_key)
        }))
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
            .send_to(&packet, peer_ip)
            .await
            .map(|_| ())
            .map_err(|_| Error::SocketSendError)
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
        let res = tokio::select! {
            Some(mut packet) = self.packet_chan.rx.recv() => {
                match self.has_multicast_dst(&mut packet) {
                    Ok(val) if val => self.handle_local_multicast_packet(packet).await,
                    Ok(_) => self.handle_mapped_unicast_packet(packet).await,
                    Err(e) => Err(e),
                }
            }
            Some((permit, Ok(bytes_read))) = wait_for_tx(&self.packet_chan.tx, self.transport_socket.recv(&mut self.recv_buffer)) => {
                #[allow(clippy::expect_used)]
                let mut packet = self.recv_buffer.get(..bytes_read).expect("We know bytes_read bytes should be in the buffer at this point").to_vec();
                self.nat.translate_incoming(&mut packet)
                    .map_err(Error::NatError)
                    .map(|_| {
                        let _ = permit.send(packet);
                    })
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
    use std::net::SocketAddrV4;

    use pnet_packet::{ipv4::Ipv4Packet, udp::UdpPacket};
    use telio_crypto::SecretKey;

    use super::*;
    use crate::{assert_src_dst_v4, utils::test_utils::*};

    const TEST_MAX_PACKET_SIZE: usize = 2048;

    struct Scaffold {
        task: Task<State>,
        transport_socket: Arc<UdpSocket>,
        channel: Chan<Vec<u8>>,
        peers: Vec<(PublicKey, UdpSocket)>,
    }

    impl Scaffold {
        async fn start() -> Self {
            let transport_socket = Arc::new(Self::bind_local_socket().await);
            let mut peers = Vec::with_capacity(3);
            for _ in 0..3 {
                peers.push((SecretKey::gen().public(), Self::bind_local_socket().await));
            }
            let (packet_chan, channel) = Chan::pipe();

            let task_peers = peers
                .iter()
                .map(|(pk, s)| Peer {
                    public_key: *pk,
                    addr: s.local_addr().unwrap(),
                })
                .collect();
            let multicast_ips = vec![IpNet::new("224.0.0.0".parse().unwrap(), 4).unwrap()];

            let task = Task::start(State {
                transport_socket: transport_socket.clone(),
                packet_chan,
                recv_buffer: vec![0; TEST_MAX_PACKET_SIZE],
                nat: StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR),
                peers: task_peers,
                multicast_ips,
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
    async fn test_handle_local_multicast_packet() {
        let scaffold = Scaffold::start().await;

        let packet = make_udp_v4("127.0.0.1:12345", "224.0.0.251:5353");

        scaffold.channel.tx.send(packet.clone()).await.unwrap();

        for (_, socket) in &scaffold.peers {
            let mut buffer = vec![0; TEST_MAX_PACKET_SIZE];
            let bytes_read = socket.recv(&mut buffer).await.unwrap();
            buffer.truncate(bytes_read);
            assert_eq!(buffer, packet);
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

        for (_, socket) in scaffold.peers.iter().skip(1) {
            let mut buffer = vec![0; TEST_MAX_PACKET_SIZE];
            assert!(socket.try_recv(&mut buffer).is_err());
        }

        let mut buffer = vec![0; TEST_MAX_PACKET_SIZE];
        scaffold.peers[0].1.try_recv(&mut buffer).unwrap();

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
            State {
                transport_socket: Arc::new(
                    UdpSocket::bind(SocketAddr::new("127.0.0.1".parse().unwrap(), 0))
                        .await
                        .unwrap(),
                ),
                packet_chan: Chan::new(1),
                recv_buffer: Vec::new(),
                nat: StarcastNat::new(IPV4_NAT_ADDR, IPV6_NAT_ADDR),
                peers: Vec::new(),
                multicast_ips,
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
