use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use futures::{future::join_all, TryFutureExt};
use ipnetwork::IpNetwork;
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
    utils::DualIpAddr,
};

#[cfg(feature = "test-util")]
const MULTICAST_TRANSPORT_PORT: u16 = 0;
#[cfg(not(feature = "test-util"))]
const MULTICAST_TRANSPORT_PORT: u16 = 13569;
const MAX_PACKET_SIZE: usize = u16::MAX as usize;

#[derive(Debug, thiserror::Error)]
/// Starcast transport-specific errors
pub enum Error {
    // Could not bind to socket
    #[error("Could not bind to socket")]
    SocketBindError(String),
    /// Invalid IP Packet
    #[error("Invalid IP Packet")]
    InvalidIpPacket,
    /// Failed to fan out local multicast packet to some peers
    #[error("Failed to fan out local multicast packet to peers {0:?}")]
    FanoutFailed(Vec<PublicKey>),
    /// Failed to nat packet
    #[error("Failed to nat packet: {0:?}")]
    NatError(nat::Error),
    /// Failed to send packet over socket
    #[error("Failed to send packet over socket")]
    SocketSendError,
    /// Failed to send packet over channel
    #[error("Failed to send packet over channel")]
    ChannelSendError,
    /// Task execution failed
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
}

/// A peer in the meshnet
pub struct Peer {
    /// The IP address of the peer
    pub addr: IpAddr,
    /// The public key of the peer
    pub public_key: PublicKey,
}

/// Config for transport component
/// Contains fields that can change at runtime
pub struct Config {
    pub peers: Vec<Peer>,
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
    /// * packet_chan - A channel to send packets to and receive packets from the transport component
    /// multicast_ips - IPs that native multicast packets can be sent to, e.g. 224.0.0.0/4
    pub async fn start(
        vpeer_ip: DualIpAddr,
        meshnet_ip: IpAddr,
        socket_pool: Arc<SocketPool>,
        packet_chan: Chan<Vec<u8>>,
        multicast_ips: Vec<IpNetwork>,
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
    multicast_ips: Vec<IpNetwork>,
}

impl State {
    fn configure(&mut self, config: Config) {
        self.peers = config.peers;
    }

    async fn handle_local_multicast_packet(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        let failed_peers = join_all(self.peers.iter().map(|peer| {
            self.transport_socket
                .send_to(
                    &packet,
                    SocketAddr::new(peer.addr, MULTICAST_TRANSPORT_PORT),
                )
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
        self.transport_socket
            .send_to(&packet, SocketAddr::new(peer_ip, MULTICAST_TRANSPORT_PORT))
            .await
            .map(|_| ())
            .map_err(|_| Error::SocketSendError)
    }

    async fn handle_remote_packet(&mut self, packet: &mut [u8]) -> Result<(), Error> {
        self.nat
            .translate_incoming(packet)
            .map_err(Error::NatError)?;
        Ok(())
    }

    fn has_multicast_dst(&self, packet: &mut [u8]) -> Result<bool, Error> {
        let dst = if let Some(packet) = MutableIpv4Packet::new(packet) {
            IpAddr::V4(packet.get_destination())
        } else if let Some(packet) = MutableIpv6Packet::new(packet) {
            IpAddr::V6(packet.get_destination())
        } else {
            return Err(Error::InvalidIpPacket);
        };
        Ok(self
            .multicast_ips
            .iter()
            .any(|network| network.contains(dst)))
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
                let mut packet = self.recv_buffer.get(..bytes_read).expect("We know bytes_read bytes should be in the buffer at this point").to_vec();
                self.handle_remote_packet(&mut packet).await.and_then(|_| {
                    let _ = permit.send(packet);
                    Ok(())
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
