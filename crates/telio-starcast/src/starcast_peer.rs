//! File containing code for the starcast peer.

use async_trait::async_trait;
use ipnet::IpNet;
use neptun::noise::{Tunn, TunnResult};
use std::{net::SocketAddr, time::Duration};
use telio_crypto::{PublicKey, SecretKey};
use telio_proto::DataMsg;
use telio_task::{
    io::{wait_for_tx, Chan},
    task_exec, Runtime, RuntimeExt, Task, WaitResponse,
};
use telio_utils::interval;
use telio_utils::{telio_log_error, telio_log_warn};
use telio_wg::uapi::Peer;
use tokio::{net::UdpSocket, sync::mpsc::error::SendTimeoutError, time::Interval};
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret};

use telio_model::constants::{
    IPV4_MULTICAST_NETWORK, IPV4_STARCAST_NETWORK, IPV6_MULTICAST_NETWORK, IPV6_STARCAST_NETWORK,
};

/// Constant for maximum packet size.
const MAX_PACKET: usize = 2048;

#[derive(Debug, thiserror::Error)]
/// Custom `UdpProxy` error
pub enum Error {
    /// `StarcastPeer` Not Configured Error
    #[error("Starcast peer is not configured")]
    NotConfigured,
    /// `StarcastPeer` `IoError`
    #[error("Starcast peer IoError")]
    IoError(#[from] std::io::Error),
    /// Task execution failed
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
    /// IP network failed
    #[error("Failed to parse IP network")]
    IpNetworkError(#[from] ipnet::AddrParseError),
    /// Send failed
    #[error(transparent)]
    Send(#[from] SendTimeoutError<(PublicKey, DataMsg)>),
    /// Tunnel creation failed
    #[error("Tunnel creation failed {0}")]
    TunnNewFail(&'static str),
}

/// The actual starcast peer containing the task which runs the wait loop for this whole component.
pub struct StarcastPeer {
    /// starcast virtual peer task for Telio runtime.
    task: Task<State>,
}

/// Starcast virtual peer configuration.
pub struct Config {
    /// Public key of the peer with which the starcast virtual peer shall communicate.
    pub public_key: PublicKey,
    /// Port number through which the virtual starcast peer shall communicate with WireGuard.
    pub wg_port: u16,
}

impl StarcastPeer {
    /// Create and start a new unconfigured starcast virtual peer. Note that it must first be configured to be functional.
    /// A port is assigned dynamically for it's socket and also a public key which may be obtained by the application
    /// by using the `get_peer()` method.
    ///
    /// # Arguments
    ///
    /// * `channel` - Channel for communicating decapsulated packets to and from the multicaster.
    ///
    /// # Returns
    ///
    /// A new starcast virtual peer.
    pub async fn start(channel: Chan<Vec<u8>>, ipv6: bool) -> Result<Self, Error> {
        // Port 0 means the OS will dynamically allocate port.
        const TIMER_UPDATE_PERIOD: Duration = Duration::from_millis(250);
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let wg_timer_tick_interval = interval(TIMER_UPDATE_PERIOD);
        let secret_key = SecretKey::gen();

        let mut allowed_ips = vec![IPV4_MULTICAST_NETWORK.into(), IPV4_STARCAST_NETWORK.into()];

        if ipv6 {
            allowed_ips.push(IPV6_MULTICAST_NETWORK.into());
            allowed_ips.push(IPV6_STARCAST_NETWORK.into());
        }

        Ok(StarcastPeer {
            task: Task::start(State {
                secret_key,
                channel,
                socket,
                tunnel: None,
                wg_sock_addr: None,
                wg_timer_tick_interval,
                packets_present_in_tunnel: false,
                sending_buffer: Box::new([0u8; MAX_PACKET]),
                receiving_buffer: Box::new([0u8; MAX_PACKET]),
                allowed_ips,
            }),
        })
    }

    // TODO (LLT-5385) figure out the implications and possible side effects of reconfiguring the starcast peer mid operation.
    /// Configure (or reconfigure) the starcast peer.
    ///
    /// # Arguments
    ///
    /// * `config` - A struct holding the configuration of the starcast peer.
    ///
    /// # Returns
    ///
    /// A result indicating wether the configuration was successful.
    pub async fn configure(&self, config: Config) -> Result<(), Error> {
        task_exec!(&self.task, async move |state| {
            Ok(state.configure(config).await)
        })
        .await??;

        Ok(())
    }

    /// Get the starcast virtual peer which can be treated as a regular peer by telio.
    ///
    /// # Returns
    ///
    /// A starcast peer.
    pub async fn get_peer(&self) -> Result<Peer, Error> {
        task_exec!(&self.task, async move |state| Ok(state.get_peer())).await?
    }

    /// Stop the starcast virtual peer.
    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

/// State for the starcast peer runtime where all the "working" members are stored and operated on.
struct State {
    /// Secret key of the starcast virtual peer.
    secret_key: SecretKey,
    /// Allowed IPs of the starcast virtual peer.
    allowed_ips: Vec<IpNet>,
    /// Interval at which the tunnel timers will be updated.
    wg_timer_tick_interval: Interval,
    /// Channel for sending decapsulated packets to the multicaster and receiving packets for encapsulation from it.
    channel: Chan<Vec<u8>>,
    /// Local socket for sending and receiving packets from WireGuard.
    socket: UdpSocket,
    /// WireGuard socket address to communicate encapsulated packets to and from Libtelio.
    wg_sock_addr: Option<SocketAddr>,
    /// WireGuard encryption tunnel for encapsulation/decapsulation of packets.
    tunnel: Option<Tunn>,
    /// Flag indicating that there are packets in the encryption tunnel internal buffer that need to be processed
    /// before new packets can be received from the socket and decapsulated.
    packets_present_in_tunnel: bool,
    /// Buffer for outbound packets.
    sending_buffer: Box<[u8; MAX_PACKET]>,
    /// Buffer for inbound packets.
    receiving_buffer: Box<[u8; MAX_PACKET]>,
}

impl State {
    async fn configure(&mut self, config: Config) -> Result<(), Error> {
        // Because this is a virtual peer, all communication happens on loopback.
        self.wg_sock_addr = Some(SocketAddr::from(([127, 0, 0, 1], config.wg_port)));
        // No point in handling old handshakes if the public key and addr have changed.
        self.packets_present_in_tunnel = false;

        self.tunnel = Some(
            Tunn::new(
                StaticSecret::from(self.secret_key.clone().into_bytes()),
                PublicKeyDalek::from(config.public_key.0),
                None,
                None,
                0,
                None,
            )
            .map_err(Error::TunnNewFail)?,
        );

        Ok(())
    }

    fn get_peer(&self) -> Result<Peer, Error> {
        let static_secret = &StaticSecret::from(self.secret_key.clone().into_bytes());

        Ok(Peer {
            public_key: PublicKey(PublicKeyDalek::from(static_secret).to_bytes()),
            endpoint: Some(self.socket.local_addr()?),
            allowed_ips: self.allowed_ips.to_owned(),
            ..Default::default()
        })
    }
}

#[async_trait]
impl Runtime for State {
    /// Task's name.
    const NAME: &'static str = "Starcast";

    /// Error that may occur in [Task]
    type Err = ();

    /// Wait loop for asynchronously handling events for the component.
    ///
    /// # Returns
    ///
    /// A response for the runtime indicating when to run again.
    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        match self {
            State {
                channel: Chan { rx, tx },
                tunnel: Some(peer),
                wg_sock_addr: Some(ref wg_sock_addr),
                socket,
                ..
            } => {
                tokio::select! {
                    // Periodic timer updates for managing handshakes.
                    _ = self.wg_timer_tick_interval.tick() => {
                        match peer.update_timers(&mut *self.sending_buffer) {
                            TunnResult::Done => (),
                            TunnResult::WriteToNetwork(packet) => {
                                if let Err(e) = socket.send_to(packet, wg_sock_addr).await {
                                    telio_log_error!("[Starcast] Update Tunn timers failed to send to socket: {:?}", e);
                                }
                            },
                            TunnResult::Err(e) => {
                                telio_log_error!("[Starcast] Failed to update Tunn timers: {:?}", e);
                            }
                            unexpected_result => telio_log_warn!("[Starcast] Update Tunn timers returned unexpected result: {:?}", unexpected_result),
                        }
                    },
                    // Outbound packets
                    Some(ip_packet) = rx.recv() => {
                        self.sending_buffer[16..16 + ip_packet.len()]
                        .copy_from_slice(&ip_packet);
                        match peer.encapsulate(&mut *self.sending_buffer, ip_packet.len()) {
                            TunnResult::Done => (),
                            TunnResult::Err(e) => {
                                telio_log_error!("[Starcast] Failed to send encapsulate packet: {:?}", e);
                            },
                            TunnResult::WriteToNetwork(packet) => {
                                if let Err(e) = socket.send_to(packet, wg_sock_addr).await {
                                    telio_log_error!("[Starcast] Failed to send encapsulated packet to socket: {:?}", e);
                                }
                            },
                            unexpected_result => {
                                telio_log_warn!("[Starcast] Encapsulate packet returned unexpected result: {:?}", unexpected_result);
                            },
                        }
                    },
                    // Here we're handling the deferred decapsulation of handshake packets to avoid deadlocking.
                    _ = socket.writable(), if self.packets_present_in_tunnel => {
                        match peer.decapsulate(None, &mut [], 0, &mut *self.sending_buffer) {
                            // Note that the handshake packet here is a slice pointing to the sending buffer.
                            TunnResult::WriteToNetwork(handshake_packet) => {
                                if let Err(e) = socket.send_to(handshake_packet, wg_sock_addr).await {
                                    telio_log_error!("[Starcast] Failed to send handshake packet : {:?}", e);
                                };
                            },
                            TunnResult::Done => {
                                self.packets_present_in_tunnel = false;
                            },
                            TunnResult::Err(e) => {
                                telio_log_error!("[Starcast] Failed to decapsulate handshake packet: {:?}", e);
                                self.packets_present_in_tunnel = false;
                            },
                            unexpected_state => {
                                telio_log_warn!("[Starcast] Unexpected state while sending handshake packets {:?}", unexpected_state);
                                self.packets_present_in_tunnel = false;
                            },
                        }
                    },
                    // Inbound packets, if there are no handshake packets in the buffer to process.
                    Some((permit, recv_res)) =
                    wait_for_tx(tx, socket.recv(&mut *self.receiving_buffer)), if !self.packets_present_in_tunnel => {
                        match recv_res {
                            Ok(bytes_read) => {
                                match peer.decapsulate(
                                    None,
                                    &mut *self.receiving_buffer,
                                    bytes_read,
                                    &mut *self.sending_buffer,
                                ) {
                                    // Handshake packets. See the comment above Tunn::decapsulate() for this case.
                                    TunnResult::WriteToNetwork(packet) => {
                                        if let Err(e) = socket.send_to(packet, wg_sock_addr).await {
                                            telio_log_error!("[Starcast] Failed to send handshake packet: {:?}", e);
                                        }
                                        // To prevent deadlock while decapsulating handshake packets, deferring to later iteration
                                        // so that other vital actions (like timer update) could be handled in between.
                                        self.packets_present_in_tunnel = true;
                                    },
                                    // Starcast packets
                                    TunnResult::WriteToTunnelV4(packet, _)
                                    | TunnResult::WriteToTunnelV6(packet, _) => {
                                        permit.send(packet.to_vec());
                                    },
                                    TunnResult::Done => (),
                                    TunnResult::Err(e) => {
                                        telio_log_error!("[Starcast] Decapsulate error {:?}", e);
                                    },
                                }
                            },
                            Err(e) => telio_log_error!("[Starcast] Decapsulate error {:?}", e),
                        }
                    },
                };
                Self::next()
            }
            _ => Self::sleep_forever().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::make_udp_v4;

    // This test connects two virtual peers by their sockets and tests if a packet
    // can make it through between them.
    #[tokio::test]
    async fn test_two_virtual_peers_intercommunication() {
        let (chan_a, chan_a_internal) = Chan::pipe();
        let (mut chan_b, chan_b_internal) = Chan::pipe();

        let starcast_vpeer_a = StarcastPeer::start(chan_a_internal, false).await.unwrap();
        let starcast_vpeer_b = StarcastPeer::start(chan_b_internal, false).await.unwrap();

        let a_peer = starcast_vpeer_a.get_peer().await.unwrap();
        let b_peer = starcast_vpeer_b.get_peer().await.unwrap();

        let peer_a_addr = a_peer.endpoint.unwrap();
        let peer_b_addr = b_peer.endpoint.unwrap();

        let config_a = Config {
            public_key: b_peer.public_key,
            wg_port: peer_b_addr.port(),
        };
        let config_b = Config {
            public_key: a_peer.public_key,
            wg_port: peer_a_addr.port(),
        };

        let udp_packet = make_udp_v4(&peer_a_addr.to_string(), &peer_b_addr.to_string());

        starcast_vpeer_a.configure(config_a).await.unwrap();
        starcast_vpeer_b.configure(config_b).await.unwrap();

        chan_a.tx.send(udp_packet.clone()).await.unwrap();
        let received_bytes = chan_b.rx.recv().await.unwrap();

        assert_eq!(udp_packet, received_bytes)
    }
}
