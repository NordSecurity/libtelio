use std::net::Ipv4Addr;
use std::time::Instant;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use pnet_packet::udp::Udp;
use tokio::net::UdpSocket;

use telio_sockets::SocketPool;
use telio_task::{
    io::{
        chan::{Rx, Tx},
        Chan,
    },
    Runtime, RuntimeExt, Task, WaitResponse,
};
use telio_utils::{
    exponential_backoff::{
        Backoff, Error as ExponentialBackoffError, ExponentialBackoff, ExponentialBackoffBounds,
    },
    PinnedSleep,
};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};

use telio_starcast::utils::MutableIpPacket;
use tokio::sync::{Mutex, RwLock};

/// Port is randomly chosen
/// PERF % 65535
const PERFORMANCE_TRANSPORT_PORT: u16 = 46750;
const MAX_PACKET_SIZE: usize = u16::MAX as usize;
const TEST_DURATION: Duration = Duration::new(2, 0);

/// Starcast transport-specific errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Could not bind to socket
    #[error("Could not bind to socket")]
    SocketBindError(String),
    /// Invalid IP Packet
    #[error("Invalid IP Packet")]
    InvalidIpPacket,
    /// Failed to send packet over socket
    #[error("Failed to send packet over socket")]
    SocketSendError,
    /// Failed to send packet over channel
    #[error("Failed to send packet over channel")]
    ChannelSendError,
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

enum PacketType {
    Invalid,
    Start,
    Test,
    End,
    Result,
    Ack,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            _ => PacketType::Invalid,
            1 => PacketType::Start,
            2 => PacketType::Test,
            3 => PacketType::End,
            4 => PacketType::Result,
            5 => PacketType::Ack,
        }
    }
}

#[derive(PartialEq)]
enum HandlerState {
    Start,
    Test,
    End,
}

/// The starcast transport component
/// Manages the task that does the actual transport
pub struct Throughput {
    task: Task<State>,
}

impl Throughput {
    /// Starts the transport component
    ///
    /// Parameters:
    /// * meshnet_ip - The meshnet IP of the node on which this component is currently running
    /// * socket_pool - To create the transport socket
    /// * packet_chan - A channel to send packets to and receive packets from the virtual peer component
    pub async fn start(
        meshnet_ip: IpAddr,
        socket_pool: Arc<SocketPool>,
        packet_chan: Rx<SocketAddr>,
        #[cfg(test)] port: u16,
    ) -> Result<Self, Error> {
        let exponential_backoff = ExponentialBackoff::new(ExponentialBackoffBounds {
            initial: Duration::from_secs(2),
            maximal: Some(Duration::from_secs(120)),
        })?;
        // If transport socket cannot be opened right now (for example, if meshnet had been started before
        // the tunnel interface's IP had been configured), transport socket cannot be opened at start and
        // will be opened later. In the mean time the channel between the starcast peer and transport
        // component will buffer the multicast messages until the transport socket will be opened. If the
        // buffers fill up, the messages will be ignored.
        let transport_socket = match open_transport_socket(
            socket_pool.clone(),
            meshnet_ip,
            #[cfg(not(test))]
            PERFORMANCE_TRANSPORT_PORT,
            #[cfg(test)]
            port,
        )
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
                cmd_chan: packet_chan,
                recv_buffer: vec![0; MAX_PACKET_SIZE],
                send_buffer: vec![0; 1350],
                socket_pool,
                meshnet_ip,
                exponential_backoff,
                handler_state: Arc::new(RwLock::new(HandlerState::Start)),
                #[cfg(test)]
                port,
            }),
        })
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
    cmd_chan: Rx<SocketAddr>,
    recv_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
    socket_pool: Arc<SocketPool>,
    meshnet_ip: IpAddr,
    exponential_backoff: ExponentialBackoff,
    handler_state: Arc<RwLock<HandlerState>>,
    #[cfg(test)]
    port: u16,
}

impl State {
    /// Separate method for handling starcast packets received on the transport socket from other
    /// meshnet nodes and dropping those packets if multicast isn't allowed for those nodes.
    async fn handle_incoming_packet(&mut self, len: usize) -> Result<(), Error> {
        // println!("Got packet of len {len}");
        match (*self.recv_buffer.first().unwrap_or(&0)).into() {
            PacketType::Start => self.send_ack().await,
            PacketType::Ack => {
                let mut state = self.handler_state.write().await;
                if *state == HandlerState::Start {
                    *state = HandlerState::Test;
                }
            }
            PacketType::End => todo!(),
            PacketType::Result => todo!(),
            PacketType::Test => todo!(),
            PacketType::Invalid => todo!(),
        }

        Ok(())
    }

    async fn send_ack(&mut self) {
        let mut send_buffer = vec![0u8; 1350];
        send_buffer.insert(0, PacketType::Ack as u8);
        let ip_addr = IpAddr::V4(Ipv4Addr::new(
            self.recv_buffer[1],
            self.recv_buffer[2],
            self.recv_buffer[3],
            self.recv_buffer[4],
        ));
        let endpoint = SocketAddr::new(
            ip_addr,
            #[cfg(not(test))]
            PERFORMANCE_TRANSPORT_PORT,
            #[cfg(test)]
            self.port,
        );
        if self
            .transport_socket
            .unwrap()
            .send_to(&send_buffer, endpoint)
            .await
            .is_ok()
        {
            return;
        };
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Throughput";

    type Err = Error;

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        let transport_socket = match &self.transport_socket {
            Some(transport_socket) => transport_socket.to_owned(),
            None => {
                PinnedSleep::new(self.exponential_backoff.get_backoff(), ()).await;
                let Ok(transport_socket) = open_transport_socket(
                    self.socket_pool.clone(),
                    self.meshnet_ip,
                    PERFORMANCE_TRANSPORT_PORT,
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
            Ok(len) = transport_socket.recv(&mut self.recv_buffer) => {
                self.handle_incoming_packet(len).await
            },
            Some(endpoint) = self.cmd_chan.recv() => {
                tokio::spawn(throughput_test_handler(endpoint, transport_socket.clone(), self.handler_state.clone()));
                Ok(())
            },
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

fn ip_to_bytes(ip: &IpAddr) -> [u8; 4] {
    match ip {
        IpAddr::V4(addr) => addr.octets(),
        IpAddr::V6(addr) => [0, 0, 0, 0],
    }
}

async fn throughput_test_handler(
    endpoint: SocketAddr,
    transport_socket: Arc<UdpSocket>,
    handler_state: Arc<RwLock<HandlerState>>,
) {
    let mut send_buffer = vec![0u8; 1350];
    loop {
        match *handler_state.read().await {
            HandlerState::Start => {
                // Inform the peer that test is starting
                send_buffer.insert(0, PacketType::Start as u8);
                send_buffer
                    .copy_from_slice(&ip_to_bytes(&transport_socket.peer_addr().unwrap().ip()));
                if transport_socket
                    .send_to(&send_buffer, endpoint)
                    .await
                    .is_ok()
                {
                    continue;
                };
            }
            HandlerState::Test => {
                let mut total_bytes = 0;
                let start = Instant::now();
                // Start sending packets to the peer
                send_buffer.insert(0, PacketType::Test as u8);
                while start.elapsed() < TEST_DURATION {
                    match transport_socket.send_to(&send_buffer, endpoint).await {
                        Ok(len) => total_bytes += len,
                        Err(e) => {
                            telio_log_warn!("Unable to send data: {e}");
                        }
                    }
                }

                // Tell the other peer test has ended
                send_buffer.insert(0, PacketType::End as u8);
                transport_socket.send_to(&send_buffer, endpoint).await;
                telio_log_debug!("Total {total_bytes} bytes sent");
            }
            HandlerState::End => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_throughput() {
        let socket_pool = Arc::new(SocketPool::new(
            telio_sockets::NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));
        let client_cmd_chan = Chan::new(10);

        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let client =
            Throughput::start(ip_addr, socket_pool.clone(), client_cmd_chan.rx, 12345).await;

        let server_cmd_chan = Chan::new(10);
        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let endpoint = SocketAddr::new(ip_addr, 54321);
        let server =
            Throughput::start(ip_addr, socket_pool.clone(), server_cmd_chan.rx, 54321).await;

        assert!(client_cmd_chan.tx.send(endpoint).await.is_ok());
        tokio::time::sleep(TEST_DURATION).await;
    }
}
