use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::time::Instant;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use telio_sockets::SocketPool;
use telio_task::io::Chan;
use telio_task::task_exec;
use telio_task::{Runtime, RuntimeExt, Task, WaitResponse};
use telio_utils::{
    exponential_backoff::{
        Backoff, Error as ExponentialBackoffError, ExponentialBackoff, ExponentialBackoffBounds,
    },
    PinnedSleep,
};
use telio_utils::{telio_log_debug, telio_log_warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::{SendError, TrySendError};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tokio::time::{Duration as TokioDuration, Instant as TokioInstant};

/// Port is randomly chosen
/// perf % 65535 = 46750
#[cfg(not(test))]
const PERFORMANCE_TRANSPORT_PORT: u16 = 46750;
const MAX_PACKET_SIZE: usize = 1500;
const TEST_DURATION: Duration = Duration::new(10, 0);
const PACKET_TYPE_OFFSET: usize = 0;
const IP_ADDR_OFFSET: usize = 1;
const PKT_LOSS_OFFSET: usize = 1;
const PKT_LOSS_DATA_SIZE: usize = std::mem::size_of::<f32>();
const THROUGHPUT_OFFSET: usize = PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE;
const THROUGHPUT_DATA_SIZE: usize = std::mem::size_of::<u32>();
const SIZE_OF_IP_ADDR: usize = 4;
/// Performance test specific errors
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
    /// Task execution failed
    #[error(transparent)]
    TaskError(#[from] telio_task::ExecError),
    /// Unable to send on channel error
    #[error(transparent)]
    ChanError(#[from] TrySendError<SocketAddr>),
    /// Transport socket isn't open yet, probably because tunnel interface hadn't been configured yet.
    #[error("Transport socket isn't open yet")]
    TransportSocketNotOpen,
    /// Exponential backoff error
    #[error(transparent)]
    ExponentialBackoffError(#[from] ExponentialBackoffError),
    /// Command channel error
    #[error(transparent)]
    CmdChannelError(#[from] SendError<std::net::SocketAddr>),
    /// Slice error
    #[error(transparent)]
    SliceError(#[from] std::array::TryFromSliceError),
    /// IO Error
    #[error(transparent)]
    IoError(#[from] std::io::Error),
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
            1 => PacketType::Start,
            2 => PacketType::Test,
            3 => PacketType::End,
            4 => PacketType::Result,
            5 => PacketType::Ack,
            _ => PacketType::Invalid,
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum HandlerState {
    Start,
    Test,
}

/// The throughput transport component
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
        packet_chan: Chan<SocketAddr>,
        #[cfg(test)] port: u16,
        #[cfg(test)] notify: Option<Arc<Notify>>,
    ) -> Result<Self, Error> {
        let exponential_backoff = ExponentialBackoff::new(ExponentialBackoffBounds {
            initial: Duration::from_secs(2),
            maximal: Some(Duration::from_secs(120)),
        })?;
        // If transport socket cannot be opened right now (for example, if meshnet had been started before
        // the tunnel interface's IP had been configured), transport socket cannot be opened at start and
        // will be opened later.
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
                    "Will try to open transport socket again in {:?}",
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
                socket_pool,
                meshnet_ip,
                exponential_backoff,
                handler_state: Arc::new(RwLock::new(HandlerState::Start)),
                pkts_recvd: 0,
                duration: Instant::now(),
                #[cfg(test)]
                notify,
            }),
        })
    }

    /// Start the throughput test with given endpoint
    pub async fn start_test(&self, ip_addr: IpAddr) -> Result<(), Error> {
        let endpoint = SocketAddr::new(
            ip_addr,
            #[cfg(not(test))]
            PERFORMANCE_TRANSPORT_PORT,
            #[cfg(test)]
            54321,
        );
        task_exec!(&self.task, async move |state| {
            state.start_test(endpoint).await
        })
        .await?;
        Ok(())
    }

    /// Stop the throughput component
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
            telio_log_warn!("Failed to bind socket: {:?}", e);
            Error::SocketBindError(e.to_string())
        })?;

    Ok(Arc::new(transport_socket))
}

struct State {
    transport_socket: Option<Arc<UdpSocket>>,
    cmd_chan: Chan<SocketAddr>,
    recv_buffer: Vec<u8>,
    socket_pool: Arc<SocketPool>,
    meshnet_ip: IpAddr,
    exponential_backoff: ExponentialBackoff,
    handler_state: Arc<RwLock<HandlerState>>,
    pkts_recvd: u64,
    duration: Instant,
    #[cfg(test)]
    notify: Option<Arc<Notify>>,
}

impl State {
    /// Separate method for handling starcast packets received on the transport socket from other
    /// meshnet nodes and dropping those packets if multicast isn't allowed for those nodes.
    async fn handle_incoming_packet(&mut self) -> Result<(), Error> {
        match (*self.recv_buffer.first().unwrap_or(&0)).into() {
            PacketType::Start => {
                // Reset bytes received and ack sent by reciever
                telio_log_debug!("Recieved throughput-test request");
                self.pkts_recvd = 0;
                self.send_ack().await?;
                self.duration = Instant::now();
            }
            PacketType::Ack => {
                let mut state = self.handler_state.write().await;
                if *state == HandlerState::Start {
                    telio_log_debug!("Changing throughput-test state to HandlerState::Test");
                    // Move the state to Test for the handler to start
                    // sending the data packets
                    *state = HandlerState::Test;
                }
            }
            PacketType::End => self.send_results().await,
            PacketType::Result => {
                telio_log_debug!("Test results recieved");
                let bytes: [u8; PKT_LOSS_DATA_SIZE] = self.recv_buffer
                    [PKT_LOSS_OFFSET..PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE]
                    .try_into()?;
                let pkt_loss = f32::from_be_bytes(bytes);

                let bytes: [u8; THROUGHPUT_DATA_SIZE] = self.recv_buffer
                    [THROUGHPUT_OFFSET..THROUGHPUT_OFFSET + THROUGHPUT_DATA_SIZE]
                    .try_into()?;
                let throughput = u32::from_be_bytes(bytes);
                // This is to notify the test and throughput measurement
                // has been completed successfully
                #[cfg(test)]
                if let Some(n) = self.notify.as_ref() {
                    n.notify_one()
                };
                // This print is intentional for now. Can be removed later.
                println!("Throughput {throughput} MiB/s Packet loss - {pkt_loss} %");
            }
            PacketType::Test => {
                self.pkts_recvd += 1;
            }
            PacketType::Invalid => telio_log_warn!("Something gone wrong"),
        }

        Ok(())
    }

    async fn send_ack(&mut self) -> Result<(), Error> {
        let send_buffer = vec![PacketType::Ack as u8; 1];
        let ip_addr = IpAddr::V4(Ipv4Addr::new(
            self.recv_buffer[IP_ADDR_OFFSET],
            self.recv_buffer[IP_ADDR_OFFSET + 1],
            self.recv_buffer[IP_ADDR_OFFSET + 2],
            self.recv_buffer[IP_ADDR_OFFSET + 3],
        ));
        let endpoint = SocketAddr::new(
            ip_addr,
            #[cfg(not(test))]
            PERFORMANCE_TRANSPORT_PORT,
            #[cfg(test)]
            12345,
        );

        telio_log_debug!("Sending ACK to {:?}", endpoint);
        if let Err(e) = self
            .transport_socket
            .as_ref()
            .ok_or(Error::TransportSocketNotOpen)?
            .send_to(&send_buffer, endpoint)
            .await
        {
            telio_log_warn!("Unable to send ack {e}")
        }
        Ok(())
    }

    async fn send_results(&mut self) {
        let duration = self.duration.elapsed();
        let mut send_buffer = vec![0u8; 1 + PKT_LOSS_DATA_SIZE + THROUGHPUT_DATA_SIZE];
        send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Result as u8);

        // Parse # of sent packets
        let pkts_sent: [u8; std::mem::size_of::<u64>()] =
            self.recv_buffer[5..13].try_into().unwrap();
        let pkts_sent = u64::from_be_bytes(pkts_sent);

        println!("pkts sent {pkts_sent}");
        println!("pkts recvd {}", self.pkts_recvd);
        println!("Time taken {:?}", duration);
        // Calculate packet loss
        let pkt_loss = (1_f32 - (self.pkts_recvd as f32 / pkts_sent as f32)) * 100_f32;
        send_buffer[PKT_LOSS_OFFSET..PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE]
            .copy_from_slice(&pkt_loss.to_be_bytes());

        // Calculate throughput
        // Bytes should be data + wg_offset + ip header + udp header
        let throughput = (((self.pkts_recvd * (1350 + 32 + 20 + 8) * 8) as f64)
            / duration.as_secs_f64()) as u32
            / 1_000_000;
        send_buffer[THROUGHPUT_OFFSET..THROUGHPUT_OFFSET + THROUGHPUT_DATA_SIZE]
            .copy_from_slice(&throughput.to_be_bytes());

        // Get endpoint of the client to respond to
        let ip_addr = IpAddr::V4(Ipv4Addr::new(
            self.recv_buffer[IP_ADDR_OFFSET],
            self.recv_buffer[IP_ADDR_OFFSET + 1],
            self.recv_buffer[IP_ADDR_OFFSET + 2],
            self.recv_buffer[IP_ADDR_OFFSET + 3],
        ));
        let endpoint = SocketAddr::new(
            ip_addr,
            #[cfg(not(test))]
            PERFORMANCE_TRANSPORT_PORT,
            #[cfg(test)]
            12345,
        );
        if self
            .transport_socket
            .as_ref()
            .unwrap()
            .send_to(&send_buffer, endpoint)
            .await
            .is_err()
        {
            telio_log_warn!("Unable to send ack")
        }
    }

    /// Start the throughput test with given endpoint
    async fn start_test(&self, endpoint: SocketAddr) -> Result<(), Error> {
        self.cmd_chan.tx.try_send(endpoint)?;
        Ok(())
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Throughput Test";

    type Err = Error;

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        let transport_socket = match &self.transport_socket {
            Some(transport_socket) => transport_socket.to_owned(),
            None => {
                telio_log_debug!("no socket yet");
                PinnedSleep::new(self.exponential_backoff.get_backoff(), ()).await;
                let Ok(transport_socket) = open_transport_socket(
                    self.socket_pool.clone(),
                    self.meshnet_ip,
                    #[cfg(not(test))]
                    PERFORMANCE_TRANSPORT_PORT,
                    #[cfg(test)]
                    12345,
                )
                .await
                else {
                    telio_log_warn!(
                        "Throughput transport socket still not opened, will retry in {:?}",
                        self.exponential_backoff.get_backoff()
                    );
                    self.exponential_backoff.next_backoff();
                    return Self::next();
                };
                telio_log_debug!("Throughput transport socket opened");
                self.transport_socket = Some(transport_socket.clone());
                self.exponential_backoff.reset();
                transport_socket
            }
        };

        let res = tokio::select! {
            Ok(_) = transport_socket.recv_from(&mut self.recv_buffer) => {
                self.handle_incoming_packet().await
            },
            Some(endpoint) = self.cmd_chan.rx.recv() => {
                {
                    let mut state = self.handler_state.write().await;
                    if *state == HandlerState::Test {
                        *state = HandlerState::Start;
                    }
                }
                tokio::spawn(throughput_test_handler(endpoint, transport_socket.clone(), self.handler_state.clone()));
                Ok(())
            },
            else => {
                telio_log_warn!("ThroughputListener: no events to wait on");
                Ok(())
            },
        };
        if let Err(e) = res {
            telio_log_debug!("ThrougputTestError: {e}");
        }
        Self::next()
    }
}

fn ip_to_bytes(ip: &IpAddr) -> [u8; 4] {
    match ip {
        IpAddr::V4(addr) => addr.octets(),
        IpAddr::V6(_) => [0, 0, 0, 0],
    }
}

async fn throughput_test_handler(
    endpoint: SocketAddr,
    transport_socket: Arc<UdpSocket>,
    handler_state: Arc<RwLock<HandlerState>>,
) -> Result<(), Error> {
    let mut send_buffer = vec![0u8; 1400];
    let mut exponential_backoff = ExponentialBackoff::new(ExponentialBackoffBounds {
        initial: Duration::from_secs(1),
        maximal: Some(Duration::from_secs(30)),
    })?;
    loop {
        telio_log_debug!("Restart");
        let state = { *{ handler_state.read().await } };
        match state {
            HandlerState::Start => {
                // Inform the peer that test is starting
                telio_log_debug!("Sending start for throughput test to {:?}", endpoint);
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Start as u8);
                send_buffer[IP_ADDR_OFFSET..IP_ADDR_OFFSET + SIZE_OF_IP_ADDR]
                    .copy_from_slice(&ip_to_bytes(&transport_socket.local_addr()?.ip()));
                if let Err(e) = transport_socket
                    .send_to(&send_buffer[..SIZE_OF_IP_ADDR + 1], endpoint)
                    .await
                {
                    telio_log_warn!(
                        "Unable to send start throughput to {:?} due to {e}",
                        endpoint
                    );
                };
                // Exp backoff to either recieve response
                // or send Start again.
                PinnedSleep::new(exponential_backoff.get_backoff(), ()).await;
                exponential_backoff.next_backoff();
                if exponential_backoff.get_backoff() == Duration::from_secs(30) {
                    telio_log_warn!("Unable to connect to peer");
                    break;
                }
                continue;
            }
            HandlerState::Test => {
                let mut total_pkts: u64 = 0;
                telio_log_debug!("Starting test");
                let start = Instant::now();
                // Start sending packets to the peer
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Test as u8);
                let delay = TokioDuration::from_nanos(1);
                while start.elapsed() < TEST_DURATION {
                    match transport_socket.try_send_to(&send_buffer, endpoint) {
                        Ok(_) => {
                            // Count the number of packets, each packet contains
                            // the same amount of bytes
                            total_pkts += 1_u64;
                        }
                        Err(e) => {
                            telio_log_warn!("Unable to send data: {e}");
                        }
                    }
                    // Prefer to get max value from system
                    let mut next_send_time = TokioInstant::now();
                    next_send_time += delay;
                    tokio::time::sleep_until(next_send_time).await;
                }
                telio_log_debug!("Test finished. Collecting results");
                // Tell the other peer test has ended
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::End as u8);
                send_buffer[IP_ADDR_OFFSET..IP_ADDR_OFFSET + SIZE_OF_IP_ADDR]
                    .copy_from_slice(&ip_to_bytes(&transport_socket.local_addr()?.ip()));
                send_buffer[5..13].copy_from_slice(&total_pkts.to_be_bytes());
                if let Err(e) = transport_socket.send_to(&send_buffer[..13], endpoint).await {
                    telio_log_warn!("Unable to send test end: {:?}", e);
                }
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use telio_task::io::Chan;
    use tokio::{sync::Notify, time::timeout};

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
        let client_cmd_chan = Chan::new(5);
        let test_ended = Arc::new(Notify::new());

        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let client = Throughput::start(
            ip_addr,
            socket_pool.clone(),
            client_cmd_chan,
            12345,
            Some(test_ended.clone()),
        )
        .await;

        let server_cmd_chan = Chan::new(5);
        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let server =
            Throughput::start(ip_addr, socket_pool.clone(), server_cmd_chan, 54321, None).await;

        assert!(client.as_ref().unwrap().start_test(ip_addr).await.is_ok());
        assert!(timeout(TEST_DURATION * 4, test_ended.notified())
            .await
            .is_ok());
    }
}
