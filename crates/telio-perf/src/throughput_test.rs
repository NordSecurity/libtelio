use std::convert::TryInto;
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
use telio_utils::{telio_log_debug, telio_log_info, telio_log_trace, telio_log_warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::RwLock;
use tokio::time::Duration as TokioDuration;

/// Port is randomly chosen
/// perf % 65535 = 46750
pub const PERFORMANCE_TRANSPORT_PORT: u16 = 46750;
const MAX_PACKET_SIZE: usize = 1500;
#[cfg(not(test))]
const TEST_DURATION: Duration = Duration::new(10, 0);
#[cfg(test)]
const TEST_DURATION: Duration = Duration::new(2, 0);
const PACKET_TYPE_OFFSET: usize = 0;
const PKT_LOSS_OFFSET: usize = 1;
const PKT_LOSS_DATA_SIZE: usize = std::mem::size_of::<f32>();
const THROUGHPUT_OFFSET: usize = PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE;
const THROUGHPUT_DATA_SIZE: usize = std::mem::size_of::<u32>();
const BUFFER_LEN: usize = 1350;
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
    /// Buffer error
    #[error("Invalid index buffer")]
    InvalidIndex,
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

#[derive(PartialEq, Clone, Copy, Debug)]
enum HandlerState {
    Start,
    Test,
    Results,
    End,
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
            0,
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
            }),
        })
    }

    /// Start the throughput test with given endpoint
    pub async fn start_test(&self, ip_addr: IpAddr, port: u16) -> Result<(), Error> {
        let endpoint = SocketAddr::new(ip_addr, port);
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

    #[cfg(test)]
    async fn get_port(&self) -> Result<u16, Error> {
        let port = task_exec!(&self.task, async move |state| state.get_port().await).await?;
        Ok(port)
    }

    #[cfg(test)]
    async fn get_handler_state(&self) -> Result<HandlerState, Error> {
        let handler_state = task_exec!(&self.task, async move |state| state
            .get_handler_state()
            .await)
        .await?;
        Ok(handler_state)
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
}

impl State {
    /// Separate method for handling starcast packets received on the transport socket from other
    /// meshnet nodes and dropping those packets if multicast isn't allowed for those nodes.
    async fn handle_incoming_packet(&mut self, socket: SocketAddr) -> Result<(), Error> {
        match (*self.recv_buffer.first().unwrap_or(&0)).into() {
            PacketType::Start => {
                // Reset bytes received and ack sent by reciever
                telio_log_trace!("Recieved throughput-test request");
                self.pkts_recvd = 0;
                self.send_ack(socket).await?;
                self.duration = Instant::now();
            }
            PacketType::Ack => {
                let mut state = self.handler_state.write().await;
                if *state == HandlerState::Start {
                    // Move the state to Test for the handler to start
                    // sending the data packets
                    *state = HandlerState::Test;
                }
            }
            PacketType::End => self.send_results(socket).await?,
            PacketType::Result => {
                {
                    let mut state = self.handler_state.write().await;
                    if *state == HandlerState::Results {
                        // Move the state to Test for the handler to start
                        // sending the data packets
                        *state = HandlerState::End;
                    }
                }
                let bytes: [u8; PKT_LOSS_DATA_SIZE] = self
                    .recv_buffer
                    .get(PKT_LOSS_OFFSET..PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE)
                    .ok_or(Error::InvalidIndex)?
                    .try_into()?;
                let pkt_loss = f32::from_be_bytes(bytes);

                let bytes: [u8; THROUGHPUT_DATA_SIZE] = self
                    .recv_buffer
                    .get(THROUGHPUT_OFFSET..THROUGHPUT_OFFSET + THROUGHPUT_DATA_SIZE)
                    .ok_or(Error::InvalidIndex)?
                    .try_into()?;
                let throughput = u32::from_be_bytes(bytes);
                telio_log_info!("Throughput {throughput} MiB/s Packet loss - {pkt_loss} %");
            }
            PacketType::Test => {
                self.pkts_recvd += 1;
            }
            PacketType::Invalid => telio_log_warn!("Something gone wrong"),
        }

        Ok(())
    }

    async fn send_ack(&mut self, endpoint: SocketAddr) -> Result<(), Error> {
        let send_buffer = vec![PacketType::Ack as u8; 1];

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

    async fn send_results(&mut self, endpoint: SocketAddr) -> Result<(), Error> {
        let duration = self.duration.elapsed();
        let mut send_buffer = vec![0u8; 1 + PKT_LOSS_DATA_SIZE + THROUGHPUT_DATA_SIZE];
        send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Result as u8);

        // Parse # of sent packets
        let pkts_sent: [u8; std::mem::size_of::<u64>()] = self
            .recv_buffer
            .get(1..9)
            .ok_or(Error::InvalidIndex)?
            .try_into()?;
        let pkts_sent = u64::from_be_bytes(pkts_sent);

        // Calculate packet loss
        let pkt_loss = (1_f32 - (self.pkts_recvd as f32 / pkts_sent as f32)) * 100_f32;
        send_buffer
            .get_mut(PKT_LOSS_OFFSET..PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE)
            .ok_or(Error::InvalidIndex)?
            .copy_from_slice(&pkt_loss.to_be_bytes());

        // Calculate throughput
        // Bytes should be data + wg_offset + ip header + udp header
        let throughput = (((self.pkts_recvd * (BUFFER_LEN as u64 + 32 + 20 + 8) * 8) as f64)
            / duration.as_secs_f64()) as u32
            / 1_000_000;

        send_buffer
            .get_mut(THROUGHPUT_OFFSET..THROUGHPUT_OFFSET + THROUGHPUT_DATA_SIZE)
            .ok_or(Error::InvalidIndex)?
            .copy_from_slice(&throughput.to_be_bytes());

        if self
            .transport_socket
            .as_ref()
            .ok_or(Error::TransportSocketNotOpen)?
            .send_to(&send_buffer, endpoint)
            .await
            .is_err()
        {
            telio_log_warn!("Unable to send ack")
        }
        Ok(())
    }

    /// Start the throughput test with given endpoint
    async fn start_test(&self, endpoint: SocketAddr) -> Result<(), Error> {
        self.cmd_chan.tx.try_send(endpoint)?;
        Ok(())
    }

    #[cfg(test)]
    /// Start the throughput test with given endpoint
    async fn get_port(&self) -> Result<u16, Error> {
        let port = self
            .transport_socket
            .as_ref()
            .ok_or(Error::TransportSocketNotOpen)?
            .local_addr()?
            .port();
        Ok(port)
    }

    #[cfg(test)]
    async fn get_handler_state(&self) -> Result<HandlerState, Error> {
        let state = self.handler_state.read().await;
        Ok(*state)
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
                telio_log_trace!("no socket yet");
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
            Ok((_, recv_ep)) = transport_socket.recv_from(&mut self.recv_buffer) => {
                self.handle_incoming_packet(recv_ep).await
            },
            Some(endpoint) = self.cmd_chan.rx.recv() => {
                {
                    let mut state = self.handler_state.write().await;
                    if *state == HandlerState::End {
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

async fn throughput_test_handler(
    endpoint: SocketAddr,
    transport_socket: Arc<UdpSocket>,
    handler_state: Arc<RwLock<HandlerState>>,
) -> Result<(), Error> {
    let mut send_buffer = vec![0u8; BUFFER_LEN];
    let mut exponential_backoff = ExponentialBackoff::new(ExponentialBackoffBounds {
        initial: Duration::from_secs(1),
        maximal: Some(Duration::from_secs(30)),
    })?;
    let mut total_pkts: u64 = 0;
    let mut retries = 0;
    const MAX_RETRIES: usize = 10;
    loop {
        let state = { *{ handler_state.read().await } };
        match state {
            HandlerState::Start => {
                // Inform the peer that test is starting
                telio_log_debug!("Sending start for throughput test to {:?}", endpoint);
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Start as u8);
                if let Err(e) = transport_socket
                    .send_to(send_buffer.get(..1).ok_or(Error::InvalidIndex)?, endpoint)
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
                total_pkts = 0;
            }
            HandlerState::Test => {
                telio_log_trace!("Starting test");
                let start = Instant::now();
                // Start sending packets to the peer
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Test as u8);
                let delay = TokioDuration::from_millis(1);
                while start.elapsed() < TEST_DURATION {
                    for _ in 0..1_000 {
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
                    }
                    // Sleep a bit, in order to not overwhelm the system
                    tokio::time::sleep(delay).await;
                }

                {
                    let mut handler = handler_state.write().await;
                    *handler = HandlerState::Results;
                }
            }
            HandlerState::Results => {
                // Tell the other peer test has ended
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::End as u8);
                send_buffer
                    .get_mut(1..9)
                    .ok_or(Error::InvalidIndex)?
                    .copy_from_slice(&total_pkts.to_be_bytes());
                if let Err(e) = transport_socket
                    .send_to(send_buffer.get(..13).ok_or(Error::InvalidIndex)?, endpoint)
                    .await
                {
                    telio_log_warn!("Unable to send test end: {:?}", e);
                }
                // Exp backoff to either recieve response
                // or send Start again.
                retries += 1;
                PinnedSleep::new(Duration::from_secs(1), ()).await;
                if retries == MAX_RETRIES {
                    telio_log_warn!("Unable to get test results");
                    break;
                }
            }
            HandlerState::End => {
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

    async fn wait_for_results(expected_state: HandlerState, client: Result<Throughput, Error>) {
        let test_ended = Arc::new(Notify::new());
        // Spawn a background task to monitor results
        let notify_clone = test_ended.clone();
        tokio::spawn(async move {
            loop {
                let state = client.as_ref().unwrap().get_handler_state().await.unwrap();
                if expected_state == state {
                    notify_clone.notify_one();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        assert!(timeout(TEST_DURATION * 4, test_ended.notified())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_delayed_start() {
        let socket_pool = Arc::new(SocketPool::new(
            telio_sockets::NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));
        let client_cmd_chan = Chan::new(5);

        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let client = Throughput::start(ip_addr, socket_pool.clone(), client_cmd_chan).await;

        // Simulating "start" packet drop
        tokio::time::sleep(Duration::from_secs(4)).await;

        let server_cmd_chan = Chan::new(5);
        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let server = Throughput::start(ip_addr, socket_pool.clone(), server_cmd_chan).await;
        let port = server.as_ref().unwrap().get_port().await.unwrap();

        assert!(client
            .as_ref()
            .unwrap()
            .start_test(ip_addr, port)
            .await
            .is_ok());

        wait_for_results(HandlerState::Test, client).await;
    }

    #[tokio::test]
    async fn test_starting_test() {
        let socket_pool = Arc::new(SocketPool::new(
            telio_sockets::NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));
        let client_cmd_chan = Chan::new(5);

        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let client = Throughput::start(ip_addr, socket_pool.clone(), client_cmd_chan).await;
        let server_cmd_chan = Chan::new(5);
        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let server = Throughput::start(ip_addr, socket_pool.clone(), server_cmd_chan).await;
        let port = server.as_ref().unwrap().get_port().await.unwrap();

        assert!(client
            .as_ref()
            .unwrap()
            .start_test(ip_addr, port)
            .await
            .is_ok());

        // State changed to test -> Ack recieved from server -> client
        wait_for_results(HandlerState::Test, client).await;
    }

    #[tokio::test]
    async fn test_end_to_end() {
        let socket_pool = Arc::new(SocketPool::new(
            telio_sockets::NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));
        let client_cmd_chan = Chan::new(5);

        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let client = Throughput::start(ip_addr, socket_pool.clone(), client_cmd_chan).await;
        let server_cmd_chan = Chan::new(5);
        let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let server = Throughput::start(ip_addr, socket_pool.clone(), server_cmd_chan).await;
        let port = server.as_ref().unwrap().get_port().await.unwrap();

        assert!(client
            .as_ref()
            .unwrap()
            .start_test(ip_addr, port)
            .await
            .is_ok());

        // Handler state -> End. Test results sent server -> client
        wait_for_results(HandlerState::End, client).await;
    }
}
