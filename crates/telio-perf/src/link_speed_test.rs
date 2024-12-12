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
pub const SPEEDTEST_PORT: u16 = 46750;
#[cfg(not(test))]
const TEST_DURATION: Duration = Duration::new(10, 0);
#[cfg(test)]
const TEST_DURATION: Duration = Duration::new(2, 0);
const PACKET_TYPE_OFFSET: usize = 0;
const PKT_LOSS_OFFSET: usize = 1;
const PKT_LOSS_DATA_SIZE: usize = std::mem::size_of::<f32>();
const LINK_SPEED_OFFSET: usize = PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE;
const LINK_SPEED_DATA_SIZE: usize = std::mem::size_of::<u32>();
const RESULT_DATA_OFFSET: usize = 1;
const RESULT_DATA_SIZE: usize = std::mem::size_of::<u64>();
const BUFFER_LEN: usize = 1352;
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
    InvalidBufferIndex,
    /// Buffer error
    #[error("Unable to complete test")]
    TestTimeout,
    /// Buffer error
    #[error("A test is already in progress. Cannot run another test")]
    TestAlreadyInProgress,
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
    Init,
    Start,
    Test,
    Results,
    End,
}

/// The link speed test component
/// Manages the task that does the actual transport
pub struct Speedtest {
    task: Task<State>,
}

impl Speedtest {
    /// Starts the link speed test component
    ///
    /// Parameters:
    /// * meshnet_ip - The meshnet IP of the node on which this component is currently running
    /// * socket_pool - To create the transport socket
    pub async fn start(meshnet_ip: IpAddr, socket_pool: Arc<SocketPool>) -> Result<Self, Error> {
        let exponential_backoff = ExponentialBackoff::new(ExponentialBackoffBounds {
            initial: Duration::from_secs(2),
            maximal: Some(Duration::from_secs(120)),
        })?;

        Ok(Self {
            task: Task::start(State {
                transport_socket: None,
                cmd_chan: Chan::new(5),
                recv_buffer: vec![0; BUFFER_LEN],
                socket_pool,
                meshnet_ip,
                exponential_backoff,
                handler_state: Arc::new(RwLock::new(HandlerState::Init)),
                pkts_recvd: 0,
                test_duration: Instant::now(),
                test_results_chan: Chan::new(5),
            }),
        })
    }

    /// Start the link speed test test with given endpoint
    pub async fn start_test(&self, ip_addr: IpAddr, port: u16) -> Result<Duration, Error> {
        let endpoint = SocketAddr::new(ip_addr, port);
        task_exec!(&self.task, async move |state| {
            state.start_test(endpoint).await
        })
        .await?;
        Ok(TEST_DURATION)
    }

    /// Start the link speed test test with given endpoint
    pub async fn try_fetch_results(&self) -> Result<i32, Error> {
        let speed = task_exec!(&self.task, async move |state| {
            state.try_fetch_results().await
        })
        .await?;
        Ok(speed)
    }

    /// Stop the link speed test component
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
    test_duration: Instant,
    test_results_chan: Chan<u32>,
}

impl State {
    /// Separate method for handling throughput packets received on the transport socket from other
    /// meshnet nodes
    async fn handle_incoming_packet(&mut self, socket: SocketAddr) -> Result<(), Error> {
        match (*self.recv_buffer.first().unwrap_or(&0)).into() {
            PacketType::Start => {
                // Reset bytes received and ack sent by reciever
                telio_log_trace!("Recieved link speed test request");
                self.pkts_recvd = 0;
                self.send_ack(socket).await?;
                self.test_duration = Instant::now();
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
                    .ok_or(Error::InvalidBufferIndex)?
                    .try_into()?;
                let pkt_loss = f32::from_be_bytes(bytes);

                let bytes: [u8; LINK_SPEED_DATA_SIZE] = self
                    .recv_buffer
                    .get(LINK_SPEED_OFFSET..LINK_SPEED_OFFSET + LINK_SPEED_DATA_SIZE)
                    .ok_or(Error::InvalidBufferIndex)?
                    .try_into()?;
                let link_speed = u32::from_be_bytes(bytes);
                #[allow(mpsc_blocking_send)]
                let _ = self.test_results_chan.tx.send(link_speed).await;
                telio_log_info!("Throughput {link_speed} MiB/s Packet loss - {pkt_loss} %");
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

    async fn calculate_results(
        pkts_recvd: u64,
        duration: Duration,
        pkts_sent: u64,
    ) -> Result<(f32, u32), Error> {
        // Calculate packet loss
        let pkt_loss = (1_f32 - (pkts_recvd as f32 / pkts_sent as f32)) * 100_f32;
        // Calculate link speed
        // Bytes should be data + wg_header + ip header + udp header
        let link_speed =
            ((pkts_recvd * (BUFFER_LEN as u64 + 32 + 20 + 8) * 8) / duration.as_secs()) / 1_000_000;

        Ok((pkt_loss, link_speed as u32))
    }

    async fn send_results(&mut self, endpoint: SocketAddr) -> Result<(), Error> {
        let duration = self.test_duration.elapsed();
        // Parse # of sent packets
        let pkts_sent: [u8; RESULT_DATA_SIZE] = self
            .recv_buffer
            .get(RESULT_DATA_OFFSET..RESULT_DATA_OFFSET + RESULT_DATA_SIZE)
            .ok_or(Error::InvalidBufferIndex)?
            .try_into()?;
        let pkts_sent = u64::from_be_bytes(pkts_sent);

        let (pkt_loss, link_speed) =
            State::calculate_results(self.pkts_recvd, duration, pkts_sent).await?;

        let mut send_buffer = vec![0u8; 1 + PKT_LOSS_DATA_SIZE + LINK_SPEED_DATA_SIZE];
        send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Result as u8);

        send_buffer
            .get_mut(PKT_LOSS_OFFSET..PKT_LOSS_OFFSET + PKT_LOSS_DATA_SIZE)
            .ok_or(Error::InvalidBufferIndex)?
            .copy_from_slice(&pkt_loss.to_be_bytes());

        send_buffer
            .get_mut(LINK_SPEED_OFFSET..LINK_SPEED_OFFSET + LINK_SPEED_DATA_SIZE)
            .ok_or(Error::InvalidBufferIndex)?
            .copy_from_slice(&link_speed.to_be_bytes());

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

    /// Start the link speed test with given endpoint
    async fn start_test(&self, endpoint: SocketAddr) -> Result<(), Error> {
        // Here add a check that if a test is going on, it returns as error!
        let state = self.handler_state.read().await;
        if *state != HandlerState::Init {
            return Err(Error::TestAlreadyInProgress);
        }
        self.cmd_chan.tx.try_send(endpoint)?;
        Ok(())
    }

    /// Start the link speed test with given endpoint
    async fn try_fetch_results(&mut self) -> Result<i32, Error> {
        match self.test_results_chan.rx.try_recv() {
            Ok(s) => Ok(s as i32),
            Err(_) => {
                if *self.handler_state.read().await == HandlerState::Init {
                    return Err(Error::TestTimeout);
                }
                // -1 denotes result isn't ready yet
                Ok(-1)
            }
        }
    }

    #[cfg(test)]
    /// Start the link speed test with given endpoint
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
    const NAME: &'static str = "Speedtest";

    type Err = Error;

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        let transport_socket = match &self.transport_socket {
            Some(transport_socket) => transport_socket.to_owned(),
            None => {
                let Ok(transport_socket) = open_transport_socket(
                    self.socket_pool.clone(),
                    self.meshnet_ip,
                    #[cfg(not(test))]
                    SPEEDTEST_PORT,
                    #[cfg(test)]
                    0,
                )
                .await
                else {
                    telio_log_warn!(
                        "link speed test transport socket still not opened, will retry in {:?}",
                        self.exponential_backoff.get_backoff()
                    );
                    PinnedSleep::new(self.exponential_backoff.get_backoff(), ()).await;
                    self.exponential_backoff.next_backoff();
                    return Self::next();
                };
                telio_log_debug!("link speed test transport socket opened");
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
                tokio::spawn(link_speed_test_handler(endpoint, transport_socket.clone(), self.handler_state.clone()));
                Ok(())
            },
            else => {
                telio_log_warn!("SpeedtestListener: no events to wait on");
                Ok(())
            },
        };
        if let Err(e) = res {
            telio_log_debug!("ThrougputTestError: {e}");
        }
        Self::next()
    }
}

async fn link_speed_test_handler(
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
    #[cfg(not(test))]
    const MAX_RETRIES: usize = 10;
    #[cfg(test)]
    const MAX_RETRIES: usize = 3;
    loop {
        let state = { *{ handler_state.read().await } };
        match state {
            HandlerState::Init => {
                let mut handler = handler_state.write().await;
                *handler = HandlerState::Start;
            }
            HandlerState::Start => {
                // Inform the peer that test is starting
                telio_log_debug!("Sending start for link speed test to {:?}", endpoint);
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Start as u8);
                if let Err(e) = transport_socket
                    .send_to(
                        send_buffer.get(..1).ok_or(Error::InvalidBufferIndex)?,
                        endpoint,
                    )
                    .await
                {
                    telio_log_warn!(
                        "Unable to send start link speed test to {:?} due to {e}",
                        endpoint
                    );
                };
                // Exp backoff to either recieve response
                // or send Start again.
                PinnedSleep::new(exponential_backoff.get_backoff(), ()).await;
                exponential_backoff.next_backoff();
                if exponential_backoff.get_backoff() == Duration::from_secs(30) {
                    telio_log_warn!("Unable to connect to peer");
                    {
                        let mut handler = handler_state.write().await;
                        *handler = HandlerState::End;
                    }
                }
                total_pkts = 0;
            }
            HandlerState::Test => {
                telio_log_trace!("Starting test");
                let start = Instant::now();
                // Start sending packets to the peer
                send_buffer.insert(PACKET_TYPE_OFFSET, PacketType::Test as u8);

                let delay = TokioDuration::from_micros(500);
                while start.elapsed() < TEST_DURATION {
                    for _ in 0..700 {
                        match transport_socket.try_send_to(&send_buffer, endpoint) {
                            Ok(_) => {
                                // Count the number of packets, each packet contains
                                // the same amount of bytes
                                total_pkts += 1_u64;
                            }
                            Err(e) => {
                                // Dont log WouldBlock errors, as they are expected
                                // and would spam the logs alot
                                if e.kind() != std::io::ErrorKind::WouldBlock {
                                    telio_log_warn!("Unable to send data: {e}");
                                }
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
                    .get_mut(RESULT_DATA_OFFSET..RESULT_DATA_OFFSET + RESULT_DATA_SIZE)
                    .ok_or(Error::InvalidBufferIndex)?
                    .copy_from_slice(&total_pkts.to_be_bytes());
                if let Err(e) = transport_socket
                    .send_to(
                        send_buffer
                            .get(..RESULT_DATA_SIZE + 1)
                            .ok_or(Error::InvalidBufferIndex)?,
                        endpoint,
                    )
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
                    {
                        let mut handler = handler_state.write().await;
                        *handler = HandlerState::End;
                    }
                }
            }
            HandlerState::End => {
                {
                    let mut handler = handler_state.write().await;
                    *handler = HandlerState::Init;
                }
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use tokio::{sync::Notify, time::timeout};

    use super::*;
    use std::net::Ipv4Addr;

    const IP_ADDR: std::net::IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    async fn wait_for_results(expected_state: HandlerState, client: Speedtest) {
        let test_ended = Arc::new(Notify::new());
        // Spawn a background task to monitor results
        let notify_clone = test_ended.clone();
        tokio::spawn(async move {
            loop {
                let state = client.get_handler_state().await.unwrap();
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
        let client = setup_peer(socket_pool.clone()).await;

        // Simulating "start" packet drop
        tokio::time::sleep(Duration::from_secs(4)).await;

        let server = setup_peer(socket_pool.clone()).await;
        let port = server.get_port().await.unwrap();

        assert!(client.start_test(IP_ADDR, port).await.is_ok());

        wait_for_results(HandlerState::Test, client).await;
    }

    async fn setup_peer(socket_pool: Arc<SocketPool>) -> Speedtest {
        let sp = Speedtest::start(IP_ADDR, socket_pool).await.unwrap();
        // Give it a little delay for task to start and socket to open
        tokio::time::sleep(Duration::from_millis(1)).await;
        sp
    }

    async fn setup_peers() -> (Speedtest, Speedtest, u16) {
        let socket_pool = Arc::new(SocketPool::new(
            telio_sockets::NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));

        let client = setup_peer(socket_pool.clone()).await;

        let server = setup_peer(socket_pool.clone()).await;

        let port = server.get_port().await.unwrap();
        (client, server, port)
    }

    #[tokio::test]
    async fn test_starting_test() {
        let (client, _server, port) = setup_peers().await;
        assert!(client.start_test(IP_ADDR, port).await.is_ok());

        // State changed to test -> Ack recieved from server -> client
        wait_for_results(HandlerState::Test, client).await;
    }

    #[tokio::test]
    async fn test_end_to_end() {
        let (client, _server, port) = setup_peers().await;

        assert!(client.start_test(IP_ADDR, port).await.is_ok());

        // Handler state -> End. Test results sent server -> client
        wait_for_results(HandlerState::End, client).await;
    }

    #[tokio::test]
    async fn test_restart() {
        let (client, _server, port) = setup_peers().await;

        assert!(client.start_test(IP_ADDR, port).await.is_ok());

        // Extra wait to make sure test has completed
        tokio::time::sleep(TEST_DURATION * 3).await;

        assert!(client.start_test(IP_ADDR, port).await.is_ok());

        // Handler state -> End. Test results sent server -> client
        wait_for_results(HandlerState::Test, client).await;
    }

    #[tokio::test]
    async fn test_multiple_tests_at_same_time() {
        let (client, _server, port) = setup_peers().await;

        assert!(client.start_test(IP_ADDR, port).await.is_ok());

        // Wait a little while to make sure tests have started
        tokio::time::sleep(TEST_DURATION / 4).await;

        assert!(client.start_test(IP_ADDR, port).await.is_err());
    }

    #[tokio::test]
    async fn test_calculating_results() {
        let duration = Duration::from_secs(10);
        let (pkt_loss, speed) = State::calculate_results(222333, duration, 444666)
            .await
            .unwrap();
        assert!(pkt_loss == 50.0);
        assert!(speed == 251);
    }

    #[tokio::test]
    async fn test_fetching_results() {
        let (client, _server, port) = setup_peers().await;

        assert!(client.start_test(IP_ADDR, port).await.is_ok());
        // Get results is not ready response
        assert!(client.try_fetch_results().await.unwrap() == -1);
        // Extra wait to make sure test has completed
        tokio::time::sleep(TEST_DURATION * 2).await;
        // Get actual results
        assert!(client.try_fetch_results().await.unwrap() > 0);
    }

    #[tokio::test]
    async fn test_unable_to_fetch_results() {
        let (client, server, port) = setup_peers().await;

        assert!(client.start_test(IP_ADDR, port).await.is_ok());

        // Extra wait to make sure test has started
        tokio::time::sleep(TEST_DURATION / 2).await;

        // Close the server end
        drop(server);

        // Extra wait to make sure exp backoff time has expired
        tokio::time::sleep(TEST_DURATION * 3).await;
        // Get actual results
        assert!(client.try_fetch_results().await.is_err());
    }
}
