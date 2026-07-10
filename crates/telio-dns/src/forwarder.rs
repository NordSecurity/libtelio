//! DNS packet forwarder for remote resolvers
//!
//! This module provides a layer for forwarding DNS queries to upstream resolvers.
//! Multiple queries can be in flight concurrently.
//!
//! Upstream resolvers are tried in order they are set.
//! If no response is received after the set timeout, the next
//! upstream resolver is tried.

use crate::{bind_tun::bind_to_tun, packet_encoder::DNS_HEADER_OFFSET};
use rand::RngExt;
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use telio_utils::{sleep_until, telio_log_debug, telio_log_warn, Instant};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Mutex},
};

/// Maximum buffer size for response packet
const FORWARDER_BUFFER_SIZE: usize = 65535;
/// Channel size for forward messages
const CHANNEL_SIZE: usize = 256;
/// Default timeout for upstream DNS queries
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum number of DNS IDs
const DNS_ID_SPACE: u32 = 65536;

/// Send a result through the response channel, logging a warning if the receiver was dropped
macro_rules! send_channel_response {
    ($tx:expr, $result:expr) => {
        if $tx.send($result).is_err() {
            telio_log_warn!("Response channel dropped");
        }
    };
}

/// Errors returned when forwarding a DNS query
#[derive(Error, Debug)]
pub enum ForwardError {
    /// Failed upstream socket bind operation
    #[error("Failed socket bind operation: {0}")]
    SocketBindFailed(#[from] io::Error),
    /// Failed to send a DNS query to the upstream resolver
    #[error("Failed to send DNS query: {0}")]
    SendFailed(io::Error),
    /// No upstreams configured
    #[error("No upstream resolvers configured")]
    NoUpstreams,
    /// The upstream resolvers did not respond within the configured timeout
    #[error("DNS query timed out")]
    Timeout,
    /// The forwarder channel was closed
    #[error("Forwarder channel closed")]
    ChannelClosed,
    /// Too many concurrent requests
    #[error("Too many concurrent requests in flight")]
    TooManyRequests,
    /// The DNS packet is too short
    #[error("DNS packet too short")]
    PacketTooShort,
}

/// DNS query forwarder bound to the tunnel interface
///
/// Forwards raw DNS queries to upstream resolvers.
/// Next upstream resolver is tried if no response is received after `timeout`.
#[derive(Clone, Debug)]
pub(crate) struct RawForwarder {
    tx: mpsc::Sender<ForwardQuery>,
    upstreams: Arc<Mutex<UpstreamState>>,
    timeout: Arc<Mutex<Duration>>,
}

/// Upstream resolver list with a generation counter to detect changes
#[derive(Clone, Debug, Default)]
struct UpstreamState {
    addrs: Vec<SocketAddr>,
    generation: u64,
}

/// Internal message for forwarding a DNS query
struct ForwardQuery {
    /// Raw DNS packet bytes to forward
    query_bytes: Vec<u8>,
    /// Channel to send the response back to the caller
    respond_to: oneshot::Sender<Result<Vec<u8>, ForwardError>>,
}

/// In progress DNS query awaiting an upstream response
struct PendingQuery {
    /// Original request ID
    original_id: u16,
    /// Raw DNS packet bytes
    query_bytes: Vec<u8>,
    /// Current upstream index for request
    upstream_index: usize,
    /// Generation of the upstream list when this query was last dispatched
    upstream_generation: u64,
    /// Channel to send the response back to the caller
    respond_to: oneshot::Sender<Result<Vec<u8>, ForwardError>>,
    /// Instant when request times out
    deadline: Instant,
}

/// Extract the 16-bit transaction ID of a DNS packet
fn get_dns_id(packet: &[u8]) -> Result<u16, ForwardError> {
    if packet.len() < DNS_HEADER_OFFSET {
        return Err(ForwardError::PacketTooShort);
    }

    // This is ok because the size is checked above
    #[allow(clippy::indexing_slicing)]
    Ok(u16::from_be_bytes([packet[0], packet[1]]))
}

/// Overwrite the 16-bit transaction ID of a DNS packet
fn set_dns_id(packet: &mut [u8], id: u16) -> Result<(), ForwardError> {
    if packet.len() < DNS_HEADER_OFFSET {
        return Err(ForwardError::PacketTooShort);
    }
    let bytes = id.to_be_bytes();

    // This is ok because the size is checked above
    #[allow(clippy::indexing_slicing)]
    {
        packet[0] = bytes[0];
        packet[1] = bytes[1];
    }
    Ok(())
}

/// Allocate an unused internal DNS transaction ID, returns `None` if all IDs are in use
fn allocate_id(pending: &HashMap<u16, PendingQuery>, next_id: &mut u16) -> Option<u16> {
    for _ in 0..DNS_ID_SPACE {
        let candidate = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

impl RawForwarder {
    /// Create a new DNS forwarder
    pub(crate) async fn new() -> Result<Self, ForwardError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        bind_to_tun(&socket)?;

        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        let upstreams = Arc::new(Mutex::new(UpstreamState::default()));
        let timeout = Arc::new(Mutex::new(DEFAULT_QUERY_TIMEOUT));

        tokio::spawn(Self::run(socket, rx, upstreams.clone(), timeout.clone()));

        Ok(RawForwarder {
            tx,
            upstreams,
            timeout,
        })
    }

    /// Forward a DNS query to the configured upstream resolver
    pub(crate) async fn query(&self, request: &[u8]) -> Result<Vec<u8>, ForwardError> {
        let (respond_to, recv) = oneshot::channel();
        let msg = ForwardQuery {
            query_bytes: request.to_vec(),
            respond_to,
        };

        self.tx
            .send(msg)
            .await
            .map_err(|_| ForwardError::ChannelClosed)?;

        recv.await.map_err(|_| ForwardError::ChannelClosed)?
    }

    /// Update the list of upstream resolvers
    pub(crate) async fn set_upstreams(&self, addrs: Vec<SocketAddr>) {
        telio_log_debug!("Changing forwarder upstreams: {addrs:?}");
        let mut state = self.upstreams.lock().await;
        state.generation = state.generation.wrapping_add(1);
        state.addrs = addrs;
    }

    // TODO: LLT-7054: remove if not needed after complete regression testing
    #[cfg(test)]
    /// Update the timeout for upstream DNS queries
    pub(crate) async fn set_timeout(&self, timeout: Duration) {
        *self.timeout.lock().await = timeout;
    }

    /// Main async loop that forwards incoming requests
    async fn run(
        socket: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<ForwardQuery>,
        upstreams: Arc<Mutex<UpstreamState>>,
        timeout: Arc<Mutex<Duration>>,
    ) {
        telio_log_debug!("Forwarder starting");
        let mut recv_buf = vec![0u8; FORWARDER_BUFFER_SIZE];
        let mut pending: HashMap<u16, PendingQuery> = HashMap::new();
        let mut next_id: u16 = rand::rng().random();

        loop {
            let deadline = Self::next_deadline(&pending);

            tokio::select! {
                // handle query to forward
                msg = rx.recv() => {
                    match msg {
                        Some(forward_msg) => {
                            Self::handle_new_query(
                                &socket,
                                forward_msg,
                                &upstreams,
                                &timeout,
                                &mut pending,
                                &mut next_id,
                            ).await;
                        }
                        None => {
                            telio_log_debug!("Forwarder channel dropped");
                            break;
                        },
                    }
                }
                // handle response from upstream
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, src)) => {
                            // validate the src IP
                            let is_known_upstream = {
                                let state = upstreams.lock().await;
                                state.addrs.iter().any(|u| u.ip() == src.ip())
                            };
                            if !is_known_upstream {
                                telio_log_warn!("Received DNS response from unknown source: {src}, ignoring");
                                continue;
                            }

                            match recv_buf.get_mut(..n) {
                                Some(response_bytes) => {
                                    Self::handle_response(response_bytes, &mut pending);
                                }
                                None =>  {
                                    telio_log_warn!("Failed to receive from upstream resolver, size overflow: {n}");
                                }
                            }
                        }
                        Err(e) => {
                            telio_log_warn!("Failed to receive from upstream resolver: {e}");
                        }
                    }
                }
                // handle timeouts
                _ = async {
                    match deadline {
                        Some(dl) => sleep_until(dl).await,
                        None => std::future::pending().await,
                    }
                } => {
                    Self::handle_timeouts(
                        &socket,
                        &upstreams,
                        &timeout,
                        &mut pending,
                    ).await;
                }
            }
        }

        for (_, entry) in pending.drain() {
            send_channel_response!(entry.respond_to, Err(ForwardError::ChannelClosed));
        }

        telio_log_debug!("Forwarder exiting");
    }

    /// Return the earliest deadline
    fn next_deadline(pending: &HashMap<u16, PendingQuery>) -> Option<Instant> {
        pending.values().map(|e| e.deadline).min()
    }

    /// Handle new query
    async fn handle_new_query(
        socket: &UdpSocket,
        msg: ForwardQuery,
        upstreams: &Arc<Mutex<UpstreamState>>,
        timeout: &Arc<Mutex<Duration>>,
        pending: &mut HashMap<u16, PendingQuery>,
        next_id: &mut u16,
    ) {
        let (original_id, internal_id, rewritten_bytes) =
            match Self::prepare_new_query(&msg.query_bytes, pending, next_id).await {
                Ok(r) => r,
                Err(e) => {
                    send_channel_response!(msg.respond_to, Err(e));
                    return;
                }
            };

        let (upstream_addr, generation) = {
            let state = upstreams.lock().await;
            match state.addrs.first().cloned() {
                Some(addr) => (addr, state.generation),
                None => {
                    send_channel_response!(msg.respond_to, Err(ForwardError::NoUpstreams));
                    return;
                }
            }
        };

        if let Err(e) = socket.send_to(&rewritten_bytes, upstream_addr).await {
            send_channel_response!(msg.respond_to, Err(ForwardError::SendFailed(e)));
            return;
        }

        let query_timeout = *timeout.lock().await;
        pending.insert(
            internal_id,
            PendingQuery {
                original_id,
                query_bytes: rewritten_bytes,
                upstream_index: 0,
                upstream_generation: generation,
                respond_to: msg.respond_to,
                deadline: Instant::now() + query_timeout,
            },
        );
    }

    /// Helper to handle new query
    async fn prepare_new_query(
        bytes: &[u8],
        pending: &HashMap<u16, PendingQuery>,
        next_id: &mut u16,
    ) -> Result<(u16, u16, Vec<u8>), ForwardError> {
        let original_id = get_dns_id(bytes)?;
        let internal_id = allocate_id(pending, next_id).ok_or(ForwardError::TooManyRequests)?;

        let mut rewritten = bytes.to_owned();
        set_dns_id(&mut rewritten, internal_id)?;

        Ok((original_id, internal_id, rewritten))
    }

    /// Match an upstream response to a pending query and deliver the result
    fn handle_response(response_bytes: &mut [u8], pending: &mut HashMap<u16, PendingQuery>) {
        let internal_id = match get_dns_id(response_bytes) {
            Ok(id) => id,
            Err(e) => {
                telio_log_warn!("Failed to get response ID: {e}");
                return;
            }
        };

        let entry = match pending.remove(&internal_id) {
            Some(e) => e,
            None => {
                telio_log_warn!("Received response for unknown ID: {internal_id}");
                return;
            }
        };

        if entry.respond_to.is_closed() {
            telio_log_warn!("Caller dropped for request: {internal_id}");
            return;
        }

        if let Err(e) = set_dns_id(response_bytes, entry.original_id) {
            send_channel_response!(entry.respond_to, Err(e));
            return;
        }

        send_channel_response!(entry.respond_to, Ok(response_bytes.to_vec()));
    }

    /// Handle expired queries
    async fn handle_timeouts(
        socket: &UdpSocket,
        upstreams: &Arc<Mutex<UpstreamState>>,
        timeout: &Arc<Mutex<Duration>>,
        pending: &mut HashMap<u16, PendingQuery>,
    ) {
        let now = Instant::now();
        let expired_ids: Vec<(u16, bool)> = pending
            .iter()
            .filter_map(|(&id, entry)| {
                let closed = entry.respond_to.is_closed();
                (entry.deadline <= now || closed).then_some((id, closed))
            })
            .collect();

        if expired_ids.is_empty() {
            return;
        }

        let current_state = {
            let locked = upstreams.lock().await;
            locked.clone()
        };

        for (internal_id, is_closed) in expired_ids {
            let mut entry = match pending.remove(&internal_id) {
                Some(e) => e,
                None => continue,
            };

            if is_closed {
                telio_log_warn!("Caller dropped for: {internal_id}");
                continue;
            }

            let next_index = if entry.upstream_generation == current_state.generation {
                entry.upstream_index + 1
            } else {
                telio_log_debug!(
                    "Upstreams changed for request: {internal_id}, restarting from index 0"
                );
                0
            };

            match current_state.addrs.get(next_index) {
                Some(&next_upstream) => {
                    telio_log_debug!(
                        "Upstream timed out for request: {internal_id}, trying next: {next_upstream}"
                    );
                    entry.upstream_index = next_index;
                    entry.upstream_generation = current_state.generation;
                    entry.deadline = Instant::now() + *timeout.lock().await;

                    if let Err(e) = socket.send_to(&entry.query_bytes, next_upstream).await {
                        send_channel_response!(entry.respond_to, Err(ForwardError::SendFailed(e)));
                        continue;
                    }

                    pending.insert(internal_id, entry);
                }
                None => {
                    telio_log_warn!("All upstreams exhausted for request: {internal_id}");
                    send_channel_response!(entry.respond_to, Err(ForwardError::Timeout));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::task::JoinHandle;

    const TEST_PACKET_ID: u16 = 0x1234;
    const MAX_DGRAM: usize = 9214;
    const TEST_DNS_PAYLOAD: &[u8; 13] = b"query-payload";

    fn make_dns_packet(id: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = id.to_be_bytes().to_vec();
        packet.extend_from_slice(payload);
        packet
    }

    enum StubBehavior {
        Echo,
        BlackHole,
    }

    async fn spawn_stub(behavior: StubBehavior) -> (SocketAddr, JoinHandle<Vec<u8>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; FORWARDER_BUFFER_SIZE];
            let (n, src) = socket.recv_from(&mut buf).await.unwrap();
            let received = buf[..n].to_vec();

            match behavior {
                StubBehavior::Echo => {
                    socket.send_to(&received, src).await.unwrap();
                }
                StubBehavior::BlackHole => {}
            }
            received
        });

        (addr, handle)
    }

    async fn spawn_multi_stub(count: usize) -> (SocketAddr, JoinHandle<Vec<Vec<u8>>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut received = Vec::new();
            for _ in 0..count {
                let (n, src) = socket.recv_from(&mut buf).await.unwrap();
                let data = buf[..n].to_vec();
                socket.send_to(&data, src).await.unwrap();
                received.push(data);
            }
            received
        });

        (addr, handle)
    }

    fn dummy_pending() -> PendingQuery {
        PendingQuery {
            original_id: 0,
            query_bytes: vec![],
            upstream_index: 0,
            upstream_generation: 0,
            respond_to: oneshot::channel().0,
            deadline: Instant::now(),
        }
    }

    #[test]
    fn get_dns_id_returns_correct_id() {
        let mut packet = vec![0x12, 0x34];
        packet.resize(12, 0);

        assert_eq!(get_dns_id(&packet).unwrap(), TEST_PACKET_ID);
    }

    #[test]
    fn get_dns_id_short_packet() {
        assert!(get_dns_id(&[]).is_err());
        assert!(get_dns_id(&[0x12]).is_err());
    }

    #[test]
    fn set_dns_id_rewrites_first_two_bytes() {
        let mut packet = vec![0x00, 0x00, 0xAA, 0xBB];
        packet.resize(12, 0);

        assert!(set_dns_id(&mut packet, 0xCAFE).is_ok());
        assert_eq!(packet[..4], [0xCA, 0xFE, 0xAA, 0xBB]);
    }

    #[test]
    fn set_dns_id_for_short_packet() {
        let mut empty: [u8; 0] = [];
        assert!(set_dns_id(&mut empty, TEST_PACKET_ID).is_err());
        let mut one = [0x12];
        assert!(set_dns_id(&mut one, TEST_PACKET_ID).is_err());
    }

    #[test]
    fn allocate_id_increments_id() {
        let mut pending = HashMap::new();
        let mut next_id = 0;
        let id = allocate_id(&pending, &mut next_id);
        assert_eq!(id, Some(0));
        assert_eq!(next_id, 1);

        pending.insert(0, dummy_pending());
        pending.insert(1, dummy_pending());

        let id = allocate_id(&pending, &mut next_id);
        assert_eq!(id, Some(2));
        assert_eq!(next_id, 3);
    }

    #[test]
    fn allocate_id_returns_none_when_exhausted() {
        let mut pending = HashMap::new();
        for i in 0..=u16::MAX {
            pending.insert(i, dummy_pending());
        }
        let mut next_id = 0;
        assert_eq!(allocate_id(&pending, &mut next_id), None);
    }

    #[tokio::test]
    async fn set_upstreams_stores_resolvers() {
        let forwarder = RawForwarder::new().await.unwrap();
        let addrs = vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        forwarder.set_upstreams(addrs.clone()).await;

        let state = forwarder.upstreams.lock().await;
        assert_eq!(state.addrs, addrs);
    }

    #[tokio::test]
    async fn set_upstreams_replaces_existing() {
        let forwarder = RawForwarder::new().await.unwrap();
        let first_addrs = vec!["8.8.8.8:53".parse().unwrap()];
        let second_addrs = vec!["1.1.1.1:53".parse().unwrap(), "8.8.4.4:53".parse().unwrap()];

        forwarder.set_upstreams(first_addrs).await;
        forwarder.set_upstreams(second_addrs.clone()).await;

        let state = forwarder.upstreams.lock().await;
        assert_eq!(state.addrs, second_addrs);
    }

    #[tokio::test]
    async fn query_returns_no_upstreams_when_empty() {
        let forwarder = RawForwarder::new().await.unwrap();

        let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
        let result = forwarder.query(&request).await;

        match result {
            Err(ForwardError::NoUpstreams) => {}
            other => panic!("Expected NoUpstreams, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn cloned_forwarders_share_upstream_state() {
        let forwarder1 = RawForwarder::new().await.unwrap();
        let forwarder2 = forwarder1.clone();

        let addrs = vec!["8.8.8.8:53".parse().unwrap()];
        forwarder1.set_upstreams(addrs.clone()).await;

        let state = forwarder2.upstreams.lock().await;
        assert_eq!(state.addrs, addrs);
    }

    #[tokio::test]
    async fn set_timeout_updates_value() {
        let forwarder = RawForwarder::new().await.unwrap();
        let target_timeout = Duration::from_secs(10);

        forwarder.set_timeout(target_timeout).await;

        let timeout = *forwarder.timeout.lock().await;
        assert_eq!(timeout, target_timeout);
    }

    #[tokio::test]
    async fn forward_query_timeout() {
        let (blackhole_addr1, _bh1) = spawn_stub(StubBehavior::BlackHole).await;
        let (blackhole_addr2, _bh2) = spawn_stub(StubBehavior::BlackHole).await;
        let target_timeout = Duration::from_millis(50);

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder
            .set_upstreams(vec![blackhole_addr1, blackhole_addr2])
            .await;
        forwarder.set_timeout(target_timeout).await;

        let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
        let result = forwarder.query(&request).await;

        match result {
            Err(ForwardError::Timeout) => {}
            other => panic!(
                "Expected Timeout after all upstreams failed, got: {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn forward_query_returns_response_from_upstream() {
        let (addr, _handle) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![addr]).await;

        let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
        let result = forwarder.query(&request).await.unwrap();

        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert_eq!(&result[2..], TEST_DNS_PAYLOAD);
    }

    #[tokio::test]
    async fn forward_query_falls_back_to_second_upstream() {
        let (blackhole_addr, _bh_handle) = spawn_stub(StubBehavior::BlackHole).await;
        let (reply_addr, _reply_handle) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder
            .set_upstreams(vec![blackhole_addr, reply_addr])
            .await;
        forwarder.set_timeout(Duration::from_millis(50)).await;

        let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
        let result = forwarder.query(&request).await.unwrap();

        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert_eq!(&result[2..], TEST_DNS_PAYLOAD);
    }

    #[tokio::test]
    async fn forward_query_passes_through_large_response() {
        let large_payload = vec![0xAB; MAX_DGRAM];
        let (addr, _handle) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![addr]).await;

        let request = make_dns_packet(TEST_PACKET_ID, &large_payload);
        let result = forwarder.query(&request).await.unwrap();

        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert_eq!(&result[2..], &large_payload[..]);
    }

    #[tokio::test]
    async fn forward_query_works_after_upstream_change() {
        let (first_addr, _h1) = spawn_stub(StubBehavior::Echo).await;
        let (second_addr, _h2) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![first_addr]).await;

        let request1 = make_dns_packet(0x1111, TEST_DNS_PAYLOAD);
        let r1 = forwarder.query(&request1).await.unwrap();
        assert_eq!(get_dns_id(&r1).unwrap(), 0x1111);

        forwarder.set_upstreams(vec![second_addr]).await;

        let request2 = make_dns_packet(0x2222, TEST_DNS_PAYLOAD);
        let r2 = forwarder.query(&request2).await.unwrap();
        assert_eq!(get_dns_id(&r2).unwrap(), 0x2222);
    }

    #[tokio::test]
    async fn concurrent_queries_receive_responses() {
        let query_count = 20;
        let (stub_addr, _stub_handle) = spawn_multi_stub(query_count).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![stub_addr]).await;
        forwarder.set_timeout(Duration::from_secs(5)).await;

        let mut handles = Vec::new();
        for i in 0..query_count {
            let f = forwarder.clone();
            let id = (i as u16) + 1;
            let payload = format!("dns-payload-{i}");
            handles.push(tokio::spawn(async move {
                let request = make_dns_packet(id, payload.as_bytes());
                let result = f.query(&request).await.unwrap();
                (id, payload, result)
            }));
        }

        for handle in handles {
            let (original_id, payload, response) = handle.await.unwrap();
            assert_eq!(get_dns_id(&response).unwrap(), original_id);
            assert_eq!(&response[2..], payload.as_bytes());
        }
    }

    #[tokio::test]
    async fn concurrent_queries_with_different_latencies() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stub_addr = socket.local_addr().unwrap();

        let _stub = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut received = Vec::new();
            for _ in 0..3 {
                let (n, src) = socket.recv_from(&mut buf).await.unwrap();
                received.push((buf[..n].to_vec(), src));
            }
            for (data, src) in received.into_iter().rev() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                socket.send_to(&data, src).await.unwrap();
            }
        });

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![stub_addr]).await;
        forwarder.set_timeout(Duration::from_secs(5)).await;

        let mut handles = Vec::new();
        for i in 0..3u16 {
            let f = forwarder.clone();
            let payload = format!("dns-latency-{i}");
            handles.push(tokio::spawn({
                let p = payload.clone();
                async move {
                    let request = make_dns_packet(100 + i, p.as_bytes());
                    let result = f.query(&request).await.unwrap();
                    (100 + i, payload, result)
                }
            }));
        }

        for handle in handles {
            let (original_id, payload, response) = handle.await.unwrap();
            assert_eq!(get_dns_id(&response).unwrap(), original_id);
            assert_eq!(&response[2..], payload.as_bytes());
        }
    }

    #[tokio::test]
    async fn id_rewrite_preserves_rest_of_packet() {
        let (addr, _handle) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![addr]).await;

        let payload: Vec<u8> = (0..200u8).collect();
        let request = make_dns_packet(0xBEEF, &payload);
        let result = forwarder.query(&request).await.unwrap();

        assert_eq!(get_dns_id(&result).unwrap(), 0xBEEF);
        assert_eq!(&result[2..], &payload[..]);
    }

    #[tokio::test]
    async fn packet_too_short_returns_error() {
        let forwarder = RawForwarder::new().await.unwrap();
        forwarder
            .set_upstreams(vec!["127.0.0.1:53".parse().unwrap()])
            .await;

        let result = forwarder.query(&[0x12]).await;
        match result {
            Err(ForwardError::PacketTooShort) => {}
            other => panic!("Expected PacketTooShort, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn set_upstreams_increments_generation() {
        let forwarder = RawForwarder::new().await.unwrap();

        let state = forwarder.upstreams.lock().await;
        assert_eq!(state.generation, 0);
        drop(state);

        forwarder
            .set_upstreams(vec!["8.8.8.8:53".parse().unwrap()])
            .await;

        let state = forwarder.upstreams.lock().await;
        assert_eq!(state.generation, 1);
        drop(state);

        forwarder
            .set_upstreams(vec!["1.1.1.1:53".parse().unwrap()])
            .await;

        let state = forwarder.upstreams.lock().await;
        assert_eq!(state.generation, 2);
    }

    #[tokio::test]
    async fn upstream_change_during_pending_query_retries_from_new_list() {
        let (blackhole_addr, _bh) = spawn_stub(StubBehavior::BlackHole).await;
        let (reply_addr, _reply) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![blackhole_addr]).await;
        forwarder.set_timeout(Duration::from_millis(50)).await;

        let f = forwarder.clone();
        let query_handle = tokio::spawn(async move {
            let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
            f.query(&request).await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        forwarder.set_upstreams(vec![reply_addr]).await;

        let result = query_handle.await.unwrap().unwrap();
        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert_eq!(&result[2..], TEST_DNS_PAYLOAD);
    }

    #[tokio::test]
    async fn upstream_change_to_empty_during_pending_query_times_out() {
        let (blackhole_addr, _bh) = spawn_stub(StubBehavior::BlackHole).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![blackhole_addr]).await;
        forwarder.set_timeout(Duration::from_millis(50)).await;

        let f = forwarder.clone();
        let query_handle = tokio::spawn(async move {
            let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
            f.query(&request).await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        forwarder.set_upstreams(vec![]).await;

        match query_handle.await.unwrap() {
            Err(ForwardError::Timeout) => {}
            other => panic!("Expected Timeout, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn upstream_change_rescues_query_that_would_have_exhausted_old_list() {
        let (blackhole_addr, _bh) = spawn_stub(StubBehavior::BlackHole).await;
        let (reply_addr, _reply) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![blackhole_addr]).await;
        forwarder.set_timeout(Duration::from_millis(100)).await;

        let f = forwarder.clone();
        let query_handle = tokio::spawn(async move {
            let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
            f.query(&request).await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        forwarder.set_upstreams(vec![reply_addr]).await;

        let result = query_handle.await.unwrap().unwrap();
        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert_eq!(&result[2..], TEST_DNS_PAYLOAD);
    }
}
