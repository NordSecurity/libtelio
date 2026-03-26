//! DNS packet forwarder for remote resolvers
//!
//! This module provides a layer for forwarding DNS queries to upstream resolvers.
//! Multiple queries can be in-flight concurrently using DNS transaction ID rewriting.

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
const FORWARDER_BUFFER_SIZE: usize = 4096;
/// Channel size for forward messages
const CHANNEL_SIZE: usize = 256;
/// Default timeout for upstream DNS queries
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of DNS IDs
const DNS_ID_SPACE: u32 = 65536;

/// Errors returned when forwarding a DNS query
#[derive(Error, Debug)]
pub enum ForwardError {
    /// Failed upstream socket bind operation
    #[error("Failed socket bind operation: {0}")]
    SocketBind(#[from] io::Error),
    /// Failed to send a DNS query to the upstream resolver
    #[error("Failed to send DNS query: {0}")]
    Send(io::Error),
    /// No upstreams configured
    #[error("No upstream resolvers configured")]
    NoUpstreams,
    /// The upstream resolver did not respond within the configured timeout
    #[error("DNS query timed out after {0:?}")]
    Timeout(Duration),
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
/// Forwards raw DNS queries to upstream resolvers. Supports multiple
/// concurrent in-flight queries via DNS transaction ID rewriting.
#[derive(Clone)]
pub struct RawForwarder {
    tx: mpsc::Sender<ForwardQuery>,
    upstreams: Arc<Mutex<Vec<SocketAddr>>>,
    timeout: Arc<Mutex<Duration>>,
}

/// Internal message for forwarding a DNS query
struct ForwardQuery {
    /// Raw DNS packet bytes to forward
    query_bytes: Vec<u8>,
    /// Timeout for the upstream response
    timeout: Duration,
    /// Channel to send the response back to the caller
    respond_to: oneshot::Sender<Result<Vec<u8>, ForwardError>>,
}

struct PendingQuery {
    /// Original request ID
    original_id: u16,
    /// Raw DNS packet bytes
    query_bytes: Vec<u8>,
    /// Current upstream index for request
    upstream_index: usize,
    /// Channel to send the response back to the caller
    respond_to: oneshot::Sender<Result<Vec<u8>, ForwardError>>,
    /// Instant when request times out
    deadline: Instant,
    /// Timeout for the upstream response
    timeout: Duration,
}

fn get_dns_id(packet: &[u8]) -> Result<u16, ForwardError> {
    if packet.len() < DNS_HEADER_OFFSET {
        return Err(ForwardError::PacketTooShort);
    }

    // This is ok because the size is checked above
    #[allow(clippy::indexing_slicing)]
    Ok(u16::from_be_bytes([packet[0], packet[1]]))
}

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
    /// Create a new forwarder with a tunnel-bound UDP socket
    pub async fn new() -> Result<Self, ForwardError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        bind_to_tun(&socket)?;

        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        let upstreams = Arc::new(Mutex::new(Vec::new()));
        let timeout = Arc::new(Mutex::new(DEFAULT_QUERY_TIMEOUT));

        tokio::spawn(Self::run(socket, rx, upstreams.clone()));

        Ok(RawForwarder {
            tx,
            upstreams,
            timeout,
        })
    }

    /// Forward a DNS query to the configured upstream resolver
    pub async fn query(&self, request: &[u8]) -> Result<Vec<u8>, ForwardError> {
        let timeout = *self.timeout.lock().await;
        let (respond_to, recv) = oneshot::channel();
        let msg = ForwardQuery {
            query_bytes: request.to_vec(),
            timeout,
            respond_to,
        };

        self.tx
            .send(msg)
            .await
            .map_err(|_| ForwardError::ChannelClosed)?;

        recv.await.map_err(|_| ForwardError::ChannelClosed)?
    }

    /// Update the list of upstream resolvers
    pub async fn set_upstreams(&self, addrs: Vec<SocketAddr>) -> Result<(), ForwardError> {
        let mut upstreams = self.upstreams.lock().await;
        *upstreams = addrs;
        Ok(())
    }

    #[allow(dead_code)]
    /// Update the timeout for upstream DNS queries
    pub async fn set_timeout(&self, timeout: Duration) {
        *self.timeout.lock().await = timeout;
    }

    /// Main async loop that processes incoming forward requests
    async fn run(
        socket: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<ForwardQuery>,
        upstreams: Arc<Mutex<Vec<SocketAddr>>>,
    ) {
        telio_log_debug!("Forwarder starting");
        let mut recv_buf = vec![0u8; FORWARDER_BUFFER_SIZE];
        let mut pending: HashMap<u16, PendingQuery> = HashMap::new();
        let mut next_id: u16 = rand::rng().random();

        loop {
            let deadline = Self::next_deadline(&pending);

            tokio::select! {
                // Handle query to forward
                msg = rx.recv() => {
                    match msg {
                        Some(forward_msg) => {
                            Self::handle_new_query(
                                &socket,
                                forward_msg,
                                &upstreams,
                                &mut pending,
                                &mut next_id,
                            ).await;
                        }
                        None => {
                            telio_log_warn!("Channel dropped");
                            break;
                        },
                    }
                }
                // handle response from upstream
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, _src)) => {
                            // TODO: verify that src is in upstreams
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
                        &mut pending,
                    ).await;
                }
            }
        }

        for (_, entry) in pending.drain() {
            let _ = entry.respond_to.send(Err(ForwardError::ChannelClosed));
        }

        telio_log_debug!("Forwarder exiting");
    }

    fn next_deadline(pending: &HashMap<u16, PendingQuery>) -> Option<Instant> {
        pending.values().map(|e| e.deadline).min()
    }

    async fn handle_new_query(
        socket: &UdpSocket,
        msg: ForwardQuery,
        upstreams: &Arc<Mutex<Vec<SocketAddr>>>,
        pending: &mut HashMap<u16, PendingQuery>,
        next_id: &mut u16,
    ) {
        let original_id = match get_dns_id(&msg.query_bytes) {
            Ok(id) => id,
            Err(e) => {
                let _ = msg.respond_to.send(Err(e));
                return;
            }
        };

        let internal_id = match allocate_id(pending, next_id) {
            Some(id) => id,
            None => {
                let _ = msg.respond_to.send(Err(ForwardError::TooManyRequests));
                return;
            }
        };

        let first_upstream = {
            let locked = upstreams.lock().await;
            locked.first().cloned()
        };

        let upstream_addr = match first_upstream {
            Some(addr) => addr,
            None => {
                let _ = msg.respond_to.send(Err(ForwardError::NoUpstreams));
                return;
            }
        };

        let mut rewritten = msg.query_bytes;
        if let Err(e) = set_dns_id(&mut rewritten, internal_id) {
            let _ = msg.respond_to.send(Err(e));
            return;
        }

        if let Err(e) = socket.send_to(&rewritten, upstream_addr).await {
            let _ = msg.respond_to.send(Err(ForwardError::Send(e)));
            return;
        }

        pending.insert(
            internal_id,
            PendingQuery {
                original_id,
                query_bytes: rewritten,
                upstream_index: 0,
                respond_to: msg.respond_to,
                deadline: Instant::now() + msg.timeout,
                timeout: msg.timeout,
            },
        );
    }

    fn handle_response(response_bytes: &mut [u8], pending: &mut HashMap<u16, PendingQuery>) {
        let internal_id = match get_dns_id(response_bytes) {
            Ok(id) => id,
            Err(e) => {
                telio_log_debug!("Received response error: {e}");
                return;
            }
        };

        let entry = match pending.remove(&internal_id) {
            Some(e) => e,
            None => {
                telio_log_debug!("Received response for unknown ID {internal_id}");
                return;
            }
        };

        let mut rewritten_response = response_bytes.to_vec();
        if let Err(e) = set_dns_id(&mut rewritten_response, entry.original_id) {
            let _ = entry.respond_to.send(Err(e));
            return;
        }

        let _ = entry.respond_to.send(Ok(rewritten_response));
    }

    async fn handle_timeouts(
        socket: &UdpSocket,
        upstreams: &Arc<Mutex<Vec<SocketAddr>>>,
        pending: &mut HashMap<u16, PendingQuery>,
    ) {
        let now = Instant::now();
        let expired_ids: Vec<u16> = pending
            .iter()
            .filter(|(_, entry)| entry.deadline <= now)
            .map(|(&id, _)| id)
            .collect();

        if expired_ids.is_empty() {
            return;
        }

        let current_upstreams = {
            let locked = upstreams.lock().await;
            locked.clone()
        };

        for internal_id in expired_ids {
            let mut entry = match pending.remove(&internal_id) {
                Some(e) => e,
                None => continue,
            };

            let next_index = entry.upstream_index + 1;
            match current_upstreams.get(next_index) {
                Some(&next_upstream) => {
                    telio_log_debug!(
                        "Upstream timed out for ID {internal_id}, trying next: {next_upstream}"
                    );
                    entry.upstream_index = next_index;
                    entry.deadline = Instant::now() + entry.timeout;

                    if let Err(e) = socket.send_to(&entry.query_bytes, next_upstream).await {
                        let _ = entry.respond_to.send(Err(ForwardError::Send(e)));
                        continue;
                    }

                    pending.insert(internal_id, entry);
                }
                None => {
                    telio_log_warn!("All upstreams exhausted for ID {internal_id}");
                    let _ = entry
                        .respond_to
                        .send(Err(ForwardError::Timeout(entry.timeout)));
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
            let mut buf = vec![0u8; 4096];
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
            respond_to: oneshot::channel().0,
            deadline: Instant::now(),
            timeout: Duration::from_secs(1),
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

        forwarder.set_upstreams(addrs.clone()).await.unwrap();

        let upstreams = forwarder.upstreams.lock().await;
        assert_eq!(*upstreams, addrs);
    }

    #[tokio::test]
    async fn set_upstreams_replaces_existing() {
        let forwarder = RawForwarder::new().await.unwrap();
        let first_addrs = vec!["8.8.8.8:53".parse().unwrap()];
        let second_addrs = vec!["1.1.1.1:53".parse().unwrap(), "8.8.4.4:53".parse().unwrap()];

        forwarder.set_upstreams(first_addrs).await.unwrap();
        forwarder.set_upstreams(second_addrs.clone()).await.unwrap();

        let upstreams = forwarder.upstreams.lock().await;
        assert_eq!(*upstreams, second_addrs);
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
        forwarder1.set_upstreams(addrs.clone()).await.unwrap();

        let upstreams = forwarder2.upstreams.lock().await;
        assert_eq!(*upstreams, addrs);
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
            .await
            .unwrap();
        forwarder.set_timeout(target_timeout).await;

        let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
        let result = forwarder.query(&request).await;

        match result {
            Err(ForwardError::Timeout(d)) => assert_eq!(d, target_timeout),
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
        forwarder.set_upstreams(vec![addr]).await.unwrap();

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
            .await
            .unwrap();
        forwarder.set_timeout(Duration::from_millis(50)).await;

        let request = make_dns_packet(TEST_PACKET_ID, TEST_DNS_PAYLOAD);
        let result = forwarder.query(&request).await.unwrap();

        assert_eq!(get_dns_id(&result).unwrap(), TEST_PACKET_ID);
        assert_eq!(&result[2..], TEST_DNS_PAYLOAD);
    }

    #[tokio::test]
    async fn forward_query_passes_through_large_response() {
        let large_payload = vec![0xAB; FORWARDER_BUFFER_SIZE - 3];
        let (addr, _handle) = spawn_stub(StubBehavior::Echo).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![addr]).await.unwrap();
        forwarder.set_timeout(Duration::from_secs(2)).await;

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
        forwarder.set_upstreams(vec![first_addr]).await.unwrap();

        let request1 = make_dns_packet(0x1111, TEST_DNS_PAYLOAD);
        let r1 = forwarder.query(&request1).await.unwrap();
        assert_eq!(get_dns_id(&r1).unwrap(), 0x1111);

        forwarder.set_upstreams(vec![second_addr]).await.unwrap();

        let request2 = make_dns_packet(0x2222, TEST_DNS_PAYLOAD);
        let r2 = forwarder.query(&request2).await.unwrap();
        assert_eq!(get_dns_id(&r2).unwrap(), 0x2222);
    }

    #[tokio::test]
    async fn concurrent_queries_receive_responses() {
        let query_count = 20;
        let (stub_addr, _stub_handle) = spawn_multi_stub(query_count).await;

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(vec![stub_addr]).await.unwrap();
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
        forwarder.set_upstreams(vec![stub_addr]).await.unwrap();
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
        forwarder.set_upstreams(vec![addr]).await.unwrap();

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
            .await
            .unwrap();

        let result = forwarder.query(&[0x12]).await;
        match result {
            Err(ForwardError::PacketTooShort) => {}
            other => panic!("Expected PacketTooShort, got: {:?}", other),
        }
    }
}
