//! DNS over TCP forwarder.
//!
//! Terminates client TCP connections that arrive as raw IP packets
//! and relays DNS messages to an upstream resolver.
//!
//! A request is buffered until its frame is complete before any upstream is
//! contacted.
//!
//! A query for a `.nord` name is never forwarded.

pub(crate) mod engine;
pub(crate) mod frame;
pub(crate) mod proxy;
pub(crate) mod syn_backlog;

#[cfg(test)]
pub(crate) mod test_utils;

use crate::error::ForwardError;
use crate::tcp_forwarder::engine::engine_loop;
use crate::upstream::UpstreamList;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

// TODO: define channel size
/// Max size of ingress / egress channel size
const CHANNEL_SIZE: usize = 128;
// TODO: define pool size
/// Number of TCP listener sockets open
pub(crate) const TCP_POOL_SIZE: usize = 16;
/// Time a client may go without progress before its connection is dropped
pub(crate) const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeouts
#[derive(Clone, Copy)]
pub(crate) struct Timeouts {
    /// Time an upstream has to connect and answer a query.
    upstream_reply: Duration,
    /// Time a client may go without progress, or take to close, before it is dropped.
    client_idle: Duration,
}

impl Timeouts {
    pub(crate) fn new(upstream_reply: Duration, client_idle: Duration) -> Self {
        Timeouts {
            upstream_reply,
            client_idle,
        }
    }
}

/// DNS over TCP ingress forwarder.
#[derive(Clone, Debug)]
pub(crate) struct TcpForwarder {
    ingress: mpsc::Sender<Vec<u8>>,
}

impl TcpForwarder {
    /// Spawn the engine task and return the egress packet stream.
    pub(crate) fn new(
        upstreams: Arc<Mutex<UpstreamList>>,
        timeouts: Timeouts,
    ) -> (Self, mpsc::Receiver<Vec<u8>>) {
        Self::spawn(upstreams, TCP_POOL_SIZE, timeouts)
    }

    fn spawn(
        upstreams: Arc<Mutex<UpstreamList>>,
        pool_size: usize,
        timeouts: Timeouts,
    ) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (ingress_tx, ingress_rx) = mpsc::channel(CHANNEL_SIZE);
        let (egress_tx, egress_rx) = mpsc::channel(CHANNEL_SIZE);

        tokio::spawn(engine_loop(
            ingress_rx, egress_tx, upstreams, pool_size, timeouts,
        ));

        (
            TcpForwarder {
                ingress: ingress_tx,
            },
            egress_rx,
        )
    }

    /// Feed one decapsulated IPv4 TCP packet into the engine
    pub(crate) async fn send_packet(&self, pkt: Vec<u8>) -> Result<(), ForwardError> {
        self.ingress
            .send(pkt)
            .await
            .map_err(|_| ForwardError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nameserver::QUERY_TIMEOUT;
    use crate::tcp_forwarder::syn_backlog::SYN_BACKLOG_CAP;
    use crate::tcp_forwarder::test_utils::*;
    use pnet_packet::tcp::TcpFlags;
    use std::net::SocketAddr;
    use std::ops::Range;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::task::JoinHandle;

    fn new_forwarder(
        addrs: Vec<SocketAddr>,
        upstream_reply_timeout: Duration,
    ) -> (TcpForwarder, mpsc::Receiver<Vec<u8>>) {
        forwarder(
            addrs,
            TCP_POOL_SIZE,
            Timeouts::new(upstream_reply_timeout, CLIENT_IDLE_TIMEOUT),
        )
    }

    fn forwarder(
        addrs: Vec<SocketAddr>,
        pool_size: usize,
        timeouts: Timeouts,
    ) -> (TcpForwarder, mpsc::Receiver<Vec<u8>>) {
        let mut upstreams = UpstreamList::default();
        upstreams.set(addrs);
        TcpForwarder::spawn(Arc::new(Mutex::new(upstreams)), pool_size, timeouts)
    }

    async fn handshake(
        forwarder: &TcpForwarder,
        egress: &mut mpsc::Receiver<Vec<u8>>,
    ) -> TestClient {
        handshake_client(forwarder, egress, TestClient::new()).await
    }

    async fn handshake_client(
        forwarder: &TcpForwarder,
        egress: &mut mpsc::Receiver<Vec<u8>>,
        mut client: TestClient,
    ) -> TestClient {
        forwarder.send_packet(client.syn()).await.unwrap();
        let synack = recv_segment(egress).await;
        assert_ne!(synack.flags & TcpFlags::SYN, 0, "expected SYN");
        assert_ne!(synack.flags & TcpFlags::ACK, 0, "expected ACK");
        assert_eq!(synack.ack, client.seq, "SYN-ACK must acknowledge ISS + 1");
        client.absorb(&synack);
        forwarder.send_packet(client.ack()).await.unwrap();
        client
    }

    async fn fill_pool(
        forwarder: &TcpForwarder,
        egress: &mut mpsc::Receiver<Vec<u8>>,
        offsets: Range<u16>,
    ) {
        for i in offsets {
            handshake_client(
                forwarder,
                egress,
                TestClient::new_with_port(CLIENT_PORT + i),
            )
            .await;
        }
    }

    async fn forwarder_with_stub(
        read: usize,
        reply: &'static [u8],
    ) -> (
        TcpForwarder,
        mpsc::Receiver<Vec<u8>>,
        JoinHandle<Vec<u8>>,
        TestClient,
    ) {
        let (addr, upstream) = spawn_stub(StubBehavior::Answer { read, reply }).await;
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);
        let client = handshake(&forwarder, &mut egress).await;
        (forwarder, egress, upstream, client)
    }

    async fn assert_query_is_reset(addrs: Vec<SocketAddr>, upstream_reply_timeout: Duration) {
        let (forwarder, mut egress) = new_forwarder(addrs, upstream_reply_timeout);
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder
            .send_packet(client.data(&framed_query(&[b"example", b"com"])))
            .await
            .unwrap();

        recv_until(&mut egress, is_rst).await;
    }

    #[tokio::test]
    async fn proxies_bytes_to_upstream_and_back() {
        const QUERY: &[u8] = &[0x00, 0x03, 0xAA, 0xBB, 0xCC];
        const RESPONSE: &[u8] = &[0x00, 0x02, 0xDD, 0xEE];

        let (forwarder, mut egress, upstream, mut client) =
            forwarder_with_stub(QUERY.len(), RESPONSE).await;

        forwarder.send_packet(client.data(QUERY)).await.unwrap();

        assert_eq!(
            upstream_saw(upstream).await,
            QUERY,
            "upstream must see the exact client bytes"
        );
        assert_eq!(
            recv_until(&mut egress, has_payload).await.payload,
            RESPONSE,
            "client must see the exact upstream bytes"
        );
    }

    #[tokio::test]
    async fn upstream_sees_nothing_until_the_request_frames_complete() {
        let query = framed_query(&[b"example", b"com"]);
        let (forwarder, _egress, upstream, mut client) =
            forwarder_with_stub(query.len(), b"").await;

        let half = query.len() / 2;
        forwarder
            .send_packet(client.data(&query[..half]))
            .await
            .unwrap();
        tokio::time::sleep(SETTLE).await;
        assert!(
            !upstream.is_finished(),
            "a partial request must not be forwarded"
        );

        forwarder
            .send_packet(client.data(&query[half..]))
            .await
            .unwrap();
        assert_eq!(
            upstream_saw(upstream).await,
            query,
            "the whole frame must arrive at once"
        );
    }

    #[tokio::test]
    async fn two_pipelined_queries_forward_as_two_frames() {
        let first = framed_query(&[b"one", b"example", b"com"]);
        let second = framed_query(&[b"two", b"example", b"com"]);
        let mut both = first.clone();
        both.extend_from_slice(&second);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut seen = vec![0u8; first.len()];
            stream.read_exact(&mut seen).await.unwrap();
            stream.write_all(&frame(b"a")).await.unwrap();
            let mut rest = vec![0u8; second.len()];
            stream.read_exact(&mut rest).await.unwrap();
            seen.extend_from_slice(&rest);
            seen
        });

        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder.send_packet(client.data(&both)).await.unwrap();
        assert_eq!(
            upstream_saw(upstream).await,
            both,
            "both frames must reach the upstream, one query at a time"
        );
    }

    #[tokio::test]
    async fn many_pipelined_queries_split_mid_frame_reach_upstream_in_order() {
        const QUERIES: u8 = 40;
        const SEGMENT: usize = 1000;
        let queries: Vec<Vec<u8>> = (0..QUERIES)
            .map(|i| framed_query(&[&[b'a' + i % 26; 1], b"example", b"com"]))
            .collect();
        let all = queries.concat();
        assert_ne!(
            all.len() % SEGMENT,
            0,
            "segments must not line up with the stream end"
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let lens: Vec<usize> = queries.iter().map(Vec::len).collect();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            for len in lens {
                let mut query = vec![0u8; len];
                stream.read_exact(&mut query).await.unwrap();
                seen.extend_from_slice(&query);
                stream.write_all(&frame(b"a")).await.unwrap();
            }
            seen
        });

        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);
        let mut client = handshake(&forwarder, &mut egress).await;

        for chunk in all.chunks(SEGMENT) {
            forwarder.send_packet(client.data(chunk)).await.unwrap();
        }
        assert_eq!(
            upstream_saw(upstream).await,
            all,
            "every frame must reach the upstream whole and in order"
        );
    }

    #[tokio::test]
    async fn nord_query_is_reset() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder
            .send_packet(client.data(&framed_query(&[b"test", b"nord"])))
            .await
            .unwrap();

        recv_until(&mut egress, is_rst).await;
        assert!(
            tokio::time::timeout(SETTLE, listener.accept())
                .await
                .is_err(),
            "a .nord query must not even open an upstream connection"
        );
    }

    #[tokio::test]
    async fn no_upstreams_frees_the_socket_after_pipelined_queries() {
        let (forwarder, mut egress) = new_forwarder(vec![], QUERY_TIMEOUT);

        fill_pool(&forwarder, &mut egress, 1..TCP_POOL_SIZE as u16).await;
        let mut client = handshake(&forwarder, &mut egress).await;

        let mut pipelined = framed_query(&[b"example", b"com"]);
        pipelined.extend_from_slice(&framed_query(&[b"example", b"net"]));
        forwarder
            .send_packet(client.data(&pipelined))
            .await
            .unwrap();

        recv_until(&mut egress, is_rst).await;

        handshake_client(
            &forwarder,
            &mut egress,
            TestClient::new_with_port(CLIENT_PORT + TCP_POOL_SIZE as u16),
        )
        .await;
    }

    #[tokio::test]
    async fn all_upstreams_refused_resets_client() {
        let (dead1, _d1) = spawn_stub(StubBehavior::Refuse).await;
        let (dead2, _d2) = spawn_stub(StubBehavior::Refuse).await;

        assert_query_is_reset(vec![dead1, dead2], QUERY_TIMEOUT).await;
    }

    #[tokio::test]
    async fn all_upstreams_silent_resets_client() {
        let (silent1, _s1) = spawn_stub(StubBehavior::Silent).await;
        let (silent2, _s2) = spawn_stub(StubBehavior::Silent).await;

        assert_query_is_reset(vec![silent1, silent2], TEST_UPSTREAM_TIMEOUT).await;
    }

    #[tokio::test]
    async fn failover_connects_second_upstream_when_first_refuses() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x01, 0x02];

        let (dead, _dead_task) = spawn_stub(StubBehavior::Refuse).await;
        let (live, upstream) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: b"",
        })
        .await;
        let (forwarder, mut egress) = new_forwarder(vec![dead, live], QUERY_TIMEOUT);
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder.send_packet(client.data(QUERY)).await.unwrap();

        assert_eq!(
            upstream_saw(upstream).await,
            QUERY,
            "second upstream must receive the bytes"
        );
    }

    #[tokio::test]
    async fn failover_replays_query_to_next_upstream_when_first_is_silent() {
        const QUERY: &[u8] = &[0x00, 0x03, 0xAA, 0xBB, 0xCC];
        const RESPONSE: &[u8] = &[0x00, 0x02, 0xDD, 0xEE];

        let (live, upstream) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: RESPONSE,
        })
        .await;
        let (silent, _silent_task) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder(vec![silent, live], TEST_UPSTREAM_TIMEOUT);
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder.send_packet(client.data(QUERY)).await.unwrap();

        assert_eq!(
            upstream_saw(upstream).await,
            QUERY,
            "query must be replayed verbatim"
        );
        assert_eq!(
            recv_until(&mut egress, has_payload).await.payload,
            RESPONSE,
            "client must see the upstream reply"
        );
    }

    #[tokio::test]
    async fn client_fin_without_a_query_closes_without_reset() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder.send_packet(client.fin()).await.unwrap();

        let seg = recv_until(&mut egress, is_fin).await;
        assert!(!is_rst(&seg), "a clean FIN must not be a reset");
    }

    #[tokio::test]
    async fn query_followed_by_fin_is_still_forwarded() {
        let query = frame(b"hello");
        let (forwarder, _egress, upstream, mut client) =
            forwarder_with_stub(query.len(), b"").await;

        forwarder.send_packet(client.data(&query)).await.unwrap();
        forwarder.send_packet(client.fin()).await.unwrap();

        assert_eq!(upstream_saw(upstream).await, query);
    }

    #[tokio::test]
    async fn client_fin_closes_connection_when_upstream_holds_open() {
        const ANSWER: &[u8] = &[0x00, 0x01, b'a'];
        let query = frame(b"q");
        let (addr, _upstream) = spawn_stub(StubBehavior::AnswerAndHold {
            read: query.len(),
            reply: ANSWER,
        })
        .await;
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder.send_packet(client.data(&query)).await.unwrap();
        let seg = recv_until(&mut egress, has_payload).await;
        client.absorb(&seg);
        forwarder.send_packet(client.ack()).await.unwrap();

        forwarder.send_packet(client.fin()).await.unwrap();

        let seg = recv_until(&mut egress, is_fin).await;
        assert!(!is_rst(&seg), "a clean FIN, not a reset");
    }

    #[tokio::test]
    async fn stalled_request_is_aborted_and_frees_the_socket() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = forwarder(
            vec![addr],
            1,
            Timeouts::new(QUERY_TIMEOUT, TEST_CLIENT_IDLE_TIMEOUT),
        );
        let mut client = handshake(&forwarder, &mut egress).await;

        // Announce ten bytes, send two, then stop.
        forwarder
            .send_packet(client.data(&[0x00, 0x0A, 0xAA, 0xBB]))
            .await
            .unwrap();

        recv_until(&mut egress, is_rst).await;

        // A pool of one, so only the freed socket can accept this.
        handshake_client(
            &forwarder,
            &mut egress,
            TestClient::new_with_port(CLIENT_PORT + 1),
        )
        .await;
    }

    /// Close a query-less connection from the client side and ACK the server FIN,
    /// so its socket returns to the pool.
    async fn free_socket(
        forwarder: &TcpForwarder,
        egress: &mut mpsc::Receiver<Vec<u8>>,
        client: &mut TestClient,
    ) {
        forwarder.send_packet(client.fin()).await.unwrap();
        let fin = recv_until(egress, is_fin).await;
        client.absorb(&fin);
        forwarder.send_packet(client.ack()).await.unwrap();
    }

    async fn assert_no_egress(egress: &mut mpsc::Receiver<Vec<u8>>, why: &str) {
        if let Ok(Some(pkt)) = tokio::time::timeout(SETTLE, egress.recv()).await {
            panic!("{why}, got flags {:#04x}", parse_segment(&pkt).flags);
        }
    }

    #[tokio::test]
    async fn saturated_pool_holds_a_new_client_until_a_socket_frees() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);

        fill_pool(&forwarder, &mut egress, 1..TCP_POOL_SIZE as u16).await;
        let mut leaving = handshake(&forwarder, &mut egress).await;

        let waiting = TestClient::new_with_port(CLIENT_PORT + TCP_POOL_SIZE as u16);
        let mut syn_sender = TestClient::new_with_port(waiting.src_port);
        forwarder.send_packet(syn_sender.syn()).await.unwrap();
        assert_no_egress(
            &mut egress,
            "a SYN beyond the pool must be held, not answered",
        )
        .await;

        free_socket(&forwarder, &mut egress, &mut leaving).await;

        let synack = recv_until(&mut egress, is_synack).await;
        assert_eq!(
            synack.ack, syn_sender.seq,
            "the freed socket must accept the held SYN"
        );
    }

    #[tokio::test]
    async fn overflowing_the_syn_backlog_drops_without_reset() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);

        fill_pool(&forwarder, &mut egress, 0..TCP_POOL_SIZE as u16).await;
        let first = CLIENT_PORT + TCP_POOL_SIZE as u16;
        for port in first..=first + SYN_BACKLOG_CAP as u16 {
            let mut client = TestClient::new_with_port(port);
            forwarder.send_packet(client.syn()).await.unwrap();
        }

        assert_no_egress(
            &mut egress,
            "SYNs past the backlog must be dropped silently so the client retransmits",
        )
        .await;
    }

    #[tokio::test]
    async fn a_syn_from_a_connected_client_is_not_held() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);

        fill_pool(&forwarder, &mut egress, 2..TCP_POOL_SIZE as u16).await;
        let mut leaving = handshake_client(
            &forwarder,
            &mut egress,
            TestClient::new_with_port(CLIENT_PORT + 1),
        )
        .await;
        // Takes the last pool socket, so the freed one is matched first.
        let mut connected = TestClient::new();
        let original_syn = connected.syn();
        connected.seq = connected.seq.wrapping_sub(1);
        handshake_client(&forwarder, &mut egress, connected).await;

        forwarder.send_packet(original_syn).await.unwrap();
        free_socket(&forwarder, &mut egress, &mut leaving).await;

        assert_no_egress(
            &mut egress,
            "a connected client's SYN belongs to its socket and must not be held and replayed",
        )
        .await;
    }

    #[tokio::test]
    async fn message_started_late_in_an_idle_period_gets_the_full_timeout() {
        const IDLE: Duration = Duration::from_secs(1);
        let query = frame(b"late");
        let (addr, upstream) = spawn_stub(StubBehavior::Answer {
            read: query.len(),
            reply: b"",
        })
        .await;
        let (forwarder, mut egress) = forwarder(
            vec![addr],
            TCP_POOL_SIZE,
            Timeouts::new(QUERY_TIMEOUT, IDLE),
        );
        let mut client = handshake(&forwarder, &mut egress).await;

        // Split so the message completes past the idle deadline of the connection,
        // but within the one restarted by its first byte.
        tokio::time::sleep(IDLE * 8 / 10).await;
        forwarder
            .send_packet(client.data(&query[..3]))
            .await
            .unwrap();
        tokio::time::sleep(IDLE / 2).await;
        forwarder
            .send_packet(client.data(&query[3..]))
            .await
            .unwrap();

        assert_eq!(upstream_saw(upstream).await, query);
    }

    /// Keep the connection alive with bare ACKs, the way an attacker holding
    /// a pool socket would, until a segment matching `want` arrives.
    async fn keep_acking_until(
        forwarder: &TcpForwarder,
        egress: &mut mpsc::Receiver<Vec<u8>>,
        client: &TestClient,
        want: fn(&Segment) -> bool,
    ) -> Segment {
        let give_up = tokio::time::Instant::now() + TEST_WAIT;
        while tokio::time::Instant::now() < give_up {
            forwarder.send_packet(client.ack()).await.unwrap();
            if let Ok(Some(pkt)) =
                tokio::time::timeout(TEST_CLIENT_IDLE_TIMEOUT / 3, egress.recv()).await
            {
                let seg = parse_segment(&pkt);
                if want(&seg) {
                    return seg;
                }
            }
        }
        panic!("no matching segment while keeping the connection alive");
    }

    #[tokio::test]
    async fn idle_client_is_closed_and_its_socket_freed() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = forwarder(
            vec![addr],
            1,
            Timeouts::new(QUERY_TIMEOUT, TEST_CLIENT_IDLE_TIMEOUT),
        );
        let client = handshake(&forwarder, &mut egress).await;

        // Silent, so only the engine's own deadline can wake it.
        let fin = recv_until(&mut egress, is_fin).await;
        assert!(!is_rst(&fin), "an idle client must be closed, not reset");

        // Never acknowledge the FIN, but keep the connection alive.
        keep_acking_until(&forwarder, &mut egress, &client, is_rst).await;

        // A pool of one, so only the freed socket can accept this.
        handshake_client(
            &forwarder,
            &mut egress,
            TestClient::new_with_port(CLIENT_PORT + 1),
        )
        .await;
    }

    #[tokio::test]
    async fn client_not_reading_its_response_is_reset() {
        const ANSWER: &[u8] = &[0x00, 0x01, b'a'];
        let query = frame(b"q");
        let (addr, _upstream) = spawn_stub(StubBehavior::AnswerAndHold {
            read: query.len(),
            reply: ANSWER,
        })
        .await;
        let (forwarder, mut egress) = forwarder(
            vec![addr],
            TCP_POOL_SIZE,
            Timeouts::new(QUERY_TIMEOUT, TEST_CLIENT_IDLE_TIMEOUT),
        );
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder.send_packet(client.data(&query)).await.unwrap();
        assert_eq!(recv_until(&mut egress, has_payload).await.payload, ANSWER);

        // ACKs that never acknowledge the answer.
        keep_acking_until(&forwarder, &mut egress, &client, is_rst).await;
    }
}
