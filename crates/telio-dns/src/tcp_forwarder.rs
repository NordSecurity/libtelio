//! DNS-over-TCP ingress forwarder backed by smoltcp.
//!
//! Terminates client TCP connections that arrive as raw IP packets from the
//! WireGuard tunnel and relays DNS messages to an upstream resolver.
//!
//! A request is buffered until its frame is complete before any upstream is
//! contacted, and a response is withheld until its frame is complete before any
//! byte reaches the client.
//!
//! A query for a `.nord` name is never forwarded.

pub(crate) mod engine;
pub(crate) mod frame;
pub(crate) mod proxy;

#[cfg(test)]
pub(crate) mod test_utils;

use crate::error::ForwardError;
use crate::tcp_forwarder::engine::engine_loop;
use crate::upstream::UpstreamList;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

const CHANNEL_SIZE: usize = 128;

/// DNS-over-TCP ingress forwarder.
#[derive(Clone, Debug)]
pub(crate) struct TcpForwarder {
    ingress: mpsc::Sender<Vec<u8>>,
}

impl TcpForwarder {
    /// Spawn the engine task and return the egress packet stream.
    pub(crate) fn new(
        upstreams: Arc<Mutex<UpstreamList>>,
        upstream_reply_timeout: Duration,
        client_request_timeout: Duration,
    ) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (ingress_tx, ingress_rx) = mpsc::channel(CHANNEL_SIZE);
        let (egress_tx, egress_rx) = mpsc::channel(CHANNEL_SIZE);

        tokio::spawn(engine_loop(
            ingress_rx,
            egress_tx,
            upstreams,
            upstream_reply_timeout,
            client_request_timeout,
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
    use crate::tcp_forwarder::engine::{CLIENT_REQUEST_TIMEOUT, TCP_LISTEN_POOL};
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
        new_forwarder_with_client_timeout(addrs, upstream_reply_timeout, CLIENT_REQUEST_TIMEOUT)
    }

    fn new_forwarder_with_client_timeout(
        addrs: Vec<SocketAddr>,
        upstream_reply_timeout: Duration,
        client_request_timeout: Duration,
    ) -> (TcpForwarder, mpsc::Receiver<Vec<u8>>) {
        let mut upstreams = UpstreamList::default();
        upstreams.set(addrs);
        TcpForwarder::new(
            Arc::new(Mutex::new(upstreams)),
            upstream_reply_timeout,
            client_request_timeout,
        )
    }

    async fn handshake(
        forwarder: &TcpForwarder,
        egress: &mut mpsc::Receiver<Vec<u8>>,
    ) -> TestClient {
        handshake_client(forwarder, egress, TestClient::new()).await
    }

    /// Complete a handshake for a caller-supplied client, so tests can drive
    /// more than one simulated peer (distinct source ports) at once.
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

    /// Hold one pool socket per port offset with an idle but healthy
    /// connection.
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

    /// A forwarder plus a handshaken client, wired to one stub upstream.
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

    /// Drive one complete query into a fresh forwarder and expect a reset.
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
    async fn a_framed_non_dns_body_is_still_forwarded() {
        let garbage = frame(&[0xFF; 40]);
        let (forwarder, _egress, upstream, mut client) =
            forwarder_with_stub(garbage.len(), b"").await;

        forwarder.send_packet(client.data(&garbage)).await.unwrap();

        assert_eq!(upstream_saw(upstream).await, garbage);
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
    async fn no_upstreams_resets_client_on_first_query() {
        assert_query_is_reset(vec![], QUERY_TIMEOUT).await;
    }

    #[tokio::test]
    async fn no_upstreams_frees_the_socket_after_pipelined_queries() {
        let (forwarder, mut egress) = new_forwarder(vec![], QUERY_TIMEOUT);

        fill_pool(&forwarder, &mut egress, 1..TCP_LISTEN_POOL as u16).await;
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
            TestClient::new_with_port(CLIENT_PORT + TCP_LISTEN_POOL as u16),
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
    async fn client_fin_reaches_upstream_after_the_query() {
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

        // The upstream still holds its side open, so the only path to a FIN
        // is the client's own EOF through service_sockets and back as
        // ProxyEvent::Eof.
        let seg = recv_until(&mut egress, is_fin).await;
        assert!(!is_rst(&seg), "a clean FIN, not a reset");
    }

    #[tokio::test]
    async fn stalled_request_is_aborted_and_frees_the_socket() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder_with_client_timeout(
            vec![addr],
            QUERY_TIMEOUT,
            TEST_CLIENT_REQUEST_TIMEOUT,
        );

        fill_pool(&forwarder, &mut egress, 1..TCP_LISTEN_POOL as u16).await;
        let mut client = handshake(&forwarder, &mut egress).await;

        // Announce ten bytes, send two, then stop.
        forwarder
            .send_packet(client.data(&[0x00, 0x0A, 0xAA, 0xBB]))
            .await
            .unwrap();

        recv_until(&mut egress, is_rst).await;

        // Only the just-freed slot can accept this
        handshake_client(
            &forwarder,
            &mut egress,
            TestClient::new_with_port(CLIENT_PORT + TCP_LISTEN_POOL as u16),
        )
        .await;
    }

    #[tokio::test]
    async fn saturated_pool_rsts_a_new_client() {
        let (addr, _upstream) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder(vec![addr], QUERY_TIMEOUT);

        fill_pool(&forwarder, &mut egress, 0..TCP_LISTEN_POOL as u16).await;

        let mut refused = TestClient::new_with_port(CLIENT_PORT + TCP_LISTEN_POOL as u16);
        forwarder.send_packet(refused.syn()).await.unwrap();

        let seg = recv_segment(&mut egress).await;
        assert!(
            is_rst(&seg),
            "a saturated pool must refuse a new client with an RST, got flags {:#04x}",
            seg.flags,
        );
        assert_eq!(
            seg.ack, refused.seq,
            "the RST must acknowledge the refused SYN"
        );
    }

    #[tokio::test]
    async fn idle_connection_is_not_subject_to_the_request_deadline() {
        let query = framed_query(&[b"example", b"com"]);
        let (addr, upstream) = spawn_stub(StubBehavior::Answer {
            read: query.len(),
            reply: b"",
        })
        .await;
        let (silent, _silent_task) = spawn_stub(StubBehavior::Silent).await;
        let (forwarder, mut egress) = new_forwarder_with_client_timeout(
            vec![addr, silent],
            NO_DEADLINE,
            TEST_CLIENT_REQUEST_TIMEOUT,
        );
        let mut client = handshake(&forwarder, &mut egress).await;

        forwarder.send_packet(client.data(&query)).await.unwrap();
        assert_eq!(upstream_saw(upstream).await, query);

        // Well past the request deadline with nothing in flight.
        tokio::time::sleep(TEST_CLIENT_REQUEST_TIMEOUT * 3).await;
        forwarder.send_packet(client.ack()).await.unwrap();
        tokio::time::sleep(SETTLE).await;
        while let Ok(pkt) = egress.try_recv() {
            assert!(
                !is_rst(&parse_segment(&pkt)),
                "a boundary-idle connection must not be aborted"
            );
        }
    }
}
