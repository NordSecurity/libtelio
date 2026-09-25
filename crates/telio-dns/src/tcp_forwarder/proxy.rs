use crate::tcp_forwarder::frame::MessageReader;
use crate::upstream::{UpstreamCursor, UpstreamList};
use smoltcp::iface::SocketHandle;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

use telio_utils::{sleep_until, telio_log_debug, telio_log_trace, telio_log_warn, Instant};
use tokio::sync::{mpsc, Mutex};

pub(crate) const PROXY_CHUNK: usize = 4096;

/// Message from the client to an upstream proxy task.
#[derive(Debug)]
pub(crate) enum ClientMsg {
    /// One complete message frame from the client.
    Query(Vec<u8>),
    /// The client closed its write half.
    Eof,
}

/// Client side state carried across upstream attempts.
#[derive(Default)]
pub(crate) struct ProxyState {
    /// Framed query awaiting a complete response, resent on failover.
    pending: Option<Vec<u8>>,
    /// Framed query accepted from the client but not yet sent.
    queued: Option<Vec<u8>>,
    /// The client closed its write half.
    client_eof: bool,
    /// A complete response was relayed during the current upstream attempt.
    served: bool,
}

/// Event from an upstream proxy task back to the engine.
#[derive(Debug)]
pub(crate) enum ProxyEvent {
    /// One complete framed message from the upstream.
    Response(Vec<u8>),
    /// The upstream closed its write half.
    Eof,
    /// Connect failure.
    Error,
}

/// Outcome of a pipe task.
pub(crate) enum PipeOutcome {
    /// Reply received.
    Done,
    /// The upstream never completed, try the next one.
    NoReply,
    /// The upstream connection is gone and a query is pending.
    Reconnect,
}

/// A connected upstream, with the deadline for the attempt and address to retry.
pub(crate) struct UpstreamConnection {
    stream: TcpStream,
    deadline: Instant,
    address: SocketAddr,
    cursor: UpstreamCursor,
}

/// Advance `cursor` until an upstream connects.
async fn connect_next_upstream(
    cursor: &mut UpstreamCursor,
    upstreams: &Arc<Mutex<UpstreamList>>,
    upstream_reply_timeout: Duration,
) -> Option<UpstreamConnection> {
    loop {
        let picked_at = cursor.clone();
        let advance = {
            let current = upstreams.lock().await;
            cursor.advance(&current)
        };

        if advance.restarted {
            telio_log_debug!("TCP upstreams changed, restarting");
        }

        let address = advance.next?;
        let deadline = Instant::now() + upstream_reply_timeout;
        if let Some(stream) = connect_with_deadline(address, deadline).await {
            return Some(UpstreamConnection {
                stream,
                deadline,
                address,
                cursor: picked_at,
            });
        }
        telio_log_debug!("Trying next TCP upstream");
    }
}

/// Connect to one upstream giving up at `deadline`.
async fn connect_with_deadline(addr: SocketAddr, deadline: Instant) -> Option<TcpStream> {
    tokio::select! {
        res = connect_upstream(addr) => match res {
            Ok(stream) => Some(stream),
            Err(e) => {
                telio_log_warn!("TCP upstream connect to {addr} failed: {e}");
                None
            }
        },
        _ = sleep_until(deadline) => {
            telio_log_debug!("TCP upstream connect to {addr} timed out");
            None
        }
    }
}

/// Connect to the upstream resolver, bound to the tunnel interface.
async fn connect_upstream(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    crate::bind_tun::bind_to_tun(&socket)?;
    socket.connect(addr).await
}

/// Per connection proxy task.
///
/// Walks the configured upstream list until one
/// connects and replies, serializing queries through [`run_proxy_pipe`].
///
/// `generation` identifies this connection
/// so the engine can discard events from a past connections.
pub(crate) async fn run_proxy(
    upstreams: Arc<Mutex<UpstreamList>>,
    upstream_reply_timeout: Duration,
    handle: SocketHandle,
    generation: u64,
    mut from_engine: mpsc::Receiver<ClientMsg>,
    events: mpsc::Sender<(SocketHandle, u64, ProxyEvent)>,
) {
    let mut cursor = upstreams.lock().await.new_cursor();
    let mut state = ProxyState::default();
    let mut retry_cursor: Option<UpstreamCursor> = None;

    loop {
        if state.pending.is_none() && state.queued.is_none() {
            match from_engine.recv().await {
                Some(ClientMsg::Query(query)) => state.queued = Some(query),
                Some(ClientMsg::Eof) => {
                    let _ = events.send((handle, generation, ProxyEvent::Eof)).await;
                    return;
                }
                None => return,
            }
        }

        let from_reconnect = match retry_cursor.take() {
            Some(retry_cursor) => {
                cursor = retry_cursor;
                true
            }
            None => false,
        };

        let Some(UpstreamConnection {
            stream,
            deadline,
            address,
            cursor: picked_at,
        }) = connect_next_upstream(&mut cursor, &upstreams, upstream_reply_timeout).await
        else {
            break;
        };

        telio_log_trace!("TCP upstream {address} connected");

        match run_proxy_pipe(
            stream,
            handle,
            generation,
            &mut from_engine,
            &events,
            deadline,
            upstream_reply_timeout,
            &mut state,
        )
        .await
        {
            PipeOutcome::Done => return,
            PipeOutcome::Reconnect => {
                if state.served || !from_reconnect {
                    retry_cursor = Some(picked_at);
                } else {
                    telio_log_debug!("TCP upstream {address} keeps closing, trying next");
                }
            }
            PipeOutcome::NoReply => {
                if state.served {
                    // Answered before this attempt, keep the same cursor.
                    retry_cursor = Some(picked_at);
                } else {
                    telio_log_debug!("TCP upstream gave no reply, trying next");
                }
            }
        }
    }

    telio_log_warn!("All TCP upstreams exhausted ({:?})", handle);
    let _ = events.send((handle, generation, ProxyEvent::Error)).await;
}

/// Write to the upstream, giving up at `deadline`.
/// Returns false if the write failed.
async fn write_bounded<W>(writer: &mut W, bytes: &[u8], deadline: Instant) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    tokio::select! {
        res = writer.write_all(bytes) => res.is_ok(),
        _ = sleep_until(deadline) => false,
    }
}

/// Request and response pipe between the engine and a connected `stream`.
///
/// A response is relayed only once a frame is complete.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_proxy_pipe<S>(
    stream: S,
    handle: SocketHandle,
    generation: u64,
    from_engine: &mut mpsc::Receiver<ClientMsg>,
    events: &mpsc::Sender<(SocketHandle, u64, ProxyEvent)>,
    first_reply_deadline: Instant,
    upstream_reply_timeout: Duration,
    state: &mut ProxyState,
) -> PipeOutcome
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut read_buf = vec![0u8; PROXY_CHUNK];
    let mut from_upstream = MessageReader::default();
    let mut deadline: Option<Instant> = None;
    let mut upstream_gone = false;
    let mut first_query = true;

    state.served = false;

    loop {
        if state.queued.is_none() {
            match from_engine.try_recv() {
                Ok(ClientMsg::Query(query)) => state.queued = Some(query),
                Ok(ClientMsg::Eof) => state.client_eof = true,
                Err(_) => {}
            }
        }

        if deadline.is_none() {
            if state.pending.is_none() {
                state.pending = state.queued.take();
            }
            if let Some(query) = state.pending.as_deref() {
                if upstream_gone {
                    return PipeOutcome::Reconnect;
                }
                let query_deadline = if first_query {
                    first_query = false;
                    first_reply_deadline
                } else {
                    Instant::now() + upstream_reply_timeout
                };
                if !write_bounded(&mut writer, query, query_deadline).await {
                    return PipeOutcome::NoReply;
                }
                deadline = Some(query_deadline);
                continue;
            }
            if state.client_eof {
                let _ = events.send((handle, generation, ProxyEvent::Eof)).await;
                return PipeOutcome::Done;
            }
        }

        tokio::select! {
            // At most one query is accepted ahead of the outstanding one
            msg = from_engine.recv(), if state.queued.is_none() => match msg {
                Some(ClientMsg::Query(query)) => state.queued = Some(query),
                Some(ClientMsg::Eof) => state.client_eof = true,
                None => return PipeOutcome::Done,
            },
            n = reader.read(&mut read_buf), if !upstream_gone => match n {
                Ok(0) => {
                    if state.pending.is_some() {
                        // Midframe EOF truncated a response.
                        return if from_upstream.partial_len() > 0 {
                            PipeOutcome::NoReply
                        } else {
                            PipeOutcome::Reconnect
                        };
                    }
                    upstream_gone = true;
                }
                Ok(n) => {
                    if state.pending.is_none() {
                        telio_log_warn!("Unsolicited TCP DNS bytes from upstream, dropping it");
                        return PipeOutcome::NoReply;
                    }
                    let Some(chunk) = read_buf.get(..n) else {
                        return PipeOutcome::NoReply;
                    };
                    from_upstream.push(chunk);
                    let Some(response) = from_upstream.next_frame() else {
                        continue;
                    };
                    if from_upstream.partial_len() > 0 {
                        telio_log_warn!("Upstream answered query more than once, dropping it");
                        return PipeOutcome::NoReply;
                    }
                    state.pending = None;
                    state.served = true;
                    deadline = None;
                    if events
                        .send((handle, generation, ProxyEvent::Response(response)))
                        .await
                        .is_err()
                    {
                        return PipeOutcome::Done;
                    }
                }
                Err(e) => {
                    telio_log_debug!("TCP upstream read failed: {e}");
                    if state.pending.is_some() {
                        return PipeOutcome::NoReply;
                    }
                    upstream_gone = true;
                }
            },
            _ = async {
                match deadline {
                    Some(dl) => sleep_until(dl).await,
                    None => std::future::pending().await,
                }
            }, if deadline.is_some() => {
                return PipeOutcome::NoReply;
            }
            // Every arm above is conditional and `select!` panics if all
            // are disabled at once, exit cleanly instead.
            else => {
                return PipeOutcome::NoReply;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_forwarder::test_utils::{
        frame, recv_event, response_bytes, spawn_stub, test_handle, upstream_saw, StubBehavior,
    };
    use crate::tcp_forwarder::test_utils::{
        AFTER_DEADLINE, DUPLEX_BUF, LAPSED_AGO, NO_DEADLINE, SETTLE, TEST_REPLY_WINDOW,
        TEST_UPSTREAM_TIMEOUT, TEST_WAIT,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::task::JoinHandle;

    pub(crate) const EVENTS_CAP: usize = 16;
    pub(crate) const TO_UPSTREAM_CAP: usize = 2;

    /// One `run_proxy_pipe` task, with the upstream
    /// end of the stream and both channel ends handed back.
    struct Pipe {
        task: JoinHandle<(PipeOutcome, ProxyState)>,
        upstream: tokio::io::DuplexStream,
        client: mpsc::Sender<ClientMsg>,
        events: mpsc::Receiver<(SocketHandle, u64, ProxyEvent)>,
        handle: SocketHandle,
    }

    fn spawn_pipe(generation: u64) -> Pipe {
        spawn_pipe_until(generation, Instant::now() + NO_DEADLINE)
    }

    fn spawn_pipe_until(generation: u64, first_reply_deadline: Instant) -> Pipe {
        let (stream, peer) = tokio::io::duplex(DUPLEX_BUF);
        let (to_pipe, mut from_engine) = mpsc::channel(TO_UPSTREAM_CAP);
        let (events_tx, events) = mpsc::channel(EVENTS_CAP);
        let handle = test_handle();
        let task = tokio::spawn(async move {
            let mut state = ProxyState::default();
            let outcome = run_proxy_pipe(
                stream,
                handle,
                generation,
                &mut from_engine,
                &events_tx,
                first_reply_deadline,
                TEST_UPSTREAM_TIMEOUT,
                &mut state,
            )
            .await;
            (outcome, state)
        });
        Pipe {
            task,
            upstream: peer,
            client: to_pipe,
            events,
            handle,
        }
    }

    async fn finish(task: JoinHandle<(PipeOutcome, ProxyState)>) -> (PipeOutcome, ProxyState) {
        tokio::time::timeout(TEST_WAIT, task)
            .await
            .expect("the pipe must return")
            .unwrap()
    }

    async fn expect_query(pipe: &mut Pipe, query: &[u8]) {
        pipe.client
            .send(ClientMsg::Query(query.to_vec()))
            .await
            .unwrap();
        let mut seen = vec![0u8; query.len()];
        pipe.upstream.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, query, "the query must be forwarded verbatim");
    }

    fn spawn_proxy(
        addrs: Vec<SocketAddr>,
    ) -> (
        mpsc::Sender<ClientMsg>,
        mpsc::Receiver<(SocketHandle, u64, ProxyEvent)>,
    ) {
        let mut upstreams = UpstreamList::default();
        upstreams.set(addrs);
        spawn_proxy_on(Arc::new(Mutex::new(upstreams)))
    }

    fn spawn_proxy_on(
        upstreams: Arc<Mutex<UpstreamList>>,
    ) -> (
        mpsc::Sender<ClientMsg>,
        mpsc::Receiver<(SocketHandle, u64, ProxyEvent)>,
    ) {
        let (to_proxy, from_engine) = mpsc::channel(TO_UPSTREAM_CAP);
        let (events_tx, events) = mpsc::channel(EVENTS_CAP);
        tokio::spawn(run_proxy(
            upstreams,
            TEST_UPSTREAM_TIMEOUT,
            test_handle(),
            1,
            from_engine,
            events_tx,
        ));
        (to_proxy, events)
    }

    #[tokio::test]
    async fn proxy_pipe_forwards_a_frame_and_returns_the_whole_response() {
        let expected_generation = 7;
        let mut pipe = spawn_pipe(expected_generation);
        let answer = frame(b"answer");

        expect_query(&mut pipe, &frame(b"query")).await;

        let half = answer.len() / 2;
        pipe.upstream.write_all(&answer[..half]).await.unwrap();
        tokio::time::sleep(SETTLE).await;
        assert!(
            pipe.events.try_recv().is_err(),
            "nothing may be emitted mid-frame"
        );

        // write the rest
        pipe.upstream.write_all(&answer[half..]).await.unwrap();
        let (handle, generation, event) = recv_event(&mut pipe.events).await;
        assert_eq!(handle, pipe.handle);
        assert_eq!(generation, expected_generation);
        assert_eq!(response_bytes(event), answer);
    }

    #[tokio::test]
    async fn partial_response_is_withheld_and_fails_over() {
        let query = frame(b"q");
        let answer = frame(b"answer");
        let mut pipe = spawn_pipe_until(1, Instant::now() + TEST_REPLY_WINDOW);

        // The query must go out before the partial response is written, or
        // the write races the pipe's unsolicited-bytes check.
        expect_query(&mut pipe, &query).await;
        pipe.upstream
            .write_all(&answer[..answer.len() / 2])
            .await
            .unwrap();

        let (outcome, state) = finish(pipe.task).await;
        assert!(matches!(outcome, PipeOutcome::NoReply));
        assert!(
            pipe.events.try_recv().is_err(),
            "a partial response must never reach the client"
        );
        assert_eq!(
            state.pending.as_deref(),
            Some(query.as_slice()),
            "the query must stay replayable"
        );
    }

    #[tokio::test]
    async fn silent_upstream_fails_over_and_keeps_the_query_replayable() {
        let query = frame(b"query");

        // A deadline still to come, then one already lapsed.
        for deadline in [
            Instant::now() + TEST_REPLY_WINDOW,
            Instant::now() - LAPSED_AGO,
        ] {
            let pipe = spawn_pipe_until(1, deadline);
            pipe.client
                .send(ClientMsg::Query(query.clone()))
                .await
                .unwrap();

            let (outcome, state) = finish(pipe.task).await;
            assert!(matches!(outcome, PipeOutcome::NoReply));
            assert_eq!(
                state.pending.as_deref(),
                Some(query.as_slice()),
                "client bytes must be kept for the next upstream"
            );
        }
    }

    #[tokio::test]
    async fn idle_client_does_not_trigger_failover() {
        let pipe = spawn_pipe_until(1, Instant::now() + TEST_REPLY_WINDOW);
        assert!(
            tokio::time::timeout(AFTER_DEADLINE, pipe.task)
                .await
                .is_err(),
            "a client that has not asked anything must not fail over"
        );
    }

    #[tokio::test]
    async fn stalled_upstream_write_fails_over() {
        // Payload far larger than the duplex, so write_all cannot complete.
        let pipe = spawn_pipe_until(1, Instant::now() + TEST_REPLY_WINDOW);
        pipe.client
            .send(ClientMsg::Query(frame(&vec![0u8; PROXY_CHUNK])))
            .await
            .unwrap();

        let (outcome, _) = finish(pipe.task).await;
        assert!(
            matches!(outcome, PipeOutcome::NoReply),
            "a write that cannot drain must fail over"
        );
    }

    #[tokio::test]
    async fn pipe_exits_after_engine_drops_connection_post_eof() {
        let mut pipe = spawn_pipe(0);

        expect_query(&mut pipe, &frame(b"hello")).await;
        pipe.client.send(ClientMsg::Eof).await.unwrap();
        tokio::time::sleep(SETTLE).await;
        drop(pipe.client);

        let (outcome, _) = finish(pipe.task).await;
        assert!(
            matches!(outcome, PipeOutcome::Done),
            "engine drop must not be reported as a failover"
        );

        let mut probe = [0u8; 1];
        let n = pipe.upstream.read(&mut probe).await.unwrap();
        assert_eq!(n, 0, "pipe exit must drop the upstream stream");
    }

    #[tokio::test]
    async fn second_query_waits_for_the_first_response() {
        let mut pipe = spawn_pipe(11);
        let first = frame(b"one");
        let second = frame(b"two");

        pipe.client
            .send(ClientMsg::Query(first.clone()))
            .await
            .unwrap();
        pipe.client
            .send(ClientMsg::Query(second.clone()))
            .await
            .unwrap();

        let mut seen = vec![0u8; first.len()];
        pipe.upstream.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, first);

        let mut probe = [0u8; 1];
        assert!(
            tokio::time::timeout(SETTLE, pipe.upstream.read(&mut probe))
                .await
                .is_err(),
            "the second query must not be sent before the first is answered"
        );

        pipe.upstream
            .write_all(&frame(b"answer-one"))
            .await
            .unwrap();
        let mut seen = vec![0u8; second.len()];
        pipe.upstream.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, second, "the queued query follows the first response");
    }

    #[tokio::test]
    async fn boundary_close_while_idle_asks_for_a_reconnect() {
        let query = frame(b"q");
        let pipe = spawn_pipe(1);

        // Close before any query: the pipe is idle at a boundary.
        drop(pipe.upstream);
        tokio::time::sleep(SETTLE).await;
        pipe.client
            .send(ClientMsg::Query(query.clone()))
            .await
            .unwrap();

        let (outcome, state) = finish(pipe.task).await;
        assert!(matches!(outcome, PipeOutcome::Reconnect));
        assert_eq!(
            state.pending.as_deref(),
            Some(query.as_slice()),
            "the query must survive for the reconnect"
        );
    }

    #[tokio::test]
    async fn unsolicited_upstream_bytes_drop_the_upstream_not_the_client() {
        let mut pipe = spawn_pipe(13);

        pipe.upstream.write_all(&frame(b"unasked")).await.unwrap();

        let (outcome, state) = finish(pipe.task).await;
        assert!(matches!(outcome, PipeOutcome::NoReply));
        assert!(state.pending.is_none(), "nothing was outstanding");
        assert!(
            pipe.events.try_recv().is_err(),
            "a rude upstream is this attempt's failure, not the client's"
        );
    }

    #[tokio::test]
    async fn upstream_answering_one_query_twice_fails_over() {
        let query = frame(b"q");
        let mut pipe = spawn_pipe(9);
        let answer = frame(b"a");
        let mut twice = answer.clone();
        twice.extend_from_slice(&answer);

        expect_query(&mut pipe, &query).await;

        pipe.upstream.write_all(&twice).await.unwrap();

        let (outcome, state) = finish(pipe.task).await;
        assert!(matches!(outcome, PipeOutcome::NoReply));
        assert_eq!(
            state.pending.as_deref(),
            Some(query.as_slice()),
            "the query must survive for the next upstream"
        );
        assert!(
            pipe.events.try_recv().is_err(),
            "neither copy of a doubled response may reach the client"
        );
    }

    #[tokio::test]
    async fn client_eof_while_idle_closes_the_connection() {
        let mut pipe = spawn_pipe(12);

        pipe.client.send(ClientMsg::Eof).await.unwrap();

        let (_, _, event) = recv_event(&mut pipe.events).await;
        assert!(matches!(event, ProxyEvent::Eof), "got {:?}", event);
        let (outcome, _) = finish(pipe.task).await;
        assert!(matches!(outcome, PipeOutcome::Done));
    }

    #[tokio::test]
    async fn failover_when_upstream_closes_before_the_query() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];

        let (live, upstream) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: b"",
        })
        .await;
        let (hangup, _hangup_task) = spawn_stub(StubBehavior::Hangup).await;
        let (to_proxy, _events) = spawn_proxy(vec![hangup, live]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();

        assert_eq!(
            upstream_saw(upstream).await,
            QUERY,
            "an upstream that hangs up must not strand the query"
        );
    }

    #[tokio::test]
    async fn boundary_close_retries_the_same_upstream() {
        const QUERY: &[u8] = &[0x00, 0x01, 0xAA];
        const REPLY: &[u8] = &[0x00, 0x01, 0xBB];

        let (addr, upstream) = spawn_stub(StubBehavior::AnswerThenClose {
            read: QUERY.len(),
            reply: REPLY,
        })
        .await;
        let (to_proxy, mut events) = spawn_proxy(vec![addr]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, first) = recv_event(&mut events).await;
        assert_eq!(response_bytes(first), REPLY);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, second) = recv_event(&mut events).await;
        assert_eq!(response_bytes(second), REPLY);

        assert_eq!(upstream_saw(upstream).await, [QUERY, QUERY].concat());
    }

    #[tokio::test]
    async fn a_transient_timeout_does_not_use_up_the_only_upstream() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];
        const REPLY: &[u8] = &[0x00, 0x01, 0xBB];

        let (addr, _task) = spawn_stub(StubBehavior::AnswerFirstThenIgnore {
            read: QUERY.len(),
            reply: REPLY,
        })
        .await;
        let (to_proxy, mut events) = spawn_proxy(vec![addr]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, first) = recv_event(&mut events).await;
        assert_eq!(response_bytes(first), REPLY);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, second) = recv_event(&mut events).await;
        assert_eq!(response_bytes(second), REPLY);
    }

    #[tokio::test]
    async fn a_working_upstream_stays_first_choice() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];
        const REPLY: &[u8] = &[0x00, 0x01, 0xBB];

        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let (good, _good_task) = spawn_stub(StubBehavior::AnswerFirstThenIgnore {
            read: QUERY.len(),
            reply: REPLY,
        })
        .await;
        let (to_proxy, mut events) = spawn_proxy(vec![silent_addr, good]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, first) = recv_event(&mut events).await;
        assert_eq!(response_bytes(first), REPLY);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, second) = recv_event(&mut events).await;
        assert_eq!(response_bytes(second), REPLY);

        let _dialed_once = tokio::time::timeout(TEST_WAIT, silent.accept())
            .await
            .expect("the head of the list must have been tried first")
            .unwrap();
        assert!(
            tokio::time::timeout(SETTLE, silent.accept()).await.is_err(),
            "an upstream that answered must keep its place, not hand the lead \
             back to one that already lapsed"
        );
    }

    #[tokio::test]
    async fn a_removed_upstream_is_not_reconnected_to() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];
        const REMOVED: &[u8] = &[0x00, 0x01, 0xAA];
        const ADDED: &[u8] = &[0x00, 0x01, 0xBB];

        let (removed, _removed_task) = spawn_stub(StubBehavior::AnswerThenClose {
            read: QUERY.len(),
            reply: REMOVED,
        })
        .await;
        let (added, _added_task) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: ADDED,
        })
        .await;

        let mut listed = UpstreamList::default();
        listed.set(vec![removed]);
        let upstreams = Arc::new(Mutex::new(listed));
        let (to_proxy, mut events) = spawn_proxy_on(upstreams.clone());

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, first) = recv_event(&mut events).await;
        assert_eq!(response_bytes(first), REMOVED);

        upstreams.lock().await.set(vec![added]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, second) = recv_event(&mut events).await;
        assert_eq!(
            response_bytes(second),
            ADDED,
            "a reconnect must not outlive the resolver it was for"
        );
    }

    #[tokio::test]
    async fn client_eof_after_pending_query_still_replays_on_failover() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];

        let (live, upstream) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: b"",
        })
        .await;
        let (silent, _silent_task) = spawn_stub(StubBehavior::Silent).await;
        let (to_proxy, _events) = spawn_proxy(vec![silent, live]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        to_proxy.send(ClientMsg::Eof).await.unwrap();

        assert_eq!(
            upstream_saw(upstream).await,
            QUERY,
            "a pending query must survive client EOF and reach the next upstream"
        );
    }

    #[tokio::test]
    async fn upstream_that_speaks_before_being_asked_does_not_kill_failover() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];
        const REPLY: &[u8] = &[0x00, 0x01, 0xBB];

        let (live, upstream) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: REPLY,
        })
        .await;
        let (rude, _rude_task) = spawn_stub(StubBehavior::SpeaksFirst { reply: b"\xFF" }).await;
        let (to_proxy, mut events) = spawn_proxy(vec![rude, live]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();

        let (_, _, event) = recv_event(&mut events).await;
        assert_eq!(
            response_bytes(event),
            REPLY,
            "an upstream that speaks before being asked must not abort the \
             connection with no failover"
        );
        assert_eq!(upstream_saw(upstream).await, QUERY);
    }

    #[tokio::test]
    async fn unsolicited_bytes_on_an_idle_upstream_fail_over_to_the_next() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];
        const FIRST: &[u8] = &[0x00, 0x01, 0xAA];
        const SECOND: &[u8] = &[0x00, 0x01, 0xBB];

        let (rude, _rude_task) = spawn_stub(StubBehavior::AnswerThenSpeakUnasked {
            read: QUERY.len(),
            reply: FIRST,
            unsolicited: b"\xFF",
        })
        .await;
        let (live, _live_task) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: SECOND,
        })
        .await;
        let (to_proxy, mut events) = spawn_proxy(vec![rude, live]);

        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, first) = recv_event(&mut events).await;
        assert_eq!(response_bytes(first), FIRST);

        tokio::time::sleep(SETTLE * 3).await;
        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .expect("the client connection must have outlived the rude upstream");

        let (_, _, second) = recv_event(&mut events).await;
        assert_eq!(
            response_bytes(second),
            SECOND,
            "a rude idle upstream must cost the client nothing but that upstream"
        );
    }

    #[tokio::test]
    async fn pre_opened_connection_is_answered_after_an_idle_period() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];
        const REPLY: &[u8] = &[0x00, 0x01, 0xBB];

        let (addr, _task) = spawn_stub(StubBehavior::AnswerAndHold {
            read: QUERY.len(),
            reply: REPLY,
        })
        .await;
        let (to_proxy, mut events) = spawn_proxy(vec![addr]);

        tokio::time::sleep(TEST_UPSTREAM_TIMEOUT + SETTLE).await;
        to_proxy
            .send(ClientMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();

        let (_, _, event) = recv_event(&mut events).await;
        assert_eq!(
            response_bytes(event),
            REPLY,
            "a query must not inherit a deadline from before it existed"
        );
    }

    #[tokio::test]
    async fn client_eof_before_any_query_never_dials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (to_proxy, mut events) = spawn_proxy(vec![addr]);

        to_proxy.send(ClientMsg::Eof).await.unwrap();

        let (_, _, event) = recv_event(&mut events).await;
        assert!(matches!(event, ProxyEvent::Eof), "got {:?}", event);
        assert!(
            tokio::time::timeout(SETTLE, listener.accept())
                .await
                .is_err(),
            "a client that never asked must not cost an upstream connection"
        );
    }

    #[tokio::test]
    async fn engine_drop_before_any_query_is_not_an_error() {
        let (silent, _silent_task) = spawn_stub(StubBehavior::Silent).await;
        let (to_proxy, mut events) = spawn_proxy(vec![silent]);

        drop(to_proxy);

        match tokio::time::timeout(SETTLE, events.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some((_, _, event))) => panic!(
                "a client that went away without asking is not a failure \
                 to serve, got {:?}",
                event
            ),
        }
    }
}
