use crate::tcp_forwarder::frame::MessageReader;
use crate::upstream::{UpstreamCursor, UpstreamList};
use smoltcp::iface::SocketHandle;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use telio_utils::{sleep_until, telio_log_debug, telio_log_warn, Instant};
use tokio::sync::{mpsc, Mutex};

pub(crate) const PROXY_CHUNK: usize = 4096;
/// Shared proxy-event channel capacity, upstream to engine.
/// Each slot holds a whole frame, up to 65537 bytes.
pub(crate) const EVENTS_CAP: usize = 16;
/// Per connection client to upstream channel capacity.
pub(crate) const TO_UPSTREAM_CAP: usize = 2;

/// Message from the engine to a connection's upstream proxy task.
#[derive(Debug)]
pub(crate) enum UpstreamMsg {
    /// One complete framed message from the client, prefix included.
    Query(Vec<u8>),
    /// The client closed its write half; no further queries will arrive.
    Eof,
}

/// Client-side state carried across upstream attempts.
#[derive(Default)]
pub(crate) struct ProxyState {
    /// Framed query awaiting a complete response, resent on failover.
    pending: Option<Vec<u8>>,
    /// One framed query accepted while `pending` was outstanding.
    queued: Option<Vec<u8>>,
    /// The client already closed its write half.
    client_eof: bool,
    /// A complete response was relayed during the current upstream attempt.
    served: bool,
}

/// Event from an upstream proxy task back to the engine.
#[derive(Debug)]
pub(crate) enum ProxyEvent {
    /// One complete framed message from the upstream, prefix included.
    Response(Vec<u8>),
    /// The upstream closed its write half.
    Eof,
    /// Connect failure or I/O error: abort the client connection.
    Error,
}

pub(crate) enum PipeOutcome {
    Done,
    /// The upstream never completed, try the next one.
    NoReply,
    /// The upstream connection is gone, either closed at a message
    /// boundary or lost to a read error, and a query is pending.
    Reconnect,
}

/// Connect to the upstream resolver, bound to the tunnel interface.
async fn connect_upstream(addr: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    crate::bind_tun::bind_to_tun(&socket)?;
    socket.connect(addr).await
}

/// Connect to one upstream giving up at `deadline`.
async fn connect_with_deadline(
    addr: SocketAddr,
    deadline: Instant,
) -> Option<tokio::net::TcpStream> {
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

/// Advance `cursor` until an upstream connects.
///
/// Returns the connected stream, the attempt's deadline, and the address, which
/// the caller retries in place after a boundary close.
async fn connect_next_upstream(
    cursor: &mut UpstreamCursor,
    upstreams: &Arc<Mutex<UpstreamList>>,
    upstream_reply_timeout: Duration,
) -> Option<(tokio::net::TcpStream, Instant, SocketAddr)> {
    loop {
        let advance = {
            let current = upstreams.lock().await;
            cursor.advance(&current)
        };

        if advance.restarted {
            telio_log_debug!("TCP upstreams changed, restarting from index 0");
        }

        let addr = advance.next?;
        let deadline = Instant::now() + upstream_reply_timeout;
        if let Some(stream) = connect_with_deadline(addr, deadline).await {
            return Some((stream, deadline, addr));
        }
        telio_log_debug!("Trying next TCP upstream after {addr}");
    }
}

/// Per-connection proxy task: walks the configured upstream list until one
/// connects and replies, serializing queries through [`run_proxy_pipe`].
///
/// `generation` identifies this connection's occupancy of the pool,
/// it is echoed back so the engine can discard events from a past connection.
pub(crate) async fn run_proxy(
    upstreams: Arc<Mutex<UpstreamList>>,
    upstream_reply_timeout: Duration,
    handle: SocketHandle,
    generation: u64,
    mut from_engine: mpsc::Receiver<UpstreamMsg>,
    events: mpsc::Sender<(SocketHandle, u64, ProxyEvent)>,
) {
    let mut cursor = upstreams.lock().await.new_cursor();
    let mut state = ProxyState::default();
    // Address to retry  a boundary close and whether the current
    // attempt is itself such a retry.
    let mut reconnect_to: Option<SocketAddr> = None;
    let mut from_reconnect;

    loop {
        let retried = match reconnect_to.take() {
            Some(addr) => {
                let deadline = Instant::now() + upstream_reply_timeout;
                connect_with_deadline(addr, deadline)
                    .await
                    .map(|stream| (stream, deadline, addr))
            }
            None => None,
        };
        let (stream, deadline, addr) = match retried {
            Some(connected) => {
                from_reconnect = true;
                connected
            }
            None => {
                match connect_next_upstream(&mut cursor, &upstreams, upstream_reply_timeout).await {
                    Some(connected) => {
                        from_reconnect = false;
                        connected
                    }
                    None => break,
                }
            }
        };

        telio_log_debug!(
            "TCP upstream {addr} connected (handle {:?}, gen {})",
            handle,
            generation,
        );

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
                    reconnect_to = Some(addr);
                } else {
                    telio_log_debug!("TCP upstream {addr} keeps closing, trying next");
                }
            }
            PipeOutcome::NoReply => telio_log_debug!(
                "TCP upstream gave no reply (handle {:?}), trying next",
                handle,
            ),
        }
    }

    telio_log_warn!("All TCP upstreams exhausted (handle {:?})", handle);
    let _ = events.send((handle, generation, ProxyEvent::Error)).await;
}

/// Write to the upstream, giving up at `deadline`.
/// Returns false if the upstream failed.
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

/// Request and response pipe between the engine (`from_engine`/`events`) and an
/// already-connected `stream`.
///
/// One query is outstanding at a time.
/// A response is relayed only if frame is complete.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_proxy_pipe<S>(
    stream: S,
    handle: SocketHandle,
    generation: u64,
    from_engine: &mut mpsc::Receiver<UpstreamMsg>,
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
        // Take a message the engine has already handed us before interpreting
        // any upstream bytes.
        if state.queued.is_none() {
            match from_engine.try_recv() {
                Ok(UpstreamMsg::Query(query)) => state.queued = Some(query),
                Ok(UpstreamMsg::Eof) => state.client_eof = true,
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
                Some(UpstreamMsg::Query(query)) => state.queued = Some(query),
                Some(UpstreamMsg::Eof) => state.client_eof = true,
                None => return PipeOutcome::Done,
            },
            n = reader.read(&mut read_buf), if !upstream_gone => match n {
                Ok(0) => {
                    if state.pending.is_some() {
                        // Mid-frame EOF truncated a response.
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
                        telio_log_warn!("Unsolicited TCP DNS bytes from upstream, aborting");
                        let _ = events.send((handle, generation, ProxyEvent::Error)).await;
                        return PipeOutcome::Done;
                    }
                    let Some(chunk) = read_buf.get(..n) else {
                        return PipeOutcome::NoReply;
                    };
                    from_upstream.push(chunk);
                    let Some(response) = from_upstream.next_frame() else {
                        continue;
                    };
                    if from_upstream.partial_len() > 0 {
                        telio_log_warn!("Upstream answered query more than once, aborting");
                        let _ = events.send((handle, generation, ProxyEvent::Error)).await;
                        return PipeOutcome::Done;
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
                let _ = events.send((handle, generation, ProxyEvent::Error)).await;
                return PipeOutcome::Done;
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
        AFTER_DEADLINE, DUPLEX_BUF, LAPSED_AGO, LATE_QUERY_DELAY, NO_DEADLINE, SETTLE,
        TEST_REPLY_WINDOW, TEST_UPSTREAM_TIMEOUT, TEST_WAIT,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::task::JoinHandle;

    /// One `run_proxy_pipe` task over an in-memory duplex, with the upstream
    /// end of the stream and both channel ends handed back.
    struct Pipe {
        task: JoinHandle<(PipeOutcome, ProxyState)>,
        peer: tokio::io::DuplexStream,
        to_pipe: mpsc::Sender<UpstreamMsg>,
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
            peer,
            to_pipe,
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

    /// Send `query` and read it back off the upstream end of the pipe.
    async fn expect_query(pipe: &mut Pipe, query: &[u8]) {
        pipe.to_pipe
            .send(UpstreamMsg::Query(query.to_vec()))
            .await
            .unwrap();
        let mut seen = vec![0u8; query.len()];
        pipe.peer.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, query, "the query must be forwarded verbatim");
    }

    fn spawn_proxy(
        addrs: Vec<SocketAddr>,
    ) -> (
        mpsc::Sender<UpstreamMsg>,
        mpsc::Receiver<(SocketHandle, u64, ProxyEvent)>,
    ) {
        let mut upstreams = UpstreamList::default();
        upstreams.set(addrs);
        let (to_proxy, from_engine) = mpsc::channel(TO_UPSTREAM_CAP);
        let (events_tx, events) = mpsc::channel(EVENTS_CAP);
        tokio::spawn(run_proxy(
            Arc::new(Mutex::new(upstreams)),
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
        let mut pipe = spawn_pipe(7);
        let answer = frame(b"answer");

        expect_query(&mut pipe, &frame(b"query")).await;

        let half = answer.len() / 2;
        pipe.peer.write_all(&answer[..half]).await.unwrap();
        tokio::time::sleep(SETTLE).await;
        assert!(
            pipe.events.try_recv().is_err(),
            "nothing may be emitted mid-frame"
        );

        pipe.peer.write_all(&answer[half..]).await.unwrap();
        let (handle, generation, event) = recv_event(&mut pipe.events).await;
        assert_eq!(handle, pipe.handle);
        assert_eq!(generation, 7);
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
        pipe.peer
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
            pipe.to_pipe
                .send(UpstreamMsg::Query(query.clone()))
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
        pipe.to_pipe
            .send(UpstreamMsg::Query(frame(&vec![0u8; PROXY_CHUNK])))
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
        pipe.to_pipe.send(UpstreamMsg::Eof).await.unwrap();
        tokio::time::sleep(SETTLE).await;
        drop(pipe.to_pipe);

        let (outcome, _) = finish(pipe.task).await;
        assert!(
            matches!(outcome, PipeOutcome::Done),
            "engine drop must not be reported as a failover"
        );

        let mut probe = [0u8; 1];
        let n = pipe.peer.read(&mut probe).await.unwrap();
        assert_eq!(n, 0, "pipe exit must drop the upstream stream");
    }

    #[tokio::test]
    async fn second_query_waits_for_the_first_response() {
        let mut pipe = spawn_pipe(11);
        let first = frame(b"one");
        let second = frame(b"two");

        pipe.to_pipe
            .send(UpstreamMsg::Query(first.clone()))
            .await
            .unwrap();
        pipe.to_pipe
            .send(UpstreamMsg::Query(second.clone()))
            .await
            .unwrap();

        let mut seen = vec![0u8; first.len()];
        pipe.peer.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, first);

        let mut probe = [0u8; 1];
        assert!(
            tokio::time::timeout(SETTLE, pipe.peer.read(&mut probe))
                .await
                .is_err(),
            "the second query must not be sent before the first is answered"
        );

        pipe.peer.write_all(&frame(b"answer-one")).await.unwrap();
        let mut seen = vec![0u8; second.len()];
        pipe.peer.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, second, "the queued query follows the first response");
    }

    #[tokio::test]
    async fn boundary_close_while_idle_asks_for_a_reconnect() {
        let query = frame(b"q");
        let pipe = spawn_pipe(1);

        // Close before any query: the pipe is idle at a boundary.
        drop(pipe.peer);
        tokio::time::sleep(SETTLE).await;
        pipe.to_pipe
            .send(UpstreamMsg::Query(query.clone()))
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
    async fn unsolicited_upstream_bytes_abort_the_connection() {
        let mut pipe = spawn_pipe(13);

        // Nothing was asked, so nothing may arrive.
        pipe.peer.write_all(&frame(b"unasked")).await.unwrap();

        let (_, _, event) = recv_event(&mut pipe.events).await;
        assert!(matches!(event, ProxyEvent::Error), "got {:?}", event);
    }

    #[tokio::test]
    async fn upstream_answering_one_query_twice_aborts_the_connection() {
        let mut pipe = spawn_pipe(9);
        let answer = frame(b"a");
        let mut twice = answer.clone();
        twice.extend_from_slice(&answer);

        expect_query(&mut pipe, &frame(b"q")).await;

        // One legitimate response is popped, but bytes remain buffered
        // afterward, which can only mean the one outstanding query was
        // answered twice.
        pipe.peer.write_all(&twice).await.unwrap();

        let (_, _, event) = recv_event(&mut pipe.events).await;
        assert!(matches!(event, ProxyEvent::Error), "got {:?}", event);
    }

    #[tokio::test]
    async fn client_eof_while_idle_closes_the_connection() {
        let mut pipe = spawn_pipe(12);

        pipe.to_pipe.send(UpstreamMsg::Eof).await.unwrap();

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

        // The hangup must land before the client asks.
        tokio::time::sleep(LATE_QUERY_DELAY).await;
        to_proxy
            .send(UpstreamMsg::Query(QUERY.to_vec()))
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
        // A single upstream: without an in-place retry the second query would
        // exhaust the list and reset the client.
        let (to_proxy, mut events) = spawn_proxy(vec![addr]);

        to_proxy
            .send(UpstreamMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, first) = recv_event(&mut events).await;
        assert_eq!(response_bytes(first), REPLY);

        to_proxy
            .send(UpstreamMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        let (_, _, second) = recv_event(&mut events).await;
        assert_eq!(response_bytes(second), REPLY);

        assert_eq!(upstream_saw(upstream).await, [QUERY, QUERY].concat());
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

        // Client EOF arrives while the first upstream's query is still
        // pending, and must not make the pipe give up before replaying it.
        to_proxy
            .send(UpstreamMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();
        to_proxy.send(UpstreamMsg::Eof).await.unwrap();

        assert_eq!(
            upstream_saw(upstream).await,
            QUERY,
            "a pending query must survive client EOF and reach the next upstream"
        );
    }

    #[tokio::test]
    async fn upstream_that_speaks_before_being_asked_does_not_kill_failover() {
        const QUERY: &[u8] = &[0x00, 0x02, 0x11, 0x22];

        let (live, upstream) = spawn_stub(StubBehavior::Answer {
            read: QUERY.len(),
            reply: b"",
        })
        .await;
        // A single byte can never complete a frame.
        let (rude, _rude_task) = spawn_stub(StubBehavior::SpeaksFirst { reply: b"\xFF" }).await;
        let (to_proxy, _events) = spawn_proxy(vec![rude, live]);

        to_proxy
            .send(UpstreamMsg::Query(QUERY.to_vec()))
            .await
            .unwrap();

        assert_eq!(
            upstream_saw(upstream).await,
            QUERY,
            "an upstream that speaks before being asked must not abort the \
             connection with no failover"
        );
    }
}
