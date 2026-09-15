use crate::tcp_forwarder::proxy::ProxyEvent;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub(crate) const DUPLEX_BUF: usize = 64;
pub(crate) const TEST_WAIT: Duration = Duration::from_secs(5);
// Long enough that a TEST_REPLY_WINDOW deadline must have fired
pub(crate) const AFTER_DEADLINE: Duration = Duration::from_millis(500);
pub(crate) const TEST_REPLY_WINDOW: Duration = Duration::from_millis(100);
pub(crate) const TEST_UPSTREAM_TIMEOUT: Duration = Duration::from_millis(200);
pub(crate) const NO_DEADLINE: Duration = Duration::from_secs(3600);
pub(crate) const LAPSED_AGO: Duration = Duration::from_secs(5);
pub(crate) const SETTLE: Duration = Duration::from_millis(50);

/// Build one length-prefixed DNS-over-TCP frame around `body`.
pub(crate) fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// Build a framed standard A/IN query for `labels`
pub(crate) fn framed_query(labels: &[&[u8]]) -> Vec<u8> {
    let mut msg = vec![
        0x12, 0x34, // id
        0x01, 0x00, // QR=0, opcode=0 (standard query), RD=1
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
    ];
    for label in labels {
        msg.push(u8::try_from(label.len()).unwrap());
        msg.extend_from_slice(label);
    }
    msg.push(0); // root label
    msg.extend_from_slice(&[0x00, 0x01]); // qtype A
    msg.extend_from_slice(&[0x00, 0x01]); // qclass IN
    frame(&msg)
}

/// Mint an opaque `SocketHandle`.
pub(crate) fn test_handle() -> SocketHandle {
    let rx = tcp::SocketBuffer::new(vec![0u8; 1]);
    let tx = tcp::SocketBuffer::new(vec![0u8; 1]);
    SocketSet::new(Vec::new()).add(tcp::Socket::new(rx, tx))
}

pub(crate) enum StubBehavior {
    /// Reads one `read`-byte frame, answers with `reply`, then closes.
    Answer {
        read: usize,
        reply: &'static [u8],
    },
    Refuse,
    Silent,
    Hangup,
    /// Answers one framed query, then HOLDS the connection open, the way
    /// an RFC 7766 upstream does between queries.
    AnswerAndHold {
        read: usize,
        reply: &'static [u8],
    },
    /// Writes `reply` immediately on accept, before ever reading
    /// anything: models an upstream that speaks out of turn.
    SpeaksFirst {
        reply: &'static [u8],
    },
    /// Answers one framed query, then, once the answer has been consumed,
    /// speaks out of turn on the connection it is still holding open.
    AnswerThenSpeakUnasked {
        read: usize,
        reply: &'static [u8],
        unsolicited: &'static [u8],
    },
    /// Answers the first framed query on every connection it accepts, then
    /// holds that connection and ignores anything more sent on it.
    AnswerFirstThenIgnore {
        read: usize,
        reply: &'static [u8],
    },
    /// Answers one framed query per connection, then closes. Models an
    /// RFC 7766 6.2.1 server dropping an idle persistent connection.
    AnswerThenClose {
        read: usize,
        reply: &'static [u8],
    },
}

pub(crate) async fn spawn_stub(behavior: StubBehavior) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let task = match behavior {
        StubBehavior::Answer { read, reply } => tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut seen = vec![0u8; read];
            stream.read_exact(&mut seen).await.unwrap();
            stream.write_all(reply).await.unwrap();
            seen
        }),
        // Dropped before the address is handed out, a connect is refused
        StubBehavior::Refuse => {
            drop(listener);
            tokio::spawn(async { Vec::new() })
        }
        StubBehavior::Silent => tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
            Vec::new()
        }),
        StubBehavior::Hangup => tokio::spawn(async move {
            while listener.accept().await.is_ok() {}
            Vec::new()
        }),
        StubBehavior::AnswerAndHold { read, reply } => tokio::spawn(async move {
            let mut seen = Vec::new();
            if let Ok((mut stream, _)) = listener.accept().await {
                seen = vec![0u8; read];
                if stream.read_exact(&mut seen).await.is_ok() {
                    let _ = stream.write_all(reply).await;
                }
                tokio::time::sleep(TEST_WAIT).await;
            }
            seen
        }),
        StubBehavior::SpeaksFirst { reply } => tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(reply).await;
                // Hold the connection open past the race window.
                tokio::time::sleep(TEST_WAIT).await;
            }
            Vec::new()
        }),
        StubBehavior::AnswerThenSpeakUnasked {
            read,
            reply,
            unsolicited,
        } => tokio::spawn(async move {
            let mut seen = Vec::new();
            if let Ok((mut stream, _)) = listener.accept().await {
                seen = vec![0u8; read];
                if stream.read_exact(&mut seen).await.is_ok() {
                    let _ = stream.write_all(reply).await;
                    // Without the pause the two writes coalesce into one
                    tokio::time::sleep(SETTLE).await;
                    let _ = stream.write_all(unsolicited).await;
                }
                tokio::time::sleep(TEST_WAIT).await;
            }
            seen
        }),
        StubBehavior::AnswerFirstThenIgnore { read, reply } => tokio::spawn(async move {
            let mut all = Vec::new();
            let mut held = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut seen = vec![0u8; read];
                if stream.read_exact(&mut seen).await.is_err() {
                    break;
                }
                all.extend_from_slice(&seen);
                if stream.write_all(reply).await.is_err() {
                    break;
                }
                held.push(stream);
                if all.len() >= read * 2 {
                    break;
                }
            }
            all
        }),
        StubBehavior::AnswerThenClose { read, reply } => tokio::spawn(async move {
            let mut all = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut seen = vec![0u8; read];
                if stream.read_exact(&mut seen).await.is_err() {
                    break;
                }
                all.extend_from_slice(&seen);
                if stream.write_all(reply).await.is_err() {
                    break;
                }
                drop(stream);
                if all.len() >= read * 2 {
                    break;
                }
            }
            all
        }),
    };

    (addr, task)
}

/// Await a stub's task and return every byte it read.
pub(crate) async fn upstream_saw(task: JoinHandle<Vec<u8>>) -> Vec<u8> {
    tokio::time::timeout(TEST_WAIT, task)
        .await
        .expect("upstream never received the query")
        .unwrap()
}

/// Take the next event a proxy emitted toward the engine.
pub(crate) async fn recv_event(
    events: &mut mpsc::Receiver<(SocketHandle, u64, ProxyEvent)>,
) -> (SocketHandle, u64, ProxyEvent) {
    tokio::time::timeout(TEST_WAIT, events.recv())
        .await
        .expect("timed out waiting for a proxy event")
        .expect("event channel closed")
}

pub(crate) fn response_bytes(event: ProxyEvent) -> Vec<u8> {
    match event {
        ProxyEvent::Response(bytes) => bytes,
        other => panic!("expected Response, got {:?}", other),
    }
}
