use crate::tcp_forwarder::proxy::ProxyEvent;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet as _;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use telio_model::constants::DNS_PORT;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub(crate) const IPV4_HEADER: usize = 20;
pub(crate) const TCP_HEADER: usize = 20;
pub(crate) const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 4);
pub(crate) const SERVER_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
pub(crate) const CLIENT_PORT: u16 = 40000;
pub(crate) const DUPLEX_BUF: usize = 64;
pub(crate) const TEST_WAIT: Duration = Duration::from_secs(5);
// Long enough that a TEST_REPLY_WINDOW deadline must have fired
pub(crate) const AFTER_DEADLINE: Duration = Duration::from_millis(500);
pub(crate) const TEST_REPLY_WINDOW: Duration = Duration::from_millis(100);
pub(crate) const TEST_UPSTREAM_TIMEOUT: Duration = Duration::from_millis(200);
pub(crate) const TEST_CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_millis(200);
pub(crate) const NO_DEADLINE: Duration = Duration::from_secs(3600);
pub(crate) const LAPSED_AGO: Duration = Duration::from_secs(5);
pub(crate) const SETTLE: Duration = Duration::from_millis(50);
pub(crate) const LATE_QUERY_DELAY: Duration = Duration::from_millis(150);

/// Build one length-prefixed DNS-over-TCP frame around `body`.
pub(crate) fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// Build a framed standard A/IN query for `labels`, bypassing any builder
/// so tests can use label bytes a well-behaved client would never send.
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

pub(crate) struct Segment {
    pub(crate) flags: u8,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn build_tcp_ipv4(
    src_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = IPV4_HEADER + TCP_HEADER + payload.len();
    let mut buf = vec![0u8; total];
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(CLIENT_IP);
        ip.set_destination(SERVER_IP);
        ip.set_checksum(0);
        ip.set_checksum(checksum(&ip.to_immutable()));
    }
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IPV4_HEADER..]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(DNS_PORT);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(64240);
        tcp.set_payload(payload);
        tcp.set_checksum(0);
        tcp.set_checksum(pnet_packet::tcp::ipv4_checksum(
            &tcp.to_immutable(),
            &CLIENT_IP,
            &SERVER_IP,
        ));
    }
    buf
}

pub(crate) fn parse_segment(pkt: &[u8]) -> Segment {
    let ip = Ipv4Packet::new(pkt).unwrap();
    assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
    let tcp = TcpPacket::new(ip.payload()).unwrap();
    Segment {
        flags: tcp.get_flags(),
        seq: tcp.get_sequence(),
        ack: tcp.get_acknowledgement(),
        payload: tcp.payload().to_vec(),
    }
}

pub(crate) struct TestClient {
    pub(crate) src_port: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
}

impl TestClient {
    pub(crate) fn new() -> Self {
        Self::new_with_port(CLIENT_PORT)
    }

    /// A client on a distinct source port, so it occupies a different
    /// pool socket than `CLIENT_PORT`'s connection.
    pub(crate) fn new_with_port(src_port: u16) -> Self {
        TestClient {
            src_port,
            seq: 1000,
            ack: 0,
        }
    }

    pub(crate) fn syn(&mut self) -> Vec<u8> {
        let pkt = build_tcp_ipv4(self.src_port, self.seq, 0, TcpFlags::SYN, &[]);
        self.seq = self.seq.wrapping_add(1);
        pkt
    }

    pub(crate) fn absorb(&mut self, seg: &Segment) {
        let mut advance = seg.payload.len() as u32;
        if seg.flags & TcpFlags::SYN != 0 {
            advance += 1;
        }
        if seg.flags & TcpFlags::FIN != 0 {
            advance += 1;
        }
        if advance > 0 {
            self.ack = seg.seq.wrapping_add(advance);
        }
    }

    pub(crate) fn ack(&self) -> Vec<u8> {
        build_tcp_ipv4(self.src_port, self.seq, self.ack, TcpFlags::ACK, &[])
    }

    pub(crate) fn data(&mut self, payload: &[u8]) -> Vec<u8> {
        let pkt = build_tcp_ipv4(
            self.src_port,
            self.seq,
            self.ack,
            TcpFlags::ACK | TcpFlags::PSH,
            payload,
        );
        self.seq = self.seq.wrapping_add(payload.len() as u32);
        pkt
    }

    pub(crate) fn fin(&mut self) -> Vec<u8> {
        let pkt = build_tcp_ipv4(
            self.src_port,
            self.seq,
            self.ack,
            TcpFlags::FIN | TcpFlags::ACK,
            &[],
        );
        self.seq = self.seq.wrapping_add(1);
        pkt
    }
}

pub(crate) async fn recv_segment(egress: &mut mpsc::Receiver<Vec<u8>>) -> Segment {
    let pkt = tokio::time::timeout(TEST_WAIT, egress.recv())
        .await
        .expect("timed out waiting for egress packet")
        .expect("egress channel closed");
    parse_segment(&pkt)
}

pub(crate) async fn recv_until(
    egress: &mut mpsc::Receiver<Vec<u8>>,
    want: fn(&Segment) -> bool,
) -> Segment {
    for _ in 0..10 {
        let seg = recv_segment(egress).await;
        if want(&seg) {
            return seg;
        }
    }
    panic!("no matching segment within 10 egress packets");
}

pub(crate) fn has_payload(seg: &Segment) -> bool {
    !seg.payload.is_empty()
}

pub(crate) fn is_rst(seg: &Segment) -> bool {
    seg.flags & TcpFlags::RST != 0
}

pub(crate) fn is_fin(seg: &Segment) -> bool {
    seg.flags & TcpFlags::FIN != 0
}

/// Mint an opaque `SocketHandle`. The socket behind it is never polled: both
/// the proxy and its tests only ever echo the handle back to the engine.
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
        // Dropped before the address is handed out, so a connect is
        // refused
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
