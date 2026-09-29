//! Backlog for the forwarder smoltcp listen pool.

use smoltcp::iface::SocketSet;
use smoltcp::socket::{tcp, AnySocket};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Packet, TcpPacket};
use std::collections::VecDeque;
use std::time::Duration;
use telio_utils::Instant;

/// TODO: set based on default pool size.
/// SYNs held while every pool socket is busy
pub(crate) const SYN_BACKLOG_CAP: usize = 32;
/// Clients retransmit a SYN after some time, refreshing the held copy.
/// Stale SYN likely belongs to a client that gave up and should be released.
const SYN_BACKLOG_MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq)]
struct Flow {
    source: IpEndpoint,
    destination: IpEndpoint,
}

struct HeldSyn {
    flow: Flow,
    packet: Vec<u8>,
    since: Instant,
}

impl HeldSyn {
    fn is_stale(&self, max_age: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.since) > max_age
    }
}

/// Bounded FIFO of SYNs waiting for a pool socket to return to Listen.
pub(crate) struct SynBacklog {
    held: VecDeque<HeldSyn>,
    cap: usize,
    max_age: Duration,
}

impl Default for SynBacklog {
    fn default() -> Self {
        SynBacklog::new(SYN_BACKLOG_CAP, SYN_BACKLOG_MAX_AGE)
    }
}

impl SynBacklog {
    fn new(cap: usize, max_age: Duration) -> Self {
        SynBacklog {
            held: VecDeque::with_capacity(cap),
            cap,
            max_age,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Queue a SYN until a pool socket is listening.
    fn hold(&mut self, flow: Flow, packet: Vec<u8>, now: Instant) {
        // Refresh
        if let Some(syn) = self.held.iter_mut().find(|syn| syn.flow == flow) {
            syn.packet = packet;
            syn.since = now;
            return;
        }
        if self.held.len() >= self.cap {
            let max_age = self.max_age;
            self.held.retain(|syn| !syn.is_stale(max_age, now));
        }
        // Full
        if self.held.len() >= self.cap {
            return;
        }
        self.held.push_back(HeldSyn {
            flow,
            packet,
            since: now,
        });
    }

    /// Take up to `count` of the oldest SYNs that are not stale and whose
    /// client has not connected yet, discarding the rest.
    fn release(
        &mut self,
        count: usize,
        now: Instant,
        connected: impl Fn(&Flow) -> bool,
    ) -> Vec<HeldSyn> {
        let mut released = Vec::new();
        while released.len() < count {
            let Some(syn) = self.held.pop_front() else {
                break;
            };
            if !syn.is_stale(self.max_age, now) && !connected(&syn.flow) {
                released.push(syn);
            }
        }
        released
    }
}

/// The flow of a SYN opening a new connection, `None` for any other packet,
/// including a SYN retransmitted to a socket that already took it.
fn new_connection_syn(packet: &[u8], sockets: &SocketSet<'_>) -> Option<Flow> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    if !tcp.syn() || tcp.ack() {
        return None;
    }
    let flow = Flow {
        source: IpEndpoint::new(IpAddress::Ipv4(ip.src_addr()), tcp.src_port()),
        destination: IpEndpoint::new(IpAddress::Ipv4(ip.dst_addr()), tcp.dst_port()),
    };
    let for_pool = tcp_sockets(sockets).any(|socket| destination_correct(socket, flow.destination));
    (for_pool && !is_connected(&flow, sockets)).then_some(flow)
}

/// Check if the socket listens on the destination endpoint before taking a connection.
fn destination_correct(socket: &tcp::Socket<'_>, destination: IpEndpoint) -> bool {
    let listen = socket.listen_endpoint();
    listen.port != 0
        && listen.port == destination.port
        && listen.addr.is_none_or(|addr| addr == destination.addr)
}

/// Whether a pool socket already took this flow's SYN.
fn is_connected(flow: &Flow, sockets: &SocketSet<'_>) -> bool {
    tcp_sockets(sockets).any(|socket| {
        socket.remote_endpoint() == Some(flow.source)
            && socket.local_endpoint() == Some(flow.destination)
    })
}

fn tcp_sockets<'s, 'a>(sockets: &'s SocketSet<'a>) -> impl Iterator<Item = &'s tcp::Socket<'a>> {
    sockets
        .iter()
        .filter_map(|(_, socket)| tcp::Socket::downcast(socket))
}

/// Pass smoltcp only as many new SYNs as there are listening sockets
/// and hold the rest so they are not answered with RST.
pub(crate) fn admit_syns(
    rx: &mut VecDeque<Vec<u8>>,
    sockets: &SocketSet<'_>,
    backlog: &mut SynBacklog,
) {
    let listening = tcp_sockets(sockets)
        .filter(|socket| socket.state() == tcp::State::Listen)
        .count();
    if backlog.is_empty() && listening >= rx.len() {
        return;
    }
    let now = Instant::now();
    let released = backlog.release(listening, now, |flow| is_connected(flow, sockets));
    let mut budget = listening.saturating_sub(released.len());

    let incoming = std::mem::take(rx);
    // The same SYN twice in one batch must only use one listening socket
    let mut admitted: Vec<Flow> = Vec::with_capacity(listening);
    for syn in released {
        admitted.push(syn.flow);
        rx.push_back(syn.packet);
    }
    for packet in incoming {
        let Some(flow) = new_connection_syn(&packet, sockets) else {
            rx.push_back(packet);
            continue;
        };
        if admitted.contains(&flow) {
            rx.push_back(packet);
        } else if budget > 0 {
            budget -= 1;
            admitted.push(flow);
            rx.push_back(packet);
        } else {
            backlog.hold(flow, packet, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_forwarder::test_utils::NO_DEADLINE;
    use smoltcp::iface::{Config, Interface};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::wire::HardwareAddress;
    use std::net::Ipv4Addr;
    use telio_model::constants::DNS_PORT;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 4);
    const SERVER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    fn client(port: u16) -> Flow {
        Flow {
            source: IpEndpoint::new(IpAddress::Ipv4(CLIENT), port),
            destination: IpEndpoint::new(IpAddress::Ipv4(SERVER), DNS_PORT),
        }
    }

    fn held_flows(backlog: &SynBacklog) -> Vec<Flow> {
        backlog.held.iter().map(|syn| syn.flow).collect()
    }

    fn packets(released: Vec<HeldSyn>) -> Vec<Vec<u8>> {
        released.into_iter().map(|syn| syn.packet).collect()
    }

    /// A bare IPv4 SYN from `CLIENT:port` to `SERVER:DNS_PORT`.
    fn syn_packet(port: u16) -> Vec<u8> {
        syn_packet_to(port, DNS_PORT)
    }

    /// A bare IPv4 SYN from `CLIENT:port` to `SERVER:dst_port`.
    fn syn_packet_to(port: u16, dst_port: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_hop_limit(64);
        ip.set_next_header(smoltcp::wire::IpProtocol::Tcp);
        ip.set_src_addr(CLIENT);
        ip.set_dst_addr(SERVER);
        let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
        tcp.set_src_port(port);
        tcp.set_dst_port(dst_port);
        tcp.set_header_len(20);
        tcp.set_syn(true);
        buf
    }

    fn listening_pool(size: usize) -> (SocketSet<'static>, Vec<smoltcp::iface::SocketHandle>) {
        let mut sockets = SocketSet::new(Vec::new());
        let handles = (0..size)
            .map(|_| {
                let rx = tcp::SocketBuffer::new(vec![0u8; 64]);
                let tx = tcp::SocketBuffer::new(vec![0u8; 64]);
                let mut socket = tcp::Socket::new(rx, tx);
                socket.listen(DNS_PORT).unwrap();
                sockets.add(socket)
            })
            .collect();
        (sockets, handles)
    }

    #[test]
    fn syn_backlog_releases_oldest_first_up_to_the_budget() {
        let now = Instant::now();
        let mut backlog = SynBacklog::new(4, NO_DEADLINE);
        for port in 1..=3u16 {
            backlog.hold(client(port), vec![port as u8], now);
        }

        assert_eq!(
            packets(backlog.release(2, now, |_| false)),
            vec![vec![1], vec![2]]
        );
        assert_eq!(
            packets(backlog.release(0, now, |_| false)),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(packets(backlog.release(5, now, |_| false)), vec![vec![3]]);
        assert!(backlog.is_empty());
    }

    #[test]
    fn syn_backlog_retransmit_refreshes_in_place() {
        let now = Instant::now();
        let mut backlog = SynBacklog::new(4, NO_DEADLINE);
        backlog.hold(client(1), vec![1], now);
        backlog.hold(client(2), vec![2], now);

        backlog.hold(client(1), vec![0xAA], now);
        assert_eq!(
            held_flows(&backlog),
            vec![client(1), client(2)],
            "a retransmitted SYN must not take a second slot"
        );
        assert_eq!(
            packets(backlog.release(2, now, |_| false)),
            vec![vec![0xAA], vec![2]],
            "the refreshed SYN keeps its place in line"
        );
    }

    #[test]
    fn syn_backlog_refuses_when_full() {
        let now = Instant::now();
        let mut backlog = SynBacklog::new(2, NO_DEADLINE);
        backlog.hold(client(1), vec![1], now);
        backlog.hold(client(2), vec![2], now);
        backlog.hold(client(3), vec![3], now);

        assert_eq!(held_flows(&backlog), vec![client(1), client(2)]);
        assert_eq!(
            packets(backlog.release(3, now, |_| false)),
            vec![vec![1], vec![2]]
        );
    }

    #[test]
    fn syn_backlog_skips_stale_syns_on_release() {
        let now = Instant::now();
        let max_age = Duration::from_secs(3);
        let mut backlog = SynBacklog::new(4, max_age);
        backlog.hold(client(1), vec![1], now - max_age - Duration::from_millis(1));
        backlog.hold(client(2), vec![2], now);

        assert_eq!(packets(backlog.release(2, now, |_| false)), vec![vec![2]]);
        assert!(
            backlog.is_empty(),
            "the stale SYN must be discarded, not kept"
        );
    }

    #[test]
    fn syn_backlog_full_of_stale_syns_admits_a_fresh_one() {
        let now = Instant::now();
        let max_age = Duration::from_secs(3);
        let mut backlog = SynBacklog::new(1, max_age);
        backlog.hold(client(1), vec![1], now - max_age - Duration::from_millis(1));

        backlog.hold(client(2), vec![2], now);

        assert_eq!(
            held_flows(&backlog),
            vec![client(2)],
            "the stale SYN must be evicted"
        );
        assert_eq!(packets(backlog.release(1, now, |_| false)), vec![vec![2]]);
    }

    #[test]
    fn released_syn_and_its_retransmit_use_one_listening_socket() {
        let (sockets, _) = listening_pool(2);
        let mut backlog = SynBacklog::new(4, NO_DEADLINE);
        backlog.hold(client(1), syn_packet(1), Instant::now());

        let mut rx = VecDeque::from([syn_packet(1), syn_packet(2), syn_packet(3)]);
        admit_syns(&mut rx, &sockets, &mut backlog);

        assert_eq!(
            Vec::from(rx),
            vec![syn_packet(1), syn_packet(1), syn_packet(2)],
            "the retransmit rides along with the released SYN, leaving a socket for port 2"
        );
        assert_eq!(
            held_flows(&backlog),
            vec![client(3)],
            "the retransmit must not be held again"
        );
    }

    #[test]
    fn held_syn_of_a_client_that_connected_since_is_discarded() {
        let (mut sockets, handles) = listening_pool(2);
        let mut device = Loopback::new(Medium::Ip);
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::ZERO,
        );
        let flow = client(1);
        // Stands in for a socket that took the client's retransmitted SYN.
        let socket = sockets.get_mut::<tcp::Socket>(handles[0]);
        socket.abort();
        socket
            .connect(iface.context(), flow.source, flow.destination)
            .unwrap();
        let mut backlog = SynBacklog::new(4, NO_DEADLINE);
        backlog.hold(flow, syn_packet(1), Instant::now());

        let mut rx = VecDeque::from([syn_packet(2)]);
        admit_syns(&mut rx, &sockets, &mut backlog);

        assert_eq!(
            Vec::from(rx),
            vec![syn_packet(2)],
            "the held SYN must not reach a listening socket"
        );
        assert!(backlog.is_empty(), "the held SYN must be discarded");
    }

    #[test]
    fn syn_for_another_port_uses_no_listening_socket() {
        let (sockets, _) = listening_pool(1);
        let mut backlog = SynBacklog::new(4, NO_DEADLINE);

        let mut rx = VecDeque::from([syn_packet_to(1, 80), syn_packet(2), syn_packet(3)]);
        admit_syns(&mut rx, &sockets, &mut backlog);

        assert_eq!(
            Vec::from(rx),
            vec![syn_packet_to(1, 80), syn_packet(2)],
            "the port 80 SYN is left for smoltcp to reset, port 2 gets the socket"
        );
        assert_eq!(held_flows(&backlog), vec![client(3)]);
    }
}
