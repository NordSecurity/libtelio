//! TCP forwarder engine implemented with smoltcp.

use crate::tcp_forwarder::frame::{is_nord_frame, MessageReader, DNS_TCP_LEN_PREFIX};
use crate::tcp_forwarder::proxy::{run_proxy, ClientMsg, ProxyEvent, PROXY_CHUNK};
use crate::tcp_forwarder::Timeouts;
use crate::upstream::UpstreamList;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use telio_model::constants::{
    DNS_PORT, DNS_VIRTUAL_PEER_IPV4, DNS_VIRTUAL_PEER_ON_EXIT_IPV4, VPN_INTERNAL_IPV4,
};
use telio_utils::{sleep_until, telio_log_debug, telio_log_trace, telio_log_warn, Instant};
use tokio::sync::{mpsc, Mutex};

const TO_UPSTREAM_CAP: usize = 16;
const EVENTS_CAP: usize = 16;

const DEVICE_MTU: usize = 1280;
const DNS_IPV4_ADDRS: [Ipv4Addr; 2] = [DNS_VIRTUAL_PEER_IPV4, DNS_VIRTUAL_PEER_ON_EXIT_IPV4];
const SUBNET_MASK: u8 = 32;

const TCP_SOCKET_BUF: usize = 16 * 1024;
const PENDING_TO_CLIENT_MAX: usize = 2 * DNS_TCP_MAX_FRAME;
const DNS_TCP_MAX_FRAME: usize = DNS_TCP_LEN_PREFIX + u16::MAX as usize;

const CLIENT_SOCKET_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// The suspend aware clock driving smoltcp's timers.
#[derive(Clone, Copy)]
struct SmolClock {
    start: Instant,
}

impl SmolClock {
    fn new() -> Self {
        SmolClock {
            start: Instant::now(),
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(
            i64::try_from(self.start.elapsed().as_micros()).unwrap_or(i64::MAX),
        )
    }
}

/// Packet queues bridging the smoltcp interface and the
/// forwarder's ingress/egress channels.
struct VirtualDevice {
    /// Packets received from the tunnel.
    rx: VecDeque<Vec<u8>>,
    /// Packets to be transmitted back to the tunnel.
    tx: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    fn new() -> Self {
        VirtualDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
}

/// Receive token handing one queued ingress packet to smoltcp.
struct VirtualRxToken(Vec<u8>);

/// Transmit token appending one egress packet to the device TX queue.
struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.0.push_back(buffer);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((VirtualRxToken(packet), VirtualTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

/// Build the smoltcp interface serving the virtual DNS addresses.
fn build_interface(device: &mut VirtualDevice, now: SmolInstant) -> Interface {
    use rand::RngExt;
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::rng().random();
    let mut iface = Interface::new(config, device, now);

    iface.update_ip_addrs(|addrs| {
        for ip in DNS_IPV4_ADDRS {
            if addrs
                .push(IpCidr::new(IpAddress::Ipv4(ip), SUBNET_MASK))
                .is_err()
            {
                telio_log_warn!(
                    "TCP forwarder interface address table full, dropping {}",
                    ip,
                );
            }
        }
    });
    // Interface requires a valid route lookup, the gateway address itself is never used.
    if iface
        .routes_mut()
        .add_default_ipv4_route(VPN_INTERNAL_IPV4)
        .is_err()
    {
        telio_log_warn!("Failed to add default route to TCP forwarder");
    }
    iface
}

/// Create smoltcp socket in listening state.
fn new_listen_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
        CLIENT_SOCKET_CONNECTION_TIMEOUT.as_secs(),
    )));
    if socket.listen(DNS_PORT).is_err() {
        telio_log_warn!("Failed to open TCP DNS listen socket");
    }
    socket
}

/// Engine side state of a proxied connection.
struct ConnState {
    /// Sender channel towards the upstream proxy task.
    to_upstream: Option<mpsc::Sender<ClientMsg>>,
    /// Reassembler for bytes arriving from the client.
    from_client: MessageReader,
    /// A framed message with no channel permit yet.
    held: Option<Vec<u8>>,
    /// Bytes from upstream to be written into the smoltcp socket.
    pending_to_client: Vec<u8>,
    /// No further responses will arrive, close once `pending_to_client` drains.
    responses_done: bool,
    /// Sent client's EOF to upstream.
    client_eof_sent: bool,
    /// Generation this connection was created.
    generation: u64,
    /// Deadline for the in-progress client message.
    request_deadline: Option<Instant>,
}

impl ConnState {
    fn new(generation: u64) -> Self {
        ConnState {
            to_upstream: None,
            from_client: MessageReader::default(),
            held: None,
            pending_to_client: Vec::new(),
            responses_done: false,
            client_eof_sent: false,
            generation,
            request_deadline: None,
        }
    }

    fn abort(&mut self) {
        self.from_client.clear();
        self.held = None;
        self.request_deadline = None;
    }
}

/// Fold an upstream proxy event into the matching connection.
fn handle_proxy_event(
    connections: &mut HashMap<SocketHandle, ConnState>,
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    generation: u64,
    event: ProxyEvent,
) {
    let Some(connection) = connections.get_mut(&handle) else {
        return;
    };
    if connection.generation != generation {
        return;
    }
    match event {
        ProxyEvent::Response(bytes) => {
            if connection.pending_to_client.len() + bytes.len() > PENDING_TO_CLIENT_MAX {
                telio_log_warn!(
                    "Client not draining (handle {:?}), pending_to_client would exceed {} B, aborting",
                    handle,
                    PENDING_TO_CLIENT_MAX,
                );
                sockets.get_mut::<tcp::Socket>(handle).abort();
            } else {
                connection.pending_to_client.extend_from_slice(&bytes);
            }
        }
        ProxyEvent::Eof => connection.responses_done = true,
        ProxyEvent::Error => sockets.get_mut::<tcp::Socket>(handle).abort(),
    }
}

/// Reassemble client bytes into whole requests and forward them upstream.
///
/// The proxy task is spawned lazily, on the first complete message.
///
/// Returns `false` when the connection was aborted.
async fn process_client_to_upstream(
    handle: SocketHandle,
    socket: &mut tcp::Socket<'_>,
    connection: &mut ConnState,
    events_tx: &mpsc::Sender<(SocketHandle, u64, ProxyEvent)>,
    upstreams: &Arc<Mutex<UpstreamList>>,
    upstream_reply_timeout: Duration,
) -> bool {
    loop {
        let Some(frame) = connection
            .held
            .take()
            .or_else(|| connection.from_client.next_frame())
        else {
            if !socket.can_recv() {
                return true;
            }
            let mut chunk = vec![0u8; PROXY_CHUNK];
            match socket.recv_slice(&mut chunk) {
                Ok(n) if n > 0 => {
                    chunk.truncate(n);
                    connection.from_client.push(&chunk);
                    continue;
                }
                _ => return true,
            }
        };
        // Complete frame received, rearm for next partial bytes
        connection.request_deadline = None;

        if is_nord_frame(&frame) {
            telio_log_debug!("TCP DNS query for .nord, aborting");
            socket.abort();
            connection.abort();
            return false;
        }

        if connection.to_upstream.is_none() {
            if upstreams.lock().await.addrs().is_empty() {
                telio_log_warn!("No upstream configured for TCP DNS, aborting");
                socket.abort();
                connection.abort();
                return false;
            }
            telio_log_trace!(
                "First TCP DNS query on handle {:?} (gen {}), connecting upstream",
                handle,
                connection.generation,
            );
            let (to_upstream_tx, to_upstream_rx) = mpsc::channel(TO_UPSTREAM_CAP);
            tokio::spawn(run_proxy(
                upstreams.clone(),
                upstream_reply_timeout,
                handle,
                connection.generation,
                to_upstream_rx,
                events_tx.clone(),
            ));
            connection.to_upstream = Some(to_upstream_tx);
        }

        let Some(sender) = connection.to_upstream.as_ref() else {
            return true;
        };
        match sender.try_reserve() {
            Ok(permit) => {
                permit.send(ClientMsg::Query(frame));
            }
            Err(_) => {
                // Hold the frame so the receive window closes and
                // the client stalls, rather than buffering without bound.
                connection.held = Some(frame);
                return true;
            }
        }
    }
}

/// Pass the client's FIN on to the proxy task, only when nothing is queued behind it.
fn forward_client_eof(connection: &mut ConnState) {
    if connection.client_eof_sent || connection.held.is_some() {
        return;
    }
    match connection.to_upstream.as_ref() {
        Some(sender) => {
            if let Ok(permit) = sender.try_reserve() {
                permit.send(ClientMsg::Eof);
                connection.client_eof_sent = true;
            }
        }
        None => {
            connection.client_eof_sent = true;
            connection.responses_done = true;
        }
    }
}

/// Drop the connection state and put a closed socket back into the listen pool.
fn return_to_pool(
    handle: SocketHandle,
    socket: &mut tcp::Socket<'_>,
    connections: &mut HashMap<SocketHandle, ConnState>,
) {
    connections.remove(&handle);
    if socket.listen(DNS_PORT).is_err() {
        telio_log_warn!("Failed to re-listen TCP DNS socket");
    }
}

/// Per-poll socket maintenance.
///
/// Returns `true` if any socket was aborted this pass.
async fn service_sockets(
    handles: &[SocketHandle],
    sockets: &mut SocketSet<'_>,
    connections: &mut HashMap<SocketHandle, ConnState>,
    events_tx: &mpsc::Sender<(SocketHandle, u64, ProxyEvent)>,
    upstreams: &Arc<Mutex<UpstreamList>>,
    timeouts: Timeouts,
    next_generation: &mut u64,
) -> bool {
    let mut aborted_this_pass = false;
    for &handle in handles {
        let socket = sockets.get_mut::<tcp::Socket>(handle);

        // Abort closed socket.
        if socket.state() == tcp::State::Closed {
            return_to_pool(handle, socket, connections);
            continue;
        }

        let established = matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        );
        if established && !connections.contains_key(&handle) {
            let generation = *next_generation;
            *next_generation = next_generation.wrapping_add(1);
            telio_log_debug!(
                "New TCP DNS connection on handle {:?} (gen {})",
                handle,
                generation,
            );
            connections.insert(handle, ConnState::new(generation));
        }

        if let Some(connection) = connections.get_mut(&handle) {
            if !process_client_to_upstream(
                handle,
                socket,
                connection,
                events_tx,
                upstreams,
                timeouts.upstream_reply,
            )
            .await
            {
                // Skip the State::Closed -> listen() below
                // re-listening now would reset the socket and discard the queued RST
                connection.request_deadline = None;
                aborted_this_pass = true;
                continue;
            }

            // A client that starts a message and stops
            // Will hold a pool socket for `CLIENT_CONNECTION_TIMEOUT`.
            if connection.held.is_some() || connection.from_client.partial_len() == 0 {
                connection.request_deadline = None;
            } else {
                match connection.request_deadline {
                    None => {
                        connection.request_deadline = Some(Instant::now() + timeouts.client_request)
                    }
                    Some(deadline) if Instant::now() >= deadline => {
                        telio_log_warn!(
                            "Client did not finish DNS message in time (handle {:?}), aborting",
                            handle,
                        );
                        socket.abort();
                        connection.abort();
                        aborted_this_pass = true;
                        continue;
                    }
                    Some(_) => {}
                }
            }

            // Client FIN, fully drained.
            if !socket.may_recv() && !socket.can_recv() {
                forward_client_eof(connection);
            }

            // Upstream to client.
            while !connection.pending_to_client.is_empty() && socket.can_send() {
                match socket.send_slice(connection.pending_to_client.as_slice()) {
                    Ok(n) if n > 0 => {
                        connection.pending_to_client.drain(..n);
                    }
                    _ => break,
                }
            }

            // Upstream finished.
            if connection.responses_done && connection.pending_to_client.is_empty() {
                socket.close();
            }
        }

        // Fully closed, return the socket to the listen pool.
        if socket.state() == tcp::State::Closed {
            return_to_pool(handle, socket, connections);
        }
    }
    aborted_this_pass
}

/// Bridge ingress to egress channels and the smoltcp stack.
pub(crate) async fn engine_loop(
    mut ingress: mpsc::Receiver<Vec<u8>>,
    egress: mpsc::Sender<Vec<u8>>,
    upstreams: Arc<Mutex<UpstreamList>>,
    tcp_pool_size: usize,
    timeouts: Timeouts,
) {
    let clock = SmolClock::new();
    let mut device = VirtualDevice::new();
    let mut iface = build_interface(&mut device, clock.now());
    let mut sockets = SocketSet::new(Vec::new());
    let handles: Vec<SocketHandle> = (0..tcp_pool_size)
        .map(|_| sockets.add(new_listen_socket()))
        .collect();
    let mut conns: HashMap<SocketHandle, ConnState> = HashMap::new();
    let (events_tx, mut events_rx) = mpsc::channel::<(SocketHandle, u64, ProxyEvent)>(EVENTS_CAP);
    let mut next_generation: u64 = 0;

    telio_log_debug!(
        "TCP forwarder loop started with {} listening sockets",
        handles.len(),
    );

    loop {
        let poll_deadline = iface
            .poll_delay(clock.now(), &sockets)
            .map(|d| Instant::now() + Duration::from_micros(d.total_micros()));
        let request_deadline = conns.values().filter_map(|c| c.request_deadline).min();
        let deadline = earliest(poll_deadline, request_deadline);

        tokio::select! {
            pkt = ingress.recv() => match pkt {
                Some(pkt) => device.rx.push_back(pkt),
                // Every handle dropped, shut down.
                None => {
                    telio_log_debug!("Ingress channel closed, stopping TCP forwarder loop");
                    return;
                }
            },
            evt = events_rx.recv() => {
                if let Some((handle, generation, event)) = evt {
                    handle_proxy_event(&mut conns, &mut sockets, handle, generation, event);
                }
            },
            _ = async {
                match deadline {
                    Some(dl) => sleep_until(dl).await,
                    None => std::future::pending().await,
                }
            } => {
                telio_log_trace!("TCP forwarder poll timer fired");
            }
        }

        // Drain any queued ingress packets.
        while let Ok(pkt) = ingress.try_recv() {
            device.rx.push_back(pkt);
        }

        // Drain any queued proxy events.
        while let Ok((handle, generation, event)) = events_rx.try_recv() {
            handle_proxy_event(&mut conns, &mut sockets, handle, generation, event);
        }

        iface.poll(clock.now(), &mut device, &mut sockets);
        let aborted = service_sockets(
            &handles,
            &mut sockets,
            &mut conns,
            &events_tx,
            &upstreams,
            timeouts,
            &mut next_generation,
        )
        .await;
        // Flush anything service_sockets produced, in particular an abort's RST.
        iface.poll(clock.now(), &mut device, &mut sockets);

        if aborted {
            // The RST should be cueued and the aborted socket may safely return
            // to Listen. service_sockets skipped this before to avoid discarding it.
            service_sockets(
                &handles,
                &mut sockets,
                &mut conns,
                &events_tx,
                &upstreams,
                timeouts,
                &mut next_generation,
            )
            .await;
        }

        while let Some(pkt) = device.tx.pop_front() {
            if egress.send(pkt).await.is_err() {
                // Egress consumer gone, shut down.
                return;
            }
        }
    }
}

/// Earliest of two instants
pub(crate) fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_forwarder::test_utils::*;

    fn conn_at_generation(
        generation: u64,
    ) -> (
        SocketSet<'static>,
        SocketHandle,
        HashMap<SocketHandle, ConnState>,
    ) {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(new_listen_socket());
        let mut conns = HashMap::new();
        conns.insert(handle, ConnState::new(generation));
        (sockets, handle, conns)
    }

    #[test]
    fn earliest_picks_the_nearer_deadline() {
        let near = Instant::now();
        let far = near + Duration::from_secs(1);

        assert_eq!(earliest(Some(near), Some(far)), Some(near));
        assert_eq!(earliest(Some(far), Some(near)), Some(near));
        assert_eq!(earliest(Some(near), None), Some(near));
        assert_eq!(earliest(None, Some(far)), Some(far));
        assert_eq!(earliest(None, None), None);
    }

    #[test]
    fn handle_proxy_event_drops_stale_generation() {
        let (mut sockets, handle, mut conns) = conn_at_generation(2);

        handle_proxy_event(
            &mut conns,
            &mut sockets,
            handle,
            1,
            ProxyEvent::Response(b"stale".to_vec()),
        );
        assert!(
            conns.get(&handle).unwrap().pending_to_client.is_empty(),
            "stale-generation Response must not be applied"
        );
        handle_proxy_event(&mut conns, &mut sockets, handle, 1, ProxyEvent::Error);
        assert_ne!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::Closed,
            "stale-generation Error must not abort the socket"
        );

        handle_proxy_event(
            &mut conns,
            &mut sockets,
            handle,
            2,
            ProxyEvent::Response(b"fresh".to_vec()),
        );
        assert_eq!(conns.get(&handle).unwrap().pending_to_client, b"fresh");
        handle_proxy_event(&mut conns, &mut sockets, handle, 2, ProxyEvent::Error);
        assert_eq!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::Closed,
            "current-generation Error must abort the socket"
        );
    }

    #[test]
    fn pending_to_client_admits_maximal_responses_up_to_the_cap() {
        let (mut sockets, handle, mut conns) = conn_at_generation(0);
        let maximal = || ProxyEvent::Response(vec![0u8; DNS_TCP_MAX_FRAME]);

        // Two legal 65537 byte responses are exactly the cap.
        handle_proxy_event(&mut conns, &mut sockets, handle, 0, maximal());
        handle_proxy_event(&mut conns, &mut sockets, handle, 0, maximal());
        assert_ne!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::Closed,
            "a response within the cap must not abort the connection"
        );
        assert_eq!(
            conns.get(&handle).unwrap().pending_to_client.len(),
            PENDING_TO_CLIENT_MAX
        );

        handle_proxy_event(
            &mut conns,
            &mut sockets,
            handle,
            0,
            ProxyEvent::Response(vec![0xAA]),
        );
        assert_eq!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::Closed,
            "a client not draining past the cap must be aborted"
        );
        assert_eq!(
            conns.get(&handle).unwrap().pending_to_client.len(),
            PENDING_TO_CLIENT_MAX,
            "over-cap bytes must not be appended"
        );
    }

    #[tokio::test]
    async fn request_deadline_guard_is_not_stalled_by_a_frame_stuck_in_held() {
        let (mut sockets, handle, mut conns) = conn_at_generation(0);
        let conn = conns.get_mut(&handle).unwrap();

        let (to_upstream_tx, _to_upstream_rx) = mpsc::channel(TO_UPSTREAM_CAP);
        for _ in 0..TO_UPSTREAM_CAP {
            to_upstream_tx
                .try_send(ClientMsg::Eof)
                .expect("channel must accept up to its own capacity");
        }
        conn.to_upstream = Some(to_upstream_tx);
        conn.held = Some(frame(b"stuck"));
        // A frame in progress, independent of `held`
        conn.from_client.push(&frame(b"next")[..3]);
        conn.request_deadline = Some(Instant::now() - LAPSED_AGO);

        let (events_tx, _events_rx) = mpsc::channel(EVENTS_CAP);
        let upstreams = Arc::new(Mutex::new(UpstreamList::default()));
        let mut next_generation: u64 = 1;

        service_sockets(
            &[handle],
            &mut sockets,
            &mut conns,
            &events_tx,
            &upstreams,
            Timeouts::new(TEST_UPSTREAM_TIMEOUT, TEST_CLIENT_REQUEST_TIMEOUT),
            &mut next_generation,
        )
        .await;

        let conn = conns
            .get(&handle)
            .expect("a frame stuck in `held` must not get the connection aborted");
        assert_eq!(
            conn.held.as_deref(),
            Some(frame(b"stuck").as_slice()),
            "the frame must still be waiting for a channel permit"
        );
        assert!(
            conn.request_deadline.is_none(),
            "a complete frame parked in `held` must not count as a stalled client"
        );
    }

    #[tokio::test]
    async fn request_deadline_is_rearmed_by_every_completed_frame() {
        let (mut sockets, handle, mut conns) = conn_at_generation(0);
        let conn = conns.get_mut(&handle).unwrap();

        let (to_upstream_tx, mut to_upstream_rx) = mpsc::channel(TO_UPSTREAM_CAP);
        conn.to_upstream = Some(to_upstream_tx);
        // A pipelining client whose segments do not align with frame boundaries: one whole
        // message followed by the beginning of the next.
        conn.from_client.push(&frame(b"done"));
        conn.from_client.push(&frame(b"next")[..3]);
        // Armed while the previous message was still partial, and long since lapsed.
        conn.request_deadline = Some(Instant::now() - LAPSED_AGO);

        let (events_tx, _events_rx) = mpsc::channel(EVENTS_CAP);
        let upstreams = Arc::new(Mutex::new(UpstreamList::default()));
        let mut next_generation: u64 = 1;

        service_sockets(
            &[handle],
            &mut sockets,
            &mut conns,
            &events_tx,
            &upstreams,
            Timeouts::new(TEST_UPSTREAM_TIMEOUT, TEST_CLIENT_REQUEST_TIMEOUT),
            &mut next_generation,
        )
        .await;

        assert!(
            matches!(to_upstream_rx.try_recv(), Ok(ClientMsg::Query(q)) if q == frame(b"done")),
            "the completed frame must be forwarded upstream"
        );
        let conn = conns
            .get(&handle)
            .expect("a client making progress must not be aborted");
        let deadline = conn
            .request_deadline
            .expect("the partial next message must still be under a deadline");
        assert!(
            deadline > Instant::now(),
            "the deadline must be rearmed from the completed frame, not inherited from the previous message"
        );
    }

    #[tokio::test]
    async fn client_eof_does_not_overtake_a_frame_stuck_in_held() {
        let mut conn = ConnState::new(0);
        let (to_upstream_tx, mut to_upstream_rx) = mpsc::channel(TO_UPSTREAM_CAP);
        conn.to_upstream = Some(to_upstream_tx);
        conn.held = Some(frame(b"stuck"));

        // The permit is free, as it would be the moment the proxy task drains the channel.
        forward_client_eof(&mut conn);

        assert!(
            !conn.client_eof_sent,
            "EOF must not be sent while a query is still waiting for a permit"
        );
        assert!(
            to_upstream_rx.try_recv().is_err(),
            "nothing may reach upstream ahead of the held query"
        );

        // `process_client_to_upstream` gets the held frame out on a later pass.
        let held = conn.held.take().expect("the frame must still be held");
        conn.to_upstream
            .as_ref()
            .expect("upstream channel")
            .try_send(ClientMsg::Query(held))
            .expect("channel must have room");

        forward_client_eof(&mut conn);

        assert!(
            matches!(to_upstream_rx.try_recv(), Ok(ClientMsg::Query(q)) if q == frame(b"stuck")),
            "the held query must reach upstream first"
        );
        assert!(
            matches!(to_upstream_rx.try_recv(), Ok(ClientMsg::Eof)),
            "EOF must follow the query it was queued behind"
        );
    }

    #[tokio::test]
    async fn a_reset_socket_is_pooled_instead_of_serviced_again() {
        let (mut sockets, handle, mut conns) = conn_at_generation(0);
        let conn = conns.get_mut(&handle).unwrap();

        let (to_upstream_tx, mut to_upstream_rx) = mpsc::channel(TO_UPSTREAM_CAP);
        conn.to_upstream = Some(to_upstream_tx);
        // Input left over from before the reset. `handle_proxy_event` aborts the socket without
        // touching the connection state, so a whole query can still be sitting here.
        conn.from_client.push(&frame(b"leftover"));
        sockets.get_mut::<tcp::Socket>(handle).abort();

        let (events_tx, _events_rx) = mpsc::channel(EVENTS_CAP);
        let upstreams = Arc::new(Mutex::new(UpstreamList::default()));
        let mut next_generation: u64 = 1;

        service_sockets(
            &[handle],
            &mut sockets,
            &mut conns,
            &events_tx,
            &upstreams,
            Timeouts::new(TEST_UPSTREAM_TIMEOUT, TEST_CLIENT_REQUEST_TIMEOUT),
            &mut next_generation,
        )
        .await;

        assert!(
            to_upstream_rx.try_recv().is_err(),
            "a reset connection must not forward anything it still had buffered"
        );
        assert!(
            !conns.contains_key(&handle),
            "the reset connection must be dropped"
        );
        assert_eq!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::Listen,
            "the socket must go back to the listen pool"
        );
    }
}
