//! TCP forwarder engine implemented with smoltcp.

use crate::tcp_forwarder::frame::{is_nord_frame, MessageReader, DNS_TCP_LEN_PREFIX};
use crate::tcp_forwarder::proxy::{run_proxy, ClientMsg, ProxyEvent};
use crate::tcp_forwarder::syn_backlog::{admit_syns, SynBacklog};
use crate::tcp_forwarder::Timeouts;
use crate::upstream::UpstreamList;
use bytes::{Buf, BytesMut};
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
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::OwnedPermit;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;

pub(crate) const TO_UPSTREAM_CAP: usize = 1;
pub(crate) const EVENTS_CAP: usize = 16;

const DEVICE_MTU: usize = 1280;
const DNS_IPV4_ADDRS: [Ipv4Addr; 2] = [DNS_VIRTUAL_PEER_IPV4, DNS_VIRTUAL_PEER_ON_EXIT_IPV4];
const SUBNET_MASK: u8 = 32;

const TCP_SOCKET_BUF: usize = 16 * 1024;
const DNS_TCP_MAX_FRAME: usize = DNS_TCP_LEN_PREFIX + u16::MAX as usize;
const PENDING_TO_CLIENT_MAX: usize = 2 * DNS_TCP_MAX_FRAME;

const CLIENT_SOCKET_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Tasks waiting for a free slot in a connection upstream channel
type ReserveWaiters = JoinSet<(SocketHandle, u64)>;

/// Suspend aware clock for smoltcp's timers.
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
    /// A waiter is armed for a free slot in the upstream channel.
    reserve_wait: bool,
    /// Bytes from upstream to be written into the smoltcp socket.
    pending_to_client: BytesMut,
    /// No further responses will arrive, close once `pending_to_client` drains.
    responses_done: bool,
    /// Sent client's EOF to upstream.
    client_eof_sent: bool,
    /// Generation this connection was created.
    generation: u64,
    /// Last client message started, completed or upstream response read.
    last_activity: Instant,
    /// Bytes in socket send_queue or `pending_to_client`.
    unsent: usize,
    /// Closing an idle connection.
    idle_closing: bool,
    /// Deadline for the socket to reach `Closed`.
    close_deadline: Option<Instant>,
}

impl ConnState {
    fn new(generation: u64) -> Self {
        ConnState {
            to_upstream: None,
            from_client: MessageReader::default(),
            held: None,
            reserve_wait: false,
            pending_to_client: BytesMut::new(),
            responses_done: false,
            client_eof_sent: false,
            generation,
            last_activity: Instant::now(),
            unsent: 0,
            idle_closing: false,
            close_deadline: None,
        }
    }

    /// Waiting on the client, either to finish its message or to send a new one.
    fn awaits_client(&self) -> bool {
        self.unsent > 0 || (self.held.is_none() && !self.idle_closing && !self.client_eof_sent)
    }

    /// Earliest instant at which `service_sockets` must look at this connection.
    fn deadline(&self, client_idle: Duration) -> Option<Instant> {
        let progress = self
            .awaits_client()
            .then(|| self.last_activity + client_idle);
        earliest(progress, self.close_deadline)
    }

    fn abort(&mut self) {
        self.from_client.clear();
        self.held = None;
    }
}

/// Outcome of trying to get a slot in the upstream channel.
enum Reservation {
    Ready(OwnedPermit<ClientMsg>),
    /// Channel full, a waiter wakes the engine once the proxy frees a slot.
    Waiting,
    /// The proxy task is gone.
    Closed,
}

/// Get a slot in the upstream channel, arming a waiter if it is full.
fn reserve_upstream(
    handle: SocketHandle,
    connection: &mut ConnState,
    waiters: &mut ReserveWaiters,
) -> Reservation {
    let Some(sender) = connection.to_upstream.clone() else {
        return Reservation::Closed;
    };
    match sender.try_reserve_owned() {
        Ok(permit) => Reservation::Ready(permit),
        Err(TrySendError::Full(sender)) => {
            if !connection.reserve_wait {
                connection.reserve_wait = true;
                let generation = connection.generation;
                waiters.spawn(async move {
                    let _ = sender.reserve_owned().await;
                    (handle, generation)
                });
            }
            Reservation::Waiting
        }
        Err(TrySendError::Closed(_)) => Reservation::Closed,
    }
}

/// A waiter found a free slot or the proxy gone.
fn reserve_waiter_done(
    connections: &mut HashMap<SocketHandle, ConnState>,
    handle: SocketHandle,
    generation: u64,
) {
    if let Some(connection) = connections.get_mut(&handle) {
        if connection.generation == generation {
            connection.reserve_wait = false;
        }
    }
}

/// Handle an upstream proxy event into the matching connection.
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
                telio_log_debug!(
                    "Client not draining ({:?}), pending_to_client would exceed {} B, aborting",
                    handle,
                    PENDING_TO_CLIENT_MAX,
                );
                sockets.get_mut::<tcp::Socket>(handle).abort();
            } else {
                connection.pending_to_client.extend_from_slice(&bytes);
                connection.last_activity = Instant::now();
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
    reserve_waiters: &mut ReserveWaiters,
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
            let at_boundary = connection.from_client.partial_len() == 0;
            match socket.recv(|buf| {
                connection.from_client.push(buf);
                (buf.len(), buf.len())
            }) {
                Ok(n) if n > 0 => {
                    if at_boundary {
                        connection.last_activity = Instant::now();
                    }
                    continue;
                }
                _ => return true,
            }
        };
        connection.last_activity = Instant::now();

        if is_nord_frame(&frame) {
            telio_log_debug!("TCP DNS query for .nord, aborting");
            socket.abort();
            connection.abort();
            return false;
        }

        if connection.to_upstream.is_none() {
            if upstreams.lock().await.addrs().is_empty() {
                telio_log_warn!("No upstream configured, aborting");
                socket.abort();
                connection.abort();
                return false;
            }
            telio_log_trace!("First TCP DNS query on {:?}, connecting upstream", handle,);
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

        match reserve_upstream(handle, connection, reserve_waiters) {
            Reservation::Ready(permit) => {
                permit.send(ClientMsg::Query(frame));
            }
            Reservation::Waiting => {
                // Hold the frame so the receive window closes and
                // the client stalls, rather than buffering without bound.
                connection.held = Some(frame);
                return true;
            }
            Reservation::Closed => {
                telio_log_debug!("Upstream proxy gone ({:?}), aborting", handle);
                socket.abort();
                connection.abort();
                return false;
            }
        }
    }
}

/// Pass the client FIN on to the proxy task, only when nothing is queued behind it.
fn forward_client_eof(
    handle: SocketHandle,
    connection: &mut ConnState,
    reserve_waiters: &mut ReserveWaiters,
) {
    if connection.client_eof_sent || connection.held.is_some() {
        return;
    }
    match reserve_upstream(handle, connection, reserve_waiters) {
        Reservation::Ready(permit) => {
            permit.send(ClientMsg::Eof);
            connection.client_eof_sent = true;
        }
        Reservation::Waiting => {}
        // No proxy, or it already reported how it ended, nothing more will arrive.
        Reservation::Closed => {
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
#[allow(clippy::too_many_arguments)]
async fn service_sockets(
    handles: &[SocketHandle],
    sockets: &mut SocketSet<'_>,
    connections: &mut HashMap<SocketHandle, ConnState>,
    events_tx: &mpsc::Sender<(SocketHandle, u64, ProxyEvent)>,
    reserve_waiters: &mut ReserveWaiters,
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
                "New TCP DNS connection on {:?} (gen {})",
                handle,
                generation,
            );
            connections.insert(handle, ConnState::new(generation));
        }

        if let Some(connection) = connections.get_mut(&handle) {
            if !connection.idle_closing
                && !process_client_to_upstream(
                    handle,
                    socket,
                    connection,
                    events_tx,
                    reserve_waiters,
                    upstreams,
                    timeouts.upstream_reply,
                )
                .await
            {
                // Skip the State::Closed -> listen() below
                // re-listening now would reset the socket and discard the queued RST
                aborted_this_pass = true;
                continue;
            }

            // Upstream to client.
            while !connection.pending_to_client.is_empty() && socket.can_send() {
                match socket.send_slice(&connection.pending_to_client) {
                    Ok(n) if n > 0 => {
                        connection.pending_to_client.advance(n);
                    }
                    _ => break,
                }
            }

            // Any segment from the client resets smoltcp's own timeout
            // a client that keeps ACKing without acknowledging its responses must be caught here.
            let now = Instant::now();
            let unsent = connection.pending_to_client.len() + socket.send_queue();
            if unsent < connection.unsent {
                connection.last_activity = now;
            }
            connection.unsent = unsent;

            // Likewise a client that started a message and stopped, or only keeps the
            // connection alive.
            if connection.awaits_client() && now >= connection.last_activity + timeouts.client_idle
            {
                if unsent == 0 && connection.from_client.partial_len() == 0 {
                    telio_log_debug!("TCP DNS connection idle ({:?}), closing", handle);
                    connection.idle_closing = true;
                } else {
                    telio_log_debug!("Client stalled ({:?}), aborting", handle);
                    socket.abort();
                    connection.abort();
                    aborted_this_pass = true;
                    continue;
                }
            }

            // Client FIN, fully drained.
            if connection.idle_closing || (!socket.may_recv() && !socket.can_recv()) {
                forward_client_eof(handle, connection, reserve_waiters);
            }

            // Upstream finished.
            if connection.responses_done && connection.pending_to_client.is_empty() {
                socket.close();
                connection
                    .close_deadline
                    .get_or_insert(now + timeouts.client_idle);
            }

            if connection
                .close_deadline
                .is_some_and(|deadline| now >= deadline)
                && socket.state() != tcp::State::Closed
            {
                telio_log_debug!("Client did not complete close ({:?}), aborting", handle);
                socket.abort();
                connection.abort();
                aborted_this_pass = true;
                continue;
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
    let mut reserve_waiters = ReserveWaiters::new();
    let mut next_generation: u64 = 0;
    let mut syn_backlog = SynBacklog::default();

    telio_log_debug!(
        "TCP forwarder loop started with {} listening sockets",
        handles.len(),
    );

    loop {
        let poll_deadline = iface
            .poll_delay(clock.now(), &sockets)
            .map(|d| Instant::now() + Duration::from_micros(d.total_micros()));
        let conn_deadline = conns
            .values()
            .filter_map(|c| c.deadline(timeouts.client_idle))
            .min();
        let deadline = earliest(poll_deadline, conn_deadline);

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
            Some(waiter) = reserve_waiters.join_next(), if !reserve_waiters.is_empty() => {
                if let Ok((handle, generation)) = waiter {
                    reserve_waiter_done(&mut conns, handle, generation);
                }
            },
            _ = async {
                match deadline {
                    Some(dl) => sleep_until(dl).await,
                    None => std::future::pending().await,
                }
            } => {}
        }

        // Drain any queued ingress packets.
        while let Ok(pkt) = ingress.try_recv() {
            device.rx.push_back(pkt);
        }

        // Drain any queued proxy events.
        while let Ok((handle, generation, event)) = events_rx.try_recv() {
            handle_proxy_event(&mut conns, &mut sockets, handle, generation, event);
        }

        admit_syns(&mut device.rx, &sockets, &mut syn_backlog);
        iface.poll(clock.now(), &mut device, &mut sockets);
        let aborted = service_sockets(
            &handles,
            &mut sockets,
            &mut conns,
            &events_tx,
            &mut reserve_waiters,
            &upstreams,
            timeouts,
            &mut next_generation,
        )
        .await;
        // Flush anything service_sockets produced, in particular an abort's RST.
        iface.poll(clock.now(), &mut device, &mut sockets);

        if aborted {
            // The RST should be queued and the aborted socket may safely return
            // to Listen. service_sockets skipped this before to avoid discarding it.
            service_sockets(
                &handles,
                &mut sockets,
                &mut conns,
                &events_tx,
                &mut reserve_waiters,
                &upstreams,
                timeouts,
                &mut next_generation,
            )
            .await;
        }

        // Hand held SYNs to sockets just returned to the pool
        if !syn_backlog.is_empty() {
            admit_syns(&mut device.rx, &sockets, &mut syn_backlog);
            iface.poll(clock.now(), &mut device, &mut sockets);
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
        assert_eq!(&conns.get(&handle).unwrap().pending_to_client[..], b"fresh");
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
    async fn a_frame_stuck_in_held_is_not_a_stalled_client() {
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
        conn.last_activity = Instant::now() - LAPSED_AGO;

        let (events_tx, _events_rx) = mpsc::channel(EVENTS_CAP);
        let upstreams = Arc::new(Mutex::new(UpstreamList::default()));
        let mut reserve_waiters = ReserveWaiters::new();
        let mut next_generation: u64 = 1;

        service_sockets(
            &[handle],
            &mut sockets,
            &mut conns,
            &events_tx,
            &mut reserve_waiters,
            &upstreams,
            Timeouts::new(TEST_UPSTREAM_TIMEOUT, TEST_CLIENT_IDLE_TIMEOUT),
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
    }

    #[tokio::test]
    async fn a_completed_frame_restarts_the_progress_timer() {
        let (mut sockets, handle, mut conns) = conn_at_generation(0);
        let conn = conns.get_mut(&handle).unwrap();

        let (to_upstream_tx, mut to_upstream_rx) = mpsc::channel(TO_UPSTREAM_CAP);
        conn.to_upstream = Some(to_upstream_tx);
        // A pipelining client whose segments do not align with frame boundaries: one whole
        // message followed by the beginning of the next.
        conn.from_client.push(&frame(b"done"));
        conn.from_client.push(&frame(b"next")[..3]);
        // Last progress long enough ago that the timer has lapsed.
        conn.last_activity = Instant::now() - LAPSED_AGO;

        let (events_tx, _events_rx) = mpsc::channel(EVENTS_CAP);
        let upstreams = Arc::new(Mutex::new(UpstreamList::default()));
        let mut reserve_waiters = ReserveWaiters::new();
        let mut next_generation: u64 = 1;

        service_sockets(
            &[handle],
            &mut sockets,
            &mut conns,
            &events_tx,
            &mut reserve_waiters,
            &upstreams,
            Timeouts::new(TEST_UPSTREAM_TIMEOUT, TEST_CLIENT_IDLE_TIMEOUT),
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
        assert!(
            conn.last_activity.elapsed() < TEST_CLIENT_IDLE_TIMEOUT,
            "the timer must be restarted by the completed frame, not inherited from before it"
        );
    }

    #[tokio::test]
    async fn client_eof_does_not_overtake_a_frame_stuck_in_held() {
        let handle = test_handle();
        let mut reserve_waiters = ReserveWaiters::new();
        let mut conn = ConnState::new(0);
        let (to_upstream_tx, mut to_upstream_rx) = mpsc::channel(TO_UPSTREAM_CAP);
        conn.to_upstream = Some(to_upstream_tx);
        conn.held = Some(frame(b"stuck"));

        // The permit is free, as it would be the moment the proxy task drains the channel.
        forward_client_eof(handle, &mut conn, &mut reserve_waiters);

        assert!(
            !conn.client_eof_sent,
            "EOF must not be sent while a query is still waiting for a permit"
        );
        assert!(
            to_upstream_rx.try_recv().is_err(),
            "nothing may reach upstream ahead of the held query"
        );

        conn.held = None;
        forward_client_eof(handle, &mut conn, &mut reserve_waiters);

        assert!(
            matches!(to_upstream_rx.try_recv(), Ok(ClientMsg::Eof)),
            "EOF must be sent once nothing is held"
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
        let mut reserve_waiters = ReserveWaiters::new();
        let mut next_generation: u64 = 1;

        service_sockets(
            &[handle],
            &mut sockets,
            &mut conns,
            &events_tx,
            &mut reserve_waiters,
            &upstreams,
            Timeouts::new(TEST_UPSTREAM_TIMEOUT, TEST_CLIENT_IDLE_TIMEOUT),
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
