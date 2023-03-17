use async_trait::async_trait;
use base64::encode as encodeBase64;
use boringtun::{
    crypto::x25519::{X25519PublicKey, X25519SecretKey},
    noise::{errors::WireGuardError, Tunn, TunnResult},
};
use bytecodec::{DecodeExt, EncodeExt, Error as ByteCodecError};
use futures::{task::Poll, Future};
use ipnet::{Ipv4Net, PrefixLenError};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    udp::{MutableUdpPacket, UdpPacket},
    Packet,
};
use rand::Rng;
use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use stun_codec::{
    rfc5389::{
        attributes::{MappedAddress, Software, XorMappedAddress},
        methods::BINDING,
        Attribute,
    },
    BrokenMessage, Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
};
use telio_crypto::SecretKey;
use telio_sockets::External;

use thiserror::Error as ThisError;
use tokio::{net::UdpSocket, time::Duration};

use telio_relay::derp::{Config as ServersConfig, Server};
use telio_task::{
    io::{
        chan::{Rx, Tx},
        Chan,
    },
    task_exec, BoxAction, Runtime, Task,
};
use telio_utils::{
    telio_log_debug, telio_log_info, telio_log_trace, telio_log_warn, Hidden, PinnedSleep,
};

#[cfg(test)]
use mockall::{automock, predicate::*};

/// Posible [Stunner] errors.
#[derive(ThisError, Debug)]
pub enum Error {
    /// Tried to use IPv6 address for STUN
    #[error("Stunner does not support IPv6 proto")]
    IPv6NotSupported,
    /// Interface is not initialized
    #[error("STUN server not found")]
    InterfaceEmpty,
    /// Unexpected packet received
    #[error("Stunner received unexpected packet")]
    UnexpectedPacket,
    /// General failure
    #[error("Stunner failed")]
    StunFailed,
    /// Config does not contain any servers
    #[error("Server list empty")]
    ServerNotFound,
    /// Received broken message from STUN server
    #[error("Stunner broken msg: {0:?}")]
    MsgDecode(BrokenMessage),
    /// No results from STUN server
    #[error("Stunner does not have valid endpoints")]
    NoResults,
    /// Wireguard error
    #[error("Stunner WG tunnel error: {0:?}")]
    WGError(WireGuardError),
    /// Error on Boringtun side
    #[error("Boringtun error: {0}")]
    Boringtun(String),
    /// Error in parsing X25519 keys
    #[error("X25519 key error: {0}")]
    X25519(String),
    /// Error, when defining subnet
    #[error(transparent)]
    PrefixLen(#[from] PrefixLenError),
    /// UDP socket error
    #[error(transparent)]
    SocketError(#[from] std::io::Error),
    /// WG message mismatch
    #[error(transparent)]
    WgMessageTypeError(#[from] TryFromPrimitiveError<WgMessageType>),
    /// Packet error
    #[error("Packet error: {0}")]
    PacketError(String),
    /// Codec error
    #[error(transparent)]
    ByteCodec(#[from] ByteCodecError),
}

#[cfg(not(test))]
const STUN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const STUN_TIMEOUT: Duration = Duration::from_millis(200);

const MAX_PACKET: usize = 4096_usize;
const STUN_SRV_MESH_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 4));

type Session = (TransactionId, PinnedSleep<()>);
pub type Result<T> = std::result::Result<T, Error>;
pub type StunPacket = Vec<u8>;

#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
pub enum WgMessageType {
    HandshakeInitiation = 0x01,
    HandshakeResponse = 0x02,
    CookieReply = 0x03,
    DataExchange = 0x04,
}

#[cfg_attr(test, automock)]
pub trait LocalEndpoints: Send + Default {
    fn get(&self, udp_socket: &External<UdpSocket>) -> Option<Vec<SocketAddr>>;
}

#[derive(Default)]
pub struct LocalEndpointsImpl;

impl LocalEndpoints for LocalEndpointsImpl {
    fn get(&self, udp_socket: &External<UdpSocket>) -> Option<Vec<SocketAddr>> {
        self.get_impl(udp_socket).map_or_else(
            |e| {
                telio_log_warn!("Failed to fetch local endpoints: {}", e.to_string());
                None
            },
            Some,
        )
    }
}

impl LocalEndpointsImpl {
    fn get_impl(&self, udp_socket: &External<UdpSocket>) -> Result<Vec<SocketAddr>> {
        let port = udp_socket.local_addr()?.port();
        let shared_range: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)?; //is_shared() unstable
        Ok(if_addrs::get_if_addrs()?
            .into_iter()
            .filter(|x| !x.addr.is_loopback())
            .filter(|x| match x.addr.ip() {
                // Filter 100.64/10 libtelio's meshnet network.
                IpAddr::V4(v4) => !shared_range.contains(&v4),
                // Filter IPv6
                _ => false,
            })
            .map(|x| SocketAddr::new(x.addr.ip(), port))
            .collect())
    }
}

#[derive(Clone, Default)]
pub struct Results {
    pub remote: Option<Hidden<SocketAddr>>,
    pub local: Option<Vec<SocketAddr>>,
}

impl Results {
    pub fn new(local: Option<Vec<SocketAddr>>) -> Self {
        Self {
            remote: None,
            local,
        }
    }

    pub fn to_vec(&self) -> Result<Vec<Hidden<SocketAddr>>> {
        if self.is_empty() {
            return Err(Error::NoResults);
        }

        let mut v: Vec<Hidden<SocketAddr>> = vec![];

        if let Some(remote) = self.remote {
            v.push(remote);
        }

        if let Some(local) = &self.local {
            v.extend(local.iter().copied().map(Hidden));
        }

        Ok(v)
    }

    fn is_empty(&self) -> bool {
        self.remote.is_none() && self.local.is_none()
    }
}

pub struct Config {
    pub plain_text_fallback: bool,
    pub servers: ServersConfig,
}

pub struct Stunner<T: LocalEndpoints = LocalEndpointsImpl> {
    task: Task<State<T>>,
}

impl<T: LocalEndpoints + 'static> Stunner<T> {
    /// Stunner constructor
    fn start_with_local_endpoints(
        udp_socket: Arc<External<UdpSocket>>,
        config: Option<Config>,
        local_endpoints: Option<T>,
    ) -> (Self, Tx<(StunPacket, SocketAddr)>) {
        // We do not want this to be very large ...
        let Chan { tx, rx } = Chan::default();

        let mut config = config;

        if let Some(c) = &mut config {
            c.servers.reset();
        }

        let local_endpoints = local_endpoints.unwrap_or_default();

        (
            Self {
                task: Task::start(State {
                    interface: Interface::new(config),
                    results: Results::new(local_endpoints.get(&udp_socket)),
                    data_tx: udp_socket,
                    data_rx: rx,
                    session: None,
                    local_endpoints,
                }),
            },
            tx,
        )
    }

    /// Attempt to perform STUN
    /// If the first server in the list is unreachable,
    /// it will move to the next one, until the successful response is received
    pub async fn do_stun(&self) -> Result<()> {
        task_exec!(&self.task, async move |s| Ok(s.do_stun().await))
            .await
            .map_err(|_| Error::StunFailed)?
    }

    /// Collect endpoints
    pub async fn fetch_endpoints(&self) -> Result<Results> {
        task_exec!(&self.task, async move |s| {
            Ok(if s.results.is_empty() {
                Err(Error::NoResults)
            } else {
                Ok(s.results.clone())
            })
        })
        .await
        .map_err(|_| Error::StunFailed)?
    }

    pub async fn configure(&self, config: Option<Config>) {
        let _ = task_exec!(&self.task, async move |s| {
            s.interface.configure(config);
            s.abort_session();
            s.clear_results();
            let _ = s.do_stun().await;
            Ok(())
        })
        .await;
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

impl Stunner {
    /// Stunner constructor
    pub fn start(
        udp_socket: Arc<External<UdpSocket>>,
        config: Option<Config>,
    ) -> (Self, Tx<(StunPacket, SocketAddr)>) {
        Stunner::start_with_local_endpoints(udp_socket, config, Some(LocalEndpointsImpl))
    }
}

enum Backend {
    Wg(Option<Box<Tunn>>),
    Plaintext,
}

impl Default for Backend {
    fn default() -> Self {
        Self::Wg(None)
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wg(_) => write!(f, "Wg"),
            Self::Plaintext => write!(f, "Plaintext"),
        }
    }
}

struct Interface {
    config: Option<Config>,
    current_server: Option<Server>,
    backend: Backend,
    buf: [u8; MAX_PACKET],
}

impl Interface {
    const IP_HEADER: usize = 20;
    const UDP_HEADER: usize = 8;

    pub fn new(config: Option<Config>) -> Self {
        let backend = Backend::default();

        Self {
            config,
            current_server: None,
            backend,
            buf: [0u8; MAX_PACKET],
        }
    }

    pub fn is_ready(&self) -> bool {
        self.addr().is_some()
    }

    pub fn reset(&mut self) -> Result<()> {
        if let Backend::Wg(ref mut tun) = &mut self.backend {
            telio_log_debug!("Reseting WG interface");

            *tun = Some(Self::create_wg_tun(
                self.current_server.as_ref().ok_or(Error::InterfaceEmpty)?,
                &self
                    .config
                    .as_ref()
                    .ok_or(Error::InterfaceEmpty)?
                    .servers
                    .secret_key,
            )?);
        }

        Ok(())
    }

    fn addr(&self) -> Option<SocketAddr> {
        if let Some(server) = &self.current_server {
            return Some(SocketAddr::new(
                std::net::IpAddr::V4(server.ipv4),
                if matches!(self.backend, Backend::Plaintext) {
                    server.stun_plaintext_port
                } else {
                    server.stun_port
                },
            ));
        }

        None
    }

    fn create_wg_tun(server: &Server, private_key: &SecretKey) -> Result<Box<Tunn>> {
        let client_secret: Arc<X25519SecretKey> = Arc::new(
            encodeBase64(private_key)
                .parse()
                .map_err(|e: &str| Error::X25519(e.to_string()))?,
        );

        let server_pub: Arc<X25519PublicKey> =
            Arc::new(X25519PublicKey::from(&server.public_key[..]));

        Tunn::new(client_secret, server_pub, None, Some(2), 0, None)
            .map_err(|e| Error::Boringtun(e.to_string()))
    }

    pub fn configure(&mut self, config: Option<Config>) {
        if let Some(config) = config {
            let c = self.config.insert(config);
            c.servers.reset();
        } else {
            self.config = None;
        }
    }

    pub async fn send_request(
        &mut self,
        socket: Arc<External<UdpSocket>>,
    ) -> Result<TransactionId> {
        if let Some(dst) = self.addr() {
            let stun_src = SocketAddr::new(
                match self.backend {
                    Backend::Wg(_) => {
                        self.config
                            .as_ref()
                            .ok_or(Error::InterfaceEmpty)?
                            .servers
                            .mesh_ip
                    }
                    Backend::Plaintext => socket.local_addr()?.ip(),
                },
                socket.local_addr()?.port(),
            );

            let stun_dst = SocketAddr::new(
                match self.backend {
                    Backend::Wg(_) => STUN_SRV_MESH_ADDR,
                    Backend::Plaintext => dst.ip(),
                },
                dst.port(),
            );

            let (packet, tid) = Self::prepare_stun_request(&stun_src, &stun_dst)?;

            match self.backend {
                // NOTE: This encapsulate only queues data packet, and will generate only
                //       WireGuard handshake initiation packet. The data packet will be sent within
                //       the decapsulate loop only within handle_stun_rx() after receiving handshake
                //       response.
                Backend::Wg(ref mut tun) => {
                    if let Some(tun) = tun {
                        match tun.encapsulate(&packet, &mut self.buf) {
                            TunnResult::WriteToNetwork(enc) => {
                                socket.send_to(enc, dst).await?;
                                return Ok(tid);
                            }
                            TunnResult::Err(e) => return Err(Error::WGError(e)),
                            TunnResult::Done => return Ok(tid),
                            _ => return Err(Error::Boringtun("Encapsulation failed".to_owned())),
                        }
                    } else {
                        return Err(Error::Boringtun("Tunnel is not initialized".to_owned()));
                    }
                }
                Backend::Plaintext => {
                    socket.send_to(&packet, dst).await?;
                    return Ok(tid);
                }
            }
        }

        Err(Error::InterfaceEmpty)
    }

    // Re-using futures::task::Poll for returning 3 states: Ok, Err and Pending
    pub async fn handle_response(
        &mut self,
        payload: &[u8],
        src_addr: &SocketAddr,
        socket: Arc<External<UdpSocket>>,
    ) -> Poll<Result<(Hidden<SocketAddr>, TransactionId)>> {
        if let Some(expected_addr) = self.addr() {
            if *src_addr != expected_addr {
                // Not from (requested) STUN server
                telio_log_debug!(
                    "Expected packet from {}, received from {}",
                    expected_addr,
                    src_addr
                );
                return Poll::Ready(Err(Error::UnexpectedPacket));
            }

            let decap_buf = &mut self.buf;

            match self.backend {
                Backend::Wg(ref mut tun) => {
                    if let Some(tun) = tun {
                        match tun.decapsulate(None, payload, decap_buf) {
                            TunnResult::WriteToNetwork(p) => {
                                telio_log_debug!(
                                    "Received {:?} packet from STUN server",
                                    WgMessageType::try_from(p[0])?
                                );

                                // Responding
                                socket.send_to(p, expected_addr).await?;

                                loop {
                                    match tun.decapsulate(None, &[], decap_buf) {
                                        TunnResult::WriteToNetwork(queued) => {
                                            telio_log_debug!("Sending queued packet");
                                            socket.send_to(queued, expected_addr).await?;
                                        }
                                        TunnResult::Err(e) => {
                                            telio_log_debug!(
                                                "Decapsulate queued packet failed ({:?})",
                                                e
                                            );
                                            return Poll::Ready(Err(Error::WGError(e)));
                                        }
                                        TunnResult::Done => {
                                            telio_log_debug!("Sending queued packet done!");
                                            return Poll::Pending;
                                        }
                                        _ => {
                                            return Poll::Ready(Err(Error::StunFailed));
                                        }
                                    }
                                }
                            }
                            TunnResult::WriteToTunnelV4(packet, _) => {
                                return Poll::Ready(Self::decode_reflexive_endpoint(packet));
                            }
                            TunnResult::Err(e) => {
                                telio_log_debug!("Decapsulate packet failed ({:?})", e);
                                return Poll::Ready(Err(Error::WGError(e)));
                            }
                            _ => (),
                        };
                    }
                }
                Backend::Plaintext => {
                    return Poll::Ready(Self::decode_reflexive_endpoint(payload));
                }
            }
        }

        Poll::Ready(Err(Error::InterfaceEmpty))
    }

    pub fn next(&mut self) -> Result<()> {
        if let Some(config) = &mut self.config {
            let mut switch_proto = false;

            let server = match config.servers.get_server() {
                Some(server) => server,
                None => {
                    telio_log_warn!("STUN server list exhausted, reseting config ...");

                    config.servers.reset();
                    let server = config.servers.get_server().ok_or(Error::ServerNotFound)?;

                    // We've tried all servers with wg, fallback to plaintext or wg
                    if config.plain_text_fallback {
                        switch_proto = true;
                    }

                    server
                }
            };

            let b = &mut self.backend;

            match b {
                Backend::Wg(ref mut tun) => {
                    if switch_proto {
                        *b = Backend::Plaintext;
                    } else if tun.is_none() {
                        telio_log_debug!("Creating new WG interface");
                        *tun = Some(Self::create_wg_tun(&server, &config.servers.secret_key)?);
                    }
                }
                Backend::Plaintext => {
                    if switch_proto {
                        *b = Backend::Wg(Some(Self::create_wg_tun(
                            &server,
                            &config.servers.secret_key,
                        )?));
                    }
                }
            }

            let s = self.current_server.insert(server);

            if switch_proto {
                telio_log_info!("Switching to {:?} mode", b);
            }

            telio_log_info!(
                "Trying STUN server: {} ({}:{}) in {:?} mode",
                &s.hostname,
                &s.ipv4,
                if matches!(b, Backend::Plaintext) {
                    &s.stun_plaintext_port
                } else {
                    &s.stun_port
                },
                b,
            );

            return Ok(());
        }

        Err(Error::InterfaceEmpty)
    }

    /// Prepare Ipv4 packet request for STUN server
    fn prepare_stun_request(
        src: &SocketAddr,
        dst: &SocketAddr,
    ) -> Result<(Vec<u8>, TransactionId)> {
        let tid = TransactionId::new(rand::thread_rng().gen::<[u8; 12]>());
        let mut msg = Message::<Attribute>::new(MessageClass::Request, BINDING, tid);
        msg.add_attribute(Attribute::Software(Software::new("Libtelio".to_string())?));

        let rq = MessageEncoder::new().encode_into_bytes(msg)?;

        let length = Self::IP_HEADER + Self::UDP_HEADER + rq.len();
        let mut packet = vec![0u8; length];

        let mut ipv4 = MutableIpv4Packet::new(packet.as_mut())
            .ok_or_else(|| Error::PacketError("MutableIpv4Packet create".to_owned()))?;
        ipv4.set_version(4);
        ipv4.set_header_length((Self::IP_HEADER / 4) as u8);
        ipv4.set_total_length(length as u16);
        ipv4.set_flags(0b0000_0010);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4.set_source(match src.ip() {
            IpAddr::V4(ip4) => ip4,
            _ => {
                return Err(Error::IPv6NotSupported);
            }
        });
        ipv4.set_destination(match dst.ip() {
            IpAddr::V4(ip4) => ip4,
            _ => {
                return Err(Error::IPv6NotSupported);
            }
        });

        let mut udp = MutableUdpPacket::new(packet[Self::IP_HEADER..].as_mut())
            .ok_or_else(|| Error::PacketError("MutableUdpPacket create".to_owned()))?;

        udp.set_source(src.port());
        udp.set_destination(dst.port());
        udp.set_length((Self::UDP_HEADER + rq.len()) as u16);
        udp.set_payload(&rq);

        Ok((packet, tid))
    }

    /// Decode reflexive endpoint from STUN response
    fn decode_reflexive_endpoint(buf: &[u8]) -> Result<(Hidden<SocketAddr>, TransactionId)> {
        let mut decoder = MessageDecoder::<Attribute>::new();
        let decoded = decoder
            .decode_from_bytes(
                UdpPacket::new(
                    Ipv4Packet::new(buf)
                        .ok_or_else(|| Error::PacketError("Ipv4Packet parse".to_owned()))?
                        .payload(),
                )
                .ok_or_else(|| Error::PacketError("UdpPacket parse".to_owned()))?
                .payload(),
            )?
            .map_err(Error::MsgDecode)?;

        let tid = decoded.transaction_id();

        let x_m_addr = decoded
            .get_attribute::<XorMappedAddress>()
            .map(|x| x.address());
        let m_addr = decoded
            .get_attribute::<MappedAddress>()
            .map(|x| x.address());
        let addr = x_m_addr.or(m_addr).ok_or(Error::StunFailed)?;

        Ok((Hidden(addr), tid))
    }
}

struct State<T: LocalEndpoints> {
    /// Reference to UDP socket for sending STUN requests
    data_tx: Arc<External<UdpSocket>>,
    /// Current `Tun` interface
    interface: Interface,
    /// Cached results
    results: Results,
    /// Rx packets from socket
    data_rx: Rx<(StunPacket, SocketAddr)>,
    /// Current STUN session
    session: Option<Session>,
    /// Object used to fetch local endpoints
    local_endpoints: T,
}

impl<T: LocalEndpoints> State<T> {
    // Will try to do STUN requests, until it receives the response
    pub async fn do_stun(&mut self) -> Result<()> {
        if self.is_stunning() {
            return Ok(());
        }

        // Must be the first time someone is calling it
        if !self.interface.is_ready() {
            self.interface.next()?;
        }

        let tid = self.interface.send_request(self.data_tx.clone()).await?;

        self.new_session(tid);

        Ok(())
    }

    pub async fn handle_stun_rx(&mut self, payload: &[u8], src_addr: &SocketAddr) -> Result<()> {
        if let Some((curr_tid, _)) = self.session {
            let result = self
                .interface
                .handle_response(payload, src_addr, self.data_tx.clone())
                .await;

            match result {
                Poll::Pending => {
                    // We are still waiting for response
                    return Ok(());
                }
                Poll::Ready(r) => {
                    self.results = Results::new(self.local_endpoints.get(&self.data_tx));

                    match r {
                        Ok((addr, tid)) => {
                            if curr_tid != tid {
                                return Err(Error::UnexpectedPacket);
                            }

                            telio_log_info!("Received reflexive endpoint: {}", &addr);
                            let _ = self.results.remote.insert(addr);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }

                    // We have received the response
                    self.abort_session();

                    return Ok(());
                }
            }
        }

        Err(Error::UnexpectedPacket)
    }

    pub async fn handle_stun_timeout(&mut self) -> Result<()> {
        // Aborting current session
        self.abort_session();

        // Clears all results (if there was any) and tries to insert only local endpoints
        self.clear_results();

        // Rotating current server, cause it didn't work out
        self.interface.next()?;

        // Try once again
        self.do_stun().await?;

        Ok(())
    }

    /// Checks, if this module is actually stunning at the given moment :)
    fn is_stunning(&self) -> bool {
        self.session.is_some()
    }

    /// Starts new session, with timeout
    fn new_session(&mut self, tid: TransactionId) {
        let _ = self
            .session
            .insert((tid, PinnedSleep::new(STUN_TIMEOUT, ())));
    }

    fn abort_session(&mut self) {
        self.session = None;
        let _ = self.interface.reset();
    }

    /// Clears results, and tries to insert local ones
    fn clear_results(&mut self) {
        self.results = Results::new(self.local_endpoints.get(&self.data_tx));
    }
}

#[async_trait]
impl<T: LocalEndpoints> Runtime for State<T> {
    const NAME: &'static str = "Stunner";

    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        // Borrow checker is happy :)
        let session = &mut self.session;

        let timeout = async move {
            match session {
                Some((_, timeout)) => {
                    timeout.await;
                    Ok(())
                }
                _ => Err(()),
            }
        };

        tokio::select! {
            // Reading data from UDP socket (passed by node, that is awaiting on socket's receive)
            Some((packet, src_addr)) = self.data_rx.recv() => {
                if self.is_stunning() {
                    telio_log_trace!("({}) handle_stun_rx(&packet[..], &src_addr: {})", Self::NAME, src_addr);
                    self.handle_stun_rx(&packet[..], &src_addr)
                        .await
                        .map_or_else(|e| {
                            telio_log_warn!("({}) Error handling stun rx: {}", Self::NAME, e.to_string());
                            Ok(())
                        }, |_| Ok(()))?;
                }
            }
            // Session timeouted, move to next one
            Ok(()) = timeout => {
                telio_log_trace!("({}) handle_stun_timeout()", Self::NAME);
                self.handle_stun_timeout()
                    .await
                    .map_or_else(|e| {
                        telio_log_warn!("({}) Error handling stun timeout: {}", Self::NAME, e.to_string());
                        Ok(())
                    }, |_| Ok(()))?;
            }
            update = update => {
                return update(self).await;
            }
            else => {
                return Ok(());
            },
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telio_crypto::{PublicKey, SecretKey};
    use telio_relay::derp::Server as DerpServer;
    use telio_sockets::SocketPool;
    use tokio::time;

    async fn prepare_test_setup<T: LocalEndpoints + 'static>(
        local_endpoints: Option<T>,
    ) -> (
        Stunner<T>,
        Tx<(StunPacket, SocketAddr)>,
        SocketAddr,
        UdpSocket,
        UdpSocket,
        SocketPool,
    ) {
        let socket_pool = SocketPool::default();
        let stunner_sock = Arc::new(
            socket_pool
                .new_external_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), None)
                .await
                .expect("Cannot create UdpSocket"),
        );
        let mut stunner_addr = stunner_sock
            .local_addr()
            .expect("Cannot get Stunner socket address: ");
        stunner_addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let server_sock_0 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("Cannot create UdpSocket: ");

        let mut server_addr_0 = server_sock_0
            .local_addr()
            .expect("Cannot fetch our udp_socket addr");
        server_addr_0.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let server_sock_1 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("Cannot create UdpSocket: ");

        let mut server_addr_1 = server_sock_1
            .local_addr()
            .expect("Cannot fetch our udp_socket addr");
        server_addr_1.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        let config = Some(Config {
            plain_text_fallback: true,
            servers: ServersConfig {
                secret_key: "+KWHh2lvjUkIDwP9v1OYNDw8U7iIwfOQthZpU556EXc="
                    .parse::<SecretKey>()
                    .unwrap(),
                servers: vec![
                    DerpServer {
                        hostname: "a1234.nordvpn.com".into(),
                        ipv4: match server_addr_0.ip() {
                            IpAddr::V4(a) => a,
                            _ => panic!("IPv6 not supported"),
                        },
                        stun_port: server_addr_0.port(),
                        public_key: "m2dAcgvH44gVSku8rsNm0kg9I/7HfHAJhz2VsxhWbWY="
                            .parse::<PublicKey>()
                            .unwrap(),
                        ..Default::default()
                    },
                    DerpServer {
                        hostname: "b4321.nordvpn.com".into(),
                        ipv4: match server_addr_1.ip() {
                            IpAddr::V4(a) => a,
                            _ => panic!("IPv6 not supported"),
                        },
                        stun_port: server_addr_1.port(),
                        public_key: "wtg69ojsF3mKu7hOqpLjinTTEFO4klvKTiVmse8bf1E="
                            .parse::<PublicKey>()
                            .unwrap(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        });

        let (stunner, stunner_tx) =
            Stunner::start_with_local_endpoints(stunner_sock, config, local_endpoints);

        (
            stunner,
            stunner_tx,
            stunner_addr,
            server_sock_0,
            server_sock_1,
            socket_pool,
        )
    }

    #[tokio::test]
    async fn server_list_exhaust() {
        // Expect call to first server
        // Expect call to second server
        // Expect call to first server
        let (stunner, stunner_tx, stun_addr, server_sock_0, server_sock_1, _pool) =
            prepare_test_setup::<LocalEndpointsImpl>(None).await;

        let _ = stunner.do_stun().await.unwrap();

        // Runtime
        let _ = tokio::spawn(async move {
            let timeout = time::sleep(STUN_TIMEOUT * 5);
            tokio::pin!(timeout);

            let mut rx_buff_0 = [0; MAX_PACKET];
            let mut rx_buff_1 = [0; MAX_PACKET];

            let mut rq_cnt = 0;

            loop {
                tokio::select! {
                    Ok((_, addr)) = server_sock_0.recv_from(&mut rx_buff_0) => {
                        assert_eq!(addr, stun_addr, "Stun socket address does not match");

                        match rq_cnt {
                            0 => {
                                // Send fake data, stunner should ignore this, and jump to other server
                                stunner_tx.send((vec![0; 128], server_sock_0.local_addr().unwrap())).await.unwrap();
                                rq_cnt += 1;
                                continue;
                            }
                            2 => {
                                // Server list is reset, success
                                break;
                            }
                            _ => {
                                assert!(false, "Bad test's state!");
                            }
                        }
                    }
                    Ok((_, addr)) = server_sock_1.recv_from(&mut rx_buff_1) => {
                        assert_eq!(addr, stun_addr, "Stun socket address does not match");

                        match rq_cnt {
                            1 => {
                                // This server is silent, stunner should ignore this as well
                                rq_cnt += 1;
                                continue;
                            }
                            _ => {
                                assert!(false, "Bad test's state!");
                            }
                        }
                    }
                    _ = &mut timeout => {
                        assert!(false, "Timeout!");
                    }
                }
            }

            let _ = stunner.stop().await;
        })
        .await;
    }

    #[tokio::test]
    async fn local_interfaces_available_before_stun_req_timeout() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(12, 34, 56, 78)), 5678);

        let mut local_endpoints_mock = MockLocalEndpoints::new();
        let local_addr_cpy = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(12, 34, 56, 78)), 5678);
        local_endpoints_mock
            .expect_get()
            .returning(move |_| Some(vec![local_addr_cpy]));

        let (stunner, _, _, _, _, _) = prepare_test_setup(Some(local_endpoints_mock)).await;

        let _ = stunner.do_stun().await.unwrap();
        let results = stunner.fetch_endpoints().await.unwrap();

        assert!(results.local.is_some());
        let local_results = results.local.unwrap();
        assert!(local_results.len() == 1);
        assert!(local_results[0] == local_addr);

        let _ = stunner.stop().await;
    }
}
