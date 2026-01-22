//! Wrapped [ForwardAuthority](https://docs.rs/trust-dns-server/0.21.2/src/trust_dns_server/store/forwarder/authority.rs.html#31-34)
//! Needed to change behaviour of [tokio::net::UdpSocket]

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
};

use async_trait::async_trait;
use hickory_server::{
    authority::{
        Authority, LookupError, LookupObject, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, Record, RecordType},
        udp::{DnsUdpSocket, UdpSocket as ProtoUdpSocket},
    },
    resolver::{
        config::ResolverConfig,
        error::ResolveErrorKind,
        lookup::Lookup as ResolverLookup,
        name_server::{GenericConnector, RuntimeProvider, TokioRuntimeProvider},
        AsyncResolver,
    },
    server::RequestInfo,
    store::forwarder::ForwardConfig,
};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_trace, telio_log_warn};
use tokio::net::UdpSocket;

use crate::bind_tun;

#[derive(Default, Clone)]
pub struct TelioRuntimeProvider(TokioRuntimeProvider);

impl RuntimeProvider for TelioRuntimeProvider {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = TelioUdpSocket;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        self.0.connect_tcp(server_addr)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        Box::pin(async move {
            let sock = tokio::net::UdpSocket::bind(local_addr).await?;
            bind_tun::bind_to_tun(&sock)?;
            Ok(TelioUdpSocket(sock))
        })
    }
}

pub type TelioAsyncResolver = AsyncResolver<GenericConnector<TelioRuntimeProvider>>;

pub struct TelioUdpSocket(UdpSocket);

#[async_trait]
impl DnsUdpSocket for TelioUdpSocket {
    type Time = <tokio::net::UdpSocket as DnsUdpSocket>::Time;

    fn poll_recv_from(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<(usize, std::net::SocketAddr)>> {
        DnsUdpSocket::poll_recv_from(&self.0, cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        target: std::net::SocketAddr,
    ) -> std::task::Poll<io::Result<usize>> {
        DnsUdpSocket::poll_send_to(&self.0, cx, buf, target)
    }
}

#[async_trait]
impl ProtoUdpSocket for TelioUdpSocket {
    async fn bind(addr: std::net::SocketAddr) -> io::Result<Self> {
        telio_log_trace!("binding to address {:?}", addr);
        let sock = UdpSocket::bind(addr).await?;
        bind_tun::bind_to_tun(&sock)?;
        Ok(Self(sock))
    }

    /// setups up a "client" udp connection that will only receive packets from the associated address
    ///
    /// if the addr is ipv4 then it will bind local addr to 0.0.0.0:0, ipv6 \[::\]0
    async fn connect(addr: std::net::SocketAddr) -> io::Result<Self> {
        let bind_addr: std::net::SocketAddr = match addr {
            std::net::SocketAddr::V4(_addr) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            std::net::SocketAddr::V6(_addr) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };

        Self::connect_with_bind(addr, bind_addr).await
    }

    async fn connect_with_bind(
        _addr: std::net::SocketAddr,
        bind_addr: std::net::SocketAddr,
    ) -> io::Result<Self> {
        let socket = Self::bind(bind_addr).await?;

        // TODO from the upstream trust-dns:
        // research connect more, it appears to break UDP receiving tests, etc...
        // socket.connect(addr).await?;

        Ok(socket)
    }
}

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the trust-dns-resolver for resolving requests.
pub struct ForwardAuthority {
    origin: LowerName,
    resolver: TelioAsyncResolver,
}

impl ForwardAuthority {
    /// Read the Authority for the origin from the specified configuration
    pub async fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: ForwardConfig,
    ) -> Result<Self, String> {
        telio_log_info!("loading forwarder config: {}", origin);

        let name_servers = config.name_servers;
        let mut options = config.options.unwrap_or_default();

        // See RFC 1034, Section 4.3.2:
        // "If the data at the node is a CNAME, and QTYPE doesn't match
        // CNAME, copy the CNAME RR into the answer section of the response,
        // change QNAME to the canonical name in the CNAME RR, and go
        // back to step 1."
        //
        // Essentially, it's saying that servers (including forwarders)
        // should emit any found CNAMEs in a response ("copy the CNAME
        // RR into the answer section"). This is the behavior that
        // preserve_intemediates enables when set to true, and disables
        // when set to false. So we set it to true.
        if !options.preserve_intermediates {
            telio_log_warn!(
                "preserve_intermediates set to false, which is invalid \
                for a forwarder; switching to true"
            );
            options.preserve_intermediates = true;
        }

        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let resolver = TelioAsyncResolver::new(config, options, GenericConnector::default());

        telio_log_info!("forward resolver configured: {}: ", origin);

        // TODO: this might be infallible?
        Ok(Self {
            origin: origin.into(),
            resolver,
        })
    }
}

#[async_trait::async_trait]
impl Authority for ForwardAuthority {
    type Lookup = ForwardLookup;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        // TODO: make this an error?
        debug_assert!(self.origin.zone_of(name));

        telio_log_debug!("forwarding lookup: {} {}", name, rtype);
        let resolve = self.resolver.lookup(name.clone(), rtype).await;

        // Log DNS failures
        match resolve {
            // Some errors are not really relevant, and happens in a wild often.
            // For example: no IPs associated with domain especially for AAAA queries
            //
            // Log such errors with lower logging level
            Err(ref e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
                telio_log_debug!("DNS name resolution failed (no records): {:?}", e);
            }

            Err(ref e) => {
                #[cfg(debug_assertions)]
                telio_log_debug!("DNS name resolution failed: {:?}", e);

                #[cfg(not(debug_assertions))]
                telio_log_warn!("DNS name resolution failed");
            }
            Ok(_) => (),
        };

        resolve
            .map(ForwardLookup)
            .map_err(|code| match code.kind() {
                ResolveErrorKind::NoRecordsFound {
                    query: _,
                    soa: _,
                    negative_ttl: _,
                    response_code,
                    trusted: _,
                } => {
                    if *response_code == ResponseCode::NoError {
                        telio_log_debug!("Got an error response with NoError code for {name}, this should not happen so converting to ServFail");
                        // Failed query with no error - convert that to a real error,
                        // otherwise the LookupError::from will panic in debug builds.
                        // If we use a number from the 'private use' range:
                        // https://datatracker.ietf.org/doc/html/rfc2929#section-2.3 like
                        // LookupError::from(ResponseCode::Unknown(3841))
                        // the trust-dns will end up looping until the requests with some other error
                        // is returned. This will make the original dns request (eg. by nslookup or dig or some app)
                        // never complete. To avoid that, lets return ServFail which will produce
                        // an empty respones.
                        LookupError::from(ResponseCode::ServFail)
                    } else {
                        LookupError::from(*response_code)
                    }
                }
                // NOTE: this is probably incorrect, and should be at least 24, most likely
                // in range 3841-4095 ('private use' range), instead of '0'.
                _ => LookupError::from(ResponseCode::Unknown(0)),
            })
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Err(LookupError::from(io::Error::other(
            "Getting NSEC records is unimplemented for the forwarder",
        )))
    }
}

pub struct ForwardLookup(ResolverLookup);

impl LookupObject for ForwardLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.record_iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}
