//! Forwarding zone handler built on the upstream hickory resolver.
//!
//! Replaces the patched `ForwardAuthority` from the NordSecurity hickory fork. The fork's
//! behaviour is kept on the libtelio side:
//! - upstream sockets are bound to the tunnel ([TelioRuntimeProvider])
//! - one UDP send per upstream, retries belong to the OS resolver ([TelioConnectionProvider])
//! - failures that the fork turned into "no reply" become SERVFAIL here, which
//!   [crate::zone::ClonableZones::lookup] drops

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::Duration,
};

use async_trait::async_trait;
use hickory_server::{
    net::{
        runtime::{RuntimeProvider, TokioRuntimeProvider},
        udp::UdpClientStream,
        xfer::DnsExchange,
        DnsError, NetError, NoRecords,
    },
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, RecordType, TSigResponseContext},
    },
    resolver::{
        config::{
            ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts,
        },
        ConnectionProvider, PoolContext, Resolver,
    },
    server::{Request, RequestInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
        ZoneHandler, ZoneType,
    },
};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_trace, telio_log_warn};
use tokio::net::UdpSocket;

use crate::{bind_tun, error::Error};

/// Tokio runtime whose UDP sockets are bound to the tunnel interface
#[derive(Default, Clone)]
pub struct TelioRuntimeProvider(TokioRuntimeProvider);

impl RuntimeProvider for TelioRuntimeProvider {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = UdpSocket;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        self.0.connect_tcp(server_addr, bind_addr, timeout)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        Box::pin(async move {
            telio_log_trace!("binding to address {:?}", local_addr);
            let sock = UdpSocket::bind(local_addr).await?;
            bind_tun::bind_to_tun(&sock)?;
            Ok(sock)
        })
    }
}

/// Connection provider sending each query once per upstream.
///
/// Upstream hickory re-sends a UDP query to the same server up to three times within the
/// timeout. The OS resolver already retries, so doing it here too doubles the retries
/// (the iOS issue behind LLT-4202).
#[derive(Default, Clone)]
pub struct TelioConnectionProvider(TelioRuntimeProvider);

impl ConnectionProvider for TelioConnectionProvider {
    type Conn = DnsExchange<TelioRuntimeProvider>;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send + 'static>>;
    type RuntimeProvider = TelioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        match config.protocol {
            ProtocolConfig::Udp => {
                let builder =
                    UdpClientStream::builder(SocketAddr::new(ip, config.port), self.0.clone())
                        .with_timeout(Some(cx.options.timeout))
                        .with_os_port_selection(cx.options.os_port_selection)
                        .avoid_local_ports(cx.options.avoid_local_udp_ports.clone())
                        .with_bind_addr(config.bind_addr)
                        .with_max_retries(1);
                Ok(Box::pin(async move { Ok(builder.exchange()) }))
            }
            _ => self.0.new_connection(ip, config, cx),
        }
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.0
    }
}

pub type TelioResolver = Resolver<TelioConnectionProvider>;

/// A zone handler that will forward resolutions to upstream resolvers.
pub struct ForwardAuthority {
    origin: LowerName,
    resolver: TelioResolver,
}

impl ForwardAuthority {
    pub fn new(
        origin: Name,
        name_servers: Vec<NameServerConfig>,
        mut options: ResolverOpts,
    ) -> Result<Self, Error> {
        telio_log_info!("loading forwarder config: {}", origin);

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
        let resolver = Resolver::builder_with_config(config, TelioConnectionProvider::default())
            .with_options(options)
            .build()?;

        telio_log_info!("forward resolver configured: {}: ", origin);

        Ok(Self {
            origin: origin.into(),
            resolver,
        })
    }

    /// Drop every entry from the resolver's cache.
    ///
    /// Removes both positive and negative (NXDOMAIN) entries. Needed when
    /// something outside DNS changes what an answer ought to be - see LLT-7558,
    /// where a TP-Lite whitelist change alters whether a query gets redirected,
    /// but a cached answer would be returned without the query ever reaching
    /// the firewall.
    pub fn flush_cache(&self) {
        self.resolver.clear_cache();
    }
}

/// Map a resolver error the way the NordSecurity hickory fork answered it.
///
/// An upstream answer without records, or with an error code, is relayed as NXDOMAIN or an empty
/// NOERROR, without the upstream SOA. Any other failure means no upstream answered; it becomes
/// SERVFAIL, which [crate::zone::ClonableZones::lookup] turns into "no reply".
fn forward_result(name: &LowerName, error: NetError) -> Result<AuthLookup, LookupError> {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords { response_code, .. }))
        | NetError::Dns(DnsError::ResponseCode(response_code)) => {
            telio_log_debug!("DNS name resolution failed (no records): {name} {response_code}");
            if response_code == ResponseCode::NXDomain {
                Err(LookupError::ResponseCode(ResponseCode::NXDomain))
            } else {
                Ok(AuthLookup::Empty)
            }
        }
        error => {
            #[cfg(debug_assertions)]
            telio_log_debug!("DNS name resolution failed: {:?}", error);

            #[cfg(not(debug_assertions))]
            telio_log_warn!("DNS name resolution failed");

            Err(LookupError::NetError(error))
        }
    }
}

#[async_trait]
impl ZoneHandler for ForwardAuthority {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
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
        _request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // TODO: make this an error?
        debug_assert!(self.origin.zone_of(name));

        telio_log_debug!("forwarding lookup: {} {}", name, rtype);
        let result = match self.resolver.lookup(Name::from(name), rtype).await {
            // Answers only, like the fork: upstream authority and additional sections are dropped
            Ok(lookup) => Ok(AuthLookup::answers(
                LookupRecords::Section(lookup.answers().to_vec()),
                None,
            )),
            Err(error) => forward_result(name, error),
        };
        LookupControlFlow::Continue(result)
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        // The catalog answers REFUSED to these anyway, but only after the lookup. Like the fork,
        // don't send the query upstream at all.
        if !request.metadata.recursion_desired {
            return (LookupControlFlow::Break(Ok(AuthLookup::Empty)), None);
        }

        let request_info = match request.request_info() {
            Ok(request_info) => request_info,
            Err(e) => return (LookupControlFlow::Break(Err(e)), None),
        };
        let result = self
            .lookup(
                request_info.query.name(),
                request_info.query.query_type(),
                Some(&request_info),
                lookup_options,
            )
            .await;
        (result, None)
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::Io(io::Error::other(
            "Getting NSEC records is unimplemented for the forwarder",
        ))))
    }
}
