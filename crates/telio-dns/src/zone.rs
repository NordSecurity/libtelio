use crate::{
    forward::ForwardAuthority, packet_decoder::normalize_qname, packet_encoder::ResponseKind,
};
use async_trait::async_trait;
use hickory_server::{
    proto::{
        op::ResponseCode,
        rr::{rdata, rdata::SOA, LowerName, Name, RData, Record, RecordType, TSigResponseContext},
    },
    resolver::config::{NameServerConfig, ResolveHosts, ResolverOpts},
    server::{Request, RequestInfo, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{
        AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions,
        ZoneHandler, ZoneType,
    },
};
use pnet_packet::dns::{DnsQuery, DnsTypes};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use telio_model::{constants::DNS_PORT, features::TtlValue};
use telio_utils::{telio_log_debug, telio_log_warn};
use thiserror::Error;

use crate::error::{Error, Result as DnsResult};
pub(crate) const NORD_ZONE: &str = "nord.";
pub(crate) const NORD_ZONE_SUFFIX: &str = ".nord.";

/// Zone is a portion of the DNS namespace that is managed by a specific
/// organization or administrator.
pub(crate) type Zones = Catalog;

/// Records (aka zone files) are instructions that live in authoritative
/// DNS servers and provide information about a domain including what IP
/// address is associated with that domain and how to handle requests
/// for that domain.
pub type Records = HashMap<String, Vec<IpAddr>>;

/// Errors returned by local nord zone resolver
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NordZoneError {
    /// Record contains a non nord entry
    #[error("record contains non-nord entry {0}")]
    NonNordRecord(String),
}

/// Parse `name` as a fully qualified name.
///
/// hickory 0.26 no longer treats `nord` and `nord.` as equal, while the zone and records
/// libtelio gets (e.g. `dns.upsert("nord", ...)`) may lack the trailing dot.
pub(crate) fn fqdn(name: &str) -> Result<Name, hickory_server::proto::ProtoError> {
    let mut name = Name::from_str(name)?;
    name.set_fqdn(true);
    Ok(name)
}

/// Helper to split a slice of IpAddr into a tuple of Ipv4Addr and Ipv6Addr iterators
fn split_addresses(
    ip: &[IpAddr],
) -> (
    impl Iterator<Item = &Ipv4Addr>,
    impl Iterator<Item = &Ipv6Addr>,
) {
    let iter = ip.iter();

    let v4 = iter.clone().filter_map(|ip| match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    });

    let v6 = iter.filter_map(|ip| match ip {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => Some(v6),
    });

    (v4, v6)
}

/// Struct that holds the local .nord zone records
#[derive(Default)]
pub(crate) struct NordZone {
    /// .nord peer records
    records: Records,
    /// TTL used to populate local nord zone replies
    ttl: TtlValue,
}

impl NordZone {
    /// Create a new local nord zone resolver
    pub(crate) fn new() -> Self {
        Self {
            records: Records::new(),
            ttl: TtlValue::default(),
        }
    }

    /// Populate the local nord zone resolver with records
    pub(crate) fn upsert(
        &mut self,
        records: &Records,
        ttl_value: TtlValue,
    ) -> Result<(), NordZoneError> {
        let nord_zone = records
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                let normalized = normalize_qname(k);

                normalized
                    .ends_with(NORD_ZONE_SUFFIX)
                    .then(|| (normalized, v.clone()))
                    .ok_or_else(|| NordZoneError::NonNordRecord(k.clone()))
            })
            .collect::<Result<Records, _>>()?;

        telio_log_debug!("Nord zone resolver upsert with: {:?}", nord_zone);

        self.records = nord_zone;
        self.ttl = ttl_value;

        Ok(())
    }

    /// Get TTL value
    pub(crate) fn ttl(&self) -> TtlValue {
        self.ttl
    }

    /// Helper to find the matching local .nord record
    ///
    /// Handles exact matches and explicit wildcard records
    fn find_matching_nord_record(&self, qname: &str) -> Option<&[IpAddr]> {
        if let Some(addresses) = self.records.get(qname) {
            return Some(addresses);
        }

        let mut remaining = qname;
        let mut wildcard = String::with_capacity(qname.len());

        while let Some((_, rest)) = remaining.split_once('.') {
            if !rest.ends_with(NORD_ZONE_SUFFIX) {
                break;
            }

            if !wildcard.is_empty() {
                wildcard.push('.');
            }
            wildcard.push('*');

            let key = format!("{wildcard}.{rest}");
            if let Some(addresses) = self.records.get(&key) {
                return Some(addresses);
            }
            remaining = rest;
        }
        None
    }

    /// Resolve the local .nord request
    pub(crate) fn resolve_local_response(&self, query: &DnsQuery) -> ResponseKind {
        if query.qtype == DnsTypes::SOA {
            return ResponseKind::SoaAnswer;
        }

        let qname = normalize_qname(&query.get_qname_parsed());

        // Query for .nord TLD
        if qname == NORD_ZONE {
            return ResponseKind::NoData;
        }

        let Some(addresses) = self.find_matching_nord_record(&qname) else {
            // No records exist
            return ResponseKind::NxDomain;
        };

        let (ipv4, ipv6) = split_addresses(addresses);

        match query.qtype {
            DnsTypes::A => {
                let addresses: Vec<Ipv4Addr> = ipv4.copied().collect();
                if !addresses.is_empty() {
                    return ResponseKind::AnswerA { addresses };
                }
            }
            DnsTypes::AAAA => {
                let addresses: Vec<Ipv6Addr> = ipv6.copied().collect();
                if !addresses.is_empty() {
                    return ResponseKind::AnswerAAAA { addresses };
                }
            }
            _ => {}
        }
        ResponseKind::NoData
    }
}

/// AuthoritativeZone is a zone for which the local server references its
/// own data when responding to queries.
pub(crate) struct AuthoritativeZone {
    pub(crate) zone: InMemoryZoneHandler,
}

impl AuthoritativeZone {
    pub(crate) async fn new(name: &str, records: &Records, ttl_value: TtlValue) -> DnsResult<Self> {
        // TODO: rewrite code so that this assert is not needed.
        for domain in records.keys() {
            if !domain.contains(name) {
                return Err(Error::RecordOutsideZone(domain.into(), name.into()));
            }
        }
        let zone_name = fqdn(name)?;
        let zone =
            InMemoryZoneHandler::empty(zone_name.clone(), ZoneType::Primary, AxfrPolicy::Deny);
        let ttl_value_signed: i32 = match ttl_value.0.try_into() {
            Ok(ttl_value) => ttl_value,
            Err(_) => {
                let default = TtlValue::default().0 as i32;
                telio_log_warn!("TTL value could not be converted from u32 to i32 without data loss, so using default value: {default}");
                default
            }
        };
        zone.upsert(
            Record::from_rdata(
                zone_name,
                ttl_value.0,
                RData::SOA(SOA::new(
                    Name::parse("mesh.nordsec.com.", None)?,
                    Name::parse("support.nordsec.com.", None)?,
                    2015082403,
                    7200,
                    ttl_value_signed,
                    1209600,
                    ttl_value.0,
                )),
            ),
            0,
        )
        .await;

        let build_record =
            |name: Name, data: RData| -> Record { Record::from_rdata(name, ttl_value.0, data) };

        for (name, record) in records.iter() {
            let name = fqdn(name)?;
            for ip in record.iter() {
                match *ip {
                    IpAddr::V4(ipv4) => {
                        let _ = zone
                            .upsert(build_record(name.clone(), RData::A(rdata::A(ipv4))), 0)
                            .await;
                    }
                    IpAddr::V6(ipv6) => {
                        let _ = zone
                            .upsert(
                                build_record(name.clone(), RData::AAAA(rdata::AAAA(ipv6))),
                                0,
                            )
                            .await;
                    }
                }
            }
        }

        Ok(AuthoritativeZone { zone })
    }
}

#[async_trait]
impl ZoneHandler for AuthoritativeZone {
    fn zone_type(&self) -> ZoneType {
        self.zone.zone_type()
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        self.zone.axfr_policy()
    }

    async fn update(
        &self,
        update: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        self.zone.update(update, now).await
    }

    fn origin(&self) -> &LowerName {
        self.zone.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.zone
            .lookup(name, rtype, request_info, lookup_options)
            .await
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        self.zone.search(request, lookup_options).await
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.zone.nsec_records(name, lookup_options).await
    }
}

/// ForwardZone allows the DNS Server to resolve queries where the client
/// sends a name to the DNS Server to request the IP address of the requested
/// host.
pub(crate) struct ForwardZone {
    pub(crate) zone: ForwardAuthority,
}

impl ForwardZone {
    pub(crate) async fn new(name: &str, ips: &[IpAddr]) -> DnsResult<Self> {
        let upstreams: Vec<_> = ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, DNS_PORT))
            .collect();
        Self::with_upstreams(name, &upstreams, Self::options())
    }

    fn options() -> ResolverOpts {
        let mut options = ResolverOpts::default();
        // Some tools and browsers do not accept responses without intermediates preserved
        options.preserve_intermediates = true;
        // We provide our own forward servers, so we don't need to look at the hosts file
        options.use_hosts_file = ResolveHosts::Never;

        options.num_concurrent_reqs = 1;

        // We set the number of retries to 0. The retry should be handled by the OS retry mechanism
        options.attempts = 0;

        // Defaults of hickory 0.24 (the NordSecurity fork), changed upstream in 0.26
        options.edns0 = false;
        options.cache_size = 32;

        options
    }

    fn with_upstreams(
        name: &str,
        upstreams: &[SocketAddr],
        options: ResolverOpts,
    ) -> DnsResult<Self> {
        let name_servers = upstreams
            .iter()
            .map(|upstream| {
                let mut config = NameServerConfig::udp_and_tcp(upstream.ip());
                for connection in &mut config.connections {
                    connection.port = upstream.port();
                }
                config
            })
            .collect();

        let zone = ForwardAuthority::new(Name::from_str(name)?, name_servers, options)?;
        Ok(ForwardZone { zone })
    }

    /// Drop every entry from the underlying resolver's cache.
    pub(crate) fn flush_cache(&self) {
        self.zone.flush_cache();
    }
}

#[async_trait]
impl ZoneHandler for ForwardZone {
    fn zone_type(&self) -> ZoneType {
        self.zone.zone_type()
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        self.zone.axfr_policy()
    }

    fn origin(&self) -> &LowerName {
        self.zone.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.zone
            .lookup(name, rtype, request_info, lookup_options)
            .await
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        self.zone.search(request, lookup_options).await
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.zone.nsec_records(name, lookup_options).await
    }
}

#[derive(Default)]
pub(crate) struct ClonableZones {
    zones: Zones,
    names: HashSet<LowerName>,
}

impl ClonableZones {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, name: LowerName, handler: Arc<dyn ZoneHandler>) {
        self.zones.upsert(name.clone(), vec![handler]);
        self.names.insert(name);
    }

    /// Look the request up, returning an error where the NordSecurity hickory fork did.
    ///
    /// Upstream hickory always writes a response into `response_handle`. The fork instead
    /// returned an error, so libtelio sent nothing and the client's own retry took over, when:
    /// - no upstream answered (SERVFAIL, see [crate::forward])
    /// - the query has recursion disabled, or no zone matches it (REFUSED)
    pub async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> Result<ResponseInfo, LookupError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let info = self.zones.lookup(request, None, now, response_handle).await;
        match info.response_code {
            code @ (ResponseCode::ServFail | ResponseCode::Refused) => {
                Err(LookupError::ResponseCode(code))
            }
            _ => Ok(info),
        }
    }

    #[cfg(test)]
    pub fn contains(&self, name: &LowerName) -> bool {
        self.names.contains(name) && self.zones.find(name).is_some()
    }
}

impl Clone for ClonableZones {
    fn clone(&self) -> Self {
        Self {
            zones: self
                .names
                .iter()
                .flat_map(|name| self.zones.find(name).map(|handlers| (name, handlers)))
                .fold(Zones::new(), |mut zone, (name, handlers)| {
                    zone.upsert(name.clone(), handlers.clone());
                    zone
                }),
            names: self.names.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    macro_rules! records {
        ($($domain:expr => [$($ip:expr),+ $(,)?]),+ $(,)?) => {{
            let mut r = Records::new();
            $(r.insert(String::from($domain), vec![$($ip),+]);)+
            r
        }};
        ($($domain:expr => []),+ $(,)?) => {{
            let mut r = Records::new();
            $(r.insert(String::from($domain), vec![]);)+
            r
        }};
    }

    fn make_dns_query(name: &str, qtype: pnet_packet::dns::DnsType) -> DnsQuery {
        let mut qname = Vec::new();
        let trimmed = name.trim_end_matches('.');
        for label in trimmed.split('.') {
            qname.push(label.len() as u8);
            qname.extend_from_slice(label.as_bytes());
        }
        qname.push(0);
        DnsQuery {
            qname,
            qtype,
            qclass: pnet_packet::dns::DnsClasses::IN,
            payload: vec![],
        }
    }

    fn new_nord_zone_with_upsert(records: &Records) -> NordZone {
        let mut nord_zone = NordZone::new();
        nord_zone.upsert(records, TtlValue(60)).unwrap();
        nord_zone
    }

    async fn validate_record(
        zone: &AuthoritativeZone,
        name: &str,
        expected_ipv4: Option<Ipv4Addr>,
        expected_ipv6: Option<Ipv6Addr>,
    ) {
        let lookup = zone
            .lookup(
                &fqdn(name).unwrap().into(),
                RecordType::A,
                None,
                Default::default(),
            )
            .await
            .map_result()
            .unwrap();

        if let Some(expected_ipv4) = expected_ipv4 {
            let lookup = lookup.unwrap();
            let records: Vec<&Record> = lookup.iter().collect();
            assert_eq!(records.len(), 1);
            let record = records[0];
            assert_eq!(record.name, fqdn(name).unwrap());
            assert_eq!(record.data, RData::A(rdata::A(expected_ipv4)));
        } else {
            assert!(matches!(lookup, Err(LookupError::NameExists)));
        }

        let lookup = zone
            .lookup(
                &fqdn(name).unwrap().into(),
                RecordType::AAAA,
                None,
                Default::default(),
            )
            .await
            .map_result()
            .unwrap();

        if let Some(expected_ipv6) = expected_ipv6 {
            let lookup = lookup.unwrap();
            let records: Vec<&Record> = lookup.iter().collect();
            assert_eq!(records.len(), 1);
            let record = records[0];
            assert_eq!(record.name, fqdn(name).unwrap());
            assert_eq!(record.data, RData::AAAA(rdata::AAAA(expected_ipv6)));
        } else {
            assert!(matches!(lookup, Err(LookupError::NameExists)));
        }
    }

    #[tokio::test]
    async fn test_authoritative_zone() {
        let alpha_ipv4 = Ipv4Addr::new(1, 2, 3, 4);
        let alpha_ipv6 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let beta_ipv4 = Ipv4Addr::new(4, 3, 2, 1);
        let gamma_ipv6 = Ipv6Addr::new(8, 7, 6, 5, 4, 3, 2, 1);

        let mut records = HashMap::new();
        records.insert(
            String::from("alpha.nord"),
            vec![IpAddr::V4(alpha_ipv4), IpAddr::V6(alpha_ipv6)],
        );
        records.insert(String::from("beta.nord"), vec![IpAddr::V4(beta_ipv4)]);
        records.insert(String::from("gamma.nord"), vec![IpAddr::V6(gamma_ipv6)]);

        let zone = AuthoritativeZone::new("nord", &records, TtlValue(60))
            .await
            .unwrap();

        validate_record(&zone, "alpha.nord", Some(alpha_ipv4), Some(alpha_ipv6)).await;
        validate_record(&zone, "beta.nord", Some(beta_ipv4), None).await;
        validate_record(&zone, "gamma.nord", None, Some(gamma_ipv6)).await;
    }

    #[test]
    fn find_matching_nord_record_exact_without_wildcard() {
        let records = records! {
            "test.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };
        let nz = new_nord_zone_with_upsert(&records);

        assert_eq!(
            nz.find_matching_nord_record("test.nord."),
            Some([IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))].as_slice())
        );
        assert_eq!(nz.find_matching_nord_record("a.test.nord."), None);
        assert_eq!(nz.find_matching_nord_record("a.b.test.nord."), None);
        assert_eq!(nz.find_matching_nord_record("other.nord."), None);
    }

    #[test]
    fn find_matching_nord_record_wildcard() {
        let records = records! {
            "*.alpha.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };
        let nz = new_nord_zone_with_upsert(&records);

        assert_eq!(
            nz.find_matching_nord_record("foo.alpha.nord."),
            Some([IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))].as_slice())
        );
        assert_eq!(
            nz.find_matching_nord_record("bar.alpha.nord."),
            Some([IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))].as_slice())
        );
        assert_eq!(nz.find_matching_nord_record("alpha.nord."), None);
        assert_eq!(nz.find_matching_nord_record("foo.bar.alpha.nord."), None);

        assert_eq!(nz.find_matching_nord_record("evil.nord.alpha.nord."), None);
        assert_eq!(nz.find_matching_nord_record("nord.example.com."), None);
        assert_eq!(nz.find_matching_nord_record("alice.nord.com."), None);
    }

    #[test]
    fn find_matching_nord_record_double_wildcard() {
        let records = records! {
            "*.*.beta.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
        };
        let nz = new_nord_zone_with_upsert(&records);

        assert_eq!(
            nz.find_matching_nord_record("foo.bar.beta.nord."),
            Some([IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))].as_slice())
        );
        assert_eq!(nz.find_matching_nord_record("foo.beta.nord."), None);
        assert_eq!(nz.find_matching_nord_record("beta.nord."), None);
        assert_eq!(nz.find_matching_nord_record("a.b.c.beta.nord."), None);
    }

    #[test]
    fn find_matching_nord_record_exact_preferred() {
        let records = records! {
            "*.alpha.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
            "specific.alpha.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
        };
        let nz = new_nord_zone_with_upsert(&records);

        assert_eq!(
            nz.find_matching_nord_record("specific.alpha.nord."),
            Some([IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))].as_slice())
        );
        assert_eq!(
            nz.find_matching_nord_record("other.alpha.nord."),
            Some([IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))].as_slice())
        );
    }

    #[test]
    fn find_matching_nord_record_boundary() {
        let records = records! {
            "*.*.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };
        let nz = new_nord_zone_with_upsert(&records);

        assert_eq!(nz.find_matching_nord_record(""), None);
        assert_eq!(nz.find_matching_nord_record("."), None);
        assert_eq!(nz.find_matching_nord_record("nord"), None);
        assert_eq!(nz.find_matching_nord_record("nord."), None);
        assert_eq!(nz.find_matching_nord_record(".nord."), None);
        assert_eq!(nz.find_matching_nord_record("..nord."), None);
        assert_eq!(nz.find_matching_nord_record("...nord."), None);
    }

    #[test]
    fn lookup_local_response_soa() {
        let nz = new_nord_zone_with_upsert(&Records::new());
        let query = make_dns_query("test.nord", DnsTypes::SOA);
        assert_eq!(nz.resolve_local_response(&query), ResponseKind::SoaAnswer);
    }

    #[test]
    fn lookup_local_response_nord_tld() {
        let records = records! {
            "test.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };
        let nz = new_nord_zone_with_upsert(&records);
        let query = make_dns_query("nord", DnsTypes::A);
        assert_eq!(nz.resolve_local_response(&query), ResponseKind::NoData);
    }

    #[test]
    fn lookup_local_response_a_record() {
        let records = records! {
            "test.nord." => [
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)),
            ],
        };
        let nz = new_nord_zone_with_upsert(&records);
        let query = make_dns_query("test.nord", DnsTypes::A);
        assert_eq!(
            nz.resolve_local_response(&query),
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(100, 64, 0, 1)]
            }
        );
    }

    #[test]
    fn lookup_local_response_aaaa_record() {
        let records = records! {
            "test.nord." => [
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)),
            ],
        };
        let nz = new_nord_zone_with_upsert(&records);
        let query = make_dns_query("test.nord", DnsTypes::AAAA);
        assert_eq!(
            nz.resolve_local_response(&query),
            ResponseKind::AnswerAAAA {
                addresses: vec![Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)]
            }
        );
    }

    #[test]
    fn lookup_local_response_nxdomain() {
        let records = records! {
            "test.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };
        let nz = new_nord_zone_with_upsert(&records);
        let query = make_dns_query("unknown.nord", DnsTypes::A);
        assert_eq!(nz.resolve_local_response(&query), ResponseKind::NxDomain);
    }

    #[test]
    fn lookup_local_response_only_aaaa_exists() {
        let records = records! {
            "test.nord." => [IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8))],
        };
        let nz = new_nord_zone_with_upsert(&records);
        let query = make_dns_query("test.nord", DnsTypes::A);
        assert_eq!(nz.resolve_local_response(&query), ResponseKind::NoData);
    }

    #[test]
    fn upsert_only_contains_nord_domains() {
        let records = records! {
            "alice.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
            "not-nord.example.com." => [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            "sneaky.nord.com." => [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        };

        let mut nz = NordZone::new();
        let err = nz.upsert(&records, TtlValue(60)).unwrap_err();
        assert!(matches!(err, NordZoneError::NonNordRecord(_)));

        assert_eq!(nz.records.len(), 0);
        assert!(!nz.records.contains_key("not-nord.example.com."));
        assert!(!nz.records.contains_key("sneaky.nord.com."));
    }

    #[test]
    fn upsert_same_domain_replaces_ip() {
        let records = records! {
            "alice.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };

        let mut nz = new_nord_zone_with_upsert(&records);

        assert_eq!(
            nz.records.get("alice.nord.").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))]
        );

        let records = records! {
            "alice.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 99))],
        };

        nz.upsert(&records, TtlValue(60)).unwrap();

        assert_eq!(nz.records.len(), 1);
        assert_eq!(
            nz.records.get("alice.nord.").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 99))]
        );
    }

    #[test]
    fn upsert_empty_addresses_filtered() {
        let mut records = records! {
            "alice.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };
        let mut nz = new_nord_zone_with_upsert(&records);

        records.insert(String::from("empty.nord."), vec![]);
        nz.upsert(&records, TtlValue(60)).unwrap();

        assert_eq!(nz.records.len(), 1);
        assert!(nz.records.contains_key("alice.nord."));
        assert!(!nz.records.contains_key("empty.nord."));
    }

    #[test]
    fn upsert_preserves_nord_zone() {
        let records = records! {
            "alice.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        };

        let mut nz = new_nord_zone_with_upsert(&records);

        let records = records! {
            "test.example." => [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        };

        let err = nz.upsert(&records, TtlValue(60)).unwrap_err();
        assert!(matches!(err, NordZoneError::NonNordRecord(_)));

        assert_eq!(nz.records.len(), 1);
        assert!(nz.records.contains_key("alice.nord."));
    }

    #[test]
    fn upsert_removes_old_domains() {
        let records = records! {
            "alice.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
            "bob.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
        };

        let mut nz = new_nord_zone_with_upsert(&records);

        assert_eq!(nz.records.len(), 2);
        assert!(nz.records.contains_key("alice.nord."));
        assert!(nz.records.contains_key("bob.nord."));

        let records = records! {
            "charlie.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3))],
        };
        nz.upsert(&records, TtlValue(60)).unwrap();

        assert_eq!(nz.records.len(), 1);
        assert!(!nz.records.contains_key("alice.nord."));
        assert!(!nz.records.contains_key("bob.nord."));
        assert!(nz.records.contains_key("charlie.nord."));
        assert_eq!(
            nz.records.get("charlie.nord.").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3))]
        );
    }

    #[test]
    fn upsert_empty_clears_domains() {
        let records = records! {
            "alice.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
            "bob.nord." => [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
        };

        let mut nz = new_nord_zone_with_upsert(&records);

        assert_eq!(nz.records.len(), 2);
        assert!(nz.records.contains_key("alice.nord."));
        assert!(nz.records.contains_key("bob.nord."));

        let records = Records::new();
        nz.upsert(&records, TtlValue(60)).unwrap();

        assert_eq!(nz.records.len(), 0);
        assert!(!nz.records.contains_key("alice.nord."));
        assert!(!nz.records.contains_key("bob.nord."));
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;
    use std::net::IpAddr;
    use telio_model::features::TtlValue;

    // Helper for tests: creates Records with one entry (domain, ip)
    // Used to test zone validation
    fn make_records(domain: &str, ip: IpAddr) -> Records {
        let mut records = Records::new();
        records.insert(domain.to_string(), vec![ip]);
        records
    }

    // Test: returns Error::RecordOutsideZone if record domain does not match zone
    #[tokio::test]
    async fn returns_record_outside_zone_error() {
        let records = make_records("domain.bad.", IpAddr::from([1, 2, 3, 4]));
        let result = AuthoritativeZone::new("nord", &records, TtlValue(60)).await;
        assert!(matches!(
            result,
            Err(Error::RecordOutsideZone(ref domain, ref zone))
                if domain == "domain.bad." && zone == "nord"
        ));
    }
}

/// Behaviour of the NordSecurity hickory fork that libtelio now provides itself
#[cfg(test)]
mod forward_tests {
    use super::*;
    use crate::resolver::Resolver as ResponseBuffer;
    use hickory_server::{
        net::xfer::Protocol,
        proto::op::{Message, MessageType, OpCode, Query},
    };
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::net::UdpSocket;

    const QUERY_NAME: &str = "example.com.";
    const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const TIMEOUT: Duration = Duration::from_millis(300);

    #[derive(Clone, Copy)]
    enum Upstream {
        Answer,
        Silent,
        Rcode(ResponseCode),
        NoDataWithSoa,
        NxDomainWithSoa,
        WrongIdFirst,
        TooShortFirst,
    }

    fn soa() -> Record {
        Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            60,
            RData::SOA(SOA::new(
                Name::from_str("ns.example.com.").unwrap(),
                Name::from_str("admin.example.com.").unwrap(),
                1,
                60,
                60,
                60,
                60,
            )),
        )
    }

    /// Upstream DNS server stub, returns its address and how many queries it received
    async fn spawn_upstream(behavior: Upstream) -> (SocketAddr, Arc<AtomicUsize>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let counter = received.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, src) = socket.recv_from(&mut buf).await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let query = Message::from_vec(&buf[..n]).unwrap();
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_desired = query.metadata.recursion_desired;
                response.metadata.recursion_available = true;
                response.add_queries(query.queries.clone());
                match behavior {
                    Upstream::Silent => continue,
                    Upstream::Answer | Upstream::WrongIdFirst | Upstream::TooShortFirst => {
                        response.add_answer(Record::from_rdata(
                            Name::from_str(QUERY_NAME).unwrap(),
                            60,
                            RData::A(rdata::A(ANSWER)),
                        ));
                    }
                    Upstream::Rcode(code) => response.metadata.response_code = code,
                    Upstream::NoDataWithSoa => {
                        response.add_authority(soa());
                    }
                    Upstream::NxDomainWithSoa => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                        response.add_authority(soa());
                    }
                }
                let reply = response.to_vec().unwrap();
                match behavior {
                    Upstream::WrongIdFirst => {
                        let mut wrong_id = reply.clone();
                        wrong_id[1] = wrong_id[1].wrapping_add(1);
                        socket.send_to(&wrong_id, src).await.unwrap();
                    }
                    Upstream::TooShortFirst => {
                        socket.send_to(&[0], src).await.unwrap();
                    }
                    _ => {}
                }
                socket.send_to(&reply, src).await.unwrap();
            }
        });
        (addr, received)
    }

    async fn zones_forwarding_to(upstream: SocketAddr) -> ClonableZones {
        zones_forwarding_to_with_timeout(upstream, TIMEOUT).await
    }

    async fn zones_forwarding_to_with_timeout(
        upstream: SocketAddr,
        timeout: Duration,
    ) -> ClonableZones {
        let mut options = ForwardZone::options();
        options.timeout = timeout;
        let forward = ForwardZone::with_upstreams(".", &[upstream], options).unwrap();
        let mut zones = ClonableZones::new();
        zones.upsert(LowerName::from_str(".").unwrap(), Arc::new(forward));
        zones
    }

    async fn forward_query(
        zones: &ClonableZones,
        recursion_desired: bool,
    ) -> Result<Message, LookupError> {
        let mut query = Message::query();
        query.metadata.recursion_desired = recursion_desired;
        query.add_query(Query::query(
            Name::from_str(QUERY_NAME).unwrap(),
            RecordType::A,
        ));
        let request = Request::from_bytes(
            query.to_vec().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 5353)),
            Protocol::Udp,
        )
        .unwrap();
        let buffer = ResponseBuffer::new();
        zones.lookup(&request, buffer.clone()).await?;
        let bytes = buffer.0.lock().await.clone();
        Ok(Message::from_vec(&bytes).unwrap())
    }

    #[tokio::test]
    async fn answer_is_forwarded() {
        let (upstream, _) = spawn_upstream(Upstream::Answer).await;
        let zones = zones_forwarding_to(upstream).await;

        let response = forward_query(&zones, true).await.unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].data, RData::A(rdata::A(ANSWER)));
    }

    #[tokio::test]
    async fn silent_upstream_gets_no_reply_and_a_single_query() {
        let (upstream, received) = spawn_upstream(Upstream::Silent).await;
        // Long enough for hickory's re-send interval (at least 333 ms) to fire
        let zones = zones_forwarding_to_with_timeout(upstream, Duration::from_millis(1500)).await;

        let result = forward_query(&zones, true).await;

        assert!(
            matches!(
                result,
                Err(LookupError::ResponseCode(ResponseCode::ServFail))
            ),
            "expected no reply, got {:?}",
            result
        );
        // Upstream hickory 0.26 would re-send to the same server up to 3 times
        assert_eq!(received.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_recursive_query_gets_no_reply() {
        let (upstream, received) = spawn_upstream(Upstream::Answer).await;
        let zones = zones_forwarding_to(upstream).await;

        let result = forward_query(&zones, false).await;

        assert!(
            matches!(
                result,
                Err(LookupError::ResponseCode(ResponseCode::Refused))
            ),
            "expected no reply, got {:?}",
            result
        );
        assert_eq!(received.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn nxdomain_is_relayed_without_soa() {
        let (upstream, _) = spawn_upstream(Upstream::NxDomainWithSoa).await;
        let zones = zones_forwarding_to(upstream).await;

        let response = forward_query(&zones, true).await.unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
        assert!(response.authorities.is_empty());
    }

    #[tokio::test]
    async fn no_data_is_relayed_as_empty_noerror_without_soa() {
        let (upstream, _) = spawn_upstream(Upstream::NoDataWithSoa).await;
        let zones = zones_forwarding_to(upstream).await;

        let response = forward_query(&zones, true).await.unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
        assert!(response.authorities.is_empty());
    }

    #[tokio::test]
    async fn upstream_servfail_is_relayed_as_empty_noerror() {
        let (upstream, _) = spawn_upstream(Upstream::Rcode(ResponseCode::ServFail)).await;
        let zones = zones_forwarding_to(upstream).await;

        let response = forward_query(&zones, true).await.unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn bogus_datagrams_before_the_reply_are_ignored() {
        for behavior in [Upstream::WrongIdFirst, Upstream::TooShortFirst] {
            let (upstream, _) = spawn_upstream(behavior).await;
            let zones = zones_forwarding_to(upstream).await;

            let response = forward_query(&zones, true).await.unwrap();

            assert_eq!(response.answers.len(), 1);
        }
    }
}
