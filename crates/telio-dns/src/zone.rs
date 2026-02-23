use crate::{
    forward::ForwardAuthority, packet_decoder::normalize_qname, packet_encoder::ResponseKind,
};
use async_trait::async_trait;
use hickory_server::{
    authority::{
        Authority, AuthorityObject, Catalog, LookupError, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    proto::rr::{rdata, rdata::SOA, DNSClass, LowerName, Name, RData, Record, RecordType},
    resolver::config::{NameServerConfigGroup, ResolverOpts},
    server::{Request, RequestInfo, ResponseHandler, ResponseInfo},
    store::{forwarder::ForwardConfig, in_memory::InMemoryAuthority},
};
use pnet_packet::dns::{DnsQuery, DnsTypes};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use telio_model::features::TtlValue;
use telio_utils::{telio_log_debug, telio_log_warn};
use thiserror::Error;

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
pub(crate) enum NordZoneError {
    /// Record contains a non nord entry
    #[error("record contains non-nord entry {0}")]
    NonNordRecord(String),
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
    pub(crate) zone: InMemoryAuthority,
}

impl AuthoritativeZone {
    pub(crate) async fn new(
        name: &str,
        records: &Records,
        ttl_value: TtlValue,
    ) -> Result<Self, String> {
        // TODO: rewrite code so that this assert is not needed.
        for domain in records.keys() {
            if !domain.contains(name) {
                return Err(format!("{domain} does not end with {name}"));
            }
        }
        let zone_name = Name::from_str(name)?;
        let zone = InMemoryAuthority::empty(zone_name.clone(), ZoneType::Primary, false);
        let ttl_value_signed: i32 = match ttl_value.0.try_into() {
            Ok(ttl_value) => ttl_value,
            Err(_) => {
                let default = TtlValue::default().0 as i32;
                telio_log_warn!("TTL value could not be converted from u32 to i32 without data loss, so using default value: {default}");
                default
            }
        };
        zone.upsert(
            Record::new()
                .set_name(zone_name)
                .set_ttl(ttl_value.0)
                .set_rr_type(RecordType::SOA)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::SOA(SOA::new(
                    Name::parse("mesh.nordsec.com.", None)?,
                    Name::parse("support.nordsec.com.", None)?,
                    2015082403,
                    7200,
                    ttl_value_signed,
                    1209600,
                    ttl_value.0,
                ))))
                .clone(),
            0,
        )
        .await;

        let build_record = |name: Name, ty: RecordType, data: RData| -> Record {
            Record::new()
                .set_name(name)
                .set_ttl(ttl_value.0)
                .set_rr_type(ty)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(data))
                .clone()
        };

        for (name, record) in records.iter() {
            let name = Name::parse(name, None)?;
            for ip in record.iter() {
                match *ip {
                    IpAddr::V4(ipv4) => {
                        let _ = zone
                            .upsert(
                                build_record(name.clone(), RecordType::A, RData::A(rdata::A(ipv4))),
                                0,
                            )
                            .await;
                    }
                    IpAddr::V6(ipv6) => {
                        let _ = zone
                            .upsert(
                                build_record(
                                    name.clone(),
                                    RecordType::AAAA,
                                    RData::AAAA(rdata::AAAA(ipv6)),
                                ),
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
impl Authority for AuthoritativeZone {
    type Lookup = <InMemoryAuthority as Authority>::Lookup;

    fn zone_type(&self) -> ZoneType {
        self.zone.zone_type()
    }

    fn is_axfr_allowed(&self) -> bool {
        self.zone.is_axfr_allowed()
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        self.zone.update(update).await
    }

    fn origin(&self) -> &LowerName {
        self.zone.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.zone.lookup(name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.zone.search(request_info, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.zone.get_nsec_records(name, lookup_options).await
    }
}

/// ForwardZone allows the DNS Server to resolve queries where the client
/// sends a name to the DNS Server to request the IP address of the requested
/// host.
pub(crate) struct ForwardZone {
    pub(crate) zone: ForwardAuthority,
}

impl ForwardZone {
    pub(crate) async fn new(name: &str, ips: &[IpAddr]) -> Result<Self, String> {
        let mut options = ResolverOpts::default();
        // Some tools and browsers do not accept responses without intermediates preserved
        options.preserve_intermediates = true;
        // We provide our own forward servers, so we don't need to look at the hosts file
        options.use_hosts_file = false;

        options.num_concurrent_reqs = 1;

        // We set the number of retries to 0. The retry should be handled by the OS retry mechanism
        options.attempts = 0;

        let zone = ForwardAuthority::try_from_config(
            Name::from_str(name)?,
            ZoneType::Forward,
            ForwardConfig {
                options: Some(options),
                name_servers: NameServerConfigGroup::from_ips_clear(ips, 53, true),
            },
        )
        .await?;
        Ok(ForwardZone { zone })
    }
}

#[async_trait]
impl Authority for ForwardZone {
    type Lookup = <ForwardAuthority as Authority>::Lookup;

    fn zone_type(&self) -> ZoneType {
        self.zone.zone_type()
    }

    fn is_axfr_allowed(&self) -> bool {
        self.zone.is_axfr_allowed()
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        self.zone.update(update).await
    }

    fn origin(&self) -> &LowerName {
        self.zone.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.zone.lookup(name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.zone.search(request_info, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.zone.get_nsec_records(name, lookup_options).await
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

    pub fn upsert(&mut self, name: LowerName, authority: Box<dyn AuthorityObject>) {
        self.zones.upsert(name.clone(), authority);
        self.names.insert(name);
    }

    pub async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> Result<ResponseInfo, LookupError> {
        self.zones.lookup(request, None, response_handle).await
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
                .flat_map(|name| self.zones.find(name).map(|auth| (name, auth)))
                .fold(Zones::new(), |mut zone, (name, auth)| {
                    zone.upsert(name.clone(), auth.box_clone());
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
                &Name::from_str(name).unwrap().into(),
                RecordType::A,
                Default::default(),
            )
            .await;

        if let Some(expected_ipv4) = expected_ipv4 {
            let lookup = lookup.unwrap();
            let records: Vec<&Record> = lookup.iter().collect();
            assert_eq!(records.len(), 1);
            let record = records[0];
            assert_eq!(record.name(), &Name::from_str(name).unwrap());
            assert_eq!(record.data(), Some(&RData::A(rdata::A(expected_ipv4))));
        } else {
            assert!(matches!(lookup, Err(LookupError::NameExists)));
        }

        let lookup = zone
            .lookup(
                &Name::from_str(name).unwrap().into(),
                RecordType::AAAA,
                Default::default(),
            )
            .await;

        if let Some(expected_ipv6) = expected_ipv6 {
            let lookup = lookup.unwrap();
            let records: Vec<&Record> = lookup.iter().collect();
            assert_eq!(records.len(), 1);
            let record = records[0];
            assert_eq!(record.name(), &Name::from_str(name).unwrap());
            assert_eq!(
                record.data(),
                Some(&RData::AAAA(rdata::AAAA(expected_ipv6)))
            );
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
