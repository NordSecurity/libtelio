use async_trait::async_trait;
use hickory_server::{
    authority::{
        Authority, AuthorityObject, Catalog, LookupControlFlow, LookupError, LookupOptions,
        MessageRequest, UpdateResult, ZoneType,
    },
    proto::rr::{
        rdata::{self, SOA},
        DNSClass, LowerName, Name, RData, Record, RecordType,
    },
    resolver::config::{NameServerConfigGroup, ResolveHosts, ResolverOpts},
    server::{Request, RequestInfo, ResponseHandler, ResponseInfo},
    store::{forwarder::ForwardConfig, in_memory::InMemoryAuthority},
};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
};
use telio_model::features::TtlValue;
use telio_utils::telio_log_warn;

use crate::forward::ForwardAuthority;

/// Zone is a portion of the DNS namespace that is managed by a specific
/// organization or administrator.
pub(crate) type Zones = Catalog;

/// Records (aka zone files) are instructions that live in authoritative
/// DNS servers and provide information about a domain including what IP
/// address is associated with that domain and how to handle requests
/// for that domain.
pub type Records = HashMap<String, Vec<IpAddr>>;

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
        let rdata = RData::SOA(SOA::new(
            Name::parse("mesh.nordsec.com.", None)?,
            Name::parse("support.nordsec.com.", None)?,
            2015082403,
            7200,
            ttl_value_signed,
            1209600,
            ttl_value.0,
        ));
        zone.upsert(
            Record::from_rdata(zone_name, ttl_value.0, rdata)
                .set_dns_class(DNSClass::IN)
                .clone(),
            0,
        )
        .await;

        let build_record = |name: Name, data: RData| -> Record {
            Record::from_rdata(name, ttl_value.0, data)
                .set_dns_class(DNSClass::IN)
                .clone()
        };

        for (name, record) in records.iter() {
            let name = Name::parse(name, None)?;
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
impl Authority for AuthoritativeZone {
    type Lookup = <InMemoryAuthority as Authority>::Lookup;

    fn zone_type(&self) -> ZoneType {
        Authority::zone_type(&self.zone)
    }

    fn is_axfr_allowed(&self) -> bool {
        Authority::is_axfr_allowed(&self.zone)
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        Authority::update(&self.zone, update).await
    }

    fn origin(&self) -> &LowerName {
        Authority::origin(&self.zone)
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        Authority::lookup(&self.zone, name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        Authority::search(&self.zone, request_info, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        Authority::get_nsec_records(&self.zone, name, lookup_options).await
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
        options.use_hosts_file = ResolveHosts::Never;

        options.num_concurrent_reqs = 1;

        // We set the number of retries to 0. The retry should be handled by the OS retry mechanism
        options.attempts = 0;

        let zone = ForwardAuthority::try_from_config(
            Name::from_str(name)?,
            ZoneType::External,
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
        Authority::zone_type(&self.zone)
    }

    fn is_axfr_allowed(&self) -> bool {
        Authority::is_axfr_allowed(&self.zone)
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        Authority::update(&self.zone, update).await
    }

    fn origin(&self) -> &LowerName {
        Authority::origin(&self.zone)
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        Authority::lookup(&self.zone, name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        Authority::search(&self.zone, request_info, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        Authority::get_nsec_records(&self.zone, name, lookup_options).await
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

    pub fn upsert(&mut self, name: LowerName, authorities: Vec<Arc<dyn AuthorityObject>>) {
        self.zones.upsert(name.clone(), authorities);
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
                    zone.upsert(name.clone(), auth.clone());
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

    async fn validate_record(
        zone: &AuthoritativeZone,
        name: &str,
        expected_ipv4: Option<Ipv4Addr>,
        expected_ipv6: Option<Ipv6Addr>,
    ) {
        let lookup = Authority::lookup(
            zone,
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
            assert_eq!(record.data(), &RData::A(rdata::A(expected_ipv4)));
        } else {
            assert!(matches!(
                lookup,
                LookupControlFlow::Continue(Err(LookupError::NameExists))
            ));
        }

        let lookup = Authority::lookup(
            zone,
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
            assert_eq!(record.data(), &RData::AAAA(rdata::AAAA(expected_ipv6)));
        } else {
            assert!(matches!(
                lookup,
                LookupControlFlow::Continue(Err(LookupError::NameExists))
            ));
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
}
