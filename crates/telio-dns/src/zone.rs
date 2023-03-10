use async_trait::async_trait;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};
use trust_dns_client::rr::{rdata::SOA, DNSClass, LowerName, Name, RData, Record, RecordType};
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverOpts};
use trust_dns_server::{
    authority::{
        Authority, Catalog, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    server::RequestInfo,
    store::{forwarder::ForwardConfig, in_memory::InMemoryAuthority},
};

use crate::forward::ForwardAuthority;

/// Zone is a portion of the DNS namespace that is managed by a specific
/// organization or administrator.
pub(crate) type Zones = Catalog;

/// Records (aka zone files) are instructions that live in authoritative
/// DNS servers and provide information about a domain including what IP
/// address is associated with that domain and how to handle requests
/// for that domain.
pub type Records = HashMap<String, Ipv4Addr>;

/// AuthoritativeZone is a zone for which the local server references its
/// own data when responding to queries.
pub(crate) struct AuthoritativeZone {
    pub(crate) zone: InMemoryAuthority,
}

impl AuthoritativeZone {
    pub(crate) async fn new(name: &str, records: &Records) -> Result<Self, String> {
        // TODO: rewrite code so that this assert is not needed.
        for domain in records.keys() {
            if !domain.contains(name) {
                return Err(format!("{} does not end with {}", domain, name));
            }
        }
        let zone_name = Name::from_str(name)?;
        let zone = InMemoryAuthority::empty(zone_name.clone(), ZoneType::Primary, false);

        zone.upsert(
            Record::new()
                .set_name(zone_name)
                .set_ttl(3600)
                .set_rr_type(RecordType::SOA)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::SOA(SOA::new(
                    Name::parse("mesh.nordsec.com.", None)?,
                    Name::parse("support.nordsec.com.", None)?,
                    2015082403,
                    7200,
                    3600,
                    1209600,
                    3600,
                ))))
                .clone(),
            0,
        )
        .await;

        for (name, &ip) in records.iter() {
            zone.upsert(
                Record::new()
                    .set_name(Name::parse(name, None)?)
                    .set_ttl(900)
                    .set_rr_type(RecordType::A)
                    .set_dns_class(DNSClass::IN)
                    .set_data(Some(RData::A(ip)))
                    .clone(),
                0,
            )
            .await;
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

        let zone = ForwardAuthority::try_from_config(
            Name::from_str(name)?,
            ZoneType::Forward,
            &ForwardConfig {
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
