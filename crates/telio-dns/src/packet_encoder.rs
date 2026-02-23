//! DNS packet encoder for the local .nord resolver
//!
//! This module provides a layer for constructing minimal DNS responses for meshnet nord domains

use crate::packet_decoder::normalize_qname;
use pnet_packet::dns::{
    DnsClasses, DnsQuery, DnsType, DnsTypes, MutableDnsPacket, MutableDnsResponsePacket, Opcode,
    Retcode,
};
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Maximum size of UDP DNS packet
const DEFAULT_MAX_UDP_SIZE: usize = 512;
/// Size of DNS packet header
const DNS_HEADER_OFFSET: usize = 12;
/// Fixed-size portion of a DNS resource record: NAME(ptr) + TYPE + CLASS + TTL + RDLENGTH
const RR_HEADER_SIZE: usize = 12;

/// Compression pointer to the first QNAME in the response
/// All answer RRs are expected to be for the same query,
/// so a single constant covers every record.
/// If we ever change the response layout this constant must be revisited.
const QNAME_TAG: u16 = 0xC000 + DNS_HEADER_OFFSET as u16;

/// Constant values for .nord SOA record
const SOA_MNAME: &str = "mesh.nordsec.com.";
const SOA_RNAME: &str = "support.nordsec.com.";
const SOA_SERIAL: u32 = 2015082404;
const SOA_REFRESH: u32 = 7200;
const SOA_EXPIRE: u32 = 1209600;
const SOA_MAX_NAME_SIZE: usize = 254;
const SOA_MAX_LABEL_SIZE: usize = 63;

/// Serialize nord SOA RDATA
fn create_nord_soa_bytes(ttl: u32) -> Result<Vec<u8>, DnsBuildError> {
    let mut bytes = Vec::new();
    encode_name(&mut bytes, SOA_MNAME)?;
    encode_name(&mut bytes, SOA_RNAME)?;
    bytes.extend_from_slice(&SOA_SERIAL.to_be_bytes());
    bytes.extend_from_slice(&SOA_REFRESH.to_be_bytes());
    // RETRY value
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&SOA_EXPIRE.to_be_bytes());
    // MINIMUM value
    bytes.extend_from_slice(&ttl.to_be_bytes());
    Ok(bytes)
}

/// Encode a DNS domain name into wire format
///
/// Accepts both bare names (`mesh.nordsec.com`) and FQDNs with a trailing dot
fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), DnsBuildError> {
    if name.trim().is_empty() {
        return Err(DnsBuildError::SoaNameEmpty);
    }
    let normalized = normalize_qname(name);
    if normalized.len() > SOA_MAX_NAME_SIZE {
        return Err(DnsBuildError::SoaNameTooLong);
    }

    let mut labels = normalized.split('.').peekable();
    while let Some(label) = labels.next() {
        if labels.peek().is_none() {
            break;
        }
        let label = label.trim();
        if label.is_empty() {
            return Err(DnsBuildError::SoaLabelEmpty);
        }
        if label.len() > SOA_MAX_LABEL_SIZE {
            return Err(DnsBuildError::SoaLabelTooLong);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Errors returned when building a DNS response.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum DnsBuildError {
    /// The header buffer is smaller than [`DNS_HEADER_OFFSET`].
    #[error("header buffer too short")]
    HeaderBufferTooShort,
    /// Could not construct a RR buffer.
    #[error("record buffer too short")]
    RecordBufferTooShort,
    /// Could encode name, too long
    #[error("SOA name exceeds maximum length")]
    SoaNameTooLong,
    /// Could encode name, empty
    #[error("SOA name is empty")]
    SoaNameEmpty,
    /// Could encode name, label too long
    #[error("SOA name label exceeds maximum length")]
    SoaLabelTooLong,
    /// Could encode name, label empty
    #[error("SOA name label is empty")]
    SoaLabelEmpty,
    /// Response exceeded maximum number of records
    #[error("records count overflow")]
    RecordCountOverflow,
    /// Record data length exceeds u16 maximum
    #[error("record data length overflow")]
    RecordLenOverflow,
}

/// Response option for the nord resolver
///
/// Use [`DnsResponseBuilder`] to construct a complete DNS response packet
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ResponseKind {
    /// Successful answer with IPv4 addresses
    AnswerA { addresses: Vec<Ipv4Addr> },
    /// Successful answer with IPv6 addresses
    AnswerAAAA { addresses: Vec<Ipv6Addr> },
    /// NOERROR, empty answer, SOA in authority
    NoData,
    /// NXDOMAIN, empty answer, SOA in authority
    NxDomain,
    /// SOA in answer
    SoaAnswer,
}

/// Builder for DNS response packets
pub(crate) struct DnsResponseBuilder {
    /// DNS packet ID
    id: u16,
    /// Parsed query to answer
    query: DnsQuery,
    /// TTL applied to generated RRs
    ttl: u32,
    /// Response kind
    kind: ResponseKind,
    /// Whether to set authoritative answer flag
    authoritative: bool,
    /// Whether the original query had recursion desired
    recursion_desired: bool,
    /// Whether server can do recursive queries
    recursion_available: bool,
    /// Maximum response size
    max_size: usize,
}

/// Parameters for writing a DNS response header
struct HeaderParams {
    id: u16,
    authoritative: bool,
    recursion_desired: bool,
    recursion_available: bool,
    truncated: bool,
    rcode: Retcode,
    answer_count: u16,
    authority_count: u16,
}

impl DnsResponseBuilder {
    /// Create a new response builder
    pub(crate) fn new(
        id: u16,
        query: DnsQuery,
        ttl: u32,
        kind: ResponseKind,
        recursion_desired: bool,
    ) -> Self {
        Self {
            id,
            query,
            ttl,
            kind,
            authoritative: true,
            recursion_desired,
            recursion_available: false,
            max_size: DEFAULT_MAX_UDP_SIZE,
        }
    }

    // TODO: LLT-7054: remove if not needed after complete regression testing
    #[cfg(test)]
    /// Set if the resolver is the authority for the domain
    ///
    /// Sets AA flag
    /// for local .nord resolution this is set to true
    pub(crate) fn set_authoritative(mut self, authoritative: bool) -> Self {
        self.authoritative = authoritative;
        self
    }

    // TODO: LLT-7054: remove if not needed after complete regression testing
    #[cfg(test)]
    /// Set if the resolver can handle recursive queries
    ///
    /// Sets RA flag if recursion is available
    /// for local .nord resolution this is set to false
    pub(crate) fn set_recursion_available(mut self, recurison_available: bool) -> Self {
        self.recursion_available = recurison_available;
        self
    }

    // TODO: LLT-7054: remove if not needed after complete regression testing
    #[cfg(test)]
    /// Set cap for UDP response size
    ///
    /// Sets TC flag if truncation occurs
    pub(crate) fn set_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size.max(DNS_HEADER_OFFSET);
        self
    }

    /// Build the DNS response as raw bytes
    ///
    /// Answers RRs are appended until `max_size` is reached
    pub(crate) fn build(self) -> Result<Vec<u8>, DnsBuildError> {
        let mut bytes = Vec::with_capacity(DEFAULT_MAX_UDP_SIZE);

        let mut answer_count: u16 = 0;
        let mut authority_count: u16 = 0;
        let mut truncated = false;

        // Make space for the header
        bytes.resize(DNS_HEADER_OFFSET, 0);

        // Add the query bytes
        bytes.extend_from_slice(&self.query.qname);
        bytes.extend_from_slice(&self.query.qtype.0.to_be_bytes());
        bytes.extend_from_slice(&self.query.qclass.0.to_be_bytes());

        let (rcode, write_soa, soa_as_answer) = match self.kind {
            ResponseKind::AnswerA { addresses } => {
                for ip in addresses {
                    try_push_rr(
                        &mut bytes,
                        self.ttl,
                        DnsTypes::A,
                        &ip.octets(),
                        self.max_size,
                        &mut truncated,
                        &mut answer_count,
                    )?;
                }

                // NODATA for A query: NOERROR + SOA in authority
                let write_soa = answer_count == 0;
                (Retcode::NoError, write_soa, false)
            }
            ResponseKind::AnswerAAAA { addresses } => {
                for ip in addresses {
                    try_push_rr(
                        &mut bytes,
                        self.ttl,
                        DnsTypes::AAAA,
                        &ip.octets(),
                        self.max_size,
                        &mut truncated,
                        &mut answer_count,
                    )?;
                }

                // NODATA for AAAA query: NOERROR + SOA in authority
                let write_soa = answer_count == 0;
                (Retcode::NoError, write_soa, false)
            }
            ResponseKind::NoData => (Retcode::NoError, true, false),
            ResponseKind::NxDomain => (Retcode::RecordNotExists, true, false),
            ResponseKind::SoaAnswer => (Retcode::NoError, true, true),
        };

        // append SOA record to Answers or Authority
        if write_soa {
            let soa_data = create_nord_soa_bytes(self.ttl)?;
            try_push_rr(
                &mut bytes,
                self.ttl,
                DnsTypes::SOA,
                &soa_data,
                self.max_size,
                &mut truncated,
                if soa_as_answer {
                    &mut answer_count
                } else {
                    &mut authority_count
                },
            )?;
        }

        write_header(
            &mut bytes,
            HeaderParams {
                id: self.id,
                authoritative: self.authoritative,
                recursion_desired: self.recursion_desired,
                recursion_available: self.recursion_available,
                truncated,
                rcode,
                answer_count,
                authority_count,
            },
        )?;

        Ok(bytes)
    }
}

/// Try to reserve needed bytes in `out` without exceeding `max_size`
///
/// Sets `truncated` to true otherwise
fn try_reserve_tail<'a>(
    out: &'a mut Vec<u8>,
    needed: usize,
    max_size: usize,
    truncated: &mut bool,
) -> Option<&'a mut [u8]> {
    if *truncated {
        return None;
    }

    let cur = out.len();
    if cur + needed > max_size {
        *truncated = true;
        return None;
    }

    out.resize(cur + needed, 0);
    out.get_mut(cur..cur + needed)
}

/// Append record to the response
fn try_push_rr(
    out: &mut Vec<u8>,
    ttl: u32,
    rtype: DnsType,
    data: &[u8],
    max_size: usize,
    truncated: &mut bool,
    record_count: &mut u16,
) -> Result<(), DnsBuildError> {
    let rr_len = RR_HEADER_SIZE + data.len();
    let Some(rr_buf) = try_reserve_tail(out, rr_len, max_size, truncated) else {
        return Ok(());
    };

    let mut p = MutableDnsResponsePacket::new(rr_buf).ok_or(DnsBuildError::RecordBufferTooShort)?;
    p.set_name_tag(QNAME_TAG);
    p.set_rtype(rtype);
    p.set_rclass(DnsClasses::IN);
    p.set_ttl(ttl);
    let data_len: u16 = data
        .len()
        .try_into()
        .map_err(|_| DnsBuildError::RecordLenOverflow)?;
    p.set_data_len(data_len);
    p.set_data(data);

    *record_count = record_count
        .checked_add(1)
        .ok_or(DnsBuildError::RecordCountOverflow)?;

    Ok(())
}

/// Write the DNS header fields into the first 12 bytes of `bytes`
fn write_header(bytes: &mut [u8], params: HeaderParams) -> Result<(), DnsBuildError> {
    let header_slice = bytes
        .get_mut(..DNS_HEADER_OFFSET)
        .ok_or(DnsBuildError::HeaderBufferTooShort)?;
    let mut header =
        MutableDnsPacket::new(header_slice).ok_or(DnsBuildError::HeaderBufferTooShort)?;

    header.set_id(params.id);
    header.set_is_response(1);
    header.set_opcode(Opcode::StandardQuery);
    header.set_is_authoriative(if params.authoritative { 1 } else { 0 });
    header.set_is_truncated(if params.truncated { 1 } else { 0 });
    header.set_is_recursion_desirable(if params.recursion_desired { 1 } else { 0 });
    header.set_is_recursion_available(if params.recursion_available { 1 } else { 0 });
    header.set_zero_reserved(0);
    header.set_is_answer_authenticated(0);
    header.set_is_non_authenticated_data(0);
    header.set_rcode(params.rcode);

    header.set_query_count(1);
    header.set_response_count(params.answer_count);
    header.set_authority_rr_count(params.authority_count);
    header.set_additional_rr_count(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::packet_decoder::{find_nord_query, parse_dns_query_packet};

    use super::*;
    use dns_parser::{Builder, Packet, QueryClass, QueryType, ResponseCode};

    const REQUEST_ID: u16 = 0x1234;
    const RECURSION_DESIRED: bool = true;
    const DEFAULT_TTL: u32 = 60;

    fn build_dns_query_bytes(qnames: &[&str], qtype: QueryType) -> Vec<u8> {
        let mut builder = Builder::new_query(REQUEST_ID, RECURSION_DESIRED);
        for qname in qnames {
            builder.add_question(qname, false, qtype, QueryClass::IN);
        }
        builder.build().unwrap().to_vec()
    }

    fn parse_response(bytes: &[u8]) -> Packet<'_> {
        Packet::parse(bytes).expect("response must parse as DNS")
    }

    fn assert_response_fields(
        response: &Packet<'_>,
        expect_rcode: ResponseCode,
        expect_qname: &str,
        expect_qtype: QueryType,
    ) {
        assert_eq!(response.header.id, REQUEST_ID);
        assert!(!response.header.query, "expected response");
        assert_eq!(response.header.response_code, expect_rcode);

        assert_eq!(response.questions.len(), 1);
        let q = &response.questions[0];

        let qname_str = q.qname.to_string().to_ascii_lowercase();
        let expected = expect_qname.trim_end_matches('.').to_ascii_lowercase();
        assert!(
            qname_str.contains(&expected),
            "expected qname containing {}, got {}",
            expected,
            qname_str
        );

        assert_eq!(q.qtype, expect_qtype);
        assert_eq!(q.qclass, QueryClass::IN);
    }

    fn soa_in_authority(response: &Packet<'_>) -> bool {
        response
            .nameservers
            .iter()
            .any(|rr| matches!(rr.data, dns_parser::RData::SOA(_)))
    }

    fn soa_in_answers(response: &Packet<'_>) -> bool {
        response
            .answers
            .iter()
            .any(|rr| matches!(rr.data, dns_parser::RData::SOA(_)))
    }

    fn answer_as_ipv4s(response: &Packet<'_>) -> Vec<Ipv4Addr> {
        response
            .answers
            .iter()
            .filter_map(|rr| match rr.data {
                dns_parser::RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    fn answer_as_ipv6s(response: &Packet<'_>) -> Vec<Ipv6Addr> {
        response
            .answers
            .iter()
            .filter_map(|rr| match rr.data {
                dns_parser::RData::AAAA(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    fn extract_soa<'a>(response: &'a Packet<'a>) -> &'a dns_parser::rdata::Soa<'a> {
        response
            .answers
            .iter()
            .chain(response.nameservers.iter())
            .find_map(|rr| match &rr.data {
                dns_parser::RData::SOA(soa) => Some(soa),
                _ => None,
            })
            .expect("expected SOA record in response")
    }

    #[test]
    fn build_response_answer_a() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(100, 100, 100, 100), Ipv4Addr::new(1, 2, 3, 4)],
            },
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);

        assert_response_fields(&response, ResponseCode::NoError, "test.nord", QueryType::A);

        assert_eq!(
            answer_as_ipv4s(&response),
            vec![Ipv4Addr::new(100, 100, 100, 100), Ipv4Addr::new(1, 2, 3, 4)]
        );
        assert!(answer_as_ipv6s(&response).is_empty());

        assert!(!soa_in_authority(&response));
        assert!(!soa_in_answers(&response));
        assert!(response.header.authoritative);
        assert!(response.header.recursion_desired);
    }

    #[test]
    fn build_response_answer_aaaa() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::AAAA);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerAAAA {
                addresses: vec![Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)],
            },
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);

        assert_response_fields(
            &response,
            ResponseCode::NoError,
            "test.nord",
            QueryType::AAAA,
        );

        assert_eq!(
            answer_as_ipv6s(&response),
            vec![Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)]
        );
        assert!(answer_as_ipv4s(&response).is_empty());
        assert!(!soa_in_authority(&response));
        assert!(!soa_in_answers(&response));
    }

    #[test]
    fn build_response_answer_a_empty() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerA { addresses: vec![] },
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);

        assert_response_fields(&response, ResponseCode::NoError, "test.nord", QueryType::A);

        assert!(
            response.answers.is_empty(),
            "expected no answers for NODATA"
        );
        assert!(
            soa_in_authority(&response),
            "expected SOA in authority for NODATA"
        );
        assert!(
            !soa_in_answers(&response),
            "SOA should not be in answers for NODATA"
        );
    }

    #[test]
    fn build_response_nodata() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::AAAA);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::NoData,
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);

        assert_response_fields(
            &response,
            ResponseCode::NoError,
            "test.nord",
            QueryType::AAAA,
        );
        assert!(response.answers.is_empty());
        assert!(soa_in_authority(&response));
        assert!(!soa_in_answers(&response));
    }

    #[test]
    fn build_response_nxdomain() {
        let request_bytes = build_dns_query_bytes(&["unknown.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::NxDomain,
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);

        assert_response_fields(
            &response,
            ResponseCode::NameError,
            "unknown.nord",
            QueryType::A,
        );

        assert!(response.answers.is_empty());
        assert!(soa_in_authority(&response));
        assert!(!soa_in_answers(&response));
    }

    #[test]
    fn build_response_soa() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::SOA);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::SoaAnswer,
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);

        assert_response_fields(
            &response,
            ResponseCode::NoError,
            "test.nord",
            QueryType::SOA,
        );
        assert!(
            soa_in_answers(&response),
            "expected SOA in answers for SOA query"
        );
        assert!(!soa_in_authority(&response));
    }

    #[test]
    fn response_truncates() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let addrs = (0..200).map(|i| Ipv4Addr::new(10, 0, 0, i as u8)).collect();
        let bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerA { addresses: addrs },
            RECURSION_DESIRED,
        )
        .set_max_size(100)
        .build()
        .unwrap();

        let parsed = Packet::parse(&bytes).unwrap();
        assert!(parsed.header.truncated);
    }

    #[test]
    fn encode_name_empty_fails() {
        let mut buf = Vec::new();
        assert_eq!(encode_name(&mut buf, ""), Err(DnsBuildError::SoaNameEmpty));
        assert_eq!(encode_name(&mut buf, " "), Err(DnsBuildError::SoaNameEmpty));
    }

    #[test]
    fn encode_name_label_max_fails() {
        let long_label = "a".repeat(SOA_MAX_LABEL_SIZE + 1);
        let name = format!("{long_label}.nord");
        let mut buf = Vec::new();
        assert_eq!(
            encode_name(&mut buf, &name),
            Err(DnsBuildError::SoaLabelTooLong)
        );
    }

    #[test]
    fn encode_name_label_succeeds() {
        let label = "a".repeat(SOA_MAX_LABEL_SIZE);
        let name = format!("{label}.nord");
        let mut buf = Vec::new();
        assert!(encode_name(&mut buf, &name).is_ok());
        assert!(!buf.is_empty());
    }

    #[test]
    fn encode_name_empty_label_fails() {
        let mut buf = Vec::new();

        assert_eq!(
            encode_name(&mut buf, "."),
            Err(DnsBuildError::SoaLabelEmpty)
        );
        assert_eq!(
            encode_name(&mut buf, ". "),
            Err(DnsBuildError::SoaLabelEmpty)
        );
        assert_eq!(
            encode_name(&mut buf, " . "),
            Err(DnsBuildError::SoaLabelEmpty)
        );
        assert_eq!(
            encode_name(&mut buf, ". ."),
            Err(DnsBuildError::SoaLabelEmpty)
        );
        assert_eq!(
            encode_name(&mut buf, " . . "),
            Err(DnsBuildError::SoaLabelEmpty)
        );

        assert_eq!(
            encode_name(&mut buf, "test..nord"),
            Err(DnsBuildError::SoaLabelEmpty)
        );
        assert_eq!(
            encode_name(&mut buf, "test. .nord"),
            Err(DnsBuildError::SoaLabelEmpty)
        );
        assert_eq!(
            encode_name(&mut buf, " . .nord"),
            Err(DnsBuildError::SoaLabelEmpty)
        );
    }

    #[test]
    fn encode_name_max_fails() {
        let name = "a".repeat(SOA_MAX_NAME_SIZE + 1);
        let mut buf = Vec::new();
        assert_eq!(
            encode_name(&mut buf, &name),
            Err(DnsBuildError::SoaNameTooLong)
        );
    }

    #[test]
    fn authoritative_false_clears_aa_flag() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
            },
            RECURSION_DESIRED,
        )
        .set_authoritative(false)
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        assert!(!response.header.authoritative);
        assert_eq!(answer_as_ipv4s(&response), vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }

    #[test]
    fn max_size_zero_clamps_to_header() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
            },
            RECURSION_DESIRED,
        )
        .set_max_size(0)
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        assert!(response.header.truncated);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn recursion_desired_set() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query.clone(),
            DEFAULT_TTL,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
            },
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        assert!(response.header.recursion_desired);

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
            },
            false,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        assert!(!response.header.recursion_desired);
    }

    #[test]
    fn recursion_available_set() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query.clone(),
            DEFAULT_TTL,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
            },
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        assert!(!response.header.recursion_available);

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
            },
            RECURSION_DESIRED,
        )
        .set_recursion_available(true)
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        assert!(response.header.recursion_available);
    }

    #[test]
    fn soa_contains_expected_fields() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::SOA);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            DEFAULT_TTL,
            ResponseKind::SoaAnswer,
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        let soa = extract_soa(&response);

        assert_eq!(soa.primary_ns.to_string(), SOA_MNAME.trim_end_matches('.'));
        assert_eq!(soa.mailbox.to_string(), SOA_RNAME.trim_end_matches('.'));
        assert_eq!(soa.serial, SOA_SERIAL);
        assert_eq!(soa.refresh, SOA_REFRESH);
        assert_eq!(soa.retry, DEFAULT_TTL);
        assert_eq!(soa.expire, SOA_EXPIRE);
        assert_eq!(soa.minimum_ttl, DEFAULT_TTL);
    }

    #[test]
    fn soa_uses_ttl() {
        let custom_ttl: u32 = 300;
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::SOA);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            custom_ttl,
            ResponseKind::SoaAnswer,
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        let soa = extract_soa(&response);

        assert_eq!(soa.retry, custom_ttl);
        assert_eq!(soa.minimum_ttl, custom_ttl);
        assert_eq!(soa.serial, SOA_SERIAL);
        assert_eq!(soa.refresh, SOA_REFRESH);
        assert_eq!(soa.expire, SOA_EXPIRE);
    }

    #[test]
    fn answer_a_uses_ttl() {
        let custom_ttl: u32 = 120;
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&request_bytes).unwrap();
        let query = find_nord_query(&packet).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            REQUEST_ID,
            query,
            custom_ttl,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(10, 0, 0, 1)],
            },
            RECURSION_DESIRED,
        )
        .build()
        .unwrap();

        let response = parse_response(&response_bytes);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, custom_ttl);
    }
}
