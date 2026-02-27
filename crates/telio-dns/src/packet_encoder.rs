//! DNS packet encoder for the local .nord resolver
//!
//! This module provides a layer for constructing minimal DNS responses for meshnet donrd domains

// TODO: Remove after merging integration
#![allow(dead_code)]

use crate::packet_decoder::{DnsQuestion, DNS_HEADER_OFFSET};
use pnet_packet::dns::{
    DnsClasses, DnsType, DnsTypes, MutableDnsPacket, MutableDnsQueryPacket,
    MutableDnsResponsePacket, Opcode, Retcode,
};
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

const DEFAULT_MAX_UDP_SIZE: usize = 512;

/// Compression pointer to the QNAME in the response
/// If we ever change the response layout this constant must be revisited.
const QNAME_TAG: u16 = 0xC00C;

/// Minimal SOA record
pub struct Soa {
    mname: &'static str,
    rname: &'static str,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl Soa {
    /// Create SOA record for default nord zone
    pub fn new(ttl: u32) -> Result<Self, DnsBuildError> {
        Ok(Self {
            mname: "mesh.nordsec.com.",
            rname: "support.nordsec.com.",
            serial: 2015082403,
            refresh: 7200,
            retry: i32::try_from(ttl).map_err(|_| DnsBuildError::SoaTtlOutOfRange)?,
            expire: 1209600,
            minimum: ttl,
        })
    }

    /// Serialize SOA RDATA
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_name(&mut bytes, self.mname);
        encode_name(&mut bytes, self.rname);
        bytes.extend_from_slice(&self.serial.to_be_bytes());
        bytes.extend_from_slice(&self.refresh.to_be_bytes());
        bytes.extend_from_slice(&self.retry.to_be_bytes());
        bytes.extend_from_slice(&self.expire.to_be_bytes());
        bytes.extend_from_slice(&self.minimum.to_be_bytes());
        bytes
    }
}

/// Encode a DNS domain name into wire format
///
/// Trailing dot is optional, it is ignored
///
/// Safety:
/// - Does not validate label length or total name length
fn encode_name(out: &mut Vec<u8>, name: &str) {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return;
    }
    for label in trimmed.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Errors returned when building a DNS response.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsBuildError {
    /// The header buffer is smaller than [`DNS_HEADER_OFFSET`].
    #[error("header buffer too short")]
    HeaderBufferTooShort,
    /// Could not construct a RR buffer.
    #[error("record buffer too short")]
    RecordBufferTooShort,
    /// Could not safely convert u32 to i32
    #[error("SOA TTL exceeds signed 32-bit range")]
    SoaTtlOutOfRange,
}

/// Response option for the nord resolver
///
/// Use [`DnsResponseBuilder`] to construct a complete DNS response packet
#[derive(Debug, Clone)]
pub enum ResponseKind {
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
pub struct DnsResponseBuilder<'a> {
    /// Parsed question to answer
    question: &'a DnsQuestion,
    /// TTL applied to generated RRs
    ttl: u32,
    /// Response kind
    kind: ResponseKind,
    /// Whether to set authoritative answer flag
    authoritative: bool,
    /// Maximum response size
    max_size: usize,
}

impl<'a> DnsResponseBuilder<'a> {
    /// Create a new response builder
    pub fn new(question: &'a DnsQuestion, ttl: u32, kind: ResponseKind) -> Self {
        Self {
            question,
            ttl,
            kind,
            authoritative: true,
            max_size: DEFAULT_MAX_UDP_SIZE,
        }
    }

    /// Set if this response is for forwarded or upstream results
    ///
    /// Sets AA flag
    pub fn set_authoritative(mut self, authoritative: bool) -> Self {
        self.authoritative = authoritative;
        self
    }

    /// Set cap for UDP response size
    ///
    /// Sets TC flag if truncation occurs
    pub fn set_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size.max(DNS_HEADER_OFFSET);
        self
    }

    /// Build the DNS response as raw bytes
    ///
    /// Answers RRs are appended until `max_size` is reached
    pub fn build(self) -> Result<Vec<u8>, DnsBuildError> {
        let mut bytes = Vec::with_capacity(DEFAULT_MAX_UDP_SIZE);

        let mut answer_count: u16 = 0;
        let mut authority_count: u16 = 0;
        let mut truncated = false;

        // Make space for the header
        bytes.resize(DNS_HEADER_OFFSET, 0);

        // Add the query bytes
        try_push_query(
            &mut bytes,
            &self.question.record_type,
            &self.question.name,
            self.max_size,
            &mut truncated,
        )?;

        let rcode = match self.kind {
            ResponseKind::AnswerA { addresses } => {
                for ip in addresses {
                    try_push_rr_a(
                        &mut bytes,
                        self.ttl,
                        ip,
                        self.max_size,
                        &mut truncated,
                        &mut answer_count,
                    )?;
                }

                // NODATA for A query: NOERROR + SOA in authority
                if answer_count == 0 {
                    try_push_rr_soa(
                        &mut bytes,
                        self.ttl,
                        self.max_size,
                        &mut truncated,
                        &mut authority_count,
                        false,
                        &mut answer_count,
                    )?;
                }
                Retcode::NoError
            }
            ResponseKind::AnswerAAAA { addresses } => {
                for ip in addresses {
                    try_push_rr_aaaa(
                        &mut bytes,
                        self.ttl,
                        ip,
                        self.max_size,
                        &mut truncated,
                        &mut answer_count,
                    )?;
                }

                // NODATA for AAAA query: NOERROR + SOA in authority
                if answer_count == 0 {
                    try_push_rr_soa(
                        &mut bytes,
                        self.ttl,
                        self.max_size,
                        &mut truncated,
                        &mut authority_count,
                        false,
                        &mut answer_count,
                    )?;
                }
                Retcode::NoError
            }
            ResponseKind::NoData => {
                try_push_rr_soa(
                    &mut bytes,
                    self.ttl,
                    self.max_size,
                    &mut truncated,
                    &mut authority_count,
                    false,
                    &mut answer_count,
                )?;
                Retcode::NoError
            }
            ResponseKind::NxDomain => {
                try_push_rr_soa(
                    &mut bytes,
                    self.ttl,
                    self.max_size,
                    &mut truncated,
                    &mut authority_count,
                    false,
                    &mut answer_count,
                )?;
                Retcode::RecordNotExists
            }
            ResponseKind::SoaAnswer => {
                try_push_rr_soa(
                    &mut bytes,
                    self.ttl,
                    self.max_size,
                    &mut truncated,
                    &mut authority_count,
                    true,
                    &mut answer_count,
                )?;
                Retcode::NoError
            }
        };

        write_header(
            &mut bytes,
            self.question,
            self.authoritative,
            truncated,
            rcode,
            answer_count,
            authority_count,
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

/// Append a query back to the response
fn try_push_query(
    out: &mut Vec<u8>,
    qtype: &DnsType,
    qname: &str,
    max_size: usize,
    truncated: &mut bool,
) -> Result<(), DnsBuildError> {
    let mut qname_wire = Vec::with_capacity(qname.len() + 2);
    encode_name(&mut qname_wire, qname);

    // qname + qtype + qclass
    let qlen = qname_wire.len() + 4;

    let Some(qbuf) = try_reserve_tail(out, qlen, max_size, truncated) else {
        return Ok(());
    };

    // We need to first manually copy the qname into the buffer.
    // `MutableDnsQueryPacket` infers QNAME length from the existing bytes.
    qbuf.get_mut(..qname_wire.len())
        .ok_or(DnsBuildError::RecordBufferTooShort)?
        .copy_from_slice(&qname_wire);

    let mut p = MutableDnsQueryPacket::new(qbuf).ok_or(DnsBuildError::RecordBufferTooShort)?;

    p.set_qtype(qtype.to_owned());
    p.set_qclass(DnsClasses::IN);

    Ok(())
}

/// Append an A record to the response
fn try_push_rr_a(
    out: &mut Vec<u8>,
    ttl: u32,
    ip: Ipv4Addr,
    max_size: usize,
    truncated: &mut bool,
    answer_count: &mut u16,
) -> Result<(), DnsBuildError> {
    let rr_len = DNS_HEADER_OFFSET + 4;
    let Some(rr_buf) = try_reserve_tail(out, rr_len, max_size, truncated) else {
        return Ok(());
    };

    let mut p = MutableDnsResponsePacket::new(rr_buf).ok_or(DnsBuildError::RecordBufferTooShort)?;
    p.set_name_tag(QNAME_TAG);
    p.set_rtype(DnsTypes::A);
    p.set_rclass(DnsClasses::IN);
    p.set_ttl(ttl);
    p.set_data_len(4);
    p.set_data(&ip.octets());

    *answer_count = answer_count.saturating_add(1);
    Ok(())
}

/// Append an AAAA record to the response
fn try_push_rr_aaaa(
    out: &mut Vec<u8>,
    ttl: u32,
    ip: Ipv6Addr,
    max_size: usize,
    truncated: &mut bool,
    answer_count: &mut u16,
) -> Result<(), DnsBuildError> {
    let rr_len = DNS_HEADER_OFFSET + 16;
    let Some(rr_buf) = try_reserve_tail(out, rr_len, max_size, truncated) else {
        return Ok(());
    };

    let mut p = MutableDnsResponsePacket::new(rr_buf).ok_or(DnsBuildError::RecordBufferTooShort)?;
    p.set_name_tag(QNAME_TAG);
    p.set_rtype(DnsTypes::AAAA);
    p.set_rclass(DnsClasses::IN);
    p.set_ttl(ttl);
    p.set_data_len(16);
    p.set_data(&ip.octets());

    *answer_count = answer_count.saturating_add(1);
    Ok(())
}

/// Append an SOA record to the response
///
/// If `as_answer` is true, increment `answer_count`, otherwise increment `authority_count`
fn try_push_rr_soa(
    out: &mut Vec<u8>,
    ttl: u32,
    max_size: usize,
    truncated: &mut bool,
    authority_count: &mut u16,
    as_answer: bool,
    answer_count: &mut u16,
) -> Result<(), DnsBuildError> {
    let rdata = Soa::new(ttl)?.to_bytes();
    let rr_len = DNS_HEADER_OFFSET + rdata.len();

    let Some(rr_buf) = try_reserve_tail(out, rr_len, max_size, truncated) else {
        return Ok(());
    };

    let mut p = MutableDnsResponsePacket::new(rr_buf).ok_or(DnsBuildError::RecordBufferTooShort)?;
    p.set_name_tag(QNAME_TAG);
    p.set_rtype(DnsTypes::SOA);
    p.set_rclass(DnsClasses::IN);
    p.set_ttl(ttl);
    p.set_data_len(rdata.len() as u16);
    p.set_data(&rdata);

    if as_answer {
        *answer_count = answer_count.saturating_add(1);
    } else {
        *authority_count = authority_count.saturating_add(1);
    }
    Ok(())
}

/// Write the DNS header fields into the first 12 bytes of `bytes`
fn write_header(
    bytes: &mut [u8],
    question: &DnsQuestion,
    authoritative: bool,
    truncated: bool,
    rcode: Retcode,
    answer_count: u16,
    authority_count: u16,
) -> Result<(), DnsBuildError> {
    let header_slice = bytes
        .get_mut(..DNS_HEADER_OFFSET)
        .ok_or(DnsBuildError::HeaderBufferTooShort)?;
    let mut header =
        MutableDnsPacket::new(header_slice).ok_or(DnsBuildError::HeaderBufferTooShort)?;

    header.set_id(question.id);
    header.set_is_response(1);
    header.set_opcode(Opcode::StandardQuery);
    header.set_is_authoriative(if authoritative { 1 } else { 0 });
    header.set_is_truncated(if truncated { 1 } else { 0 });
    header.set_is_recursion_desirable(0);
    header.set_is_recursion_available(0);
    header.set_zero_reserved(0);
    header.set_is_answer_authenticated(0);
    header.set_is_non_authenticated_data(0);
    header.set_rcode(rcode);

    header.set_query_count(1);
    header.set_response_count(answer_count);
    header.set_authority_rr_count(authority_count);
    header.set_additional_rr_count(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_parser::{Builder, Packet, QueryClass, QueryType, ResponseCode};

    fn build_dns_query_bytes(qnames: &[&str], qtype: QueryType) -> Vec<u8> {
        let mut builder = Builder::new_query(0x1234, true);
        for qname in qnames {
            // Avoid the dns_parser trailing-dot double-terminator issue:
            let normalized = qname.strip_suffix('.').unwrap_or(qname);
            builder.add_question(normalized, false, qtype, QueryClass::IN);
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
        assert_eq!(response.header.id, 0x1234);
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

    #[test]
    fn build_response_answer_a() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let question = DnsQuestion::parse(&request_bytes).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            &question,
            60,
            ResponseKind::AnswerA {
                addresses: vec![Ipv4Addr::new(100, 100, 100, 100), Ipv4Addr::new(1, 2, 3, 4)],
            },
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
    }

    #[test]
    fn build_response_answer_aaaa() {
        let request_bytes = build_dns_query_bytes(&["test.nord"], QueryType::AAAA);
        let question = DnsQuestion::parse(&request_bytes).unwrap();

        let response_bytes = DnsResponseBuilder::new(
            &question,
            60,
            ResponseKind::AnswerAAAA {
                addresses: vec![Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)],
            },
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
        let question = DnsQuestion::parse(&request_bytes).unwrap();

        let response_bytes =
            DnsResponseBuilder::new(&question, 60, ResponseKind::AnswerA { addresses: vec![] })
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
        let question = DnsQuestion::parse(&request_bytes).unwrap();

        let response_bytes = DnsResponseBuilder::new(&question, 60, ResponseKind::NoData)
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
        let question = DnsQuestion::parse(&request_bytes).unwrap();

        let response_bytes = DnsResponseBuilder::new(&question, 60, ResponseKind::NxDomain)
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
        let question = DnsQuestion::parse(&request_bytes).unwrap();

        let response_bytes = DnsResponseBuilder::new(&question, 60, ResponseKind::SoaAnswer)
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
        let question = DnsQuestion::parse(&request_bytes).unwrap();

        let addrs = (0..200).map(|i| Ipv4Addr::new(10, 0, 0, i as u8)).collect();
        let bytes =
            DnsResponseBuilder::new(&question, 60, ResponseKind::AnswerA { addresses: addrs })
                .set_max_size(100)
                .build()
                .unwrap();

        let parsed = Packet::parse(&bytes).unwrap();
        assert!(parsed.header.truncated);
    }
}
