//! DNS packet decoder for the local .nord resolver
//!
//! This module provides a layer for parsisng a single DNS question from raw UDP bytes

// TODO: Remove after merging integration
#![allow(dead_code)]

use pnet_packet::dns::{DnsClass, DnsClasses, DnsPacket, DnsType, Opcode};
use thiserror::Error;

pub const DNS_HEADER_OFFSET: usize = 0xC;

/// Errors returned when parsing a DNS query from raw bytes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsParseError {
    /// The buffer is too short to contain a valid DNS header or required fields
    #[error("packet too short")]
    PacketTooShort,
    /// The packet is not a standard DNS query
    #[error("not a supported DNS query")]
    NotQuery,
    /// Opcode is not supported
    #[error("unsupported opcode: {0:?}")]
    UnsupportedOpcode(Opcode),
    /// Only class IN is supported.
    #[error("unsupported query class: {0:?}")]
    UnsupportedClass(DnsClass),
    /// The question section is missing or truncated
    #[error("truncated question section")]
    TruncatedQuestion,
}

/// A parsed DNS question
///
/// This represents only the first question in the DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Identifier of the message
    pub id: u16,
    /// QNAME of the request
    pub name: String,
    /// QTYPE of the request
    pub record_type: DnsType,
}

impl DnsQuestion {
    /// Check if the query is for the `.nord` top-level domain
    pub fn is_nord_tld(&self) -> bool {
        is_nord_name(&self.name)
    }

    /// Parse a DNS Question from raw DNS bytes
    ///
    /// Takes only the fist query in case there are multiple
    pub fn parse(packet_bytes: &[u8]) -> Result<DnsQuestion, DnsParseError> {
        let dns_packet = DnsPacket::new(packet_bytes).ok_or(DnsParseError::PacketTooShort)?;

        if dns_packet.get_is_response() != 0 {
            return Err(DnsParseError::NotQuery);
        }

        let opcode = dns_packet.get_opcode();
        if opcode != Opcode::StandardQuery {
            return Err(DnsParseError::UnsupportedOpcode(opcode));
        }

        let queries = dns_packet.get_queries();
        let first_query = queries.first().ok_or(DnsParseError::NotQuery)?;

        if first_query.qclass != DnsClasses::IN {
            return Err(DnsParseError::UnsupportedClass(first_query.qclass));
        }

        Ok(DnsQuestion {
            id: dns_packet.get_id(),
            name: first_query.get_qname_parsed().to_ascii_lowercase(),
            record_type: first_query.qtype,
        })
    }
}

/// Check if `name` is in the `.nord` top-level domain
fn is_nord_name(name: &str) -> bool {
    let normalized = normalize(name);
    if normalized.is_empty() {
        return false;
    }
    normalized == "nord" || normalized.ends_with(".nord")
}

/// Normalize the name, converting to lowercase and trimming trailing dot
pub fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_parser::{Builder, QueryClass, QueryType};
    use pnet_packet::dns::DnsTypes;

    fn build_dns_query_bytes(qnames: &[&str], qtype: QueryType) -> Vec<u8> {
        let mut builder = Builder::new_query(0x1234, true);
        for qname in qnames {
            // Avoid the dns_parser trailing-dot double-terminator issue:
            let normalized = qname.strip_suffix('.').unwrap_or(qname);
            builder.add_question(normalized, false, qtype, QueryClass::IN);
        }
        builder.build().unwrap().to_vec()
    }

    #[test]
    fn parse_single_a() {
        let bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let parsed = DnsQuestion::parse(&bytes).expect("parse should succeed");

        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.name, "test.nord");
        assert_eq!(parsed.record_type, DnsTypes::A);
        assert!(parsed.is_nord_tld());
    }

    #[test]
    fn parse_multiple_queries_takes_first() {
        let bytes = build_dns_query_bytes(&["first.nord", "second.nord"], QueryType::A);
        let parsed = DnsQuestion::parse(&bytes).expect("parse should succeed");
        assert_eq!(parsed.name, "first.nord");
    }

    #[test]
    fn parse_zero_queries() {
        let mut bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        // patch QDCOUNT=0.
        bytes[4] = 0;
        bytes[5] = 0;

        let err = DnsQuestion::parse(&bytes).unwrap_err();
        assert_eq!(err, DnsParseError::NotQuery);
    }

    #[test]
    fn test_nord_name() {
        assert!(is_nord_name("test.nord"));
        assert!(is_nord_name("test.nord."));
        assert!(is_nord_name("TeSt.NoRd"));

        assert!(is_nord_name("nord"));
        assert!(is_nord_name("nord."));

        assert!(!is_nord_name("test.nordsec.com"));
        assert!(!is_nord_name("test.nord.com"));
        assert!(!is_nord_name("test.nordsec"));
        assert!(!is_nord_name("testnord"));
        assert!(!is_nord_name(""));
        assert!(!is_nord_name("."));
    }

    #[test]
    fn test_query() {
        let a = DnsQuestion::parse(&build_dns_query_bytes(&["test.nord"], QueryType::A)).unwrap();
        assert_eq!(a.record_type, DnsTypes::A);

        let aaaa =
            DnsQuestion::parse(&build_dns_query_bytes(&["test.nord"], QueryType::AAAA)).unwrap();
        assert_eq!(aaaa.record_type, DnsTypes::AAAA);

        let soa =
            DnsQuestion::parse(&build_dns_query_bytes(&["test.nord"], QueryType::SOA)).unwrap();
        assert_eq!(soa.record_type, DnsTypes::SOA);
    }
}
