//! DNS packet decoder for the local .nord resolver
//!
//! This module provides a layer for parsisng a single DNS question from raw UDP bytes

// TODO: Remove after merging integration
#![allow(dead_code)]

use pnet_packet::{
    dns::{DnsClasses, DnsPacket, DnsQuery, Opcode},
    FromPacket,
};
use thiserror::Error;

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
}

/// Check if `name` is in the `.nord` top-level domain
fn is_nord_name(name: &str) -> bool {
    let normalized = normalize_qname(name);
    if normalized.is_empty() {
        return false;
    }
    normalized == "nord" || normalized.ends_with(".nord")
}

/// Normalize the name, converting to lowercase and trimming trailing dot
pub fn normalize_qname(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse a DNS Question from raw DNS bytes
pub fn parse_dns_packet(packet_bytes: &[u8]) -> Result<DnsPacket<'_>, DnsParseError> {
    let dns_packet = DnsPacket::new(packet_bytes).ok_or(DnsParseError::PacketTooShort)?;

    if dns_packet.get_is_response() != 0 || dns_packet.get_query_count() == 0 {
        return Err(DnsParseError::NotQuery);
    }

    let opcode = dns_packet.get_opcode();
    if opcode != Opcode::StandardQuery {
        return Err(DnsParseError::UnsupportedOpcode(opcode));
    }

    Ok(dns_packet)
}

/// Find a query containing .nord domain
///
/// Returns the first found query
pub fn find_nord_query(dns_packet: &DnsPacket) -> Option<DnsQuery> {
    dns_packet.get_queries_iter().find_map(|q| {
        let query = q.from_packet();
        if query.qclass == DnsClasses::IN && is_nord_name(&query.get_qname_parsed()) {
            Some(query)
        } else {
            None
        }
    })
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
        let packet = parse_dns_packet(&bytes).expect("parse should succeed");
        let query = find_nord_query(&packet).expect("should have nord query");
        let qname = query.get_qname_parsed();

        assert_eq!(packet.get_id(), 0x1234);
        assert_eq!(qname, "test.nord");
        assert_eq!(query.qtype, DnsTypes::A);
    }

    #[test]
    fn parse_multiple_queries_takes_first() {
        let bytes = build_dns_query_bytes(&["first.nord", "second.nord"], QueryType::A);
        let packet = parse_dns_packet(&bytes).expect("parse should succeed");
        let query = find_nord_query(&packet).expect("should have nord query");
        let qname = query.get_qname_parsed();
        assert_eq!(qname, "first.nord");
    }

    #[test]
    fn parse_zero_queries() {
        let mut bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        // patch QDCOUNT=0.
        bytes[4] = 0;
        bytes[5] = 0;

        let err = parse_dns_packet(&bytes).unwrap_err();
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
}
