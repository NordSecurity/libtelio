//! DNS packet decoder for the local .nord resolver
//!
//! This module provides a layer for parsing a single DNS question from raw UDP bytes

use crate::zone::{NORD_ZONE, NORD_ZONE_SUFFIX};
use pnet_packet::{
    dns::{DnsClasses, DnsPacket, DnsQuery, Opcodes},
    FromPacket,
};
use telio_utils::telio_log_warn;
use thiserror::Error;

/// Errors returned when parsing a DNS query from raw bytes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsParseError {
    /// The buffer is too short to contain a valid DNS header or required fields
    #[error("packet too short")]
    PacketTooShort,
    /// The packet is not a DNS query
    #[error("not a DNS query")]
    NotQuery,
    /// The packet has no DNS queries
    #[error("no DNS queries")]
    NoQueries,
}

/// Check if `name` is in the `.nord` top-level domain
fn is_nord_name(name: &str) -> bool {
    let normalized = normalize_qname(name);
    if normalized.is_empty() {
        return false;
    }
    normalized == NORD_ZONE || normalized.ends_with(NORD_ZONE_SUFFIX)
}

/// Normalize the name, converting to lowercase and appending trailing dot
pub(crate) fn normalize_qname(name: &str) -> String {
    let mut name = name.trim().to_ascii_lowercase();
    if !name.ends_with('.') {
        name.push('.');
    }
    name
}

/// Parse a DNS Question from raw DNS bytes
pub fn parse_dns_query_packet(packet_bytes: &[u8]) -> Result<DnsPacket<'_>, DnsParseError> {
    let dns_packet = DnsPacket::new(packet_bytes).ok_or(DnsParseError::PacketTooShort)?;

    if dns_packet.get_is_response() != 0 {
        return Err(DnsParseError::NotQuery);
    }

    if dns_packet.get_query_count() == 0 {
        return Err(DnsParseError::NoQueries);
    }

    Ok(dns_packet)
}

/// Find a query containing .nord domain
///
/// Checks only the first query
/// DNS spec in theory makes it possible to have multiple query per packet
/// but in practice this is never implemented
pub fn find_nord_query(dns_packet: &DnsPacket) -> Option<DnsQuery> {
    let opcode = dns_packet.get_opcode();
    if opcode != Opcodes::StandardQuery {
        telio_log_warn!("Unsupported Opcode for nord query: {opcode:?}");
        return None;
    }

    if dns_packet.get_query_count() > 1 {
        telio_log_warn!(
            "DNS packet contains multiple queries: {}",
            dns_packet.get_query_count()
        );
    }
    let first = dns_packet.get_queries_iter().next()?.from_packet();
    if first.qclass == DnsClasses::IN && is_nord_name(&first.get_qname_parsed()) {
        Some(first)
    } else {
        None
    }
}

/// Check whether the first query is for the `.onion` top-level domain.
pub(crate) fn is_onion_query(dns_packet: &DnsPacket) -> bool {
    let Some(query) = dns_packet
        .get_queries_iter()
        .next()
        .map(|query| query.from_packet())
    else {
        return false;
    };

    if query.qclass != DnsClasses::IN {
        return false;
    }

    let qname = normalize_qname(&query.get_qname_parsed());
    qname == "onion." || qname.ends_with(".onion.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_parser::{Builder, QueryClass, QueryType};
    use pnet_packet::dns::DnsTypes;

    const REQUEST_ID: u16 = 0x1234;
    const RECURSION_DESIRED: bool = true;

    fn build_dns_query_bytes(qnames: &[&str], qtype: QueryType) -> Vec<u8> {
        let mut builder = Builder::new_query(REQUEST_ID, RECURSION_DESIRED);
        for qname in qnames {
            builder.add_question(qname, false, qtype, QueryClass::IN);
        }
        builder.build().unwrap().to_vec()
    }

    #[test]
    fn parse_single_a() {
        let bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&bytes).expect("parse should succeed");
        let query = find_nord_query(&packet).expect("should have nord query");
        let qname = query.get_qname_parsed();

        assert_eq!(packet.get_id(), REQUEST_ID);
        assert_eq!(qname, "test.nord");
        assert_eq!(query.qtype, DnsTypes::A);
    }

    #[test]
    fn parse_multiple_queries_takes_first() {
        let bytes = build_dns_query_bytes(&["first.nord", "second.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&bytes).expect("parse should succeed");
        let query = find_nord_query(&packet).expect("should have nord query");
        let qname = query.get_qname_parsed();
        assert_eq!(qname, "first.nord");
    }

    #[test]
    fn parse_multiple_queries_takes_first_non_nord() {
        let bytes = build_dns_query_bytes(&["google.com", "second.nord"], QueryType::A);
        let packet = parse_dns_query_packet(&bytes).expect("parse should succeed");
        assert!(
            find_nord_query(&packet).is_none(),
            "should not have nord query"
        );
    }

    #[test]
    fn parse_zero_queries() {
        let mut bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        // patch QDCOUNT=0.
        bytes[4] = 0;
        bytes[5] = 0;

        let err = parse_dns_query_packet(&bytes).unwrap_err();
        assert_eq!(err, DnsParseError::NoQueries);
    }

    #[test]
    fn parse_packet_too_short() {
        assert_eq!(
            parse_dns_query_packet(&[]),
            Err(DnsParseError::PacketTooShort)
        );
        assert_eq!(
            parse_dns_query_packet(&[0; 2]),
            Err(DnsParseError::PacketTooShort)
        );
    }

    #[test]
    fn parse_response_packet_rejected() {
        let mut bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        // Set QR bit to response
        bytes[2] |= 0x80;
        assert_eq!(parse_dns_query_packet(&bytes), Err(DnsParseError::NotQuery));
    }

    #[test]
    fn parse_opcode() {
        let mut bytes = build_dns_query_bytes(&["test.nord"], QueryType::A);
        // Set opcode to 2 (Status) while keeping QR=0
        bytes[2] = (bytes[2] & 0x80) | (2 << 3);
        let packet = parse_dns_query_packet(&bytes).unwrap();
        assert_eq!(packet.get_opcode(), Opcodes::ServerStatusRequest);
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
    fn test_onion_query() {
        for qname in ["onion", "service.onion", "SERVICE.ONION"] {
            let bytes = build_dns_query_bytes(&[qname], QueryType::A);
            let packet = parse_dns_query_packet(&bytes).unwrap();
            assert!(is_onion_query(&packet), "expected {} to be .onion", qname);
        }

        for qname in ["notonion", "onion.example", "service.onion.test"] {
            let bytes = build_dns_query_bytes(&[qname], QueryType::A);
            let packet = parse_dns_query_packet(&bytes).unwrap();
            assert!(
                !is_onion_query(&packet),
                "did not expect {} to be .onion",
                qname
            );
        }
    }
}
