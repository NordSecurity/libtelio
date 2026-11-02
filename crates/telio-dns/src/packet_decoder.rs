//! DNS packet decoder for the local .nord resolver
//!
//! This module provides a layer for parsing a single DNS question from raw UDP bytes

use crate::{
    packet_encoder::DNS_HEADER_OFFSET,
    zone::{NORD_ZONE, NORD_ZONE_SUFFIX},
};
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

/// Offsets of the section counts in the DNS header
const QDCOUNT_OFFSET: usize = 4;
const ANCOUNT_OFFSET: usize = 6;
const NSCOUNT_OFFSET: usize = 8;
const ARCOUNT_OFFSET: usize = 10;
/// RR type of the EDNS OPT record
const OPT_RR_TYPE: u16 = 41;
/// Size of the RR TYPE, CLASS, TTL and RDLENGTH fields following the owner name
const RR_FIXED_LEN: usize = 10;
/// Size of the QTYPE and QCLASS fields following a question name
const QUESTION_FIXED_LEN: usize = 4;

/// Read a big endian u16 at `at`
fn read_u16(packet: &[u8], at: usize) -> Option<u16> {
    let &[hi, lo] = packet.get(at..at.checked_add(2)?)? else {
        return None;
    };
    Some(u16::from_be_bytes([hi, lo]))
}

/// Offset just past the domain name starting at `pos`
///
/// Compression pointers end the name and are not followed, so this cannot loop
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Some(pos + 1),
            0x00 => pos += 1 + usize::from(len),
            0xC0 => return Some(pos + 2),
            // Reserved label types (RFC 6891 section 5)
            _ => return None,
        }
    }
}

/// UDP payload size advertised by the EDNS OPT record of `packet`
///
/// Returns `None` if the packet carries no OPT record or is malformed
pub(crate) fn edns_udp_payload_size(packet: &[u8]) -> Option<u16> {
    let question_count = read_u16(packet, QDCOUNT_OFFSET)?;
    let record_count = usize::from(read_u16(packet, ANCOUNT_OFFSET)?)
        + usize::from(read_u16(packet, NSCOUNT_OFFSET)?);
    let additional_count = read_u16(packet, ARCOUNT_OFFSET)?;

    let mut pos = DNS_HEADER_OFFSET;
    for _ in 0..question_count {
        pos = skip_name(packet, pos)? + QUESTION_FIXED_LEN;
    }

    for index in 0..record_count + usize::from(additional_count) {
        let fixed = skip_name(packet, pos)?;
        // The OPT record can only appear in the additional section, where CLASS holds the payload size
        if index >= record_count && read_u16(packet, fixed)? == OPT_RR_TYPE {
            return read_u16(packet, fixed + 2);
        }
        let rdata_len = read_u16(packet, fixed + 8)?;
        pos = fixed + RR_FIXED_LEN + usize::from(rdata_len);
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::packet_encoder::QNAME_TAG;
    use dns_parser::{Builder, QueryClass, QueryType};
    use pnet_packet::dns::DnsTypes;
    use std::convert::TryFrom;

    const REQUEST_ID: u16 = 0x1234;
    const RECURSION_DESIRED: bool = true;
    const ROOT_NAME: [u8; 1] = [0];
    const A_RR_TYPE: u16 = 1;
    const IN_CLASS: u16 = 1;

    /// Append a record and bump the section count at `count_offset`
    ///
    /// Records must be pushed in section order
    fn push_record(
        packet: &mut Vec<u8>,
        count_offset: usize,
        name: &[u8],
        rr_type: u16,
        class: u16,
        rdata: &[u8],
    ) {
        packet.extend_from_slice(name);
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&class.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(rdata);
        let count = read_u16(packet, count_offset).unwrap() + 1;
        packet[count_offset..count_offset + 2].copy_from_slice(&count.to_be_bytes());
    }

    pub(crate) fn push_opt(packet: &mut Vec<u8>, udp_payload_size: u16) {
        push_record(
            packet,
            ARCOUNT_OFFSET,
            &ROOT_NAME,
            OPT_RR_TYPE,
            udp_payload_size,
            &[],
        );
    }

    pub(crate) fn build_dns_query_bytes(qnames: &[&str], qtype: QueryType) -> Vec<u8> {
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
    fn edns_udp_payload_size_without_opt_is_none() {
        let query = build_dns_query_bytes(&["example.com"], QueryType::TXT);
        assert_eq!(edns_udp_payload_size(&query), None);
    }

    #[test]
    fn edns_udp_payload_size_reads_opt_class() {
        let mut query = build_dns_query_bytes(&["example.com"], QueryType::TXT);
        push_opt(&mut query, 1232);
        assert_eq!(edns_udp_payload_size(&query), Some(1232));
    }

    #[test]
    fn edns_udp_payload_size_is_not_clamped() {
        let mut query = build_dns_query_bytes(&["example.com"], QueryType::TXT);
        push_opt(&mut query, 100);
        assert_eq!(edns_udp_payload_size(&query), Some(100));
    }

    #[test]
    fn edns_udp_payload_size_skips_questions_and_records_before_opt() {
        let mut packet = build_dns_query_bytes(&["example.com", "www.example.com"], QueryType::TXT);
        push_record(
            &mut packet,
            ANCOUNT_OFFSET,
            &QNAME_TAG.to_be_bytes(),
            A_RR_TYPE,
            IN_CLASS,
            &[192, 0, 2, 1],
        );
        push_record(
            &mut packet,
            ARCOUNT_OFFSET,
            b"\x02ns\x07example\x03com\x00",
            A_RR_TYPE,
            IN_CLASS,
            &[192, 0, 2, 2],
        );
        push_opt(&mut packet, 4096);
        assert_eq!(edns_udp_payload_size(&packet), Some(4096));
    }

    #[test]
    fn edns_udp_payload_size_ignores_opt_type_outside_additional_section() {
        let mut packet = build_dns_query_bytes(&["example.com"], QueryType::TXT);
        push_record(
            &mut packet,
            ANCOUNT_OFFSET,
            &ROOT_NAME,
            OPT_RR_TYPE,
            1232,
            &[],
        );
        assert_eq!(edns_udp_payload_size(&packet), None);
    }

    #[test]
    fn edns_udp_payload_size_of_cut_packet_is_none() {
        let mut query = build_dns_query_bytes(&["example.com"], QueryType::TXT);
        push_opt(&mut query, 1232);
        let opt_class_end = query.len() - 6;
        for len in 0..opt_class_end {
            assert_eq!(edns_udp_payload_size(&query[..len]), None, "len {len}");
        }
    }

    #[test]
    fn edns_udp_payload_size_rejects_reserved_label_type() {
        let mut query = build_dns_query_bytes(&["example.com"], QueryType::TXT);
        push_opt(&mut query, 1232);
        query[DNS_HEADER_OFFSET] = 0x40;
        assert_eq!(edns_udp_payload_size(&query), None);
    }
}
