#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

//! Easily create and run in process dns resolver.

mod dns;
// TODO: LLT-7053 remove after integrating forwarder
#[allow(dead_code)]
mod forwarder;
mod nameserver;
mod packet_decoder;
mod packet_encoder;
mod resolver;
mod zone;

pub mod bind_tun;

pub(crate) mod forward;

pub use crate::dns::{DnsResolver, LocalDnsResolver};
pub use nameserver::{LocalNameServer, NameServer};
pub use resolver::Resolver;
pub use zone::Records;

#[cfg(feature = "mockall")]
pub use crate::dns::MockDnsResolver;

/// Public functions exposed for fuzzing framework
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    pub use super::nameserver::fuzz_decode_packet;
    pub use super::packet_decoder::{find_nord_query, parse_dns_query_packet};
    pub use super::packet_encoder::fuzz_build_response;
}
