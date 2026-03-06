#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

//! Easily create and run in process dns resolver.

mod dns;
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
