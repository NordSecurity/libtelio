#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

//! Crate responsible for communicating with Derp.
//! It defines two tasks:
//!     derp: for direct communication with Derp,
//!     multiplexer: for distributing Derp traffic to other crates

pub mod derp;
pub mod multiplexer;

pub use derp::*;
