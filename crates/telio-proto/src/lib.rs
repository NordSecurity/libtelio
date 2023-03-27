#![deny(missing_docs)]
#![allow(unknown_lints)]

//! Telio protocol crate.
//!
//! Defines all possible packets to be send. And how they are encoded / decoded.

mod codec;
#[allow(unwrap_check)]
#[allow(clippy::unwrap_used, clippy::panic)]
pub(crate) mod messages {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}
mod packet;

pub use codec::{Codec, Error as CodecError, Result as CodecResult};
pub use packet::*;

pub use messages::nurse::Heartbeat_Status as HeartbeatStatus;
pub use messages::nurse::Heartbeat_Type as HeartbeatType;

pub use messages::natter::CallMeMaybe_Type as CallMeMaybeType;

pub use messages::natter::CallMeMaybeDeprecated_Type as CallMeMaybeDeprecatedType;
