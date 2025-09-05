#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(unknown_lints)]

//! Telio protocol crate.
//!
//! Defines all possible packets to be send. And how they are encoded / decoded.

mod codec;
#[allow(clippy::unwrap_used, clippy::panic)]
pub(crate) mod messages {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

mod packet;

mod ens;

pub use ens::{
    grpc::{ConnectionError, Error as GrpcError},
    Error, ErrorNotificationService,
};

pub use codec::{Codec, Error as CodecError, Result as CodecResult};
pub use packet::*;

pub use messages::nurse::heartbeat::NatType as HeartbeatNatType;
pub use messages::nurse::heartbeat::Status as HeartbeatStatus;
pub use messages::nurse::heartbeat::Type as HeartbeatType;

pub use messages::natter::call_me_maybe::Type as CallMeMaybeType;

pub use messages::natter::call_me_maybe_deprecated::Type as CallMeMaybeDeprecatedType;
