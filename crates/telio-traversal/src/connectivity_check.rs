pub mod cross_ping_check;

use crate::endpoint_providers;
use telio_utils::exponential_backoff;
use thiserror::Error as TError;

use telio_model::{features::EndpointProvider, SocketAddr};
use telio_utils::Instant;

use telio_crypto::PublicKey;
use telio_proto::{CallMeMaybeMsg, Session};

#[derive(Debug, TError)]
pub enum Error {
    #[error("Received pong packet for unkown session")]
    UnkownSessionForRxedPongPacket,
    #[error("Endpoint provider error")]
    EndpointProviderError(#[from] endpoint_providers::Error),
    #[error("Exponential backoff error")]
    ExponentialBackoffError(#[from] exponential_backoff::Error),
    #[error("Error responding to CMM initiator message")]
    RespondingToCMMInitiatorError(
        #[from] tokio::sync::mpsc::error::SendError<(PublicKey, CallMeMaybeMsg)>,
    ),
    #[error("Error publishing WG endpoint")]
    PublishingWireGuardEndpointError(
        #[from] Box<tokio::sync::mpsc::error::SendError<WireGuardEndpointCandidateChangeEvent>>,
    ),
    #[error("Task Execution error")]
    TaskExecError(#[from] telio_task::ExecError),
    #[error("Unexpected peer {0}")]
    UnexpectedPeer(PublicKey),
    #[error("Codec error: {0}")]
    CodecError(#[from] telio_proto::CodecError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardEndpointCandidateChangeEvent {
    pub public_key: PublicKey,
    pub remote_endpoint: (SocketAddr, EndpointProvider),
    pub local_endpoint: (SocketAddr, EndpointProvider),
    pub session: Session,
    pub changed_at: Instant,
}
