pub mod local;
pub mod stun;

use async_trait::async_trait;
use ipnet::PrefixLenError;
use std::time::Duration;
use thiserror::Error as TError;

use telio_model::SocketAddr;
use telio_proto::{PingerMsg, Session, WGPort};
use telio_task::io::chan;
use telio_wg;

#[derive(Debug, TError)]
pub enum Error {
    #[error(transparent)]
    PrefixLenError(#[from] PrefixLenError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    EndpointCandidatePublishError(
        #[from] tokio::sync::mpsc::error::SendError<EndpointCandidatesChangeEvent>,
    ),
    #[error(transparent)]
    PongRxedPublishError(#[from] tokio::sync::mpsc::error::SendError<PongEvent>),
    #[error(transparent)]
    WireGuardError(#[from] telio_wg::Error),
    #[error("WireGuard listening port is missing")]
    NoWGListenPort,
    #[error(transparent)]
    PacketParserError(#[from] telio_proto::CodecError),
    #[error("Failed to build pong packet")]
    FailedToBuildPongPacket,
    /// Stun codec error
    #[error(transparent)]
    ByteCodecError(#[from] bytecodec::Error),
    #[error(transparent)]
    RuntimeError(#[from] telio_task::ExecError),
    /// Component was not configured for operation
    #[error("Component was not configured for operation")]
    NotConfigured,
    /// Stun peer does not exist in wireguard
    #[error("Stun peer does not exist in wireguard")]
    NoStunPeer,
    /// Stun peer is missconfigured (no allowed_ip or endpoint)
    #[error("Stun peer is misconfigured")]
    BadStunPeer,
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct EndpointCandidate {
    pub wg: SocketAddr,
    pub udp: SocketAddr,
}

pub type EndpointCandidatesChangeEvent = Vec<EndpointCandidate>;

#[derive(Debug, Clone)]
pub struct PongEvent {
    pub addr: SocketAddr,
    pub rtt: Duration,
    pub msg: PingerMsg,
}

#[async_trait]
pub trait EndpointProvider {
    async fn subscribe_for_pong_events(&self, tx: chan::Tx<PongEvent>);
    async fn subscribe_for_endpoint_candidates_change_events(
        &self,
        tx: chan::Tx<EndpointCandidatesChangeEvent>,
    );
    async fn trigger_endpoint_candidates_discovery(&self) -> Result<(), Error>;

    async fn send_ping(
        &self,
        addr: SocketAddr,
        peer_id: WGPort,
        session_id: Session,
    ) -> Result<(), Error>;
}
