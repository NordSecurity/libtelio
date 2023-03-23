use telio_crypto::PublicKey;
use telio_proto::DataMsg;

use telio_task::ExecError;
use tokio::sync::mpsc::error::SendError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Task was stooped")]
    Stopped,
    #[error("Could not acquire channel")]
    Channel,
    #[error("Peer already exists")]
    PeerExists,
    #[error("Derp config not set for path set builder")]
    DerpConfigNotSet,
    #[error(transparent)]
    TaskError(#[from] ExecError),
    #[error(transparent)]
    Send(#[from] SendError<(PublicKey, DataMsg)>),
    #[error("Failed to send a message: {0}")]
    SendError(#[from] Box<dyn std::error::Error + Send + Sync>),
}
