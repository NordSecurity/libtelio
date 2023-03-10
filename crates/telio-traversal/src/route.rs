use async_trait::async_trait;
use tokio::time::Duration;

use telio_crypto::PublicKey;

/// Posible [Codec] trait errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Length of bytes being parrsed is invalid.
    #[error("Cannot set nodes.")]
    SetNodesFailed,
    /// Bytes format is invalid for deserialization.
    #[error("Failed to parse packet.")]
    NodeNotFound,
    /// Latency is not measured for this peer
    #[error("Latency not measured")]
    LatencyUnknown,
    #[error(transparent)]
    Task(#[from] telio_task::ExecError),
}

/// Result wrapper for implementations.
pub type RouteResult<T> = std::result::Result<T, Error>;

#[async_trait]
pub trait Route: Configure {
    /// Set nodes to natter's database, for them to be traversed. All previously set nodes will be deleted.
    async fn set_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()>;

    /// Update or insert some new nodes, not touching the unnafected nodes' states
    async fn update_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()>;

    /// Reset nodes states
    async fn reset_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()>;

    /// Check, if a peer has an active path through natter
    async fn is_reachable(&self, node: PublicKey) -> bool;

    /// Check peer's path metric
    async fn rtt(&self, node: PublicKey) -> RouteResult<Duration>;
}

#[async_trait]
pub trait Configure {
    /// Configure route during runtime
    async fn configure(&self, config: telio_relay::Config);
}
