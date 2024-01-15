use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use telio_crypto::PublicKey;
use telio_wg::{DynamicWg, WireGuard};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown peer: {0}")]
    UnknownPeer(PublicKey),
    #[error("Unable to communicate with wireguard: {0}")]
    UnableToCommunicateWithWG(#[from] telio_wg::Error),
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait TimeSinceLastRxProvider: Send + Sync {
    /// Return last rx time for a peer using given public key
    async fn last_rx_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error>;
    async fn max_no_rx_time(&self) -> Duration;
}

/// WireGuard based implementation of TimeSinceLastRxProvider
pub struct WireGuardTimeSinceLastRxProvider {
    pub wg: Arc<DynamicWg>,
    pub threshold: Duration,
}

#[async_trait]
impl TimeSinceLastRxProvider for WireGuardTimeSinceLastRxProvider {
    async fn last_rx_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error> {
        Ok(self.wg.time_since_last_rx(*public_key).await?)
    }

    async fn max_no_rx_time(&self) -> Duration {
        self.threshold
    }
}

pub async fn is_peer_alive(
    last_rx_time_provider: &dyn TimeSinceLastRxProvider,
    public_key: &PublicKey,
) -> bool {
    match last_rx_time_provider.last_rx_time(public_key).await {
        Ok(Some(time)) => time < last_rx_time_provider.max_no_rx_time().await,
        _ => false,
    }
}

#[cfg(test)]
#[async_trait]
impl<T: TimeSinceLastRxProvider> TimeSinceLastRxProvider for tokio::sync::Mutex<T> {
    async fn last_rx_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error> {
        self.lock().await.last_rx_time(public_key).await
    }

    async fn max_no_rx_time(&self) -> Duration {
        self.lock().await.max_no_rx_time().await
    }
}
