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
pub trait LastHandshakeTimeProvider: Send + Sync {
    /// Return last handshake time for a peer using given public key
    async fn last_handshake_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error>;
    async fn max_no_handshake_time(&self) -> Duration;
}

/// WireGuard based implementation of LastHandshakeTimeProvider
pub struct WireGuardLastHandshakeTimeProvider {
    pub wg: Arc<DynamicWg>,
    pub threshold: Duration,
}

#[async_trait]
impl LastHandshakeTimeProvider for WireGuardLastHandshakeTimeProvider {
    async fn last_handshake_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error> {
        let interface = self.wg.get_interface().await?;
        match interface
            .peers
            .get(public_key)
            .map(|peer| peer.time_since_last_handshake)
        {
            Some(t) => Ok(t),
            None => Err(Error::UnknownPeer(*public_key)),
        }
    }

    async fn max_no_handshake_time(&self) -> Duration {
        self.threshold
    }
}

pub async fn is_peer_alive(
    last_handshake_time_provider: &dyn LastHandshakeTimeProvider,
    public_key: &PublicKey,
) -> bool {
    match last_handshake_time_provider
        .last_handshake_time(public_key)
        .await
    {
        Ok(Some(time)) => time < last_handshake_time_provider.max_no_handshake_time().await,
        _ => false,
    }
}

#[cfg(test)]
#[async_trait]
impl<T: LastHandshakeTimeProvider> LastHandshakeTimeProvider for tokio::sync::Mutex<T> {
    async fn last_handshake_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error> {
        self.lock().await.last_handshake_time(public_key).await
    }

    async fn max_no_handshake_time(&self) -> Duration {
        self.lock().await.max_no_handshake_time().await
    }
}
