use std::time::Duration;

use async_trait::async_trait;
use telio_crypto::PublicKey;
use telio_wg::{DynamicWg, WireGuard};

pub const MAX_PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(180);

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
}

#[async_trait]
impl LastHandshakeTimeProvider for DynamicWg {
    async fn last_handshake_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error> {
        let interface = self.get_interface().await?;
        match interface
            .peers
            .get(public_key)
            .map(|peer| peer.time_since_last_handshake)
        {
            Some(t) => Ok(t),
            None => Err(Error::UnknownPeer(*public_key)),
        }
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
        Ok(Some(time)) => time < MAX_PEER_HANDSHAKE_TIMEOUT,
        _ => false,
    }
}

#[cfg(test)]
#[async_trait]
impl<T: LastHandshakeTimeProvider> LastHandshakeTimeProvider for tokio::sync::Mutex<T> {
    async fn last_handshake_time(&self, public_key: &PublicKey) -> Result<Option<Duration>, Error> {
        self.lock().await.last_handshake_time(public_key).await
    }
}
