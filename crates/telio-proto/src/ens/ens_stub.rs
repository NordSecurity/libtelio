use std::sync::Arc;

use telio_crypto::SecretKey;
use telio_model::PublicKey;
use telio_sockets::SocketPool;
use telio_task::io::{
    chan::{Rx, Tx},
    Chan,
};
use telio_utils::exponential_backoff::Backoff;
use telio_utils::telio_log_warn;

pub(crate) mod grpc {
    /// Stub VPN connection error for when ENS is disabled at compile time.
    #[derive(Debug, Clone, Default)]
    pub struct ConnectionError {
        /// gRPC error code
        pub code: i32,
    }

    /// Stub gRPC error enum for when ENS is disabled at compile time.
    #[repr(i32)]
    #[derive(Debug)]
    #[allow(missing_docs)]
    pub enum Error {
        ConnectionLimitReached = 1,
        ServerMaintenance = 2,
        Unauthenticated = 3,
        Superseded = 4,
    }
}

/// ENS errors (stub when ENS is disabled at compile time)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// ENS is not available (disabled at compile time)
    #[error("ENS is disabled at compile time")]
    Disabled,
}

/// Stub ErrorNotificationService for when ENS is disabled at compile time.
pub struct ErrorNotificationService {
    _tx: Tx<(grpc::ConnectionError, PublicKey)>,
}

impl ErrorNotificationService {
    /// Create stub instance (ENS is disabled at compile time)
    pub fn new(
        buffer_size: usize,
        _socket_pool: Arc<SocketPool>,
        _allow_only_mlkem: bool,
        _root_certificate_override: Option<Vec<u8>>,
    ) -> (Self, Rx<(grpc::ConnectionError, PublicKey)>) {
        let Chan { rx, tx }: Chan<(grpc::ConnectionError, PublicKey)> = Chan::new(buffer_size);
        (Self { _tx: tx }, rx)
    }

    /// No-op: ENS is disabled at compile time
    pub async fn start_monitor(
        &mut self,
        _vpn_ip: std::net::IpAddr,
        _vpn_public_key: PublicKey,
        _local_private_key: SecretKey,
        _backoff: impl Backoff,
    ) -> Result<(), Error> {
        telio_log_warn!("ENS start_monitor called but ENS is disabled at compile time");
        Err(Error::Disabled)
    }

    /// No-op: ENS is disabled at compile time
    pub async fn stop(&mut self) {}
}

/// When ENS is disabled, we should only have ring provider and there should be no need
/// to explicitly configure the default crypto provider. But just to be on the safe side,
/// (and handle a case where there 3rd crypto provider) we will configure ring either way.
pub fn install_default_crypto_provider() {
    if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
        telio_log_warn!("Failed to install default crypto provider for rustls: {e:?}");
    }
}
