//! DNS packet forwarder for remote resolvers
//!
//! This module provides a layer for forwarding DNS queries to upstream resolvers
//! through bound sockets

use crate::bind_tun::bind_to_tun;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use telio_utils::{telio_log_debug, telio_log_warn};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Mutex},
};

/// Maximum buffer size for response packet
const FORWARDER_BUFFER_SIZE: usize = 4096;
/// Channel size for forward messages
const CHANNEL_SIZE: usize = 1;
/// Default timeout for upstream DNS queries
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors returned when forwarding a DNS query
#[derive(Error, Debug)]
pub enum ForwardError {
    #[error("Failed to send DNS query: {0}")]
    Send(#[from] io::Error),
    #[error("Failed to receive DNS response: {0}")]
    Receive(io::Error),
    /// No upstreams configured
    #[error("No upstream resolvers configured")]
    NoUpstreams,
    /// The upstream resolver did not respond within the configured timeout
    #[error("DNS query timed out after {0:?}")]
    Timeout(Duration),
    /// The forwarder channel was closed
    #[error("Forwarder channel closed")]
    ChannelClosed,
}

/// DNS query forwarder bound to the tunnel interface
///
/// Forwards raw DNS queries to upstream resolvers.
#[derive(Clone)]
pub struct RawForwarder {
    tx: mpsc::Sender<ForwardMsg>,
    upstreams: Arc<Mutex<Vec<SocketAddr>>>,
    timeout: Arc<Mutex<Duration>>,
}

/// Internal message for forwarding a DNS query
struct ForwardMsg {
    /// Raw DNS packet bytes to forward
    request: Vec<u8>,
    /// Timeout for the upstream response
    timeout: Duration,
    /// Channel to send the response back to the caller
    respond_to: oneshot::Sender<Result<Vec<u8>, ForwardError>>,
}

impl RawForwarder {
    /// Create a new forwarder with a tunnel-bound UDP socket
    pub async fn new() -> Result<Self, ForwardError> {
        let socket = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(ForwardError::Send)?,
        );

        bind_to_tun(&socket).map_err(ForwardError::Send)?;

        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        let upstreams = Arc::new(Mutex::new(Vec::new()));
        let timeout = Arc::new(Mutex::new(DEFAULT_QUERY_TIMEOUT));

        tokio::spawn(Self::run(socket, rx, upstreams.clone()));

        Ok(RawForwarder {
            tx,
            upstreams,
            timeout,
        })
    }

    /// Forward a DNS query to the configured upstream resolver
    pub async fn query(&self, request: &[u8]) -> Result<Vec<u8>, ForwardError> {
        let timeout = *self.timeout.lock().await;
        let (respond_to, recv) = oneshot::channel();
        let msg = ForwardMsg {
            request: request.to_vec(),
            timeout,
            respond_to,
        };

        self.tx
            .send(msg)
            .await
            .map_err(|_| ForwardError::ChannelClosed)?;

        recv.await.map_err(|_| ForwardError::ChannelClosed)?
    }

    /// Update the list of upstream resolvers
    pub async fn set_upstreams(&self, addrs: Vec<SocketAddr>) -> Result<(), ForwardError> {
        let mut upstreams = self.upstreams.lock().await;
        *upstreams = addrs;
        Ok(())
    }

    /// Update the timeout for upstream DNS queries
    pub async fn set_timeout(&self, timeout: Duration) {
        *self.timeout.lock().await = timeout;
    }

    /// Main async loop that processes incoming forward requests
    async fn run(
        socket: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<ForwardMsg>,
        upstreams: Arc<Mutex<Vec<SocketAddr>>>,
    ) {
        telio_log_debug!("Forwarder starting");
        let mut recv_buf = vec![0u8; FORWARDER_BUFFER_SIZE];

        while let Some(ForwardMsg {
            request,
            timeout,
            respond_to,
        }) = rx.recv().await
        {
            let current_upstreams = {
                let locked = upstreams.lock().await;
                locked.clone()
            };

            let result = Self::forward_query(
                &socket,
                &request,
                &current_upstreams,
                &mut recv_buf,
                timeout,
            )
            .await;
            let _ = respond_to.send(result);
        }

        telio_log_debug!("Forwarder exiting");
    }

    /// Forward a DNS query trying each upstream in order until one succeeds
    async fn forward_query(
        socket: &UdpSocket,
        request: &[u8],
        upstreams: &[SocketAddr],
        recv_buf: &mut [u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ForwardError> {
        let mut last_error = ForwardError::NoUpstreams;

        for &upstream in upstreams {
            match Self::try_upstream(socket, request, upstream, recv_buf, timeout).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    telio_log_warn!("Upstream {upstream} failed: {e}, trying next");
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }

    /// Send a DNS query to a single upstream resolver and receive the response
    async fn try_upstream(
        socket: &UdpSocket,
        request: &[u8],
        upstream: SocketAddr,
        recv_buf: &mut [u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ForwardError> {
        socket
            .send_to(request, upstream)
            .await
            .map_err(ForwardError::Send)?;

        let (bytes_read, _) = tokio::time::timeout(timeout, socket.recv_from(recv_buf))
            .await
            .map_err(|_| ForwardError::Timeout(timeout))?
            .map_err(ForwardError::Receive)?;

        recv_buf
            .get(..bytes_read)
            .map(|slice| slice.to_vec())
            .ok_or_else(|| ForwardError::Receive(std::io::Error::other("buffer overflow")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_upstreams_stores_resolvers() {
        let forwarder = RawForwarder::new().await.unwrap();
        let addrs = vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        forwarder.set_upstreams(addrs.clone()).await.unwrap();

        let upstreams = forwarder.upstreams.lock().await;
        assert_eq!(*upstreams, addrs);
    }

    #[tokio::test]
    async fn set_upstreams_replaces_existing() {
        let forwarder = RawForwarder::new().await.unwrap();
        let first_addrs = vec!["8.8.8.8:53".parse().unwrap()];
        let second_addrs = vec!["1.1.1.1:53".parse().unwrap(), "8.8.4.4:53".parse().unwrap()];

        forwarder.set_upstreams(first_addrs).await.unwrap();
        forwarder.set_upstreams(second_addrs.clone()).await.unwrap();

        let upstreams = forwarder.upstreams.lock().await;
        assert_eq!(*upstreams, second_addrs);
    }

    #[tokio::test]
    async fn query_returns_no_upstreams_when_empty() {
        let forwarder = RawForwarder::new().await.unwrap();

        let result = forwarder.query(b"test").await;

        match result {
            Err(ForwardError::NoUpstreams) => {}
            other => panic!("Expected NoUpstreams, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn cloned_forwarders_share_upstream_state() {
        let forwarder1 = RawForwarder::new().await.unwrap();
        let forwarder2 = forwarder1.clone();

        let addrs = vec!["8.8.8.8:53".parse().unwrap()];
        forwarder1.set_upstreams(addrs.clone()).await.unwrap();

        let upstreams = forwarder2.upstreams.lock().await;
        assert_eq!(*upstreams, addrs);
    }

    #[tokio::test]
    async fn cloned_forwarders_share_channel() {
        let forwarder1 = RawForwarder::new().await.unwrap();
        let forwarder2 = forwarder1.clone();

        let upstreams = vec!["8.8.8.8:53".parse().unwrap()];
        forwarder1.set_upstreams(upstreams).await.unwrap();

        assert!(Arc::ptr_eq(&forwarder1.upstreams, &forwarder2.upstreams),);
    }

    #[tokio::test]
    async fn set_timeout_updates_value() {
        let forwarder = RawForwarder::new().await.unwrap();
        let target_timeout = Duration::from_secs(10);

        forwarder.set_timeout(target_timeout).await;

        let timeout = *forwarder.timeout.lock().await;
        assert_eq!(timeout, target_timeout);
    }

    #[tokio::test]
    async fn forward_query_timeout() {
        let upstreams: Vec<SocketAddr> = vec![
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let target_timeout = Duration::from_millis(50);

        let forwarder = RawForwarder::new().await.unwrap();
        forwarder.set_upstreams(upstreams).await.unwrap();
        forwarder.set_timeout(target_timeout).await;

        let result = forwarder.query(b"test").await;

        match result {
            Err(ForwardError::Timeout(d)) => assert_eq!(d, target_timeout),
            other => panic!(
                "Expected Timeout after all upstreams failed, got: {:?}",
                other
            ),
        }
    }
}
