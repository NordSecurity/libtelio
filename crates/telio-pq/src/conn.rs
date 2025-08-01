use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::task::JoinHandle;

use telio_model::features::FeaturePostQuantumVPN;
use telio_task::io::chan;
use telio_utils::{reset_after, telio_log_debug, telio_log_warn};

use crate::proto;

pub struct ConnKeyRotation {
    task: JoinHandle<()>,
}

impl ConnKeyRotation {
    pub fn run(
        chan: chan::Tx<super::Event>,
        socket_pool: Arc<telio_sockets::SocketPool>,
        addr: SocketAddr,
        wg_secret: telio_crypto::SecretKey,
        peer: telio_crypto::PublicKey,
        features: &FeaturePostQuantumVPN,
    ) -> Self {
        telio_log_debug!("Starting PQ task");

        let rekey_interval = Duration::from_secs(features.rekey_interval_s as _);
        let request_retry = Duration::from_secs(features.handshake_retry_interval_s as _);
        let pq_version = features.version;

        let task = async move {
            let mut retry_interval = telio_utils::interval(request_retry);

            let proto::KeySet {
                mut wg_keys,
                pq_secret,
            } = loop {
                retry_interval.tick().await;

                // Dylint is unhappy about the `fetch_keys` future size
                // and asks for using `Box::pin` to move it on the heap
                let fetch_keys = Box::pin(super::proto::fetch_keys(
                    &socket_pool,
                    addr,
                    &wg_secret,
                    &peer,
                    pq_version,
                ));

                match tokio::time::timeout(request_retry, fetch_keys).await {
                    Ok(Ok(keys)) => {
                        telio_log_debug!("PQ keys fetched");
                        break keys;
                    }
                    Ok(Err(err)) => telio_log_warn!("Failed to fetch PQ keys: {err}"),
                    Err(_timeout) => telio_log_warn!(
                        "Failed to fetch PQ keys: TIMEOUT({}s)",
                        request_retry.as_secs()
                    ),
                }
            };

            // The channel is allways open during the library operation.
            // It can only be closed on library shutdown, in that case we
            // may not care since the task itself will be killed soon
            #[allow(mpsc_blocking_send)]
            let _ = chan
                .send(super::Event::Handshake(addr, wg_keys.clone()))
                .await;

            telio_log_debug!("Rekey interval: {}s", rekey_interval.as_secs());
            let mut interval = telio_utils::interval(rekey_interval);

            interval.tick().await; // This call returns immedietly
            loop {
                interval.tick().await;

                // Dylint is unhappy about the `rekey` future size
                // and asks for using `Box::pin` to move it on the heap
                let rekey = if pq_version == 2 {
                    Box::pin(super::proto::rekey(
                        &socket_pool,
                        &pq_secret,
                        pq_version,
                        Some(super::proto::RekeyV2Auth {
                            pre_shared_key: wg_keys.pq_shared.clone(),
                            wg_client_public: wg_keys.wg_secret.public(),
                            wg_server_public: peer,
                        }),
                    ))
                } else {
                    Box::pin(super::proto::rekey(
                        &socket_pool,
                        &pq_secret,
                        pq_version,
                        None,
                    ))
                };

                match tokio::time::timeout(request_retry, rekey).await {
                    Ok(Ok(key)) => {
                        telio_log_debug!("Successful PQ REKEY");
                        wg_keys.pq_shared = key.clone();

                        // The channel is allways open during the library operation.
                        // It can only be closed on library shutdown, in that case we
                        // may not care since the task itself will be killed soon
                        #[allow(mpsc_blocking_send)]
                        let _ = chan.send(super::Event::Rekey(wg_keys.clone())).await;
                    }
                    Ok(Err(err)) => {
                        telio_log_warn!("Failed to perform PQ rekey: {err}");
                        reset_after(&mut interval, request_retry);
                    }
                    Err(_timeout) => {
                        telio_log_warn!(
                            "Failed to perform PQ rekey: TIMEOUT({}s)",
                            request_retry.as_secs()
                        );
                        interval.reset_immediately();
                    }
                }
            }
        };

        let task = tokio::spawn(task);

        Self { task }
    }
}

impl Drop for ConnKeyRotation {
    fn drop(&mut self) {
        self.task.abort();
        telio_log_debug!("PQ rekey task aborted");
    }
}
