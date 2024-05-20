use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::task::JoinHandle;

use telio_model::features::FeaturePostQuantumVPN;
use telio_task::io::chan;
use telio_utils::{telio_log_debug, telio_log_warn};

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

        let task = async move {
            let mut interval = tokio::time::interval(request_retry);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            let proto::KeySet {
                mut wg_keys,
                pq_secret,
            } = loop {
                interval.tick().await;

                // Dylint is unhappy about the `fetch_keys` future size
                // and asks for using `Box::pin` to move it on the heap
                match Box::pin(super::proto::fetch_keys(
                    &socket_pool,
                    addr,
                    &wg_secret,
                    &peer,
                ))
                .await
                {
                    Ok(keys) => {
                        telio_log_debug!("PQ keys fetched");
                        break keys;
                    }
                    Err(err) => telio_log_warn!("Failed to fetch PQ keys: {err}"),
                }
            };

            // The channel is allways open during the library operation.
            // It can only be closed on library shutdown, in that case we
            // may not care since the task itself will be killed soon
            #[allow(mpsc_blocking_send)]
            let _ = chan.send(super::Event::Handshake(addr, wg_keys)).await;

            telio_log_debug!("Rekey interval: {}s", rekey_interval.as_secs());
            let mut interval = tokio::time::interval(rekey_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            interval.tick().await; // This call returns immedietly
            loop {
                interval.tick().await;

                // Dylint is unhappy about the `rekey` future size
                // and asks for using `Box::pin` to move it on the heap
                match Box::pin(super::proto::rekey(&socket_pool, &pq_secret)).await {
                    Ok(key) => {
                        telio_log_debug!("Successful PQ REKEY");
                        wg_keys.pq_shared = key;

                        // The channel is allways open during the library operation.
                        // It can only be closed on library shutdown, in that case we
                        // may not care since the task itself will be killed soon
                        #[allow(mpsc_blocking_send)]
                        let _ = chan.send(super::Event::Rekey(wg_keys)).await;
                    }
                    Err(err) => telio_log_warn!("Failed to perform PQ rekey: {err}"),
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
