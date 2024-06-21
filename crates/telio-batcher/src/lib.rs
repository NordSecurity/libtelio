use async_trait::async_trait;
use futures::{future, stream::FuturesUnordered, Future};
use std::collections::HashMap;
use telio_task::{task_exec, BoxAction, ExecError, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_info};
use tokio::sync::{watch, Mutex};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Generic error")]
    Generic(#[from] ExecError),
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
pub trait BatcherTrait {
    async fn start() -> Batcher;
    async fn stop(&self);

    fn remove(&mut self, key: &tokio::sync::watch::Receiver<()>);
    async fn add(
        &mut self,
        key: String,
        interval: std::time::Duration,
        threshold: std::time::Duration,
    ) -> std::result::Result<tokio::sync::watch::Receiver<()>, Error>;
}

type Result<T> = std::result::Result<T, Error>;

use std::sync::Arc;

struct State {
    notifiers: Arc<Mutex<HashMap<String, BatchEntry>>>,
}

impl State {
    async fn update(&self) {
        telio_log_info!("****** Batcher update after tick");
        let now = std::time::Instant::now();
        for (_key, entry) in self.notifiers.lock().await.iter_mut() {
            let elapsed = now - entry.add_time;
            if elapsed >= entry.interval {
                entry.tx.send(()).unwrap();
            }
        }
    }
}

pub struct Batcher {
    task: Task<State>,
}

struct BatchEntry {
    add_time: std::time::Instant,
    interval: std::time::Duration,
    threshold: std::time::Duration,
    tx: tokio::sync::watch::Sender<()>,
    rx: tokio::sync::watch::Receiver<()>,
}

impl BatchEntry {
    fn reset(&mut self) {
        self.add_time = std::time::Instant::now();
    }
}
// TODO: add internal task that would watch for the rate of triggering and would warn of potential issues
#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Batcher";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        telio_log_info!("****** Batcher wait_with_update @1");

        let now = std::time::Instant::now();
        let keys_that_batch: Vec<String> = self
            .notifiers
            .lock()
            .await
            .iter()
            .filter_map(|(key, entry)| {
                // TODO: make proper threshold calculation
                let elapsed = now - entry.add_time;
                if elapsed >= (entry.interval - entry.threshold) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        use futures::StreamExt;

        telio_log_info!(
            "****** Batcher wait_with_update @2. len: {}",
            keys_that_batch.len()
        );
        if keys_that_batch.len() > 0 {
            let mut locked = self.notifiers.lock().await;
            for key in keys_that_batch {
                println!("***** keykey {:?}", key);
                let val = locked.get_mut(&key).unwrap();
                let _ = val.tx.send(()).unwrap();
                val.reset();
            }
        } else {
            telio_log_info!("****** Batcher wait_with_update @1-else");
            tokio::select! {
                update = update => {
                    telio_log_info!("****** Batcher wait_with_update @1-update before");
                    return update(self).await;
                    telio_log_info!("****** Batcher wait_with_update @1-update after");
                }
                else => {
                    telio_log_info!("****** Batcher wait_with_update @1-else");
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    async fn stop(mut self) {
        telio_log_info!(">>>>>>>>>>>> ****** Batcher S T O P");
        todo!();
    }
}

impl BatcherTrait for Batcher {
    async fn start() -> Self {
        telio_log_info!("****** Starting Batcher");

        let task = Task::start(State {
            notifiers: Arc::new(Mutex::new(HashMap::new())),
        });

        Self { task }
    }

    fn remove(&mut self, _key: &tokio::sync::watch::Receiver<()>) {
        todo!();
        // task_exec!(&self.task, async move |s| {
        //     // s.notifiers.remove(key);
        //     todo!("impl remove");
        //     Ok(())
        // });
    }

    async fn add(
        &mut self,
        key: String,
        interval: std::time::Duration,
        threshold: std::time::Duration,
    ) -> std::result::Result<tokio::sync::watch::Receiver<()>, Error> {
        telio_log_info!("****** Adding task to Batcher");

        task_exec!(&self.task, async move |s| {
            let (tx, rx) = tokio::sync::watch::channel(());
            let entry = BatchEntry {
                add_time: std::time::Instant::now(),
                interval,
                threshold,
                tx,
                rx: rx.clone(), // TODO: suspicious clone
            };

            telio_log_info!("****** Adding task to Batcher before lock");
            s.notifiers.lock().await.insert(key, entry);
            telio_log_info!("****** Adding task to Batcher after lock");
            Ok(rx)
        })
        .await
        .map_err(Error::Generic)
    }

    async fn stop(&self) {
        telio_log_info!(">>>>>>>>>>>> ****** Batcher @2 S T O P ");
    }
}
