use async_trait::async_trait;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use std::collections::HashMap;
use telio_task::{task_exec, BoxAction, ExecError, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_warn};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Generic error")]
    Generic(#[from] ExecError),
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait BatcherTrait {
    async fn remove(&self, key: String);
    async fn add(
        &self,
        key: String,
        interval: std::time::Duration,
        threshold: std::time::Duration,
    ) -> std::result::Result<tokio::sync::watch::Receiver<()>, Error>;
}

struct State {
    notifiers: HashMap<String, BatchEntry>,
}

pub struct Batcher {
    task: Task<State>,
}

struct BatchEntry {
    deadline: tokio::time::Instant,
    interval: std::time::Duration,
    threshold: std::time::Duration,
    tx: tokio::sync::watch::Sender<()>,
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Batcher";
    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        let mut sleep_futures = {
            let futures: FuturesUnordered<_> = self
                .notifiers
                .iter()
                .map(|(key, entry)| {
                    let deadline = entry.deadline;
                    let key_clone = key.clone();
                    async move {
                        tokio::time::sleep_until(deadline).await;
                        key_clone
                    }
                })
                .collect();

            futures
        };

        tokio::select! {
            update = update => {
                return update(self).await;
            }
            Some(_) = sleep_futures.next() => {
                let now = tokio::time::Instant::now();

                let mut batched_count = 0;
                let mut keys_to_delete = vec![];

                {
                    for (key, &mut ref mut entry) in self.notifiers.iter_mut() {
                        let deadline_with_threshold = entry.deadline - entry.threshold;
                        if now >= deadline_with_threshold {
                            batched_count +=1;
                            entry.deadline = now + entry.interval;

                            if entry.tx.send(()).is_err() {
                                keys_to_delete.push(key.clone());
                            }
                        }
                    }
                }

                // Safety guard. Should never be logged
                if batched_count == 0 {
                    telio_log_warn!("Batcher was awoken by a task however didn't find any tasks to batch. At the very least the task which awakened it should be present.");
                }

                self.notifiers.retain(|key, _| {
                    !keys_to_delete.contains(key)
                });

                Ok(())
            }
            else => {
                return Ok(());
            }
        }
    }
}

#[async_trait]
impl BatcherTrait for Batcher {
    async fn remove(&self, key: String) {
        telio_log_debug!("removing item from batcher with key({:?})", key);
        let _ = task_exec!(&self.task, async move |s| {
            s.notifiers.remove(&key);
            Ok(())
        })
        .await;
    }

    async fn add(
        &self,
        key: String,
        interval: std::time::Duration,
        threshold: std::time::Duration,
    ) -> std::result::Result<tokio::sync::watch::Receiver<()>, Error> {
        telio_log_debug!(
            "adding item to batcher with key({:?}), interval({:?}), threshold({:?})",
            key,
            interval,
            threshold
        );
        task_exec!(&self.task, async move |s| {
            let (tx, rx) = tokio::sync::watch::channel(());
            let entry = BatchEntry {
                deadline: tokio::time::Instant::now(),
                interval,
                threshold,
                tx,
            };

            s.notifiers.insert(key, entry);
            Ok(rx)
        })
        .await
        .map_err(Error::Generic)
    }
}

impl Batcher {
    pub fn start() -> Self {
        let task = Task::start(State {
            notifiers: HashMap::new(),
        });

        Self { task }
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

#[cfg(test)]
mod tests {

    use crate::batcher::{Batcher, BatcherTrait};
    use tokio::time;
    use tokio::time::Instant;
    #[tokio::test]
    async fn batch_no_threshold() {
        let batcher = Batcher::start();

        let mut rx = batcher
            .add(
                "key".to_string(),
                std::time::Duration::from_millis(1000),
                std::time::Duration::from_secs(0),
            )
            .await
            .unwrap();
        let instants = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                rx.changed().await.unwrap();
                let now = Instant::now();
                instants.push(now);
                if instants.len() == 5 {
                    break;
                }
            }
            instants
        })
        .await
        .unwrap();

        let mut total_durations = std::time::Duration::new(0, 0);

        for i in 1..instants.len() {
            let duration = instants[i].duration_since(instants[i - 1]);
            total_durations += duration;
        }

        // first signal must be emitted immediately upon adding it
        assert!(
            (total_durations.as_secs_f64() - 4.0).abs() < 0.01,
            "Signal durations incorrect"
        );

        let _ = batcher.remove("key".to_string());

        let mut rx0 = batcher
            .add(
                "key0".to_string(),
                std::time::Duration::from_millis(1000),
                std::time::Duration::from_millis(0),
            )
            .await
            .unwrap();
        let mut rx1 = batcher
            .add(
                "key1".to_string(),
                std::time::Duration::from_millis(2000),
                std::time::Duration::from_millis(0),
            )
            .await
            .unwrap();

        let instants = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                tokio::select! {
                    _ = rx0.changed() => {
                        instants.push(Instant::now());
                    }
                    _ = rx1.changed() => {
                        instants.push(Instant::now());
                    }
                }

                if instants.len() == 10 {
                    break;
                }
            }
            instants
        })
        .await
        .unwrap();

        let mut total_durations = std::time::Duration::new(0, 0);
        for i in 1..instants.len() {
            let duration = instants[i].duration_since(instants[i - 1]);
            total_durations += duration;
        }

        assert!(
            (total_durations.as_secs_f64() - 6.0).abs() < 0.01,
            "Signals should be batched"
        );
    }

    #[tokio::test]
    async fn batch_with_threshold() {
        let batcher = Batcher::start();

        let mut rx = batcher
            .add(
                "key".to_string(),
                std::time::Duration::from_millis(1000),
                std::time::Duration::from_millis(500),
            )
            .await
            .unwrap();

        let instants = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                rx.changed().await.unwrap();
                let now = Instant::now();
                instants.push(now);
                if instants.len() == 5 {
                    break;
                }
            }
            instants
        })
        .await
        .unwrap();

        let mut total_durations = std::time::Duration::new(0, 0);

        for i in 1..instants.len() {
            let duration = instants[i].duration_since(instants[i - 1]);
            total_durations += duration;
        }

        // threshold doesn't make a differnece in a singular signal
        assert!(
            (total_durations.as_secs_f64() - 4.0).abs() < 0.01,
            "Signal durations incorrect"
        );

        let _ = batcher.remove("key".to_string());

        let mut rx0 = batcher
            .add(
                "key0".to_string(),
                std::time::Duration::from_millis(1000),
                std::time::Duration::from_millis(500),
            )
            .await
            .unwrap();
        let mut rx1 = batcher
            .add(
                "key1".to_string(),
                std::time::Duration::from_millis(2000),
                std::time::Duration::from_millis(1050), // Add some leeway as this is just on the boundary
            )
            .await
            .unwrap();

        let instants = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                tokio::select! {
                    _ = rx0.changed() => {
                        instants.push(Instant::now());
                    }
                    _ = rx1.changed() => {
                        instants.push(Instant::now());
                    }
                }

                if instants.len() == 10 {
                    break;
                }
            }
            instants
        })
        .await
        .unwrap();

        let mut total_durations = std::time::Duration::new(0, 0);
        for i in 1..instants.len() {
            let duration = instants[i].duration_since(instants[i - 1]);
            total_durations += duration;
        }

        assert!(
            (total_durations.as_secs_f64() - 4.0).abs() < 0.01,
            "Signals should be batched"
        );

        let _ = batcher.remove("key0".to_string());
        let _ = batcher.remove("key1".to_string());
    }

    #[tokio::test]
    async fn batch_no_threshold_delayed() {
        let batcher = Batcher::start();

        let mut rx0 = batcher
            .add(
                "key0".to_string(),
                std::time::Duration::from_millis(1000),
                std::time::Duration::from_millis(0),
            )
            .await
            .unwrap();

        let instants0 = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                tokio::select! {
                    _ = rx0.changed() => {
                        instants.push(Instant::now());
                    }
                }

                if instants.len() == 10 {
                    break;
                }
            }
            instants
        });

        time::sleep(time::Duration::from_millis(500)).await;

        let mut rx1 = batcher
            .add(
                "key1".to_string(),
                std::time::Duration::from_millis(1000),
                std::time::Duration::from_millis(0),
            )
            .await
            .unwrap();

        let instants1 = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                tokio::select! {
                    _ = rx1.changed() => {
                        instants.push(Instant::now());
                    }
                }

                if instants.len() == 10 {
                    break;
                }
            }
            instants
        });

        let instants0 = instants0.await.unwrap();
        let instants1 = instants1.await.unwrap();

        {
            let mut total_durations = std::time::Duration::new(0, 0);
            for i in 1..instants0.len() {
                let duration = instants0[i].duration_since(instants0[i - 1]);
                total_durations += duration;
            }
            assert!((total_durations.as_secs_f64() - 9.0).abs() < 0.02);
        }

        {
            let mut total_durations = std::time::Duration::new(0, 0);
            for i in 1..instants1.len() {
                let duration = instants1[i].duration_since(instants1[i - 1]);
                total_durations += duration;
            }
            assert!((total_durations.as_secs_f64() - 9.0).abs() < 0.02);
        }
    }

    #[tokio::test]
    async fn batch_with_threshold_delayed() {
        let batcher = Batcher::start();

        let add = batcher.add(
            "key0".to_string(),
            std::time::Duration::from_millis(1000),
            std::time::Duration::from_millis(500),
        );
        let mut rx0 = add.await.unwrap();

        let instants0 = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                tokio::select! {
                    _ = rx0.changed() => {
                        instants.push(Instant::now());
                    }
                }

                if instants.len() == 11 {
                    break;
                }
            }
            instants
        });

        time::sleep(time::Duration::from_millis(600)).await;

        let mut rx1 = batcher
            .add(
                "key1".to_string(),
                std::time::Duration::from_millis(1000),
                std::time::Duration::from_millis(500),
            )
            .await
            .unwrap();

        let instants1 = tokio::spawn(async move {
            let mut instants = vec![];
            loop {
                tokio::select! {
                    _ = rx1.changed() => {
                        instants.push(Instant::now());
                    }
                }

                if instants.len() == 10 {
                    break;
                }
            }
            instants
        });

        let instants0 = instants0.await.unwrap();
        let instants1 = instants1.await.unwrap();

        let a = instants0.iter().rev().take(3);
        let b = instants1.iter().rev().take(3);

        a.zip(b).for_each(|(x, y)| {
            assert!(
                x.duration_since(*y).as_secs_f64() < 0.01,
                "signals should be aligned"
            );
            assert!(
                y.duration_since(*x).as_secs_f64() < 0.01,
                "signals should be aligned"
            );
        });
    }

    #[tokio::test(start_paused = true)]
    async fn batch_with_time_advancement() {
        let batcher = Batcher::start();

        let mut rx = batcher
            .add(
                "key0".to_string(),
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(0),
            )
            .await
            .unwrap();

        // skip initial beat
        let _ = rx.changed().await;

        time::advance(std::time::Duration::from_secs(60 * 60)).await;

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {
                panic!("Missed batches should immediately resolve");
            }
            _ = rx.changed() => {

            }
        }
    }
}
