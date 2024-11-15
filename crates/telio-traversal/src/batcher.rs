// Batcher is an optimizer of aligning actions to be done in batches
// with the goal to conserve resources, thus Batcher's main goals are:
// 1) Don't break existing functionality done by usual means
// 2) Align actions

use futures::future::BoxFuture;
use std::fmt::Debug;
use std::hash::Hash;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};
use tokio::time::{sleep_until, Duration};

use thiserror::Error as ThisError;

type Action<V, R = std::result::Result<(), ()>> =
    Arc<dyn for<'a> Fn(&'a mut V) -> BoxFuture<'a, R> + Sync + Send>;

pub struct Batcher<K, V> {
    actions: HashMap<K, (BatchEntry, Action<V>)>,
}

struct BatchEntry {
    deadline: tokio::time::Instant,
    interval: std::time::Duration,
    threshold: std::time::Duration,
}

/// Possible [Batcher] errors.
#[derive(ThisError, Debug)]
pub enum BatcherError {
    /// No actions in batcher
    #[error("No actions present")]
    NoActions,
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
#[async_trait]
pub trait BatcherTrait<K, V>: Send + Sync
where
    K: Eq + Hash + Debug + Clone + Send + Sync,
    V: Send + Sync,
{
    fn add(&mut self, key: K, interval: Duration, threshold: Duration, action: Action<V>);
    fn remove(&mut self, key: &K);
    async fn get_actions(&mut self) -> Result<Vec<(K, Action<V>)>, BatcherError>;
    fn get_interval(&self, key: &K) -> Option<Duration>;
}

impl<K, V> Default for Batcher<K, V>
where
    K: Eq + Hash + Send + Sync + Debug + Clone,
    V: Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Batcher<K, V>
where
    K: Eq + Hash + Send + Sync + Debug + Clone,
    V: Send + Sync,
{
    // It's necessary not to allow too short intervals since they can drain resources.
    // Historically, libtelio had highest frequency action of 5seconds for direct
    // connection keepalive, thus we cap any action to have at least that.
    const MIN_INTERVAL: Duration = Duration::from_secs(5);
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }
}

#[async_trait]
impl<K, V> BatcherTrait<K, V> for Batcher<K, V>
where
    K: Eq + Hash + Send + Sync + Debug + Clone,
    V: Send + Sync,
{
    /// Batching works by sleeping until the nearest future and then trying to batch more actions
    /// based on the threshold value. Higher delay before calling the function will increase the chances of batching
    /// because the deadlines will _probably_ be in the past already.
    /// Adding a new action wakes up the batcher due to immediate trigger of the action.
    async fn get_actions(&mut self) -> Result<Vec<(K, Action<V>)>, BatcherError> {
        if self.actions.is_empty() {
            return Err(BatcherError::NoActions);
        }

        let mut batched_actions: Vec<(K, Action<V>)> = vec![];
        let actions = &mut self.actions;

        if let Some(closest_entry) = actions.values().min_by_key(|entry| entry.0.deadline) {
            _ = sleep_until(closest_entry.0.deadline).await;

            let now = tokio::time::Instant::now();
            // at this point in time we know we're at the earliest spot for batching, thus we can check if we have more actions to add
            for (key, action) in actions.iter_mut() {
                let adjusted_action_deadline = now + action.0.threshold;

                if action.0.deadline <= adjusted_action_deadline {
                    action.0.deadline = now + action.0.interval;
                    batched_actions.push((key.clone(), action.1.clone()));
                }
            }

            if batched_actions.is_empty() {
                telio_log_error!("Batched jobs incorrectly. At least one job should be emitted.");
                return Err(BatcherError::NoActions);
            }
            // There should be at least one action here always - the one that triggered everything
            return Ok(batched_actions);
        } else {
            return Err(BatcherError::NoActions);
        }
    }

    /// Remove batcher action. Action is no longer eligible for batching
    fn remove(&mut self, key: &K) {
        telio_log_debug!("removing item from batcher with key({:?})", key);
        self.actions.remove(key);
    }

    /// Add batcher action. Batcher itself doesn't run the tasks and depends
    /// on actions being polled and invoked. It is a passive component on itself.
    /// Adding an action has immediate deadline thus action is invoked as soon
    /// as it's polled.
    ///
    /// Higher threshold means more opportunities to batch the action, however too high
    /// means wasting resources since the job will be batched alongside other jobs more
    /// frequently than necessary. For example an infrequent job with high
    /// threshold will batch together with higher frequency job(shorter interval) with no added
    /// value.
    ///
    /// A threshold of 0 makes batcher act effectively as `RepeatedActions` and will have
    /// no opportunities to be batched. A small threshold will limit batching opportunities.
    ///
    /// Proving that the threshold of half the period is enough between two actions with same interval
    /// when being added at different times can be done visually. In the scenario below
    /// we have two actions A and B that have same interval and threshold:
    ///
    /// Legends:
    ///   - `d` - next deadline
    ///   - `D` - current deadline
    ///   - `-` - time tick
    ///   - `*` - jobs threshold
    ///   - '_' - indicates that action is not yet added
    ///
    /// ```text
    /// Step #1
    /// A: D------******d------******d------******d------******d-----> time
    /// B: __d------******d------******d------******d------******d---> time
    /// ```
    /// at the beginning, job A was added and thus is immediately emitted. B doesn't yet exist
    /// as it's added a bit later. Once B is added, it's deadline is immediate and it's next
    /// deadline is shifted after one interval. Once B is added it cannot batch A since it's
    /// not within the threshold.
    ///
    /// however a nice thing happens on the next A deadline:
    ///
    /// ```text
    /// Step #2
    /// A: d------******D------******d------******d------******d-----> time
    /// B: __d------******d------******d------******d------******d---> time
    /// ```
    ///
    /// At this point A will batch action B as well, since it's `deadline-threshold` is within the reach
    /// and the timelines suddenly align afterwards:
    ///
    /// ```text
    /// Step #3
    /// A: d------******d------******d------******d------******d-----> time
    /// B: __d------****d------******d------******d------******d-----> time
    /// ```
    ///
    /// From now on A and B will always emit together(order is not guaranteed nor maintained).
    ///
    /// This is however a simplified approach and is not as easy to prove exactly what happens
    /// when:
    /// - jobs have same interval but different threshold
    /// - jobs have different intervals.
    /// - jobs have different intervals and different thresholds
    ///
    /// Thus it's best to aim for:
    /// - as high interval as possible
    /// - threshold being close to half the interval
    fn add(
        &mut self,
        key: K,
        interval: std::time::Duration,
        threshold: std::time::Duration,
        action: Action<V>,
    ) {
        telio_log_debug!(
            "adding item to batcher with key({:?}), interval({:?}), threshold({:?})",
            key,
            interval,
            threshold,
        );

        let interval = {
            if interval < Self::MIN_INTERVAL {
                telio_log_warn!(
                    "Interval of {:?} is too short, overriding to {:?}",
                    interval,
                    Self::MIN_INTERVAL
                );
                Self::MIN_INTERVAL
            } else {
                interval
            }
        };

        let max_threshold = interval / 2;

        let threshold = {
            if threshold > max_threshold {
                telio_log_warn!(
                    "Threshold of {:?} is higher than maximum allowed threshold calculated: {:?}, overriding",
                    threshold,
                    max_threshold
                );
                max_threshold
            } else {
                threshold
            }
        };

        let entry = BatchEntry {
            deadline: tokio::time::Instant::now(),
            interval,
            threshold,
        };

        self.actions.insert(key, (entry, action));
    }

    fn get_interval(&self, key: &K) -> Option<Duration> {
        self.actions.get(key).map(|(entry, _)| entry.interval)
    }
}

/// Tests provide near-perfect immediate sleeps due to how tokio runtime acts when it's paused(basically sleeps are resolved immediately)
#[cfg(test)]
mod tests {

    pub struct TestChecker {
        values: Vec<(String, tokio::time::Instant)>,
    }

    use std::{sync::Arc, time::Duration};

    use crate::batcher::{Batcher, BatcherError, BatcherTrait};

    #[tokio::test]
    async fn no_actions() {
        let mut batcher = Batcher::<String, TestChecker>::new();
        assert!(matches!(
            batcher.get_actions().await,
            Err(BatcherError::NoActions)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn no_threshold_expect_no_batching() {
        let start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        let mut test_checker = TestChecker { values: Vec::new() };

        batcher.add(
            "key0".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key0".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        // simulate some delay before adding a second task so they would be misaligned
        tokio::time::advance(Duration::from_secs(20)).await;

        batcher.add(
            "key1".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key1".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        // Await for few actions to resolve
        for _ in 0..6 {
            for ac in batcher.get_actions().await.unwrap() {
                ac.1(&mut test_checker).await.unwrap();
            }
        }

        // expect no batched behaviour since the thresholds were zero
        assert!(test_checker.values[0].1.duration_since(start_time) == Duration::from_secs(0));
        assert!(test_checker.values[1].1.duration_since(start_time) == Duration::from_secs(20));
        assert!(test_checker.values[2].1.duration_since(start_time) == Duration::from_secs(100));
        assert!(test_checker.values[3].1.duration_since(start_time) == Duration::from_secs(120));
        assert!(test_checker.values[4].1.duration_since(start_time) == Duration::from_secs(200));
        assert!(test_checker.values[5].1.duration_since(start_time) == Duration::from_secs(220));
        assert!(test_checker.values[6].1.duration_since(start_time) == Duration::from_secs(300));
    }

    #[tokio::test(start_paused = true)]
    async fn batch_one_no_threshold_expect_no_batch() {
        let start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        batcher.add(
            "key".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        let mut test_checker = TestChecker { values: Vec::new() };

        // pick up the immediate fire
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(test_checker.values.len() == 1);

        // pick up the second event
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(test_checker.values.len() == 2);

        assert!(test_checker.values[0].1.duration_since(start_time) == Duration::from_secs(0));
        assert!(test_checker.values[1].1.duration_since(start_time) == Duration::from_secs(100));

        // after a pause of retrieving actions there will be a delay in signals as well as they are not active on their own
        tokio::time::advance(Duration::from_secs(550)).await;
        assert!(test_checker.values.len() == 2);

        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(test_checker.values.len() == 3);
        assert!(test_checker.values[2].1.duration_since(start_time) == Duration::from_secs(650));
    }

    #[tokio::test(start_paused = true)]
    async fn batch_two_with_threshold_and_delay() {
        let start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        batcher.add(
            "key0".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(50),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key0".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        tokio::time::advance(Duration::from_secs(30)).await;

        batcher.add(
            "key1".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(50),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key1".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        // At this point there are two actions added, one at t(0) and another at t(30).
        let mut test_checker = TestChecker { values: Vec::new() };

        // pick up the immediate fires
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(test_checker.values.len() == 2);

        // Do again and batching should be in action since the threshold of the second signal is bigger(50) than the delay between the packets(30)
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(test_checker.values.len() == 4);

        let key0_entries: Vec<tokio::time::Duration> = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key0")
            .map(|e| e.1.duration_since(start_time))
            .collect();
        let key1_entries: Vec<tokio::time::Duration> = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key1")
            .map(|e| e.1.duration_since(start_time))
            .collect();

        // Immediate fires were supressed because we need to poll them and we did so only after 30seconds
        // Thus everything will be aligned at 30seconds

        assert!(key0_entries[0] == Duration::from_secs(30));
        assert!(key1_entries[0] == Duration::from_secs(30));

        assert!(key0_entries[1] == Duration::from_secs(130));
        assert!(key1_entries[1] == Duration::from_secs(130));
    }

    #[tokio::test(start_paused = true)]
    async fn batch_two_with_threshold_check_threshold_limit_enforcement() {
        let start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        batcher.add(
            "key0".to_owned(),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key0".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        let mut test_checker = TestChecker { values: Vec::new() };

        // pick up the immediate fire
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        tokio::time::advance(Duration::from_secs(5)).await;

        batcher.add(
            "key1".to_owned(),
            Duration::from_secs(5),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key1".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        for _ in 0..8 {
            for ac in batcher.get_actions().await.unwrap() {
                ac.1(&mut test_checker).await.unwrap();
            }
        }

        let key0_entries: Vec<tokio::time::Duration> = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key0")
            .map(|e| e.1.duration_since(start_time))
            .collect();
        let key1_entries: Vec<tokio::time::Duration> = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key1")
            .map(|e| e.1.duration_since(start_time))
            .collect();

        // At this point we expect the first job to be batched alongside the
        // second, very frequent job at half the interval(capped)
        assert!(key0_entries[0] == Duration::from_secs(0));
        assert!(key0_entries[1] == Duration::from_secs(15));
        assert!(key0_entries[2] == Duration::from_secs(30));

        assert!(key1_entries[0] == Duration::from_secs(5));
        assert!(key1_entries[1] == Duration::from_secs(10));
        assert!(key1_entries[2] == Duration::from_secs(15));
        assert!(key1_entries[3] == Duration::from_secs(20));
    }

    #[tokio::test(start_paused = true)]
    async fn batch_two_with_threshold_check_interval_limit_enforcement() {
        let start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        batcher.add(
            "key0".to_owned(),
            // Make interval and threshold too small and expect override
            Duration::from_secs(1),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key0".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        let mut test_checker = TestChecker { values: Vec::new() };

        // pick up the immediate fire
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        tokio::time::advance(Duration::from_secs(1)).await;

        batcher.add(
            "key1".to_owned(),
            // Make interval too small and expect override
            Duration::from_secs(2),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key1".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        for _ in 0..8 {
            for ac in batcher.get_actions().await.unwrap() {
                ac.1(&mut test_checker).await.unwrap();
            }
        }

        let key0_entries: Vec<tokio::time::Duration> = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key0")
            .map(|e| e.1.duration_since(start_time))
            .collect();
        let key1_entries: Vec<tokio::time::Duration> = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key1")
            .map(|e| e.1.duration_since(start_time))
            .collect();

        // Expect forcing minimal interval of 5seconds
        assert!(key0_entries[0] == Duration::from_secs(0));
        assert!(key0_entries[1] == Duration::from_secs(5));
        assert!(key0_entries[2] == Duration::from_secs(10));
        assert!(key0_entries[3] == Duration::from_secs(15));

        assert!(key1_entries[0] == Duration::from_secs(1));
        assert!(key1_entries[1] == Duration::from_secs(6));
        assert!(key1_entries[2] == Duration::from_secs(11));
        assert!(key1_entries[3] == Duration::from_secs(16));
    }

    #[tokio::test(start_paused = true)]
    async fn batch_two_no_threshold_delayed_check() {
        let _start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        batcher.add(
            "key0".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key0".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        tokio::time::advance(Duration::from_secs(30)).await;

        batcher.add(
            "key1".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key1".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        // At this point there are two actions added, one at t(0) and another at t(30).
        let mut test_checker = TestChecker { values: Vec::new() };

        // pick up the immediate fire
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(
            test_checker.values.len() == 2,
            "Both actions should be emitted immediately"
        );

        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(test_checker.values.len() == 4, "Even though there was no threshold and actions were added at different times, we query only after adding the second one which resets both deadlines and aligns them");
    }

    #[tokio::test(start_paused = true)]
    async fn batch_two_no_threshold_nodelay_check() {
        let start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        batcher.add(
            "key0".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key0".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        let mut test_checker = TestChecker { values: Vec::new() };
        // pick up the immediate fire
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(test_checker.values.len() == 1);

        tokio::time::advance(Duration::from_secs(30)).await;

        batcher.add(
            "key1".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values
                        .push(("key1".to_owned(), tokio::time::Instant::now()));
                    Ok(())
                })
            }),
        );

        // pick up the immediate fire from the second action
        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(test_checker.values.len() == 2);

        for ac in batcher.get_actions().await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(
            test_checker.values.len() == 3,
            "No threshold but a delay was given, thus one signal should have resolved"
        );

        test_checker.values = vec![];
        for _ in 0..12 {
            for ac in batcher.get_actions().await.unwrap() {
                ac.1(&mut test_checker).await.unwrap();
            }
        }

        let key0sum: tokio::time::Duration = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key0")
            .map(|e| e.1.duration_since(start_time))
            .collect::<Vec<Duration>>()
            .windows(2)
            .map(|w| w[1] - w[0])
            .sum();

        let key1sum: tokio::time::Duration = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key1")
            .map(|e| e.1.duration_since(start_time))
            .collect::<Vec<Duration>>()
            .windows(2)
            .map(|w| w[1] - w[0])
            .sum();

        // Because of misalignment, each call produces only one action instead of both
        assert!(key0sum == Duration::from_secs(500));
        assert!(key1sum == Duration::from_secs(500));

        // Now let's wait a bit so upon iterating again signals would be aligned
        test_checker.values = vec![];
        tokio::time::advance(tokio::time::Duration::from_secs(500)).await;
        for _i in 0..11 {
            for ac in batcher.get_actions().await.unwrap() {
                ac.1(&mut test_checker).await.unwrap();
            }
        }

        let key0sum: tokio::time::Duration = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key0")
            .map(|e| e.1.duration_since(start_time))
            .collect::<Vec<Duration>>()
            .windows(2)
            .map(|w| w[1] - w[0])
            .sum();

        let key1sum: tokio::time::Duration = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key1")
            .map(|e| e.1.duration_since(start_time))
            .collect::<Vec<Duration>>()
            .windows(2)
            .map(|w| w[1] - w[0])
            .sum();

        assert!(key0sum == Duration::from_secs(1000));
        assert!(key1sum == Duration::from_secs(1000));
    }
}
