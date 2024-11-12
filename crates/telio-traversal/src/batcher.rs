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

use thiserror::Error as ThisError;
use tokio::time::{sleep_until, Duration, Instant};

type Action<V, R = std::result::Result<(), ()>> =
    Arc<dyn for<'a> Fn(&'a mut V) -> BoxFuture<'a, R> + Sync + Send>;

pub struct Batcher<K, V> {
    actions: HashMap<K, (BatchEntry, Action<V>)>,
}

struct BatchEntry {
    deadline: Instant,
    interval: Duration,
    threshold: Duration,
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
    async fn get_actions(
        &mut self,
        last_network_activity: Option<Instant>,
    ) -> Result<Vec<(K, Action<V>)>, BatcherError>;
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

    // When traffic triggered, it should only be valid for a certain amount of time.
    // Based on https://developer.android.com/develop/connectivity/network-ops/network-access-optimization
    // the value is hardcoded and not up for a configuration at this point though it might be
    // useful in the future.
    const TRIGGER_EFFECTIVE_DURATION: Duration = Duration::from_secs(10);

    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    pub fn get_remaining_trigger_duration(latest_network_activity: Instant) -> Option<Duration> {
        if latest_network_activity.elapsed() < Self::TRIGGER_EFFECTIVE_DURATION {
            Some(Self::TRIGGER_EFFECTIVE_DURATION - latest_network_activity.elapsed())
        } else {
            None
        }
    }
}

#[async_trait]
impl<K, V> BatcherTrait<K, V> for Batcher<K, V>
where
    K: Eq + Hash + Send + Sync + Debug + Clone,
    V: Send + Sync,
{
    async fn get_actions(
        &mut self,
        last_network_activity: Option<Instant>,
    ) -> Result<Vec<(K, Action<V>)>, BatcherError> {
        if self.actions.is_empty() {
            return Err(BatcherError::NoActions);
        }

        fn collect_batch_jobs<K: Clone, V>(
            actions: &mut HashMap<K, (BatchEntry, Action<V>)>,
            duration: Option<Duration>,
        ) -> Vec<(K, Action<V>)> {
            let now = Instant::now();

            let mut batched_actions: Vec<(K, Action<V>)> = vec![];

            for (key, action) in actions.iter_mut() {
                let adjusted_deadline =
                    now + action.0.threshold + duration.unwrap_or(Duration::from_secs(0));

                if action.0.deadline <= adjusted_deadline {
                    action.0.deadline = now + action.0.interval;
                    batched_actions.push((key.clone(), action.1.clone()));
                }
            }

            batched_actions
        }

        let early_batch_remaining_duration =
            last_network_activity.and_then(Self::get_remaining_trigger_duration);

        if let Some(closest_deadline) = self
            .actions
            .values()
            .min_by_key(|entry| entry.0.deadline)
            .map(|v| v.0.deadline)
        {
            if let Some(duration) = early_batch_remaining_duration {
                let batched_actions = collect_batch_jobs(&mut self.actions, Some(duration));

                if !batched_actions.is_empty() {
                    return Ok(batched_actions);
                }
            }

            // we failed to early batch any actions, so lets wait until the closest one resolves
            _ = sleep_until(closest_deadline).await;

            let batched_actions = collect_batch_jobs(&mut self.actions, None);

            if batched_actions.is_empty() {
                telio_log_error!("Batcher resolves with empty list of jobs");
                return Err(BatcherError::NoActions);
            }
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
    fn add(&mut self, key: K, interval: Duration, threshold: Duration, action: Action<V>) {
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
            deadline: Instant::now(),
            interval,
            threshold,
        };

        self.actions.insert(key, (entry, action));
    }

    fn get_interval(&self, key: &K) -> Option<Duration> {
        self.actions.get(key).map(|(entry, _)| entry.interval)
    }
}

#[cfg(test)]
mod tests {
    use crate::batcher::{Batcher, BatcherError, BatcherTrait};
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};
    use tokio::time::*;

    struct TestChecker {
        values: Vec<(String, Instant)>,
    }

    #[derive(Copy, Clone)]
    struct FakeNetwork {
        latency: Duration,
    }

    impl FakeNetwork {
        async fn send(
            &self,
            peer_a_activity: Arc<watch::Sender<Instant>>,
            peer_b_activity: Arc<watch::Sender<Instant>>,
        ) {
            // We're concerned about any activity, thus we just send to channel of one peer
            // to simulate the send-trigger and after latency we simulate receival on another
            // channel
            peer_a_activity.send(Instant::now()).unwrap();

            // latency sim
            sleep(self.latency).await;

            // Simulate peer receiving data after some latency
            peer_b_activity.send(Instant::now()).unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_triggered_batching() {
        struct TestHelperStruct {
            trigger_enabled: bool,
            latency: Duration,
            start_emit_traffic_at: Instant,
            stop_emit_traffic_at: Instant,
            emit_packet_every: Duration,
            test_duration: Duration,
            delay_to_add_second_peer: Duration,
        }

        #[derive(Debug)]
        struct TestHelperResult {
            left_peer_avg_interval: f64,
            right_peer_avg_interval: f64,
            left_peer_avg_interval_1st_half: f64,
            left_peer_avg_interval_2nd_half: f64,
            right_peer_avg_interval_1st_half: f64,
            right_peer_avg_interval_2nd_half: f64,

            avg_aligned_interval: f64,
            avg_aligned_interval_1st_half: f64,
            avg_aligned_interval_2nd_half: f64,
        }

        async fn test_helper(params: TestHelperStruct) -> TestHelperResult {
            let (left_send, left_recv) = watch::channel(Instant::now());
            let (right_send, right_recv) = watch::channel(Instant::now());

            let left_send = Arc::new(left_send);
            let right_send = Arc::new(right_send);

            let fake_network = Arc::new(FakeNetwork {
                latency: params.latency,
            });

            let mut batcher_left = Batcher::<String, Arc<Mutex<TestChecker>>>::new();
            let mut batcher_right = Batcher::<String, Arc<Mutex<TestChecker>>>::new();

            let test_checker_left = Arc::new(Mutex::new(TestChecker { values: Vec::new() }));
            let test_checker_right = Arc::new(Mutex::new(TestChecker { values: Vec::new() }));

            // simulate emission of some organic traffic
            {
                let fake_network = fake_network.clone();
                let left_send = left_send.clone();
                let right_send = right_send.clone();
                let start = params.start_emit_traffic_at;
                let deadline = params.stop_emit_traffic_at;

                let emit_packet_every = params.emit_packet_every;

                tokio::spawn(async move {
                    sleep_until(start).await;

                    loop {
                        tokio::select! {
                            _ = sleep_until(deadline) => {
                                break
                            }
                            _ = sleep(emit_packet_every) => {
                            let _ = fake_network
                                .send(left_send.clone(), right_send.clone())
                            .await;

                        }
                        }
                    }
                });
            }

            {
                let fake_network = fake_network.clone();
                let left_send = left_send.clone();
                let right_send = right_send.clone();
                batcher_left.add(
                    "key".to_owned(),
                    Duration::from_secs(100),
                    Duration::from_secs(50),
                    Arc::new(move |s: _| {
                        let fake_net = Arc::clone(&fake_network);
                        let left_send = left_send.clone();
                        let right_send = right_send.clone();
                        Box::pin(async move {
                            {
                                let mut s = s.lock().await;
                                s.values.push(("key".to_owned(), Instant::now()));
                            }

                            let _ = fake_net.send(left_send, right_send).await;
                            Ok(())
                        })
                    }),
                );
            }

            {
                let left_send = left_send.clone();
                let right_send = right_send.clone();
                let fake_network = fake_network.clone();

                batcher_right.add(
                    "key".to_owned(),
                    Duration::from_secs(100),
                    Duration::from_secs(50),
                    Arc::new(move |s: _| {
                        let fake_net = Arc::clone(&fake_network);
                        let left_send = left_send.clone();
                        let right_send = right_send.clone();
                        Box::pin(async move {
                            {
                                let mut s = s.lock().await;
                                s.values.push(("key".to_owned(), Instant::now()));
                            }
                            let _ = fake_net.send(right_send, left_send).await;
                            Ok(())
                        })
                    }),
                );
            }

            fn spawn_batcher_poller(
                trigger: bool,
                mut network_activity_sub: watch::Receiver<Instant>,
                mut batcher: Batcher<String, Arc<Mutex<TestChecker>>>,
                mut checker: Arc<Mutex<TestChecker>>,
            ) {
                tokio::spawn(async move {
                    let mut last_activity = {
                        if trigger {
                            Some(Instant::now())
                        } else {
                            None
                        }
                    };

                    loop {
                        tokio::select! {
                            Ok( _) = network_activity_sub.changed() => {
                                if trigger {
                                    last_activity = Some(*network_activity_sub.borrow_and_update());
                                } else {
                                    last_activity = None;
                            }

                            }
                            Ok(ac) = batcher.get_actions(last_activity) => {
                                for a in ac {
                                    a.1(&mut checker).await.unwrap();
                                }
                            }
                        }
                    }
                });
            }

            // begin the actual test
            spawn_batcher_poller(
                params.trigger_enabled,
                left_recv,
                batcher_left,
                test_checker_left.clone(),
            );

            // add another action after a delay to the peer so they would be misaligned
            sleep(params.delay_to_add_second_peer).await;

            spawn_batcher_poller(
                params.trigger_enabled,
                right_recv,
                batcher_right,
                test_checker_right.clone(),
            );

            sleep(params.test_duration).await;

            let left_values = test_checker_left
                .lock()
                .await
                .values
                .iter()
                .map(|v| v.1.elapsed().as_secs() as i64)
                .collect::<Vec<i64>>();
            let right_values = test_checker_right
                .lock()
                .await
                .values
                .iter()
                .map(|v| v.1.elapsed().as_secs() as i64)
                .collect::<Vec<i64>>();

            // Produces an average diff between data points. It compares points by finding
            // the closest value and compares against it. Produces an average of differences. The closer
            // to 0 the more similar the datasets
            fn average_alignment(left: &[i64], right: &[i64]) -> f64 {
                if left.is_empty() || right.is_empty() {
                    panic!("no data present");
                }

                fn find_closest_value(v: i64, data: &[i64]) -> i64 {
                    data.iter()
                        .min_by_key(|&&ts| (ts - v).abs())
                        .copied()
                        .unwrap_or(v)
                }

                let mut total_diff = 0.0;
                let mut count = 0;

                for &t1 in left {
                    let closest_t2 = find_closest_value(t1, right);
                    total_diff += (t1 - closest_t2).abs() as f64;
                    count += 1;
                }

                total_diff / count as f64
            }

            fn average_difference(numbers: &[i64]) -> f64 {
                if numbers.len() < 2 {
                    panic!("not enough elements");
                }

                let total_diff: i64 = numbers.windows(2).map(|w| w[0] - w[1]).sum();

                let count = (numbers.len() - 1) as f64;
                total_diff as f64 / count
            }

            let (first_half_a, second_half_a) =
                left_values.as_slice().split_at(left_values.len() / 2);
            let (first_half_b, second_half_b) =
                right_values.as_slice().split_at(right_values.len() / 2);

            TestHelperResult {
                left_peer_avg_interval: average_difference(left_values.as_slice()),
                right_peer_avg_interval: average_difference(right_values.as_slice()),

                left_peer_avg_interval_1st_half: average_difference(first_half_a),
                left_peer_avg_interval_2nd_half: average_difference(second_half_a),

                right_peer_avg_interval_1st_half: average_difference(first_half_b),
                right_peer_avg_interval_2nd_half: average_difference(second_half_b),

                avg_aligned_interval: average_alignment(
                    left_values.as_slice(),
                    right_values.as_slice(),
                ),
                avg_aligned_interval_1st_half: average_alignment(first_half_a, first_half_b),
                avg_aligned_interval_2nd_half: average_alignment(second_half_a, second_half_b),
            }
        }

        // actual tests
        {
            // due to traffic being triggered every second for the duration of the testacase, we do
            // not expect any batching to happen and periods to be effectively shortened by
            // half due to threshold
            let res = test_helper(TestHelperStruct {
                trigger_enabled: true,
                latency: Duration::from_millis(333),
                start_emit_traffic_at: Instant::now(),
                stop_emit_traffic_at: Instant::now() + Duration::from_secs(3600),
                emit_packet_every: Duration::from_secs(1),
                delay_to_add_second_peer: Duration::from_secs(17),
                test_duration: Duration::from_secs(3600),
            })
            .await;

            assert!((16.0..17.0).contains(&res.avg_aligned_interval)); // delay until second peer is added
            assert!((41.0..42.0).contains(&res.left_peer_avg_interval));
            assert!((41.0..42.0).contains(&res.right_peer_avg_interval));
        }

        {
            // organic traffic starts and stops in the middle of the test and lasts for a bit. This
            // should have minimal effect on batching since it should already have the actions
            // batched
            let res = test_helper(TestHelperStruct {
                trigger_enabled: true,
                latency: Duration::from_millis(333),
                start_emit_traffic_at: Instant::now() + Duration::from_secs(1800),
                stop_emit_traffic_at: Instant::now() + Duration::from_secs(1800),
                emit_packet_every: Duration::from_secs(1),
                delay_to_add_second_peer: Duration::from_secs(17),
                test_duration: Duration::from_secs(3600),
            })
            .await;

            assert!((1.0..2.0).contains(&res.avg_aligned_interval));
            assert!((99.0..=100.0).contains(&res.left_peer_avg_interval));
            assert!((99.0..=100.0).contains(&res.right_peer_avg_interval));
        }

        {
            // organic traffic starts at the beginning until almost half the testcase duration. First half should
            // have no batching since it's constant triggering and batcher simply tries to batch
            // jobs within threshold and emit. However in the second half of it, once the organic
            // traffic stops, batcher's triggering mechanism should make the alignment between the peers
            let res = test_helper(TestHelperStruct {
                trigger_enabled: true,
                latency: Duration::from_millis(333),
                start_emit_traffic_at: Instant::now(),
                stop_emit_traffic_at: Instant::now() + Duration::from_secs(1400),
                emit_packet_every: Duration::from_secs(1),
                delay_to_add_second_peer: Duration::from_secs(17),
                test_duration: Duration::from_secs(3600),
            })
            .await;

            assert!((41.0..42.0).contains(&res.left_peer_avg_interval_1st_half));
            assert!((41.0..42.0).contains(&res.right_peer_avg_interval_1st_half));
            assert!((89.0..90.0).contains(&res.left_peer_avg_interval_2nd_half));
            assert!((88.0..89.0).contains(&res.right_peer_avg_interval_2nd_half));

            assert!((16.0..17.0).contains(&res.avg_aligned_interval_1st_half));
            assert!((3.0..4.0).contains(&res.avg_aligned_interval_2nd_half));
        }
    }

    #[tokio::test]
    async fn no_actions() {
        let mut batcher = Batcher::<String, TestChecker>::new();
        assert!(matches!(
            batcher.get_actions(None).await,
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

        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        // simulate some delay before adding a second task so they would be misaligned
        advance(Duration::from_secs(20)).await;

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
            for ac in batcher.get_actions(None).await.unwrap() {
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
        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(test_checker.values.len() == 1);

        // pick up the second event
        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(test_checker.values.len() == 2);

        assert!(test_checker.values[0].1.duration_since(start_time) == Duration::from_secs(0));
        assert!(test_checker.values[1].1.duration_since(start_time) == Duration::from_secs(100));

        // after a pause of retrieving actions there will be a delay in signals as well as they are not active on their own
        tokio::time::advance(Duration::from_secs(550)).await;
        assert!(test_checker.values.len() == 2);

        for ac in batcher.get_actions(None).await.unwrap() {
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
        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(test_checker.values.len() == 2);

        // Do again and batching should be in action since the threshold of the second signal is bigger(50) than the delay between the packets(30)
        for ac in batcher.get_actions(None).await.unwrap() {
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
        for ac in batcher.get_actions(None).await.unwrap() {
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
            for ac in batcher.get_actions(None).await.unwrap() {
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
        for ac in batcher.get_actions(None).await.unwrap() {
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
            for ac in batcher.get_actions(None).await.unwrap() {
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
        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(
            test_checker.values.len() == 2,
            "Both actions should be emitted immediately"
        );

        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(test_checker.values.len() == 4, "Even though there was no threshold and actions were added at different times, we query only after adding the second one which resets both deadlines and aligns them");
    }

    #[tokio::test(start_paused = true)]
    async fn batch_two_no_threshold_nodelay_check() {
        let start_time = Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new();
        batcher.add(
            "key0".to_owned(),
            Duration::from_secs(100),
            Duration::from_secs(0),
            Arc::new(|s: _| {
                Box::pin(async move {
                    s.values.push(("key0".to_owned(), Instant::now()));
                    Ok(())
                })
            }),
        );

        let mut test_checker = TestChecker { values: Vec::new() };
        // pick up the immediate fire
        for ac in batcher.get_actions(None).await.unwrap() {
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
                    s.values.push(("key1".to_owned(), Instant::now()));
                    Ok(())
                })
            }),
        );

        // pick up the immediate fire from the second action
        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }
        assert!(test_checker.values.len() == 2);

        for ac in batcher.get_actions(None).await.unwrap() {
            ac.1(&mut test_checker).await.unwrap();
        }

        assert!(
            test_checker.values.len() == 3,
            "No threshold but a delay was given, thus one signal should have resolved"
        );

        test_checker.values = vec![];
        for _ in 0..12 {
            for ac in batcher.get_actions(None).await.unwrap() {
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
        tokio::time::advance(Duration::from_secs(500)).await;

        for _i in 0..11 {
            for ac in batcher.get_actions(None).await.unwrap() {
                ac.1(&mut test_checker).await.unwrap();
            }
        }

        let key0sum: Duration = test_checker
            .values
            .iter()
            .filter(|e| e.0 == "key0")
            .map(|e| e.1.duration_since(start_time))
            .collect::<Vec<Duration>>()
            .windows(2)
            .map(|w| w[1] - w[0])
            .sum();

        let key1sum: Duration = test_checker
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
