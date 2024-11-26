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
    last_trigger_checkpoint: Instant,
    options: BatchingOptions,
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

#[derive(Copy, Clone, Debug)]
pub struct BatchingOptions {
    pub trigger_effective_duration: Duration,
    pub trigger_cooldown_duration: Duration,
}

impl Default for BatchingOptions {
    fn default() -> Self {
        Self {
            trigger_effective_duration: Duration::from_secs(10),
            trigger_cooldown_duration: Duration::from_secs(60),
        }
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

    pub fn new(options: BatchingOptions) -> Self {
        telio_log_debug!("Options for batcher: {:?}", options);

        Self {
            actions: HashMap::new(),
            options,
            last_trigger_checkpoint: Instant::now(),
        }
    }

    pub fn is_trigger_outstanding(&self, latest_network_activity: Instant) -> bool {
        if self.last_trigger_checkpoint.elapsed() <= self.options.trigger_cooldown_duration {
            telio_log_debug!(
                "Batcher trigger in cooldown: {}",
                self.last_trigger_checkpoint.elapsed().as_secs()
            );
            return false;
        }

        latest_network_activity.elapsed() < self.options.trigger_effective_duration
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
        ) -> Vec<(K, Action<V>)> {
            let now = Instant::now();

            let mut batched_actions: Vec<(K, Action<V>)> = vec![];

            for (key, action) in actions.iter_mut() {
                let adjusted_deadline = now + action.0.threshold;

                if action.0.deadline <= adjusted_deadline {
                    action.0.deadline = now + action.0.interval;
                    batched_actions.push((key.clone(), action.1.clone()));
                }
            }

            batched_actions
        }

        if let Some(closest_deadline) = self
            .actions
            .values()
            .min_by_key(|entry| entry.0.deadline)
            .map(|v| v.0.deadline)
        {
            let early_batch = last_network_activity.map(|na| self.is_trigger_outstanding(na));

            if let Some(true) = early_batch {
                let batched_actions = collect_batch_jobs(&mut self.actions);

                if !batched_actions.is_empty() {
                    // TODO(LLT-5807): if there's an eligible trigger, maybe it's worth just
                    // emitting all the actions there are. Given a big enough cooldown it should
                    // pose no harm at the cost of near perfect alignment in one go. This should be
                    // experimented with.
                    self.last_trigger_checkpoint = Instant::now();
                    return Ok(batched_actions);
                }
            }

            // we failed to early batch any actions, so lets wait until the closest one resolves
            _ = sleep_until(closest_deadline).await;

            let batched_actions = collect_batch_jobs(&mut self.actions);

            if batched_actions.is_empty() {
                telio_log_error!("Batcher resolves with empty list of jobs");
                return Err(BatcherError::NoActions);
            }
            self.last_trigger_checkpoint = Instant::now();
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
    use crate::batcher::{Batcher, BatcherError, BatcherTrait, BatchingOptions};
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
            left_batching_options: BatchingOptions,
            right_batching_options: BatchingOptions,
        }

        #[derive(Debug)]
        struct TestHelperResult {
            left_peer_avg_interval: Duration,
            right_peer_avg_interval: Duration,
            avg_aligned_interval: Duration,
        }

        // testing is split into two parts and results are stored separately. This allows for
        // flexibility when asserting results more accurately and expectedly
        async fn test_helper(params: TestHelperStruct) -> (TestHelperResult, TestHelperResult) {
            let (left_send, left_recv) = watch::channel(Instant::now());
            let (right_send, right_recv) = watch::channel(Instant::now());

            let left_send = Arc::new(left_send);
            let right_send = Arc::new(right_send);

            let fake_network = Arc::new(FakeNetwork {
                latency: params.latency,
            });

            let mut batcher_left =
                Batcher::<String, Arc<Mutex<TestChecker>>>::new(params.left_batching_options);
            let mut batcher_right =
                Batcher::<String, Arc<Mutex<TestChecker>>>::new(params.right_batching_options);

            let test_checker_left = Arc::new(Mutex::new(TestChecker { values: Vec::new() }));
            let test_checker_right = Arc::new(Mutex::new(TestChecker { values: Vec::new() }));

            let first_half_left_values = Arc::new(Mutex::new(vec![]));
            let first_half_right_values = Arc::new(Mutex::new(vec![]));

            // at half the testcase, save the values and erase existing ones to remove the bias
            // when calculating test metrics
            //
            {
                let test_duration = params.test_duration.clone();
                let test_checker_left = test_checker_left.clone();
                let test_checker_right = test_checker_right.clone();
                let first_half_left_values = first_half_left_values.clone();
                let first_half_right_values = first_half_right_values.clone();

                tokio::spawn(async move {
                    sleep(test_duration / 2).await;

                    let mut left = test_checker_left.lock().await;
                    let mut right = test_checker_right.lock().await;

                    let mut l = first_half_left_values.lock().await;
                    let mut r = first_half_right_values.lock().await;

                    *l = (*left.values).to_vec();
                    *r = (*right.values).to_vec();

                    left.values.clear();
                    right.values.clear()
                });
            }

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

            let first_half_left_values = first_half_left_values
                .lock()
                .await
                .iter()
                .map(|v| v.1.elapsed())
                .collect::<Vec<_>>();
            let first_half_right_values = first_half_right_values
                .lock()
                .await
                .iter()
                .map(|v| v.1.elapsed())
                .collect::<Vec<_>>();

            let second_half_left_values = test_checker_left
                .lock()
                .await
                .values
                .iter()
                .map(|v| v.1.elapsed())
                .collect::<Vec<_>>();
            let second_half_right_values = test_checker_right
                .lock()
                .await
                .values
                .iter()
                .map(|v| v.1.elapsed())
                .collect::<Vec<_>>();

            fn average_alignment(left: &[Duration], right: &[Duration]) -> Duration {
                if left.is_empty() || right.is_empty() {
                    panic!("no data present");
                }

                fn find_closest_value(v: Duration, data: &[Duration]) -> Duration {
                    data.iter()
                        .min_by_key(|&&ts| (ts.as_millis().abs_diff(v.as_millis())))
                        .copied()
                        .unwrap_or(v)
                }

                let mut total_diff = 0;
                let mut count = 0;

                for &t1 in left {
                    let closest_t2 = find_closest_value(t1, right);
                    total_diff += t1.as_millis().abs_diff(closest_t2.as_millis());
                    count += 1;
                }

                Duration::from_millis((total_diff / count) as u64)
            }

            fn average_difference(numbers: &[Duration]) -> Duration {
                if numbers.len() < 2 {
                    panic!("not enough elements");
                }

                let total_diff: u128 = numbers
                    .windows(2)
                    .map(|w| (w[0].as_millis().abs_diff(w[1].as_millis() as u128)))
                    .sum();

                let count = numbers.len() - 1;
                Duration::from_millis((total_diff / count as u128) as u64)
            }

            let res_first_half = TestHelperResult {
                left_peer_avg_interval: average_difference(first_half_left_values.as_slice()),
                right_peer_avg_interval: average_difference(first_half_right_values.as_slice()),

                avg_aligned_interval: average_alignment(
                    first_half_left_values.as_slice(),
                    first_half_right_values.as_slice(),
                ),
            };

            let res_second_half = TestHelperResult {
                left_peer_avg_interval: average_difference(second_half_left_values.as_slice()),
                right_peer_avg_interval: average_difference(second_half_right_values.as_slice()),

                avg_aligned_interval: average_alignment(
                    second_half_left_values.as_slice(),
                    second_half_right_values.as_slice(),
                ),
            };

            return (res_first_half, res_second_half);
        }

        fn durations_close_enough(d1: Duration, d2: Duration, tolerance: Duration) -> bool {
            let diff = if d1 > d2 { d1 - d2 } else { d2 - d1 };
            diff <= tolerance
        }

        fn within_1s(d1: Duration, d2: Duration) -> bool {
            durations_close_enough(d1, d2, Duration::from_secs(1))
        }

        fn within_1ms(d1: Duration, d2: Duration) -> bool {
            durations_close_enough(d1, d2, Duration::from_millis(1))
        }

        // actual testcases
        {
            // due to traffic being triggered every second for the duration of the testcase, we do
            // not expect effective batching to happen. This is because trigger doesn't differentiate the
            // traffic and thus constant activity just means attempts to batch all the time which
            // just means that intervals will be shortened to `T - threshold` but no alignment
            // between peers happens. The trigger cooldown is also high enough that it doesn't
            // interfere with average interval
            let (res_first_half, res_second_half) = test_helper(TestHelperStruct {
                trigger_enabled: true,
                latency: Duration::from_millis(333),
                start_emit_traffic_at: Instant::now(),
                stop_emit_traffic_at: Instant::now() + Duration::from_secs(3600),
                emit_packet_every: Duration::from_secs(1),
                delay_to_add_second_peer: Duration::from_secs(17),
                test_duration: Duration::from_secs(3600),
                left_batching_options: BatchingOptions {
                    trigger_cooldown_duration: Duration::from_secs(600),
                    trigger_effective_duration: Duration::from_secs(10),
                },
                right_batching_options: BatchingOptions {
                    trigger_cooldown_duration: Duration::from_secs(600),
                    trigger_effective_duration: Duration::from_secs(10),
                },
            })
            .await;

            assert!(within_1s(
                res_first_half.left_peer_avg_interval,
                Duration::from_secs(100)
            ));
            assert!(within_1s(
                res_first_half.right_peer_avg_interval,
                Duration::from_secs(100)
            ));

            assert!(within_1s(
                res_second_half.left_peer_avg_interval,
                Duration::from_secs(100)
            ));
            assert!(within_1s(
                res_second_half.right_peer_avg_interval,
                Duration::from_secs(100)
            ));

            // 17seconds in the test we add a secod peer and expect this amount of misalignment
            // between the peers
            assert!(within_1s(
                res_first_half.avg_aligned_interval,
                Duration::from_secs(17)
            ));
            assert!(within_1s(
                res_second_half.avg_aligned_interval,
                Duration::from_secs(20)
            ));
        }

        {
            // due to traffic being triggered every second for the duration of the testcase, we do
            // not expect effective batching to happen. This is because trigger doesn't differentiate the
            // traffic and thus constant activity just means attempts to batch all the time which
            // just means that intervals will be shortened to `T - threshold` but no alignment
            // between peers happens. The trigger cooldown is short enough to showcase that it just
            // reduces the action intervals but doesn't achieve alignment
            let (res_first_half, res_second_half) = test_helper(TestHelperStruct {
                trigger_enabled: true,
                latency: Duration::from_millis(333),
                start_emit_traffic_at: Instant::now(),
                stop_emit_traffic_at: Instant::now() + Duration::from_secs(3600),
                emit_packet_every: Duration::from_secs(1),
                delay_to_add_second_peer: Duration::from_secs(17),
                test_duration: Duration::from_secs(3600),
                left_batching_options: BatchingOptions {
                    trigger_cooldown_duration: Duration::from_secs(30),
                    trigger_effective_duration: Duration::from_secs(10),
                },
                right_batching_options: BatchingOptions {
                    trigger_cooldown_duration: Duration::from_secs(30),
                    trigger_effective_duration: Duration::from_secs(10),
                },
            })
            .await;

            assert!(within_1s(
                res_first_half.left_peer_avg_interval,
                Duration::from_secs(50)
            ));
            assert!(within_1s(
                res_first_half.right_peer_avg_interval,
                Duration::from_secs(50)
            ));

            assert!(within_1s(
                res_second_half.left_peer_avg_interval,
                Duration::from_secs(50)
            ));
            assert!(within_1s(
                res_second_half.right_peer_avg_interval,
                Duration::from_secs(50)
            ));

            // 17seconds in the test we add a secod peer and expect this amount of misalignment
            // between the peers
            assert!(within_1s(
                res_first_half.avg_aligned_interval,
                Duration::from_secs(17)
            ));
            assert!(within_1s(
                res_second_half.avg_aligned_interval,
                Duration::from_secs(18)
            ));
        }

        {
            // Start emitting traffic in the middle of the testcase. It should have no effect since
            // batcher already aligned both peers and triggering more often has no effect on that except
            // on local interval shortening(side effect or triggering)
            let (res_first_half, res_second_half) = test_helper(TestHelperStruct {
                trigger_enabled: true,
                latency: Duration::from_millis(333),
                start_emit_traffic_at: Instant::now() + Duration::from_secs(1800),
                stop_emit_traffic_at: Instant::now() + Duration::from_secs(3600),
                emit_packet_every: Duration::from_secs(1),
                delay_to_add_second_peer: Duration::from_secs(17),
                test_duration: Duration::from_secs(3600),
                left_batching_options: BatchingOptions {
                    trigger_cooldown_duration: Duration::from_secs(30),
                    trigger_effective_duration: Duration::from_secs(10),
                },
                right_batching_options: BatchingOptions {
                    trigger_cooldown_duration: Duration::from_secs(30),
                    trigger_effective_duration: Duration::from_secs(10),
                },
            })
            .await;

            assert!(within_1s(
                res_first_half.left_peer_avg_interval,
                Duration::from_secs(100)
            ));
            assert!(within_1s(
                res_first_half.right_peer_avg_interval,
                Duration::from_secs(100)
            ));

            assert!(within_1s(
                res_first_half.avg_aligned_interval,
                Duration::from_secs(1)
            ));

            assert!(within_1s(
                res_second_half.left_peer_avg_interval,
                Duration::from_secs(50)
            ));

            assert!(within_1s(
                res_second_half.right_peer_avg_interval,
                Duration::from_secs(50)
            ));

            assert!(within_1ms(
                res_second_half.avg_aligned_interval,
                Duration::from_millis(333),
            ));
        }
    }
    //
    #[tokio::test]
    async fn no_actions() {
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
        assert!(matches!(
            batcher.get_actions(None).await,
            Err(BatcherError::NoActions)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn no_threshold_expect_no_batching() {
        let start_time = tokio::time::Instant::now();
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
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
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
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
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
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
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
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
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
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
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
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
        let mut batcher = Batcher::<String, TestChecker>::new(BatchingOptions::default());
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
