use crate::{telio_log_debug, telio_log_warn};
use rustc_hash::FxHashMap;
use std::{
    sync::Arc,
    thread::{current, sleep, spawn, ThreadId},
    time::{Duration, Instant},
};

const ALERT_DURATION: Duration = Duration::from_secs(10);
const UNPARKED_THRESHOLD: Duration = Duration::from_secs(1);

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum ThreadStatus {
    Started,
    Stopped,
    Parked,
    Unparked,
}

/// ThreadTracker will track changes of state of tokio's threads.
pub struct ThreadTracker {
    statuses: FxHashMap<ThreadId, (ThreadStatus, Instant)>,
    last_change: Instant,
}

impl Default for ThreadTracker {
    fn default() -> Self {
        Self {
            statuses: Default::default(),
            last_change: Instant::now(),
        }
    }
}

impl ThreadTracker {
    fn set_status(&mut self, status: ThreadStatus) {
        let now = Instant::now();
        let tid = current().id();

        self.last_change = now;
        if let Some((ThreadStatus::Unparked, thread_last_status_change)) =
            self.statuses.insert(tid, (status, now))
        {
            let delta = now - thread_last_status_change;
            if status == ThreadStatus::Parked && delta > UNPARKED_THRESHOLD {
                telio_log_debug!("Thread {tid:?} was unparked for too long: {delta:?}");
            }
        }
    }

    fn check_for_long_unparked_threads(&self) {
        let now = Instant::now();
        for (tid, (status, last_status_change)) in &self.statuses {
            if *status == ThreadStatus::Unparked {
                let delta = now - *last_status_change;
                if delta > 2 * UNPARKED_THRESHOLD {
                    telio_log_debug!("{tid:?} is unparked for {delta:?}");
                }
            }
        }
    }

    fn are_all_threads_parked(&self) -> bool {
        self.statuses
            .values()
            .all(|(s, _)| *s == ThreadStatus::Parked)
    }

    /// Tokio runtime callback
    pub fn on_thread_start(&mut self) {
        self.set_status(ThreadStatus::Started);
    }

    /// Tokio runtime callback
    pub fn on_thread_stop(&mut self) {
        self.set_status(ThreadStatus::Stopped);
    }

    /// Tokio runtime callback
    pub fn on_thread_park(&mut self) {
        self.set_status(ThreadStatus::Parked);
    }

    /// Tokio runtime callback
    pub fn on_thread_unpark(&mut self) {
        self.set_status(ThreadStatus::Unparked);
    }
}

/// Monitor can start background thread to monitor the state of tokio threads.
pub trait Monitor {
    /// Start background monitoring thread.
    fn start(self);
}

impl Monitor for Arc<parking_lot::Mutex<ThreadTracker>> {
    fn start(self) {
        spawn(move || {
            let mut last_alert = None;
            loop {
                sleep(ALERT_DURATION);
                let now = Instant::now();
                let thread_tracker = self.lock();
                let time_since_last_change = now - thread_tracker.last_change;
                thread_tracker.check_for_long_unparked_threads();
                if time_since_last_change > ALERT_DURATION
                    && thread_tracker.are_all_threads_parked()
                    && last_alert
                        .map(|last_alert| last_alert < thread_tracker.last_change)
                        .unwrap_or(true)
                {
                    telio_log_warn!(
                        "All tokio threads are parked for {:?}",
                        time_since_last_change
                    );
                    last_alert = Some(now);
                }
            }
        });
    }
}
