use tokio::time::{self, Duration, Instant, Interval, MissedTickBehavior};

/// Just like `tokio::time::interval` but the missed tick behaviour
/// is set to `Delay`.
pub fn interval(period: Duration) -> Interval {
    interval_at(Instant::now(), period)
}

/// Just like `tokio::time::interval_at` but the missed tick behaviour
/// is set to `Delay`.
#[allow(tokio_time_interval)]
pub fn interval_at(start: Instant, period: Duration) -> Interval {
    let mut interval = time::interval_at(start, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}
