use tokio::time::{self, Duration, Interval, MissedTickBehavior};

/// Just like `tokio::time::interval` but the missed tick behaviour
/// is set to `Delay`.
pub fn interval(period: Duration) -> Interval {
    interval_after(Duration::ZERO, period)
}

/// Just like `tokio::time::interval_at(Instant::now() + offest, period)`, but the missed
/// tick behaviour is set to `Delay`.
#[allow(tokio_time_interval)]
pub fn interval_after(offset: Duration, period: Duration) -> Interval {
    #[allow(instant)]
    let start = time::Instant::now() + offset;
    let mut interval = time::interval_at(start, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

/// Resets the interval after the specified `std::time::Duration`.
pub fn reset_after(interval: &mut Interval, offset: Duration) {
    #[allow(instant)]
    interval.reset_at(time::Instant::now() + offset);
}
