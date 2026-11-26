/// A suspend-aware interval ticker.
///
/// `tokio::time::Instant` and `std::time::Instant` are not suspend aware, which means
/// that the timers that are driving periodic actions won't advance while a device is
/// suspended. As a result of that, we might have to wait an entire `period` after waking
/// up from sleep rather than firing immediately, which can cause slowdowns and nonets.
/// `crate::Instant` is suspend-aware, and allows this ticker to also be suspend-aware,
/// which let's other components restore connectivity much faster after waking up from
/// suspend.
///
/// The next tick is always based on the current time, rather than just advancing
/// `next` by `period`. That way, if the tick is happening after the device wakes
/// up from a long sleep, the ticker won't fire multiple ticks to try to catch up
pub struct SuspendAwareTicker {
    period: tokio::time::Duration,
    /// The wall-clock deadline for the next tick, measured with a suspend-aware clock.
    next: crate::Instant,
}

impl SuspendAwareTicker {
    /// Create a new ticker with a given period where the first tick happens immediately
    pub fn new(period: tokio::time::Duration) -> Self {
        Self::new_after(tokio::time::Duration::ZERO, period)
    }

    /// Create a new ticker with a given period where the first tick is `offset` time from now
    pub fn new_after(offset: tokio::time::Duration, period: tokio::time::Duration) -> Self {
        Self {
            period,
            next: crate::Instant::now() + offset,
        }
    }

    /// Wait until the next tick, then advance the deadline
    pub async fn tick(&mut self) {
        crate::sleep_until(self.next).await;
        self.next = crate::Instant::now() + self.period;
    }

    /// Reset the ticker so the next tick happens `offset` time from now
    pub fn reset_after(&mut self, offset: tokio::time::Duration) {
        self.next = crate::Instant::now() + offset;
    }

    /// Reset the ticker so the next tick happens immediately
    pub fn reset_immediately(&mut self) {
        self.next = crate::Instant::now();
    }
}
