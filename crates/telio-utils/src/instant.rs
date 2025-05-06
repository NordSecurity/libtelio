use std::time::Duration;

const CHECK_PERIOD: Duration = Duration::from_secs(60);

/// Wrapper for the `tokio::time::Instant`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(tokio::time::Instant);

impl Instant {
    /// Returns an instant corresponding to “now”.
    pub fn now() -> Self {
        Self(tokio::time::Instant::now())
    }

    /// Returns the amount of time elapsed from another instant to this one, or zero duration if that instant is later than this one.
    pub fn duration_since(&self, earlier: Self) -> Duration {
        self.0.duration_since(earlier.0)
    }

    /// Returns `Some(t)` where `t` is the time `self + duration` if `t` can be represented as `Instant` (which means it’s inside the bounds of the underlying data structure), `None` otherwise.
    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    /// Returns the amount of time elapsed since this instant was created, or zero duration if this instant is in the future.
    pub fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    /// Returns the amount of time elapsed from another instant to this one, or None if that instant is later than this one.
    pub fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }

    /// Returns the amount of time elapsed from another instant to this one, or zero duration if that instant is later than this one.
    pub fn saturating_duration_since(&self, earlier: Self) -> Duration {
        self.0.saturating_duration_since(earlier.0)
    }
}

impl std::ops::Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs
    }
}

impl std::ops::Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl std::ops::Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Self::Output {
        self.0 - rhs.0
    }
}

/// Suspend aware replacement for tokio::time::sleep_until. In case
/// operating system was suspended long enough, so that `instant` is
/// in the past when operating system resumes - in that case `sleep_until`
/// will complete within 60 seconds after the resume.
pub async fn sleep_until(instant: Instant) {
    loop {
        let now = Instant::now();

        if now >= instant {
            return;
        }

        let remaining = instant.duration_since(now);

        if remaining <= CHECK_PERIOD {
            tokio::time::sleep(remaining).await;
            return;
        }

        // Otherwise, sleep for a minute and check again. This sleep can
        // actually take more than CHECK_PERIOD, if the operating system
        // was suspended after the `sleep` was called.
        tokio::time::sleep(CHECK_PERIOD).await;
    }
}
