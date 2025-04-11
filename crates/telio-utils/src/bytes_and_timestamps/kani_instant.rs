use std::{
    ops::{AddAssign, Sub},
    time::Duration,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(super) struct Instant {
    millis: u64,
}

impl Instant {
    pub fn duration_since(&self, other: Self) -> Duration {
        Duration::from_millis(self.millis.saturating_sub(other.millis))
    }
}

impl Sub for Instant {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        self.duration_since(rhs)
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self {
            millis: self.millis.saturating_sub(rhs.as_millis() as u64),
        }
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.millis += rhs.as_millis() as u64;
    }
}
