use std::ops::{Deref, DerefMut};
use std::time::Duration;
use std::time::Instant;

/// Replacement for std::time::Instant that compensates for the time while asleep
#[derive(Copy, Clone, Debug)]
pub struct TelioInstant(Instant);

impl TelioInstant {
    /// https://www.manpagez.com/man/3/clock_gettime/
    /// Return instant bound to the current point in time
    pub fn now() -> Self {
        #[cfg(target_vendor = "apple")]
        const CLOCK_ID: libc::clockid_t = libc::CLOCK_MONOTONIC;

        #[cfg(not(target_vendor = "apple"))]
        const CLOCK_ID: libc::clockid_t = libc::CLOCK_BOOTTIME;

        println!("Using custom clock source!");

        // Replace with actual custom time fetching if needed
        Self(Instant::now())
    }

    /// Return elapsed duration for the instant
    pub fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}
