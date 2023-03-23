//! A simple tool for making exponential backoffs easier

use std::time::Duration;

use thiserror::Error as TError;

/// Enumeration of `Error` types for the exponential backoff implementiation
#[derive(Debug, TError)]
pub enum Error {
    /// Occurs when user provides initial bound equal to zero,
    /// or maximal bound exists and is smaller than initial one
    #[error("Invalid exponential backof bounds")]
    InvalidExponentialBackoffBounds,
}

/// Exponential backoff bounds
///
/// A pair of bounds for the exponential backoffs
#[derive(Clone, Copy, Debug)]
pub struct ExponentialBackoffBounds {
    /// Initial bound
    ///
    /// Used as the first backoff value after ExponentialBackoff creation or reset
    pub initial: Duration,

    /// Maximal bound
    ///
    /// A maximal backoff value which might be achieved during exponential backoff
    /// - if not defined there will be no upper bound for the penalty duration
    pub maximal: Option<Duration>,
}

impl Default for ExponentialBackoffBounds {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(2),
            maximal: Some(Duration::from_secs(120)),
        }
    }
}

/// Exponential backoff helper
///
/// Returns consequtive backoffs growing exponentially
#[derive(Clone, Debug)]
pub struct ExponentialBackoffHelper {
    bounds: ExponentialBackoffBounds,
    current_backoff: Duration,
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
impl ExponentialBackoffHelper {
    /// Given the bounds for exponential backoff returns an instance of
    /// ExponentialBackofHelper
    pub fn new(bounds: ExponentialBackoffBounds) -> Result<Self, Error> {
        if bounds.initial == Duration::ZERO
            || bounds.maximal.map(|t| t < bounds.initial).unwrap_or(false)
        {
            Err(Error::InvalidExponentialBackoffBounds)
        } else {
            Ok(Self {
                bounds,
                current_backoff: bounds.initial,
            })
        }
    }

    /// Returns the current backoff
    pub fn get_backoff(&self) -> Duration {
        self.current_backoff
    }

    /// Moves to the next backoff
    pub fn next_backoff(&mut self) {
        self.current_backoff *= 2;

        if let Some(maximal) = self.bounds.maximal {
            if self.current_backoff > maximal {
                self.current_backoff = maximal;
            }
        }
    }

    /// Resets exponential backoff - the next backoff value will be again
    /// the initial one
    pub fn reset(&mut self) {
        self.current_backoff = self.bounds.initial;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::ExponentialBackoffHelper;

    #[tokio::test]
    async fn exponential_backoff_basic_usage() {
        let mut backoff_instance = ExponentialBackoffHelper::new(crate::ExponentialBackoffBounds {
            initial: Duration::from_millis(100),
            maximal: Some(Duration::from_millis(700)),
        })
        .expect("It seems that the bounds provided in test are incorrect");

        for backoff in [100, 200, 400, 700, 700] {
            assert_eq!(
                backoff_instance.get_backoff(),
                Duration::from_millis(backoff)
            );
            backoff_instance.next_backoff();
        }

        backoff_instance.reset();

        for backoff in [100, 200, 400, 700, 700] {
            assert_eq!(
                backoff_instance.get_backoff(),
                Duration::from_millis(backoff)
            );
            backoff_instance.next_backoff();
        }
    }
}
