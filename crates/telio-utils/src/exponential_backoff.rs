//! A simple tool for making exponential backoffs easier

use std::fmt::Debug;
use std::time::Duration;

use smart_default::SmartDefault;
use thiserror::Error as TError;

const EXPONENTIAL_BACKOFF_MULTIPLIER: u32 = 2;

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
#[derive(Clone, Copy, Debug, SmartDefault)]
pub struct ExponentialBackoffBounds {
    /// Initial bound
    ///
    /// Used as the first backoff value after ExponentialBackoff creation or reset
    #[default(Duration::from_secs(2))]
    pub initial: Duration,

    /// Maximal bound
    ///
    /// A maximal backoff value which might be achieved during exponential backoff
    /// - if not defined there will be no upper bound for the penalty duration
    #[default(Some(Duration::from_secs(120)))]
    pub maximal: Option<Duration>,
}

/// Exponential backoff helper interface
#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
pub trait Backoff: Sync + Send + Debug + 'static {
    /// Returns the current backoff
    fn get_backoff(&self) -> Duration;

    /// Moves to the next backoff
    fn next_backoff(&mut self);

    /// Resets exponential backoff - the next backoff value will be again
    /// the initial one
    fn reset(&mut self);
}

/// Exponential backoff helper
///
/// Returns consequtive backoffs growing exponentially
#[derive(Clone, Debug)]
pub struct ExponentialBackoff {
    bounds: ExponentialBackoffBounds,
    current_backoff: Duration,
}

impl ExponentialBackoff {
    /// Given the bounds for exponential backoff returns an instance of
    /// `ExponentialBackoff`
    ///
    /// # Errors
    ///
    /// Returns an error if the initial bound is zero or maximal bound is
    /// defined and is smaller than the initial one.
    pub fn new(bounds: ExponentialBackoffBounds) -> Result<Self, Error> {
        if bounds.initial == Duration::ZERO || bounds.maximal.is_some_and(|t| t < bounds.initial) {
            return Err(Error::InvalidExponentialBackoffBounds);
        }
        Ok(Self {
            bounds,
            current_backoff: bounds.initial,
        })
    }
}

impl Backoff for ExponentialBackoff {
    fn get_backoff(&self) -> Duration {
        self.current_backoff
    }

    fn next_backoff(&mut self) {
        self.current_backoff *= EXPONENTIAL_BACKOFF_MULTIPLIER;

        if let Some(maximal) = self.bounds.maximal {
            if self.current_backoff > maximal {
                self.current_backoff = maximal;
            }
        }
    }

    fn reset(&mut self) {
        self.current_backoff = self.bounds.initial;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn exponential_backoff_basic_usage() {
        let mut backoff_instance = ExponentialBackoff::new(ExponentialBackoffBounds {
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
