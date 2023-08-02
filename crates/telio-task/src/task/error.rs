use std::any::Any;

use tokio::task::JoinError;

/// Task was stopped during execution.
#[derive(Debug, thiserror::Error)]
#[error("Failed to execute.")]
pub struct ExecError;

/// Task stop status.
#[derive(Debug)]
pub enum StopResult<E> {
    /// Task was stopped succesfully
    Ok,
    /// Task stopped due to internal error.
    Err(E),
    /// Task panic'ed
    Panic(Box<dyn Any + Send + 'static>),
}

impl<E> StopResult<E> {
    /// Stopped successfully
    pub fn is_ok(&self) -> bool {
        matches!(self, &StopResult::Ok)
    }

    /// Stopped due to internal error
    pub fn is_err(&self) -> bool {
        matches!(self, &StopResult::Err(_))
    }

    /// Stopped due to inner panic
    pub fn is_panic(&self) -> bool {
        matches!(self, &StopResult::Panic(_))
    }

    /// Return Ok for proper stop or Err if internal error occurred.
    ///
    /// # Panics
    /// Propagates panic if task stopped due to panic
    pub fn resume_unwind(self) -> Result<(), E> {
        match self {
            Self::Ok => Ok(()),
            Self::Err(e) => Err(e),
            Self::Panic(p) => std::panic::resume_unwind(p),
        }
    }
}

impl<E: PartialEq> PartialEq for StopResult<E> {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (&Self::Ok, &Self::Ok) => true,
            (&Self::Err(el), &Self::Err(er)) => el == er,
            _ => false,
        }
    }
}

impl<T, E> From<Result<Result<T, E>, JoinError>> for StopResult<E> {
    fn from(value: Result<Result<T, E>, JoinError>) -> Self {
        match value {
            Ok(Ok(_)) => StopResult::Ok,
            Ok(Err(e)) => StopResult::Err(e),
            Err(e) if e.is_panic() => StopResult::Panic(e.into_panic()),
            // Match arm for cancelled case
            _ => StopResult::Ok,
        }
    }
}
