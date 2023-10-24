//! Information reported by task monitor

use std::error::Error;

use serde::Serialize;
use tokio::task::JoinError;

/// Event reported by [TaskMonitor]
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
#[serde(tag = "event")]
#[serde(rename_all = "snake_case")]
pub enum MonitorEvent {
    /// Task has been looping excessively
    TaskBusyLoop {
        /// Name of the task
        name: &'static str,
    },
    /// Task was started
    TaskStart {
        /// Name of the task
        name: &'static str,
    },
    /// Task was stopped
    TaskStop {
        /// Name of the task
        name: &'static str,
        /// Stop reason
        reason: StopReason,
    },
}

/// Possible reasons why task was stopped
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
#[serde(tag = "type", content = "message")]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Task stopped manually by calling [Task::stop]
    /// We expect for all task to be stopped manualy
    Manual,
    /// Task stopped via drop
    Dropped,
    /// Task stopped due to inner panic
    Panic,
    /// Task stopped due to inner error
    Error(String),
    /// Task stopped by [tokio::task::JoinHandle::abort]
    Cancel,
}

/// How task was stopped
pub enum StopKind {
    /// Task was stopped manualy, calling stop
    /// We expect use of manual stop, to ensure we wait for
    /// tasks to close properly
    Manual,
    /// Task was stopped using Drop
    Dropped,
}

impl<E: Error> From<&Result<Result<StopKind, E>, JoinError>> for StopReason {
    fn from(value: &Result<Result<StopKind, E>, JoinError>) -> Self {
        use StopReason::*;
        match value {
            Ok(res) => match res {
                Ok(StopKind::Manual) => Manual,
                Ok(StopKind::Dropped) => Dropped,
                Err(e) => Error(e.to_string()),
            },
            Err(e) => {
                if e.is_cancelled() {
                    Cancel
                } else {
                    Panic
                }
            }
        }
    }
}
