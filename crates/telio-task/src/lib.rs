#![warn(missing_docs)]

//! A component runs during runtime, react to events and produces events or channels
//!
//! To be a component these factors should be met:
//! * Has runtime behaviour:
//!     - Needs to do something periodically
//!     - React to events.
//!     - Generates events
//!     - Read/Writes data.
//! * Is updatable during runtime.
//!

mod macros;
mod task;

pub mod io;

pub use macros::*;
pub use task::*;
