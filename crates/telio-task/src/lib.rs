#![warn(missing_docs)]

//! A component runs during runtime, react to events and produces events or channels
//!
//! To be a component these factors should be met:
//! * Has runtime behaviour:
//!     - Needs to do something periodicaly
//!     - React to events.
//!     - Generates events
//!     - Read/Writes data.
//! * Is updateable during runtime.
//!

mod macros;
mod task;

pub mod io;

pub use macros::*;
pub use task::BoxAction;
pub use task::*;
