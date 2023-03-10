/// Nurse errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A component was unavailable.
    #[error("Component was stopped.")]
    Stopped,
}
