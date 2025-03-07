/// Utilities
///

/// wrapping tracing::trace and adding more information
#[macro_export]
macro_rules! telio_log_trace {
       ( $msg: expr) => {tracing::trace!($msg)};
       ( $format: expr, $($arg:tt)+) => {tracing::trace!($format,  $($arg)+)};
}

/// wrapping tracing::debug and adding more information
#[macro_export]
macro_rules! telio_log_debug {
       ( $msg: expr) => {tracing::debug!($msg)};
       ( $format: expr, $($arg:tt)+) => { tracing::debug!( $format,  $($arg)+) };
}

/// wrapping tracing::info and adding more information
#[macro_export]
macro_rules! telio_log_info {
       ( $msg: expr) => {tracing::info!($msg)};
       ( $format: expr, $($arg:tt)+) => { tracing::info!( $format,  $($arg)+) };
}

/// wrapping tracing::warn and adding more information
#[macro_export]
macro_rules! telio_log_warn {
       ( $msg: expr) => {tracing::warn!($msg)};
       ( $format: expr, $($arg:tt)+) => { tracing::warn!( $format,  $($arg)+) };
}

/// wrapping tracing::error and adding more information
#[macro_export]
macro_rules! telio_log_error {
       ( $msg: expr) => {tracing::error!($msg)};
       ( $format: expr, $($arg:tt)+) => { tracing::error!( $format,  $($arg)+) };
}

/// Error with log is used to log something
/// e.g. an error and give it back afterwards
/// wrapped on a Err(..)
///
#[macro_export]
macro_rules! telio_err_with_log {
    // log the error and give it back
    ($error: expr) => {{
        // See implementation of `dbg!` in std lib:
        // https://github.com/rust-lang/rust/blob/1.68.0/library/std/src/macros.rs#L340-L362
        match $error {
            tmp => {
                tracing::debug!(
                    "{:?} - {:?} at {:?}:{:?}",
                    std::module_path!(),
                    &tmp,
                    file!(),
                    line!()
                );
                Err(tmp)
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn telio_err_with_log_evaluates_once() {
        let counter = AtomicUsize::new(0);
        let _result: Result<(), usize> =
            telio_err_with_log!(counter.fetch_add(1, Ordering::Relaxed));
        assert_eq!(1, counter.load(Ordering::Relaxed));
    }
}
