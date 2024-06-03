/// Utilities
///

#[macro_export]
macro_rules! telio_log_generic {
    ( $log_func: ident, $msg: expr) => {tracing::$log_func!($msg)};
    ( $log_func: ident, $format: expr, $($arg:expr),+) => {{
        use std::net::{IpAddr, SocketAddr};

        #[allow(dead_code)]
        trait HideSensitiveInfo {
            fn hide_me_maybe(&self) -> &'static str {
                "******"
            }
        }
        impl HideSensitiveInfo for IpAddr {}
        impl HideSensitiveInfo for SocketAddr {}

        #[allow(dead_code)]
        trait NotHideAtAll {
            fn hide_me_maybe(&self) -> &Self {
                self
            }
        }
        impl<T> NotHideAtAll for &T {}

        tracing::$log_func!($format,  $((&$arg).hide_me_maybe()),+)
    }};
}

/// wrapping tracing::trace and adding more information
#[macro_export]
macro_rules! telio_log_trace {
       ( $($arg:expr),*) => { telio_log_generic!(trace, $($arg),*) };
}

/// wrapping tracing::debug and adding more information
#[macro_export]
macro_rules! telio_log_debug {
       ( $($arg:expr),*) => { telio_log_generic!(debug, $($arg),*) };
}

/// wrapping tracing::info and adding more information
#[macro_export]
macro_rules! telio_log_info {
       ( $($arg:expr),*) => { telio_log_generic!(info, $($arg),*) };
}

/// wrapping tracing::warn and adding more information
#[macro_export]
macro_rules! telio_log_warn {
       ( $($arg:expr),*) => { telio_log_generic!(warn, $($arg),*) };
}

/// wrapping tracing::error and adding more information
#[macro_export]
macro_rules! telio_log_error {
       ( $($arg:expr),*) => { telio_log_generic!(error, $($arg),*) };
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
