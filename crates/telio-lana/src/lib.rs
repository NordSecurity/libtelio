#![deny(missing_docs)]
//! Contains macros to simplify using Moose functions from within libtelio

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{sync_channel, SyncSender},
    },
    time::Duration,
};

pub use telio_utils::{telio_log_error, telio_log_warn};

#[cfg_attr(all(feature = "moose", not(docrs)), path = "event_log_moose.rs")]
#[cfg_attr(any(not(feature = "moose"), docsrs), path = "event_log_file.rs")]
pub mod event_log;
/// Module containing moose callbacks
pub mod moose_callbacks;

pub use event_log::*;

/// App name used to initialize moose with
pub const LANA_APP_NAME: &str = "libtelio";
/// Version of the tracker used, should be updated everytime the tracker library is updated
pub const LANA_MOOSE_VERSION: &str = "0.8.0";
/// Timeout for moose to send init error, if any, through callback
pub const LANA_MOOSE_MAX_INIT_TIME: u8 = 2;

static MOOSE_INITIALIZED: AtomicBool = AtomicBool::new(false);
const DEFAULT_ORDERING: Ordering = Ordering::SeqCst;

/// Wrapper to call a moose function with optional arguments,
/// returns the result of the call while also logging any error.
///
/// # Parameters:
/// * func - Name of the moose function to call.
/// * arg - Contains the arguments passed to the called function, if any.
/// # Returns:
/// * result - Moose function call result (successful or not).
/// * Err() - moose::Error::NotInitiatedError if lana was not initialized.
#[macro_export]
macro_rules! lana {
    (
        $func:ident
        $(,$arg:expr)*
    ) => {{
            if is_lana_initialized() {
                let result = moose::$func($($arg),*);
                if let Some(error) = result.as_ref().err() {
                    telio_log_warn!(
                        "[Moose] Error: {} on call to `{}`",
                        error,
                        stringify!($func));
                }

                result
            } else {
                Err(moose::Error::NotInitiatedError)
            }
    }};
}

/// Initialize lana with the given configuration
///
/// # Parameters:
/// * event_path - path of the DB file where events will be stored. If such file does not exist, it will be created, otherwise reused.
/// * app_version - Indicates the semantic version of the application.
/// * prod - wether the events should be sent to production or not
pub fn init_lana(
    event_path: String,
    app_version: String,
    prod: bool,
) -> Result<moose::Result, moose::Error> {
    let (tx, rx) = sync_channel(1);
    if !is_lana_initialized() {
        if let Err(err) = init_moose(event_path, app_version, prod, tx) {
            telio_log_warn!("[Moose] Error: {:?} on call to `{}`", err, "moose_init");
            return Err(err);
        };

        match rx.recv_timeout(Duration::from_secs(LANA_MOOSE_MAX_INIT_TIME as u64)) {
            Err(_) => {
                telio_log_warn!(
                    "[Moose] Failed to receive moose init callback result, channel timed out"
                );
                Err(moose::Error::NotInitiatedError)
            }
            Ok(init_result) => {
                if init_result {
                    MOOSE_INITIALIZED.store(true, DEFAULT_ORDERING);
                    init_context_info();
                    Ok(moose::Result::Success)
                } else {
                    Err(moose::Error::NotInitiatedError)
                }
            }
        }
    } else {
        Ok(moose::Result::AlreadyInitiated)
    }
}

/// Deinitialize lana
///
/// # Returns:
/// * Result(Success) - If lana was deinitialized successfully
/// * Result(Error) - Otherwise
pub fn deinit_lana() -> Result<moose::Result, moose::Error> {
    if is_lana_initialized() {
        let result = moose::moose_deinit();
        if let Some(error) = result.as_ref().err() {
            telio_log_warn!("[Moose] Error: {} on call to `{}`", error, "moose_deinit");
        }

        MOOSE_INITIALIZED.store(false, DEFAULT_ORDERING);

        result
    } else {
        Err(moose::Error::NotInitiatedError)
    }
}

/// Has lana been initialized, generally should not be called manually,
/// is used to verify that the feature was enabled when using the lana! macro.
///
/// Returns:
/// bool - True if lana was initialized, false otherwise.
pub fn is_lana_initialized() -> bool {
    MOOSE_INITIALIZED.load(DEFAULT_ORDERING)
}

/// Initialize different moose variations (real, file or mock)
///
/// # Parameters:
/// * event_path - path of the DB file where events will be stored. If such file does not exist, it will be created, otherwise reused.
/// * app_version - Indicates the semantic version of the application.
/// * prod - whether the events should be sent to production or not
/// * tx - channel tx half for the InitCallback instance
pub fn init_moose(
    event_path: String,
    app_version: String,
    prod: bool,
    tx: SyncSender<bool>,
) -> std::result::Result<moose::Result, moose::Error> {
    #[cfg(test)]
    {
        if let Some(mock) = test::STUB.try_lock().unwrap().as_ref() {
            return mock.init(
                event_path,
                LANA_APP_NAME.to_string(),
                app_version,
                LANA_MOOSE_VERSION.to_string(),
                prod,
                Box::new(moose_callbacks::MooseInitCallback {
                    init_success_tx: tx,
                }),
                Box::new(moose_callbacks::MooseErrorCallback),
            );
        }
    }
    moose::init(
        event_path,
        LANA_APP_NAME.to_string(),
        app_version,
        LANA_MOOSE_VERSION.to_string(),
        prod,
        Box::new(moose_callbacks::MooseInitCallback {
            init_success_tx: tx,
        }),
        Box::new(moose_callbacks::MooseErrorCallback),
    )
}
#[cfg(test)]
mod test {
    use serial_test::serial;
    use std::sync::Mutex;

    use super::{
        deinit_lana,
        event_log::moose,
        init_lana, is_lana_initialized,
        moose::{ErrorCallback, InitCallback},
    };

    pub static STUB: Mutex<Option<MooseStub>> = Mutex::new(None);

    pub struct MooseStubWrapper {}

    impl MooseStubWrapper {
        fn new(m: MooseStub) -> Self {
            set_custom_mock(Some(m));
            Self {}
        }
    }

    impl Drop for MooseStubWrapper {
        fn drop(&mut self) {
            teardown();
        }
    }

    pub struct MooseStub {
        return_success: bool,
        init_cb_result: Result<moose::TrackerState, moose::MooseError>,
        should_call_init_cb: bool,
    }

    impl MooseStub {
        #[allow(clippy::too_many_arguments)]
        pub fn init(
            &self,
            _event_path: String,
            _app_name: String,
            _app_version: String,
            _exp_moose_ver: String,
            _prod: bool,
            init_cb: Box<(dyn InitCallback + 'static)>,
            _error_cb: Box<(dyn ErrorCallback + Sync + std::marker::Send + 'static)>,
        ) -> std::result::Result<moose::Result, moose::Error> {
            if self.should_call_init_cb {
                init_cb.after_init(&self.init_cb_result);
            }
            if self.return_success {
                Ok(moose::Result::Success)
            } else {
                Err(moose::Error::NotInitiatedError)
            }
        }
    }

    impl Default for MooseStub {
        fn default() -> Self {
            MooseStub {
                return_success: true,
                init_cb_result: Ok(moose::TrackerState::Ready),
                should_call_init_cb: true,
            }
        }
    }

    fn set_custom_mock(mock: Option<MooseStub>) {
        if let Ok(mut stub) = STUB.try_lock() {
            *stub = mock;
        }
    }

    fn teardown() {
        match deinit_lana() {
            Ok(success) => assert_eq!("Success", format!("{:?}", success)),
            Err(error) => assert_eq!("NotInitiatedError", format!("{:?}", error)),
        };
        set_custom_mock(None);
    }

    #[test]
    #[serial]
    fn test_init_lana() {
        let result = init_lana("/event.db".to_string(), "tests".to_string(), false);
        match result {
            Ok(res) => assert_eq!("Success", format!("{:?}", res)),
            Err(error) => panic!("{:?}", error),
        };

        assert!(is_lana_initialized());

        teardown();
    }

    #[test]
    #[serial]
    fn test_init_lana_initialized() {
        let result = init_lana("/event.db".to_string(), "tests".to_string(), false);
        match result {
            Ok(res) => assert_eq!("Success", format!("{:?}", res)),
            Err(error) => panic!("{:?}", error),
        };

        assert!(is_lana_initialized());

        let result = init_lana("/event.db".to_string(), "tests".to_string(), false);
        match result {
            Ok(res) => assert_eq!("AlreadyInitiated", format!("{:?}", res)),
            Err(error) => panic!("{:?}", error),
        };

        assert!(is_lana_initialized());

        teardown();
    }

    #[test]
    #[serial]
    fn test_init_lana_with_failing_moose_init() {
        let _wrapper = MooseStubWrapper::new(MooseStub {
            return_success: false,
            init_cb_result: Ok(moose::TrackerState::Ready),
            should_call_init_cb: true,
        });

        let result = init_lana("/event.db".to_string(), "tests".to_string(), false);
        match result {
            Ok(res) => panic!("{:?}", res),
            Err(error) => assert_eq!("NotInitiatedError", format!("{:?}", error)),
        };

        assert!(!is_lana_initialized());
    }

    #[test]
    #[serial]
    fn test_init_lana_with_failing_moose_init_cb() {
        let _wrapper = MooseStubWrapper::new(MooseStub {
            return_success: true,
            init_cb_result: Err(moose::MooseError::NotInitiated),
            should_call_init_cb: true,
        });

        let result = init_lana("/event.db".to_string(), "tests".to_string(), false);
        match result {
            Ok(res) => panic!("{:?}", res),
            Err(error) => assert_eq!("NotInitiatedError", format!("{:?}", error)),
        };

        assert!(!is_lana_initialized());
    }

    #[test]
    #[serial]
    fn test_deinit_lana() {
        let result = init_lana("/event.db".to_string(), "tests".to_string(), false);
        match result {
            Ok(res) => assert_eq!("Success", format!("{:?}", res)),
            Err(error) => panic!("{:?}", error),
        };

        assert!(is_lana_initialized());

        let result = deinit_lana();
        match result {
            Ok(res) => assert_eq!("Success", format!("{:?}", res)),
            Err(error) => panic!("{:?}", error),
        };

        assert!(!is_lana_initialized());

        teardown();
    }

    #[test]
    #[serial]
    fn test_deinit_lana_uninitialized() {
        let result = deinit_lana();

        match result {
            Ok(res) => panic!("{:?}", res),
            Err(error) => assert_eq!("NotInitiatedError", format!("{:?}", error)),
        };

        assert!(!is_lana_initialized());

        teardown();
    }
}
