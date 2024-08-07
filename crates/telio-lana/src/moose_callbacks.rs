pub use crate::event_log::moose::{
    ErrorCallback, InitCallback, MooseError, MooseErrorLevel, TrackerState,
};
use crate::{DEFAULT_ORDERING, MOOSE_INITIALIZED};

pub use telio_utils::{telio_log_error, telio_log_info, telio_log_warn};

/// Struct for moose::InitCallback
pub struct MooseInitCallback;

/// Struct for moose::ErrorCallback
pub struct MooseErrorCallback;

impl InitCallback for MooseInitCallback {
    fn after_init(&self, result_code: &Result<TrackerState, MooseError>) {
        match result_code {
            Ok(res) => {
                telio_log_info!("[Moose] Init callback success: {:?}", res);
                MOOSE_INITIALIZED.store(true, DEFAULT_ORDERING);
                true
            }
            Err(err) => {
                telio_log_warn!("[Moose] Init callback error: {:?}", err);
                MOOSE_INITIALIZED.store(false, DEFAULT_ORDERING);
                false
            }
        };
    }
}

impl ErrorCallback for MooseErrorCallback {
    fn on_error(&self, error_level: MooseErrorLevel, error_code: MooseError, msg: &str) {
        match error_level {
            MooseErrorLevel::Warning => {
                telio_log_warn!("[Moose] Error callback {:?}: {:?}", error_code, msg)
            }
            MooseErrorLevel::Error => {
                telio_log_warn!("[Moose] Error callback {:?}: {:?}", error_code, msg)
            }
        }
    }
}
