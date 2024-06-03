pub use crate::event_log::moose::{
    ErrorCallback, InitCallback, MooseError, MooseErrorLevel, TrackerState,
};

use std::sync::mpsc::SyncSender;
pub use telio_utils::{telio_log_error, telio_log_generic, telio_log_info, telio_log_warn};

/// Struct for moose::InitCallback
pub struct MooseInitCallback {
    /// Channel tx half to send init result
    pub init_success_tx: SyncSender<bool>,
}

/// Struct for moose::ErrorCallback
pub struct MooseErrorCallback;

impl InitCallback for MooseInitCallback {
    fn after_init(&self, result_code: &Result<TrackerState, MooseError>) {
        let success = match result_code {
            Ok(res) => {
                telio_log_info!("[Moose] Init callback success: {:?}", res);
                true
            }
            Err(err) => {
                telio_log_warn!("[Moose] Init callback error: {:?}", err);
                false
            }
        };
        #[allow(mpsc_blocking_send)]
        let _ = self.init_success_tx.send(success);
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
