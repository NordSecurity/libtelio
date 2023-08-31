pub use crate::event_log::*;
pub use telio_utils::{telio_log_error, telio_log_info, telio_log_warn};

/// Struct for Moose callbacks
pub struct MooseCallbacks;

impl moose::InitCallback for MooseCallbacks {
    fn after_init(&self, result_code: &Result<moose::TrackerState, moose::MooseError>) {
        match result_code {
            Ok(res) => telio_log_info!("Moose init success with code {:?}", res),
            Err(err) => telio_log_error!("Moose init failed with code {:?}", err),
        }
    }
}

impl moose::ErrorCallback for MooseCallbacks {
    fn on_error(
        &self,
        error_level: moose::MooseErrorLevel,
        error_code: moose::MooseError,
        msg: &str,
    ) {
        match error_level {
            moose::MooseErrorLevel::Warning => {
                telio_log_warn!("Moose error {:?}: {}", error_code, msg)
            }
            moose::MooseErrorLevel::Error => {
                telio_log_error!("Moose error {:?}: {}", error_code, msg)
            }
        }
    }
}
