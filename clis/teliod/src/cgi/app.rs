//! App logic for web ui

use tracing::error;

use super::api::{get_config_from_file, get_status_report, is_teliod_running};
use crate::{config::TeliodDaemonConfig, TelioStatusReport};

#[derive(Clone)]
pub struct AppState {
    pub running: bool,
    pub config: TeliodDaemonConfig,
    pub status: Option<TelioStatusReport>,
}

impl AppState {
    /// Collect app state from current enviroment
    pub fn collect() -> Self {
        Self {
            running: is_teliod_running(),
            config: get_local_or_default_config(),
            status: get_status_report().ok(),
        }
    }
}

pub fn get_local_or_default_config() -> TeliodDaemonConfig {
    match get_config_from_file() {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to get previous config err: {err}");
            Default::default()
        }
    }
}
