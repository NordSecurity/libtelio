//! App logic for web ui

use tracing::error;

use crate::{config::TeliodDaemonConfig, TelioStatusReport};

use super::api::{get_config, get_status_report, is_teliod_running};

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
    match get_config() {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to get previous config err: {err}");
            Default::default()
        }
    }
}
