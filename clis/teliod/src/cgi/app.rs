//! App logic for web ui

use std::collections::HashMap;

use tracing::error;

use crate::{config::TeliodDaemonConfig, TelioStatusReport};

use super::api::{get_config, get_status_report, is_teliod_running};

#[derive(Clone)]
pub struct AppState {
    pub running: bool,
    pub config: TeliodDaemonConfig,
    pub status: Option<TelioStatusReport>,

    // TODO: if error occur durring upade_config, this should collect it
    // and add info to the generated form
    pub errors: HashMap<String, String>,
}

impl AppState {
    /// Collect app state from current enviroment
    pub fn collect() -> Self {
        Self {
            running: is_teliod_running(),
            config: get_local_or_default_config(),
            status: get_status_report().ok(),
            errors: HashMap::new(),
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
