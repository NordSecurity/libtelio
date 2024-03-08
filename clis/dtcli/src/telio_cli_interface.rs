use anyhow::Result;
use std::sync::Arc;

use parking_lot;

use common::{self, cli};
use telio_model::api_config::Features;

pub struct TelioCliInterface {
    cli: cli::Cli,
}

impl TelioCliInterface {
    // Telio login must happen outside of async context, so this function must also be called outside of async context or it will panic.
    pub fn new(token: Option<String>, features: Option<String>) -> Result<Self> {
        let features: Features = features
            .map(|s| serde_json::from_str(&s))
            .transpose()?
            .unwrap_or_default();

        let derp_server =
            Arc::new(parking_lot::Mutex::<Option<telio_model::config::Server>>::new(None));

        let cli = cli::Cli::new(features, token, derp_server)?;

        Ok(TelioCliInterface { cli })
    }

    pub fn exec(&mut self, cmd: String) -> Result<String> {
        let resp = self.cli.exec(&cmd);

        let mut full_response: Vec<String> = Vec::new();
        for response in resp {
            full_response.push(format!("{}", response));
        }

        Ok(full_response.join("\n"))
    }

    pub fn get_telio_help(cmd: &str) -> Result<String> {
        // CLI implementation requires a derp server configuration regardless if it's just for displaying help
        let derp_server =
            Arc::new(parking_lot::Mutex::<Option<telio_model::config::Server>>::new(None));
        let resp = cli::Cli::new(Features::default(), None, derp_server)?.exec(cmd);

        let mut full_response: Vec<String> = Vec::new();
        for response in resp {
            full_response.push(format!("{}", response));
        }

        Ok(full_response.join("\n"))
    }
}
