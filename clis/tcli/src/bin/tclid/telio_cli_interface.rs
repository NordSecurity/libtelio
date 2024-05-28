//! Code for handling and communicating with libtelio and abstracting it away as a dependency.

use std::sync::Arc;

use anyhow::Result;

use telio_model::features::Features;

use tcli::cli;

/// Platform specific line ending.
#[cfg(windows)]
const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &str = "\n";

/// Struct containing the CLI instance which is used to communicate with libtelio.
/// This instance is basically the TCLI command parser and is intentionally left unchanged to
/// make TCLID as simple to adapt to as possible for the developers who are used to TCLI.
///
/// NOTE! The inner cli type must be dropped outside of the Tokio async runtime, so this struct must
/// be dropped outside of it as well!
pub struct TelioCliInterface {
    /// Internal CLI instance. Same as used by TCLI. Panics if dropped inside the Tokio async runtime!
    cli: cli::Cli,
}

impl TelioCliInterface {
    /// Starts a new instance of the libtelio CLI and it's dependencies, essentially making Telio ready
    /// to receive commands. The dependencies include logging in with the provided Nord token, parsing
    /// the feature flags into a readable format and starting a connection to the DERP server.
    /// Note that because of how nord.rs is written, Telio login must happen outside of async context,
    /// so this function must also be called outside of async context or it will panic.
    /// Returns itself as the handle to the libtelio CLI instance.
    ///
    /// # Arguments
    ///
    /// * `token` - Nord token used to log into the Nord servers.
    /// * `features` - Optional string containing the features specification for Telio in JSON.
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
    /// Execute the actual commands for libtelio received from the event loop of the daemon and return a response
    /// so that it could be sent back to the API. Also handles the format matching between libtelio and TCLID.
    ///
    /// # Arguments
    ///
    /// * `cmd` - Command that was sent by the user through the API.
    pub fn exec(&mut self, cmd: String) -> Result<String> {
        let resp = self.cli.exec(&cmd);
        let resp = resp
            .iter()
            .map(|resp| resp.to_string())
            .collect::<Vec<String>>()
            .join(LINE_ENDING);

        Ok(resp)
    }
    /// Special helper function to retrieve the help message from the TCLI parser without the overhead of
    /// having to start any libtelio dependencies or even run the daemon itself.
    ///
    /// # Arguments
    ///
    /// * `args` - Command line arguments forming the command for which the help is being requested.
    pub fn get_help(args: Vec<String>) -> Result<String> {
        cli::Cli::print_help(args)
    }
}
