//! Code for the daemon which runs actual libtelio in the background.

use std::fs;

use anyhow::Result;
use tracing::{info, level_filters::LevelFilter};

use crate::coms::DaemonSocket;
use crate::get_ipc_socket_path;
use crate::telio_cli_interface::TelioCliInterface;

/// Function to setup the TCLID daemon's dependencies (including Telio itself) and and run it.
/// AKA the event loop.
///
/// # Arguments
///
/// * `features` - Optional string containing the features specification for Telio in JSON.
///
/// # Returns
///
/// A Result indicating whether the event loop shut down gracefully.
pub fn run_tclid(features: Option<String>) -> Result<()> {
    let (non_blocking_writer, _tracing_worker_guard) =
        tracing_appender::non_blocking(fs::File::create("tclid.log")?);
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let nord_token = std::env::var("NORD_TOKEN").ok();
    let mut telio_cli = TelioCliInterface::new(nord_token, features)?;
    let socket = DaemonSocket::new(&get_ipc_socket_path()?)?;
    info!("Entered event loop");

    loop {
        let mut connection = socket.accept()?;
        let command = connection.read_command()?;

        match command.as_str() {
            "quit" => {
                // "OK" here is an arbitrary response to indicate that the server had started shutting down.
                connection.respond("OK".to_owned())?;

                break;
            }
            _ => {
                let response = telio_cli.exec(command);
                connection.respond(response?)?;
            }
        }
    }
    info!("Stopping daemon");

    Ok(())
}
