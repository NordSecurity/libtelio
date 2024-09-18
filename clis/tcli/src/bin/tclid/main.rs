#![deny(missing_docs)]
// TCLID doc rs documentation introduction:
#![doc = include_str!["./doc/tclid_documentation.md"]]

//! Main and code for the API which is used for sending commands to libtelio which runs on a daemon.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use daemon_common::{
    comms::DaemonSocket,
    daemon::{Daemon, ProcessType},
};
use tokio::time::Duration;

mod tclid;
mod telio_cli_interface;
use telio_cli_interface::TelioCliInterface;

// TODO Add meshnet examples.
// TODO Add --restart flag which would restart the whole daemon before executing the provided command for faster iterating when debugging.
// TODO figure out logging, because multiple tracing subscribers can't be used. Maybe reroute STDIO of daemon?
// TODO Maybe add auto completion support? (probably won't work due to mixed parsing implementation)

struct TcliDaemon;

impl Daemon for TcliDaemon {
    const NAME: &'static str = "Tclid";

    fn get_wd_path() -> Result<PathBuf> {
        Ok(std::env::current_exe()?
            .parent()
            .ok_or(anyhow::anyhow!(
                "Cannot create daemon working directory at root"
            ))?
            .join(format!("/var/run/{}_wd", Self::NAME)))
    }
}

impl TcliDaemon {
    /// Forks the daemon from the API process.
    ///
    /// # Returns
    ///
    /// Current process type indicating whether it's the API or the Daemon.
    /// This is useful because of how the fork syscall.
    fn start() -> Result<ProcessType> {
        use std::fs::File;
        let wd_path = Self::get_wd_path()?;

        std::fs::create_dir_all(&wd_path)?;
        let stderr = File::create(wd_path.join(format!("{}.err", Self::NAME)))?;

        // Every method except `new` and `start` is optional, see `Daemonize` documentation for
        // default behavior.
        let daemonize = daemonize::Daemonize::new()
            .pid_file(Self::get_pid_path()?)
            .chown_pid_file(true)
            .working_directory(wd_path)
            .stderr(stderr);

        match daemonize.execute() {
            daemonize::Outcome::Parent(Ok(daemonize::Parent { .. })) => Ok(ProcessType::Api),
            daemonize::Outcome::Parent(Err(err)) => Err(err.into()),
            daemonize::Outcome::Child(Ok(_)) => Ok(ProcessType::Daemon),
            daemonize::Outcome::Child(Err(err)) => Err(err.into()),
        }
    }

    /// Function for conveniently printing the stderr file of the daemon.
    /// Used by the API to quickly inform the user if something is wrong
    /// with the daemon. Works only when daemon is started with `start()`.
    ///
    /// # Returns
    ///
    /// The whole contents of the daemons stderr file as a String.
    fn get_stderr() -> Result<String> {
        let stderr_file = Self::get_wd_path()?.join(format!("{}.err", Self::NAME));

        let stderr_string = std::fs::read_to_string(stderr_file)?;

        Ok(stderr_string)
    }
}

/// Argument structure for the TCLID API used by Clap to parse the arguments.
#[derive(Parser)]
#[clap(disable_help_flag = true)]
struct Args {
    /// This flag is set when --help or -h is passed, but help is disabled for this struct,
    /// because we want to retrieve the help message from the original TCLI parser to keep things simple.
    /// So help is handled separately according to this flag.
    #[clap(short = 'h', long = "help")]
    help: bool,
    /// Used to pass in features to the TCLID daemon. Note that the TCLID daemon only accepts
    /// feature flags on startup.
    #[clap(short, long)]
    features: Option<String>,
    /// Holds all the other arguments which will be forwarded to the TCLI parser.
    input: Vec<String>,
}

/// Main of the whole TCLID package.
fn main() -> Result<()> {
    let args: Args = Args::parse();

    match run_api(args) {
        Ok(()) => Ok(()),
        Err(e) => {
            #[cfg(unix)]
            // For convenience printing stderr of the daemon to inform the user that something's wrong.
            if let Ok(stderr) = TcliDaemon::get_stderr() {
                if !stderr.is_empty() {
                    println!("Daemon stderr: {}", stderr);
                }
            }
            Err(e)
        }
    }
}

/// Separate function that handles printing the help message,
/// because we don't want to start the whole TCLID daemon just for that.
///
/// # Arguments
///
/// * `input` - The command that was sent through the API when requesting for help.
fn print_help(mut input: Vec<String>) -> Result<()> {
    // Clap removes the actual flag from the args, so need to bring it back, since we're forwarding this to the Telio parser.
    input.push("--help".to_owned());
    // CLI also needs the first element of the vector to be the application name.
    input.insert(0, "tclid".to_owned());

    println!("{}", TelioCliInterface::get_help(input)?);

    Ok(())
}

/// Main function of the API. This is where all the API's decision making happens.
///
/// # Arguments
///
/// * `args` - Command line arguments for the API (already parsed).
fn run_api(args: Args) -> Result<()> {
    // We don't want to start the daemon if all we want is to print the help message.
    // But we also have to retrieve the help message from the TCLI parser.
    if args.help {
        return print_help(args.input);
    }

    match args.input.first().map(|s| s.as_str()) {
        // If no arguments are supplied default behavior is starting the daemon.
        None => {
            if TcliDaemon::is_running()? {
                eprintln!("TCLID daemon is already running, stop it by calling `tclid quit`");
            } else {
                start_daemon(args.features.clone())?;
            }
        }
        Some("quit") => {
            if TcliDaemon::is_running()? {
                let response =
                    DaemonSocket::send_command(&TcliDaemon::get_ipc_socket_path()?, "quit")?;

                if response.as_str() == "OK" {
                    println!("TCLID daemon stopped");
                } else {
                    eprintln!("Error while trying to stop TCLID daemon, please check if TCLID daemon is still running and close it manually");
                }
            } else {
                eprintln!("TCLID daemon is not running");
            }
        }
        Some(_) => {
            if !TcliDaemon::is_running()? {
                start_daemon(args.features.clone())?;
            } else if args.features.is_some() {
                eprintln!("Features cannot be set while TCLID daemon is running.");
            }
            let response = DaemonSocket::send_command(
                &TcliDaemon::get_ipc_socket_path()?,
                &args.input.join(" "),
            )?;
            println!("{}", response);
        }
    };

    Ok(())
}

/// Starts the TCLID daemon which will run actual Telio. For Unix systems uses forking. Decided not to
/// separate api and tclid.d into separate binaries in the project, because that added a lot of extra work.
/// Like having to build the tclid.d binary manually before running the api and didn't really pay off the extra effort.
///
/// # Arguments
///
/// * `features` - Optional string containing the features specification for Telio in JSON.
fn start_daemon(features: Option<String>) -> Result<()> {
    println!("Starting TCLID daemon...");
    match TcliDaemon::start() {
        Ok(ProcessType::Api) => {
            // Verifying that the server had been started, but we have no way of synchronizing
            // the verification with the daemon, so using retries instead.
            // The delay values had been chose experimentally to get a fast, but efficient start of the daemon.
            // This delay mostly depends on how quickly Telio initializes itself from inside the daemon.
            DaemonSocket::send_command_with_retries(
                &TcliDaemon::get_ipc_socket_path()?,
                "status",
                &[
                    Duration::from_millis(400),
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                    Duration::from_millis(500),
                ],
            )?;
            if let Some(features) = features {
                println!("TCLID daemon started with features: {}", features);
            } else {
                println!("TCLID daemon started");
            }

            Ok(())
        }
        Ok(ProcessType::Daemon) => match tclid::run_tclid(features) {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("{e}");
                Err(e)
            }
        },
        Err(e) => Err(e),
    }
}
