extern crate daemonize;

use tokio::time::Duration;

use clap::Parser;

use anyhow::Result;
use tokio::sync::{mpsc, oneshot};

mod coms;
mod daemon;
mod telio_cli_interface;

use coms::DaemonIPC;
use daemon::{Daemon, ProcessType};
use telio_cli_interface::TelioCliInterface;

// Cross platform compatibility notes:
// Linux is supported and tested.
// MacOS is supported, but not tested.
// Windows is not supported.
// TODO test MacOS support.

#[derive(Parser, Debug)]
struct Args {
    /// Pass [Features] in json format. Configure optional features.
    #[clap(short, long)]
    features: Option<String>,
}

// TODO for now this value had been chosen randomly.
const DAEMON_GRPC_ADDRESS: &'static str = "[::1]:50051";

// TODO Sometimes getting a stream closed because of a broken pipe when calling quit. (added a delay and monitoring)
// TODO figure out logging, because multiple tracing subscribers can't be used. Maybe reroute STDIO of daemon?
// TODO add something better than strings for controlling daemon.
// TODO Add tests.
// TODO Test if features and help flags work properly.
// TODO Maybe add auto completion support?
// TODO Try and make help and feature commands more user friendly like they were in TCLI.
// TODO Figure out if running daemon with root privileges is a good idea.
// TODO Make sure the new cargo runner with '-E' flag won't cause issues.
// TODO Should probably replace all the eprintln's with error propagation.
// TODO Sometimes getting connection refused when starting daemon.

// OS does not create new threads when forking, so we need to initialize the Tokio runtime after forking.
fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).peekable();

    // TODO Maybe try and get Clap to do this parsing, but had issues with getting variable strings and predefined flags to work together.
    match args.peek().as_deref().map(|s| s.as_str()) {
        // If no arguments are supplied default behavior is starting the daemon.
        None => {
            if Daemon::is_running()? {
                eprintln!("DTCLI daemon is already running, stop it by running `dtcli quit`");
            } else {
                start_daemon(None)?;
                // TODO check if daemon started successfully.
                println!("DTCLI Daemon started");
            }
        }
        // Handling quit command separately, because it needs to stop the daemon.
        Some("quit") => {
            if Daemon::is_running()? {
                // TODO gracefully shut down both the server, the daemon that's running it and (forgot)
                let response = DaemonIPC::send_command(DAEMON_GRPC_ADDRESS, "quit")?;

                if response.as_str() == "OK" {
                    println!("Daemon stopped");
                } else {
                    eprintln!("Error while trying to stop daemon, please check if daemon is still running and close it manually");
                }
            } else {
                println!("DTCLI daemon is not running, run it by running `dtcli` or `dtcli start`");
            }
        }
        // TODO There is probably a better way to handle feature flags, but even if not, it should be well documented
        // That the -f flag must be the first and only flag.
        Some("-f") => {
            if !Daemon::is_running()? {
                println!("Starting daemon with features...");
                let features = args.skip(1).collect::<Vec<String>>().join(" ");
                start_daemon(Some(features))?;
                println!("DTCLI Daemon started with features");
            } else {
                eprintln!("Cannot set features while DTCLI daemon is already running, stop it by running `dtcli quit`");
            }
        }
        // Help command should not require running a daemon so handling it separately here:
        Some("help") => {
            let response =
                TelioCliInterface::get_telio_help(&args.collect::<Vec<String>>().join(" "))?;
            println!("{}", response);
        }
        Some(_) => {
            if !Daemon::is_running()? {
                println!("Starting daemon...");
                start_daemon(None)?;
                println!("DTCLI Daemon started and is running");
            }
            let response = DaemonIPC::send_command(
                DAEMON_GRPC_ADDRESS,
                &format!("exec {}", args.collect::<Vec<String>>().join(" ")),
            )?;
            println!("{}", response);
        }
    };
    //TODO should the PID file be deleted?

    Ok(())
}

fn start_daemon(features: Option<String>) -> Result<()> {
    match Daemon::start() {
        Ok(ProcessType::Api) => {
            // Verifying that the server had been started, but we have no way of synchronising
            // the verification with the daemon, so using retries instead.
            let retry_delay_list = vec![
                Duration::from_millis(500),
                Duration::from_millis(200),
                Duration::from_millis(200),
                Duration::from_millis(200),
                Duration::from_millis(500),
            ];
            DaemonIPC::send_command_with_retries(
                DAEMON_GRPC_ADDRESS,
                "ping_daemon_ipc",
                retry_delay_list,
            )?;
            Ok(())
        }
        Ok(ProcessType::Daemon) => {
            let nord_token = std::env::var("NORD_TOKEN").ok();
            let telio_cli = TelioCliInterface::new(nord_token, features)?;
            tokio::runtime::Runtime::new()?.block_on(async {
                let grpc_coms = run_grpc_server().await?;
                run_event_loop(grpc_coms, telio_cli).await
            })
        }
        Err(e) => Err(e),
    }
}

struct GRPCComs {
    request_rx: mpsc::Receiver<String>,
    response_tx: mpsc::Sender<String>,
    shutdown_tx: oneshot::Sender<()>,
}

// Separated this part into it's own function so that it can be run as soon as possible
// so there's no delay before the daemon's gRPC server becomes responsive.
async fn run_grpc_server() -> Result<GRPCComs> {
    let (request_tx, request_rx) = mpsc::channel(10);
    let (response_tx, response_rx) = mpsc::channel(10);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        match DaemonIPC::new(request_tx, response_rx, shutdown_rx)
            .listen(DAEMON_GRPC_ADDRESS)
            .await
        {
            Ok(_) => println!(
                "Telio daemon stopped listening for gRPC requests on {}",
                DAEMON_GRPC_ADDRESS
            ),
            Err(e) => eprintln!("Error occurred while listening for gRPC requests: {}", e),
        }
    });

    println!(
        "Telio daemon started listening for gRPC requests on {}",
        DAEMON_GRPC_ADDRESS
    );

    Ok(GRPCComs {
        request_rx,
        response_tx,
        shutdown_tx,
    })
}

async fn run_event_loop(grpc_coms: GRPCComs, mut telio_cli: TelioCliInterface) -> Result<()> {
    println!("Entered event loop");
    let GRPCComs {
        mut request_rx,
        response_tx,
        shutdown_tx,
    } = grpc_coms;

    loop {
        if let Some(mut command) = request_rx.recv().await {
            match command.as_str() {
                "quit" => {
                    response_tx.send("OK".to_owned()).await?;
                    break;
                }
                "ping_daemon_ipc" => {
                    response_tx.send("OK".to_owned()).await?;
                }
                _ => {
                    if !command.starts_with("exec ") {
                        response_tx.send("Unsupported command".to_owned()).await?;
                    }
                    command = command.split_off("exec ".len());

                    let response;
                    (response, telio_cli) = tokio::task::spawn_blocking(move || {
                        println!("GOT: {}", command);
                        let response = telio_cli.exec(command);

                        (response, telio_cli)
                    })
                    .await?;
                    response_tx.send(response?).await?;
                }
            }
        }
    }

    println!("Stopping daemon");
    // TODO there's a race condition here. gRPC get's shut down before it can send a response if this delay is not present.
    tokio::time::sleep(Duration::from_micros(10)).await;
    // drop(response_tx);

    shutdown_tx
        .send(())
        .map_err(|_| anyhow::anyhow!("Error occurred while trying to gracefully shut down daemon!"))
}
