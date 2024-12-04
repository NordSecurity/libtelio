use std::{
    fs, io,
    process::{Command, Stdio},
    time::Duration,
};

use const_format::concatcp;
use rust_cgi::{http::Method, text_response, Request, Response};

use crate::{
    command_listener::CommandResponse,
    DaemonSocket, TIMEOUT_SEC,
};

const TELIOD_TMP_DIR: &str = "/tmp/nordsecuritymeshnet";
const PID_FILE: &str = concatcp!(TELIOD_TMP_DIR, "/teliod.pid");
const QPKG_DIR: &str = "/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet";
const TELIOD_BIN: &str = concatcp!(QPKG_DIR, "/teliod");
const TELIOD_CFG: &str = concatcp!(QPKG_DIR, "/teliod.cfg");
const MESHNET_LOG: &str = concatcp!(QPKG_DIR, "/meshnet.log");
const TELIOD_LOG: &str = "/var/log/teliod.log";

pub(crate) fn handle_request(request: Request) -> Response {
    match (request.method(), request.uri().query()) {
        (&Method::POST, Some("action=start")) => start_daemon(),
        (&Method::POST, Some("action=stop")) => stop_daemon(),
        (&Method::PATCH, Some(_action)) => {
            text_response(400, "Invalid request.")
        }
        (&Method::GET, Some("info=get-status")) => get_status(),
        (&Method::GET, Some("info=get-teliod-logs")) => get_teliod_logs(),
        (&Method::GET, Some("info=get-meshnet-logs")) => get_meshnet_logs(),
        (_, _) => text_response(400, "Invalid request."),
    }
}

fn is_teliod_running() -> bool {
    fs::read_to_string(PID_FILE)
        .and_then(|pid| fs::metadata(format!("/proc/{}", pid.trim())))
        .is_ok()
}

fn teliod_socket_exists() -> bool {
    DaemonSocket::get_ipc_socket_path()
        .and_then(|path| path.metadata())
        .is_ok()
}

fn kill_teliod_process() -> Result<(), io::Error> {
    match fs::read_to_string(PID_FILE) {
        Ok(pid) => {
            let _ = Command::new("kill").arg(pid.trim()).status();
            if teliod_socket_exists() {
                let _ = Command::new("kill").arg("-9").arg(pid.trim()).status();
                let _ = DaemonSocket::get_ipc_socket_path().and_then(fs::remove_file);
            }
            fs::remove_file(PID_FILE)
        }
        Err(e) => Err(e),
    }
}

fn start_daemon() -> Response {
    if is_teliod_running() {
        if teliod_socket_exists() {
            return text_response(400, "Application is already running.");
        } else {
            let _ = kill_teliod_process();
        }
    }

    let teliod_log_file = match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(TELIOD_LOG)
    {
        Ok(file) => file,
        Err(_) => {
            return text_response(500, "Failed to open teliod log file.");
        }
    };

    match Command::new("setsid")
        .arg(TELIOD_BIN)
        .arg("daemon")
        .arg(TELIOD_CFG)
        .stdout(Stdio::from(
            teliod_log_file
                .try_clone()
                .expect("Failed to open teliod log file."),
        ))
        .stderr(Stdio::from(teliod_log_file))
        .spawn()
    {
        Ok(child) => {
            let pid = child.id();
            if fs::write(PID_FILE, pid.to_string()).is_ok() {
                text_response(200, "Application started successfully.")
            } else {
                text_response(500, "Failed to save PID.")
            }
        }
        Err(_) => text_response(500, "Failed to start the application."),
    }
}

fn stop_daemon() -> Response {
    if is_teliod_running() {
        if kill_teliod_process().is_ok() {
            text_response(200, "Application stopped successfully.")
        } else {
            text_response(500, "Failed to stop the application.")
        }
    } else {
        text_response(400, "Application is not running.")
    }
}

// TODO: LLT-5712
// fn update_config(_post_data: &str) {
// }

fn get_status() -> Response {
    if is_teliod_running() && teliod_socket_exists() {
        if let Ok(socket_path) = DaemonSocket::get_ipc_socket_path() {
            let response = futures::executor::block_on(tokio::time::timeout(
                Duration::from_secs(TIMEOUT_SEC),
                DaemonSocket::send_command(
                    &socket_path,
                    &serde_json::to_string("get-status").unwrap_or_default(),
                ),
            ));

            match response {
                Ok(Ok(response)) => {
                    if let Ok(CommandResponse::StatusReport(status)) =
                        CommandResponse::deserialize(&response)
                    {
                        text_response(
                            200,
                            serde_json::to_string_pretty(&status).unwrap_or_default(),
                        )
                    } else {
                        text_response(500, "Failed to retrieve status.")
                    }
                }
                _ => text_response(500, "Failed to retrieve status."),
            }
        } else {
            text_response(500, "Failed to retrieve status.")
        }
    } else {
        text_response(400, "Application is not running.")
    }
}

fn get_teliod_logs() -> Response {
    match fs::read_to_string(TELIOD_LOG) {
        Ok(logs) => text_response(200, logs),
        Err(_) => text_response(404, "Log file not found."),
    }
}

fn get_meshnet_logs() -> Response {
    match fs::read_to_string(MESHNET_LOG) {
        Ok(logs) => text_response(200, logs),
        Err(_) => text_response(404, "Log file not found."),
    }
}
