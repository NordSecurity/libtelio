use std::{
    env, fs,
    io::{self, Read},
    process::{Command, Stdio},
};

use serde_json::json;

use crate::config::TeliodDaemonConfig;

struct PathConfig;

impl PathConfig {
    const APP_TMP_DIR: &'static str = "/tmp/nordsecuritymeshnet";
    const QPKG_DIR: &'static str = "/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet";

    pub fn teliod_bin() -> String {
        format!("{}/teliod", Self::QPKG_DIR)
    }

    pub fn teliod_cfg() -> String {
        format!("{}/teliod.cfg", Self::QPKG_DIR)
    }

    pub fn teliod_log() -> String {
        "/var/log/teliod.log".to_owned()
    }

    pub fn meshnet_log() -> String {
        format!("{}/meshnet.log", Self::QPKG_DIR)
    }

    pub fn pid() -> String {
        format!("{}/teliod.pid", Self::APP_TMP_DIR)
    }
}

#[derive(Debug, PartialEq)]
enum HttpMethod {
    Get,
    Post,
    Patch,
    Unsupported,
}

impl HttpMethod {
    fn from_method(method: &str) -> Self {
        match method {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PATCH" => HttpMethod::Patch,
            _ => HttpMethod::Unsupported,
        }
    }

    fn get_post_data(&self) -> String {
        let mut data = String::new();
        if matches!(self, HttpMethod::Post | HttpMethod::Patch) {
            let content_length = env::var("CONTENT_LENGTH")
                .ok()
                .and_then(|len| len.parse::<usize>().ok());
            if let Some(length) = content_length {
                let _ = io::stdin().take(length as u64).read_to_string(&mut data);
            }
        }
        data
    }
}

#[derive(Debug, PartialEq)]
enum Action {
    Start,
    Stop,
    UpdateConfig,
    GetStatus,
    GetTeliodLogs,
    GetMeshnetLogs,
    Invalid,
}

impl Action {
    fn from_query(query: &str) -> Self {
        match query {
            "action=start" => Action::Start,
            "action=stop" => Action::Stop,
            "action=update-config" => Action::UpdateConfig,
            "action=get-status" => Action::GetStatus,
            "action=get-teliod-logs" => Action::GetTeliodLogs,
            "action=get-meshnet-logs" => Action::GetMeshnetLogs,
            _ => Action::Invalid,
        }
    }
}

pub(crate) fn parse_cgi() {
    println!("Content-Type: application/json\n");

    let http_method = {
        let method = env::var("REQUEST_METHOD").unwrap_or_default();
        HttpMethod::from_method(&method)
    };
    let post_data = http_method.get_post_data();
    let action = {
        let query = env::var("QUERY_STRING").unwrap_or_default();
        Action::from_query(&query)
    };

    match (http_method, action) {
        (HttpMethod::Post, Action::Start) => start_daemon(),
        (HttpMethod::Post, Action::Stop) => stop_daemon(),
        (HttpMethod::Patch, Action::UpdateConfig) => update_config(&post_data),
        (HttpMethod::Get, Action::GetStatus) => get_status(),
        (HttpMethod::Get, Action::GetMeshnetLogs) => get_meshnet_logs(),
        (HttpMethod::Get, Action::GetTeliodLogs) => get_teliod_logs(),
        (HttpMethod::Unsupported, _) => send_response(405, "Method not allowed."),
        (_, Action::Invalid) => send_response(400, "Invalid action."),
        _ => send_response(400, "Bad request."),
    }
}

fn is_teliod_running() -> bool {
    if let Ok(pid) = fs::read_to_string(PathConfig::pid()) {
        if fs::metadata(format!("/proc/{}", pid.trim())).is_ok() {
            return true;
        }
    }
    false
}

fn send_response<T: serde::Serialize>(code: u16, message: T) {
    let response = json!({ "code": code, "message": message });
    println!("{}", response);
}

fn start_daemon() {
    if is_teliod_running() {
        send_response(400, "Application is already running.");
        return;
    }

    let teliod_log_file = match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(PathConfig::teliod_log())
    {
        Ok(file) => file,
        Err(_) => {
            send_response(500, "Failed to open teliod log file.");
            return;
        }
    };

    match Command::new("setsid")
        .arg(PathConfig::teliod_bin())
        .arg("daemon")
        .arg(PathConfig::teliod_cfg())
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
            if fs::write(PathConfig::pid(), pid.to_string()).is_ok() {
                send_response(200, "Application started successfully.");
            } else {
                send_response(500, "Failed to save PID.");
            }
        }
        Err(_) => send_response(500, "Failed to start the application."),
    }
}

fn stop_daemon() {
    if is_teliod_running() {
        if let Ok(pid) = fs::read_to_string(PathConfig::pid()) {
            if Command::new("kill").arg(pid.trim()).status().is_ok() {
                let _ = fs::remove_file(PathConfig::pid());
                send_response(200, "Application stopped successfully.");
            } else {
                send_response(500, "Failed to stop the application.");
            }
        }
    } else {
        send_response(400, "Application is not running.");
    }
}

// TODO: LLT-5712
fn update_config(_post_data: &str) {
    // match serde_json::from_str::<serde_json::Value>(post_data)
    //     .ok()
    //     .and_then(|json| json.get("config").and_then(|c| c.as_str()))
    // {
    //     Some(new_config) => {
    //         if fs::write(PathConfig::cfg(), new_config).is_ok() {
    //             send_response(200, "Configuration updated successfully.");
    //         } else {
    //             send_response(500, "Failed to update configuration.");
    //         }
    //     }
    //     None => send_response(400, "Invalid configuration data."),
    // }
}

fn get_status() {
    if is_teliod_running() {
        match Command::new(PathConfig::teliod_bin())
            .arg("get-status")
            .output()
        {
            Ok(output) => {
                let status = String::from_utf8_lossy(&output.stdout).to_string();
                send_response(200, json!({ "status-report": status }));
            }
            Err(_) => send_response(500, "Failed to retrieve status."),
        }
    } else {
        send_response(400, "Application is not running.");
    }
}

fn get_teliod_logs() {
    match fs::read_to_string(PathConfig::teliod_log()) {
        Ok(logs) => send_response(200, json!({ "teliod-logs": logs })),
        Err(_) => send_response(404, "Log file not found."),
    }
}

fn get_meshnet_logs() {
    match fs::read_to_string(PathConfig::meshnet_log()) {
        Ok(logs) => send_response(200, json!({ "meshnet-logs": logs })),
        Err(_) => send_response(404, "Log file not found."),
    }
}
