use core::str;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    process::{self, Command, Stdio},
};

use const_format::concatcp;
use rust_cgi::{http::Method, http::StatusCode, text_response, Request, Response};
use tracing::warn;

use crate::{
    command_listener::CommandResponse,
    config::{TeliodDaemonConfig, TeliodDaemonConfigPartial},
    ClientCmd, DaemonSocket, TeliodError, TIMEOUT_SEC,
};

const TELIOD_TMP_DIR: &str = "/tmp/nordsecuritymeshnet";
const PID_FILE: &str = concatcp!(TELIOD_TMP_DIR, "/teliod.pid");
const QPKG_DIR: &str = "/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet";
const TELIOD_BIN: &str = concatcp!(QPKG_DIR, "/teliod");
const MESHNET_LOG: &str = concatcp!(QPKG_DIR, "/meshnet.log");
const TELIOD_LOG: &str = "/var/log/teliod.log";

#[cfg(not(test))]
const TELIOD_CFG: &str = concatcp!(QPKG_DIR, "/teliod.cfg");
#[cfg(test)]
use tests::TELIOD_CFG;

pub struct PidFile;

impl PidFile {
    pub async fn new() -> Result<Self, TeliodError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(PID_FILE)?;
        writeln!(file, "{}", process::id())?;
        Ok(Self)
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(PID_FILE) {
            warn!("Failed to remove PID file: {}", e);
        }
    }
}

macro_rules! teliod_blocking_query {
    ($command:expr) => {{
        let socket_path = DaemonSocket::get_ipc_socket_path();
        futures::executor::block_on(tokio::time::timeout(
            std::time::Duration::from_secs(TIMEOUT_SEC),
            DaemonSocket::send_command(
                &socket_path.unwrap_or_default(),
                &serde_json::to_string(&$command).unwrap_or_default(),
            ),
        ))
    }};
}

pub(crate) fn handle_request(request: Request) -> Response {
    match (request.method(), request.uri().query()) {
        (&Method::POST, _) => start_daemon(),
        (&Method::DELETE, _) => stop_daemon(),
        (&Method::PATCH, _) => {
            let body = match str::from_utf8(request.body()) {
                Ok(body) => body,
                Err(error) => {
                    return text_response(
                        StatusCode::BAD_REQUEST,
                        format!("Invalid UTF-8 in request body: {}", error),
                    )
                }
            };
            update_config(body)
        }
        (&Method::GET, Some("info=get-status")) => get_status(),
        (&Method::GET, Some("info=get-teliod-logs")) => get_teliod_logs(),
        (&Method::GET, Some("info=get-meshnet-logs")) => get_meshnet_logs(),
        (_, _) => text_response(StatusCode::BAD_REQUEST, "Invalid request."),
    }
}

fn is_teliod_running() -> bool {
    matches!(teliod_blocking_query!(ClientCmd::GetStatus), Ok(Ok(_)))
}

fn kill_teliod_process() -> Result<(), io::Error> {
    match fs::read_to_string(PID_FILE) {
        Ok(pid) => {
            // result is ignored: trivial/nowhere to log
            let _ = Command::new("kill")
                .arg("-9")
                .arg(pid.trim())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            fs::remove_file(PID_FILE)
        }
        Err(e) => Err(e),
    }
}

fn start_daemon() -> Response {
    if is_teliod_running() {
        return text_response(StatusCode::BAD_REQUEST, "Application is already running.");
    }

    let mut teliod_log_file = match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(TELIOD_LOG)
    {
        Ok(file) => file,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to open teliod log file.",
            );
        }
    };
    let stdout = match teliod_log_file.try_clone() {
        Ok(file) => Stdio::from(file),
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start the application: {error}"),
            )
        }
    };
    let stderr = match teliod_log_file.try_clone() {
        Ok(file) => Stdio::from(file),
        Err(error) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start the application: {error}"),
            )
        }
    };
    match Command::new("setsid")
        .arg(TELIOD_BIN)
        .arg("daemon")
        .arg(TELIOD_CFG)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
    {
        Ok(process) => {
            let _ = teliod_log_file.write_all(format!("Process ID: {}\n", process.id()).as_bytes());
            text_response(StatusCode::CREATED, "Application started successfully.")
        }
        Err(error) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to start the application: {error}"),
        ),
    }
}

fn stop_daemon() -> Response {
    if is_teliod_running() {
        if kill_teliod_process().is_ok() {
            text_response(StatusCode::OK, "Application stopped successfully.")
        } else {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to stop the application.",
            )
        }
    } else {
        match kill_teliod_process() {
            Ok(_) => text_response(StatusCode::OK, "Application stopped successfully."),
            _ => text_response(StatusCode::GONE, "Application not found."),
        }
    }
}

fn update_config(body: &str) -> Response {
    let mut config: TeliodDaemonConfig = match fs::read_to_string(TELIOD_CFG)
        .and_then(|content| serde_json::from_str(&content).map_err(|e| e.into()))
    {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config file: {}", e);
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read existing config",
            );
        }
    };
    let updated_config = match serde_json::from_str::<TeliodDaemonConfigPartial>(body) {
        Ok(updates) => updates,
        Err(e) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON payload: {e}"),
            );
        }
    };

    config.update(updated_config);

    match fs::write(TELIOD_CFG, serde_json::to_string_pretty(&config).unwrap()) {
        Ok(_) => text_response(StatusCode::OK, "Configuration updated successfully"),
        Err(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to write updated config",
        ),
    }
}

fn get_status() -> Response {
    if !is_teliod_running() {
        return text_response(StatusCode::GONE, "Application is not running.");
    }

    match teliod_blocking_query!(ClientCmd::GetStatus) {
        Ok(Ok(daemon_reply)) => match CommandResponse::deserialize(&daemon_reply) {
            Ok(CommandResponse::StatusReport(status)) => text_response(
                StatusCode::OK,
                serde_json::to_string_pretty(&status).unwrap_or_default(),
            ),
            Ok(cmd_response) => text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unexpected Teliod response: {}", cmd_response.serialize()),
            ),
            Err(error) => text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to retrieve status: {}", error),
            ),
        },
        Ok(Err(error)) => text_response(
            StatusCode::GONE,
            format!("Failed to communicate with the daemon: {}", error),
        ),
        Err(error) => text_response(
            StatusCode::GATEWAY_TIMEOUT,
            format!("Failed to communicate with the daemon: {}", error),
        ),
    }
}

fn get_teliod_logs() -> Response {
    match fs::read_to_string(TELIOD_LOG) {
        Ok(logs) => text_response(StatusCode::OK, logs),
        Err(error) => text_response(
            StatusCode::BAD_GATEWAY,
            format!("Error reading teliod log file: {}", error),
        ),
    }
}

fn get_meshnet_logs() -> Response {
    match fs::read_to_string(MESHNET_LOG) {
        Ok(logs) => text_response(StatusCode::OK, logs),
        Err(error) => text_response(
            StatusCode::BAD_GATEWAY,
            format!("Error reading meshnet log file: {}", error),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, num::NonZeroU64, path::PathBuf};

    use reqwest::StatusCode;
    use serial_test::serial;
    use tracing::level_filters::LevelFilter;
    use uuid::Uuid;

    use super::{update_config, TeliodDaemonConfig};
    use crate::{
        config::{InterfaceConfig, MqttConfig, Percentage},
        configure_interface::InterfaceConfigurationProvider,
    };

    pub const TELIOD_CFG: &str = "/tmp/teliod_config.json";

    #[test]
    #[serial]
    fn test_update_config() {
        let mut expected_config = TeliodDaemonConfig {
            log_level: LevelFilter::DEBUG,
            log_file_path: "/path/to/log".to_owned(),
            interface: InterfaceConfig {
                name: "eth0".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
            app_user_uid: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
            authentication_token:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            http_certificate_file_path: Some(PathBuf::from("/http/certificate/path/")),
            mqtt: MqttConfig {
                backoff_initial: NonZeroU64::new(5).unwrap(),
                backoff_maximal: NonZeroU64::new(600).unwrap(),
                reconnect_after_expiry: Percentage(100),
                certificate_file_path: Some(PathBuf::from("some/certificate/path/")),
            },
        };
        let initial_config = r#"
        {
            "log_level": "debug",
            "log_file_path": "/path/to/log",
            "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "app_user_uid": "00000000-0000-0000-0000-000000000000",
            "interface": {
                "name": "eth0",
                "config_provider": "manual"
            },
            "http_certificate_file_path": "/http/certificate/path/",
            "mqtt": {
                "backoff_initial": 5,
                "backoff_maximal": 600,
                "reconnect_after_expiry": 100,
                "certificate_file_path": "some/certificate/path"
            }
        }
        "#;
        fs::write(TELIOD_CFG, initial_config).unwrap();

        let read_config =
            serde_json::from_str::<TeliodDaemonConfig>(&fs::read_to_string(TELIOD_CFG).unwrap())
                .unwrap();
        assert_eq!(read_config, expected_config);

        expected_config.log_level = LevelFilter::INFO;
        expected_config.log_file_path = "/new/path/to/log".to_owned();
        expected_config.authentication_token =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
        expected_config.app_user_uid =
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        expected_config.interface = InterfaceConfig {
            name: "eth1".to_owned(),
            config_provider: InterfaceConfigurationProvider::Ifconfig,
        };
        expected_config.http_certificate_file_path =
            Some(PathBuf::from("new/http/certificate/path/"));
        expected_config.mqtt = MqttConfig {
            certificate_file_path: Some(PathBuf::from("new/certificate/path/")),
            ..Default::default()
        };
        let update_body = r#"
        {
            "log_level": "info",
            "log_file_path": "/new/path/to/log",
            "authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "app_user_uid": "11111111-1111-1111-1111-111111111111",
            "interface": {
                "name": "eth1",
                "config_provider": "ifconfig"
            },
            "http_certificate_file_path": "new/http/certificate/path/",
            "mqtt": {
                "backoff_initial": 1,
                "backoff_maximal": 300,
                "reconnect_after_expiry": 90,
                "certificate_file_path": "new/certificate/path"
            }
        }
        "#;
        assert_eq!(update_config(update_body).status(), StatusCode::OK);

        let updated_config: TeliodDaemonConfig =
            serde_json::from_str(&fs::read_to_string(TELIOD_CFG).unwrap()).unwrap();
        assert_eq!(updated_config, expected_config);
    }

    #[test]
    #[serial]
    fn test_update_partial_config() {
        let mut expected_config = TeliodDaemonConfig {
            log_level: LevelFilter::DEBUG,
            log_file_path: "/path/to/log".to_owned(),
            interface: InterfaceConfig {
                name: "eth0".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
            app_user_uid: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
            authentication_token:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            http_certificate_file_path: Some(PathBuf::from("/http/certificate/path/")),
            mqtt: MqttConfig::default(),
        };
        let initial_config = r#"
        {
            "log_level": "debug",
            "log_file_path": "/path/to/log",
            "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "app_user_uid": "00000000-0000-0000-0000-000000000000",
            "interface": {
                "name": "eth0",
                "config_provider": "manual"
            },
            "http_certificate_file_path": "/http/certificate/path/",
            "mqtt": {
                "backoff_initial": 1,
                "backoff_maximal": 300,
                "reconnect_after_expiry": 90,
                "certificate_file_path": null
            }
        }
        "#;
        fs::write(TELIOD_CFG, initial_config).unwrap();

        let read_config =
            serde_json::from_str::<TeliodDaemonConfig>(&fs::read_to_string(TELIOD_CFG).unwrap())
                .unwrap();
        assert_eq!(read_config, expected_config);

        expected_config.interface.name = "eth1".to_owned();
        expected_config.interface.config_provider = InterfaceConfigurationProvider::Ifconfig;
        let update_body = r#"
        {
            "interface": {
                "name": "eth1",
                "config_provider": "ifconfig"
            }
        }
        "#;
        assert_eq!(update_config(update_body).status(), StatusCode::OK);

        let updated_config =
            serde_json::from_str::<TeliodDaemonConfig>(&fs::read_to_string(TELIOD_CFG).unwrap())
                .unwrap();
        assert_eq!(updated_config, expected_config);

        expected_config.authentication_token =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
        let update_body = r#"
        {
            "authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
        "#;
        assert_eq!(update_config(update_body).status(), StatusCode::OK);

        let updated_config =
            serde_json::from_str::<TeliodDaemonConfig>(&fs::read_to_string(TELIOD_CFG).unwrap())
                .unwrap();
        assert_eq!(updated_config, expected_config);
    }
}
