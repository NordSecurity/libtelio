use std::{
    fs, io,
    process::{Command, Stdio},
    str,
    thread::sleep,
    time::Duration,
};

use rust_cgi::{
    http::{Method, StatusCode},
    text_response, Response,
};

use crate::{
    command_listener::CommandResponse,
    config::{TeliodDaemonConfig, TeliodDaemonConfigPartial},
    ClientCmd, DaemonSocket, TelioStatusReport, TeliodError, TIMEOUT_SEC,
};

use super::{
    constants::{MESHNET_LOG, TELIOD_BIN, TELIOD_CFG, TELIOD_LOG},
    CgiRequest,
};

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

pub(crate) fn handle_api(request: &CgiRequest) -> Option<Response> {
    match (request.method(), request.route()) {
        (&Method::POST, "" | "/") => {
            let (status_code, body) = start_daemon();
            Some(text_response(status_code, body))
        }
        (&Method::DELETE, "" | "/") => {
            let (status_code, body) = stop_daemon();
            Some(text_response(status_code, body))
        }

        (&Method::PATCH, "" | "/") => {
            let body = match str::from_utf8(request.body()) {
                Ok(body) => body,
                Err(error) => {
                    return Some(text_response(
                        StatusCode::BAD_REQUEST,
                        format!("Invalid UTF-8 in request body: {}", error),
                    ))
                }
            };
            Some(update_config(body))
        }
        (&Method::GET, "/get-status") => Some(get_status()),
        (&Method::GET, "/get-teliod-logs") => Some(get_teliod_logs()),
        (&Method::GET, "/get-meshnet-logs") => Some(get_meshnet_logs()),
        (_, _) => Some(text_response(
            StatusCode::NOT_FOUND,
            "Non-existing endpoint",
        )),
    }
}

pub(crate) fn is_teliod_running() -> bool {
    matches!(teliod_blocking_query!(ClientCmd::IsAlive), Ok(Ok(_)))
}

fn shutdown_teliod() -> Result<(), TeliodError> {
    if let Ok(Ok(daemon_reply)) = teliod_blocking_query!(ClientCmd::QuitDaemon) {
        if CommandResponse::deserialize(&daemon_reply)
            .is_ok_and(|response| response == CommandResponse::Ok)
        {
            return Ok(());
        }
    }
    Err(TeliodError::ClientTimeoutError)
}

pub(crate) fn start_daemon() -> (StatusCode, String) {
    if is_teliod_running() {
        return (
            StatusCode::BAD_REQUEST,
            "Application is already running.".to_string(),
        );
    }

    let teliod_log_file = match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .open(TELIOD_LOG)
    {
        Ok(file) => file,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to open teliod log file {TELIOD_LOG}, err: {err}"),
            );
        }
    };
    let stdout = match teliod_log_file.try_clone() {
        Ok(file) => Stdio::from(file),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start the application: {error}"),
            )
        }
    };
    let stderr = match teliod_log_file.try_clone() {
        Ok(file) => Stdio::from(file),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start the application: {error}"),
            )
        }
    };
    match Command::new("setsid")
        .arg(TELIOD_BIN)
        .arg("start")
        .arg("--no-detach")
        .arg(TELIOD_CFG)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
    {
        Ok(_process) => {
            // Wait for teliod to become available
            for _ in 0..10 {
                if is_teliod_running() {
                    return (
                        StatusCode::CREATED,
                        "Application started successfully.".to_string(),
                    );
                }
                sleep(Duration::from_millis(500));
            }

            (
                StatusCode::REQUEST_TIMEOUT,
                "Failed to start the application, check logs.".to_string(),
            )
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to start the application: {error}"),
        ),
    }
}

pub(crate) fn stop_daemon() -> (StatusCode, String) {
    match shutdown_teliod() {
        Ok(_) => (
            StatusCode::OK,
            "Application stopped successfully.".to_string(),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to stop application: {error}"),
        ),
    }
}

pub(crate) fn get_config() -> io::Result<TeliodDaemonConfig> {
    fs::read_to_string(TELIOD_CFG)
        .and_then(|content| serde_json::from_str(&content).map_err(|e| e.into()))
}

pub(crate) fn update_config(body: &str) -> Response {
    let mut config: TeliodDaemonConfig = match get_config() {
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

    match fs::write(
        TELIOD_CFG,
        serde_json::to_string_pretty(&config).unwrap_or_default(),
    ) {
        Ok(_) => text_response(StatusCode::OK, "Configuration updated successfully"),
        Err(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to write updated config",
        ),
    }
}

pub(crate) fn get_status_report() -> Result<TelioStatusReport, TeliodError> {
    let msg = teliod_blocking_query!(ClientCmd::GetStatus)
        .map_err(|_| TeliodError::ClientTimeoutError)??;

    match CommandResponse::deserialize(&msg)? {
        CommandResponse::Ok => Err(TeliodError::InvalidResponse("Expected status".to_string())),
        CommandResponse::StatusReport(status) => Ok(status),
        CommandResponse::Err(err) => Err(TeliodError::InvalidResponse(err)),
    }
}

fn get_status() -> Response {
    if !is_teliod_running() {
        return text_response(StatusCode::GONE, "Application is not running.");
    }

    // TODO(pna): use get_status_report, add logic to convert TeliodError into Response

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
    use telio::device::AdapterType;
    use tracing::level_filters::LevelFilter;

    use super::{update_config, TeliodDaemonConfig};
    use crate::{
        cgi::constants::TELIOD_CFG,
        config::{InterfaceConfig, MqttConfig, Percentage},
        configure_interface::InterfaceConfigurationProvider,
    };

    #[test]
    #[serial]
    fn test_update_config() {
        let mut expected_config = TeliodDaemonConfig {
            log_level: LevelFilter::DEBUG,
            log_file_path: "/path/to/log".to_owned(),
            log_file_count: 7,
            adapter_type: AdapterType::NepTUN,
            interface: InterfaceConfig {
                name: "eth0".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
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
            "adapter_type": "neptun",
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
        expected_config.log_file_count = 8;
        expected_config.authentication_token =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
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
            "log_file_count": 8,
            "authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "adapter_type": "neptun",
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
            log_file_count: 7,
            adapter_type: AdapterType::NepTUN,
            interface: InterfaceConfig {
                name: "eth0".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
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
            "adapter_type": "neptun",
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
