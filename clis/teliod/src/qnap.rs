use std::{
    fs, io, path::PathBuf, process::{Command, Stdio}, time::Duration
};

use const_format::concatcp;
use rust_cgi::{http::Method, text_response, Request, Response};
use tracing::level_filters::LevelFilter;
use uuid::Uuid;

use crate::{
    command_listener::CommandResponse, config::{InterfaceConfig, MqttConfig, TeliodDaemonConfig}, DaemonSocket, TIMEOUT_SEC
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

pub(crate) fn handle_request(request: Request) -> Response {
    match (request.method(), request.uri().query()) {
        (&Method::POST, Some("action=start")) => start_daemon(),
        (&Method::POST, Some("action=stop")) => stop_daemon(),
        (&Method::PATCH, Some(action)) => {
            if !action.starts_with("action=update-config") {
                text_response(400, "Invalid request.")
            } else {
                let body = match String::from_utf8(request.into_body()) {
                    Ok(body) => body,
                    Err(_) => return text_response(400, "Invalid UTF-8 in request body."),
                };
                update_config(&body)
            }
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

fn update_config(body: &str) -> Response {
    let mut config: TeliodDaemonConfig = match fs::read_to_string(TELIOD_CFG)
        .and_then(|content| serde_json::from_str(&content).map_err(|e| e.into()))
    {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config file: {}", e);
            return text_response(500, "Failed to read existing config");
        }
    };

    let update_values: serde_json::Value = match serde_json::from_str(body) {
        Ok(updates) => updates,
        Err(e) => {
            eprintln!("Error parsing config json: {}", e);
            return text_response(400, "Invalid JSON payload");
        }
    };

    if let serde_json::Value::Object(update_map) = update_values {
        for (key, value) in update_map {
            match key.as_str() {
                "log_level" => {
                    if let Some(log_level_str) = value.as_str() {
                        if let Ok(log_level) = log_level_str.parse::<LevelFilter>() {
                            config.log_level = log_level;
                        }
                    }
                }
                "log_file_path" => {
                    if let Some(log_file_path) = value.as_str() {
                        config.log_file_path = log_file_path.to_string();
                    }
                }
                "authentication_token" => {
                    if let Some(auth_token) = value.as_str() {
                        config.authentication_token = auth_token.to_string();
                    }
                }
                "app_user_uid" => {
                    if let Some(uid_str) = value.as_str() {
                        if let Ok(uid) = Uuid::parse_str(uid_str) {
                            config.app_user_uid = uid;
                        }
                    }
                }
                "interface" => {
                    if let Ok(interface) = serde_json::from_value::<InterfaceConfig>(value) {
                        config.interface = interface;
                    }
                }
                "http_certificate_file_path" => {
                    if value.is_null() {
                        config.http_certificate_file_path = None;
                    } else if let Some(path_str) = value.as_str() {
                        config.http_certificate_file_path = Some(PathBuf::from(path_str));
                    }
                }
                "mqtt" => {
                    if let Ok(mqtt_config) = serde_json::from_value::<MqttConfig>(value) {
                        config.mqtt = mqtt_config;
                    }
                }
                _ => {}
            }
        }
    } else {
        return text_response(400, "Invalid JSON format");
    }

    match fs::write(TELIOD_CFG, serde_json::to_string_pretty(&config).unwrap()) {
        Ok(_) => text_response(200, "Configuration updated successfully"),
        Err(_) => text_response(500, "Failed to write updated config"),
    }
}

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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};
    use tracing::level_filters::LevelFilter;
    use uuid::Uuid;

    use super::{update_config, MqttConfig, TeliodDaemonConfig};
    use crate::configure_interface::InterfaceConfigurationProvider;

    pub const TELIOD_CFG: &str = "/tmp/teliod_config.json";

    #[test]
    fn test_update_config() {
        let initial_config = r#"
        {
            "log_level": "debug",
            "log_file_path": "/path/to/log",
            "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "app_user_uid": "00000000-0000-0000-0000-000000000000",
            "interface": {
                "name": "eth0",
                "config_provider": "manual"
            }
        }
        "#;
        fs::write(TELIOD_CFG, initial_config).unwrap();

        let update_body = r#"
        {
            "log_level": "info",
            "log_file_path": "/new/path/to/log",
            "authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "app_user_uid": "11111111-1111-1111-1111-111111111111",
            "interface": {
                "name": "eth1",
                "config_provider": "ifconfig"
            }
        }
        "#;

        let response = update_config(update_body);
        assert_eq!(response.status(), 200);

        let updated_config: TeliodDaemonConfig =
            serde_json::from_str(&fs::read_to_string(TELIOD_CFG).unwrap()).unwrap();

        assert_eq!(
            updated_config.log_level,
            tracing::level_filters::LevelFilter::INFO
        );
        assert_eq!(updated_config.log_file_path, "/new/path/to/log");
        assert_eq!(
            updated_config.authentication_token,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            updated_config.app_user_uid,
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
        );
        assert_eq!(updated_config.interface.name, "eth1");
        assert_eq!(
            updated_config.interface.config_provider,
            InterfaceConfigurationProvider::Ifconfig
        );
        assert_eq!(updated_config.http_certificate_file_path, None);
        let mqtt_default_cfg = MqttConfig::default();
        assert_eq!(
            updated_config.mqtt.backoff_initial,
            mqtt_default_cfg.backoff_initial
        );
        assert_eq!(
            updated_config.mqtt.backoff_maximal,
            mqtt_default_cfg.backoff_maximal
        );
        assert_eq!(
            updated_config.mqtt.reconnect_after_expiry,
            mqtt_default_cfg.reconnect_after_expiry
        );
        assert_eq!(
            updated_config.mqtt.certificate_file_path,
            mqtt_default_cfg.certificate_file_path
        );
    }

    #[test]
    fn test_update_config_auth_token_only() {
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
            "http_certificate_file_path": "/http/certificate/path/"
        }
        "#;
        fs::write(TELIOD_CFG, initial_config).unwrap();

        let update_body = r#"
        {
            "authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
        "#;

        let response = update_config(update_body);
        assert_eq!(response.status(), 200);

        let updated_config: TeliodDaemonConfig =
            serde_json::from_str(&fs::read_to_string(TELIOD_CFG).unwrap()).unwrap();

        assert_eq!(updated_config.log_level, LevelFilter::DEBUG);
        assert_eq!(updated_config.log_file_path, "/path/to/log");
        assert_eq!(
            updated_config.authentication_token,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            updated_config.app_user_uid,
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
        );
        assert_eq!(updated_config.interface.name, "eth0");
        assert_eq!(
            updated_config.interface.config_provider,
            InterfaceConfigurationProvider::Manual
        );
        assert_eq!(
            updated_config.http_certificate_file_path,
            Some(PathBuf::from("/http/certificate/path/"))
        );
        let mqtt_default_cfg = MqttConfig::default();
        assert_eq!(
            updated_config.mqtt.backoff_initial,
            mqtt_default_cfg.backoff_initial
        );
        assert_eq!(
            updated_config.mqtt.backoff_maximal,
            mqtt_default_cfg.backoff_maximal
        );
        assert_eq!(
            updated_config.mqtt.reconnect_after_expiry,
            mqtt_default_cfg.reconnect_after_expiry
        );
        assert_eq!(
            updated_config.mqtt.certificate_file_path,
            mqtt_default_cfg.certificate_file_path
        );
    }
}
