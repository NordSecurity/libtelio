use std::{
    fs, io,
    path::{Path, PathBuf},
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
    constants::{APP_PATHS, LOG_PATHS},
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
                        format!("Invalid UTF-8 in request body: {error}"),
                    ))
                }
            };
            Some(update_config(body))
        }
        (&Method::GET, "/get-status") => Some(get_status()),
        (&Method::GET, "/get-logs") => {
            let mut days_count = 2;

            // Parse query string
            // /get-logs?days_count=2
            if let Some(query) = request.uri().query() {
                for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                    if key == "days_count" {
                        if let Ok(parsed) = value.parse::<usize>() {
                            days_count = parsed;
                        }
                    }
                }
            }

            Some(get_logs(
                days_count,
                LOG_PATHS.daemon_log(),
                LOG_PATHS.daemon_init_log(),
                LOG_PATHS.dir(),
            ))
        }
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

    let teliod_init_log_file = match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .open(LOG_PATHS.daemon_init_log())
    {
        Ok(file) => file,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to open teliod log file {:?}, err: {err}",
                    LOG_PATHS.daemon_init_log()
                ),
            );
        }
    };
    let stdout = match teliod_init_log_file.try_clone() {
        Ok(file) => Stdio::from(file),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start the application: {error}"),
            )
        }
    };
    let stderr = match teliod_init_log_file.try_clone() {
        Ok(file) => Stdio::from(file),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start the application: {error}"),
            )
        }
    };

    // Teliod runs as a daemon and doesn't report errors to the caller.
    // Logs must be checked manually for errors.
    // As a quick QoL improvement, we validate the config and auth tokens early
    // to provide immediate feedback instead of waiting for `teliod` to show up in the process list.
    match get_config() {
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read config file: {e:?}"),
            );
        }
        Ok(cfg) => {
            if cfg.authentication_token.is_empty() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication token not set".to_string(),
                );
            }
        }
    }

    match Command::new(APP_PATHS.teliod_bin())
        .arg("start")
        .arg(APP_PATHS.teliod_cfg())
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
                "Failed to start the application. Please check the logs or visit https://support.nordvpn.com".to_string(),
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
    fs::read_to_string(APP_PATHS.teliod_cfg())
        .and_then(|content| serde_json::from_str(&content).map_err(|e| e.into()))
}

pub(crate) fn update_config(body: &str) -> Response {
    let mut config: TeliodDaemonConfig = match get_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config file: {e}");
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

    if let Err(e) = config.update(updated_config) {
        return text_response(
            StatusCode::BAD_REQUEST,
            format!("Invalid config value: {e}"),
        );
    };

    match fs::write(
        APP_PATHS.teliod_cfg(),
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
                format!("Failed to retrieve status: {error}"),
            ),
        },
        Ok(Err(error)) => text_response(
            StatusCode::GONE,
            format!("Failed to communicate with the daemon: {error}"),
        ),
        Err(error) => text_response(
            StatusCode::GATEWAY_TIMEOUT,
            format!("Failed to communicate with the daemon: {error}"),
        ),
    }
}

fn get_logs(
    days_count: usize,
    init_log_path: &Path,
    stdout_log_path: &Path,
    logs_dir: &Path,
) -> Response {
    let mut concatenated_logs = String::new();

    // Helper to append an error
    let append_log_error = |logs: &mut String, content: &str| {
        logs.push_str(&format!("--- Logs Error ---\n{content}\n"))
    };

    // Helper to append a section
    let append_log_section =
        |logs: &mut String, label: &str, path: &Path| match fs::read_to_string(path) {
            Ok(content) => {
                logs.push_str(&format!("--- {label} ---\n\n{content}\n"));
            }
            Err(err) => {
                append_log_error(
                    logs,
                    &format!("Error reading log file {}: {}", path.to_string_lossy(), err),
                );
            }
        };

    // gather init and stdout logs
    append_log_section(&mut concatenated_logs, "init", init_log_path);
    append_log_section(&mut concatenated_logs, "stdout", stdout_log_path);

    // Due to log rotation, teliod lib logs have the format of
    // teliod_lib.log.YYYY_MM_DD, we collect all the files that start with teliod_lib.log
    // from `logs_dir` and sort by name to get the latest one, as a fall back if log rotation is
    // disabled, it will return teliod_lib.log file without the date suffix.
    let mut log_files: Vec<PathBuf> = match fs::read_dir(logs_dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with(LOG_PATHS.prefix()))
                        .unwrap_or(false)
            })
            .collect(),
        Err(err) => {
            append_log_error(
                &mut concatenated_logs,
                &format!(
                    "Failed to read log directory {}: {}",
                    logs_dir.to_string_lossy(),
                    err
                ),
            );
            return text_response(StatusCode::OK, concatenated_logs);
        }
    };

    // Sort by filename (aka date)
    log_files.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

    if log_files.is_empty() {
        append_log_error(
            &mut concatenated_logs,
            &format!(
                "No teliod log files {} found in: {}",
                LOG_PATHS.prefix(),
                logs_dir.to_string_lossy()
            ),
        );
    }

    // Concatenate the lib logs, but only up to days_count
    for path in log_files.iter().take(days_count) {
        let path_str = path.to_string_lossy();
        append_log_section(&mut concatenated_logs, &path_str, path.as_path());
    }

    if concatenated_logs.is_empty() {
        // This should never be empty, but just in case
        text_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve logs")
    } else {
        text_response(StatusCode::OK, concatenated_logs)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, num::NonZeroU64, path::PathBuf, sync::Arc};

    use reqwest::StatusCode;
    use serial_test::serial;
    use telio::device::AdapterType;
    use temp_dir::TempDir;
    use tracing::level_filters::LevelFilter;

    use super::*;
    use crate::{
        config::{InterfaceConfig, MqttConfig, Percentage},
        configure_interface::InterfaceConfigurationProvider,
    };

    #[test]
    #[serial]
    fn test_update_config() {
        let res = APP_PATHS.init();
        if let Err(e) = res {
            assert_eq!(
                e.to_string(),
                "Failed executing system command: \"AppPaths already initialized\""
            );
        }

        let mut expected_config = TeliodDaemonConfig {
            log_level: LevelFilter::DEBUG,
            log_file_path: APP_PATHS.join("test.log").to_string_lossy().into_owned(),
            log_file_count: 7,
            adapter_type: AdapterType::NepTUN,
            interface: InterfaceConfig {
                name: "eth0".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
            vpn: None,
            authentication_token: Arc::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned()
                    .into(),
            ),
            http_certificate_file_path: Some(PathBuf::from("/http/certificate/path/")),
            device_identity_file_path: None,
            mqtt: MqttConfig {
                backoff_initial: NonZeroU64::new(5).unwrap(),
                backoff_maximal: NonZeroU64::new(600).unwrap(),
                reconnect_after_expiry: Percentage(100),
                certificate_file_path: Some(PathBuf::from("some/certificate/path/")),
            },
        };
        let initial_config = format!(
            r#"
            {{
                "log_level": "debug",
                "log_file_path": "{}",
                "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "adapter_type": "neptun",
                "interface": {{
                    "name": "eth0",
                    "config_provider": "manual"
                }},
                "http_certificate_file_path": "/http/certificate/path/",
                "mqtt": {{
                    "backoff_initial": 5,
                    "backoff_maximal": 600,
                    "reconnect_after_expiry": 100,
                    "certificate_file_path": "some/certificate/path"
                }}
            }}
            "#,
            APP_PATHS.join("test.log").to_string_lossy()
        );
        fs::write(APP_PATHS.teliod_cfg(), initial_config).unwrap();

        let read_config = serde_json::from_str::<TeliodDaemonConfig>(
            &fs::read_to_string(APP_PATHS.teliod_cfg()).unwrap(),
        )
        .unwrap();
        assert_eq!(read_config, expected_config);

        expected_config.log_level = LevelFilter::INFO;
        expected_config.log_file_path = LOG_PATHS.log().to_string_lossy().into_owned();
        expected_config.log_file_count = 8;
        expected_config.authentication_token = Arc::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned()
                .into(),
        );
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
        let update_body = format!(
            r#"
            {{
                "log_level": "info",
                "log_file_path": "{}",
                "log_file_count": 8,
                "authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "adapter_type": "neptun",
                "interface": {{
                    "name": "eth1",
                    "config_provider": "ifconfig"
                }},
                "http_certificate_file_path": "new/http/certificate/path/",
                "mqtt": {{
                    "backoff_initial": 1,
                    "backoff_maximal": 300,
                    "reconnect_after_expiry": 90,
                    "certificate_file_path": "new/certificate/path"
                }}
            }}
            "#,
            LOG_PATHS.log().to_string_lossy()
        );
        assert_eq!(update_config(&update_body).status(), StatusCode::OK);

        let updated_config: TeliodDaemonConfig =
            serde_json::from_str(&fs::read_to_string(APP_PATHS.teliod_cfg()).unwrap()).unwrap();
        assert_eq!(updated_config, expected_config);
    }

    #[test]
    #[serial]
    fn test_update_partial_config() {
        let res = APP_PATHS.init();
        if let Err(e) = res {
            assert_eq!(
                e.to_string(),
                "Failed executing system command: \"AppPaths already initialized\""
            );
        }

        let mut expected_config = TeliodDaemonConfig {
            log_level: LevelFilter::DEBUG,
            log_file_path: APP_PATHS.join("test.log").to_string_lossy().into_owned(),
            log_file_count: 7,
            adapter_type: AdapterType::NepTUN,
            interface: InterfaceConfig {
                name: "eth0".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
            vpn: None,
            authentication_token: Arc::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned()
                    .into(),
            ),
            http_certificate_file_path: Some(PathBuf::from("/http/certificate/path/")),
            device_identity_file_path: None,
            mqtt: MqttConfig::default(),
        };
        let initial_config = format!(
            r#"
            {{
                "log_level": "debug",
                "log_file_path": "{}",
                "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "adapter_type": "neptun",
                "interface": {{
                    "name": "eth0",
                    "config_provider": "manual"
                }},
                "http_certificate_file_path": "/http/certificate/path/",
                "mqtt": {{
                    "backoff_initial": 1,
                    "backoff_maximal": 300,
                    "reconnect_after_expiry": 90,
                    "certificate_file_path": null
                }}
            }}"#,
            APP_PATHS.join("test.log").to_string_lossy()
        );
        fs::write(APP_PATHS.teliod_cfg(), initial_config).unwrap();

        let read_config = serde_json::from_str::<TeliodDaemonConfig>(
            &fs::read_to_string(APP_PATHS.teliod_cfg()).unwrap(),
        )
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

        let updated_config = serde_json::from_str::<TeliodDaemonConfig>(
            &fs::read_to_string(APP_PATHS.teliod_cfg()).unwrap(),
        )
        .unwrap();
        assert_eq!(updated_config, expected_config);

        expected_config.authentication_token = Arc::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned()
                .into(),
        );
        let update_body = r#"
        {
            "authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
        "#;
        assert_eq!(update_config(update_body).status(), StatusCode::OK);

        let updated_config = serde_json::from_str::<TeliodDaemonConfig>(
            &fs::read_to_string(APP_PATHS.teliod_cfg()).unwrap(),
        )
        .unwrap();
        assert_eq!(updated_config, expected_config);
    }

    #[test]
    fn test_get_logs_valid_files() {
        let dir = TempDir::new().unwrap();
        let log_dir_path = dir.path().to_path_buf();

        let init_log = log_dir_path.join("teliod_init.log");
        let stdout_log = log_dir_path.join("teliod_stdout.log");
        fs::write(&init_log, "init log content").unwrap();
        fs::write(&stdout_log, "stdout log content").unwrap();

        for i in 0..3 {
            let rotated_log = log_dir_path.join(format!("teliod_lib.log.2024_05_0{}", i + 1));
            fs::write(rotated_log, format!("rotated log {}", i + 1)).unwrap();
        }

        let response = get_logs(2, &init_log, &stdout_log, &log_dir_path);

        assert_eq!(response.status(), StatusCode::OK);
        let text = String::from_utf8_lossy(response.body());
        assert!(text.contains("init log content"));
        assert!(text.contains("stdout log content"));
        assert!(text.contains("rotated log 3")); // newest first
        assert!(text.contains("rotated log 2"));
        // not included
        assert!(!text.contains("rotated log 1"));
    }

    #[test]
    fn test_get_logs_missing_files() {
        let dir = TempDir::new().unwrap();
        let log_dir_path = dir.path().to_path_buf();

        let init_log = log_dir_path.join("teliod_init.log");
        let stdout_log = log_dir_path.join("teliod_stdout.log");
        fs::write(&init_log, "init log content").unwrap();
        fs::write(&stdout_log, "stdout log content").unwrap();

        let response = get_logs(1, &init_log, &stdout_log, &log_dir_path);

        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("No teliod log files"));
    }

    #[test]
    fn test_get_logs_no_files() {
        let dir = TempDir::new().unwrap();
        let log_dir_path = dir.path().to_path_buf();

        let init_log = log_dir_path.join("teliod_init.log");
        let stdout_log = log_dir_path.join("teliod_stdout.log");
        fs::write(&init_log, "init log content").unwrap();
        fs::write(&stdout_log, "stdout log content").unwrap();

        for i in 0..3 {
            let rotated_log = log_dir_path.join(format!("teliod_lib.log.2024_05_0{}", i + 1));
            fs::write(rotated_log, format!("rotated log {}", i + 1)).unwrap();
        }

        let response = get_logs(0, &init_log, &stdout_log, &log_dir_path);

        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("init log content"));
        assert!(body.contains("stdout log content"));
        // not included
        assert!(!body.contains("rotated log 3"));
        assert!(!body.contains("rotated log 2"));
        assert!(!body.contains("rotated log 1"));
    }

    #[test]
    fn test_missing_init_log() {
        let dir = TempDir::new().unwrap();
        let log_dir_path = dir.path().to_path_buf();

        let init_log = log_dir_path.join("teliod_init.log");
        let stdout_log = log_dir_path.join("teliod_stdout.log");
        fs::write(&stdout_log, "stdout log content").unwrap();

        let response = get_logs(1, &init_log, &stdout_log, &log_dir_path);

        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("Error reading log file"));
    }

    #[test]
    fn test_missing_log_dir() {
        let dir = TempDir::new().unwrap();
        let log_dir_path = dir.path().to_path_buf();

        let fake_log_dir_path = Path::new("/something/made/up");

        let init_log = log_dir_path.join("teliod_init.log");
        let stdout_log = log_dir_path.join("teliod_stdout.log");
        fs::write(&init_log, "init log content").unwrap();
        fs::write(&stdout_log, "stdout log content").unwrap();

        let response = get_logs(1, &init_log, &stdout_log, fake_log_dir_path);

        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("Failed to read log directory"));
    }

    #[test]
    fn test_missing_all_logs() {
        let fake_init_log = Path::new("/made/up/init");
        let fake_stdout_log = Path::new("/made/up/stdout");
        let fake_log_dir_path = Path::new("/something/made/up");

        let response = get_logs(1, fake_init_log, fake_stdout_log, fake_log_dir_path);

        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("Error reading log file"));
        assert!(body.contains("Failed to read log directory"));
    }
}
