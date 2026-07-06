//! Main and implementation of config and commands for Nord VPN Lite - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use daemonize::{Daemonize, Outcome};
use std::fs::{self, OpenOptions};
use tokio::time::{timeout, Duration};

mod auth;
mod command_listener;
mod comms;
mod config;
mod core_api;
mod daemon;
mod interface;
mod logging;

use crate::{
    auth::{NordToken, NordVpnLiteAuth},
    command_listener::{ClientCmd, Cmd, CommandResponse, LoginOpts, LogoutOpts, TIMEOUT_SEC},
    comms::DaemonSocket,
    config::{NordVpnLiteConfig, RunningConfig},
    core_api::get_countries_with_exp_backoff,
    daemon::NordVpnLiteError,
};

/// Umask allows only rw-rw-r--
const DEFAULT_UMASK: u32 = 0o113;

/// Default permissions for created files.
const DEFAULT_FILE_PERMISSIONS: u32 = 0o640;

fn main() -> Result<(), NordVpnLiteError> {
    let mut cmd = Cmd::parse();

    // Pre-daemonizing setup
    if let Cmd::Start(opts) = &mut cmd {
        // Check if daemon already is running before forking
        if DaemonSocket::get_ipc_socket_path()?.exists() {
            return Err(NordVpnLiteError::DaemonIsRunning);
        }

        // Parse config file
        let mut config = RunningConfig::from_file(&opts.config_path)?;

        // Migrate config format if it contains an authentication token
        config.migrate_config_format(&opts.config_path)?;

        // Make sure authentication token is configured
        // Could be provided via environment variable or auth file
        // Environment variables have precedence over the auth file
        config.parsed.check_auth_token()?;

        println!("Saving logs to: {}", config.parsed.log_file_path);
        println!("Starting daemon");

        // Fork the process before starting Tokio runtime.
        // Tokio creates a multi-threaded asynchronous runtime,
        // but during forking only a single thread survives,
        // leaving tokio runtime in an undefined state and resulting in a panic.
        // https://github.com/tokio-rs/tokio/issues/4301
        if !opts.no_detach {
            // Redirect stdout and stderr to a specified file or /var/log/nordvpnlite.log by default
            let stdout_log_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&opts.stdout_path)?;

            // Daemon working directory is set to `/` by default
            // any relative path operations from now on could fail
            let daemon = Daemonize::new()
                .umask(DEFAULT_UMASK)
                .working_directory(&opts.working_directory)
                .stdout(stdout_log_file.try_clone()?)
                .stderr(stdout_log_file);

            // Daemonize the process
            match daemon.execute() {
                // Quit parent process
                Outcome::Parent(Ok(_)) => {
                    return Ok(());
                }
                // Continue in child process
                Outcome::Child(Ok(_)) => {}
                // Errors
                Outcome::Parent(Err(err)) => {
                    eprintln!("Fork parent error: {err}");
                    return Err(err.into());
                }
                Outcome::Child(Err(err)) => {
                    eprintln!("Child error {err}");
                    return Err(err.into());
                }
            }
        }

        let mut logging_handle = logging::setup_logging(
            &config.parsed.log_file_path,
            config.parsed.log_level,
            config.parsed.log_file_count,
        )?;

        // Run the daemon event loop.
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(daemon::daemon_event_loop(config, &mut logging_handle))
    } else {
        client_main(cmd)
    }
}

#[tokio::main]
async fn client_main(cmd: Cmd) -> Result<(), NordVpnLiteError> {
    match cmd {
        Cmd::Client(cmd) => {
            let socket_path = DaemonSocket::get_ipc_socket_path()?;
            if socket_path.exists() {
                let response = timeout(
                    Duration::from_secs(TIMEOUT_SEC),
                    DaemonSocket::send_command(&socket_path, &serde_json::to_string(&cmd)?),
                )
                .await
                .map_err(|_| NordVpnLiteError::ClientTimeoutError)?;

                match CommandResponse::deserialize(&response?)? {
                    CommandResponse::Ok => {
                        println!("Command executed successfully");
                        Ok(())
                    }
                    CommandResponse::StatusReport(status) => {
                        println!("{}", serde_json::to_string_pretty(&status)?);
                        Ok(())
                    }
                    CommandResponse::DaemonInitializing => {
                        println!("Daemon is not ready, ignoring");
                        Err(NordVpnLiteError::CommandFailed(cmd))
                    }
                    CommandResponse::Err(e) => {
                        println!("Command executed failed: {e}");
                        Err(NordVpnLiteError::CommandFailed(cmd))
                    }
                }
            } else {
                match cmd {
                    ClientCmd::QuitDaemon => {
                        println!("Daemon is already stopped");
                        Ok(())
                    }
                    _ => Err(NordVpnLiteError::DaemonIsNotRunning),
                }
            }
        }
        // Display list of available countries with VPN servers
        Cmd::Countries => {
            for country in get_countries_with_exp_backoff(None).await? {
                println!("{}: {}", country.name, country.code);
            }
            Ok(())
        }
        // Handle login command
        Cmd::Login(opts) => handle_login(opts),
        // Handle logout command
        Cmd::Logout(opts) => handle_logout(opts),

        // Unexpected command, Cmd::Start should be handled by main
        _ => Err(NordVpnLiteError::InvalidCommand(format!("{cmd:?}"))),
    }
}

/// Store NordVPN authentication credentials in the auth file.
///
/// The token is validated before the config is read, then written to the
/// auth file, overwriting any previously stored credentials.
fn handle_login(opts: LoginOpts) -> Result<(), NordVpnLiteError> {
    println!("Storing NordVPN authentication credentials");

    let token = NordToken::new(opts.token())?;

    let config = NordVpnLiteConfig::from_file(&opts.config_path)?;
    let auth_token = NordVpnLiteAuth::new(token);
    auth_token.to_file(&config.auth_file_path)?;

    println!("Authentication credentials stored successfully.");

    Ok(())
}

/// Clear NordVPN authentication credentials file.
///
/// Loads the config and removes the auth file specified in the config.
fn handle_logout(opts: LogoutOpts) -> Result<(), NordVpnLiteError> {
    println!("Clearing NordVPN authentication credentials");

    let config = NordVpnLiteConfig::from_existing_file(&opts.config_path)?;
    println!("Removing auth from: {}", config.auth_file_path);
    match fs::remove_file(&config.auth_file_path) {
        Ok(()) => {
            println!("Authentication credentials cleared successfully.");
            Ok(())
        }
        // If there are no stored credentials, treat it as a no-op.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("No authentication credentials to clear.");
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

/// Shared helpers and fixtures for unit tests across the crate.
#[cfg(test)]
pub mod test_utils {
    use std::env;
    use std::ffi::OsString;

    use temp_file::TempFile;

    use crate::auth::{NordToken, NordVpnLiteAuth};

    /// The environment variable used to pass authentication token.
    pub const NORD_TOKEN_ENV: &str = "NORD_TOKEN";

    /// A syntactically valid token: 64 lowercase hex characters.
    pub const VALID_TOKEN: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A second valid token, distinct from [`VALID_TOKEN`], used to verify token updates.
    pub const OTHER_VALID_TOKEN: &str =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// Create a temp file with the given content.
    pub fn temp_config(content: &str) -> TempFile {
        TempFile::new()
            .expect("Failed to create temp config file")
            .with_contents(content.as_bytes())
            .expect("Failed to write config file")
    }

    /// Build a config JSON string with the given log path, auth path, and `vpn` section.
    pub fn build_json(log_path: &str, auth_path: &str, vpn: &str) -> String {
        format!(
            r#"{{
                "log_level": "Info",
                "log_file_path": "{log_path}",
                "auth_file_path": "{auth_path}",
                "adapter_type": "linux-native",
                "interface": {{
                    "name": "test",
                    "config_provider": "manual"
                }},
                "vpn": {vpn}
            }}"#
        )
    }

    /// Write a valid auth file containing the given token at `path`.
    pub fn write_auth_file(path: &str, token: &str) {
        let token = NordToken::new(token).expect("token should be valid");
        NordVpnLiteAuth::new(token)
            .to_file(path)
            .expect("Failed to write auth file");
    }

    /// RAII helper that mutates a process environment variable
    /// for the duration of a test and restores its original state on drop.
    #[must_use = "the environment is restored when the guard is dropped; bind it to a variable"]
    pub struct EnvVarHelper {
        key: OsString,
        previous: Option<OsString>,
    }

    impl EnvVarHelper {
        /// Set `key` to `value`, remembering the previous value for restoration.
        pub fn set(key: &str, value: &str) -> Self {
            let guard = Self {
                key: key.into(),
                previous: env::var_os(key),
            };
            env::set_var(key, value);
            guard
        }

        /// Ensure `key` is unset, remembering the previous value for restoration.
        pub fn unset(key: &str) -> Self {
            let guard = Self {
                key: key.into(),
                previous: env::var_os(key),
            };
            env::remove_var(key);
            guard
        }
    }

    impl Drop for EnvVarHelper {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => env::set_var(&self.key, value),
                None => env::remove_var(&self.key),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        build_json, temp_config, write_auth_file, EnvVarHelper, NORD_TOKEN_ENV, OTHER_VALID_TOKEN,
        VALID_TOKEN,
    };
    use assert_matches::assert_matches;
    use serial_test::serial;
    use temp_file::TempFile;

    /// Config JSON pointing its auth file at the given path.
    fn config_json(auth_file_path: &str) -> String {
        build_json("test.log", auth_file_path, "\"recommended\"")
    }

    /// Create a temp file to be used as the auth file and return its path.
    /// The file is removed so initially it does not exist.
    fn non_exist_auth_path() -> String {
        let file = TempFile::new().expect("Failed to create temp auth file");
        let path = file.path().to_str().unwrap().to_owned();
        drop(file);
        path
    }

    /// Create a temp file to be used as the config file and return its path.
    /// The file is removed so initially it does not exist.
    fn non_exist_config_path() -> String {
        let file = temp_config(&config_json(&non_exist_auth_path()));
        let path = file.path().to_str().unwrap().to_owned();
        drop(file);
        path
    }

    /// Read the config at the given path
    fn read_config(path: &str) -> NordVpnLiteConfig {
        NordVpnLiteConfig::from_existing_file(path).expect("Failed to read config back")
    }

    /// Assert that the config at the given path has no valid auth token.
    macro_rules! assert_no_auth_token {
        ($path:expr) => {
            assert_matches!(
                read_config($path).check_auth_token(),
                Err(NordVpnLiteError::InvalidConfigToken { .. })
            );
        };
    }

    #[test]
    fn test_logout_fails_with_no_config_file() {
        let path = non_exist_config_path();

        // no config file present initially
        assert!(!std::path::Path::new(&path).exists());

        let result = handle_logout(LogoutOpts {
            config_path: path.clone(),
        });

        // should fail with a NotFound IO error
        assert_matches!(
            result,
            Err(NordVpnLiteError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound
        );

        // config file should not be created
        assert!(!std::path::Path::new(&path).exists());
    }

    #[test]
    #[serial]
    fn test_login_creates_default_config_file() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let path = non_exist_config_path();

        // no config file present initially
        assert!(!std::path::Path::new(&path).exists());

        handle_login(LoginOpts {
            config_path: path.clone(),
            token: Some(VALID_TOKEN.to_owned()),
            token_positional: None,
        })
        .expect("login should succeed");

        // config file should be created
        assert!(std::path::Path::new(&path).exists());

        // auth file created, token stored
        let stored = read_config(&path)
            .get_auth_token()
            .expect("token should be stored after login");
        assert_eq!(stored.as_ref(), VALID_TOKEN);
    }

    #[test]
    #[serial]
    fn test_login_creates_auth_file() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_path = non_exist_auth_path();
        let file = temp_config(&config_json(&auth_path));
        let path = file.path().to_str().unwrap().to_owned();

        // no auth file present initially
        assert_no_auth_token!(&path);

        handle_login(LoginOpts {
            config_path: path.clone(),
            token: Some(VALID_TOKEN.to_owned()),
            token_positional: None,
        })
        .expect("login should succeed with a valid token");

        // auth file created, token stored
        let stored = read_config(&path)
            .get_auth_token()
            .expect("token should be stored after login");
        assert_eq!(stored.as_ref(), VALID_TOKEN);
    }

    #[test]
    #[serial]
    fn test_login_updates_auth_file() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_path = non_exist_auth_path();
        write_auth_file(&auth_path, VALID_TOKEN);
        let file = temp_config(&config_json(&auth_path));
        let path = file.path().to_str().unwrap().to_owned();

        // auth file present, initial token stored
        let stored = read_config(&path)
            .get_auth_token()
            .expect("token should be stored after login");
        assert_eq!(stored.as_ref(), VALID_TOKEN);

        handle_login(LoginOpts {
            config_path: path.clone(),
            token: Some(OTHER_VALID_TOKEN.to_owned()),
            token_positional: None,
        })
        .expect("login should succeed and overwrite the existing token");

        // auth file present, new token stored
        let stored = read_config(&path)
            .get_auth_token()
            .expect("new token should be stored after second login");
        assert_eq!(stored.as_ref(), OTHER_VALID_TOKEN);
    }

    #[test]
    #[serial]
    fn test_login_rejects_invalid_token() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_path = non_exist_auth_path();
        let file = temp_config(&config_json(&auth_path));
        let path = file.path().to_str().unwrap().to_owned();

        // no auth file present initially
        assert_no_auth_token!(&path);

        let result = handle_login(LoginOpts {
            config_path: path.clone(),
            token: Some("not-a-valid-token".to_owned()),
            token_positional: None,
        });

        // login should fail and the auth file should not be created
        assert_matches!(result, Err(NordVpnLiteError::InvalidConfigToken { .. }));
        assert_no_auth_token!(&path);
    }

    #[test]
    #[serial]
    fn test_logout_removes_auth_file() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_path = non_exist_auth_path();
        write_auth_file(&auth_path, VALID_TOKEN);
        let file = temp_config(&config_json(&auth_path));
        let path = file.path().to_str().unwrap().to_owned();

        // auth file present, token stored
        assert!(read_config(&path).check_auth_token().is_ok());

        handle_logout(LogoutOpts {
            config_path: path.clone(),
        })
        .expect("logout should succeed when auth file is present");

        // auth file should be removed
        assert_no_auth_token!(&path);
    }

    #[test]
    #[serial]
    fn test_login_then_logout_roundtrip() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_path = non_exist_auth_path();
        let file = temp_config(&config_json(&auth_path));
        let path = file.path().to_str().unwrap().to_owned();

        // no auth file present initially
        assert_no_auth_token!(&path);

        handle_login(LoginOpts {
            config_path: path.clone(),
            token: Some(VALID_TOKEN.to_owned()),
            token_positional: None,
        })
        .expect("login should succeed");

        // auth file created, token stored
        let stored = read_config(&path)
            .get_auth_token()
            .expect("token should be stored after login");
        assert_eq!(stored.as_ref(), VALID_TOKEN);

        handle_logout(LogoutOpts {
            config_path: path.clone(),
        })
        .expect("logout should succeed");

        // auth file removed
        assert_no_auth_token!(&path);

        handle_login(LoginOpts {
            config_path: path.clone(),
            token: Some(OTHER_VALID_TOKEN.to_owned()),
            token_positional: None,
        })
        .expect("login should succeed");

        // auth file re-created, new token stored
        let stored = read_config(&path)
            .get_auth_token()
            .expect("token should be stored after login");
        assert_eq!(stored.as_ref(), OTHER_VALID_TOKEN);

        handle_logout(LogoutOpts {
            config_path: path.clone(),
        })
        .expect("logout should succeed");

        // auth file removed
        assert_no_auth_token!(&path);
    }
}
