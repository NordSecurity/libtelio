use std::{
    net::SocketAddr,
    num::NonZeroU64,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use smart_default::SmartDefault;
use std::fs;
use tracing::{level_filters::LevelFilter, Level};
use uuid::Uuid;

use telio::{crypto::PublicKey, device::AdapterType, telio_utils::Hidden};

use crate::{configure_interface::InterfaceConfigurationProvider, TeliodError};

#[derive(PartialEq, Eq, Clone, Copy, Debug, SmartDefault)]
#[repr(transparent)]
pub struct Percentage(pub u8);

impl std::ops::Mul<std::time::Duration> for Percentage {
    type Output = std::time::Duration;

    fn mul(self, rhs: std::time::Duration) -> Self::Output {
        (self.0 as u32 * rhs) / 100
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Deserialize, Serialize, SmartDefault)]
#[serde(default)]
pub struct MqttConfig {
    /// Starting backoff time for mqtt retry, has to be at least one. (in seconds)
    #[default(backoff_initial_default())]
    pub backoff_initial: NonZeroU64,
    /// Maximum backoff time for the mqtt retry. Has to be greater than the initial value. (in seconds)
    #[default(backoff_maximal_default())]
    pub backoff_maximal: NonZeroU64,

    /// Percentage of the expiry period after which new mqtt token will be requested
    #[default(reconnect_after_expiry_default())]
    #[serde(
        deserialize_with = "deserialize_percent",
        serialize_with = "serialize_percent"
    )]
    pub reconnect_after_expiry: Percentage,

    /// Path to a mqtt pem certificate to be used when connecting to Notification Center
    pub certificate_file_path: Option<PathBuf>,
}

fn backoff_initial_default() -> NonZeroU64 {
    #[allow(clippy::unwrap_used)]
    NonZeroU64::new(1).unwrap()
}

fn backoff_maximal_default() -> NonZeroU64 {
    #[allow(clippy::unwrap_used)]
    NonZeroU64::new(300).unwrap()
}

fn reconnect_after_expiry_default() -> Percentage {
    Percentage(90)
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct NordToken(Arc<Hidden<String>>);

impl NordToken {
    pub fn new(token: &str) -> Result<Self, TeliodError> {
        if Self::validate(token) {
            Ok(NordToken(Arc::new(token.to_owned().into())))
        } else {
            Err(TeliodError::InvalidConfigOption {
                key: "authentication_token".to_owned(),
                msg: "Invalid authentication token format".to_owned(),
                value: "".to_owned(),
            })
        }
    }

    fn validate(token: &str) -> bool {
        token.is_empty() || (token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()))
    }
}

impl Default for NordToken {
    fn default() -> Self {
        NordToken(Arc::new(Hidden("".to_owned())))
    }
}

impl std::fmt::Display for NordToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for NordToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for NordToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Clone)]
pub struct TeliodDaemonConfig {
    #[serde(
        deserialize_with = "deserialize_log_level",
        serialize_with = "serialize_log_level"
    )]
    pub log_level: LevelFilter,
    pub log_file_path: String,
    #[serde(default = "default_log_file_count")]
    pub log_file_count: usize,
    pub adapter_type: AdapterType,
    pub interface: InterfaceConfig,
    pub vpn: Option<VpnConfig>,

    #[serde(
        deserialize_with = "deserialize_nord_token",
        serialize_with = "serialize_nord_token"
    )]
    pub authentication_token: NordToken,

    /// Path to a http pem certificate to be used when connecting to CoreApi
    pub http_certificate_file_path: Option<PathBuf>,

    /// Path to a device identity file, should only be used for testing
    pub device_identity_file_path: Option<PathBuf>,

    #[serde(default)]
    pub mqtt: MqttConfig,
}

impl TeliodDaemonConfig {
    #[cfg(feature = "cgi")]
    pub fn update(&mut self, update: TeliodDaemonConfigPartial) -> Result<(), TeliodError> {
        if let Some(log_file_path) = update.log_file_path {
            self.log_file_path = Self::resolve_log_path(&log_file_path)?;
        }
        if let Some(log_level) = update.log_level {
            self.log_level = log_level;
        }
        if let Some(log_file_count) = update.log_file_count {
            self.log_file_count = log_file_count;
        }
        if let Some(authentication_token) = update.authentication_token {
            self.authentication_token = authentication_token;
        }
        if let Some(adapter) = update.adapter_type {
            self.adapter_type = adapter;
        }
        if let Some(interface) = update.interface {
            self.interface = interface;
        }
        if let Some(vpn) = update.vpn {
            self.vpn = Some(vpn);
        }
        if let Some(http_certificate_file_path) = update.http_certificate_file_path {
            self.http_certificate_file_path = http_certificate_file_path;
        }

        if let Some(device_identity_file_path) = update.device_identity_file_path {
            self.device_identity_file_path = device_identity_file_path
        }
        if let Some(mqtt) = update.mqtt {
            self.mqtt = mqtt;
        }

        Ok(())
    }

    /// Construct a TeliodDaemonConfig by deserializing a file at given path
    pub fn from_file(path: &str) -> Result<Self, TeliodError> {
        println!("Reading config from: {path}");

        let file = fs::File::open(path)?;
        let mut config: TeliodDaemonConfig = serde_json::from_reader(file)?;

        // Config file should only be written when valid, just in case it was
        // manually modified we check again.
        config.log_file_path = Self::resolve_log_path(&config.log_file_path)?;

        Ok(config)
    }

    fn resolve_log_path(log_file_path: &str) -> Result<String, TeliodError> {
        let path = PathBuf::from(log_file_path);

        let file_name = path
            .file_name()
            .ok_or_else(|| TeliodError::InvalidConfigOption {
                key: "log_file_path".to_owned(),
                msg: "must specify a file name".to_owned(),
                value: path.to_string_lossy().into_owned(),
            })?;

        let final_path = if path.is_relative() {
            let dir = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };

            let path_canonical =
                dir.canonicalize()
                    .map_err(|e| TeliodError::InvalidConfigOption {
                        key: "log_file_path".to_owned(),
                        msg: format!("could not resolve log directory: {e}"),
                        value: path.to_string_lossy().into_owned(),
                    })?;
            path_canonical.join(file_name)
        } else {
            if let Some(parent) = path.parent() {
                if !parent.is_dir() {
                    return Err(TeliodError::InvalidConfigOption {
                        key: "log_file_path".to_owned(),
                        msg: "parent directory does not exist".to_owned(),
                        value: path.to_string_lossy().into_owned(),
                    });
                }
            }
            path
        };

        Ok(final_path.to_string_lossy().to_string())
    }

    /// Checks if NORD_TOKEN env var is set and contains a valid token.
    pub fn resolve_env_token(&mut self) -> bool {
        if let Ok(token) = std::env::var("NORD_TOKEN") {
            println!("Overriding token from env");
            match NordToken::new(&token) {
                Ok(nordtoken) => {
                    self.authentication_token = nordtoken;
                    return true;
                }
                Err(e) => {
                    eprintln!("Token from env not valid: {}", e);
                }
            };
        }
        false
    }
}

impl Default for TeliodDaemonConfig {
    fn default() -> Self {
        TeliodDaemonConfig {
            log_level: LevelFilter::from_level(if cfg!(debug_assertions) {
                Level::TRACE
            } else {
                Level::INFO
            }),
            log_file_path: {
                // TODO: Should this path be different for CGI?
                #[cfg(feature = "cgi")]
                {
                    crate::cgi::constants::LOG_PATHS
                        .log()
                        .to_string_lossy()
                        .into_owned()
                }
                #[cfg(not(feature = "cgi"))]
                {
                    "/var/log/teliod_lib.log".to_string()
                }
            },
            log_file_count: default_log_file_count(),
            adapter_type: AdapterType::default(),
            interface: InterfaceConfig {
                name: "nlx".to_string(),
                config_provider: Default::default(),
            },
            vpn: None,
            authentication_token: Default::default(),
            http_certificate_file_path: None,
            device_identity_file_path: None,
            mqtt: MqttConfig::default(),
        }
    }
}

fn deserialize_percent<'de, D>(deserializer: D) -> Result<Percentage, D::Error>
where
    D: Deserializer<'de>,
{
    let value: u8 = de::Deserialize::deserialize(deserializer)?;
    if value > 100 {
        return Err(de::Error::custom(
            "Percentage value can only be in range from 0 to 100 inclusive",
        ));
    }
    Ok(Percentage(value))
}

fn serialize_percent<S>(percentage: &Percentage, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u8(percentage.0)
}

fn deserialize_log_level<'de, D>(deserializer: D) -> Result<LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).and_then(|s: String| {
        LevelFilter::from_str(&s).map_err(|_| {
            de::Error::unknown_variant(&s, &["error", "warn", "info", "debug", "trace", "off"])
        })
    })
}

fn serialize_log_level<S>(log_level: &LevelFilter, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&log_level.to_string())
}

fn deserialize_nord_token<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<NordToken, D::Error> {
    let raw_string: Hidden<String> = de::Deserialize::deserialize(deserializer)?;
    NordToken::new(&raw_string).map_err(de::Error::custom)
}

fn serialize_nord_token<S>(token: &NordToken, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(token)
}

const fn default_log_file_count() -> usize {
    7
}

#[derive(Default, PartialEq, Eq, Deserialize, Serialize, Debug, Clone)]
pub struct InterfaceConfig {
    pub name: String,
    pub config_provider: InterfaceConfigurationProvider,
}

#[derive(PartialEq, Eq, Deserialize, Serialize, Debug, Copy, Clone)]
pub struct VpnConfig {
    pub server_endpoint: SocketAddr,
    pub server_pubkey: PublicKey,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Default)]
pub struct TeliodDaemonConfigPartial {
    #[serde(default, deserialize_with = "deserialize_partial_log_level")]
    pub log_level: Option<LevelFilter>,
    pub log_file_path: Option<String>,
    pub log_file_count: Option<usize>,
    pub adapter_type: Option<AdapterType>,
    pub interface: Option<InterfaceConfig>,
    pub vpn: Option<VpnConfig>,
    pub app_user_uid: Option<Uuid>,
    #[serde(default, deserialize_with = "deserialize_partial_nord_token")]
    pub authentication_token: Option<NordToken>,
    pub http_certificate_file_path: Option<Option<PathBuf>>,
    pub device_identity_file_path: Option<Option<PathBuf>>,
    pub mqtt: Option<MqttConfig>,
}

fn deserialize_partial_log_level<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<LevelFilter>, D::Error> {
    let deserialized_level_filter: Option<String> = Option::deserialize(deserializer)?;

    match deserialized_level_filter {
        Some(ref level_string) => LevelFilter::from_str(level_string).map(Some).map_err(|_| {
            de::Error::unknown_variant(
                level_string,
                &["error", "warn", "info", "debug", "trace", "off"],
            )
        }),
        _ => Ok(None),
    }
}

fn deserialize_partial_nord_token<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NordToken>, D::Error> {
    let deserialized_auth_token: Option<Hidden<String>> =
        de::Deserialize::deserialize(deserializer)?;

    match deserialized_auth_token {
        Some(raw_auth_token) => Ok(NordToken::new(&raw_auth_token).ok()),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::time::Duration;
    use temp_file::TempFile;

    fn temp_config(content: &str) -> TempFile {
        TempFile::new()
            .expect("Failed to create temp config file")
            .with_contents(content.as_bytes())
            .expect("Failed to write config file")
    }

    fn config_json_for_log(path: &str) -> String {
        format!(
            r#"{{
                "log_level": "Info",
                "log_file_path": "{}",
                "adapter_type": "linux-native",
                "interface": {{
                    "name": "test",
                    "config_provider": "manual"
                }},
                "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }}"#,
            path
        )
    }

    #[test]
    fn percentage_times_duration() {
        let input = Duration::from_secs(86400);
        let expected = Duration::from_secs(77760);
        let percentage = Percentage(90);
        assert_eq!(expected, percentage * input);
    }

    #[test]
    fn teliod_config_minimal_json() {
        let expected = TeliodDaemonConfig {
            log_level: LevelFilter::INFO,
            log_file_path: "test.log".to_owned(),
            log_file_count: 7,
            adapter_type: AdapterType::LinuxNativeWg,
            interface: InterfaceConfig {
                name: "utun10".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
            vpn: None,
            authentication_token: NordToken::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            http_certificate_file_path: None,
            device_identity_file_path: None,
            mqtt: MqttConfig {
                backoff_initial: NonZeroU64::new(1).unwrap(),
                backoff_maximal: NonZeroU64::new(300).unwrap(),
                reconnect_after_expiry: Percentage(90),
                certificate_file_path: None,
            },
        };

        {
            let json = r#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "adapter_type": "linux-native",
            "interface": {
                "name": "utun10",
                "config_provider": "manual"
            },
            "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }"#;

            assert_eq!(expected, serde_json::from_str(json).unwrap());
        }

        {
            let json = r#"{
                "log_level": "Info",
                "log_file_path": "test.log",
                "adapter_type": "linux-native",
                "interface": {
                    "name": "utun10",
                    "config_provider": "manual"
                },
                "authentication_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "mqtt": {}
            }"#;

            assert_eq!(expected, serde_json::from_str(json).unwrap());
        }
    }

    #[test]
    fn test_config_with_absolute_path() {
        let log_path = std::env::current_dir().unwrap().join("absolute.log");
        let config_json = config_json_for_log(log_path.to_str().unwrap());

        let file = temp_config(&config_json);
        let config = TeliodDaemonConfig::from_file(file.path().to_str().unwrap()).unwrap();

        assert_eq!(config.log_file_path, log_path.to_string_lossy());
    }

    #[test]
    fn test_relative_log_path() {
        let config_json = config_json_for_log("./relative.log");
        let file = temp_config(&config_json);
        let config = TeliodDaemonConfig::from_file(file.path().to_str().unwrap()).unwrap();

        let expected = std::env::current_dir().unwrap().join("relative.log");
        assert_eq!(config.log_file_path, expected.to_string_lossy());
    }

    #[test]
    fn test_invalid_log_path_error() {
        let config_json = config_json_for_log("");

        let file = temp_config(&config_json);
        let err = TeliodDaemonConfig::from_file(file.path().to_str().unwrap()).unwrap_err();

        matches!(err, TeliodError::InvalidConfigOption { .. });
    }

    #[test]
    #[serial]
    fn test_token_override_from_env() {
        let config_json = config_json_for_log("test.log");
        let file = temp_config(&config_json);

        let valid_token = "b".repeat(64);
        std::env::set_var("NORD_TOKEN", &valid_token);

        let mut config = TeliodDaemonConfig::from_file(file.path().to_str().unwrap()).unwrap();
        config.resolve_env_token();
        assert_eq!(config.authentication_token.as_ref(), valid_token);

        std::env::remove_var("NORD_TOKEN");
    }

    #[test]
    #[serial]
    fn test_invalid_env_token_ignored() {
        let config_json = config_json_for_log("test.log");
        let file = temp_config(&config_json);

        std::env::set_var("NORD_TOKEN", "short");

        let config = TeliodDaemonConfig::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.authentication_token.as_ref(), "a".repeat(64));

        std::env::remove_var("NORD_TOKEN");
    }
}
