use std::{num::NonZeroU64, path::PathBuf, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use smart_default::SmartDefault;
use std::fs;
use tracing::{debug, info, level_filters::LevelFilter, warn};
use uuid::Uuid;

use telio::crypto::SecretKey;

use crate::configure_interface::InterfaceConfigurationProvider;

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
    #[allow(clippy::unwrap_used, unwrap_check)]
    NonZeroU64::new(1).unwrap()
}

fn backoff_maximal_default() -> NonZeroU64 {
    #[allow(clippy::unwrap_used, unwrap_check)]
    NonZeroU64::new(300).unwrap()
}

fn reconnect_after_expiry_default() -> Percentage {
    Percentage(90)
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DeviceIdentity {
    pub hw_identifier: Uuid,
    pub private_key: SecretKey,
    pub machine_identifier: String,
}

pub fn generate_hw_identifier() -> Uuid {
    // Generate hw_identifier
    debug!("Generating a new hw identifier");
    Uuid::new_v4()
}

impl DeviceIdentity {
    pub fn from_file(identity_path: &PathBuf) -> Option<DeviceIdentity> {
        info!("Fetching identity config");

        if let Ok(file) = fs::File::open(identity_path) {
            debug!(
                "Found existing identity config {}",
                identity_path.to_string_lossy()
            );
            if let Ok(c) = serde_json::from_reader(file) {
                return Some(c);
            } else {
                warn!("Reading identity config failed");
            }
        }
        None
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TeliodDaemonConfig {
    #[serde(
        deserialize_with = "deserialize_log_level",
        serialize_with = "serialize_log_level"
    )]
    pub log_level: LevelFilter,
    pub log_file_path: String,
    pub interface: InterfaceConfig,

    #[serde(
        deserialize_with = "deserialize_authentication_token",
        serialize_with = "serialize_authentication_token"
    )]
    pub authentication_token: String,

    /// Path to a http pem certificate to be used when connecting to CoreApi
    pub http_certificate_file_path: Option<PathBuf>,

    #[serde(default)]
    pub mqtt: MqttConfig,
}

impl TeliodDaemonConfig {
    #[allow(dead_code)]
    pub fn update(&mut self, update: TeliodDaemonConfigPartial) {
        if let Some(log_level) = update.log_level {
            self.log_level = log_level;
        }
        if let Some(log_file_path) = update.log_file_path {
            self.log_file_path = log_file_path;
        }
        if let Some(authentication_token) = update.authentication_token {
            self.authentication_token = authentication_token;
        }
        if let Some(interface) = update.interface {
            self.interface = interface;
        }
        if let Some(http_certificate_file_path) = update.http_certificate_file_path {
            self.http_certificate_file_path = http_certificate_file_path;
        }
        if let Some(mqtt) = update.mqtt {
            self.mqtt = mqtt;
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

fn deserialize_authentication_token<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let raw_string: String = de::Deserialize::deserialize(deserializer)?;
    let re = regex::Regex::new("[0-9a-f]{64}").map_err(de::Error::custom)?;
    if re.is_match(&raw_string) {
        Ok(raw_string)
    } else {
        Err(de::Error::custom("Incorrect authentication token"))
    }
}

fn serialize_authentication_token<S>(auth_token: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if auth_token.len() == 64 && auth_token.chars().all(|c| c.is_ascii_hexdigit()) {
        serializer.serialize_str(auth_token)
    } else {
        Err(serde::ser::Error::custom(
            "Invalid authentication token format",
        ))
    }
}

#[derive(Default, PartialEq, Eq, Deserialize, Serialize, Debug)]
pub struct InterfaceConfig {
    pub name: String,
    pub config_provider: InterfaceConfigurationProvider,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct TeliodDaemonConfigPartial {
    #[serde(default, deserialize_with = "deserialize_partial_log_level")]
    log_level: Option<LevelFilter>,
    log_file_path: Option<String>,
    interface: Option<InterfaceConfig>,
    app_user_uid: Option<Uuid>,
    #[serde(default, deserialize_with = "deserialize_partial_authentication_token")]
    authentication_token: Option<String>,
    http_certificate_file_path: Option<Option<PathBuf>>,
    mqtt: Option<MqttConfig>,
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

fn deserialize_partial_authentication_token<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let deserialized_auth_token: Option<String> = Option::deserialize(deserializer)?;

    match deserialized_auth_token {
        Some(ref raw_auth_token) => {
            let re = regex::Regex::new("[0-9a-f]{64}").map_err(de::Error::custom)?;
            if re.is_match(raw_auth_token) {
                Ok(Some(raw_auth_token.to_owned()))
            } else {
                Err(de::Error::custom("Incorrect authentication token"))
            }
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

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
            interface: InterfaceConfig {
                name: "utun10".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
            authentication_token:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            http_certificate_file_path: None,
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
}
