use std::{num::NonZeroU64, path::PathBuf, str::FromStr};

use serde::{de, Deserialize, Deserializer};
use smart_default::SmartDefault;
use tracing::level_filters::LevelFilter;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, SmartDefault)]
#[repr(transparent)]
pub struct Percentage(u8);

impl std::ops::Mul<std::time::Duration> for Percentage {
    type Output = std::time::Duration;

    fn mul(self, rhs: std::time::Duration) -> Self::Output {
        (self.0 as u32 * rhs) / 100
    }
}

#[derive(Clone, Debug, Deserialize, SmartDefault)]
pub struct MqttConfig {
    /// Starting backoff time for mqtt retry, has to be at least one. (in seconds)
    #[default(backoff_initial_default())]
    #[serde(default = "backoff_initial_default")]
    pub backoff_initial: NonZeroU64,
    /// Maximum backoff time for the mqtt retry. Has to be greater than the initial value. (in seconds)
    #[default(backoff_maximal_default())]
    #[serde(default = "backoff_maximal_default")]
    pub backoff_maximal: NonZeroU64,

    /// Percentage of the expiry period after which new mqtt token will be requested
    #[default(reconnect_after_expiry_default())]
    #[serde(deserialize_with = "deserialize_percent")]
    #[serde(default = "reconnect_after_expiry_default")]
    pub reconnect_after_expiry: Percentage,

    /// Path to a mqtt pem certificate to be used when connecting to Notification Center
    #[serde(default)]
    pub certificate_file_path: Option<PathBuf>,
}

fn backoff_initial_default() -> NonZeroU64 {
    #[allow(unwrap_check)]
    NonZeroU64::new(1).unwrap()
}

fn backoff_maximal_default() -> NonZeroU64 {
    #[allow(unwrap_check)]
    NonZeroU64::new(300).unwrap()
}

fn reconnect_after_expiry_default() -> Percentage {
    Percentage(90)
}

#[derive(Deserialize, Debug)]
pub struct TeliodDaemonConfig {
    #[serde(deserialize_with = "deserialize_log_level")]
    pub log_level: LevelFilter,
    pub log_file_path: String,

    pub app_user_uid: Uuid,

    #[serde(deserialize_with = "deserialize_authentication_token")]
    pub authentication_token: String,

    /// Path to a http pem certificate to be used when connecting to CoreApi
    pub http_certificate_file_path: Option<PathBuf>,

    #[serde(default)]
    pub mqtt: MqttConfig,
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
}
