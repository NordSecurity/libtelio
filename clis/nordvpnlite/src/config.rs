use std::{
    net::Ipv4Addr,
    num::NonZeroU64,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use smart_default::SmartDefault;
use std::fs;
use tracing::{level_filters::LevelFilter, Level};

use telio::{crypto::SecretKey, device::AdapterType, telio_utils::Hidden};

use crate::{interface::InterfaceConfig, NordVpnLiteError};
use std::net::IpAddr;
use telio::crypto::PublicKey;

pub(crate) const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 2);

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

// These IPs are documented but the documentation is not publicly available
fn dns_default() -> Vec<IpAddr> {
    vec![
        Ipv4Addr::new(103, 86, 96, 100).into(),
        Ipv4Addr::new(103, 86, 99, 100).into(),
    ]
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct NordToken(Arc<Hidden<String>>);

impl NordToken {
    pub fn new(token: &str) -> Result<Self, NordVpnLiteError> {
        if Self::validate(token) {
            Ok(NordToken(Arc::new(token.to_owned().into())))
        } else {
            Err(NordVpnLiteError::InvalidConfigOption {
                key: "authentication_token".to_owned(),
                msg: "Invalid authentication token format".to_owned(),
                value: "".to_owned(),
            })
        }
    }

    fn validate(token: &str) -> bool {
        token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl Default for NordToken {
    fn default() -> Self {
        NordToken(Arc::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned()
                .into(),
        ))
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

#[derive(Deserialize)]
pub struct NordlynxKeyResponse {
    pub nordlynx_private_key: String,
}

impl NordlynxKeyResponse {
    pub fn into_secret_key(self) -> Result<SecretKey, NordVpnLiteError> {
        self.nordlynx_private_key.parse::<SecretKey>().map_err(|_| {
            NordVpnLiteError::InvalidResponse("Failed to parse nordlynx private key".to_owned())
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NordVpnLiteConfig {
    #[serde(
        deserialize_with = "deserialize_nord_token",
        serialize_with = "serialize_nord_token"
    )]
    pub authentication_token: NordToken,

    #[serde(default)]
    pub vpn: VpnConfig,

    #[serde(
        deserialize_with = "deserialize_log_level",
        serialize_with = "serialize_log_level"
    )]
    pub log_level: LevelFilter,
    pub log_file_path: String,
    #[serde(default = "default_log_file_count")]
    pub log_file_count: usize,
    #[serde(
        serialize_with = "serialize_adapter_type",
        deserialize_with = "deserialize_adapter_type"
    )]
    pub adapter_type: AdapterType,
    pub interface: InterfaceConfig,
    #[serde(default = "dns_default")]
    pub dns: Vec<IpAddr>,
    /// Overrides the default WireGuard endpoint port, should be used only for testing.
    /// The Core API does not include the WireGuard port in its response, and in environments like
    /// natlab where a non-standard port is used, this allows specifying a custom port manually.
    pub override_default_wg_port: Option<u16>,

    /// Path to a http pem certificate to be used when connecting to CoreApi
    pub http_certificate_file_path: Option<PathBuf>,

    #[serde(default)]
    pub mqtt: MqttConfig,
}

impl PartialEq for NordVpnLiteConfig {
    fn eq(&self, other: &Self) -> bool {
        match (&self.adapter_type, &other.adapter_type) {
            (AdapterType::NepTUN, AdapterType::NepTUN) => {}
            (AdapterType::LinuxNativeWg, AdapterType::LinuxNativeWg) => {}
            (AdapterType::WindowsNativeWg, AdapterType::WindowsNativeWg) => {}
            _ => return false,
        }

        (
            &self.log_level,
            &self.log_file_path,
            &self.log_file_count,
            &self.interface,
            &self.vpn,
            &self.override_default_wg_port,
            &self.authentication_token,
            &self.http_certificate_file_path,
            &self.mqtt,
        )
            .eq(&(
                &other.log_level,
                &other.log_file_path,
                &other.log_file_count,
                &other.interface,
                &other.vpn,
                &other.override_default_wg_port,
                &other.authentication_token,
                &other.http_certificate_file_path,
                &other.mqtt,
            ))
    }
}

impl NordVpnLiteConfig {
    /// Construct a NordVpnLiteConfig by deserializing a file at given path
    pub fn from_file(path: &str) -> Result<Self, NordVpnLiteError> {
        println!("Reading config from: {path}");

        let file = fs::File::open(path)?;
        let mut config: NordVpnLiteConfig = serde_json::from_reader(file)?;

        // Config file should only be written when valid, just in case it was
        // manually modified we check again.
        config.log_file_path = Self::resolve_log_path(&config.log_file_path)?;

        Ok(config)
    }

    fn resolve_log_path(log_file_path: &str) -> Result<String, NordVpnLiteError> {
        let path = PathBuf::from(log_file_path);

        let file_name = path
            .file_name()
            .ok_or_else(|| NordVpnLiteError::InvalidConfigOption {
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
                    .map_err(|e| NordVpnLiteError::InvalidConfigOption {
                        key: "log_file_path".to_owned(),
                        msg: format!("could not resolve log directory: {e}"),
                        value: path.to_string_lossy().into_owned(),
                    })?;
            path_canonical.join(file_name)
        } else {
            if let Some(parent) = path.parent() {
                if !parent.is_dir() {
                    return Err(NordVpnLiteError::InvalidConfigOption {
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

impl Default for NordVpnLiteConfig {
    fn default() -> Self {
        NordVpnLiteConfig {
            log_level: LevelFilter::from_level(if cfg!(debug_assertions) {
                Level::TRACE
            } else {
                Level::INFO
            }),
            log_file_path: "/var/log/nordvpnlite.log".to_string(),
            log_file_count: default_log_file_count(),
            adapter_type: AdapterType::default(),
            interface: InterfaceConfig {
                name: "nlx".to_string(),
                config_provider: Default::default(),
            },
            vpn: Default::default(),
            dns: dns_default(),
            override_default_wg_port: None,
            authentication_token: Default::default(),
            http_certificate_file_path: None,
            mqtt: MqttConfig::default(),
        }
    }
}

fn serialize_adapter_type<S>(adapter: &AdapterType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let name = match adapter {
        AdapterType::NepTUN => "netpun",
        AdapterType::LinuxNativeWg => "linux-native",
        AdapterType::WindowsNativeWg => "wireguard-nt",
        AdapterType::Custom(_) => "custom",
    };
    serializer.serialize_str(name)
}

fn deserialize_adapter_type<'de, D>(deserializer: D) -> Result<AdapterType, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).and_then(|s: String| {
        AdapterType::from_str(&s).map_err(|_| {
            de::Error::unknown_variant(&s, &["TODO", "TODO", "TODO", "TODO", "TODO", "TODO"])
        })
    })
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

#[derive(PartialEq, Eq, Deserialize, Serialize, Debug, Clone)]
pub struct Endpoint {
    pub address: IpAddr,
    pub public_key: PublicKey,
    pub hostname: Option<String>,
}

/// Type of VPN server connection, automatic by country, or specified server endpoint
#[derive(Default, PartialEq, Eq, Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum VpnConfig {
    /// Direct endpoint and public key of VPN server
    Server(Endpoint),
    /// Country name or ISO code of VPN server location
    Country(String),
    /// Any server from the recommendations list
    #[default]
    Recommended,
}

#[cfg(test)]
mod tests {
    use crate::interface::InterfaceConfigurationProvider;

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
                "vpn": {{
                    "country": "lt"
                }},
                "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
    fn nordvpnlite_config_minimal_json() {
        let expected = NordVpnLiteConfig {
            log_level: LevelFilter::INFO,
            log_file_path: "test.log".to_owned(),
            log_file_count: 7,
            adapter_type: AdapterType::LinuxNativeWg,
            interface: InterfaceConfig {
                name: "utun10".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
            },
            vpn: Default::default(),
            dns: dns_default(),
            override_default_wg_port: None,
            authentication_token: Default::default(),
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
            "adapter_type": "linux-native",
            "interface": {
                "name": "utun10",
                "config_provider": "manual"
            },
            "vpn": "recommended",
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
                "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "mqtt": {}
            }"#;

            assert_eq!(expected, serde_json::from_str(json).unwrap());
        }
    }

    #[test]
    fn test_config_example() {
        let example = NordVpnLiteConfig::from_file("example_nordvpnlite_config.json").unwrap();

        assert_eq!(example.adapter_type, AdapterType::NepTUN);
    }

    #[test]
    fn test_config_vpn_country() {
        let expected_config = NordVpnLiteConfig::default();

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": "recommended",
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_dns_custom() {
        let mut expected_config = NordVpnLiteConfig::default();
        expected_config.dns = vec![Ipv4Addr::new(1, 1, 1, 1).into()];

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "dns": ["1.1.1.1"],
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_dns_custom_multiple() {
        let mut expected_config = NordVpnLiteConfig::default();
        expected_config.dns = vec![
            Ipv4Addr::new(1, 1, 1, 1).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
        ];

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "dns": ["1.1.1.1", "8.8.8.8"],
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_vpn_and_dns_default_setting() {
        let expected_config = NordVpnLiteConfig::default();

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_vpn_endpoint() {
        let expected_config = NordVpnLiteConfig {
            vpn: VpnConfig::Server(Endpoint {
                address: "127.0.0.1".parse().unwrap(),
                public_key: "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro="
                    .parse()
                    .unwrap(),
                hostname: None,
            }),
            ..NordVpnLiteConfig::default()
        };

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": {
                "server": {
                    "address": "127.0.0.1",
                    "public_key": "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro="
                }
            },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_vpn_fails() {
        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": {
                "country": "de",
                "country": "pl"
            },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;
        assert!(serde_json::from_str::<NordVpnLiteConfig>(json).is_err());

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": {
                "country": "de"
            },
            "vpn": {
                "country": "pl"
            },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert!(serde_json::from_str::<NordVpnLiteConfig>(json).is_err());

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": {
                "country": "de"
            },
            "vpn": {
                "server": {
                    "address": "127.0.0.1",
                    "public_key": "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro="
                }
            },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert!(serde_json::from_str::<NordVpnLiteConfig>(json).is_err());

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": {
                "country": "de",
                "server": {
                    "address": "127.0.0.1",
                    "public_key": "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro="
                }
            },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert!(serde_json::from_str::<NordVpnLiteConfig>(json).is_err());

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": "recommended",
            "dns": ["1.1.1.1.1"]
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }"#;

        assert!(
            serde_json::from_str::<NordVpnLiteConfig>(json).is_err(),
            "Bad DNS ip"
        );
    }

    #[test]
    fn test_config_with_absolute_path() {
        let log_path = std::env::current_dir().unwrap().join("absolute.log");
        let config_json = config_json_for_log(log_path.to_str().unwrap());

        let file = temp_config(&config_json);
        let config = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap();

        assert_eq!(config.log_file_path, log_path.to_string_lossy());
        assert_eq!(
            serde_json::from_str::<NordVpnLiteConfig>(&config_json).unwrap(),
            config
        );
    }

    #[test]
    fn test_relative_log_path() {
        let config_json = config_json_for_log("./relative.log");
        let file = temp_config(&config_json);
        let config = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap();

        let expected = std::env::current_dir().unwrap().join("relative.log");
        assert_eq!(config.log_file_path, expected.to_string_lossy());
    }

    #[test]
    fn test_invalid_log_path_error() {
        let config_json = config_json_for_log("");

        let file = temp_config(&config_json);
        let err = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap_err();

        matches!(err, NordVpnLiteError::InvalidConfigOption { .. });
    }

    #[test]
    #[serial]
    fn test_token_override_from_env() {
        let config_json = config_json_for_log("test.log");
        let file = temp_config(&config_json);

        let valid_token = "b".repeat(64);
        std::env::set_var("NORD_TOKEN", &valid_token);

        let mut config = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap();
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

        let config = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(
            config.authentication_token.as_ref(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        std::env::remove_var("NORD_TOKEN");
    }
}
