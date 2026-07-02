use std::{
    fs,
    io::Write,
    net::IpAddr,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use tracing::{level_filters::LevelFilter, Level};

use telio::{
    crypto::{PublicKey, SecretKey},
    device::AdapterType,
    telio_utils::Hidden,
};

use crate::{interface::InterfaceConfig, NordVpnLiteError};

#[derive(Clone)]
pub struct ConfigFile {
    pub path: String,
    hash: u64,
}

impl ConfigFile {
    pub fn new(path: String) -> Self {
        let hash = std::fs::read(&path)
            .map(|b| Self::hash_bytes(&b))
            .unwrap_or(0);
        Self { path, hash }
    }

    pub fn read_if_changed(&self) -> Option<Result<(NordVpnLiteConfig, u64), NordVpnLiteError>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let new_hash = Self::hash_bytes(&bytes);
                if new_hash != self.hash {
                    Some(NordVpnLiteConfig::from_bytes(&bytes).map(|config| (config, new_hash)))
                } else {
                    None
                }
            }
            Err(e) => {
                tracing::error!(
                    "Cannot read config file '{}' for hash check: {e}. Treating as unchanged.",
                    self.path
                );
                None
            }
        }
    }

    pub fn set_hash(&mut self, hash: u64) {
        self.hash = hash;
    }

    fn hash_bytes(bytes: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }
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
        } else if token.to_lowercase().contains("token") {
            Err(NordVpnLiteError::InvalidConfigToken {
                msg: "Provide your authentication token from https://my.nordaccount.com".to_owned(),
            })
        } else {
            Err(NordVpnLiteError::InvalidConfigToken {
                msg: "Invalid authentication token format".to_owned(),
            })
        }
    }

    fn validate(token: &str) -> bool {
        token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Token that will fail to deserialize, prompting the user to update it
    pub fn new_invalid_template() -> Self {
        NordToken(Arc::new(
            "<PASTE_YOUR_AUTHENTICATION_TOKEN_HERE>".to_owned().into(),
        ))
    }

    pub fn zeroize(&mut self) {
        self.0 = Arc::new(Hidden::from(String::new()));
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

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
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

    /// Enables the libtelio firewall that processes packets.
    #[serde(default)]
    pub enable_firewall: bool,
}

impl NordVpnLiteConfig {
    /// Construct a NordVpnLiteConfig by deserializing raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, NordVpnLiteError> {
        let mut config: NordVpnLiteConfig = serde_json::from_slice(bytes)?;
        config.log_file_path = Self::resolve_log_path(&config.log_file_path)?;
        Ok(config)
    }

    /// Construct a NordVpnLiteConfig by deserializing a file at given path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, NordVpnLiteError> {
        let path = path.as_ref();
        println!("Reading config from: {}", path.display());

        match fs::File::open(path) {
            Ok(file) => {
                let mut config: NordVpnLiteConfig = serde_json::from_reader(file)?;
                config.log_file_path = Self::resolve_log_path(&config.log_file_path)?;
                Ok(config)
            }
            // Create a default config if it does not exist
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("File not found, creating default config");

                // Create directories
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Write default config to file
                let default_config = Self {
                    authentication_token: NordToken::new_invalid_template(),
                    ..Default::default()
                };

                let mut file = fs::File::create(path)?;
                let mut permissions = file.metadata()?.permissions();
                permissions.set_mode(0o640);
                fs::set_permissions(path, permissions)?;

                let config_json = serde_json::to_string_pretty(&default_config)?;
                file.write_all(config_json.as_bytes())?;

                Err(NordVpnLiteError::InvalidConfigToken {
                    msg: "Provide your authentication token from https://my.nordaccount.com"
                        .to_owned(),
                })
            }
            Err(err) => Err(err.into()),
        }
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
                max_route_priority: None,
            },
            vpn: Default::default(),
            dns: dns_default(),
            override_default_wg_port: None,
            authentication_token: Default::default(),
            http_certificate_file_path: None,
            enable_firewall: false,
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
            de::Error::unknown_variant(&s, &["neptun", "linux-native", "wireguard-nt", "custom"])
        })
    })
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
    fn nordvpnlite_config_minimal_json() {
        let expected = NordVpnLiteConfig {
            log_level: LevelFilter::INFO,
            log_file_path: "test.log".to_owned(),
            log_file_count: 7,
            adapter_type: AdapterType::LinuxNativeWg,
            interface: InterfaceConfig {
                name: "utun10".to_owned(),
                config_provider: InterfaceConfigurationProvider::Manual,
                max_route_priority: None,
            },
            vpn: Default::default(),
            dns: dns_default(),
            override_default_wg_port: None,
            authentication_token: Default::default(),
            http_certificate_file_path: None,
            enable_firewall: false,
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
                "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
    fn test_absolute_log_path() {
        let log_path = std::env::current_dir().unwrap().join("absolute.log");
        let config_json = config_json_for_log(log_path.to_str().unwrap());

        let file = temp_config(&config_json);
        let config = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap();

        assert_eq!(config.log_file_path, log_path.to_string_lossy());
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
    fn test_invalid_log_path_returns_error() {
        let config_json = config_json_for_log("");

        let file = temp_config(&config_json);
        let err = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap_err();

        assert!(
            matches!(err, NordVpnLiteError::InvalidConfigOption { ref key, .. } if key == "log_file_path"),
            "expected InvalidConfigOption for log_file_path, got: {err:?}"
        );
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

    #[test]
    fn test_config_file_unchanged_returns_none() {
        let file = temp_config(r#"{"key": "value"}"#);
        let path = file.path().to_str().unwrap().to_owned();
        let config_file = ConfigFile::new(path);
        assert!(config_file.read_if_changed().is_none());
    }

    #[test]
    fn test_config_file_changed_returns_some() {
        let valid_config = r#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "adapter_type": "linux-native",
            "interface": { "name": "utun10", "config_provider": "manual" },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }"#;
        let file = temp_config(r#"{"key": "original"}"#);
        let path = file.path().to_str().unwrap().to_owned();
        let config_file = ConfigFile::new(path.clone());
        std::fs::write(&path, valid_config).unwrap();
        assert!(config_file.read_if_changed().is_some());
    }

    #[test]
    fn test_config_file_changed_invalid_config_returns_some_err() {
        let file = temp_config(r#"{"key": "original"}"#);
        let path = file.path().to_str().unwrap().to_owned();
        let config_file = ConfigFile::new(path.clone());
        std::fs::write(
            &path,
            r#"{"key": "changed but invalid json for NordVpnLiteConfig"}"#,
        )
        .unwrap();
        let result = config_file.read_if_changed();
        assert!(matches!(result, Some(Err(_))));
    }

    #[test]
    fn test_config_file_unchanged_for_missing_file_returns_none() {
        let config_file = ConfigFile {
            path: "/nonexistent/path/config.json".to_owned(),
            hash: 42,
        };
        assert!(config_file.read_if_changed().is_none());
    }

    #[test]
    fn test_config_file_hash_is_zero_for_missing_file() {
        let config_file = ConfigFile::new("/nonexistent/path/config.json".to_owned());
        assert_eq!(config_file.hash, 0);
    }

    #[test]
    fn test_config_file_set_hash_marks_file_as_seen() {
        let valid_config = r#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "adapter_type": "linux-native",
            "interface": { "name": "utun10", "config_provider": "manual" },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }"#;
        let file = temp_config(r#"{"key": "original"}"#);
        let path = file.path().to_str().unwrap().to_owned();
        let mut config_file = ConfigFile::new(path.clone());

        std::fs::write(&path, valid_config).unwrap();
        let (_, new_hash) = config_file
            .read_if_changed()
            .expect("expected Some after file change")
            .expect("expected valid config");

        // Update the hash
        config_file.set_hash(new_hash);
        assert!(
            config_file.read_if_changed().is_none(),
            "expected None after set_hash with current hash"
        );
    }

    fn minimal_config_bytes(log_path: &str) -> Vec<u8> {
        config_json_for_log(log_path).into_bytes()
    }

    #[test]
    fn test_from_bytes_absolute_log_path_nonexistent_parent_returns_error() {
        let bytes = minimal_config_bytes("/nonexistent/dir/app.log");
        let err = NordVpnLiteConfig::from_bytes(&bytes)
            .expect_err("from_bytes should fail when the parent directory does not exist");

        assert!(
            matches!(err, NordVpnLiteError::InvalidConfigOption { ref key, .. } if key == "log_file_path"),
            "expected InvalidConfigOption for log_file_path, got: {err:?}"
        );
    }

    #[test]
    fn test_from_bytes_invalid_json_returns_error() {
        let err = NordVpnLiteConfig::from_bytes(b"not valid json at all")
            .expect_err("from_bytes should fail on malformed JSON input");

        assert!(
            matches!(err, NordVpnLiteError::ParsingError(_)),
            "expected ParsingError for invalid JSON, got: {err:?}"
        );
    }

    #[test]
    fn test_from_bytes_missing_required_field_returns_error() {
        // authentication_token is omitted
        let bytes = br#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "adapter_type": "linux-native",
            "interface": { "name": "utun10", "config_provider": "manual" }
        }"#;

        let err = NordVpnLiteConfig::from_bytes(bytes)
            .expect_err("from_bytes should fail when a required field is missing");

        assert!(
            matches!(err, NordVpnLiteError::ParsingError(_)),
            "expected ParsingError for missing required field, got: {err:?}"
        );
    }

    #[test]
    fn test_from_bytes_unknown_field_returns_error() {
        let bytes = br#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "adapter_type": "linux-native",
            "interface": { "name": "utun10", "config_provider": "manual" },
            "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "unknown_field": "should_fail"
        }"#;

        let err = NordVpnLiteConfig::from_bytes(bytes)
            .expect_err("from_bytes should fail when an unknown field is present");

        assert!(
            matches!(err, NordVpnLiteError::ParsingError(_)),
            "expected ParsingError for unknown field, got: {err:?}"
        );
    }

    #[test]
    fn test_from_bytes_invalid_token_returns_error() {
        // authentication_token is too short
        let bytes = br#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "adapter_type": "linux-native",
            "interface": { "name": "utun10", "config_provider": "manual" },
            "authentication_token": "deadbeef"
        }"#;

        let err = NordVpnLiteConfig::from_bytes(bytes)
            .expect_err("from_bytes should fail for an invalid authentication token");

        assert!(
            matches!(err, NordVpnLiteError::ParsingError(_)),
            "expected ParsingError for invalid token, got: {err:?}"
        );
    }

    #[test]
    fn test_from_bytes_all_optional_fields_parsed() {
        let log_path = std::env::current_dir().unwrap().join("full.log");
        let bytes = format!(
            r#"{{
                "log_level": "Debug",
                "log_file_path": "{}",
                "log_file_count": 3,
                "adapter_type": "linux-native",
                "interface": {{ "name": "nlx", "config_provider": "manual" }},
                "vpn": {{ "country": "de" }},
                "dns": ["1.1.1.1", "8.8.8.8"],
                "override_default_wg_port": 51820,
                "authentication_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }}"#,
            log_path.display()
        )
        .into_bytes();

        let config =
            NordVpnLiteConfig::from_bytes(&bytes).expect("from_bytes should accept all fields");

        assert_eq!(config.log_level, LevelFilter::DEBUG);
        assert_eq!(config.log_file_count, 3);
        assert_eq!(config.vpn, VpnConfig::Country("de".to_owned()));
        assert_eq!(
            config.dns,
            vec![
                IpAddr::from(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::from(Ipv4Addr::new(8, 8, 8, 8)),
            ]
        );
        assert_eq!(config.override_default_wg_port, Some(51820));
        assert_eq!(config.log_file_path, log_path.to_string_lossy().as_ref());
    }
}
