use std::{
    fs,
    io::{BufReader, Write},
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use tracing::{level_filters::LevelFilter, Level};

use telio_core::{crypto::PublicKey, device::AdapterType};

use crate::{
    auth::{NordToken, NordVpnLiteAuth},
    interface::InterfaceConfig,
    NordVpnLiteError, DEFAULT_FILE_PERMISSIONS,
};

#[derive(Clone, Debug)]
pub struct RunningConfig {
    pub parsed: NordVpnLiteConfig,
    pub path: PathBuf,
    pub hash: u64,
}

impl RunningConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, NordVpnLiteError> {
        let path = path.as_ref().to_path_buf();
        let parsed = NordVpnLiteConfig::from_file(&path)?;
        let path = path.canonicalize()?;
        let hash = Self::hash_file(&path).unwrap_or(0);
        Ok(Self { parsed, path, hash })
    }

    fn hash_file(path: &Path) -> Result<u64, std::io::Error> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::io::BufRead;

        const CHUNK_SIZE: usize = 8 * 1024; // 8 KiB

        let file = fs::File::open(path)?;
        let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
        let mut hasher = DefaultHasher::new();

        loop {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                break;
            }
            chunk.hash(&mut hasher);
            let len = chunk.len();
            reader.consume(len);
        }

        Ok(hasher.finish())
    }

    pub fn migrate_config_format(&mut self, config_path: &str) -> Result<(), NordVpnLiteError> {
        let result = self.parsed.migrate_config_format(config_path);
        match result {
            Ok(true) => {
                // Update the hash after migration to reflect the new file content
                self.hash = Self::hash_file(&self.path).unwrap_or(0);
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// These IPs are documented but the documentation is not publicly available
fn dns_default() -> Vec<IpAddr> {
    vec![
        Ipv4Addr::new(103, 86, 96, 100).into(),
        Ipv4Addr::new(103, 86, 99, 100).into(),
    ]
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NordVpnLiteConfig {
    /// Authentication credentials file path
    #[serde(default = "default_auth_file_path")]
    pub auth_file_path: String,
    /// Backward compatibility: accept old config format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_token: Option<NordToken>,

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

    #[serde(default)]
    pub post_quantum: bool,
}

impl NordVpnLiteConfig {
    /// Construct a NordVpnLiteConfig by deserializing a file at given path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, NordVpnLiteError> {
        let path = path.as_ref();
        println!("Reading config from: {}", path.display());

        match fs::File::open(path) {
            Ok(file) => {
                let mut config: NordVpnLiteConfig = serde_json::from_reader(BufReader::new(file))?;
                config.log_file_path = Self::resolve_log_path(&config.log_file_path)?;
                config.auth_file_path = Self::resolve_auth_path(&config.auth_file_path)?;
                Ok(config)
            }
            // Create a default config if it does not exist
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                println!(
                    "File not found, creating default config: {}",
                    path.display()
                );

                // Write default config to file
                let default_config = NordVpnLiteConfig::default();
                default_config.to_file(path)?;

                Ok(default_config)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Construct a NordVpnLiteConfig by deserializing an existing file at the given path
    pub fn from_existing_file<P: AsRef<Path>>(path: P) -> Result<Self, NordVpnLiteError> {
        let path = path.as_ref();
        println!("Reading config from: {}", path.display());

        match fs::File::open(path) {
            Ok(file) => {
                let mut config: NordVpnLiteConfig = serde_json::from_reader(BufReader::new(file))?;
                config.log_file_path = Self::resolve_log_path(&config.log_file_path)?;
                config.auth_file_path = Self::resolve_auth_path(&config.auth_file_path)?;
                Ok(config)
            }
            Err(err) => Err(err.into()),
        }
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), NordVpnLiteError> {
        let path = path.as_ref();

        // Create directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create the file with restrictive permissions set at creation time.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(DEFAULT_FILE_PERMISSIONS)
            .open(path)?;

        // Ensure permissions are correct even if the file already existed
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(DEFAULT_FILE_PERMISSIONS);
        fs::set_permissions(path, permissions)?;

        let config_json = serde_json::to_string_pretty(&self)?;
        file.write_all(config_json.as_bytes())?;
        Ok(())
    }

    fn resolve_log_path(log_file_path: &str) -> Result<String, NordVpnLiteError> {
        Self::resolve_path("log_file_path", log_file_path)
    }

    fn resolve_auth_path(auth_file_path: &str) -> Result<String, NordVpnLiteError> {
        Self::resolve_path("auth_file_path", auth_file_path)
    }

    fn resolve_path(key: &str, file_path: &str) -> Result<String, NordVpnLiteError> {
        let path = PathBuf::from(file_path);

        let file_name = path
            .file_name()
            .ok_or_else(|| NordVpnLiteError::InvalidConfigOption {
                key: key.to_owned(),
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
                        key: key.to_owned(),
                        msg: format!("could not resolve directory: {e}"),
                        value: path.to_string_lossy().into_owned(),
                    })?;
            path_canonical.join(file_name)
        } else {
            if let Some(parent) = path.parent() {
                if !parent.is_dir() {
                    return Err(NordVpnLiteError::InvalidConfigOption {
                        key: key.to_owned(),
                        msg: "parent directory does not exist".to_owned(),
                        value: path.to_string_lossy().into_owned(),
                    });
                }
            }
            path
        };

        Ok(final_path.to_string_lossy().to_string())
    }

    pub fn logging_params_changed(&self, other: &Self) -> bool {
        self.log_file_path != other.log_file_path
            || self.log_level != other.log_level
            || self.log_file_count != other.log_file_count
    }

    /// Migrate the config format if it contains an authentication token.
    /// This is a one-time action to move the token to a dedicated file (if not present)
    /// and update the config file to remove the token.
    pub fn migrate_config_format(&mut self, config_path: &str) -> Result<bool, NordVpnLiteError> {
        if let Some(token) = self.authentication_token.take() {
            // If the auth file already exists and contains a valid token, we don't overwrite it.
            if NordVpnLiteAuth::from_existing_file(&self.auth_file_path).is_err() {
                let auth = NordVpnLiteAuth::new(token);
                auth.to_file(&self.auth_file_path)?;
                println!(
                    "Config migration - auth token moved to a dedicated file: {}",
                    self.auth_file_path
                );
            }
            self.to_file(config_path)?;
            println!(
                "Config migration - configuration file updated: {}",
                config_path
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// Ensure a usable authentication token is configured.
    ///
    /// Checks if it is available in the environment or in the auth file.
    /// Distinguishes the "not logged in yet" case from genuine failures
    /// such as a corrupt file or insufficient permissions.
    pub fn check_auth_token(&self) -> Result<(), NordVpnLiteError> {
        if NordVpnLiteAuth::resolve_env_token().is_some() {
            // Allow the authentication via the environment
            return Ok(());
        }
        match NordVpnLiteAuth::from_existing_file(&self.auth_file_path) {
            Ok(_) => Ok(()),
            // Auth file absent: the user simply hasn't logged in yet.
            Err(NordVpnLiteError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(NordVpnLiteError::InvalidConfigToken {
                    msg:
                        "Please retrieve your authentication token from https://my.nordaccount.com \
                         and use the following command to set it: `nordvpnlite login <your_token>` \
                         (or `nordvpnlite login --token <your_token>`)."
                            .to_owned(),
                })
            }
            // File exists but could not be read/parsed/validated: surface the real cause.
            Err(err) => Err(err),
        }
    }

    /// Get the authentication token from the environment.
    fn get_auth_env() -> Option<NordToken> {
        let auth = NordVpnLiteAuth::resolve_env_token();
        auth.map(|a| a.get_token())
    }

    /// Get the authentication token from the auth file.
    fn get_auth_file(&self) -> Result<NordToken, NordVpnLiteError> {
        let auth = NordVpnLiteAuth::from_existing_file(&self.auth_file_path)?;
        Ok(auth.get_token())
    }

    /// Get the authentication token from either the environment or the auth file.
    /// The environment variable takes precedence over the auth file.
    pub fn get_auth_token(&self) -> Result<NordToken, NordVpnLiteError> {
        if let Some(token) = Self::get_auth_env() {
            Ok(token)
        } else {
            self.get_auth_file()
        }
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
            authentication_token: None,
            auth_file_path: default_auth_file_path(),
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
            http_certificate_file_path: None,
            enable_firewall: false,
            post_quantum: false,
        }
    }
}

fn serialize_adapter_type<S>(adapter: &AdapterType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let name = match adapter {
        AdapterType::NepTUN => "neptun",
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

const fn default_log_file_count() -> usize {
    7
}

#[cfg(not(test))]
fn default_auth_file_path() -> String {
    "/etc/nordvpnlite/auth.json".to_string()
}

#[cfg(test)]
fn default_auth_file_path() -> String {
    "/tmp/nordvpnlite-auth.json".to_string()
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
    use crate::test_utils::{
        build_json, temp_config, write_auth_file, EnvVarHelper, NORD_TOKEN_ENV, OTHER_VALID_TOKEN,
        VALID_TOKEN,
    };

    use super::*;
    use serial_test::serial;
    use temp_file::TempFile;

    fn config_json(log_path: &str, auth_path: &str) -> String {
        build_json(log_path, auth_path, r#"{ "country": "lt" }"#)
    }

    /// Build a config whose auth file points at `auth_file_path`.
    fn config_with_auth_path(auth_file_path: &str) -> NordVpnLiteConfig {
        NordVpnLiteConfig {
            auth_file_path: auth_file_path.to_owned(),
            ..Default::default()
        }
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
            authentication_token: None,
            override_default_wg_port: None,
            auth_file_path: "auth.json".to_owned(),
            http_certificate_file_path: None,
            enable_firewall: false,
            post_quantum: false,
        };
        {
            let json = r#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "auth_file_path": "auth.json",
            "adapter_type": "linux-native",
            "interface": {
                "name": "utun10",
                "config_provider": "manual"
            },
            "vpn": "recommended",
            "post_quantum": false
            }"#;

            assert_eq!(expected, serde_json::from_str(json).unwrap());
        }

        {
            let json = r#"{
                "log_level": "Info",
                "log_file_path": "test.log",
                "auth_file_path": "auth.json",
                "adapter_type": "linux-native",
                "interface": {
                    "name": "utun10",
                    "config_provider": "manual"
                }
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
            "auth_file_path": "/tmp/nordvpnlite-auth.json",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "vpn": "recommended"
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_dns_custom() {
        let expected_config = NordVpnLiteConfig {
            dns: vec![Ipv4Addr::new(1, 1, 1, 1).into()],
            ..Default::default()
        };

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "auth_file_path": "/tmp/nordvpnlite-auth.json",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "dns": ["1.1.1.1"]
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_dns_custom_multiple() {
        let expected_config = NordVpnLiteConfig {
            dns: vec![
                Ipv4Addr::new(1, 1, 1, 1).into(),
                Ipv4Addr::new(8, 8, 8, 8).into(),
            ],
            ..Default::default()
        };

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "auth_file_path": "/tmp/nordvpnlite-auth.json",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "dns": ["1.1.1.1", "8.8.8.8"]
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_vpn_and_dns_default_setting() {
        let expected_config = NordVpnLiteConfig::default();

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "auth_file_path": "/tmp/nordvpnlite-auth.json",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            }
            }"#;

        assert_eq!(expected_config, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn test_config_post_quantum() {
        let mut expected_config = NordVpnLiteConfig::default();
        expected_config.post_quantum = true;

        let json = r#"{
            "log_level": "Trace",
            "log_file_path": "/var/log/nordvpnlite.log",
            "auth_file_path": "/tmp/nordvpnlite-auth.json",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            },
            "post_quantum": true
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
            "auth_file_path": "/tmp/nordvpnlite-auth.json",
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
            }
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
            }
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
            }
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
            }
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
            }
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
            }"#;

        assert!(
            serde_json::from_str::<NordVpnLiteConfig>(json).is_err(),
            "Bad DNS ip"
        );
    }

    #[test]
    fn test_config_with_absolute_path() {
        let log_path = std::env::current_dir().unwrap().join("absolute.log");
        let auth_path = std::env::current_dir().unwrap().join("auth.json");
        let config_json = config_json(log_path.to_str().unwrap(), auth_path.to_str().unwrap());

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
        let config_json = config_json("./relative.log", "./auth.json");
        let file = temp_config(&config_json);
        let config = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap();

        let expected = std::env::current_dir().unwrap().join("relative.log");
        assert_eq!(config.log_file_path, expected.to_string_lossy());
    }

    #[test]
    fn test_invalid_log_path_returns_error() {
        let config = config_json("", "./auth.json");

        let file = temp_config(&config);
        let err = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap_err();

        assert!(
            matches!(err, NordVpnLiteError::InvalidConfigOption { ref key, .. } if key == "log_file_path"),
            "expected InvalidConfigOption for log_file_path, got: {err:?}"
        );

        let config = config_json("./relative.log", "");

        let file = temp_config(&config);
        let err = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap_err();

        assert!(
            matches!(err, NordVpnLiteError::InvalidConfigOption { ref key, .. } if key == "auth_file_path"),
            "expected InvalidConfigOption for auth_file_path, got: {err:?}"
        );
    }

    #[test]
    fn test_from_file_creates_default() {
        use std::os::unix::fs::PermissionsExt;

        let file = TempFile::new().expect("Failed to create temp file");
        let path = file.path().to_str().unwrap().to_owned();
        drop(file);

        assert!(!std::path::Path::new(&path).exists());

        let config = NordVpnLiteConfig::from_file(&path)
            .expect("from_file should create and return a default config");

        // default config should have been created
        assert_eq!(config, NordVpnLiteConfig::default());

        // verify config file was created with correct permissions
        assert!(std::path::Path::new(&path).exists());
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, DEFAULT_FILE_PERMISSIONS);

        // verify that the config can be read back from the file
        let config = NordVpnLiteConfig::from_existing_file(&path)
            .expect("written default config should be readable");
        assert_eq!(config, NordVpnLiteConfig::default());
    }

    #[test]
    fn test_from_file_propagates_errors() {
        use std::os::unix::fs::PermissionsExt;

        let file = TempFile::new().expect("Failed to create temp file");
        let path = file.path().to_str().unwrap().to_owned();

        assert!(std::path::Path::new(&path).exists());
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        // make sure test executed without root privileges
        if fs::File::open(&path).is_err() {
            let result = NordVpnLiteConfig::from_file(&path);
            assert_matches::assert_matches!(
                result,
                Err(NordVpnLiteError::Io(ref e)) if e.kind() == std::io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn test_get_auth_file_reads_token() {
        let auth_file = TempFile::new().expect("Failed to create temp auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();
        write_auth_file(&auth_path, VALID_TOKEN);

        let config = config_with_auth_path(&auth_path);
        let token = config
            .get_auth_file()
            .expect("get_auth_file should read a valid token");
        assert_eq!(token.as_ref(), VALID_TOKEN);
    }

    #[test]
    fn test_get_auth_file_errors_when_missing() {
        let auth_file = TempFile::new().expect("Failed to create temp auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();
        drop(auth_file);

        let config = config_with_auth_path(&auth_path);
        assert_matches::assert_matches!(
            config.get_auth_file(),
            Err(NordVpnLiteError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn test_from_existing_file_errors_when_missing() {
        let file = TempFile::new().expect("Failed to create temp config file");
        let path = file.path().to_owned();
        drop(file);

        assert_matches::assert_matches!(
            NordVpnLiteConfig::from_existing_file(&path),
            Err(NordVpnLiteError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn test_resolve_relative_path_missing_parent() {
        let config = config_json("does_not_exist_dir/relative.log", "./auth.json");
        let file = temp_config(&config);
        let err = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap_err();

        assert_matches::assert_matches!(
            err,
            NordVpnLiteError::InvalidConfigOption { ref key, .. } if key == "log_file_path"
        );
    }

    #[test]
    fn test_resolve_absolute_path_missing_parent() {
        let config = config_json("/nonexistent_dir_for_test/absolute.log", "./auth.json");
        let file = temp_config(&config);
        let err = NordVpnLiteConfig::from_file(file.path().to_str().unwrap()).unwrap_err();

        assert_matches::assert_matches!(
            err,
            NordVpnLiteError::InvalidConfigOption { ref key, ref msg, .. }
                if key == "log_file_path" && msg == "parent directory does not exist"
        );
    }

    #[test]
    fn test_deserialize_invalid_adapter_type() {
        let json = r#"{
            "log_level": "Info",
            "log_file_path": "test.log",
            "auth_file_path": "auth.json",
            "adapter_type": "not-a-real-adapter",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            }
            }"#;

        assert!(serde_json::from_str::<NordVpnLiteConfig>(json).is_err());
    }

    #[test]
    fn test_deserialize_invalid_log_level() {
        let json = r#"{
            "log_level": "not-a-real-level",
            "log_file_path": "test.log",
            "auth_file_path": "auth.json",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "manual"
            }
            }"#;

        assert!(serde_json::from_str::<NordVpnLiteConfig>(json).is_err());
    }

    #[test]
    fn test_serialize_adapter_type_all_variants() {
        fn serialized(adapter: AdapterType) -> String {
            let config = NordVpnLiteConfig {
                adapter_type: adapter,
                ..Default::default()
            };
            let value: serde_json::Value =
                serde_json::to_value(&config).expect("config should serialize");
            value["adapter_type"].as_str().unwrap().to_owned()
        }

        assert_eq!(serialized(AdapterType::NepTUN), "neptun");
        assert_eq!(serialized(AdapterType::LinuxNativeWg), "linux-native");
        assert_eq!(serialized(AdapterType::WindowsNativeWg), "wireguard-nt");
    }

    #[test]
    fn test_serialize_log_level() {
        fn serialized(level: LevelFilter) -> String {
            let config = NordVpnLiteConfig {
                log_level: level,
                ..Default::default()
            };
            let value: serde_json::Value =
                serde_json::to_value(&config).expect("config should serialize");
            value["log_level"].as_str().unwrap().to_owned()
        }

        assert_eq!(serialized(LevelFilter::INFO), "info");
        assert_eq!(serialized(LevelFilter::TRACE), "trace");
        assert_eq!(serialized(LevelFilter::OFF), "off");
    }

    #[test]
    fn test_config_serde_all_fields() {
        let json = r#"{
            "log_level": "Debug",
            "log_file_path": "/var/log/nordvpnlite.log",
            "log_file_count": 3,
            "auth_file_path": "/etc/nordvpnlite/auth.json",
            "adapter_type": "neptun",
            "interface": {
                "name": "nlx",
                "config_provider": "iproute",
                "max_route_priority": 100
            },
            "vpn": {
                "server": {
                    "address": "127.0.0.1",
                    "public_key": "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro=",
                    "hostname": "de123.nordvpn.com"
                }
            },
            "dns": ["1.1.1.1", "8.8.8.8"],
            "override_default_wg_port": 51820,
            "http_certificate_file_path": "/etc/nordvpnlite/cert.pem",
            "enable_firewall": true
            }"#;

        let config: NordVpnLiteConfig = serde_json::from_str(json).unwrap();

        // Verify the parsed non-default values.
        assert_eq!(config.log_level, LevelFilter::DEBUG);
        assert_eq!(config.log_file_count, 3);
        assert_eq!(config.adapter_type, AdapterType::NepTUN);
        assert_eq!(config.interface.max_route_priority, Some(100));
        assert_eq!(
            config.interface.config_provider,
            InterfaceConfigurationProvider::Iproute
        );
        assert_eq!(config.override_default_wg_port, Some(51820));
        assert_eq!(
            config.http_certificate_file_path,
            Some(PathBuf::from("/etc/nordvpnlite/cert.pem"))
        );
        assert!(config.enable_firewall);
        assert_matches::assert_matches!(
            config.vpn,
            VpnConfig::Server(Endpoint { hostname: Some(ref h), .. }) if h == "de123.nordvpn.com"
        );

        // Round-trip: serialize and deserialize again, expecting an identical value.
        let serialized = serde_json::to_string(&config).expect("config should serialize");
        let deserialized: NordVpnLiteConfig =
            serde_json::from_str(&serialized).expect("serialized config should deserialize");
        assert_eq!(config, deserialized);
    }

    #[test]
    #[serial]
    fn test_check_auth_token_valid_auth_file() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_file = TempFile::new().expect("Failed to create temp auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();

        let token = NordToken::new(VALID_TOKEN).expect("token should be valid");
        NordVpnLiteAuth::new(token)
            .to_file(&auth_path)
            .expect("Failed to write auth file");

        let config = config_with_auth_path(&auth_path);
        config
            .check_auth_token()
            .expect("check_auth_token should succeed for a valid token file");
    }

    #[test]
    #[serial]
    fn test_check_auth_token_returns_login_hint() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_file = TempFile::new().expect("Failed to create temp auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();
        drop(auth_file);

        let config = config_with_auth_path(&auth_path);
        assert_matches::assert_matches!(
            config.check_auth_token(),
            Err(NordVpnLiteError::InvalidConfigToken { msg })
                if msg == "Please retrieve your authentication token from https://my.nordaccount.com \
                           and use the following command to set it: `nordvpnlite login <your_token>` \
                           (or `nordvpnlite login --token <your_token>`)."
        );
    }

    #[test]
    #[serial]
    fn test_check_auth_token_propagates_permission_error() {
        use std::os::unix::fs::PermissionsExt;

        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let dir = std::env::temp_dir().join("nordvpnlite_auth_perms");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("auth.json");
        let token = NordToken::new(VALID_TOKEN).expect("token should be valid");
        NordVpnLiteAuth::new(token)
            .to_file(&path)
            .expect("Failed to write auth file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        // Only assert when running without privileges that bypass permissions.
        if fs::File::open(&path).is_err() {
            let config = config_with_auth_path(path.to_str().unwrap());
            assert_matches::assert_matches!(
                config.check_auth_token(),
                Err(NordVpnLiteError::Io(ref e)) if e.kind() == std::io::ErrorKind::PermissionDenied
            );
        }

        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    fn test_check_auth_token_propagates_corrupt_file_error() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        let auth_file = TempFile::new()
            .expect("Failed to create temp auth file")
            .with_contents(b"{ this is not valid json")
            .expect("Failed to write auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();

        let config = config_with_auth_path(&auth_path);
        assert_matches::assert_matches!(
            config.check_auth_token(),
            Err(NordVpnLiteError::ParsingError(_))
        );
    }

    #[test]
    #[serial]
    fn test_check_auth_token_env_token() {
        let _env = EnvVarHelper::set(NORD_TOKEN_ENV, VALID_TOKEN);
        let auth_file = TempFile::new().expect("Failed to create temp auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();
        drop(auth_file);

        let config = config_with_auth_path(&auth_path);
        let result = config.check_auth_token();

        result.expect("should succeed when env token is set");
    }

    #[test]
    #[serial]
    fn test_get_auth_env_returns_token_when_set() {
        let _env = EnvVarHelper::set(NORD_TOKEN_ENV, VALID_TOKEN);
        let token = NordVpnLiteConfig::get_auth_env();
        assert_eq!(
            token.expect("env token should resolve").as_ref(),
            VALID_TOKEN
        );
    }

    #[test]
    #[serial]
    fn test_get_auth_env_returns_none_when_unset() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);
        assert!(NordVpnLiteConfig::get_auth_env().is_none());
    }

    #[test]
    #[serial]
    fn test_get_auth_token_prefers_env_over_file() {
        let _env = EnvVarHelper::set(NORD_TOKEN_ENV, OTHER_VALID_TOKEN);

        let auth_file = TempFile::new().expect("Failed to create temp auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();
        write_auth_file(&auth_path, VALID_TOKEN);

        let config = config_with_auth_path(&auth_path);
        let token = config.get_auth_token();

        assert_eq!(
            token.expect("env token should be used").as_ref(),
            OTHER_VALID_TOKEN
        );
    }

    #[test]
    #[serial]
    fn test_get_auth_token_falls_back_to_file() {
        let _env = EnvVarHelper::unset(NORD_TOKEN_ENV);

        let auth_file = TempFile::new().expect("Failed to create temp auth file");
        let auth_path = auth_file.path().to_str().unwrap().to_owned();
        write_auth_file(&auth_path, VALID_TOKEN);

        let config = config_with_auth_path(&auth_path);
        let token = config
            .get_auth_token()
            .expect("should fall back to the file");

        assert_eq!(token.as_ref(), VALID_TOKEN);
    }

    #[test]
    fn test_migrate_config_format() {
        let config_json = format!(
            r#"{{
            "log_level": "Info",
            "log_file_path": "test.log",
            "adapter_type": "linux-native",
            "interface": {{
                "name": "utun10",
                "config_provider": "manual"
            }},
            "vpn": "recommended",
            "post_quantum": false,
            "authentication_token": "{}"
        }}"#,
            VALID_TOKEN
        );

        let config_file = temp_config(&config_json);
        let config_path = config_file.path().to_str().unwrap().to_owned();

        let mut config: NordVpnLiteConfig =
            NordVpnLiteConfig::from_existing_file(&config_path).expect("config should load");

        config
            .migrate_config_format(&config_path)
            .expect("migration should succeed");
        assert!(
            config.authentication_token.is_none(),
            "in-memory config should clear inline token after migration"
        );

        let migrated_auth = NordVpnLiteAuth::from_existing_file(&config.auth_file_path)
            .expect("auth file should be created during migration");
        assert_eq!(migrated_auth.get_token().as_ref(), VALID_TOKEN);

        let migrated_config = NordVpnLiteConfig::from_existing_file(&config_path)
            .expect("migrated config file should be readable");
        assert!(
            migrated_config.authentication_token.is_none(),
            "migrated config should not contain inline auth token"
        );
    }

    #[test]
    fn running_config_valid_file_loads_parsed_config() {
        let auth_path = std::env::current_dir().unwrap().join("auth.json");
        let log_path = std::env::current_dir().unwrap().join("test.log");
        let json = format!(
            r#"{{
                "log_level": "Info",
                "log_file_path": "{}",
                "auth_file_path": "{}",
                "adapter_type": "linux-native",
                "interface": {{ "name": "utun10", "config_provider": "manual" }}
            }}"#,
            log_path.display(),
            auth_path.display()
        );
        let file = temp_config(&json);

        let rc = RunningConfig::from_file(file.path()).unwrap();

        assert_eq!(rc.parsed.adapter_type, AdapterType::LinuxNativeWg);
        assert_eq!(rc.parsed.interface.name, "utun10");
    }

    #[test]
    fn running_config_valid_file_canonicalizes_path() {
        let json = config_json("test.log", "auth.json");
        let file = temp_config(&json);

        let rc = RunningConfig::from_file(file.path()).unwrap();

        assert!(
            rc.path.is_absolute(),
            "path should be absolute after canonicalization"
        );
        assert_eq!(rc.path, file.path().canonicalize().unwrap());
    }

    #[test]
    fn running_config_valid_file_produces_nonzero_hash() {
        let json = config_json("test.log", "auth.json");
        let file = temp_config(&json);

        let rc = RunningConfig::from_file(file.path()).unwrap();

        assert_ne!(rc.hash, 0, "hash should be non-zero for a non-empty file");
    }

    #[test]
    fn running_config_same_content_produces_same_hash() {
        let json = config_json("test.log", "auth.json");

        let file_a = temp_config(&json);
        let file_b = temp_config(&json);

        let rc_a = RunningConfig::from_file(file_a.path()).unwrap();
        let rc_b = RunningConfig::from_file(file_b.path()).unwrap();

        assert_eq!(
            rc_a.hash, rc_b.hash,
            "identical file contents must produce the same hash"
        );
    }

    #[test]
    fn running_config_different_content_produces_different_hash() {
        let json_a = config_json("a.log", "auth.json");
        let json_b: String = config_json("b.log", "auth.json");

        let file_a = temp_config(&json_a);
        let file_b = temp_config(&json_b);

        let rc_a = RunningConfig::from_file(file_a.path()).unwrap();
        let rc_b = RunningConfig::from_file(file_b.path()).unwrap();

        assert_ne!(
            rc_a.hash, rc_b.hash,
            "different file contents should produce different hashes"
        );
    }

    #[test]
    fn running_config_invalid_json_returns_error() {
        let file = temp_config("this is not json {{ }}");

        let err = RunningConfig::from_file(file.path())
            .expect_err("RunningConfig::from_file should fail on malformed JSON");

        assert!(
            matches!(err, NordVpnLiteError::ParsingError(_)),
            "expected ParsingError for invalid JSON, got: {err:?}"
        );
    }

    #[test]
    fn running_config_file_not_found_creates_default_and_returns_token_error() {
        let dir = temp_dir::TempDir::new().expect("failed to create temp dir");
        let nonexistent = dir.path().join("does_not_exist.json");

        RunningConfig::from_file(&nonexistent).expect(
            "RunningConfig::from_file should create a default config file if it does not exist",
        );

        assert!(
            nonexistent.exists(),
            "default config file should have been created"
        );
    }
}
