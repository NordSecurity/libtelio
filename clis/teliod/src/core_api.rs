use base64::{prelude::*, DecodeError};
use reqwest::{header, Certificate, Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use telio::crypto::SecretKey;
use telio::telio_lana::telio_log_warn;
use telio::telio_utils::exponential_backoff::{
    Backoff, Error as BackoffError, ExponentialBackoff, ExponentialBackoffBounds,
};

use crate::config::TeliodDaemonConfig;

use telio::{crypto::PublicKey, telio_model::config::Config as MeshMap};
use thiserror::Error;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

const API_BASE: &str = "https://api.nordvpn.com/v1";
#[cfg(target_os = "macos")]
const OS_NAME: &str = "macos";
#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";
const WIREGUARD_ID: u64 = 35;

type MachineIdentifier = String;
const MAX_RETRIES: usize = 10;
const REQUEST_TIMEOUT_SECONDS: u64 = 30;

static DEVICE_IDENTITY_FILE_PATH: LazyLock<Result<PathBuf, Error>> = LazyLock::new(|| {
    dirs::data_local_dir()
        .ok_or(Error::NoDataLocalDir)
        .and_then(|mut path| {
            path.push("teliod");
            create_dir_all(&path)?;
            path.push("data.json");
            Ok(path)
        })
});

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),
    #[error("Unable to fetch Machine Identifier: {0}")]
    FetchingIdentifier(StatusCode),
    #[error("Unable to register due to Error: {0}")]
    PeerRegistering(StatusCode),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("Invalid response received from server")]
    InvalidResponse,
    #[error("Unable to update machine due to Error: {0}")]
    UpdateMachine(StatusCode),
    #[error("Max retries exceeded for connection")]
    ExpBackoffTimeout(),
    #[error("No local data directory found")]
    NoDataLocalDir,
    #[error("Device not registered with server")]
    DeviceNotFound,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BackoffBounds(#[from] BackoffError),
    #[error("Failed to access device identity file")]
    DeviceIdentityFileAccess,
    #[error("API responded with error: {0}")]
    ApiErrorResponse(ErrorDetail),
}

/// Error response returned by the Core API in case of bad requests
///
/// For example:
/// ```json
/// {
///  "errors": {
///    "code": 101101,
///    "message": "Invalid form data: {...}"
///  }
/// }
/// ```
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    pub errors: ErrorDetail,
}

/// Error details
#[derive(Debug, Deserialize)]
pub struct ErrorDetail {
    pub code: u32,
    pub message: String,
}

impl Display for ErrorDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Country description returned by the Core API
#[derive(Debug, PartialEq, Deserialize)]
pub struct Country {
    /// Internal country ID
    pub id: u64,
    /// Full country name
    pub name: String,
    /// Country ISO A2 code
    pub code: String,
}

impl Country {
    /// Check if the given &str is either full name or ISO code of the country
    pub fn matches(&self, target: &str) -> bool {
        let target = target.trim().to_lowercase();
        self.name.trim().to_lowercase() == target || self.code.trim().to_lowercase() == target
    }
}

/// VPN Server description returned by the Core API
#[derive(Debug, PartialEq, Deserialize)]
pub struct Server {
    station: IpAddr,
    hostname: Option<String>,
    technologies: Vec<Technology>,
}

/// VPN Server technology stack
#[derive(Debug, PartialEq, Deserialize)]
struct Technology {
    id: u64,
    metadata: Vec<Metadata>,
}

/// VPN Server technology stack metadata
#[derive(Debug, PartialEq, Deserialize)]
struct Metadata {
    name: String,
    value: String,
}

impl Server {
    /// Get IP address of server
    pub fn address(&self) -> IpAddr {
        self.station
    }

    /// Get hostname of VPN server
    pub fn hostname(&self) -> Option<String> {
        self.hostname.to_owned()
    }

    /// Get public_key of wireguard service
    pub fn wg_public_key(&self) -> Option<String> {
        self.technologies
            .iter()
            .filter(|t| t.id == WIREGUARD_ID)
            .flat_map(|t| &t.metadata)
            .filter(|m| m.name == "public_key")
            .map(|m| m.value.to_owned())
            .next()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct MeshConfig {
    public_key: PublicKey,
    hardware_identifier: String,
    os: String,
    os_version: String,
    device_type: String,
    traffic_routing_supported: bool,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DeviceIdentity {
    pub hw_identifier: uuid::Uuid,
    pub private_key: SecretKey,
    pub machine_identifier: String,
}

impl DeviceIdentity {
    /// Generate a new device identity.
    /// A new key and hw id are generated, whereas the machine id is fetched from the
    /// API with a [1,180]s exponential backoff.
    pub async fn new(config: &TeliodDaemonConfig) -> Result<Self, Error> {
        let private_key = SecretKey::gen();
        let hw_identifier = uuid::Uuid::new_v4();

        // LLT-6406: There's likely a bug here since looking for a device with a private key that
        // we just created above is trivial and will fail. This will always register a new device.
        let machine_identifier = match fetch_identifier_with_exp_backoff(
            &config.authentication_token,
            &config.http_certificate_file_path,
            private_key.public(),
        )
        .await
        {
            Ok(id) => id,
            Err(e) => match e {
                Error::DeviceNotFound => {
                    info!("Unable to load identifier due to {e}. Registering ...");
                    Box::pin(register_machine_with_exp_backoff(
                        &hw_identifier.to_string(),
                        private_key.public(),
                        &config.authentication_token,
                        &config.http_certificate_file_path,
                    ))
                    .await?
                }
                _ => return Err(e),
            },
        };

        Ok(DeviceIdentity {
            private_key,
            hw_identifier,
            machine_identifier,
        })
    }

    /// Device identity is parsed from a given file.
    /// Either the path is provided as parameter or hardcoded path
    /// is used.
    pub fn from_file(path: Option<&Path>) -> Result<DeviceIdentity, Error> {
        info!("Fetching identity config");

        let path = path.unwrap_or(Self::device_identity_path()?);

        match std::fs::File::open(path) {
            Ok(file) => {
                debug!("Found existing identity config {}", path.to_string_lossy());
                serde_json::from_reader(file).map_err(Error::Deserialize)
            }
            Err(e) => {
                warn!("Reading identity config failed: {e}");
                Err(Error::Io(e))
            }
        }
    }

    // Write device identity to the corresponding file.
    // File path is DEVICE_IDENTITY_FILE_PATH.
    pub fn write(&self) -> Result<(), Error> {
        // User has read/write but others have none
        // Mode for identity file rw-------
        let mut file = OpenOptions::new()
            .mode(0o600)
            .create(true)
            .truncate(true)
            .write(true)
            .open(Self::device_identity_path()?)?;
        serde_json::to_writer(&mut file, &self)?;
        Ok(())
    }

    pub fn remove_file() {
        if let Ok(path) = Self::device_identity_path() {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    info!(
                        "Successfully removed device identity file at {}",
                        path.display()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!(
                        "Device identity file not found at {} - nothing to remove",
                        path.display()
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to remove device identity file at {}: {}",
                        path.display(),
                        e
                    );
                }
            };

            if let Some(parent) = path.parent() {
                match std::fs::remove_dir(parent) {
                    Ok(()) => {
                        debug!("Removed empty directory {}", parent.display());
                    }
                    Err(e) => {
                        debug!("Could not remove directory {}: {}", parent.display(), e);
                    }
                };
            };
        }
    }

    fn device_identity_path() -> Result<&'static Path, Error> {
        DEVICE_IDENTITY_FILE_PATH
            .as_ref()
            .map(|p| p.as_path())
            .map_err(|e| {
                warn!("Failed to access device identity file: {e}");
                Error::DeviceIdentityFileAccess
            })
    }
}

fn build_backoff() -> Result<ExponentialBackoff, Error> {
    let backoff_bounds = ExponentialBackoffBounds {
        initial: Duration::from_secs(1),
        maximal: Some(Duration::from_secs(180)),
    };
    Ok(ExponentialBackoff::new(backoff_bounds)?)
}

fn http_client(cert_path: &Option<PathBuf>) -> Client {
    cert_path
        .as_ref()
        .and_then(|cert_path| {
            File::open(cert_path)
                .inspect_err(|err| {
                    telio_log_warn!("Custom certificate file could not be opened: {err:?}")
                })
                .ok()
        })
        .and_then(|mut cert_file| {
            let mut buf = Vec::new();
            cert_file
                .read_to_end(&mut buf)
                .inspect_err(|err| {
                    telio_log_warn!("Custom certificate file could not be read: {err:?}")
                })
                .ok()
                .and_then(|_| {
                    Certificate::from_pem(&buf)
                        .inspect_err(|err| {
                            telio_log_warn!("Custom certificate file could not be parsed: {err:?}")
                        })
                        .ok()
                })
        })
        .and_then(|cert| {
            telio_log_warn!(
                "Using a self-signed certificate is unsafe and should generally be avoided"
            );
            Client::builder()
                .add_root_certificate(cert)
                .use_rustls_tls()
                .danger_accept_invalid_certs(true)
                .build()
                .inspect_err(|err| {
                    telio_log_warn!("Could not build http client with custom certificate: {err:?}")
                })
                .ok()
        })
        .unwrap_or_default()
}

pub async fn init_with_api(config: &TeliodDaemonConfig) -> Result<DeviceIdentity, Error> {
    let device_identity = if let Ok(parsed_device_identity) =
        DeviceIdentity::from_file(config.device_identity_file_path.as_deref())
    {
        update_machine_with_exp_backoff(
            &config.authentication_token,
            &config.http_certificate_file_path,
            &parsed_device_identity,
        )
        .await?;
        parsed_device_identity
    } else {
        Box::pin(DeviceIdentity::new(config)).await?
    };

    device_identity.write()?;
    Ok(device_identity)
}

async fn update_machine_with_exp_backoff(
    auth_token: &str,
    cert_path: &Option<PathBuf>,
    device_identity: &DeviceIdentity,
) -> Result<(), Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match update_machine(device_identity, auth_token, cert_path).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if let Error::UpdateMachine(_) = e {
                    return Err(e);
                }
                warn!(
                    "Failed to update machine due to {e}, will wait for {:?} and retry",
                    backoff.get_backoff()
                );
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
        }
    }
}

async fn fetch_identifier_with_exp_backoff(
    auth_token: &str,
    cert_path: &Option<PathBuf>,
    public_key: PublicKey,
) -> Result<MachineIdentifier, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match fetch_identifier_from_api(auth_token, cert_path, public_key).await {
            Ok(id) => return Ok(id),
            Err(e) => {
                warn!(
                    "Failed to fetch identifier due to {e:?}, will wait for {:?} and retry",
                    backoff.get_backoff()
                );
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
        }
    }
}

async fn register_machine_with_exp_backoff(
    hw_identifier: &str,
    public_key: PublicKey,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<MachineIdentifier, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match register_machine(hw_identifier, public_key, auth_token, cert_path).await {
            Ok(id) => return Ok(id),
            Err(e) => match e {
                Error::PeerRegistering(_) => return Err(e),
                _ => {
                    warn!(
                        "Failed to register machine due to {e}, will wait for {:?} and retry",
                        backoff.get_backoff()
                    );
                    wait_with_backoff_delay(&mut backoff, &mut retries).await?;
                }
            },
        }
    }
}

async fn wait_with_backoff_delay(
    backoff: &mut ExponentialBackoff,
    retries: &mut usize,
) -> Result<(), Error> {
    tokio::time::sleep(backoff.get_backoff()).await;
    if *retries > MAX_RETRIES {
        return Err(Error::ExpBackoffTimeout());
    }
    backoff.next_backoff();
    *retries += 1;

    Ok(())
}

async fn fetch_identifier_from_api(
    auth_token: &str,
    cert_path: &Option<PathBuf>,
    public_key: PublicKey,
) -> Result<MachineIdentifier, Error> {
    debug!("Fetching machine identifier");
    let client = http_client(cert_path);
    let response = client
        .get(format!("{API_BASE}/meshnet/machines"))
        .header(header::AUTHORIZATION, format!("Bearer token:{auth_token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status();
    if status == StatusCode::OK {
        let json_data: Value = serde_json::from_str(&response.text().await?)?;

        for node in json_data.as_array().ok_or(Error::InvalidResponse)? {
            // Get the public_key and identifier from each item
            if let Some(recvd_pk) = node.get("public_key").and_then(|k| k.as_str()) {
                if BASE64_STANDARD
                    .decode(recvd_pk)?
                    .as_slice()
                    .cmp(&public_key.0)
                    .is_eq()
                {
                    if let Some(identifier) = node.get("identifier").and_then(|i| i.as_str()) {
                        info!("Match found! Identifier: {}", identifier);
                        return Ok(identifier.to_owned());
                    }
                }
            }
        }
        return Err(Error::DeviceNotFound);
    }

    error!(
        "Unable to fetch identifier due to {:?}",
        response.text().await
    );
    Err(Error::FetchingIdentifier(status))
}

async fn update_machine(
    device_identity: &DeviceIdentity,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<(), Error> {
    debug!("Updating machine");
    let client = http_client(cert_path);
    let status = client
        .patch(format!(
            "{}/meshnet/machines/{}",
            API_BASE, device_identity.machine_identifier
        ))
        .header(header::AUTHORIZATION, format!("Bearer token:{auth_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&MeshConfig {
            public_key: device_identity.private_key.public(),
            hardware_identifier: device_identity.hw_identifier.to_string(),
            os: OS_NAME.to_owned(),
            os_version: "teliod".to_owned(),
            device_type: "other".to_owned(),
            traffic_routing_supported: true,
        })
        .send()
        .await?
        .status();

    if status == StatusCode::OK {
        return Ok(());
    }
    Err(Error::UpdateMachine(status))
}

pub async fn get_meshmap(
    device_identity: Arc<DeviceIdentity>,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<MeshMap, Error> {
    debug!("Getting meshmap");
    let client = http_client(cert_path);
    Ok(serde_json::from_str(
        &(client
            .get(format!(
                "{}/meshnet/machines/{}/map",
                API_BASE, device_identity.machine_identifier
            ))
            .header(header::AUTHORIZATION, format!("Bearer token:{auth_token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await?
            .text()
            .await)?,
    )?)
}

/// Get list of all known countries from core API
/// Will retry [MAX_RETRIES] times if request timed out.
pub async fn get_countries_with_exp_backoff(
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<Vec<Country>, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match get_countries(auth_token, cert_path).await {
            Ok(countries) => return Ok(countries),
            Err(Error::Reqwest(ref e)) if e.is_timeout() => {
                warn!(
                    "Failed to fetch countries due to {e}, will wait for {:?} and retry",
                    backoff.get_backoff()
                );
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
            Err(e) => {
                // other error, return immedately
                return Err(e);
            }
        }
    }
}

/// Get list of all known countries from core API
/// used to find the internal country ID for filtering VPN servers
async fn get_countries(
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<Vec<Country>, Error> {
    debug!("Getting countries list");
    let client = http_client(cert_path);
    let response = client
        .get(format!("{}/countries", API_BASE))
        .header(header::AUTHORIZATION, format!("Bearer token:{auth_token}"))
        .header(header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
        .send()
        .await?;
    let status = response.status();
    if status == StatusCode::OK {
        Ok(serde_json::from_str(&(response.text().await)?)?)
    } else {
        if let Ok(error_detail) = serde_json::from_str::<ErrorResponse>(&(response.text().await)?) {
            return Err(Error::ApiErrorResponse(error_detail.errors));
        }
        error!("Unable to get countries list: {:?}", status);
        Err(Error::InvalidResponse)
    }
}

/// Get recommended server list from core API with exponential backoff
/// Will retry [MAX_RETRIES] times if request timed out.
pub async fn get_recommended_servers_with_exp_backoff(
    country_id_filter: Option<u64>,
    limit_filter: Option<u64>,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<Vec<Server>, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match get_recommended_servers(country_id_filter, limit_filter, auth_token, cert_path).await
        {
            Ok(servers) => return Ok(servers),
            Err(Error::Reqwest(ref e)) if e.is_timeout() => {
                warn!(
                    "Failed to fetch recommended servers due to {e}, will wait for {:?} and retry",
                    backoff.get_backoff()
                );
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
            Err(e) => {
                // other error, return immedately
                return Err(e);
            }
        }
    }
}

/// Get recommended server list from core API
/// optionally filtered by country ID and result limit
async fn get_recommended_servers(
    country_id_filter: Option<u64>,
    limit_filter: Option<u64>,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<Vec<Server>, Error> {
    debug!(
        "Getting server recommendations list: country_id:{:?}, limit:{:?}",
        country_id_filter, limit_filter
    );

    let mut filter: Vec<(String, String)> = vec![
        (
            "filters[servers_technologies][id]".into(),
            WIREGUARD_ID.to_string(),
        ),
        (
            "filters[servers_technologies][pivot][status]".into(),
            "online".into(),
        ),
    ];

    // add a filter for limit
    if let Some(limit) = limit_filter {
        filter.push(("limit".into(), limit.to_string()));
    };

    // add a filter for country id
    if let Some(country_id) = country_id_filter {
        filter.push(("filters[country_id]".into(), country_id.to_string()));
    };

    let client = http_client(cert_path);
    let response = client
        .get(format!("{}/servers/recommendations", API_BASE))
        .header(header::AUTHORIZATION, format!("Bearer token:{auth_token}"))
        .header(header::ACCEPT, "application/json")
        .query(&filter)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
        .send()
        .await?;

    let status = response.status();
    if status == StatusCode::OK {
        Ok(serde_json::from_str(&(response.text().await)?)?)
    } else {
        if let Ok(error_detail) = serde_json::from_str::<ErrorResponse>(&(response.text().await)?) {
            return Err(Error::ApiErrorResponse(error_detail.errors));
        }
        error!("Unable to get server recommendations: {:?}", status);
        Err(Error::InvalidResponse)
    }
}

async fn register_machine(
    hw_identifier: &str,
    public_key: PublicKey,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<MachineIdentifier, Error> {
    info!("Registering machine");
    let client = http_client(cert_path);
    let response = client
        .post(format!("{API_BASE}/meshnet/machines"))
        .header(header::AUTHORIZATION, format!("Bearer token:{auth_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&MeshConfig {
            public_key,
            hardware_identifier: hw_identifier.to_owned(),
            os: OS_NAME.to_owned(),
            os_version: "teliod".to_owned(),
            device_type: "other".to_owned(),
            traffic_routing_supported: true,
        })
        .send()
        .await?;

    let status = response.status();
    // Save the machine identifier received from API
    if status == StatusCode::CREATED {
        let response: Value = serde_json::from_str(&response.text().await?)?;
        if let Some(machine_identifier) = response.get("identifier").and_then(|i| i.as_str()) {
            info!("Machine Registered!");
            return Ok(machine_identifier.to_owned());
        } else {
            return Err(Error::InvalidResponse);
        }
    }

    error!("Unable to register due to {:?}", response.text().await);
    Err(Error::PeerRegistering(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::ExitNodeConfig;

    #[test]
    fn test_parse_country() {
        let json = r#"
            [
                {"id":1,"name":"Afghanistan","code":"AF"},
                {"id":2,"name":"Albania","code":"AL"},
                {"id":3,"name":"Algeria","code":"DZ"}
            ]
        "#;

        let countries: Vec<Country> = serde_json::from_str(json).unwrap();
        assert_eq!(countries.len(), 3);
        assert_eq!(
            countries,
            [
                Country {
                    id: 1,
                    name: "Afghanistan".to_string(),
                    code: "AF".to_string()
                },
                Country {
                    id: 2,
                    name: "Albania".to_string(),
                    code: "AL".to_string()
                },
                Country {
                    id: 3,
                    name: "Algeria".to_string(),
                    code: "DZ".to_string()
                }
            ]
        );

        // check we can search for a country by both it's full name and ISO code
        assert!(countries[0].matches("af"));
        assert!(countries[0].matches("afghanistan"));
        assert_eq!(countries[0].id, 1);

        // check the rest of the countries
        assert!(countries[1].matches("al"));
        assert_eq!(countries[1].id, 2);
        assert!(countries[2].matches("dz"));
        assert_eq!(countries[2].id, 3);

        // not equal
        assert!(!countries[0].matches("france"));
    }

    #[test]
    fn test_parse_servers() {
        let json = r#"
            [
            {
                "id": 123456,
                "name": "Test #100",
                "station": "127.0.0.1",
                "ipv6_station": "",
                "hostname": "test100.domain.com",
                "load": 10,
                "status": "online",
                "locations": [
                {
                    "id": 133,
                    "created_at": "2017-06-15 14:06:47",
                    "updated_at": "2017-06-15 14:06:47",
                    "latitude": 50.116667,
                    "longitude": 8.683333,
                    "country": {
                    "id": 81,
                    "name": "Germany",
                    "code": "DE",
                    "city": {
                        "id": 2215709,
                        "name": "Frankfurt",
                        "latitude": 50.116667,
                        "longitude": 8.683333,
                        "dns_name": "frankfurt",
                        "hub_score": 0
                    }
                    }
                }
                ],
                "technologies": [
                {
                    "id": 35,
                    "name": "Wireguard",
                    "identifier": "wireguard_udp",
                    "created_at": "2019-02-14 14:08:43",
                    "updated_at": "2019-02-14 14:08:43",
                    "metadata": [
                    {
                        "name": "public_key",
                        "value": "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro="
                    }
                    ],
                    "pivot": {
                    "technology_id": 35,
                    "server_id": 123456,
                    "status": "online"
                    }
                }
                ]
            }
            ]
        "#;

        let servers: Vec<Server> = serde_json::from_str(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers,
            [Server {
                station: "127.0.0.1".parse().unwrap(),
                hostname: Some("test100.domain.com".to_string()),
                technologies: vec![Technology {
                    id: WIREGUARD_ID,
                    metadata: vec![Metadata {
                        name: "public_key".to_string(),
                        value: "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro=".to_string()
                    }]
                }]
            }]
        );

        let exit_node = servers
            .first()
            .and_then(|server| ExitNodeConfig::from_api(server).ok())
            .unwrap();
        assert_eq!(exit_node.address, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            exit_node.public_key,
            "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro="
                .parse()
                .unwrap()
        );
        assert_eq!(exit_node.hostname, Some("test100.domain.com".to_string()));
    }
}
