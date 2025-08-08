use base64::{prelude::*, DecodeError};
use reqwest::{header, Certificate, Client, StatusCode};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fmt;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use telio::crypto::SecretKey;
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

type MachineIdentifier = String;
const MAX_RETRIES: usize = 10;

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
    #[error("Invalid response recieved from server")]
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
}

/// API error classification for retry logic: LLT-5553
macro_rules! handle_api_error {
    ($error:expr) => {
        match $error {
            // Terminal errors
            Error::PeerRegistering(_)
            | Error::Decode(_)
            | Error::InvalidResponse
            | Error::UpdateMachine(_)
            | Error::ExpBackoffTimeout()
            | Error::NoDataLocalDir
            | Error::DeviceNotFound
            | Error::BackoffBounds(_)
            | Error::DeviceIdentityFileAccess => Err($error),

            // Terminal HTTP status codes
            Error::FetchingIdentifier(status_code) => {
                if status_code == StatusCode::BAD_REQUEST
                    || status_code == StatusCode::UNAUTHORIZED
                    || status_code == StatusCode::FORBIDDEN
                    || status_code == StatusCode::NOT_FOUND
                {
                    Err($error)
                } else {
                    // Server errors (5xx) and other non-terminal errors
                    Ok(())
                }
            }

            // Non-terminal errors
            Error::Reqwest(_) | Error::Deserialize(_) | Error::Io(_) => Ok(()),
        }
    };
}

/// Result of loading device identity
enum IdentityLoadResult {
    /// Identity was loaded from file and synchronized with API
    Loaded(DeviceIdentity),
    /// New identity was created and registered
    Created(DeviceIdentity),
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

#[derive(Serialize, Debug, Default)]
pub struct DeviceIdentity {
    pub hw_identifier: uuid::Uuid,
    pub private_key: SecretKey,
    pub machine_identifier: String,
}

impl DeviceIdentity {
    /// Generate a new device identity.
    /// A new key and hw id are generated, whereas the machine id is obtained after
    /// registering the device with the API, which uses an [1,180]s exponential backoff.
    pub async fn new(config: &TeliodDaemonConfig) -> Result<Self, Error> {
        info!("Generating a new device identity..");
        let private_key = SecretKey::gen();
        let hw_identifier = uuid::Uuid::new_v4();
        let machine_identifier = Box::pin(register_machine_with_exp_backoff(
            &hw_identifier.to_string(),
            private_key.public(),
            &config.authentication_token,
            &config.http_certificate_file_path,
        ))
        .await?;

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
        let path = path.unwrap_or(Self::device_identity_path()?);

        match std::fs::File::open(path) {
            Ok(file) => {
                info!("Found existing identity config {}", path.to_string_lossy());
                serde_json::from_reader(file).map_err(Error::Deserialize)
            }
            Err(e) => {
                info!("Reading identity config failed: {e}");
                Err(Error::Io(e))
            }
        }
    }

    /// Write device identity to file.
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
        info!(
            "Device identity written to {:?}",
            Self::device_identity_path()?
        );
        Ok(())
    }

    /// Remove device identity file.
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
                        "Device identity file not found at {}, nothing to remove",
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

    /// Returns default device identity path based user's local data directory.
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

/// Parses device identity file and handles missing values (LLT-5553).
/// Returned device identity must be matched against the API using the fetch/update functions (PATCH).
/// Missing:
///   - hw_identifier: generates new hw_identifier, API should be updated.
///   - private_key: generates new key pair, API should be updated.
///   - machine_identifier: empty string is acceptable as value can be fetched from API.
impl<'de> Deserialize<'de> for DeviceIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeviceIdentityVisitor;

        impl<'de> Visitor<'de> for DeviceIdentityVisitor {
            type Value = DeviceIdentity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a DeviceIdentity with optional fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut hw_identifier = None;
                let mut private_key = None;
                let mut machine_identifier = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "hw_identifier" => {
                            hw_identifier = Some(map.next_value()?);
                        }
                        "private_key" => {
                            private_key = Some(map.next_value()?);
                        }
                        "machine_identifier" => {
                            machine_identifier = Some(map.next_value()?);
                        }
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                            debug!("Ignoring unknown field: {}", key);
                        }
                    }
                }

                Ok(DeviceIdentity {
                    hw_identifier: hw_identifier.unwrap_or_else(|| {
                        warn!("Identity file missing hardware identifier, a new one is generated",);
                        uuid::Uuid::new_v4()
                    }),
                    private_key: private_key.unwrap_or_else(|| {
                        warn!("Identity file missing private key, a new key pair is generated");
                        SecretKey::gen()
                    }),
                    machine_identifier: machine_identifier.unwrap_or_else(|| {
                        warn!(
                            "Identity file missing machine identifier, is the device registered?"
                        );
                        String::new()
                    }),
                })
            }
        }

        deserializer.deserialize_map(DeviceIdentityVisitor)
    }
}

/// Initialize device identity with API synchronization.
///
/// This function handles three scenarios:
/// 1. No existing identity file, creates a new one and registers it [Created]
/// 2. Existing file but with missing machine_identifier, fetches it from API [Loaded] or registers it if not found [Created]
/// 3. Complete identity file, validate by updating it on API [Loaded], registers it if not found [Created]
pub async fn sync_device_identity(config: &TeliodDaemonConfig) -> Result<DeviceIdentity, Error> {
    let device_identity = match Box::pin(load_or_create_identity(config)).await? {
        IdentityLoadResult::Loaded(identity) => {
            match Box::pin(update_machine_with_exp_backoff(
                &config.authentication_token,
                &config.http_certificate_file_path,
                &identity,
            ))
            .await
            {
                Ok(_) => identity,
                Err(Error::UpdateMachine(StatusCode::NOT_FOUND)) => {
                    warn!("Machine not found while updating, generating new identity..");
                    DeviceIdentity::remove_file();
                    DeviceIdentity::new(config).await?
                }
                Err(e) => return Err(e),
            }
        }
        IdentityLoadResult::Created(identity) => identity,
    };

    device_identity.write()?;
    Ok(device_identity)
}

/// Load existing identity or create a new one
async fn load_or_create_identity(config: &TeliodDaemonConfig) -> Result<IdentityLoadResult, Error> {
    match DeviceIdentity::from_file(config.device_identity_file_path.as_deref()) {
        Ok(mut identity) => {
            if identity.machine_identifier.is_empty() {
                info!("Device identity missing machine identifier, attempting to sync with API");
                match fetch_identifier_with_exp_backoff(
                    &config.authentication_token,
                    &config.http_certificate_file_path,
                    identity.private_key.public(),
                )
                .await
                {
                    Ok(machine_id) => {
                        info!(
                            machine_id = %machine_id,
                            "Successfully fetched existing machine identifier from API"
                        );
                        identity.machine_identifier = machine_id;

                        Ok(IdentityLoadResult::Loaded(identity))
                    }
                    Err(Error::DeviceNotFound) => {
                        info!(
                            hw_id = %identity.hw_identifier,
                            "Device not found in API, registering"
                        );
                        identity.machine_identifier = Box::pin(register_machine_with_exp_backoff(
                            &identity.hw_identifier.to_string(),
                            identity.private_key.public(),
                            &config.authentication_token,
                            &config.http_certificate_file_path,
                        ))
                        .await?;

                        Ok(IdentityLoadResult::Created(identity))
                    }
                    Err(e) => Err(e),
                }
            } else {
                info!(
                    machine_id = %identity.machine_identifier,
                    "Loaded complete device identity"
                );

                Ok(IdentityLoadResult::Loaded(identity))
            }
        }

        Err(e) => {
            warn!(
                error = %e,
                "Failed to load device identity from file, creating new identity"
            );
            let new_identity = DeviceIdentity::new(config).await?;
            Ok(IdentityLoadResult::Created(new_identity))
        }
    }
}

async fn update_machine_with_exp_backoff(
    auth_token: &str,
    cert_path: &Option<PathBuf>,
    device_identity: &DeviceIdentity,
) -> Result<(), Error> {
    info!(
        "Updating existing machine: {}",
        device_identity.machine_identifier
    );
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match update_machine(device_identity, auth_token, cert_path).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                warn!("Failed to update machine due to {e:?}");
                handle_api_error!(e)?;
                warn!("Will wait for {:?} and retry", backoff.get_backoff());
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
    info!("Fetching machine identifier..");
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match fetch_identifier_from_api(auth_token, cert_path, public_key).await {
            Ok(id) => return Ok(id),
            Err(e) => {
                warn!("Failed to fetch identifier due to {e:?}");
                handle_api_error!(e)?;
                warn!("Will wait for {:?} and retry", backoff.get_backoff());
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
    info!("Registering machine..");
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match register_machine(hw_identifier, public_key, auth_token, cert_path).await {
            Ok(id) => return Ok(id),
            Err(e) => {
                warn!("Failed to register machine due to {e:?}");
                handle_api_error!(e)?;
                warn!("Will wait for {:?} and retry", backoff.get_backoff());
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
        }
    }
}

async fn fetch_identifier_from_api(
    auth_token: &str,
    cert_path: &Option<PathBuf>,
    public_key: PublicKey,
) -> Result<MachineIdentifier, Error> {
    let client = http_client(cert_path);
    let response = client
        .get(format!("{API_BASE}/meshnet/machines"))
        .header(header::AUTHORIZATION, format!("Bearer token:{auth_token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status();
    if status.is_success() {
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
                        return Ok(identifier.to_owned());
                    }
                }
            }
        }
        return Err(Error::DeviceNotFound);
    }

    debug!(
        "Unable to fetch device identifier, API returned: [{}] {:?}",
        status,
        response.text().await
    );
    Err(Error::FetchingIdentifier(status))
}

async fn update_machine(
    device_identity: &DeviceIdentity,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<(), Error> {
    let client = http_client(cert_path);
    let response = client
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
        .await?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        debug!(
            "Unable to update device, API returned: [{}] {:?}",
            status,
            response.text().await
        );
        Err(Error::UpdateMachine(status))
    }
}

async fn register_machine(
    hw_identifier: &str,
    public_key: PublicKey,
    auth_token: &str,
    cert_path: &Option<PathBuf>,
) -> Result<MachineIdentifier, Error> {
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
    if status.is_success() {
        let response: Value = serde_json::from_str(&response.text().await?)?;
        if let Some(machine_identifier) = response.get("identifier").and_then(|i| i.as_str()) {
            info!("Machine registered: {}", response);
            return Ok(machine_identifier.to_owned());
        } else {
            return Err(Error::InvalidResponse);
        }
    }

    debug!(
        "Unable to register device, API returned: [{}] {:?}",
        status,
        response.text().await
    );
    Err(Error::PeerRegistering(status))
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
            .header(
                header::AUTHORIZATION,
                format!("Bearer token:{}", auth_token),
            )
            .header(header::ACCEPT, "application/json")
            .send()
            .await?
            .text()
            .await)?,
    )?)
}

fn build_backoff() -> Result<ExponentialBackoff, Error> {
    let backoff_bounds = ExponentialBackoffBounds {
        initial: Duration::from_secs(1),
        maximal: Some(Duration::from_secs(180)),
    };
    Ok(ExponentialBackoff::new(backoff_bounds)?)
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

fn http_client(cert_path: &Option<PathBuf>) -> Client {
    cert_path
        .as_ref()
        .and_then(|cert_path| {
            File::open(cert_path)
                .inspect_err(|err| warn!("Custom certificate file could not be opened: {err:?}"))
                .ok()
        })
        .and_then(|mut cert_file| {
            let mut buf = Vec::new();
            cert_file
                .read_to_end(&mut buf)
                .inspect_err(|err| warn!("Custom certificate file could not be read: {err:?}"))
                .ok()
                .and_then(|_| {
                    Certificate::from_pem(&buf)
                        .inspect_err(|err| {
                            warn!("Custom certificate file could not be parsed: {err:?}")
                        })
                        .ok()
                })
        })
        .and_then(|cert| {
            warn!("Using a self-signed certificate is unsafe and should generally be avoided");
            Client::builder()
                .add_root_certificate(cert)
                .use_rustls_tls()
                .danger_accept_invalid_certs(true)
                .build()
                .inspect_err(|err| {
                    warn!("Could not build http client with custom certificate: {err:?}")
                })
                .ok()
        })
        .unwrap_or_default()
}
