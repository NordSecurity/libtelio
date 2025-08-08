use base64::{prelude::*, DecodeError};
use reqwest::{header, Certificate, Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Read;
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
        info!("Generating a new device identity..");
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
            Err(Error::DeviceNotFound) => {
                info!("Device not found, registering...");
                Box::pin(register_machine_with_exp_backoff(
                    &hw_identifier.to_string(),
                    private_key.public(),
                    &config.authentication_token,
                    &config.http_certificate_file_path,
                ))
                .await?
            }
            Err(e) => return Err(e),
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

    // Write device identity to file.
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
        Err(Error::UpdateMachine(status))
    }
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

    error!(
        "Unable to register device, API returned: [{}] {:?}",
        status,
        response.text().await
    );
    Err(Error::PeerRegistering(status))
}
