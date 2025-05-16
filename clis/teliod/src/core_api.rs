use crate::config::generate_hw_identifier;
use crate::DeviceIdentity;
use base64::{prelude::*, DecodeError};
use reqwest::{header, Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{create_dir_all, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use telio::crypto::SecretKey;
use telio::telio_utils::exponential_backoff::{
    Backoff, Error as BackoffError, ExponentialBackoff, ExponentialBackoffBounds,
};
use telio::telio_utils::Hidden;
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
    #[error("Max retries exceeded for connection: {0}")]
    ExpBackoffTimeout(String),
    #[error("No local data directory found")]
    NoDataLocalDir,
    #[error("Device not registered with server")]
    DeviceNotFound,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BackoffBounds(#[from] BackoffError),
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

fn build_backoff() -> Result<ExponentialBackoff, Error> {
    let backoff_bounds = ExponentialBackoffBounds {
        initial: Duration::from_secs(1),
        maximal: Some(Duration::from_secs(180)),
    };
    Ok(ExponentialBackoff::new(backoff_bounds)?)
}

pub async fn init_with_api(auth_token: &str) -> Result<DeviceIdentity, Error> {
    let mut identity_path = dirs::data_local_dir().ok_or(Error::NoDataLocalDir)?;
    identity_path.push("teliod");
    if !identity_path.exists() {
        let _ = create_dir_all(&identity_path);
    }
    identity_path.push("data.json");

    let mut device_identity = match DeviceIdentity::from_file(&identity_path) {
        Some(identity) => identity,
        None => {
            let private_key = SecretKey::gen();
            let hw_identifier = generate_hw_identifier();

            let machine_identifier =
                match fetch_identifier_with_exp_backoff(auth_token, private_key.public()).await {
                    Ok(id) => id,
                    Err(e) => match e {
                        Error::DeviceNotFound => {
                            info!("Unable to load identifier due to {e}. Registering ...");
                            register_machine_with_exp_backoff(
                                &hw_identifier.to_string(),
                                private_key.public(),
                                auth_token,
                            )
                            .await?
                        }
                        _ => return Err(e),
                    },
                };

            DeviceIdentity {
                private_key,
                hw_identifier,
                machine_identifier,
            }
        }
    };

    if let Err(e) = update_machine_with_exp_backoff(auth_token, &device_identity).await {
        if let Error::UpdateMachine(status) = e {
            if status == StatusCode::NOT_FOUND {
                debug!("Unable to update. Registering machine ...");
                device_identity.machine_identifier = register_machine_with_exp_backoff(
                    &device_identity.hw_identifier.to_string(),
                    device_identity.private_key.public(),
                    auth_token,
                )
                .await?;
            } else {
                // exit daemon
                return Err(Error::UpdateMachine(status));
            }
        } else {
            return Err(e);
        }
    }

    let mut options = OpenOptions::new();
    // User has read/write but others have none
    options.mode(0o600);
    let mut file = options.create(true).write(true).open(identity_path)?;
    serde_json::to_writer(&mut file, &device_identity)?;
    Ok(device_identity)
}

async fn update_machine_with_exp_backoff(
    auth_token: &str,
    device_identity: &DeviceIdentity,
) -> Result<(), Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match update_machine(device_identity, auth_token).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if let Error::UpdateMachine(_) = e {
                    return Err(e);
                }
                wait_with_backoff_delay(&mut backoff, &mut retries, "update machine", e).await?;
            }
        }
    }
}

async fn fetch_identifier_with_exp_backoff(
    auth_token: &str,
    public_key: PublicKey,
) -> Result<MachineIdentifier, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match fetch_identifier_from_api(auth_token, public_key).await {
            Ok(id) => return Ok(id),
            Err(e) => match e {
                Error::FetchingIdentifier(_) | Error::DeviceNotFound => return Err(e),
                _ => {
                    wait_with_backoff_delay(&mut backoff, &mut retries, "fetch identifier", e)
                        .await?;
                }
            },
        }
    }
}

async fn register_machine_with_exp_backoff(
    hw_identifier: &str,
    public_key: PublicKey,
    auth_token: &str,
) -> Result<MachineIdentifier, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match register_machine(hw_identifier, public_key, auth_token).await {
            Ok(id) => return Ok(id),
            Err(e) => match e {
                Error::PeerRegistering(_) => return Err(e),
                _ => {
                    wait_with_backoff_delay(&mut backoff, &mut retries, "register machine", e)
                        .await?;
                }
            },
        }
    }
}

async fn wait_with_backoff_delay(
    backoff: &mut ExponentialBackoff,
    retries: &mut usize,
    action: &str,
    error: Error,
) -> Result<(), Error> {
    warn!(
        "Failed to {action} due to {error}, will wait for {:?} and retry",
        backoff.get_backoff()
    );
    tokio::time::sleep(backoff.get_backoff()).await;
    if *retries > MAX_RETRIES {
        return Err(Error::ExpBackoffTimeout(action.to_string()));
    }
    backoff.next_backoff();
    *retries += 1;

    Ok(())
}

async fn fetch_identifier_from_api(
    auth_token: &str,
    public_key: PublicKey,
) -> Result<MachineIdentifier, Error> {
    debug!("Fetching machine identifier");
    let client = Client::new();
    let response = client
        .get(format!("{}/meshnet/machines", API_BASE))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", auth_token),
        )
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

async fn update_machine(device_identity: &DeviceIdentity, auth_token: &str) -> Result<(), Error> {
    debug!("Updating machine");
    let client = Client::new();
    let status = client
        .patch(format!(
            "{}/meshnet/machines/{}",
            API_BASE, device_identity.machine_identifier
        ))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", auth_token),
        )
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
    auth_token: Arc<Hidden<String>>,
) -> Result<MeshMap, Error> {
    debug!("Getting meshmap");
    let client = Client::new();
    Ok(serde_json::from_str(
        &client
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
            .await?,
    )?)
}

async fn register_machine(
    hw_identifier: &str,
    public_key: PublicKey,
    auth_token: &str,
) -> Result<MachineIdentifier, Error> {
    info!("Registering machine");
    let client = Client::new();
    let response = client
        .post(format!("{}/meshnet/machines", API_BASE))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", auth_token),
        )
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
