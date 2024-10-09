use crate::ClientConfig;
use base64::{prelude::*, DecodeError};
use reqwest::{blocking::Client as BlockingClient, header, Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use telio::crypto::PublicKey;
use thiserror::Error;
use tracing::info;
const API_BASE: &str = "https://api.nordvpn.com/v1";

#[cfg(windows)]
const OS_NAME: &str = "windows";
#[cfg(target_os = "macos")]
const OS_NAME: &str = "macos";
#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    DeserializeError(#[from] serde_json::Error),
    #[error("Machine Identifier not found due to Error: {0}")]
    FetchingIdentifierError(StatusCode),
    #[error("Unable to register due to Error: {0}")]
    PeerRegisteringError(StatusCode),
    #[error(transparent)]
    DecodeError(#[from] DecodeError),
    #[error("Invalid response recieved from server")]
    InvalidResponse,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MeshDev {
    public_key: PublicKey,
    hardware_identifier: String,
    os: String,
    os_version: String,
    device_type: String,
    traffic_routing_supported: bool,
}

pub async fn load_identifier_from_api(
    auth_token: &String,
    public_key: PublicKey,
) -> Result<String, Error> {
    info!("fetching machine identifier");
    let client = Client::new();
    let register = client
        .get(&format!("{}/meshnet/machines", API_BASE))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", auth_token),
        )
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;

    info!("Status {}", register.status());
    let status = register.status().clone();
    let json_data: Value = serde_json::from_str(&register.text().await?)?;

    if let Some(items) = json_data.as_array() {
        for item in items {
            // Get the public_key and identifier from each item
            if let Some(recvd_pk) = item.get("public_key").and_then(|k| k.as_str()) {
                if BASE64_STANDARD
                    .decode(recvd_pk)?
                    .as_slice()
                    .cmp(&public_key.0)
                    .is_eq()
                {
                    if let Some(machine_identifier) =
                        item.get("identifier").and_then(|i| i.as_str())
                    {
                        info!("Match found! Identifier: {}", machine_identifier);
                        return Ok(machine_identifier.to_owned());
                    }
                }
            }
        }
    }
    Err(Error::FetchingIdentifierError(status))
}

pub async fn update_machine(client_config: &ClientConfig) -> Result<StatusCode, Error> {
    info!("Updating machine");
    let client = Client::new();
    Ok(client
        .patch(&format!(
            "{}/meshnet/machines/{}",
            API_BASE,
            client_config.machine_identifier.clone()
        ))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", &client_config.auth_token),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&MeshDev {
            public_key: client_config.public_key,
            hardware_identifier: client_config.hw_identifier.clone(),
            os: OS_NAME.to_owned(),
            os_version: "unknown".to_owned(),
            device_type: "other".to_owned(),
            traffic_routing_supported: true,
        })
        .send()
        .await?
        .status())
}

pub fn get_meshmap(client_config: &ClientConfig) -> Result<String, Error> {
    info!("Getting meshmap");
    let client = BlockingClient::new();
    Ok(client
        .get(&format!(
            "{}/meshnet/machines/{}/map",
            API_BASE,
            client_config.machine_identifier.clone()
        ))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", client_config.auth_token),
        )
        .header(header::ACCEPT, "application/json")
        .send()?
        .text()?)
}

pub async fn register_machine(
    hw_identifier: &String,
    public_key: PublicKey,
    auth_token: &String,
) -> Result<String, Error> {
    info!("Registering machine");
    let client = Client::new();
    let result = client
        .post(&format!("{}/meshnet/machines", API_BASE))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", auth_token),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&MeshDev {
            public_key: public_key,
            hardware_identifier: hw_identifier.clone(),
            os: OS_NAME.to_owned(),
            os_version: "unknown".to_owned(),
            device_type: "other".to_owned(),
            traffic_routing_supported: true,
        })
        .send()
        .await?;

    // Save the machine identifier received from API
    if result.status() == StatusCode::CREATED {
        let response: Value = serde_json::from_str(&result.text().await?)?;
        if let Some(machine_identifier) = response.get("identifier").and_then(|i| i.as_str()) {
            info!("Machine Registered!");
            return Ok(machine_identifier.to_owned());
        } else {
            Err(Error::InvalidResponse)
        }
    } else {
        Err(Error::PeerRegisteringError(result.status()))
    }
}
