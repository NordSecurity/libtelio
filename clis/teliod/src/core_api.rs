use crate::ClientConfig;
use base64::{prelude::*, DecodeError};
use reqwest::{header, Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use telio::crypto::PublicKey;
use thiserror::Error;
use tracing::{debug, info};

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
    ReqwestError(#[from] reqwest::Error),
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

#[derive(Default, Serialize, Deserialize)]
struct MeshConfig {
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
    debug!("Fetching machine identifier");
    let client = Client::new();
    let response = client
        .get(&format!("{}/meshnet/machines", API_BASE))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", auth_token),
        )
        .header(header::ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status().clone();
    let json_data: Value = serde_json::from_str(&response.text().await?)?;

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
    debug!("Updating machine");
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
        .json(&MeshConfig {
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

pub async fn get_meshmap(client_config: Arc<ClientConfig>) -> Result<String, Error> {
    debug!("Getting meshmap");
    let client = Client::new();
    Ok({
        client
            .get(&format!(
                "{}/meshnet/machines/{}/map",
                API_BASE, client_config.machine_identifier
            ))
            .header(
                header::AUTHORIZATION,
                format!("Bearer token:{}", client_config.auth_token),
            )
            .header(header::ACCEPT, "application/json")
            .send()
            .await?
            .text()
            .await?
    })
}

pub async fn register_machine(
    hw_identifier: &String,
    public_key: PublicKey,
    auth_token: &String,
) -> Result<String, Error> {
    info!("Registering machine");
    let client = Client::new();
    let response = client
        .post(&format!("{}/meshnet/machines", API_BASE))
        .header(
            header::AUTHORIZATION,
            format!("Bearer token:{}", auth_token),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&MeshConfig {
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
    if response.status() == StatusCode::CREATED {
        let response: Value = serde_json::from_str(&response.text().await?)?;
        if let Some(machine_identifier) = response.get("identifier").and_then(|i| i.as_str()) {
            info!("Machine Registered!");
            return Ok(machine_identifier.to_owned());
        } else {
            Err(Error::InvalidResponse)
        }
    } else {
        Err(Error::PeerRegisteringError(response.status()))
    }
}
