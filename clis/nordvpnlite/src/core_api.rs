use base64::DecodeError;
use rand::prelude::*;
use reqwest::{header, Certificate, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use telio::telio_model::mesh::ExitNode;
use thiserror::Error;
use tokio::time::Duration;
use tracing::{debug, error, info, trace, warn};

use telio::crypto::SecretKey;
use telio::telio_utils::exponential_backoff::{
    Backoff, Error as BackoffError, ExponentialBackoff, ExponentialBackoffBounds,
};

use crate::config::{Endpoint, NordToken, NordVpnLiteConfig, NordlynxKeyResponse, VpnConfig};
use crate::NordVpnLiteError;

const API_BASE: &str = "https://api.nordvpn.com/v1";
const WIREGUARD_ID: u64 = 35;
const MAX_RETRIES: usize = 10;
const REQUEST_TIMEOUT_SECONDS: u64 = 30;
pub const DEFAULT_WIREGUARD_PORT: u16 = 51820;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("Invalid response received from server")]
    InvalidResponse,
    #[error("Max retries exceeded for connection")]
    ExpBackoffTimeout(),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BackoffBounds(#[from] BackoffError),
    #[error("API responded with error: {0}")]
    ApiErrorResponse(ErrorDetail, StatusCode),
}

/// Error response returned by the Core API in case of bad requests
///
/// For example:
/// ```json
/// {
///  "errors": {
///    "code": 101101,
///    "message": "Invalid form data: {...}"
///  },
///  "status_code": 400
/// }
/// ```
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    errors: ErrorDetail,
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
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Server {
    station: IpAddr,
    hostname: Option<String>,
    technologies: Vec<Technology>,
}

/// VPN Server technology stack
#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Technology {
    id: u64,
    metadata: Vec<Metadata>,
}

/// VPN Server technology stack metadata
#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Metadata {
    name: String,
    value: String,
}

impl TryFrom<&Server> for Endpoint {
    type Error = Error;

    fn try_from(server: &Server) -> Result<Self, Self::Error> {
        Ok(Self {
            address: server.address(),
            public_key: server
                .wg_public_key()
                .and_then(|key| key.parse().ok())
                .ok_or(Error::InvalidResponse)?,
            hostname: server.hostname(),
        })
    }
}

impl TryFrom<&Server> for ExitNode {
    type Error = NordVpnLiteError;

    fn try_from(server: &Server) -> Result<Self, Self::Error> {
        Ok(Self {
            identifier: uuid::Uuid::new_v4().to_string(),
            public_key: server
                .wg_public_key()
                .and_then(|key| key.parse().ok())
                .ok_or(NordVpnLiteError::EndpointNoPublicKey)?,
            allowed_ips: None,
            endpoint: Some(SocketAddr::new(server.address(), DEFAULT_WIREGUARD_PORT)),
        })
    }
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

/// API error classification for retry logic: LLT-5553
macro_rules! handle_api_error {
    ($error:expr) => {
        match $error {
            // Terminal errors
            Error::Decode(_)
            | Error::InvalidResponse
            | Error::ExpBackoffTimeout()
            | Error::BackoffBounds(_) => Err($error),

            // Terminal HTTP status codes
            Error::ApiErrorResponse(_, status_code) => {
                if status_code == StatusCode::BAD_REQUEST
                    || status_code == StatusCode::UNAUTHORIZED
                    || status_code == StatusCode::FORBIDDEN
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

/// Request the Nordlynx private key from the API.
pub(crate) async fn request_nordlynx_key(
    auth_token: &NordToken,
    cert_path: Option<&Path>,
) -> Result<SecretKey, Error> {
    info!("Requesting Nordlynx secret..");
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match send_request_nordlynx_key(auth_token, cert_path).await {
            Ok(id) => return Ok(id),
            Err(e) => {
                warn!("Failed to request Nordlynx secret due to {e:?}");
                handle_api_error!(e)?;
                warn!("Will wait for {:?} and retry", backoff.get_backoff());
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
        }
    }
}

async fn send_request_nordlynx_key(
    auth_token: &NordToken,
    cert_path: Option<&Path>,
) -> Result<SecretKey, Error> {
    let client = http_client(cert_path);
    let response = client
        .get(format!("{API_BASE}/users/services/credentials"))
        .basic_auth("token", Some(auth_token as &str))
        .send()
        .await?;

    let status = response.status();
    let resp = response.text().await?;
    debug!("Got response: {resp}");
    if status.is_success() {
        Ok(serde_json::from_str::<NordlynxKeyResponse>(&resp)?
            .into_secret_key()
            .map_err(|_| Error::InvalidResponse)?)
    } else {
        debug!(
            "Unable to request nordlynx private key, API returned: [{}] {:?}",
            status, resp
        );
        if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&resp) {
            return Err(Error::ApiErrorResponse(error_response.errors, status));
        }
        Err(Error::InvalidResponse)
    }
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

fn http_client(cert_path: Option<&Path>) -> Client {
    cert_path
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

/// Get the list of countries with VPN servers from core API.
pub async fn get_countries_with_exp_backoff(
    cert_path: Option<&Path>,
) -> Result<Vec<Country>, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match get_countries(cert_path).await {
            Ok(countries) => return Ok(countries),
            Err(Error::Reqwest(ref e)) if e.is_timeout() => {
                warn!(
                    "Failed to fetch countries due to {e}, will wait for {:?} and retry",
                    backoff.get_backoff()
                );
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

/// Get the list of countries with VPN servers from core API.
async fn get_countries(cert_path: Option<&Path>) -> Result<Vec<Country>, Error> {
    debug!("Getting countries list");
    let response = http_client(cert_path)
        .get(format!("{}/servers/countries", API_BASE))
        .header(header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
        .send()
        .await?;

    let status = response.status();
    let resp = response.text().await?;
    if status == StatusCode::OK {
        Ok(serde_json::from_str(&resp)?)
    } else {
        if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&resp) {
            return Err(Error::ApiErrorResponse(error_response.errors, status));
        }
        error!("Unable to get countries list: {:?}", status);
        Err(Error::InvalidResponse)
    }
}

/// Get recommended server list from the API,
/// (optionally) Filtered by country ID and result list size limit.
/// If no country_id is found, it will still return a
/// recommended server based on other metrics.
/// (see API docs)
pub async fn get_recommended_servers_with_exp_backoff(
    country_id_filter: Option<u64>,
    limit_filter: Option<u64>,
    cert_path: Option<&Path>,
) -> Result<Vec<Server>, Error> {
    let mut backoff = build_backoff()?;
    let mut retries = 0;

    loop {
        match get_recommended_servers(country_id_filter, limit_filter, cert_path).await {
            Ok(servers) => return Ok(servers),
            Err(Error::Reqwest(ref e)) if e.is_timeout() => {
                warn!(
                    "Failed to fetch recommended servers due to {e}, will wait for {:?} and retry",
                    backoff.get_backoff()
                );
                wait_with_backoff_delay(&mut backoff, &mut retries).await?;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

/// Get recommended server list from core API.
async fn get_recommended_servers(
    country_id_filter: Option<u64>,
    limit_filter: Option<u64>,
    cert_path: Option<&Path>,
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
    if let Some(limit) = limit_filter {
        filter.push(("limit".into(), limit.to_string()));
    };
    if let Some(country_id) = country_id_filter {
        filter.push(("filters[country_id]".into(), country_id.to_string()));
    };

    let client = http_client(cert_path);
    let response = client
        .get(format!("{}/servers/recommendations", API_BASE))
        .header(header::ACCEPT, "application/json")
        .query(&filter)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
        .send()
        .await?;

    let status = response.status();
    let resp = response.text().await?;
    if status == StatusCode::OK {
        Ok(serde_json::from_str(&resp)?)
    } else {
        if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&resp) {
            return Err(Error::ApiErrorResponse(error_response.errors, status));
        }
        error!("Unable to get server recommendations: {:?}", status);
        Err(Error::InvalidResponse)
    }
}

pub async fn get_server_endpoints_list(config: &NordVpnLiteConfig) -> Result<Vec<Endpoint>, Error> {
    let country_id: Option<u64> = match &config.vpn {
        // Use the endpoint directly if provided in the config
        VpnConfig::Server(endpoint) => return Ok(vec![endpoint.clone()]),
        // Find VPN exit node based on country
        VpnConfig::Country(target_country) => {
            if !target_country.chars().all(|c| c.is_ascii_alphabetic()) {
                warn!("Invalid country format: '{target_country}', non-ascii characters used");
                None
            } else {
                match get_countries_with_exp_backoff(config.http_certificate_file_path.as_deref())
                    .await
                {
                    Ok(countries_list) => countries_list
                        .iter()
                        .find_map(|country| {
                            // search for country full name or iso code
                            if country.matches(target_country) {
                                Some(country.id)
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            warn!("Servers not found for '{target_country}' country code.");
                            None
                        }),
                    Err(e) => {
                        error!("Getting countries failed due to: {e}");
                        None
                    }
                }
            }
        }
        VpnConfig::Recommended => None,
    };

    if country_id.is_none() {
        info!("Using a recommended server");
    };

    // Fetch the list of recommended server from the API
    let mut servers = get_recommended_servers_with_exp_backoff(
        country_id,
        None,
        config.http_certificate_file_path.as_deref(),
    )
    .await?
    .iter()
    .map(Endpoint::try_from)
    .collect::<Result<Vec<_>, _>>()?;

    servers.shuffle(&mut rand::thread_rng());

    trace!("Servers {:#?}", servers);
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use telio::telio_model::mesh::ExitNode;

    use super::*;

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

        let exit_node: ExitNode = servers
            .first()
            .and_then(|server| ExitNode::try_from(server).ok())
            .unwrap();
        assert_eq!(
            exit_node.endpoint,
            format!("127.0.0.1:{}", DEFAULT_WIREGUARD_PORT)
                .parse::<SocketAddr>()
                .ok()
        );
        assert_eq!(
            exit_node.public_key,
            "urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uro="
                .parse()
                .unwrap()
        );
    }
}
