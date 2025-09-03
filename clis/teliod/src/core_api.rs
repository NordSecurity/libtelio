use base64::DecodeError;
use reqwest::{Certificate, Client, StatusCode};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use thiserror::Error;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use telio::crypto::SecretKey;
use telio::telio_utils::exponential_backoff::{
    Backoff, Error as BackoffError, ExponentialBackoff, ExponentialBackoffBounds,
};

use crate::config::NordToken;

const API_BASE: &str = "https://api.nordvpn.com/v1";

const MAX_RETRIES: usize = 10;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),
    #[error("Unable to fetch Nordlynx private key: {0}")]
    RequestingNordlynxPrivateKey(StatusCode),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("Invalid response recieved from server")]
    InvalidResponse,
    #[error("Max retries exceeded for connection")]
    ExpBackoffTimeout(),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BackoffBounds(#[from] BackoffError),
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
            Error::RequestingNordlynxPrivateKey(status_code) => {
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

/// Request the Nordlynx private key to the API using an exp. backoff on failure.
pub(crate) async fn request_nordlynx_key(
    auth_token: &NordToken,
    cert_path: &Option<PathBuf>,
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
    cert_path: &Option<PathBuf>,
) -> Result<SecretKey, Error> {
    let client = http_client(cert_path);
    let response = client
        .get(format!("{API_BASE}/users/services/credentials"))
        .basic_auth("token", Some(auth_token))
        .send()
        .await?;

    let status = response.status();
    let resp = response.text().await?;
    debug!("Got response: {resp}");
    if status.is_success() {
        serde_json::from_str::<Value>(&resp)?
            .get("nordlynx_private_key")
            .and_then(|v| v.as_str())
            .ok_or(Error::InvalidResponse)?
            .parse::<SecretKey>()
            .map_err(|_| Error::InvalidResponse)
    } else {
        debug!(
            "Unable to request nordlynx private key, API returned: [{}] {:?}",
            status, resp
        );
        Err(Error::RequestingNordlynxPrivateKey(status))
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
