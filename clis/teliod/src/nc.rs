use serde::{Deserialize, Serialize};
use uuid::Uuid;

const TOKENS_URL: &'static str = "https://api.nordvpn.com/v1/notifications/tokens";
const ROUTER_PLATFORM_ID: u64 = 900;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to get send http request for token: {0}")]
    TokenHttpError(#[from] reqwest::Error),
    #[error("Failed to get token: {0}")]
    TokenError(String),
    #[error("Malformed notification center json response: {0}")]
    MalformedNotificationCenterJsonResponse(#[from] serde_json::Error),
}

pub struct NotificationCenter {}

impl NotificationCenter {
    pub async fn new(authentication_token: &str, app_user_uid: Uuid) -> Result<Self, Error> {
        let nc_config = request_nc_config(authentication_token, app_user_uid).await?;

        dbg!(nc_config);
        todo!()
    }
}

async fn request_nc_config(
    authentication_token: &str,
    app_user_uid: Uuid,
) -> Result<NotificationCenterConfig, Error> {
    let client = reqwest::Client::new();

    let data = TokenHttpRequestData {
        app_user_uid: app_user_uid.to_string(),
        platform_id: ROUTER_PLATFORM_ID,
    };
    let resp = client
        .post(TOKENS_URL)
        .basic_auth("token", Some(authentication_token))
        .json(&data)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if status != 201 {
        return Err(Error::TokenError(text));
    }

    let resp: NotificationCenterConfig = serde_json::from_str(&text)?;
    Ok(resp)
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenHttpRequestData {
    app_user_uid: String,
    platform_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct NotificationCenterConfig {
    endpoint: String,
    username: String,
    password: String,
    expires_in: u64,
}
