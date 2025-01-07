use rust_cgi::{http::header::COOKIE, Request};
use serde::Deserialize;

use crate::TIMEOUT_SEC;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Rewquest(#[from] reqwest::header::ToStrError),
    #[error("Missing authentication token")]
    MissingAuthToken,
    #[error("Headers missing HTTP cookie")]
    MissingHTTPCookie,
    #[error("User must be authenticated")]
    UserNotAuthenticated,
    #[error("User must have admin rights")]
    UserNotAdminGroup,
    #[error(transparent)]
    FailedAuthValidation(#[from] reqwest::Error),
    #[error("Timed out while validating auth token")]
    AuthValidationTimeOut,
    #[error("Unknown group admin value from auth check")]
    UnknownAuthGroupAdminValue,
}

#[derive(Debug)]
enum AuthCheckStatus {
    Success,
    Failed,
}

impl TryFrom<u8> for AuthCheckStatus {
    type Error = Error;

    // From the  API documents we only got the information that
    // "1" means "Success", other values are perceived as "Failed".
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AuthCheckStatus::Success),
            _ => Ok(AuthCheckStatus::Failed),
        }
    }
}

impl<'de> Deserialize<'de> for AuthCheckStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: u8 = Deserialize::deserialize(deserializer)?;
        AuthCheckStatus::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
struct AuthCheckResponse {
    status: AuthCheckStatus,
    admingroup: u8,
}

pub fn authorize(request: &Request) -> Result<(), Error> {
    retrieve_sid(request).and_then(|sid| {
        let auth_response = match tokio::runtime::Handle::current().block_on(tokio::time::timeout(
            std::time::Duration::from_secs(TIMEOUT_SEC),
            check_user_auth(sid),
        )) {
            Ok(Ok(resp)) => resp,
            Ok(Err(error)) => return Err(error),
            _ => return Err(Error::AuthValidationTimeOut),
        };
        match (auth_response.status, auth_response.admingroup) {
            (AuthCheckStatus::Success, 1) => Ok(()),
            (AuthCheckStatus::Success, 0) => Err(Error::UserNotAdminGroup),
            (AuthCheckStatus::Failed, 0 | 1) => Err(Error::UserNotAuthenticated),
            _ => Err(Error::UnknownAuthGroupAdminValue),
        }
    })
}

fn retrieve_sid(request: &Request) -> Result<String, Error> {
    request
        .headers()
        .get(COOKIE)
        .ok_or(Error::MissingHTTPCookie)?
        .to_str()?
        .split(';')
        .filter_map(|pair| {
            let mut parts = pair.trim().split('=');
            match (parts.next(), parts.next()) {
                (Some("NAS_SID"), Some(value)) => Some(value.to_string()),
                _ => None,
            }
        })
        .next()
        .ok_or(Error::MissingAuthToken)
}

async fn check_user_auth(sid: String) -> Result<AuthCheckResponse, Error> {
    let url = format!(
        "http://127.0.0.1:8080/cgi-bin/filemanager/utilRequest.cgi?func=check_sid&sid={}",
        sid
    );
    Ok(reqwest::get(&url)
        .await?
        .json::<AuthCheckResponse>()
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rust_cgi::http::{header::COOKIE, Request};

    #[test]
    fn test_sid_retrieval_with_cookie() {
        let expected_sid = "nastestsid0%&)+";
        let request = Request::builder()
            .uri("http://example.com/")
            .header("User-Agent", "test-agent/1.0")
            .header(
                COOKIE,
                format!(
                    "DESKTOP=1; NAS_USER=admin; home=1; NAS_SID={}; remeber=1;",
                    expected_sid
                ),
            )
            .body(vec![])
            .unwrap();

        let parsed_sid = retrieve_sid(&request).unwrap();

        assert!(parsed_sid.eq(expected_sid));
    }

    #[test]
    fn test_sid_retrieval_without_cookie() {
        let request = Request::builder()
            .uri("http://example.com/")
            .header("User-Agent", "test-agent/1.0")
            .body(vec![])
            .unwrap();

        assert!(matches!(
            retrieve_sid(&request),
            Err(Error::MissingHTTPCookie)
        ));
    }

    #[test]
    fn test_sid_retrieval_without_authentication() {
        let request = Request::builder()
            .uri("http://example.com/")
            .header("User-Agent", "test-agent/1.0")
            .header(COOKIE, "DESKTOP=1; NAS_USER=admin; home=1; remeber=1;")
            .body(vec![])
            .unwrap();

        assert!(matches!(
            retrieve_sid(&request),
            Err(Error::MissingAuthToken)
        ));
    }
}
