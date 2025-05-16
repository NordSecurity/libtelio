use crate::Hidden;
use rust_cgi::{http::header::COOKIE, Request};
use serde::Deserialize;

use super::{AdminGroupStatus, AuthorizationValidator, Error, TokenCheckStatus};

impl TryFrom<u8> for TokenCheckStatus {
    type Error = Error;

    // From the  API documents we only got the information that
    // "1" means "Success", so any other values are perceived as "Failed".
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TokenCheckStatus::Success),
            _ => Ok(TokenCheckStatus::Failed),
        }
    }
}

impl<'de> Deserialize<'de> for TokenCheckStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: u8 = Deserialize::deserialize(deserializer)?;
        TokenCheckStatus::try_from(value).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<u8> for AdminGroupStatus {
    type Error = Error;

    // From the  API documents we only got the information that
    // "1" means the user belongs to "Admin" group,
    // so any other values are perceived as "NonAdmin".
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AdminGroupStatus::Admin),
            _ => Ok(AdminGroupStatus::NonAdmin),
        }
    }
}

impl<'de> Deserialize<'de> for AdminGroupStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: u8 = Deserialize::deserialize(deserializer)?;
        AdminGroupStatus::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct QnapUserAuthorization {
    status: TokenCheckStatus,
    admingroup: AdminGroupStatus,
}

impl AuthorizationValidator for QnapUserAuthorization {
    fn retrieve_token(request: &Request) -> Result<Hidden<String>, Error> {
        request
            .headers()
            .get(COOKIE)
            .ok_or(Error::MissingHTTPCookie)?
            .to_str()?
            .split(';')
            .filter_map(|pair| {
                let mut parts = pair.trim().split('=');
                match (parts.next(), parts.next()) {
                    (Some("NAS_SID"), Some(value)) => Some(Hidden(value.to_string())),
                    _ => None,
                }
            })
            .next()
            .ok_or(Error::MissingAuthToken)
    }

    async fn is_token_valid(sid: &str) -> Result<impl AuthorizationValidator, Error> {
        let url = format!(
            "http://127.0.0.1:8080/cgi-bin/filemanager/utilRequest.cgi?func=check_sid&sid={}",
            sid
        );
        Ok(reqwest::get(&url).await?.json::<Self>().await?)
    }

    fn validate(&self) -> Result<(), Error> {
        match (&self.status, &self.admingroup) {
            (TokenCheckStatus::Success, AdminGroupStatus::Admin) => Ok(()),
            (TokenCheckStatus::Success, AdminGroupStatus::NonAdmin) => {
                Err(Error::UserNotAdminGroup)
            }
            (TokenCheckStatus::Failed, _) => Err(Error::UserNotAuthenticated),
        }
    }
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

        let parsed_sid = QnapUserAuthorization::retrieve_token(&request).unwrap();

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
            QnapUserAuthorization::retrieve_token(&request),
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
            QnapUserAuthorization::retrieve_token(&request),
            Err(Error::MissingAuthToken)
        ));
    }

    #[test]
    fn test_authorization_for_valid_user() {
        let example_user_auth: QnapUserAuthorization = serde_json::from_str("{ \"status\": 1, \"sid\": \"0\", \"servername\": \"Example Server Name\", \"username\": \"admin\", \"admingroup\": 1,\
        \"version\": \"5.0.0\", \"build\": \"20151225\", \"remote_folder_is_valid_user\": 1 }").unwrap();
        assert!(matches!(example_user_auth.validate(), Ok(())));
    }

    #[test]
    fn test_authorization_for_user_with_invalid_token() {
        let example_user_auth: QnapUserAuthorization = serde_json::from_str("{ \"status\": 0, \"sid\": \"0\", \"servername\": \"Example Server Name\", \"username\": \"admin\", \"admingroup\": 1,\
        \"version\": \"5.0.0\", \"build\": \"20151225\", \"remote_folder_is_valid_user\": 1 }").unwrap();
        assert!(matches!(
            example_user_auth.validate(),
            Err(Error::UserNotAuthenticated)
        ));

        let example_user_auth: QnapUserAuthorization = serde_json::from_str("{ \"status\": 2, \"sid\": \"0\", \"servername\": \"Example Server Name\", \"username\": \"admin\", \"admingroup\": 1,\
        \"version\": \"5.0.0\", \"build\": \"20151225\", \"remote_folder_is_valid_user\": 1 }").unwrap();
        assert!(matches!(
            example_user_auth.validate(),
            Err(Error::UserNotAuthenticated)
        ));
    }

    #[test]
    fn test_authorization_for_nonadmin_user() {
        let example_user_auth: QnapUserAuthorization = serde_json::from_str("{ \"status\": 1, \"sid\": \"0\", \"servername\": \"Example Server Name\", \"username\": \"admin\", \"admingroup\": 3,\
        \"version\": \"5.0.0\", \"build\": \"20151225\", \"remote_folder_is_valid_user\": 1 }").unwrap();
        assert!(matches!(
            example_user_auth.validate(),
            Err(Error::UserNotAdminGroup)
        ));

        let example_user_auth: QnapUserAuthorization = serde_json::from_str("{ \"status\": 1, \"sid\": \"0\", \"servername\": \"Example Server Name\", \"username\": \"admin\", \"admingroup\": 0,\
        \"version\": \"5.0.0\", \"build\": \"20151225\", \"remote_folder_is_valid_user\": 1 }").unwrap();
        assert!(matches!(
            example_user_auth.validate(),
            Err(Error::UserNotAdminGroup)
        ));
    }
}
