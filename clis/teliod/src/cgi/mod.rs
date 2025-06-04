use std::ops::Deref;

use rust_cgi::{http::StatusCode, text_response, Request, Response};

use crate::TIMEOUT_SEC;
use telio::telio_utils::Hidden;
use tracing::trace;

mod api;
mod app;
mod web;

pub(crate) mod constants;
#[cfg(feature = "qnap")]
mod qnap;

#[allow(dead_code)]
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
}

pub struct CgiRequest {
    inner: Request,
    route: String,
}

impl CgiRequest {
    fn new(inner: Request, route: &str) -> Self {
        Self {
            inner,
            route: route.to_string(),
        }
    }

    pub fn route(&self) -> &str {
        &self.route
    }
}

impl Deref for CgiRequest {
    type Target = Request;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum TokenCheckStatus {
    Success,
    Failed,
}

#[allow(dead_code)]
#[derive(Debug)]
enum AdminGroupStatus {
    Admin,
    NonAdmin,
}

pub trait AuthorizationValidator {
    fn retrieve_token(request: &Request) -> Result<Hidden<String>, Error>;
    async fn is_token_valid(token: &str) -> Result<Self, Error>
    where
        Self: Sized;
    fn validate(&self) -> Result<(), Error>;
}

// ByPassValidator: always authorizes (for non-qnap builds)
pub struct ByPassValidator;

impl AuthorizationValidator for ByPassValidator {
    fn retrieve_token(_request: &Request) -> Result<Hidden<String>, Error> {
        Ok(Hidden(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ))
    }
    async fn is_token_valid(_sid: &str) -> Result<Self, Error> {
        Ok(ByPassValidator)
    }
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

// CGI entrypoint
pub fn handle_request_env(request: Request) -> Response {
    static PATH_INFO_KEY: &str = "PATH_INFO";
    let path = std::env::var(PATH_INFO_KEY).unwrap_or_default();
    #[cfg(feature = "qnap")]
    {
        handle_request::<qnap::QnapUserAuthorization>(request, &path)
    }
    #[cfg(not(feature = "qnap"))]
    {
        handle_request::<ByPassValidator>(request, &path)
    }
}

pub fn handle_request<T: AuthorizationValidator + Send + 'static>(
    request: Request,
    path: &str,
) -> Response {
    let request = CgiRequest::new(request, path);

    let auth_result = authorize::<T>(&request);
    if let Err(error) = auth_result {
        return text_response(StatusCode::UNAUTHORIZED, format!("Unauthorized: {}", error));
    }
    if let Some(response) = web::handle_web_ui(&request) {
        trace!(
            "Returning response..: {:?}",
            std::str::from_utf8(response.body()).ok()
        );

        // Enabling tracing during tests obviously breaks it since the debug information messes up the output
        #[cfg(all(debug_assertions, not(test)))]
        let response = trace_request(&request, &response).unwrap_or(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Tracing request failed.",
        ));

        return response;
    }
    if let Some(response) = api::handle_api(&request) {
        // Enabling tracing during tests obviously breaks it since the debug information messes up the output
        #[cfg(all(debug_assertions, not(test)))]
        let response = trace_request(&request, &response).unwrap_or(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Tracing request failed.",
        ));

        return response;
    }
    text_response(StatusCode::BAD_REQUEST, "Invalid request.")
}
pub fn authorize<T: AuthorizationValidator>(request: &Request) -> Result<(), Error> {
    T::retrieve_token(request).and_then(|sid| {
        let user_authorization =
            match tokio::runtime::Handle::current().block_on(tokio::time::timeout(
                std::time::Duration::from_secs(TIMEOUT_SEC),
                T::is_token_valid(&sid),
            )) {
                Ok(Ok(resp)) => resp,
                Ok(Err(error)) => return Err(error),
                _ => return Err(Error::AuthValidationTimeOut),
            };
        user_authorization.validate()
    })
}

#[cfg(debug_assertions)]
pub fn trace_request(request: &CgiRequest, response: &Response) -> Option<Response> {
    use std::{env::vars, fmt::Write};
    let mut msg = String::new();
    let _ = writeln!(
        &mut msg,
        "ENVIRONMENT:\n{:#?}\n",
        vars().collect::<Vec<_>>(),
    );
    let _ = writeln!(
        &mut msg,
        "REQUEST:\nmethod: {:?}\nuri: {:?}\npath: {:?}\nroute: {:?}\nquery: {:?}\n",
        request.method(),
        request.uri(),
        request.uri().path(),
        request.route(),
        request.uri().query(),
    );
    let _ = writeln!(
        &mut msg,
        "RESPONSE:\nstatus_code: {:?}\nbody: {:?}\n",
        response.status(),
        std::str::from_utf8(response.body()).unwrap_or("[Error] Response with invalid UTF-8."),
    );
    Some(text_response(StatusCode::OK, msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_cgi::http::Method;
    use rust_cgi::Request;

    #[tokio::test]
    async fn test_handle_request_invalid_route() {
        tokio::task::spawn_blocking(|| {
            let resp = handle_request::<ByPassValidator>(
                Request::default(),
                "/this/path/is/really/not/handled",
            );
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_handle_request_web_ui_root() {
        tokio::task::spawn_blocking(|| {
            let resp = handle_request::<ByPassValidator>(Request::default(), "/");
            assert!(resp.status() == StatusCode::OK);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_handle_request_api() {
        tokio::task::spawn_blocking(|| {
            let resp = handle_request::<ByPassValidator>(Request::default(), "/meshnet");
            assert!(resp.status() == StatusCode::OK);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_handle_request_unauthorized() {
        struct DenyValidator;
        impl AuthorizationValidator for DenyValidator {
            fn retrieve_token(_request: &Request) -> Result<Hidden<String>, Error> {
                Ok(Hidden("deny".to_string()))
            }
            async fn is_token_valid(_sid: &str) -> Result<Self, Error> {
                Ok(DenyValidator)
            }
            fn validate(&self) -> Result<(), Error> {
                Err(Error::UserNotAuthenticated)
            }
        }

        tokio::task::spawn_blocking(|| {
            let resp = handle_request::<DenyValidator>(Request::default(), "/meshnet");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        })
        .await
        .unwrap();
    }
}
