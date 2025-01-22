use std::{env::var, fs, ops::Deref};

use rust_cgi::{http::StatusCode, text_response, Request, Response};
use serde::Deserialize;

use crate::TIMEOUT_SEC;
use tracing::{info, Level};

#[cfg(feature = "qnap")]
use qnap::QnapUserAuthorization;

mod api;
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
    fn new(inner: Request) -> Self {
        Self {
            inner,
            route: var("PATH_INFO").unwrap_or_default(),
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
    // Retrieve sid token from the cookie of an http request.
    fn retrieve_token(request: &Request) -> Result<String, Error>;
    // Check user's sid against a provided validator.
    async fn is_token_valid(sid: String) -> Result<impl AuthorizationValidator, Error>;
    // Validate user authorization
    fn validate(&self) -> Result<(), Error>;
}

pub fn handle_request(request: Request) -> Response {
    #[cfg(debug_assertions)]
    match fs::File::create("./cgi.log") {
        Ok(file) => {
            let (non_blocking_writer, _tracing_worker_guard) = tracing_appender::non_blocking(file);
            tracing_subscriber::fmt()
                .with_max_level(Level::TRACE)
                .with_writer(non_blocking_writer)
                .with_ansi(false)
                .with_line_number(true)
                .with_level(true)
                .init();
        }
        Err(error) => eprintln!("Failed to create debug log file: {error}"),
    };

    let request = CgiRequest::new(request);

    #[cfg(feature = "qnap")]
    if let Err(error) = authorize::<QnapUserAuthorization>(&request) {
        return text_response(StatusCode::UNAUTHORIZED, format!("Unauthorized: {}", error));
    }

    if let Some(response) = api::handle_api(&request) {
        #[cfg(debug_assertions)]
        let response = trace_request(&request, &response).unwrap_or(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Tracing request failed.",
        ));
        return response;
    }

    text_response(StatusCode::BAD_REQUEST, "Invalid request.")
}

#[allow(dead_code)]
pub fn authorize<T: AuthorizationValidator>(request: &Request) -> Result<(), Error> {
    T::retrieve_token(request).and_then(|sid| {
        let user_authorization =
            match tokio::runtime::Handle::current().block_on(tokio::time::timeout(
                std::time::Duration::from_secs(TIMEOUT_SEC),
                T::is_token_valid(sid),
            )) {
                Ok(Ok(resp)) => resp,
                Ok(Err(error)) => return Err(error),
                _ => return Err(Error::AuthValidationTimeOut),
            };
        user_authorization.validate()
    })
}

#[cfg(debug_assertions)]
fn trace_request(request: &CgiRequest, response: &Response) -> Option<Response> {
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
