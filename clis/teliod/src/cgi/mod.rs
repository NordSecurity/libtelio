pub mod constants;

mod api;
mod pid;

use std::{env::var, ops::Deref};

use rust_cgi::{http::StatusCode, text_response, Request, Response};

pub use self::pid::PidFile;

const CHAIN: &[fn(&CgiRequest) -> Option<Response>] = &[
    api::handle_api,
    #[cfg(debug_assertions)]
    trace_request,
];

pub fn handle_request(request: Request) -> Response {
    let request = CgiRequest::new(request);

    for handler in CHAIN.iter() {
        if let Some(response) = handler(&request) {
            return response;
        }
    }

    text_response(StatusCode::BAD_REQUEST, "Invalid request.")
}

#[cfg(debug_assertions)]
fn trace_request(request: &CgiRequest) -> Option<Response> {
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

    Some(text_response(StatusCode::OK, msg))
}

/// Request with aditional information
pub struct CgiRequest {
    pub inner: Request,
    route: String,
}

impl CgiRequest {
    fn new(inner: Request) -> Self {
        Self {
            inner,
            route: var("PATH_INFO").unwrap_or_default(),
        }
    }

    /// The path after the cgi script path
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
