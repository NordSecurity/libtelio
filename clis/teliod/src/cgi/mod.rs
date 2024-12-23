use std::{env::var, ops::Deref};

use rust_cgi::{http::StatusCode, text_response, Request, Response};

mod api;
pub(crate) mod constants;

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

pub fn handle_request(request: Request) -> Response {
    let request = CgiRequest::new(request);

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
