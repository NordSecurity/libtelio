use rust_cgi::{http::StatusCode, text_response, Request, Response};

const CHAIN: &[fn(&Request) -> Option<Response>] = &[];

pub(crate) fn handle_request(request: Request) -> Response {
    for handler in CHAIN.iter() {
        if let Some(response) = handler(&request) {
            return response;
        }
    }

    text_response(StatusCode::BAD_REQUEST, "Invalid request.")
}
