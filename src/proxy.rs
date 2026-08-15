use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{
        self, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri,
        header::{
            CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
            TRANSFER_ENCODING, UPGRADE, WWW_AUTHENTICATE,
        },
    },
    response::{IntoResponse, Response},
};
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use serde_json::json;
use uuid::Uuid;

use crate::{
    auth::{AuthError, authenticate},
    logging::LogSender,
};

pub type HttpClient = Client<HttpConnector, Body>;

pub struct AppState {
    client: HttpClient,
    upstream: Uri,
    logger: LogSender,
}

impl AppState {
    pub fn new(client: HttpClient, upstream: Uri, logger: LogSender) -> Self {
        Self {
            client,
            upstream,
            logger,
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new().fallback(proxy).with_state(state)
}

async fn proxy(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let request_id = Uuid::new_v4();
    let (mut parts, body) = request.into_parts();
    if !state.logger.is_healthy() {
        return json_error_response(
            &state.logger,
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "logger_unavailable",
            "The audit log writer is unavailable; the proxy is failing closed.",
        );
    }
    let authentication = authenticate(&parts.headers);
    let authorized = authentication.result.is_ok();
    state.logger.request_started(
        request_id,
        peer,
        authentication.presented_key,
        authorized,
        &parts,
    );

    if let Err(error) = authentication.result {
        state.logger.drain_request(request_id, body);
        return authentication_error(&state.logger, request_id, error);
    }

    parts.uri = match upstream_uri(&state.upstream, &parts.uri) {
        Ok(uri) => uri,
        Err(error) => {
            state.logger.drain_request(request_id, body);
            return json_error_response(
                &state.logger,
                request_id,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "invalid_proxy_uri",
                &format!("Could not construct upstream URI: {error}"),
            );
        }
    };

    parts.version = http::Version::HTTP_11;
    remove_hop_by_hop_headers(&mut parts.headers);
    set_upstream_host(&parts.uri, &mut parts.headers);
    let body = state.logger.request_body(request_id, body);
    let upstream_request = Request::from_parts(parts, body);

    let upstream_response = match state.client.request(upstream_request).await {
        Ok(response) => response,
        Err(error) => {
            return json_error_response(
                &state.logger,
                request_id,
                StatusCode::BAD_GATEWAY,
                "api_error",
                "upstream_connection_error",
                &format!("Could not reach the upstream API: {error}"),
            );
        }
    };

    relay_response(&state.logger, request_id, upstream_response)
}

fn authentication_error(logger: &LogSender, request_id: Uuid, error: AuthError) -> Response {
    let mut response = json_error_body(
        StatusCode::UNAUTHORIZED,
        "invalid_request_error",
        "invalid_api_key",
        error.message(),
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    finish_local_response(logger, request_id, response)
}

fn json_error_response(
    logger: &LogSender,
    request_id: Uuid,
    status: StatusCode,
    error_type: &'static str,
    code: &'static str,
    message: &str,
) -> Response {
    let response = json_error_body(status, error_type, code, message);
    finish_local_response(logger, request_id, response)
}

fn json_error_body(
    status: StatusCode,
    error_type: &'static str,
    code: &'static str,
    message: &str,
) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "message": message,
                "type": error_type,
                "param": null,
                "code": code
            }
        })),
    )
        .into_response()
}

fn finish_local_response(logger: &LogSender, request_id: Uuid, mut response: Response) -> Response {
    insert_request_id(&mut response, request_id);
    log_response(logger, request_id, response)
}

fn relay_response(
    logger: &LogSender,
    request_id: Uuid,
    response: http::Response<Incoming>,
) -> Response {
    let (mut parts, body) = response.into_parts();
    parts.version = http::Version::HTTP_11;
    remove_hop_by_hop_headers(&mut parts.headers);
    let mut response = Response::from_parts(parts, Body::new(body));
    insert_request_id(&mut response, request_id);
    log_response(logger, request_id, response)
}

fn log_response(logger: &LogSender, request_id: Uuid, response: Response) -> Response {
    let (parts, body) = response.into_parts();
    logger.response_started(request_id, &parts);
    let body = logger.response_body(request_id, body);
    Response::from_parts(parts, body)
}

fn insert_request_id(response: &mut Response, request_id: Uuid) {
    let value = HeaderValue::from_str(&request_id.to_string())
        .expect("a UUID is always a valid HTTP header value");
    response
        .headers_mut()
        .insert(HeaderName::from_static("x-proxy-request-id"), value);
}

pub(crate) fn upstream_uri(upstream: &Uri, incoming: &Uri) -> Result<Uri, http::Error> {
    let base_path = upstream.path().trim_end_matches('/');
    let incoming_path = incoming.path();
    let path = if base_path.is_empty() {
        incoming_path.to_owned()
    } else if incoming_path == "/" {
        format!("{base_path}/")
    } else {
        format!("{base_path}{incoming_path}")
    };
    let path_and_query = match incoming.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };

    Uri::builder()
        .scheme(
            upstream
                .scheme()
                .expect("validated upstream scheme")
                .clone(),
        )
        .authority(
            upstream
                .authority()
                .expect("validated upstream authority")
                .clone(),
        )
        .path_and_query(path_and_query)
        .build()
}

fn set_upstream_host(upstream: &Uri, headers: &mut HeaderMap) {
    let authority = upstream
        .authority()
        .expect("validated upstream authority")
        .as_str();
    let host = HeaderValue::from_str(authority).expect("URI authority is a valid Host value");
    headers.insert(HOST, host);
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    // RFC 9110 allows Connection to name additional hop-by-hop fields.
    let mut connection_headers = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for name in value.as_bytes().split(|byte| *byte == b',') {
            let Some(first) = name.iter().position(|byte| !byte.is_ascii_whitespace()) else {
                continue;
            };
            let last = name
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace())
                .expect("a nonempty trimmed header name");
            if let Ok(name) = HeaderName::from_bytes(&name[first..=last]) {
                connection_headers.push(name);
            }
        }
    }
    for name in connection_headers {
        headers.remove(name);
    }

    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_origin_and_keeps_path_and_query() {
        let upstream: Uri = "http://127.0.0.1:1234".parse().unwrap();
        let incoming: Uri = "/v1/responses?stream=true".parse().unwrap();

        assert_eq!(
            upstream_uri(&upstream, &incoming).unwrap(),
            "http://127.0.0.1:1234/v1/responses?stream=true"
        );
    }

    #[test]
    fn prepends_an_upstream_path_prefix() {
        let upstream: Uri = "http://127.0.0.1:1234/internal/".parse().unwrap();
        let incoming: Uri = "/v1/models".parse().unwrap();

        assert_eq!(
            upstream_uri(&upstream, &incoming).unwrap(),
            "http://127.0.0.1:1234/internal/v1/models"
        );
    }

    #[test]
    fn removes_standard_and_connection_named_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-remove"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-remove", HeaderValue::from_static("yes"));
        headers.insert("x-keep", HeaderValue::from_static("yes"));

        remove_hop_by_hop_headers(&mut headers);

        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-remove"));
        assert!(headers.contains_key("x-keep"));
    }

    #[test]
    fn still_removes_valid_connection_tokens_next_to_non_utf8_bytes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_bytes(b"\xff, x-remove").unwrap(),
        );
        headers.insert("x-remove", HeaderValue::from_static("yes"));

        remove_hop_by_hop_headers(&mut headers);

        assert!(!headers.contains_key("x-remove"));
    }
}
