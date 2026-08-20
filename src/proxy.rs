use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{
        self, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri,
        header::{
            ACCEPT_ENCODING, CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
            TRAILER, TRANSFER_ENCODING, UPGRADE, WWW_AUTHENTICATE,
        },
        request,
    },
    response::{IntoResponse, Response},
};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use serde_json::json;
use uuid::Uuid;

use crate::{
    auth::{AuthError, KeyStore, authenticate},
    logging::{LogSender, RequestInfo},
};

pub type HttpClient = Client<HttpConnector, Body>;

const IDENTITY: HeaderValue = HeaderValue::from_static("identity");

pub struct AppState {
    client: HttpClient,
    upstream: Uri,
    logger: LogSender,
    keys: KeyStore,
}

impl AppState {
    pub fn new(client: HttpClient, upstream: Uri, logger: LogSender, keys: KeyStore) -> Self {
        Self {
            client,
            upstream,
            logger,
            keys,
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new().fallback(proxy).with_state(state)
}

/// Authenticate, forward, and log. Every response leaves through
/// [`finish`], which is the only place a response body gets wrapped.
async fn proxy(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if !state.logger.is_healthy() {
        // Nothing can be logged, so answer without attempting to.
        return json_error_body(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "logger_unavailable",
            "The audit log writer is unavailable; the proxy is failing closed.",
        );
    }

    let request_id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let authentication = authenticate(&parts.headers, &state.keys);
    // Held for the rest of the handler: if the client disconnects while we wait
    // on the upstream, this closes the record out instead of leaking it.
    let mut guard = state
        .logger
        .request_started(request_id, RequestInfo::new(peer, &parts, &authentication));

    let response = match authentication.result {
        Ok(()) => forward(&state, parts, body).await,
        Err(error) => authentication_error(error),
    };

    guard.disarm();
    finish(&state.logger, request_id, response)
}

async fn forward(state: &AppState, mut parts: request::Parts, body: Body) -> Response {
    parts.uri = match upstream_uri(&state.upstream, &parts.uri) {
        Ok(uri) => uri,
        Err(error) => {
            return json_error_body(
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
    // Token accounting reads the `usage` object out of the response as it
    // streams past, which only works on an uncompressed body.
    parts.headers.insert(ACCEPT_ENCODING, IDENTITY);

    let upstream_response = match state.client.request(Request::from_parts(parts, body)).await {
        Ok(response) => response,
        Err(error) => {
            return json_error_body(
                StatusCode::BAD_GATEWAY,
                "api_error",
                "upstream_connection_error",
                &format!("Could not reach the upstream API: {error}"),
            );
        }
    };

    let (mut parts, body) = upstream_response.into_parts();
    parts.version = http::Version::HTTP_11;
    remove_hop_by_hop_headers(&mut parts.headers);

    Response::from_parts(parts, Body::new(body))
}

fn authentication_error(error: AuthError) -> Response {
    let status = if error == AuthError::Disabled {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNAUTHORIZED
    };
    let mut response = json_error_body(
        status,
        "invalid_request_error",
        error.code(),
        error.message(),
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));

    response
}

fn json_error_body(
    status: StatusCode,
    error_type: &'static str,
    code: &str,
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

/// Stamp the request id and hand the body to the logger for byte counting and
/// token sniffing.
fn finish(logger: &LogSender, request_id: Uuid, mut response: Response) -> Response {
    insert_request_id(&mut response, request_id);
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
