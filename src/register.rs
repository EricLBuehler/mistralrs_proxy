use std::sync::Arc;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, PRAGMA, REFERRER_POLICY},
    },
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::{auth::KeyCreationError, proxy::AppState};

pub const BODY_LIMIT: usize = 1_024;

const PAGE: &str = include_str!("register.html");
const AVAILABILITY_PLACEHOLDER: &str = "__REGISTRATION_AVAILABLE__";
const UNAVAILABLE_MESSAGE: &str = "Key registration unavailable.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    name: String,
}

pub async fn page(State(state): State<Arc<AppState>>) -> Response {
    let registration = state.runtime.registration();
    let available = registration.enabled && state.keys.can_register(registration.max_keys);
    let page = PAGE.replacen(
        AVAILABILITY_PLACEHOLDER,
        if available { "true" } else { "false" },
        1,
    );

    secure_response(Html(page).into_response())
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<RegistrationRequest>, JsonRejection>,
) -> Response {
    let registration = state.runtime.registration();
    if is_cross_site(&headers)
        || !registration.enabled
        || !state.keys.can_register(registration.max_keys)
    {
        return unavailable(StatusCode::SERVICE_UNAVAILABLE);
    }

    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(rejection) => return unavailable(rejection.status()),
    };

    match state
        .keys
        .create_non_admin(&payload.name, registration.max_keys)
        .await
    {
        Ok(api_key) => secure_response(
            (
                StatusCode::CREATED,
                Json(json!({
                    "api_key": api_key,
                })),
            )
                .into_response(),
        ),
        Err(KeyCreationError::InvalidName(_)) => unavailable(StatusCode::BAD_REQUEST),
        Err(KeyCreationError::DuplicateName) => unavailable(StatusCode::CONFLICT),
        Err(KeyCreationError::LimitReached | KeyCreationError::Unavailable(_)) => {
            unavailable(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

fn is_cross_site(headers: &HeaderMap) -> bool {
    headers
        .get(HeaderName::from_static("sec-fetch-site"))
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"cross-site"))
}

fn unavailable(status: StatusCode) -> Response {
    secure_response(
        (
            status,
            Json(json!({
                "error": {
                    "message": UNAVAILABLE_MESSAGE,
                    "type": "api_error",
                    "param": null,
                    "code": "registration_unavailable"
                }
            })),
        )
            .into_response(),
    )
}

fn secure_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("clipboard-write=(self)"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_page_has_exactly_one_availability_marker() {
        assert_eq!(PAGE.matches(AVAILABILITY_PLACEHOLDER).count(), 1);
    }

    #[test]
    fn embedded_page_contains_the_registration_flow() {
        for required in [
            "mistral.rs key registration",
            "Your name",
            "Create API key",
            "It won&rsquo;t be shown again.",
            "Key registration unavailable.",
        ] {
            assert!(PAGE.contains(required), "page is missing {required:?}");
        }
    }
}
