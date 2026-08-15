use axum::http::{HeaderMap, header::AUTHORIZATION};
use subtle::ConstantTimeEq;

/// Keys accepted by the proxy. Changing this list requires rebuilding the binary.
///
/// These values are deliberately plain strings because that is the requested
/// deployment model. Be aware that strings embedded in a binary are extractable.
pub const ALLOWED_API_KEYS: &[&str] = &["foobar"];

#[derive(Debug)]
pub struct Authentication {
    pub presented_key: Option<String>,
    pub result: Result<&'static str, AuthError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    Missing,
    Malformed,
    Invalid,
}

impl AuthError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Missing => "Missing Authorization header. Expected 'Bearer <API key>'.",
            Self::Malformed => "Malformed Authorization header. Expected 'Bearer <API key>'.",
            Self::Invalid => "Incorrect API key provided.",
        }
    }
}

pub fn authenticate(headers: &HeaderMap) -> Authentication {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Authentication {
            presented_key: None,
            result: Err(AuthError::Missing),
        };
    };

    // Multiple Authorization headers are ambiguous and can be interpreted
    // differently by downstream HTTP implementations, so reject them.
    if values.next().is_some() {
        return Authentication {
            presented_key: None,
            result: Err(AuthError::Malformed),
        };
    }

    let Ok(value) = value.to_str() else {
        return Authentication {
            presented_key: None,
            result: Err(AuthError::Malformed),
        };
    };
    let mut fields = value.split_ascii_whitespace();
    let (Some(scheme), Some(key), None) = (fields.next(), fields.next(), fields.next()) else {
        return Authentication {
            presented_key: None,
            result: Err(AuthError::Malformed),
        };
    };
    if !scheme.eq_ignore_ascii_case("bearer") || key.is_empty() {
        return Authentication {
            presented_key: Some(key.to_owned()),
            result: Err(AuthError::Malformed),
        };
    }

    let presented_key = Some(key.to_owned());
    let allowed = ALLOWED_API_KEYS.iter().copied().find(|candidate| {
        candidate.len() == key.len() && bool::from(candidate.as_bytes().ct_eq(key.as_bytes()))
    });

    Authentication {
        presented_key,
        result: allowed.ok_or(AuthError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderValue, header::AUTHORIZATION};

    use super::*;

    fn headers(value: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn accepts_openai_style_bearer_auth() {
        let auth = authenticate(&headers(Some("Bearer foobar")));

        assert_eq!(auth.result.unwrap(), "foobar");
        assert_eq!(auth.presented_key.as_deref(), Some("foobar"));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        assert!(authenticate(&headers(Some("bEaReR foobar"))).result.is_ok());
    }

    #[test]
    fn rejects_missing_malformed_and_unknown_keys() {
        assert_eq!(authenticate(&headers(None)).result, Err(AuthError::Missing));
        assert_eq!(
            authenticate(&headers(Some("foobar"))).result,
            Err(AuthError::Malformed)
        );
        assert_eq!(
            authenticate(&headers(Some("Bearer wrong"))).result,
            Err(AuthError::Invalid)
        );
    }
}
