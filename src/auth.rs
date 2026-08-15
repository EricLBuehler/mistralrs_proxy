use std::{fs, io, path::Path};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

/// An immutable set of API keys loaded once during process startup.
pub struct ApiKeyAllowlist {
    digests: Box<[[u8; 32]]>,
}

impl ApiKeyAllowlist {
    /// Load one API key per line. Empty lines and lines beginning with `#` are
    /// ignored. The returned allowlist does not retain or reread the path.
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not read API key file {}: {error}", path.display()),
            )
        })?;

        let mut keys = Vec::new();
        for (index, key) in contents.lines().enumerate() {
            if key.is_empty() || key.starts_with('#') {
                continue;
            }
            if key != key.trim() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "API key file {} has leading or trailing whitespace on line {}",
                        path.display(),
                        index + 1
                    ),
                ));
            }
            if !key.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "API key file {} has whitespace or a non-ASCII character on line {}",
                        path.display(),
                        index + 1
                    ),
                ));
            }
            keys.push(key.to_owned());
        }

        Self::from_keys(keys).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("invalid API key file {}: {error}", path.display()),
            )
        })
    }

    /// Construct an allowlist from already-loaded keys.
    ///
    /// This is useful for embedding the proxy as a library and for tests. The
    /// standalone binary always uses [`Self::from_file`].
    pub fn from_keys<I, S>(keys: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let keys: Vec<String> = keys.into_iter().map(Into::into).collect();
        if keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the API key allowlist is empty",
            ));
        }
        if keys
            .iter()
            .any(|key| key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_graphic()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "API keys must be nonempty printable ASCII without whitespace",
            ));
        }

        let mut digests = Vec::with_capacity(keys.len());
        for key in keys {
            let digest: [u8; 32] = Sha256::digest(key.as_bytes()).into();
            if digests.contains(&digest) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the API key allowlist contains a duplicate key",
                ));
            }
            digests.push(digest);
        }

        Ok(Self {
            digests: digests.into_boxed_slice(),
        })
    }

    fn contains(&self, presented: &str) -> bool {
        let presented: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        let mut allowed = Choice::from(0);
        for candidate in &self.digests {
            allowed |= candidate.ct_eq(&presented);
        }
        bool::from(allowed)
    }
}

#[derive(Debug)]
pub struct Authentication {
    pub presented_key: Option<String>,
    pub result: Result<(), AuthError>,
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

pub fn authenticate(headers: &HeaderMap, allowlist: &ApiKeyAllowlist) -> Authentication {
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
    Authentication {
        presented_key,
        result: allowlist
            .contains(key)
            .then_some(())
            .ok_or(AuthError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use axum::http::{HeaderValue, header::AUTHORIZATION};

    use super::*;

    fn allowlist() -> ApiKeyAllowlist {
        ApiKeyAllowlist::from_keys(["foobar"]).unwrap()
    }

    fn headers(value: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn accepts_openai_style_bearer_auth() {
        let auth = authenticate(&headers(Some("Bearer foobar")), &allowlist());

        assert_eq!(auth.result, Ok(()));
        assert_eq!(auth.presented_key.as_deref(), Some("foobar"));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        assert!(
            authenticate(&headers(Some("bEaReR foobar")), &allowlist())
                .result
                .is_ok()
        );
    }

    #[test]
    fn rejects_missing_malformed_and_unknown_keys() {
        let allowlist = allowlist();
        assert_eq!(
            authenticate(&headers(None), &allowlist).result,
            Err(AuthError::Missing)
        );
        assert_eq!(
            authenticate(&headers(Some("foobar")), &allowlist).result,
            Err(AuthError::Malformed)
        );
        assert_eq!(
            authenticate(&headers(Some("Bearer wrong")), &allowlist).result,
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn loads_keys_once_from_a_line_oriented_file() {
        let path =
            std::env::temp_dir().join(format!("proxy-api-keys-{}.txt", uuid::Uuid::new_v4()));
        fs::write(&path, "# local keys\nfirst-key\n\nsecond-key\n").unwrap();

        let allowlist = ApiKeyAllowlist::from_file(&path).unwrap();
        fs::write(&path, "replacement-key\n").unwrap();
        fs::remove_file(&path).unwrap();

        assert!(allowlist.contains("first-key"));
        assert!(allowlist.contains("second-key"));
        assert!(!allowlist.contains("replacement-key"));
    }

    #[test]
    fn rejects_empty_and_malformed_key_files() {
        let empty =
            std::env::temp_dir().join(format!("proxy-api-keys-{}.txt", uuid::Uuid::new_v4()));
        fs::write(&empty, "# comments only\n\n").unwrap();
        assert!(ApiKeyAllowlist::from_file(&empty).is_err());
        fs::remove_file(&empty).unwrap();

        let malformed =
            std::env::temp_dir().join(format!("proxy-api-keys-{}.txt", uuid::Uuid::new_v4()));
        fs::write(&malformed, "valid-key\nnot a key\n").unwrap();
        assert!(ApiKeyAllowlist::from_file(&malformed).is_err());
        fs::remove_file(&malformed).unwrap();

        let duplicate =
            std::env::temp_dir().join(format!("proxy-api-keys-{}.txt", uuid::Uuid::new_v4()));
        fs::write(&duplicate, "same-key\nsame-key\n").unwrap();
        assert!(ApiKeyAllowlist::from_file(&duplicate).is_err());
        fs::remove_file(&duplicate).unwrap();
    }
}
