use std::{io, path::Path, sync::Arc};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::keys::{self, KeyFile, KeyRecord};

/// Who a request belongs to, resolved from the key database at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyIdentity {
    pub name: String,
    pub identifier: String,
    pub key_sha256: String,
    pub admin: bool,
    pub disabled: bool,
}

/// An immutable set of keys loaded once during process startup.
pub struct KeyStore {
    digests: Box<[[u8; 32]]>,
    identities: Box<[Arc<KeyIdentity>]>,
}

impl KeyStore {
    /// Load the JSON key database. The store does not retain or reread the path.
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = KeyFile::load(path)?;
        Self::from_records(file.keys).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("unusable key file {}: {error}", path.display()),
            )
        })
    }

    /// Build a store from already-loaded records.
    ///
    /// Useful when embedding the proxy as a library and in tests; the binary
    /// always goes through [`Self::from_file`].
    pub fn from_records(records: Vec<KeyRecord>) -> io::Result<Self> {
        if records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the key database is empty; run `mistralrs_proxy key create <name>` first",
            ));
        }
        if !records.iter().any(|record| !record.disabled) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "every key in the database is disabled",
            ));
        }

        let mut digests = Vec::with_capacity(records.len());
        let mut identities = Vec::with_capacity(records.len());
        for record in records {
            let Some(digest) = keys::decode_digest(&record.key_sha256) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("key {} has a malformed digest", record.name),
                ));
            };
            if digests.contains(&digest) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "two keys share the same digest",
                ));
            }
            digests.push(digest);
            identities.push(Arc::new(KeyIdentity {
                name: record.name,
                identifier: record.identifier,
                key_sha256: keys::hex_encode(&digest),
                admin: record.admin,
                disabled: record.disabled,
            }));
        }

        Ok(Self {
            digests: digests.into_boxed_slice(),
            identities: identities.into_boxed_slice(),
        })
    }

    /// Number of keys in the store.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Always false: an empty database is rejected at construction.
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Look up a presented key. Returns its digest for logging plus the
    /// matching identity, comparing every entry so the work does not depend on
    /// which key was presented.
    fn lookup(&self, presented: &str) -> (String, Option<Arc<KeyIdentity>>) {
        let digest = keys::digest(presented);
        let mut matched = u64::MAX;
        for (index, candidate) in self.digests.iter().enumerate() {
            let is_match = candidate.ct_eq(&digest);
            matched = u64::conditional_select(&matched, &(index as u64), is_match);
        }
        let identity =
            (matched != u64::MAX).then(|| Arc::clone(&self.identities[matched as usize]));

        (keys::hex_encode(&digest), identity)
    }
}

/// The outcome of authenticating one request.
#[derive(Debug)]
pub struct Authentication {
    /// Hex SHA-256 of whatever key was presented, if a key was presented at
    /// all. The plaintext key is never retained.
    pub key_sha256: Option<String>,
    /// The matching database entry, when the key is known.
    pub identity: Option<Arc<KeyIdentity>>,
    pub result: Result<(), AuthError>,
}

impl Authentication {
    fn rejected(error: AuthError) -> Self {
        Self {
            key_sha256: None,
            identity: None,
            result: Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    Missing,
    Malformed,
    Invalid,
    Disabled,
}

impl AuthError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Missing => "Missing Authorization header. Expected 'Bearer <API key>'.",
            Self::Malformed => "Malformed Authorization header. Expected 'Bearer <API key>'.",
            Self::Invalid => "Incorrect API key provided.",
            Self::Disabled => "This API key has been disabled.",
        }
    }

    /// Short machine-readable reason, also used in the audit log.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing | Self::Malformed | Self::Invalid => "invalid_api_key",
            Self::Disabled => "api_key_disabled",
        }
    }
}

pub fn authenticate(headers: &HeaderMap, store: &KeyStore) -> Authentication {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Authentication::rejected(AuthError::Missing);
    };

    // Multiple Authorization headers are ambiguous and can be interpreted
    // differently by downstream HTTP implementations, so reject them.
    if values.next().is_some() {
        return Authentication::rejected(AuthError::Malformed);
    }

    let Ok(value) = value.to_str() else {
        return Authentication::rejected(AuthError::Malformed);
    };
    let mut fields = value.split_ascii_whitespace();
    let (Some(scheme), Some(key), None) = (fields.next(), fields.next(), fields.next()) else {
        return Authentication::rejected(AuthError::Malformed);
    };
    if !scheme.eq_ignore_ascii_case("bearer") || key.is_empty() {
        return Authentication::rejected(AuthError::Malformed);
    }

    let (key_sha256, identity) = store.lookup(key);
    let result = match &identity {
        Some(identity) if identity.disabled => Err(AuthError::Disabled),
        Some(_) => Ok(()),
        None => Err(AuthError::Invalid),
    };

    Authentication {
        key_sha256: Some(key_sha256),
        identity,
        result,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderValue, header::AUTHORIZATION};

    use super::*;
    use crate::keys::{KeyFile, SCHEMA_VERSION};

    fn store_with(records: Vec<KeyRecord>) -> KeyStore {
        KeyStore::from_records(records).unwrap()
    }

    fn one_key() -> (KeyStore, String, KeyRecord) {
        let (record, key) = KeyRecord::generate("alice", true).unwrap();
        (store_with(vec![record.clone()]), key, record)
    }

    fn headers(value: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn accepts_openai_style_bearer_auth_and_resolves_the_identity() {
        let (store, key, record) = one_key();

        let auth = authenticate(&headers(Some(&format!("Bearer {key}"))), &store);

        assert_eq!(auth.result, Ok(()));
        let identity = auth.identity.unwrap();
        assert_eq!(identity.name, "alice");
        assert_eq!(identity.identifier, record.identifier);
        assert!(identity.admin);
        assert_eq!(auth.key_sha256.as_deref(), Some(record.key_sha256.as_str()));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let (store, key, _) = one_key();

        assert!(
            authenticate(&headers(Some(&format!("bEaReR {key}"))), &store)
                .result
                .is_ok()
        );
    }

    #[test]
    fn rejects_missing_malformed_and_unknown_keys() {
        let (store, _, _) = one_key();

        assert_eq!(
            authenticate(&headers(None), &store).result,
            Err(AuthError::Missing)
        );
        assert_eq!(
            authenticate(&headers(Some("no-scheme")), &store).result,
            Err(AuthError::Malformed)
        );
        let unknown = authenticate(
            &headers(Some("Bearer eb_AAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")),
            &store,
        );
        assert_eq!(unknown.result, Err(AuthError::Invalid));
        // An unknown key still yields a digest so the log can identify repeats.
        assert!(unknown.key_sha256.is_some());
        assert!(unknown.identity.is_none());
    }

    #[test]
    fn a_disabled_key_is_recognised_but_refused() {
        let (mut record, key) = KeyRecord::generate("retired", false).unwrap();
        record.disabled = true;
        let (enabled, _) = KeyRecord::generate("current", true).unwrap();
        let store = store_with(vec![record, enabled]);

        let auth = authenticate(&headers(Some(&format!("Bearer {key}"))), &store);

        assert_eq!(auth.result, Err(AuthError::Disabled));
        assert_eq!(auth.identity.unwrap().name, "retired");
    }

    #[test]
    fn an_empty_or_fully_disabled_database_is_refused() {
        assert!(KeyStore::from_records(Vec::new()).is_err());

        let (mut record, _) = KeyRecord::generate("retired", true).unwrap();
        record.disabled = true;
        assert!(KeyStore::from_records(vec![record]).is_err());
    }

    #[test]
    fn keys_are_loaded_once_from_the_json_file() {
        let path = std::env::temp_dir().join(format!("proxy-auth-{}.json", uuid::Uuid::new_v4()));
        let (first_record, first_key) = KeyRecord::generate("first", true).unwrap();
        KeyFile {
            version: SCHEMA_VERSION,
            keys: vec![first_record],
        }
        .save(&path)
        .unwrap();

        let store = KeyStore::from_file(&path).unwrap();

        let (replacement, replacement_key) = KeyRecord::generate("second", true).unwrap();
        KeyFile {
            version: SCHEMA_VERSION,
            keys: vec![replacement],
        }
        .save(&path)
        .unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(store.lookup(&first_key).1.is_some());
        assert!(store.lookup(&replacement_key).1.is_none());
        assert_eq!(store.len(), 1);
    }
}
