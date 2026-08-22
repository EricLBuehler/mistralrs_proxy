use std::{
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::keys::{self, KeyFile, KeyRecord};

/// Maximum number of Unicode scalar values accepted in a key name.
pub const MAX_KEY_NAME_CHARS: usize = 64;

/// Who a request belongs to, resolved from the key database at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyIdentity {
    pub name: String,
    pub identifier: String,
    pub key_sha256: String,
    pub admin: bool,
    pub disabled: bool,
}

/// The immutable lookup data published to request handlers as one snapshot.
struct KeyIndex {
    digests: Box<[[u8; 32]]>,
    identities: Box<[Arc<KeyIdentity>]>,
}

impl KeyIndex {
    fn from_records(records: Vec<KeyRecord>) -> io::Result<Self> {
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

    /// Look up a presented key, comparing every entry so the work does not
    /// depend on which key was presented.
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

struct KeyWriter {
    path: PathBuf,
    gate: tokio::sync::Mutex<()>,
}

/// A cheaply cloned, atomically updated set of API keys.
///
/// Stores loaded with [`Self::from_file`] can issue persistent non-admin keys
/// while the proxy is running. Stores built with [`Self::from_records`] remain
/// useful for embedding and tests, but deliberately have no persistence path.
#[derive(Clone)]
pub struct KeyStore {
    index: Arc<RwLock<KeyIndex>>,
    writer: Option<Arc<KeyWriter>>,
}

impl KeyStore {
    /// Load the JSON key database and retain its path for runtime issuance.
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = KeyFile::load(&path)?;
        let index = KeyIndex::from_records(file.keys).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("unusable key file {}: {error}", path.display()),
            )
        })?;

        Ok(Self {
            index: Arc::new(RwLock::new(index)),
            writer: Some(Arc::new(KeyWriter {
                path,
                gate: tokio::sync::Mutex::new(()),
            })),
        })
    }

    /// Build a store from already-loaded records.
    ///
    /// Useful when embedding the proxy as a library and in tests; the binary
    /// always goes through [`Self::from_file`].
    pub fn from_records(records: Vec<KeyRecord>) -> io::Result<Self> {
        Ok(Self {
            index: Arc::new(RwLock::new(KeyIndex::from_records(records)?)),
            writer: None,
        })
    }

    /// Number of keys in the store.
    pub fn len(&self) -> usize {
        self.index
            .read()
            .expect("key store lock poisoned")
            .identities
            .len()
    }

    /// Always false: an empty database is rejected at construction.
    pub fn is_empty(&self) -> bool {
        self.index
            .read()
            .expect("key store lock poisoned")
            .identities
            .is_empty()
    }

    /// Whether this store can currently accept another runtime registration.
    ///
    /// This is an advisory snapshot for presenting the registration UI. The
    /// limit is checked again inside [`Self::create_non_admin`] while writes are
    /// serialized.
    pub fn can_register(&self, max_keys: Option<usize>) -> bool {
        self.writer.is_some() && !max_keys.is_some_and(|limit| self.len() >= limit)
    }

    /// Look up a presented key. Returns its digest for logging plus the
    /// matching identity, comparing every entry so the work does not depend on
    /// which key was presented.
    fn lookup(&self, presented: &str) -> (String, Option<Arc<KeyIdentity>>) {
        self.index
            .read()
            .expect("key store lock poisoned")
            .lookup(presented)
    }

    /// Persist and immediately publish a new active, non-admin key.
    ///
    /// Registrations are serialized across every clone of this store. Each
    /// transaction reloads the file before changing it, then publishes the
    /// complete saved snapshot before allowing the next transaction to begin.
    pub async fn create_non_admin(
        &self,
        name: &str,
        max_keys: Option<usize>,
    ) -> Result<String, KeyCreationError> {
        let name = normalize_key_name(name)?;
        let writer = self.writer.as_ref().ok_or_else(|| {
            KeyCreationError::Unavailable(io::Error::new(
                io::ErrorKind::Unsupported,
                "this key store was not loaded from a file",
            ))
        })?;
        let _guard = writer.gate.lock().await;
        let path = writer.path.clone();

        let (index, plaintext) = tokio::task::spawn_blocking(move || {
            let mut file = KeyFile::load(&path).map_err(KeyCreationError::Unavailable)?;
            if max_keys.is_some_and(|limit| file.keys.len() >= limit) {
                return Err(KeyCreationError::LimitReached);
            }
            if file.keys.iter().any(|key| key.name == name) {
                return Err(KeyCreationError::DuplicateName);
            }

            let (record, plaintext) =
                KeyRecord::generate(name, false).map_err(KeyCreationError::Unavailable)?;
            file.keys.push(record);
            let index =
                KeyIndex::from_records(file.keys.clone()).map_err(KeyCreationError::Unavailable)?;
            file.save(&path).map_err(KeyCreationError::Unavailable)?;

            Ok((index, plaintext))
        })
        .await
        .map_err(|error| {
            KeyCreationError::Unavailable(io::Error::other(format!(
                "key creation worker failed: {error}"
            )))
        })??;

        *self.index.write().expect("key store lock poisoned") = index;

        Ok(plaintext)
    }
}

/// Why a runtime API-key creation request could not be completed.
#[derive(Debug)]
pub enum KeyCreationError {
    InvalidName(&'static str),
    DuplicateName,
    LimitReached,
    Unavailable(io::Error),
}

impl fmt::Display for KeyCreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(reason) => write!(formatter, "invalid key name: {reason}"),
            Self::DuplicateName => formatter.write_str("a key with that name already exists"),
            Self::LimitReached => {
                formatter.write_str("the key registration limit has been reached")
            }
            Self::Unavailable(source) => {
                write!(formatter, "key registration is unavailable: {source}")
            }
        }
    }
}

impl Error for KeyCreationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unavailable(source) => Some(source),
            Self::InvalidName(_) | Self::DuplicateName | Self::LimitReached => None,
        }
    }
}

fn normalize_key_name(name: &str) -> Result<String, KeyCreationError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(KeyCreationError::InvalidName("it cannot be empty"));
    }
    if name.chars().count() > MAX_KEY_NAME_CHARS {
        return Err(KeyCreationError::InvalidName(
            "it cannot be longer than 64 characters",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(KeyCreationError::InvalidName(
            "it cannot contain control characters",
        ));
    }

    Ok(name.to_owned())
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

    fn file_backed_store() -> (PathBuf, KeyStore) {
        let path = std::env::temp_dir().join(format!("proxy-auth-{}.json", uuid::Uuid::new_v4()));
        let (record, _) = KeyRecord::generate("admin", true).unwrap();
        KeyFile {
            version: SCHEMA_VERSION,
            keys: vec![record],
        }
        .save(&path)
        .unwrap();
        let store = KeyStore::from_file(&path).unwrap();

        (path, store)
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

    #[test]
    fn registration_names_are_trimmed_bounded_and_free_of_controls() {
        assert_eq!(
            normalize_key_name("  Alice Example  ").unwrap(),
            "Alice Example"
        );
        assert_eq!(
            normalize_key_name(&"é".repeat(MAX_KEY_NAME_CHARS)).unwrap(),
            "é".repeat(MAX_KEY_NAME_CHARS)
        );

        for invalid in [
            String::new(),
            " \t\n ".to_owned(),
            "Alice\nAdmin".to_owned(),
            "é".repeat(MAX_KEY_NAME_CHARS + 1),
        ] {
            assert!(matches!(
                normalize_key_name(&invalid),
                Err(KeyCreationError::InvalidName(_))
            ));
        }
    }

    #[tokio::test]
    async fn a_persistent_non_admin_key_is_published_immediately_and_never_stored_plaintext() {
        let (path, store) = file_backed_store();
        let request_store = store.clone();

        let plaintext = store.create_non_admin("  Bob  ", None).await.unwrap();

        assert_eq!(store.len(), 2);
        let auth = authenticate(
            &headers(Some(&format!("Bearer {plaintext}"))),
            &request_store,
        );
        assert_eq!(auth.result, Ok(()));
        let identity = auth.identity.unwrap();
        assert_eq!(identity.name, "Bob");
        assert!(!identity.admin);
        assert!(!identity.disabled);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains(&plaintext));
        let file = KeyFile::load(&path).unwrap();
        assert_eq!(file.keys.len(), 2);
        assert_eq!(file.keys[1].name, "Bob");
        assert!(!file.keys[1].admin);
        assert_eq!(
            file.keys[1].key_sha256,
            keys::hex_encode(&keys::digest(&plaintext))
        );

        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn registration_distinguishes_duplicates_limits_and_read_only_stores() {
        let (path, store) = file_backed_store();

        assert!(store.can_register(None));
        assert!(store.can_register(Some(2)));

        store.create_non_admin("Bob", None).await.unwrap();
        assert!(store.can_register(None));
        assert!(!store.can_register(Some(2)));
        assert!(matches!(
            store.create_non_admin("Bob", None).await,
            Err(KeyCreationError::DuplicateName)
        ));
        assert!(matches!(
            store.create_non_admin("Carol", Some(2)).await,
            Err(KeyCreationError::LimitReached)
        ));

        let (read_only, _, _) = one_key();
        assert!(!read_only.can_register(None));
        assert!(!read_only.can_register(Some(10)));
        assert!(matches!(
            read_only.create_non_admin("Bob", None).await,
            Err(KeyCreationError::Unavailable(_))
        ));
        assert_eq!(KeyFile::load(&path).unwrap().keys.len(), 2);

        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn concurrent_registrations_are_serialized_without_lost_updates() {
        const REGISTRATIONS: usize = 8;

        let (path, store) = file_backed_store();
        let mut tasks = Vec::new();
        for index in 0..REGISTRATIONS {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                let name = format!("user-{index}");
                let plaintext = store.create_non_admin(&name, None).await.unwrap();
                (name, plaintext)
            }));
        }

        let mut issued = Vec::new();
        for task in tasks {
            issued.push(task.await.unwrap());
        }

        assert_eq!(store.len(), REGISTRATIONS + 1);
        let file = KeyFile::load(&path).unwrap();
        assert_eq!(file.keys.len(), REGISTRATIONS + 1);
        let contents = std::fs::read_to_string(&path).unwrap();
        for (name, plaintext) in issued {
            assert!(!contents.contains(&plaintext));
            let auth = authenticate(&headers(Some(&format!("Bearer {plaintext}"))), &store);
            assert_eq!(auth.result, Ok(()));
            assert_eq!(auth.identity.unwrap().name, name);
        }

        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn concurrent_duplicate_names_create_exactly_one_key() {
        let (path, store) = file_backed_store();
        let first_store = store.clone();
        let second_store = store.clone();
        let first = tokio::spawn(async move { first_store.create_non_admin("Bob", None).await });
        let second = tokio::spawn(async move { second_store.create_non_admin("Bob", None).await });
        let results = [first.await.unwrap(), second.await.unwrap()];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(KeyCreationError::DuplicateName)))
                .count(),
            1
        );
        assert_eq!(store.len(), 2);
        assert_eq!(KeyFile::load(&path).unwrap().keys.len(), 2);

        std::fs::remove_file(path).unwrap();
    }
}
