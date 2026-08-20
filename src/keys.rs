//! The on-disk key database.
//!
//! Keys look like `eb_<identifier>_<secret>`, where both halves use the
//! URL-safe base64 alphabet: 8 characters of identifier and 32 characters of
//! secret. Only the identifier and a SHA-256 digest of the whole key are
//! stored, so the file cannot be used to recover a key.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Namespace prefix shared by every key this tool issues.
pub const KEY_PREFIX: &str = "eb";
/// Characters in the public identifier segment.
pub const IDENTIFIER_LEN: usize = 8;
/// Characters in the secret segment.
pub const SECRET_LEN: usize = 32;
/// The only key-file schema this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Default path used when no `--keys-file` is given.
pub fn default_path() -> PathBuf {
    PathBuf::from("keys.json")
}

/// One issued key. `key_sha256` is lowercase hex over the ASCII key text.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyRecord {
    pub name: String,
    pub identifier: String,
    pub key_sha256: String,
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub created_at_unix_ms: u64,
}

impl KeyRecord {
    /// Mint a new key, returning the record to store and the one-time
    /// plaintext to hand to the operator.
    pub fn generate(name: impl Into<String>, admin: bool) -> io::Result<(Self, String)> {
        let name = name.into();
        let identifier = random_base64(IDENTIFIER_LEN)?;
        let secret = random_base64(SECRET_LEN)?;
        let key = format!("{KEY_PREFIX}_{identifier}_{secret}");
        let record = Self {
            name,
            identifier,
            key_sha256: hex_encode(&digest(&key)),
            admin,
            disabled: false,
            created_at_unix_ms: now_unix_ms(),
        };

        Ok((record, key))
    }
}

/// The parsed contents of a key file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyFile {
    pub version: u32,
    pub keys: Vec<KeyRecord>,
}

impl Default for KeyFile {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            keys: Vec::new(),
        }
    }
}

impl KeyFile {
    /// Read and validate a key file.
    pub fn load(path: &Path) -> io::Result<Self> {
        let contents = fs::read_to_string(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not read key file {}: {error}", path.display()),
            )
        })?;
        let file: Self = serde_json::from_str(&contents).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("could not parse key file {}: {error}", path.display()),
            )
        })?;
        file.validate().map_err(|message| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid key file {}: {message}", path.display()),
            )
        })?;

        Ok(file)
    }

    /// Read a key file, treating a missing file as an empty database.
    pub fn load_or_default(path: &Path) -> io::Result<Self> {
        match Self::load(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            other => other,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema version {} (this build understands {SCHEMA_VERSION})",
                self.version
            ));
        }
        for (index, key) in self.keys.iter().enumerate() {
            let position = index + 1;
            if key.name.trim().is_empty() {
                return Err(format!("key {position} has an empty name"));
            }
            if !is_base64_segment(&key.identifier, IDENTIFIER_LEN) {
                return Err(format!(
                    "key {position} has identifier {:?}, expected {IDENTIFIER_LEN} base64 characters",
                    key.identifier
                ));
            }
            if decode_digest(&key.key_sha256).is_none() {
                return Err(format!(
                    "key {position} has a key_sha256 that is not 64 hex characters"
                ));
            }
            if self.keys[..index]
                .iter()
                .any(|earlier| earlier.identifier == key.identifier)
            {
                return Err(format!("identifier {} appears twice", key.identifier));
            }
            if self.keys[..index]
                .iter()
                .any(|earlier| earlier.key_sha256.eq_ignore_ascii_case(&key.key_sha256))
            {
                return Err(format!(
                    "the digest for key {position} ({}) appears twice",
                    key.name
                ));
            }
        }

        Ok(())
    }

    /// Replace the file at `path`, keeping it owner-only on Unix.
    ///
    /// The new contents are written to a sibling temporary file and renamed, so
    /// an interrupted save cannot truncate an existing database.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        self.validate()
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;

        let mut json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        json.push(b'\n');

        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let temporary = match directory {
            Some(directory) => directory.join(temporary_name(path)),
            None => PathBuf::from(temporary_name(path)),
        };

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        let result = file
            .write_all(&json)
            .and_then(|()| file.sync_all())
            .and_then(|()| harden_permissions(&file))
            .and_then(|()| fs::rename(&temporary, path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }

        result
    }
}

fn temporary_name(path: &Path) -> String {
    let stem = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keys.json".to_owned());
    format!(".{stem}.{}.tmp", std::process::id())
}

#[cfg(unix)]
fn harden_permissions(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
}

#[cfg(not(unix))]
fn harden_permissions(_file: &File) -> io::Result<()> {
    Ok(())
}

/// SHA-256 over the ASCII text of a key.
pub fn digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// Parse 64 hex characters into a digest.
pub fn decode_digest(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }

    Some(digest)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

/// The identifier segment of a well-formed key, if it has one.
///
/// The segments are split at fixed offsets rather than on the first underscore,
/// because `_` is itself part of the URL-safe base64 alphabet.
pub fn identifier_of(key: &str) -> Option<&str> {
    let rest = key.strip_prefix(KEY_PREFIX)?.strip_prefix('_')?;
    if rest.len() != IDENTIFIER_LEN + 1 + SECRET_LEN {
        return None;
    }
    let (identifier, rest) = rest.split_at(IDENTIFIER_LEN);
    let secret = rest.strip_prefix('_')?;
    (is_base64_segment(identifier, IDENTIFIER_LEN) && is_base64_segment(secret, SECRET_LEN))
        .then_some(identifier)
}

fn is_base64_segment(segment: &str, length: usize) -> bool {
    segment.len() == length
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// `length` characters of URL-safe base64 drawn from the system CSPRNG.
fn random_base64(length: usize) -> io::Result<String> {
    // Four base64 characters encode three bytes, and `length` is a multiple of
    // four here, so the encoding is exact and needs no padding.
    let mut bytes = vec![0u8; length / 4 * 3];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("could not read system randomness: {error}")))?;
    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    debug_assert_eq!(encoded.len(), length);

    Ok(encoded)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("proxy-keys-{}-{name}.json", uuid::Uuid::new_v4()))
    }

    #[test]
    fn generated_keys_have_the_documented_shape() {
        let (record, key) = KeyRecord::generate("alice", true).unwrap();

        assert_eq!(record.identifier.len(), IDENTIFIER_LEN);
        assert_eq!(identifier_of(&key), Some(record.identifier.as_str()));
        assert_eq!(
            key.len(),
            KEY_PREFIX.len() + 1 + IDENTIFIER_LEN + 1 + SECRET_LEN
        );
        assert!(key.starts_with("eb_"));
        assert_eq!(record.key_sha256, hex_encode(&digest(&key)));
        assert!(record.admin);
        assert!(!record.disabled);
    }

    #[test]
    fn distinct_keys_are_generated() {
        let (first, _) = KeyRecord::generate("a", false).unwrap();
        let (second, _) = KeyRecord::generate("a", false).unwrap();

        assert_ne!(first.identifier, second.identifier);
        assert_ne!(first.key_sha256, second.key_sha256);
    }

    #[test]
    fn a_saved_file_round_trips() {
        let path = scratch("round-trip");
        let (record, key) = KeyRecord::generate("admin", true).unwrap();
        let file = KeyFile {
            version: SCHEMA_VERSION,
            keys: vec![record],
        };
        file.save(&path).unwrap();

        let loaded = KeyFile::load(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].name, "admin");
        assert_eq!(loaded.keys[0].key_sha256, hex_encode(&digest(&key)));
    }

    #[test]
    fn a_missing_file_reads_as_an_empty_database() {
        let file = KeyFile::load_or_default(&scratch("absent")).unwrap();

        assert!(file.keys.is_empty());
        assert_eq!(file.version, SCHEMA_VERSION);
    }

    #[test]
    fn duplicate_and_malformed_records_are_rejected() {
        let (record, _) = KeyRecord::generate("dup", false).unwrap();
        let duplicated = KeyFile {
            version: SCHEMA_VERSION,
            keys: vec![record.clone(), record.clone()],
        };
        assert!(duplicated.validate().is_err());

        let mut bad_identifier = record.clone();
        bad_identifier.identifier = "short".to_owned();
        assert!(
            KeyFile {
                version: SCHEMA_VERSION,
                keys: vec![bad_identifier]
            }
            .validate()
            .is_err()
        );

        let mut bad_digest = record.clone();
        bad_digest.key_sha256 = "zz".to_owned();
        assert!(
            KeyFile {
                version: SCHEMA_VERSION,
                keys: vec![bad_digest]
            }
            .validate()
            .is_err()
        );

        assert!(
            KeyFile {
                version: SCHEMA_VERSION + 1,
                keys: vec![record]
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn an_underscore_inside_a_segment_does_not_confuse_parsing() {
        let key = "eb_aa_bbccd_eeffgghhiijjkkllmmnnooppqqrrsstt";
        assert_eq!(
            key.len(),
            KEY_PREFIX.len() + 1 + IDENTIFIER_LEN + 1 + SECRET_LEN
        );

        assert_eq!(identifier_of(key), Some("aa_bbccd"));
    }

    #[test]
    fn only_well_formed_keys_expose_an_identifier() {
        assert_eq!(
            identifier_of("eb_AAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            Some("AAAAAAAA")
        );
        assert_eq!(identifier_of("eb_AAAAAAAA_short"), None);
        assert_eq!(
            identifier_of("xx_AAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            None
        );
        assert_eq!(identifier_of("nonsense"), None);
    }
}
