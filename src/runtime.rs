use std::{
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::http::Uri;
use serde::Deserialize;
use tokio::time::MissedTickBehavior;

pub const RELOAD_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub id: String,
    pub url: Uri,
    pub enabled: bool,
}

impl Backend {
    pub fn new(id: impl Into<String>, url: Uri, enabled: bool) -> Self {
        Self {
            id: id.into(),
            url,
            enabled,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub backends: Vec<Backend>,
    pub registration: RegistrationConfig,
}

/// Runtime controls for the public API-key registration page.
///
/// Registration is deliberately disabled unless the runtime file opts in.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RegistrationConfig {
    pub enabled: bool,
    pub max_keys: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RuntimeFile {
    backends: Vec<BackendFile>,
    #[serde(default)]
    registration: RegistrationConfig,
}

#[derive(Debug, Deserialize)]
struct BackendFile {
    id: String,
    url: String,
    enabled: bool,
}

impl RuntimeConfig {
    pub async fn load(path: &Path) -> Result<Self, RuntimeConfigError> {
        let contents =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|source| RuntimeConfigError::Read {
                    path: path.to_owned(),
                    source,
                })?;

        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self, RuntimeConfigError> {
        let file: RuntimeFile = toml::from_str(contents).map_err(RuntimeConfigError::Parse)?;
        if file.backends.len() != 1 {
            return Err(RuntimeConfigError::BackendCount(file.backends.len()));
        }

        let backends = file
            .backends
            .into_iter()
            .map(|backend| {
                let url = parse_backend_url(&backend.url).map_err(|reason| {
                    RuntimeConfigError::InvalidBackendUrl {
                        id: backend.id.clone(),
                        url: backend.url.clone(),
                        reason,
                    }
                })?;

                Ok(Backend::new(backend.id, url, backend.enabled))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            backends,
            registration: file.registration,
        })
    }
}

#[derive(Debug)]
pub enum RuntimeConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse(toml::de::Error),
    BackendCount(usize),
    InvalidBackendUrl {
        id: String,
        url: String,
        reason: String,
    },
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::Parse(source) => write!(formatter, "invalid runtime TOML: {source}"),
            Self::BackendCount(actual) => write!(
                formatter,
                "runtime config must contain exactly one backend (found {actual})"
            ),
            Self::InvalidBackendUrl { id, url, reason } => write!(
                formatter,
                "backend {id:?} has invalid URL {url:?}: {reason}"
            ),
        }
    }
}

impl Error for RuntimeConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::BackendCount(_) | Self::InvalidBackendUrl { .. } => None,
        }
    }
}

fn parse_backend_url(value: &str) -> Result<Uri, String> {
    let uri = value
        .parse::<Uri>()
        .map_err(|error| format!("invalid URI: {error}"))?;

    if uri.scheme_str() != Some("http") {
        return Err("backend URL must use http:// (this build has no TLS connector)".to_owned());
    }
    let Some(authority) = uri.authority() else {
        return Err("backend URL must include a host".to_owned());
    };
    if authority.as_str().contains('@') {
        return Err("backend URL cannot include user information".to_owned());
    }
    if uri.query().is_some() {
        return Err("backend URL cannot include a query string".to_owned());
    }

    Ok(uri)
}

/// The current valid runtime configuration shared by handlers and the reloader.
/// Reads only hold the lock long enough to clone the requested value, never
/// across I/O.
#[derive(Clone, Debug)]
pub struct RuntimeState {
    inner: Arc<RwLock<RuntimeConfig>>,
}

impl RuntimeState {
    pub fn new(backends: Vec<Backend>) -> Self {
        Self::from_config(RuntimeConfig {
            backends,
            registration: RegistrationConfig::default(),
        })
    }

    pub fn from_config(config: RuntimeConfig) -> Self {
        assert_eq!(
            config.backends.len(),
            1,
            "the proxy currently supports exactly one backend"
        );
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    pub fn available(&self) -> Option<Backend> {
        self.inner
            .read()
            .expect("runtime state lock poisoned")
            .backends
            .iter()
            .find(|backend| backend.enabled)
            .cloned()
    }

    pub fn configured(&self) -> Backend {
        self.inner
            .read()
            .expect("runtime state lock poisoned")
            .backends[0]
            .clone()
    }

    pub fn registration(&self) -> RegistrationConfig {
        self.inner
            .read()
            .expect("runtime state lock poisoned")
            .registration
    }

    fn replace(&self, config: RuntimeConfig) {
        debug_assert_eq!(config.backends.len(), 1);
        *self.inner.write().expect("runtime state lock poisoned") = config;
    }
}

/// Re-read `path` every 500 ms, atomically publishing each valid configuration.
/// Invalid transient contents leave the entire last known-good state in place.
pub async fn reload(path: PathBuf, runtime: RuntimeState) {
    let mut interval = tokio::time::interval(RELOAD_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // `interval`'s first tick is immediate; startup already performed that load.
    interval.tick().await;
    let mut last_error = None;

    loop {
        interval.tick().await;
        match RuntimeConfig::load(&path).await {
            Ok(config) => {
                runtime.replace(config);
                if last_error.take().is_some() {
                    eprintln!("runtime config at {} is valid again", path.display());
                }
            }
            Err(error) => {
                let message = error.to_string();
                if last_error.as_deref() != Some(message.as_str()) {
                    eprintln!(
                        "could not reload runtime config; keeping the last valid state: {message}"
                    );
                }
                last_error = Some(message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENABLED_BACKEND: &str = r#"
[[backends]]
id = "gh200-a"
url = "http://127.0.0.1:1234"
enabled = true
"#;

    #[test]
    fn parses_the_runtime_backend_vector() {
        let config = RuntimeConfig::parse(ENABLED_BACKEND).unwrap();

        assert_eq!(
            config.backends,
            vec![Backend::new(
                "gh200-a",
                "http://127.0.0.1:1234".parse().unwrap(),
                true,
            )]
        );
        assert_eq!(config.registration, RegistrationConfig::default());
    }

    #[test]
    fn registration_is_disabled_and_unlimited_when_omitted() {
        let config = RuntimeConfig::parse(ENABLED_BACKEND).unwrap();

        assert!(!config.registration.enabled);
        assert_eq!(config.registration.max_keys, None);
    }

    #[test]
    fn parses_registration_controls() {
        let config = RuntimeConfig::parse(&format!(
            "{ENABLED_BACKEND}\n[registration]\nenabled = true\nmax_keys = 25\n"
        ))
        .unwrap();

        assert_eq!(
            config.registration,
            RegistrationConfig {
                enabled: true,
                max_keys: Some(25),
            }
        );
    }

    #[test]
    fn an_empty_registration_section_keeps_safe_defaults() {
        let config = RuntimeConfig::parse(&format!("{ENABLED_BACKEND}\n[registration]\n")).unwrap();

        assert_eq!(config.registration, RegistrationConfig::default());
    }

    #[test]
    fn omitted_max_keys_means_unlimited_even_when_registration_is_enabled() {
        let config = RuntimeConfig::parse(&format!(
            "{ENABLED_BACKEND}\n[registration]\nenabled = true\n"
        ))
        .unwrap();

        assert!(config.registration.enabled);
        assert_eq!(config.registration.max_keys, None);
    }

    #[test]
    fn a_disabled_backend_is_not_available() {
        let config = RuntimeConfig::parse(&ENABLED_BACKEND.replace("true", "false")).unwrap();
        let runtime = RuntimeState::from_config(config);

        assert!(runtime.available().is_none());
    }

    #[test]
    fn requires_exactly_one_backend() {
        let no_backends = RuntimeConfig::parse("backends = []").unwrap_err();
        assert!(matches!(no_backends, RuntimeConfigError::BackendCount(0)));

        let two_backends =
            RuntimeConfig::parse(&format!("{ENABLED_BACKEND}{ENABLED_BACKEND}")).unwrap_err();
        assert!(matches!(two_backends, RuntimeConfigError::BackendCount(2)));
    }

    #[test]
    fn rejects_backend_urls_the_http_connector_cannot_use() {
        for url in [
            "https://example.com",
            "/relative",
            "http://example.com?q=1",
            "http://user:pass@example.com",
        ] {
            let contents = ENABLED_BACKEND.replace("http://127.0.0.1:1234", url);
            assert!(
                matches!(
                    RuntimeConfig::parse(&contents),
                    Err(RuntimeConfigError::InvalidBackendUrl { .. })
                ),
                "accepted {url}"
            );
        }
    }
}
