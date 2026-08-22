//! Durable operator state for backend drain fences.
//!
//! Missing entries mean `active`. Only `draining` and `disabled` are written,
//! keeping the file an operational overlay rather than a second copy of
//! `runtime.toml`.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

use crate::backend::BackendMode;

const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedBackend {
    mode: BackendMode,
    changed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    schema_version: u32,
    backends: BTreeMap<String, PersistedBackend>,
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            backends: BTreeMap::new(),
        }
    }
}

/// Serialized writer and in-memory view of the durable operational overlay.
#[derive(Clone, Debug)]
pub struct BackendStateStore {
    path: Arc<PathBuf>,
    state: Arc<Mutex<StateFile>>,
}

impl BackendStateStore {
    pub fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let state = match fs::read_to_string(&path) {
            Ok(contents) => {
                let state: StateFile = serde_json::from_str(&contents).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("could not parse backend state {}: {error}", path.display()),
                    )
                })?;
                validate(&state).map_err(|message| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid backend state {}: {message}", path.display()),
                    )
                })?;
                state
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => StateFile::default(),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("could not read backend state {}: {error}", path.display()),
                ));
            }
        };

        Ok(Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn modes(&self) -> HashMap<String, BackendMode> {
        self.lock()
            .backends
            .iter()
            .map(|(id, state)| (id.clone(), state.mode))
            .collect()
    }

    /// Persist a mode transition atomically. `Active` removes the durable
    /// fence; the other modes install one before a command can report success.
    pub fn set_mode(&self, backend_id: &str, mode: BackendMode) -> io::Result<()> {
        let mut state = self.lock();
        let previous = state.clone();
        match mode {
            BackendMode::Active => {
                state.backends.remove(backend_id);
            }
            BackendMode::Draining | BackendMode::Disabled => {
                state.backends.insert(
                    backend_id.to_owned(),
                    PersistedBackend {
                        mode,
                        changed_at_unix_ms: now_unix_ms(),
                    },
                );
            }
        }
        if let Err(error) = save_file(&self.path, &state) {
            *state = previous;
            return Err(error);
        }
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, StateFile> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn validate(state: &StateFile) -> Result<(), String> {
    if state.schema_version != STATE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema version {} (this build understands {STATE_SCHEMA_VERSION})",
            state.schema_version
        ));
    }
    for (id, backend) in &state.backends {
        if id.is_empty() {
            return Err("an entry has an empty backend id".to_owned());
        }
        if backend.mode == BackendMode::Active {
            return Err(format!(
                "backend {id:?} stores mode active; active backends must be omitted"
            ));
        }
    }
    Ok(())
}

fn save_file(path: &Path, state: &StateFile) -> io::Result<()> {
    validate(state).map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;
    let mut json = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    json.push(b'\n');

    let directory = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory)?;
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "backend-state.json".to_owned());
    let temporary = directory.join(format!(".{filename}.{}.tmp", std::process::id()));

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    let result = file
        .write_all(&json)
        .and_then(|()| file.sync_all())
        .and_then(|()| harden_permissions(&file))
        .and_then(|()| fs::rename(&temporary, path))
        .and_then(|()| sync_directory(directory));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn harden_permissions(file: &File) -> io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
}

#[cfg(not(unix))]
fn harden_permissions(_file: &File) -> io::Result<()> {
    Ok(())
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
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
    use uuid::Uuid;

    use super::*;

    fn path() -> PathBuf {
        std::env::temp_dir().join(format!("proxy-backend-state-{}.json", Uuid::new_v4()))
    }

    #[test]
    fn missing_state_means_every_backend_is_active() {
        let path = path();
        let store = BackendStateStore::load(&path).unwrap();
        assert!(store.modes().is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn non_active_modes_round_trip_and_activate_removes_the_fence() {
        let path = path();
        let store = BackendStateStore::load(&path).unwrap();
        store.set_mode("gpu-a", BackendMode::Draining).unwrap();
        store.set_mode("gpu-b", BackendMode::Disabled).unwrap();

        let loaded = BackendStateStore::load(&path).unwrap();
        assert_eq!(loaded.modes()["gpu-a"], BackendMode::Draining);
        assert_eq!(loaded.modes()["gpu-b"], BackendMode::Disabled);

        loaded.set_mode("gpu-a", BackendMode::Active).unwrap();
        assert!(
            !BackendStateStore::load(&path)
                .unwrap()
                .modes()
                .contains_key("gpu-a")
        );
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_is_owner_only() {
        let path = path();
        let store = BackendStateStore::load(&path).unwrap();
        store.set_mode("gpu-a", BackendMode::Disabled).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(path).unwrap();
    }
}
