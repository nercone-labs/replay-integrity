use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Files, Layout, Log, ReplayError, Settings};

/// A file the engine installed: what it was, where it came from and when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledFile {
    pub sha256: String,
    /// What the application said the file came from, such as a URL.
    pub source: Option<String>,
    /// Seconds since the Unix epoch.
    pub installed_at: u64,
}

/// What the engine remembers between commands.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct State {
    pub keybox: Option<InstalledFile>,
    pub fingerprint: Option<InstalledFile>,
    /// When `apply` last ran, in seconds since the Unix epoch.
    pub applied_at: Option<u64>,
    /// When the boot hook last ran `boot`, in seconds since the Unix epoch.
    pub booted_at: Option<u64>,
}

/// The directory of the engine, `/data/adb/replay-integrity`, readable by root only:
/// `state.json`, the settings applied last (`settings.json`), the installed fingerprint
/// (`fingerprint.prop`), the keybox replaced last (`previous-keybox.xml`), the log, and the copy
/// of the engine that the boot hook runs (`replay`).
pub struct Store {
    pub directory: PathBuf,
}

impl Store {
    pub const DIRECTORY_MODE: u32 = 0o700;
    pub const FILE_MODE: u32 = 0o600;
    pub const STATE: &'static str = "state.json";
    pub const PREVIOUS_KEYBOX: &'static str = "previous-keybox.xml";
    pub const LOG: &'static str = "replay.log";
    pub const SETTINGS: &'static str = "settings.json";
    pub const EXECUTABLE: &'static str = "replay";
    pub const EXECUTABLE_MODE: u32 = 0o700;

    pub fn new(layout: &Layout) -> Store {
        Store { directory: layout.store() }
    }

    pub fn create(&self) -> Result<(), ReplayError> {
        Files::create_directory(&self.directory, Store::DIRECTORY_MODE)
    }

    pub fn log(&self) -> Log {
        Log::new(self.directory.is_dir().then(|| self.directory.join(Store::LOG)))
    }

    /// The remembered state. A missing or unreadable state is the empty state: it only
    /// describes earlier installations, and losing it loses no configuration.
    pub fn state(&self, log: &mut Log) -> State {
        let path = self.directory.join(Store::STATE);
        match Files::read_optional(&path) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                log.warning(format!("{} is invalid and is ignored: {error}", path.display()));
                State::default()
            }),
            Ok(None) => State::default(),
            Err(error) => {
                log.warning(format!("{error}; the state is ignored"));
                State::default()
            }
        }
    }

    pub fn save(&self, state: &State) -> Result<(), ReplayError> {
        self.create()?;
        let json = serde_json::to_vec_pretty(state).map_err(|error| ReplayError::io("serialize the state", std::io::Error::other(error)))?;
        Files::write_atomic(&self.directory.join(Store::STATE), &json, Store::FILE_MODE)
    }

    /// The settings `apply` saved, or the defaults when none were saved. Saved settings that
    /// cannot be read are an error: applying the defaults instead would silently undo the
    /// user's choices.
    pub fn settings(&self) -> Result<Settings, ReplayError> {
        match Files::read_optional(&self.directory.join(Store::SETTINGS))? {
            Some(bytes) => Settings::parse(&bytes),
            None => Ok(Settings::default()),
        }
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<(), ReplayError> {
        self.create()?;
        let json = serde_json::to_vec_pretty(settings).map_err(|error| ReplayError::io("serialize the settings", std::io::Error::other(error)))?;
        Files::write_atomic(&self.directory.join(Store::SETTINGS), &json, Store::FILE_MODE)
    }

    /// The copy of the engine that the boot hook runs. The engine of the application lives in
    /// its native library directory, whose path changes with every update of the application,
    /// so the hook runs a copy at a fixed path instead.
    pub fn executable(&self) -> PathBuf {
        self.directory.join(Store::EXECUTABLE)
    }

    /// Copies `source` (the running engine) to `executable`, replacing an earlier copy atomically.
    pub fn install_executable(&self, source: &std::path::Path) -> Result<PathBuf, ReplayError> {
        let target = self.executable();
        if source == target {
            return Ok(target);
        }
        self.create()?;
        let bytes = Files::read(source)?;
        Files::write_atomic(&target, &bytes, Store::EXECUTABLE_MODE)?;
        Ok(target)
    }

    pub fn previous_keybox(&self) -> PathBuf {
        self.directory.join(Store::PREVIOUS_KEYBOX)
    }
}
