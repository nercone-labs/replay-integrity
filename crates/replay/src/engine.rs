use android::{ActivityManager, PackageManager};
use der::Time;
use keybox::KeyboxDocument;
use serde::Serialize;

use crate::{
    BootHook, Component, ComponentState, Conflicts, Files, Fingerprint, FingerprintReport, KeystoreConfig, KeystoreDaemon, Layout, Log, Module, PatchDate,
    PersistedKey, ReplayError, RootManager, Settings, Store, TargetList, Verifier, Zygisk, config, store::InstalledFile, store::State, verify::KeyboxVerdict,
};

/// The packages whose Play Integrity state must be refreshed for a new keybox or fingerprint to
/// take effect: the DroidGuard process of Play services and the Play Store.
pub const REFRESH_PROCESSES: [&str; 2] = ["com.google.android.gms.unstable", "com.android.vending"];

/// What an `apply` or `repair` did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyReport {
    pub targets: usize,
    pub security_patch: Option<String>,
    pub spoof: Vec<(String, bool)>,
    /// The persisted keys removed because their chains were signed by a key no longer present.
    pub stale_keys_removed: usize,
    pub daemon_restarted: bool,
    pub refreshed: bool,
}

/// The result of installing a keybox or fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallReport {
    pub sha256: String,
    /// Whether the file changed what was on disk.
    pub changed: bool,
    pub verdict: Option<KeyboxVerdict>,
    pub fingerprint: Option<FingerprintReport>,
}

/// The whole state of the device, for the application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    pub root_manager: Option<RootManager>,
    pub zygisk: Option<Zygisk>,
    pub components: Vec<ComponentState>,
    pub conflicts: Vec<Module>,
    pub keybox: Option<KeyboxVerdict>,
    pub keybox_installed: Option<InstalledFile>,
    pub fingerprint: Option<FingerprintReport>,
    pub fingerprint_installed: Option<InstalledFile>,
    pub daemon_running: bool,
    pub stale_keys: usize,
    pub boot_hook: bool,
    pub repaired_at: Option<u64>,
    /// Whether every piece needed for STRONG is present: both components, a strong-capable
    /// keybox, a sound fingerprint, no conflicts, and Zygisk for the integrity module.
    pub strong_ready: bool,
}

/// The engine: every operation on the device's attestation configuration.
pub struct Engine {
    pub layout: Layout,
    pub store: Store,
    pub config: KeystoreConfig,
    pub log: Log,
}

impl Engine {
    pub fn new(layout: Layout) -> Engine {
        let store = Store::new(&layout);
        let log = store.log();
        Engine { config: KeystoreConfig::new(&layout), store, log, layout }
    }

    fn now() -> Time {
        Time { seconds: i64::try_from(Log::now()).unwrap_or(0) }
    }

    /// Loads the certificate status list from its JSON, if the application fetched it. Without
    /// it, revocation is not checked and the engine says so.
    fn verifier(&mut self, status_json: Option<&str>) -> Verifier {
        let status = status_json.and_then(|json| match attestation::StatusList::parse(json) {
            Ok(list) => Some(list),
            Err(error) => {
                self.log.warning(format!("the certificate status list is invalid and is ignored: {error}"));
                None
            }
        });
        Verifier::new(status)
    }

    /// Checks a keybox without installing it.
    pub fn inspect_keybox(&mut self, bytes: &[u8], status_json: Option<&str>) -> Result<KeyboxVerdict, ReplayError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ReplayError::Rejected(vec!["the keybox is not UTF-8 text".to_string()]))?;
        let document = KeyboxDocument::parse(text)?;
        Ok(self.verifier(status_json).check(&document, Engine::now()))
    }

    pub fn inspect_fingerprint(&mut self, bytes: &[u8]) -> Result<FingerprintReport, ReplayError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ReplayError::Rejected(vec!["the fingerprint is not UTF-8 text".to_string()]))?;
        Ok(Fingerprint::parse(text).report(Engine::now().seconds))
    }

    /// Installs a keybox after checking it: it must parse and have at least one usable key.
    /// The keybox on disk is replaced atomically, and the one replaced is kept in the store.
    pub fn install_keybox(&mut self, bytes: &[u8], source: Option<String>, status_json: Option<&str>) -> Result<InstallReport, ReplayError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ReplayError::Rejected(vec!["the keybox is not UTF-8 text".to_string()]))?;
        let document = KeyboxDocument::parse(text)?;
        let verdict = self.verifier(status_json).check(&document, Engine::now());
        if !verdict.is_installable() {
            return Err(ReplayError::Rejected(vec!["the keybox has no key, or a key whose private key does not match its certificate".to_string()]));
        }
        let path = self.config.keybox();
        Files::create_directory(&self.layout.tricky_store(), BootHook::DIRECTORY_MODE)?;
        let sha256 = Files::sha256(bytes);
        let current = Files::read_optional(&path)?;
        let changed = current.as_deref() != Some(bytes);
        if changed {
            self.store.create()?;
            if let Some(previous) = &current {
                Files::write_atomic(&self.store.previous_keybox(), previous, Store::FILE_MODE)?;
            }
            Files::write_atomic(&path, bytes, KeystoreConfig::KEYBOX_MODE)?;
            self.log.info(format!("installed a keybox: {} of {} key(s) usable now", verdict.usable_keys(), verdict.keys.len()));
        }
        self.update_state(|state| state.keybox = Some(InstalledFile { sha256: sha256.clone(), source, installed_at: Log::now() }))?;
        Ok(InstallReport { sha256, changed, verdict: Some(verdict), fingerprint: None })
    }

    /// Installs a fingerprint after checking it has no problems. The spoof flags and the
    /// security patch are applied, and the result is written where PlayIntegrityFork reads it.
    pub fn install_fingerprint(&mut self, bytes: &[u8], source: Option<String>, settings: &Settings) -> Result<InstallReport, ReplayError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ReplayError::Rejected(vec!["the fingerprint is not UTF-8 text".to_string()]))?;
        let fingerprint = Fingerprint::parse(text);
        let report = fingerprint.report(Engine::now().seconds);
        if !report.problems.is_empty() {
            return Err(ReplayError::Rejected(vec!["the fingerprint has problems (see the report)".to_string()]));
        }
        let spoof = settings.spoof_flags(self.sdk());
        let prepared = config::fingerprint_for_integrity(&fingerprint, &spoof);
        let rendered = prepared.file.render();
        Files::create_directory(&self.config.fingerprint_directory(), BootHook::DIRECTORY_MODE)?;
        let path = self.config.fingerprint_path();
        let changed = Files::read_optional(&path)?.as_deref() != Some(rendered.as_bytes());
        Files::write_atomic(&path, rendered.as_bytes(), KeystoreConfig::CONFIG_MODE)?;
        self.write_integrity_fingerprint(&prepared)?;
        if let Some(patch) = fingerprint.security_patch() {
            self.write_security_patch(patch)?;
        }
        let sha256 = Files::sha256(rendered.as_bytes());
        self.update_state(|state| state.fingerprint = Some(InstalledFile { sha256: sha256.clone(), source, installed_at: Log::now() }))?;
        if changed {
            self.log.info("installed a fingerprint");
        }
        Ok(InstallReport { sha256, changed, verdict: None, fingerprint: Some(report) })
    }

    /// Writes the fingerprint to the `custom.pif.prop` of the PlayIntegrityFork module, if it
    /// is installed. Returns whether it was written.
    fn write_integrity_fingerprint(&mut self, fingerprint: &Fingerprint) -> Result<bool, ReplayError> {
        let path = self.config.custom_pif();
        let Some(directory) = path.parent() else { return Ok(false) };
        if !directory.is_dir() {
            return Ok(false);
        }
        Files::write_atomic(&path, fingerprint.file.render().as_bytes(), KeystoreConfig::CONFIG_MODE)?;
        Ok(true)
    }

    fn write_security_patch(&mut self, patch: PatchDate) -> Result<(), ReplayError> {
        Files::create_directory(&self.layout.tricky_store(), BootHook::DIRECTORY_MODE)?;
        Files::write_atomic(&self.config.security_patch(), KeystoreConfig::security_patch_contents(patch).as_bytes(), KeystoreConfig::CONFIG_MODE)
    }

    /// Builds and writes `target.txt` from the installed third-party packages and the extra
    /// packages of the settings.
    pub fn build_targets(&mut self, settings: &Settings) -> Result<TargetList, ReplayError> {
        let third_party = PackageManager::third_party().unwrap_or_default();
        let list = TargetList::build(&third_party, &settings.extra_packages);
        Files::create_directory(&self.layout.tricky_store(), BootHook::DIRECTORY_MODE)?;
        Files::write_atomic(&self.config.target(), list.render().as_bytes(), KeystoreConfig::CONFIG_MODE)?;
        Ok(list)
    }

    /// The API level of the device.
    pub fn sdk(&self) -> Option<u32> {
        android::SystemProperty::sdk()
    }

    /// The installed keybox, if any, read and checked.
    pub fn keybox_verdict(&mut self, status_json: Option<&str>) -> Result<Option<KeyboxVerdict>, ReplayError> {
        match Files::read_optional(&self.config.keybox())? {
            Some(bytes) => Ok(Some(self.inspect_keybox(&bytes, status_json)?)),
            None => Ok(None),
        }
    }

    /// The certificates that sign the first-level certificate of each key of the installed
    /// keybox: the signers that a persisted key's chain must match to be current.
    fn keybox_signers(&self) -> Result<Vec<Vec<u8>>, ReplayError> {
        let Some(bytes) = Files::read_optional(&self.config.keybox())? else { return Ok(Vec::new()) };
        let text = std::str::from_utf8(&bytes).map_err(|_| ReplayError::Rejected(vec!["the keybox is not UTF-8 text".to_string()]))?;
        let document = KeyboxDocument::parse(text)?;
        Ok(document.keys().filter_map(|key| key.certificates.first().map(|certificate| certificate.der.clone())).collect())
    }

    /// The persisted keys whose chains were signed by a key that is not in the current keybox:
    /// their attestation uses an old keybox and fails once it is revoked or expires.
    pub fn stale_keys(&self) -> Result<Vec<PersistedKey>, ReplayError> {
        let signers = self.keybox_signers()?;
        if signers.is_empty() {
            return Ok(Vec::new());
        }
        let signers: Vec<&[u8]> = signers.iter().map(Vec::as_slice).collect();
        let directory = self.layout.tricky_store().join(PersistedKey::DIRECTORY);
        Ok(PersistedKey::list(&directory)?.into_iter().filter(|key| key.is_stale(&signers)).collect())
    }

    /// Removes the stale persisted keys. The keystore daemon regenerates a key an application
    /// asks for again, with the current keybox, so removing them is safe. Returns how many.
    pub fn remove_stale_keys(&mut self) -> Result<usize, ReplayError> {
        let stale = self.stale_keys()?;
        for key in &stale {
            Files::remove(&key.path)?;
            self.log.info(format!("removed a stale persisted key of uid {} ({})", key.uid, key.alias));
        }
        Ok(stale.len())
    }

    /// Restarts the keystore daemon so it reloads the keybox and the persisted keys, then asks
    /// Play services and the Play Store to re-evaluate by ending their processes.
    pub fn restart(&mut self) -> Result<bool, ReplayError> {
        let daemon = KeystoreDaemon::new(&self.layout);
        let restarted = if daemon.state().is_running() {
            daemon.restart(&mut self.log)?;
            true
        } else {
            self.log.warning("the keystore daemon is not running; not restarting it");
            false
        };
        self.refresh_play();
        Ok(restarted)
    }

    /// Ends the DroidGuard and Play Store processes so they re-evaluate Play Integrity. The
    /// system restarts them; a failure to end one is not fatal.
    pub fn refresh_play(&mut self) {
        let processes = android::ProcessTable::list().unwrap_or_default();
        for name in REFRESH_PROCESSES {
            for process in processes.iter().filter(|process| process.name == name) {
                let _ = process.kill();
            }
        }
        let _ = ActivityManager::kill_background();
    }

    /// Re-applies the configuration without fetching anything: rebuild `target.txt`, re-apply
    /// the spoof flags and the security patch from the installed fingerprint, remove stale
    /// persisted keys, and restart the daemon. This is what runs at boot and periodically; it
    /// is what keeps the verdict from drifting after the modules' own scripts run.
    pub fn apply(&mut self, settings: &Settings, restart: bool) -> Result<ApplyReport, ReplayError> {
        let targets = self.build_targets(settings)?.targets.len();
        let spoof = settings.spoof_flags(self.sdk());
        let mut security_patch = None;
        if let Some(bytes) = Files::read_optional(&self.config.fingerprint_path())? {
            let fingerprint = Fingerprint::parse(&String::from_utf8_lossy(&bytes));
            let prepared = fingerprint.with_settings(&spoof);
            self.write_integrity_fingerprint(&prepared)?;
            if let Some(patch) = fingerprint.security_patch() {
                self.write_security_patch(patch)?;
                security_patch = Some(patch.to_string());
            }
        }
        let stale_keys_removed = self.remove_stale_keys()?;
        let daemon_restarted = if restart { self.restart()? } else { false };
        self.update_state(|state| state.repaired_at = Some(Log::now()))?;
        Ok(ApplyReport {
            targets,
            security_patch,
            spoof: spoof.values.iter().map(|(flag, value)| (flag.key().to_string(), *value)).collect(),
            stale_keys_removed,
            daemon_restarted,
            refreshed: daemon_restarted,
        })
    }

    /// Installs a module zip of `component` with the root manager. The module takes effect at
    /// the next boot.
    pub fn install_module(&mut self, component: Component, zip: &str) -> Result<String, ReplayError> {
        let manager = RootManager::single(&self.layout)?;
        self.log.info(format!("installing {} with {manager:?}", component.module_name()));
        manager.install_module(&self.layout, zip)
    }

    pub fn install_hook(&mut self, executable: &str) -> Result<BootHook, ReplayError> {
        BootHook::install(&self.layout, executable)
    }

    pub fn remove_hook(&mut self) -> Result<BootHook, ReplayError> {
        BootHook::remove(&self.layout)
    }

    /// Reads the whole state of the device.
    pub fn status(&mut self, status_json: Option<&str>) -> Result<StatusReport, ReplayError> {
        let manager = RootManager::installed(&self.layout);
        let root_manager = match manager.as_slice() {
            [single] => Some(*single),
            _ => manager.first().copied(),
        };
        let zygisk = root_manager.map(|manager| manager.zygisk(&self.layout));
        let components: Vec<ComponentState> = Component::ALL.iter().map(|component| component.state(&self.layout)).collect();
        let conflicts = Conflicts::active(&self.layout);
        let keybox = self.keybox_verdict(status_json)?;
        let fingerprint = Files::read_optional(&self.config.fingerprint_path())?
            .map(|bytes| Fingerprint::parse(&String::from_utf8_lossy(&bytes)).report(Engine::now().seconds));
        let daemon_running = KeystoreDaemon::new(&self.layout).state().is_running();
        let stale_keys = self.stale_keys().map(|keys| keys.len()).unwrap_or(0);
        let boot_hook = BootHook::current(&self.layout).is_installed();
        let state = self.store.state(&mut self.log);
        let strong_ready = components.iter().all(ComponentState::is_ready)
            && conflicts.is_empty()
            && keybox.as_ref().is_some_and(KeyboxVerdict::is_strong_capable)
            && fingerprint.as_ref().is_some_and(|report| report.problems.is_empty())
            && zygisk.as_ref().is_some_and(Zygisk::available);
        Ok(StatusReport {
            root_manager,
            zygisk,
            components,
            conflicts,
            keybox,
            keybox_installed: state.keybox,
            fingerprint,
            fingerprint_installed: state.fingerprint,
            daemon_running,
            stale_keys,
            boot_hook,
            repaired_at: state.repaired_at,
            strong_ready,
        })
    }

    fn update_state(&mut self, change: impl FnOnce(&mut State)) -> Result<(), ReplayError> {
        let mut state = self.store.state(&mut self.log);
        change(&mut state);
        self.store.save(&state)
    }

    /// Checks that the engine runs as root (uid 0), which every operation that changes the
    /// system needs.
    pub fn require_root() -> Result<(), ReplayError> {
        let uid = current_euid();
        if uid == 0 { Ok(()) } else { Err(ReplayError::refused(format!("the engine must run as root, but runs as uid {uid}"))) }
    }
}

/// The effective user ID of the engine process.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn current_euid() -> u32 {
    // SAFETY: geteuid takes no arguments and always succeeds.
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn current_euid() -> u32 {
    0
}
