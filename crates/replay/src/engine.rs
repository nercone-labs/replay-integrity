use android::{ActivityManager, Capability, DeviceKeystore, KeyDeletion, PackageList, PackageManager, ProcessCapabilities};
use attestation::{StatusList, TrustAnchors};
use der::Time;
use keybox::{KeyAlgorithm, KeyboxDocument};
use serde::Serialize;

use crate::{
    BootHook, Component, ComponentState, Conflicts, DaemonState, Files, Fingerprint, FingerprintReport, KeyCategory, KeyRemovalSettings, KeystoreConfig,
    KeystoreDaemon, Layout, Log, Module, OutdatedKey, OutdatedReason, PackageWatcher, PatchDate, PersistedKey, ReplayError, RootManager, Settings, Store,
    TargetList, Verifier, WatchReport, Zygisk, store::InstalledFile, store::State, verify::KeyboxVerdict,
};

/// The packages whose Play Integrity state must be refreshed for a new keybox or fingerprint to
/// take effect: the DroidGuard process of Play services and the Play Store.
pub const REFRESH_PROCESSES: [&str; 2] = ["com.google.android.gms.unstable", "com.android.vending"];

/// How `apply` runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// Rebuild the target list, re-apply the configuration, then restart the keystore daemon
    /// and end the Play processes so that the change takes effect at once.
    Restart,
    /// Like `Restart`, without restarting anything: the change takes effect when the daemon
    /// and the Play processes next start.
    NoRestart,
    /// At boot, before the framework starts: the package manager does not run yet, so the
    /// target list is kept as it is, and nothing is restarted, because nothing runs yet.
    EarlyBoot,
}

/// When `install_keybox` replaces the installed keybox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyboxPolicy {
    /// Always, when the keybox is installable: the user chose this file.
    Replace,
    /// Only when the keybox ranks at least as high as the installed one
    /// (`KeyboxVerdict::may_replace`), so that an automatic refresh from a mirror that serves a
    /// revoked or broken keybox never replaces a working one. A mirror's newer keybox replaces
    /// a working one of the same rank, before that one can leak and be revoked; every change of
    /// the keybox outdates the keys attested with the old one.
    NoDowngrade,
    /// Like `NoDowngrade`, and only when the installed keybox will not have a usable EC key
    /// `margin_seconds` from now: it is missing, revoked, untrusted, or expires within the
    /// margin. A working keybox is kept, so the keys attested with it stay current. A revocation
    /// is seen only with the certificate status list.
    WhenNeeded { margin_seconds: i64 },
}

impl KeyboxPolicy {
    /// Why this policy keeps the installed keybox instead of the offered one, whose verdict is
    /// `offered`; `None` when the offered one is installed. `installed` is the verdict of the
    /// installed keybox now, and `installed_later` its verdict at the end of the margin of
    /// `WhenNeeded` (`None` without an installed keybox that can be read).
    pub fn declines(&self, offered: &KeyboxVerdict, installed: Option<&KeyboxVerdict>, installed_later: Option<&KeyboxVerdict>) -> Option<Declined> {
        match self {
            KeyboxPolicy::Replace => None,
            KeyboxPolicy::WhenNeeded { .. } if installed_later.is_some_and(|later| later.has_usable(KeyAlgorithm::ECDSA)) => Some(Declined::NotNeeded),
            KeyboxPolicy::NoDowngrade | KeyboxPolicy::WhenNeeded { .. } if !offered.may_replace(installed) => Some(Declined::Worse),
            KeyboxPolicy::NoDowngrade | KeyboxPolicy::WhenNeeded { .. } => None,
        }
    }
}

/// Why `install_keybox` kept the installed keybox instead of the offered one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Declined {
    /// The installed keybox ranks higher than the offered one (`KeyboxPolicy::NoDowngrade`).
    Worse,
    /// The installed keybox stays usable beyond the margin (`KeyboxPolicy::WhenNeeded`).
    NotNeeded,
}

/// What an `apply` did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyReport {
    /// The number of packages in `target.txt` afterwards.
    pub targets: usize,
    /// Whether `target.txt` was rebuilt; it is kept when the package manager cannot list packages.
    pub targets_rebuilt: bool,
    pub security_patch: Option<String>,
    pub spoof: Vec<(String, bool)>,
    /// The stale persisted keys removed (`Engine::stale_keys`).
    pub stale_keys_removed: usize,
    /// The stale persisted keys kept because the keystore could not delete their alias; the
    /// next `apply` tries again (`Engine::remove_stale_keys`).
    pub stale_keys_kept: usize,
    /// The outdated persisted keys that the settings keep (`OutdatedKey::removed_by_repair`).
    pub outdated_keys_kept: usize,
    /// Whether the installed keybox was not well-formed and was written again (`Engine::repair_keybox`).
    pub keybox_repaired: bool,
    pub daemon_restarted: bool,
}

/// What a `boot` did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum BootReport {
    /// The configuration was applied.
    Applied { report: ApplyReport },
    /// The application is uninstalled: the boot hook removed itself and nothing was applied.
    Uninstalled,
}

/// The result of installing a keybox or fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallReport {
    /// The SHA-256 of the file as it was written, or of the installed file when it was kept.
    pub sha256: String,
    /// Whether the file changed what was on disk.
    pub changed: bool,
    /// The verdict of the keybox that was offered, with every key it held.
    pub verdict: Option<KeyboxVerdict>,
    /// The keys of the offered keybox that were not written, because others are usable.
    pub dropped_keys: usize,
    /// Why the offered file was not installed, when the policy kept the installed one.
    pub declined: Option<Declined>,
    pub fingerprint: Option<FingerprintReport>,
}

/// The whole state of the device, for the application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    pub engine_version: String,
    /// The API level the device launched with: Google cross-checks it against the spoofed
    /// build, so it decides whether a spoofed Pixel identity can reach STRONG.
    pub first_api_level: Option<u32>,
    /// Every installed root manager; leftovers of an earlier one may make several appear.
    pub root_managers: Vec<RootManager>,
    pub zygisk: Option<Zygisk>,
    pub components: Vec<ComponentState>,
    pub conflicts: Vec<Module>,
    pub keybox: Option<KeyboxVerdict>,
    pub keybox_installed: Option<InstalledFile>,
    /// The fingerprint the engine installed, as it was downloaded or imported.
    pub fingerprint: Option<FingerprintReport>,
    pub fingerprint_installed: Option<InstalledFile>,
    /// The `custom.pif.prop` PlayIntegrityFork reads now, with the spoof flags it has. It
    /// differs from the applied flags when a script of the module rewrote it.
    pub integrity: Option<FingerprintReport>,
    /// The spoof flags `apply` writes with the saved settings, for comparison with `integrity`.
    pub spoof: Vec<(String, bool)>,
    /// The contents of `security_patch.txt`.
    pub security_patch: Option<String>,
    /// The packages of `target.txt`.
    pub targets: Option<TargetList>,
    /// The number of keys TEESimulator-RS persisted for applications.
    pub persisted_keys: usize,
    /// The outdated persisted keys (`Engine::outdated_keys`), judged by the saved settings: the
    /// next repair removes those with `removed_by_repair`.
    pub outdated_keys: Vec<OutdatedKey>,
    pub daemon: DaemonState,
    pub boot_hook: BootHook,
    pub applied_at: Option<u64>,
    pub booted_at: Option<u64>,
    /// The settings `apply` saved, which the boot hook applies.
    pub settings: Settings,
    /// The capabilities in `Engine::CAPABILITIES` that the engine lacks: when not empty, the
    /// root manager restricts root, and commands that change the system refuse to run.
    pub missing_capabilities: Vec<String>,
    /// Whether every piece needed for STRONG is present: both components, a strong-capable
    /// keybox (a usable EC key, in a file the daemon can read), a sound fingerprint, no
    /// conflicts, and Zygisk for the integrity module.
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
    /// The capabilities the engine uses. Running as uid 0 does not imply them: a root manager
    /// can drop them (the "Restrict" policy of Magisk drops every one).
    pub const CAPABILITIES: [Capability; 3] = [
        // Downloaded files are read from the private directory of the application.
        Capability::DAC_READ_SEARCH,
        // The Play processes and the keystore daemon of other users are ended.
        Capability::KILL,
        // `/proc` may be mounted with `hidepid`; the processes of other users are found with it.
        Capability::SYS_PTRACE,
    ];

    /// How many keys under the alias of a stale key the keystore deletes at most, before it
    /// finds none. The key of TEESimulator-RS and a key of the device's keystore make two; the
    /// rest allows for an application that makes its key again in the meantime.
    pub const STALE_KEY_DELETIONS: usize = 4;

    /// The properties that hold the API level the device launched with, in order of preference.
    pub const FIRST_API_LEVEL_PROPERTIES: [&'static str; 3] = ["ro.product.first_api_level", "ro.board.first_api_level", "ro.board.api_level"];

    pub fn new(layout: Layout) -> Engine {
        let store = Store::new(&layout);
        let log = store.log();
        Engine { config: KeystoreConfig::new(&layout), store, log, layout }
    }

    fn now() -> Time {
        Time { seconds: i64::try_from(Log::now()).unwrap_or(0) }
    }

    fn text(bytes: &[u8], what: &str) -> Result<String, ReplayError> {
        String::from_utf8(bytes.to_vec()).map_err(|_| ReplayError::Rejected(vec![format!("the {what} is not UTF-8 text")]))
    }

    /// Loads the certificate status list from its JSON, if the application fetched it. Without
    /// it, revocation is not checked and the engine says so.
    fn verifier(&mut self, status_json: Option<&str>) -> Verifier {
        Verifier::new(self.status_list(status_json))
    }

    /// The certificate status list of `status_json`; `None` without one, or with a warning
    /// when it is invalid.
    fn status_list(&mut self, status_json: Option<&str>) -> Option<StatusList> {
        status_json.and_then(|json| match StatusList::parse(json) {
            Ok(list) => Some(list),
            Err(error) => {
                self.log.warning(format!("the certificate status list is invalid and is ignored: {error}"));
                None
            }
        })
    }

    /// The certificate status list that persisted keys are judged with: `status_json`, or else
    /// the copy `apply` saved (`Store::status_list`), so that the boot hook, which is given none,
    /// judges as the application does. A copy may miss later revocations, which only keeps keys.
    /// An invalid `status_json` falls back to the copy as well.
    fn key_status_list(&mut self, status_json: Option<&str>) -> Option<StatusList> {
        self.status_list(status_json).or_else(|| {
            let saved = self.store.status_list();
            self.status_list(saved.as_deref())
        })
    }

    /// Reads a keybox, recovering the keys of one that is not well-formed (`KeyboxDocument::read`).
    pub fn read_keybox(bytes: &[u8]) -> Result<KeyboxDocument, ReplayError> {
        Ok(KeyboxDocument::read(&Engine::text(bytes, "keybox")?)?)
    }

    /// Checks a keybox without installing it.
    pub fn inspect_keybox(&mut self, bytes: &[u8], status_json: Option<&str>) -> Result<KeyboxVerdict, ReplayError> {
        let document = Engine::read_keybox(bytes)?;
        Ok(self.verifier(status_json).check(&document, Engine::now()))
    }

    pub fn inspect_fingerprint(&mut self, bytes: &[u8]) -> Result<FingerprintReport, ReplayError> {
        Ok(Fingerprint::read(&Engine::text(bytes, "fingerprint")?)?.report(Engine::now().seconds))
    }

    /// Installs a keybox after checking it: it must be read (`KeyboxDocument::read`) and have at
    /// least one key whose private key matches its certificate (`KeyboxVerdict::is_installable`). With
    /// `KeyboxPolicy::NoDowngrade`, a keybox that ranks below the installed one is declined and
    /// the installed one kept; with `KeyboxPolicy::WhenNeeded`, also while the installed one
    /// stays usable beyond the margin.
    ///
    /// What is written is never the offered text itself but its keys written again as a
    /// well-formed keybox (`KeyboxDocument::render`), with only the usable keys when there are
    /// any (`KeyboxVerdict::keys_to_write`). The keystore daemon then reads exactly the keys
    /// that were checked: none hidden by broken markup, and no revoked or untrusted key that it
    /// might prefer to a usable one. The keybox on disk is replaced atomically, and the one
    /// replaced is kept in the store.
    pub fn install_keybox(
        &mut self,
        bytes: &[u8],
        source: Option<String>,
        status_json: Option<&str>,
        policy: KeyboxPolicy,
    ) -> Result<InstallReport, ReplayError> {
        let document = Engine::read_keybox(bytes)?;
        let verifier = self.verifier(status_json);
        let now = Engine::now();
        let verdict = verifier.check(&document, now);
        if !verdict.is_installable() {
            return Err(ReplayError::Rejected(vec!["the keybox has no key whose private key matches its certificate".to_string()]));
        }
        if let Some(defect) = &verdict.defect {
            self.log.warning(format!("the keybox is not well-formed ({defect}); its keys were recovered and are written as a well-formed keybox"));
        }
        let path = self.config.keybox();
        let current = Files::read_optional(&path)?;
        if policy != KeyboxPolicy::Replace {
            let installed_document = current.as_deref().and_then(|bytes| Engine::read_keybox(bytes).ok());
            let installed = installed_document.as_ref().map(|document| verifier.check(document, now));
            let installed_later = match policy {
                KeyboxPolicy::WhenNeeded { margin_seconds } => {
                    installed_document.as_ref().map(|document| verifier.check(document, Time { seconds: now.seconds.saturating_add(margin_seconds) }))
                }
                KeyboxPolicy::Replace | KeyboxPolicy::NoDowngrade => None,
            };
            let declined = policy.declines(&verdict, installed.as_ref(), installed_later.as_ref());
            match declined {
                Some(Declined::NotNeeded) => self.log.info("the installed keybox stays usable beyond the expiry margin, so it is kept"),
                Some(Declined::Worse) => self.log.warning(format!(
                    "the installed keybox is better than the offered one, which is kept out: {} of {} offered key(s) are usable",
                    verdict.usable_keys(),
                    verdict.keys.len()
                )),
                None => {}
            }
            if declined.is_some() {
                let sha256 = current.as_deref().map(Files::sha256).unwrap_or_default();
                return Ok(InstallReport { sha256, changed: false, verdict: Some(verdict), dropped_keys: 0, declined, fingerprint: None });
            }
        }
        let indices = verdict.keys_to_write();
        let mut index = 0;
        let written = document.retain_keys(|_| {
            let keep = indices.contains(&index);
            index += 1;
            keep
        });
        let dropped_keys = verdict.keys.len() - indices.len();
        let rendered = written.render();
        Files::create_directory(&self.layout.tricky_store(), BootHook::DIRECTORY_MODE)?;
        let sha256 = Files::sha256(rendered.as_bytes());
        let changed = current.as_deref() != Some(rendered.as_bytes());
        if changed {
            self.store.create()?;
            if let Some(previous) = &current {
                Files::write_atomic(&self.store.previous_keybox(), previous, Store::FILE_MODE)?;
            }
            Files::write_atomic(&path, rendered.as_bytes(), KeystoreConfig::KEYBOX_MODE)?;
            self.log.info(format!("installed a keybox: {} of {} key(s) usable now, {dropped_keys} left out", verdict.usable_keys(), verdict.keys.len()));
        }
        self.update_state(|state| state.keybox = Some(InstalledFile { sha256: sha256.clone(), source, installed_at: Log::now() }))?;
        Ok(InstallReport { sha256, changed, verdict: Some(verdict), dropped_keys, declined: None, fingerprint: None })
    }

    /// Writes the installed keybox again as a well-formed keybox when it is not well-formed XML
    /// (another tool put it there), so that the keystore daemon can read its keys. The daemon
    /// reads no key from such a file, so writing the recovered keys cannot leave it worse off;
    /// every recovered key is written, because without the status list no key is judged here.
    /// The original is kept in the store as the previous keybox. Returns whether the file was
    /// written.
    pub fn repair_keybox(&mut self) -> Result<bool, ReplayError> {
        let path = self.config.keybox();
        let Some(bytes) = Files::read_optional(&path)? else { return Ok(false) };
        let document = Engine::read_keybox(&bytes)?;
        let Some(defect) = &document.defect else { return Ok(false) };
        self.log.warning(format!("the installed keybox is not well-formed ({defect}); it is written again with the keys recovered from it"));
        let rendered = document.render();
        self.store.create()?;
        Files::write_atomic(&self.store.previous_keybox(), &bytes, Store::FILE_MODE)?;
        Files::write_atomic(&path, rendered.as_bytes(), KeystoreConfig::KEYBOX_MODE)?;
        let sha256 = Files::sha256(rendered.as_bytes());
        self.update_state(|state| {
            if let Some(installed) = &mut state.keybox {
                installed.sha256 = sha256;
            }
        })?;
        Ok(true)
    }

    /// Installs a fingerprint (`custom.pif.prop`, or `custom.pif.json` converted to it) after
    /// checking it has no problems. It is kept in the store in the prop format, and written with the spoof flags of `settings` and its security patch where
    /// PlayIntegrityFork and TEESimulator-RS read them.
    pub fn install_fingerprint(&mut self, bytes: &[u8], source: Option<String>, settings: &Settings) -> Result<InstallReport, ReplayError> {
        let fingerprint = Fingerprint::read(&Engine::text(bytes, "fingerprint")?)?;
        let report = fingerprint.report(Engine::now().seconds);
        if !report.problems.is_empty() {
            return Err(ReplayError::Rejected(vec!["the fingerprint has problems (see the report)".to_string()]));
        }
        let rendered = fingerprint.file.render();
        let path = self.config.fingerprint_path();
        let changed = Files::read_optional(&path)?.as_deref() != Some(rendered.as_bytes());
        self.store.create()?;
        Files::write_atomic(&path, rendered.as_bytes(), Store::FILE_MODE)?;
        self.write_integrity_fingerprint(&fingerprint.with_settings(&settings.spoof_flags(Engine::sdk())))?;
        if let Some(patch) = fingerprint.security_patch() {
            self.write_security_patch(patch)?;
        }
        let sha256 = Files::sha256(rendered.as_bytes());
        self.update_state(|state| state.fingerprint = Some(InstalledFile { sha256: sha256.clone(), source, installed_at: Log::now() }))?;
        if changed {
            self.log.info(format!("installed a fingerprint of {}", report.fingerprint.as_deref().unwrap_or("an unknown build")));
        }
        Ok(InstallReport { sha256, changed, verdict: None, dropped_keys: 0, declined: None, fingerprint: Some(report) })
    }

    /// The installed fingerprint, if any.
    fn installed_fingerprint(&self) -> Result<Option<Fingerprint>, ReplayError> {
        Ok(Files::read_optional(&self.config.fingerprint_path())?.map(|bytes| Fingerprint::parse(&String::from_utf8_lossy(&bytes))))
    }

    /// Writes the fingerprint to the `custom.pif.prop` of the PlayIntegrityFork module, if it
    /// is installed and the file differs. Returns whether the module is installed.
    fn write_integrity_fingerprint(&mut self, fingerprint: &Fingerprint) -> Result<bool, ReplayError> {
        let path = self.config.custom_pif();
        let Some(directory) = path.parent() else { return Ok(false) };
        if !directory.is_dir() {
            self.log.warning("PlayIntegrityFork is not installed; its custom.pif.prop is not written");
            return Ok(false);
        }
        Files::write_if_changed(&path, fingerprint.file.render().as_bytes(), KeystoreConfig::CONFIG_MODE)?;
        Ok(true)
    }

    fn write_security_patch(&mut self, patch: PatchDate) -> Result<(), ReplayError> {
        Files::create_directory(&self.layout.tricky_store(), BootHook::DIRECTORY_MODE)?;
        let contents = KeystoreConfig::security_patch_contents(patch);
        Files::write_if_changed(&self.config.security_patch(), contents.as_bytes(), KeystoreConfig::CONFIG_MODE).map(|_| ())
    }

    /// Builds `target.txt` from the installed packages and `settings`, and writes it when it
    /// differs from the file on disk. It needs a working package manager: a failure leaves
    /// `target.txt` as it is, rather than replacing it with a list that lacks the installed
    /// applications.
    pub fn build_targets(&mut self, settings: &Settings) -> Result<TargetList, ReplayError> {
        let installed = PackageManager::installed()?;
        let third_party = PackageManager::third_party()?;
        let list = TargetList::build(&installed, &third_party, settings);
        Files::create_directory(&self.layout.tricky_store(), BootHook::DIRECTORY_MODE)?;
        if Files::write_if_changed(&self.config.target(), list.render().as_bytes(), KeystoreConfig::CONFIG_MODE)? {
            self.log.info(format!("target.txt now lists {} package(s)", list.targets.len()));
        }
        Ok(list)
    }

    /// The packages of `target.txt`, if it exists.
    pub fn targets(&self) -> Result<Option<TargetList>, ReplayError> {
        Ok(Files::read_optional(&self.config.target())?.map(|bytes| TargetList::parse(&String::from_utf8_lossy(&bytes))))
    }

    /// The API level of the device.
    pub fn sdk() -> Option<u32> {
        android::SystemProperty::sdk()
    }

    /// The API level the device launched with, from the first property of
    /// `FIRST_API_LEVEL_PROPERTIES` that holds a number.
    pub fn first_api_level() -> Option<u32> {
        Engine::FIRST_API_LEVEL_PROPERTIES.iter().find_map(|name| android::SystemProperty::get(name)?.trim().parse().ok())
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
        let document = Engine::read_keybox(&bytes)?;
        Ok(document.keys().filter_map(|key| key.certificates.first().map(|certificate| certificate.der.clone())).collect())
    }

    fn persisted_keys(&self) -> Result<Vec<PersistedKey>, ReplayError> {
        PersistedKey::list(&self.layout.tricky_store().join(PersistedKey::DIRECTORY))
    }

    /// The patch that `security_patch.txt` sets for every application, when the file is in the
    /// form this engine writes (`KeystoreConfig::security_patch_of`). `None` when the file is
    /// missing or cannot be read: the patch is then not compared, and the keys are still
    /// compared by their signers.
    fn configured_patch(&self) -> Option<PatchDate> {
        let bytes = Files::read_optional(&self.config.security_patch()).ok()??;
        std::str::from_utf8(&bytes).ok().and_then(KeystoreConfig::security_patch_of)
    }

    /// The persisted keys that were attested with what is no longer configured, each with the
    /// reasons (`OutdatedReason`), its category (`KeyCategory`), and whether `removal` removes
    /// it in a repair:
    ///
    /// - every key whose chain was signed by a key that is not in the current keybox: its
    ///   attestation fails once the old keybox is revoked or expires. Whether that chain is
    ///   already unusable is judged at now, with `status` for revocation;
    /// - the key of the Play Integrity API (`KeyCategory::Integrity`) when it attests a security
    ///   patch other than the configured one (`configured_patch`): it contradicts the patch of the
    ///   spoofed build.
    ///
    /// The patch is compared for the integrity key only. Another key may hold what the user
    /// enrolled with it (a card for tap-and-pay, a passkey, a banking application's enrolment),
    /// which deleting it on every monthly patch would lose; and a genuine device keeps the patch
    /// of a key's generation in its certificate too, so an older patch alone is no fault.
    ///
    /// Without a keybox, no key is outdated: there is nothing to compare with, and a key made
    /// again would not be attested either.
    pub fn outdated_keys(&self, removal: &KeyRemovalSettings, status: Option<&StatusList>) -> Result<Vec<OutdatedKey>, ReplayError> {
        let signers = self.keybox_signers()?;
        if signers.is_empty() {
            return Ok(Vec::new());
        }
        let signers: Vec<&[u8]> = signers.iter().map(Vec::as_slice).collect();
        let patch = self.configured_patch();
        // Without the package list, the packages of a key come from its attestation alone.
        let packages = PackageList::read_from(&self.layout.packages_list()).unwrap_or_default();
        let anchors = TrustAnchors::google();
        let now = Engine::now();
        let mut outdated = Vec::new();
        for key in self.persisted_keys()? {
            let key_packages = key.packages(&packages);
            let category = KeyCategory::of(&key, &key_packages);
            let mut reasons = Vec::new();
            if key.is_signed_by_other(&signers) {
                let unusable = key.signer_problems(now, status, &anchors).is_some_and(|problems| !problems.is_empty());
                reasons.push(OutdatedReason::OldKeybox { unusable });
            }
            if category == KeyCategory::Integrity
                && let (Some(patch), Some(description)) = (patch, key.key_description())
                && patch.differs_from_attested(&description)
            {
                reasons.push(OutdatedReason::OldPatch);
            }
            if reasons.is_empty() {
                continue;
            }
            let removed_by_repair = OutdatedKey::is_removed_by(category, &reasons, removal);
            outdated.push(OutdatedKey { key, category, packages: key_packages, reasons, removed_by_repair });
        }
        Ok(outdated)
    }

    /// The outdated persisted keys judged by `settings`, with `status_json` or the copy of the
    /// certificate status list that `apply` saved.
    pub fn outdated_keys_of(&mut self, settings: &Settings, status_json: Option<&str>) -> Result<Vec<OutdatedKey>, ReplayError> {
        let status = self.key_status_list(status_json);
        self.outdated_keys(&settings.key_removal, status.as_ref())
    }

    /// The outdated persisted keys that a repair with `removal` removes: the stale keys.
    pub fn stale_keys(&self, removal: &KeyRemovalSettings, status: Option<&StatusList>) -> Result<Vec<OutdatedKey>, ReplayError> {
        Ok(self.outdated_keys(removal, status)?.into_iter().filter(|key| key.removed_by_repair).collect())
    }

    /// Removes the stale persisted keys (`stale_keys`), so that each application makes its key
    /// again, attested with the current keybox and patch. Returns how many were removed, how
    /// many were kept because the keystore could not delete them, and how many outdated keys
    /// `removal` keeps.
    ///
    /// A key is deleted through the keystore, as the application that owns it, until the
    /// keystore has no key under its alias: TEESimulator-RS answers for its own key, and the
    /// device's keystore for a key of its own under the same alias. Such a device key is left
    /// over from a time when TEESimulator-RS did not generate the application's keys (it was not
    /// a target, or not in `Generate` mode). Removing only the persisted file would make it the
    /// application's key again, and TEESimulator-RS serves it unpatched to a `Generate` target,
    /// with the device's own root of trust: an unlocked or self-signed boot fails attestation
    /// until the application happens to make a new key.
    ///
    /// Only a key that TEESimulator-RS hides is deleted: while its module is not active, or the
    /// application is not a target, a device key under the alias is the application's own key,
    /// in use, and the persisted file is inert, so the file alone is removed. When the keystore cannot delete the alias (the
    /// client fails, keystore2 cannot be reached, the engine cannot run the client as the
    /// application), the key is kept for the next `apply`, and the status keeps reporting it as
    /// stale. When the device has no keystore client, or the alias cannot be given to it exactly,
    /// the file alone is removed, as the only repair possible, and a warning says so.
    pub fn remove_stale_keys(&mut self, removal: &KeyRemovalSettings, status: Option<&StatusList>) -> Result<(usize, usize, usize), ReplayError> {
        let keystore = DeviceKeystore::new(self.layout.keystore_client());
        let targets = self.targets().unwrap_or(None);
        let (mut removed, mut kept, mut left) = (0, 0, 0);
        for outdated in self.outdated_keys(removal, status)? {
            if !outdated.removed_by_repair {
                left += 1;
            } else if self.remove_stale_key(&keystore, &outdated, targets.as_ref())? {
                removed += 1;
            } else {
                kept += 1;
            }
        }
        if left > 0 {
            self.log.info(format!("kept {left} outdated persisted key(s), as the settings say; they can be removed one by one"));
        }
        Ok((removed, kept, left))
    }

    /// Removes the outdated persisted keys of the user `uid` under `alias`, whatever the settings
    /// keep, as `remove_stale_keys` removes a key: the user chose to lose what was enrolled with
    /// them. A key that is not outdated is never removed: it is current, and removing it would
    /// lose its enrolment for nothing. `alias` is compared with the alias as it is reported, so
    /// a key whose alias is not read exactly can be removed too; its file alone is removed, as a
    /// repair does. Returns how many were removed and how many were kept because the keystore
    /// could not delete them; no such key is an error. It holds the lock of `apply`, so that the
    /// two never delete under one alias at once.
    pub fn remove_key(&mut self, uid: u32, alias: &str, status_json: Option<&str>) -> Result<(usize, usize), ReplayError> {
        let _lock = self.store.lock_apply()?;
        let status = self.key_status_list(status_json);
        let matching: Vec<OutdatedKey> = self
            .outdated_keys(&KeyRemovalSettings::default(), status.as_ref())?
            .into_iter()
            .filter(|outdated| outdated.key.uid == uid && outdated.key.alias == alias)
            .collect();
        if matching.is_empty() {
            return Err(ReplayError::Rejected(vec![format!("uid {uid} has no outdated persisted key under the alias \"{alias}\"")]));
        }
        let keystore = DeviceKeystore::new(self.layout.keystore_client());
        let targets = self.targets().unwrap_or(None);
        let (mut removed, mut kept) = (0, 0);
        for outdated in matching {
            if self.remove_stale_key(&keystore, &outdated, targets.as_ref())? {
                removed += 1;
            } else {
                kept += 1;
            }
        }
        Ok((removed, kept))
    }

    /// Removes one stale persisted key (see `Engine::remove_stale_keys`). Returns whether it was
    /// removed.
    ///
    /// The device's key under the alias is deleted only while TEESimulator-RS hides it: the
    /// module is active and a package of the key is a target of `targets` (`target.txt`). For a
    /// package that is not a target, TEESimulator-RS passes the deletion to keystore2, and the
    /// device's key under the alias is the application's own key, in use; so the file alone is
    /// removed. Without a target list, no package is a target.
    fn remove_stale_key(&mut self, keystore: &DeviceKeystore, outdated: &OutdatedKey, targets: Option<&TargetList>) -> Result<bool, ReplayError> {
        let key = &outdated.key;
        let name = format!("uid {} ({})", key.uid, key.alias);
        // A module that waits for the next boot in `modules_update` does not run yet.
        let active = Module::read(&self.layout, Component::Keystore.module_id()).is_some_and(|module| module.installed && module.is_active());
        if !active {
            Files::remove(&key.path)?;
            self.log.info(format!(
                "removed a stale persisted key of {name}; {} is not active, so a key of the device's keystore under that alias is the application's own and is left alone",
                Component::Keystore.module_name()
            ));
            return Ok(true);
        }
        let target = targets.is_some_and(|list| list.packages().any(|package| outdated.packages.iter().any(|name| name == package)));
        if !target {
            Files::remove(&key.path)?;
            self.log.info(format!(
                "removed a stale persisted key of {name}; its application is not a target, so a key of the device's keystore under that alias is the application's own and is left alone"
            ));
            return Ok(true);
        }
        let unreachable = if !keystore.is_available() {
            Some(format!("{} does not exist", self.layout.device_path(&keystore.client).display()))
        } else if !key.alias_exact {
            Some("its alias cannot be read exactly".to_string())
        } else if !key.alias.is_ascii() {
            // The client reads the alias with `GetSwitchValueASCII`, which gives an empty
            // string for any other text.
            Some("the keystore client takes only ASCII aliases".to_string())
        } else {
            None
        };
        if let Some(reason) = unreachable {
            Files::remove(&key.path)?;
            self.log.warning(format!(
                "removed a stale persisted key of {name}; {reason}, so a key of the device's keystore under that alias, if there is one, is not deleted and becomes the application's key"
            ));
            return Ok(true);
        }
        let mut deleted = 0;
        let mut cleared = false;
        while deleted < Engine::STALE_KEY_DELETIONS {
            // An application's group is its user: Android gives each one a group of the same
            // number.
            match keystore.delete(key.uid, key.uid, &key.alias) {
                Ok(KeyDeletion::Deleted) => deleted += 1,
                Ok(KeyDeletion::NotFound) => {
                    cleared = true;
                    break;
                }
                Err(error) if deleted == 0 => {
                    self.log.warning(format!("kept a stale persisted key of {name} for a later repair: the keystore cannot delete it: {error}"));
                    return Ok(false);
                }
                // TEESimulator-RS has already deleted its key and the file with it: there is no
                // stale key left to keep, only a device key that may now be the application's.
                Err(error) => {
                    Files::remove(&key.path)?;
                    self.log.warning(format!(
                        "removed a stale persisted key of {name}, but the keystore failed after deleting {deleted} key(s) under that alias, so a key of the device's keystore under it may remain and become the application's key: {error}"
                    ));
                    return Ok(true);
                }
            }
        }
        Files::remove(&key.path)?;
        if cleared {
            self.log.info(format!("removed a stale persisted key of {name}: the keystore deleted {deleted} key(s) under that alias"));
        } else {
            self.log.warning(format!(
                "removed a stale persisted key of {name}: the keystore deleted {deleted} key(s) under that alias without running out of them; the application seems to make its key again"
            ));
        }
        Ok(true)
    }

    /// Restarts the keystore daemon so it reloads the keybox and the persisted keys, then asks
    /// Play services and the Play Store to re-evaluate by ending their processes; with
    /// `end_background`, every background application as well (`refresh_play`).
    pub fn restart(&mut self, end_background: bool) -> Result<bool, ReplayError> {
        let daemon = KeystoreDaemon::new(&self.layout);
        let restarted = if daemon.state().is_running() {
            daemon.restart(&mut self.log)?;
            true
        } else {
            self.log.warning("the keystore daemon is not running; not restarting it");
            false
        };
        self.refresh_play(end_background);
        Ok(restarted)
    }

    /// Ends the DroidGuard and Play Store processes so they re-evaluate Play Integrity, and
    /// with `end_background` every background application, so that the other targets ask for
    /// their keys again. The system restarts them; a failure to end one is logged, not fatal.
    pub fn refresh_play(&mut self, end_background: bool) {
        let processes = android::ProcessTable::list().unwrap_or_default();
        for name in REFRESH_PROCESSES {
            for process in processes.iter().filter(|process| process.name == name) {
                if let Err(error) = process.kill() {
                    self.log.warning(format!("cannot end {name} ({}): {error}", process.pid));
                }
            }
        }
        if end_background && let Err(error) = ActivityManager::kill_background() {
            self.log.warning(format!("cannot end the background processes: {error}"));
        }
    }

    /// Re-applies the configuration without fetching anything: saves `settings` for the boot
    /// hook (except at boot, which applies the saved ones), rebuilds `target.txt`, re-applies the
    /// spoof flags and the security patch from the installed fingerprint, writes the installed
    /// keybox again when it is not well-formed (`repair_keybox`), removes the stale persisted
    /// keys that the settings allow (`remove_stale_keys`, judged with `status_json` or the copy
    /// saved last), and restarts as `mode` says. This is what keeps the verdict from drifting
    /// after the modules' own scripts run. A valid `status_json` is saved for the boot hook.
    pub fn apply(&mut self, settings: &Settings, mode: ApplyMode, status_json: Option<&str>) -> Result<ApplyReport, ReplayError> {
        let _lock = self.store.lock_apply()?;
        if mode != ApplyMode::EarlyBoot {
            self.store.save_settings(settings)?;
        }
        let status = self.key_status_list(status_json);
        if let Some(json) = status_json
            && StatusList::parse(json).is_ok()
        {
            self.store.save_status_list(json)?;
        }
        let rebuilt = if mode == ApplyMode::EarlyBoot {
            None
        } else {
            match self.build_targets(settings) {
                Ok(list) => Some(list),
                Err(error) => {
                    self.log.warning(format!("target.txt is kept as it is: {error}"));
                    None
                }
            }
        };
        let targets_rebuilt = rebuilt.is_some();
        let targets = match rebuilt {
            Some(list) => list.targets.len(),
            None => self.targets()?.map_or(0, |list| list.targets.len()),
        };
        let spoof = settings.spoof_flags(Engine::sdk());
        let mut security_patch = None;
        if let Some(fingerprint) = self.installed_fingerprint()? {
            self.write_integrity_fingerprint(&fingerprint.with_settings(&spoof))?;
            if let Some(patch) = fingerprint.security_patch() {
                self.write_security_patch(patch)?;
                security_patch = Some(patch.to_string());
            }
        } else {
            self.log.warning("no fingerprint is installed; the spoof flags are not written");
        }
        let keybox_repaired = match self.repair_keybox() {
            Ok(repaired) => repaired,
            Err(error) => {
                self.log.warning(format!("the installed keybox cannot be read and is kept as it is: {error}"));
                false
            }
        };
        let (stale_keys_removed, stale_keys_kept, outdated_keys_kept) = self.remove_stale_keys(&settings.key_removal, status.as_ref())?;
        let daemon_restarted = if mode == ApplyMode::Restart { self.restart(settings.end_background_applications)? } else { false };
        self.update_state(|state| state.applied_at = Some(Log::now()))?;
        Ok(ApplyReport {
            targets,
            targets_rebuilt,
            security_patch,
            spoof: spoof.values.iter().map(|(flag, value)| (flag.key().to_string(), *value)).collect(),
            stale_keys_removed,
            stale_keys_kept,
            outdated_keys_kept,
            keybox_repaired,
            daemon_restarted,
        })
    }

    /// Runs at boot from the boot hook: applies the saved settings in `ApplyMode::EarlyBoot`.
    /// When `package` (the application) is uninstalled, the hook removes itself instead, so
    /// that nothing of the application keeps running at boot.
    pub fn boot(&mut self, package: &str) -> Result<BootReport, ReplayError> {
        Engine::require_root()?;
        if !Engine::is_package_present(&self.layout, package) {
            self.log.warning(format!("{package} seems to be uninstalled; the boot hook removes itself"));
            BootHook::remove(&self.layout)?;
            return Ok(BootReport::Uninstalled);
        }
        let settings = self.store.settings()?;
        let report = self.apply(&settings, ApplyMode::EarlyBoot, None)?;
        self.update_state(|state| state.booted_at = Some(Log::now()))?;
        Ok(BootReport::Applied { report })
    }

    /// Whether `package` is installed, as the package list of the previous boot
    /// (`/data/system/packages.list`) shows before the framework starts. The package manager
    /// rewrites the list as soon as a package is installed or removed, and it covers adopted
    /// storage, which is not mounted yet at boot. A list that cannot be read counts as holding
    /// the package, so that the hook never removes itself only because it cannot look.
    pub fn is_package_present(layout: &Layout, package: &str) -> bool {
        match PackageList::read_from(&layout.packages_list()) {
            Ok(packages) => PackageList::app_id_of(&packages, package).is_some(),
            Err(_) => true,
        }
    }

    /// Installs a module zip of `component` with the root manager. The module takes effect at
    /// the next boot.
    pub fn install_module(&mut self, component: Component, zip: &str) -> Result<String, ReplayError> {
        let manager = RootManager::single(&self.layout)?;
        self.log.info(format!("installing {} with {manager:?}", component.module_name()));
        manager.install_module(&self.layout, zip)
    }

    /// Disables the active conflicting modules (`Conflicts::disable`); they stop running at the
    /// next boot. Returns them as they are afterwards.
    pub fn disable_conflicts(&mut self) -> Result<Vec<Module>, ReplayError> {
        let disabled = Conflicts::disable(&self.layout)?;
        for module in &disabled {
            self.log.info(format!("disabled the conflicting module {} from the next boot", module.id));
        }
        Ok(disabled)
    }

    /// Installs the boot hook for `package`, with a copy of the running engine. With `watch`,
    /// the hook also starts the package watcher at every boot, and the watcher is started now
    /// when it does not run, so that it works without a reboot.
    pub fn install_hook(&mut self, package: &str, watch: bool) -> Result<BootHook, ReplayError> {
        let executable = std::env::current_exe().map_err(|error| ReplayError::io("find the engine executable", error))?;
        let hook = BootHook::install(&self.layout, &executable, package, watch)?;
        if watch && hook.is_installed() && PackageWatcher::new(&self.layout).start(package)? {
            self.log.info("started the package watcher");
            return Ok(BootHook::current(&self.layout));
        }
        Ok(hook)
    }

    /// Runs the package watcher (`PackageWatcher`) for the application `package` until the
    /// application is uninstalled or the boot hook is removed: once the system has booted, it
    /// rebuilds `target.txt` with the saved settings, then again after every change of the
    /// package list. A rebuild that fails is logged and the watcher goes on; the next change,
    /// or the next refresh of the application, tries again.
    pub fn watch(&mut self, package: &str, watcher: &PackageWatcher) -> Result<WatchReport, ReplayError> {
        Engine::require_root()?;
        let Some(_lock) = watcher.lock()? else {
            return Ok(WatchReport::AlreadyRunning { pid: watcher.running() });
        };
        watcher.detach();
        while !android::SystemProperty::is_boot_completed() {
            std::thread::sleep(watcher.boot_poll);
        }
        let list = self.layout.packages_list();
        let mut watch = android::FileWatch::new(&list).map_err(|error| ReplayError::io_at("watch", &list, error))?;
        self.log.info(format!("watching {} for installed and removed applications", self.layout.device_path(&list).display()));
        loop {
            if let Some(report) = self.watch_step(package)? {
                return Ok(report);
            }
            // The lines were written to the log file; keeping them would grow without bound.
            self.log.lines.clear();
            watch.wait().map_err(|error| ReplayError::io_at("watch", &list, error))?;
            std::thread::sleep(watcher.settle);
            watch.take_pending().map_err(|error| ReplayError::io_at("watch", &list, error))?;
        }
    }

    /// One round of the package watcher: ends it when the application was uninstalled (removing
    /// the boot hook) or the boot hook removed, and rebuilds `target.txt` otherwise.
    ///
    /// While the system runs, `packages.list` also leaves out applications whose storage is
    /// unmounted (an ejected adopted card), so an absence there is confirmed with the package
    /// manager before the hook is removed; when the package manager cannot answer, nothing is
    /// removed.
    fn watch_step(&mut self, package: &str) -> Result<Option<WatchReport>, ReplayError> {
        if !Engine::is_package_present(&self.layout, package)
            && PackageManager::installed().is_ok_and(|installed| !installed.iter().any(|name| name == package))
        {
            self.log.warning(format!("{package} is uninstalled; the boot hook removes itself"));
            BootHook::remove(&self.layout)?;
            return Ok(Some(WatchReport::Uninstalled));
        }
        if !BootHook::current(&self.layout).watches {
            self.log.info("the service script of the boot hook was removed; the package watcher ends");
            return Ok(Some(WatchReport::Stopped));
        }
        let _lock = self.store.lock_apply()?;
        match self.store.settings() {
            Ok(settings) => {
                if let Err(error) = self.build_targets(&settings) {
                    self.log.warning(format!("target.txt is kept as it is: {error}"));
                }
            }
            Err(error) => self.log.warning(format!("the saved settings cannot be read; target.txt is kept as it is: {error}")),
        }
        Ok(None)
    }

    pub fn remove_hook(&mut self) -> Result<BootHook, ReplayError> {
        BootHook::remove(&self.layout)
    }

    /// Reads the whole state of the device. Parts that cannot be read are logged and left
    /// empty, so that one broken file does not hide everything else.
    pub fn status(&mut self, status_json: Option<&str>) -> Result<StatusReport, ReplayError> {
        let root_managers = RootManager::installed(&self.layout);
        let zygisk = root_managers.first().map(|manager| manager.zygisk(&self.layout));
        let components: Vec<ComponentState> = Component::ALL.iter().map(|component| component.state(&self.layout)).collect();
        let conflicts = Conflicts::active(&self.layout);
        let keybox = self.keybox_verdict(status_json).unwrap_or_else(|error| {
            self.log.warning(format!("the installed keybox cannot be read: {error}"));
            None
        });
        let now = Engine::now().seconds;
        let fingerprint = self.readable(self.installed_fingerprint(), "the installed fingerprint").map(|fingerprint| fingerprint.report(now));
        let integrity = self
            .readable(Files::read_optional(&self.config.custom_pif()), "custom.pif.prop")
            .map(|bytes| Fingerprint::parse(&String::from_utf8_lossy(&bytes)).report(now));
        let security_patch = self
            .readable(Files::read_optional(&self.config.security_patch()), "security_patch.txt")
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string());
        let targets = self.readable(self.targets(), "target.txt");
        let persisted_keys = self.persisted_keys().map(|keys| keys.len()).unwrap_or(0);
        let daemon = KeystoreDaemon::new(&self.layout).state();
        let boot_hook = BootHook::current(&self.layout);
        let state = self.store.state(&mut self.log);
        let settings = self.store.settings().unwrap_or_else(|error| {
            self.log.warning(format!("the saved settings cannot be read: {error}"));
            Settings::default()
        });
        let key_status = self.key_status_list(status_json);
        let outdated_keys = self.outdated_keys(&settings.key_removal, key_status.as_ref()).unwrap_or_default();
        let spoof = settings.spoof_flags(Engine::sdk()).values.iter().map(|(flag, value)| (flag.key().to_string(), *value)).collect();
        let missing_capabilities = Engine::missing_capabilities().unwrap_or_default().iter().map(Capability::to_string).collect();
        let strong_ready = components.iter().all(ComponentState::is_ready)
            && conflicts.is_empty()
            && keybox.as_ref().is_some_and(KeyboxVerdict::is_strong_capable)
            && fingerprint.as_ref().is_some_and(|report| report.problems.is_empty())
            && zygisk.as_ref().is_some_and(Zygisk::available);
        Ok(StatusReport {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            first_api_level: Engine::first_api_level(),
            root_managers,
            zygisk,
            components,
            conflicts,
            keybox,
            keybox_installed: state.keybox,
            fingerprint,
            fingerprint_installed: state.fingerprint,
            integrity,
            spoof,
            security_patch,
            targets,
            persisted_keys,
            outdated_keys,
            daemon,
            boot_hook,
            applied_at: state.applied_at,
            booted_at: state.booted_at,
            settings,
            missing_capabilities,
            strong_ready,
        })
    }

    /// The value of `result`, or `None` with a warning naming `what` when it could not be read.
    fn readable<T>(&mut self, result: Result<Option<T>, ReplayError>, what: &str) -> Option<T> {
        result.unwrap_or_else(|error| {
            self.log.warning(format!("{what} cannot be read: {error}"));
            None
        })
    }

    fn update_state(&mut self, change: impl FnOnce(&mut State)) -> Result<(), ReplayError> {
        let mut state = self.store.state(&mut self.log);
        change(&mut state);
        self.store.save(&state)
    }

    pub fn uid() -> u32 {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return rustix::process::geteuid().as_raw();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        return u32::MAX;
    }

    /// The capabilities of `Engine::CAPABILITIES` that the engine lacks.
    pub fn missing_capabilities() -> Result<Vec<Capability>, ReplayError> {
        let capabilities = ProcessCapabilities::current().map_err(|error| ReplayError::io("read the capabilities of the engine", error))?;
        Ok(Engine::CAPABILITIES.into_iter().filter(|capability| !capabilities.effective.contains(*capability)).collect())
    }

    /// Requires running as root (uid 0) with every capability in `Engine::CAPABILITIES`, which
    /// every operation that changes the system needs.
    pub fn require_root() -> Result<(), ReplayError> {
        let uid = Engine::uid();
        if uid != 0 {
            return Err(ReplayError::refused(format!("the engine must run as root (uid 0), not uid {uid}")));
        }
        let missing = Engine::missing_capabilities()?;
        if missing.is_empty() { Ok(()) } else { Err(ReplayError::Restricted(missing)) }
    }
}
