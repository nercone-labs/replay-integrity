use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Component, KeyCategory, Layout, PatchDate, ReplayError, SpoofFlag, SpoofFlags, Target, TargetMode};

/// The files of TEESimulator-RS and PlayIntegrityFork that the engine writes, under
/// `/data/adb/tricky_store` and in the module directories.
pub struct KeystoreConfig {
    pub layout: Layout,
}

impl KeystoreConfig {
    pub const KEYBOX: &'static str = "keybox.xml";
    pub const TARGET: &'static str = "target.txt";
    pub const SECURITY_PATCH: &'static str = "security_patch.txt";
    /// The file PlayIntegrityFork reads for the spoofed build (its `custom.pif.prop`).
    pub const CUSTOM_PIF: &'static str = "custom.pif.prop";
    /// The file this engine keeps the installed fingerprint in, inside its own store.
    pub const FINGERPRINT: &'static str = "fingerprint.prop";
    pub const KEYBOX_MODE: u32 = 0o600;
    pub const CONFIG_MODE: u32 = 0o644;

    pub fn new(layout: &Layout) -> KeystoreConfig {
        KeystoreConfig { layout: layout.clone() }
    }

    pub fn keybox(&self) -> PathBuf {
        self.layout.tricky_store().join(KeystoreConfig::KEYBOX)
    }

    pub fn target(&self) -> PathBuf {
        self.layout.tricky_store().join(KeystoreConfig::TARGET)
    }

    pub fn security_patch(&self) -> PathBuf {
        self.layout.tricky_store().join(KeystoreConfig::SECURITY_PATCH)
    }

    /// The directory this engine keeps the installed fingerprint in: its own store.
    pub fn fingerprint_directory(&self) -> PathBuf {
        self.layout.store()
    }

    pub fn fingerprint_path(&self) -> PathBuf {
        self.fingerprint_directory().join(KeystoreConfig::FINGERPRINT)
    }

    /// The `custom.pif.prop` of the installed PlayIntegrityFork module, where its zygisk reads
    /// the spoofed build; `None` when the module is not installed.
    pub fn custom_pif(&self) -> PathBuf {
        self.layout.modules().join(Component::Integrity.module_id()).join(KeystoreConfig::CUSTOM_PIF)
    }

    /// `security_patch.txt` in the form TEESimulator-RS reads: `system=`, `vendor=` and `boot=`
    /// set to the fingerprint's own patch date, so the patch level in attestation matches the
    /// claimed build. Dotted dates (`YYYY-MM-DD`) are accepted for every component.
    pub fn security_patch_contents(patch: PatchDate) -> String {
        format!("system={patch}\nvendor={patch}\nboot={patch}\n")
    }

    /// The patch of `contents` when it is exactly `security_patch_contents` of a patch: the
    /// inverse of `security_patch_contents`. `None` for any other contents (per-package
    /// sections, `prop`, keywords, components with different dates), whose patch levels
    /// TEESimulator-RS resolves in ways this engine does not reproduce.
    pub fn security_patch_of(contents: &str) -> Option<PatchDate> {
        let first = contents.lines().next()?;
        let patch = PatchDate::parse(first.strip_prefix("system=")?)?;
        (contents == KeystoreConfig::security_patch_contents(patch)).then_some(patch)
    }
}

/// Which installed applications are attestation targets besides the Play stack, which always
/// is one (`TargetList::build`). Packages the user adds are targets whatever the scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TargetScope {
    /// The Play stack only: Play Integrity is all that is attested.
    Play,
    /// The Play stack and the installed wallet applications (`TargetList::WALLET`).
    PlayAndWallets,
    /// The Play stack, the installed wallet applications and every third-party application,
    /// so that applications that check key attestation themselves pass as well.
    AllApplications,
}

/// When a persisted key whose chain was signed by a key that is no longer in the keybox is
/// removed, so that its application makes it again with the current keybox
/// (`OutdatedKey::is_removed_by`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyRemoval {
    /// Never: the key is reported, and only the user removes it (`Engine::remove_key`).
    Never,
    /// When the chain the key was attested with is known to be no longer valid: revoked,
    /// expired or untrusted. Until then the key keeps passing attestation, and what the user
    /// enrolled with it is kept.
    WhenUnusable,
    /// As soon as the keybox that attested it is replaced, before that keybox can be revoked.
    WhenReplaced,
}

/// Which outdated persisted keys a repair removes, for each kind of key (`KeyCategory`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KeyRemovalSettings {
    /// The key of the Play Integrity API (`KeyCategory::Integrity`). It holds nothing of the
    /// user's, and a key on an old keybox fails Play Integrity, so it is removed as soon as its
    /// keybox is replaced by default.
    pub integrity: KeyRemoval,
    /// The other keys of the Play stack (`KeyCategory::Play`): tap-and-pay cards, passkeys and
    /// the like, which are lost with the key. Kept by default.
    pub play: KeyRemoval,
    /// The keys of every other application (`KeyCategory::Application`): a banking or wallet
    /// application's enrolment, which is lost with the key. Kept by default.
    pub applications: KeyRemoval,
    /// Whether the key of the Play Integrity API is removed when it attests a security patch
    /// other than the configured one (`OutdatedReason::OldPatch`).
    pub integrity_patch: bool,
}

impl Default for KeyRemovalSettings {
    fn default() -> KeyRemovalSettings {
        KeyRemovalSettings { integrity: KeyRemoval::WhenReplaced, play: KeyRemoval::Never, applications: KeyRemoval::Never, integrity_patch: true }
    }
}

impl KeyRemovalSettings {
    /// The removal of the keys of `category`.
    pub fn of(&self, category: KeyCategory) -> KeyRemoval {
        match category {
            KeyCategory::Integrity => self.integrity,
            KeyCategory::Play => self.play,
            KeyCategory::Application => self.applications,
        }
    }
}

/// The settings of the engine: what the user chose for the attestation targets, the spoof
/// flags, the removal of outdated keys and the restarts. The application passes them with
/// `--settings`, and `apply` saves a copy in the store, so that the boot hook, which runs
/// without the application, applies the same choices.
///
/// The defaults are the safe choices that still reach STRONG: they never remove a key that may
/// hold what the user enrolled, and never end applications that Play Integrity does not need
/// ended. Each one can be changed towards integrity or towards safety.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Packages added to the attestation targets.
    pub extra_packages: Vec<String>,
    /// Installed packages left out of the attestation targets. The Play stack
    /// (`TargetList::ALWAYS`) cannot be left out.
    pub excluded_packages: Vec<String>,
    /// Which installed applications are targets besides the Play stack.
    pub target_scope: TargetScope,
    /// How TEESimulator-RS handles the keys of every target but the Play stack.
    pub target_mode: TargetMode,
    /// How TEESimulator-RS handles the keys of the Play stack (`TargetList::ALWAYS`).
    /// `Generate` by default: Play Integrity then always gets a key attested with the keybox,
    /// never one of the device's own keystore patched, which fails when that keystore does.
    pub play_target_mode: TargetMode,
    /// Overrides of the spoof flags, by their key.
    pub spoof_overrides: Vec<(String, bool)>,
    /// Which outdated persisted keys a repair removes.
    pub key_removal: KeyRemovalSettings,
    /// Whether a restart also ends every background application (`ActivityManager::kill_background`),
    /// besides the Play processes that Play Integrity needs restarted (`REFRESH_PROCESSES`).
    pub end_background_applications: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            extra_packages: Vec::new(),
            excluded_packages: Vec::new(),
            target_scope: TargetScope::AllApplications,
            target_mode: TargetMode::Auto,
            play_target_mode: TargetMode::Generate,
            spoof_overrides: Vec::new(),
            key_removal: KeyRemovalSettings::default(),
            end_background_applications: false,
        }
    }
}

impl Settings {
    /// Parses settings and checks them: every package must be a package name, so that nothing
    /// else can reach `target.txt`, and every override must name a known spoof flag.
    ///
    /// Settings written before `play_target_mode` existed gave the Play stack `target_mode`. When
    /// the field is missing and that mode was not `Auto`, the user chose it on purpose, so the
    /// Play stack keeps it; otherwise it gets the default, `Generate`.
    pub fn parse(bytes: &[u8]) -> Result<Settings, ReplayError> {
        let invalid = |error: serde_json::Error| ReplayError::Rejected(vec![format!("invalid settings: {error}")]);
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(invalid)?;
        let has_play_mode = value.get("playTargetMode").is_some();
        let mut settings: Settings = serde_json::from_value(value).map_err(invalid)?;
        if !has_play_mode && settings.target_mode != TargetMode::Auto {
            settings.play_target_mode = settings.target_mode;
        }
        let problems = settings.problems();
        if problems.is_empty() { Ok(settings) } else { Err(ReplayError::Rejected(problems)) }
    }

    /// Every reason why the settings are not acceptable.
    pub fn problems(&self) -> Vec<String> {
        let packages = self.extra_packages.iter().chain(&self.excluded_packages);
        let mut problems: Vec<String> =
            packages.filter(|package| !Target::is_package_name(package)).map(|package| format!("\"{package}\" is not a package name")).collect();
        problems
            .extend(self.spoof_overrides.iter().filter(|(key, _)| SpoofFlag::from_key(key).is_none()).map(|(key, _)| format!("\"{key}\" is not a spoof flag")));
        problems
    }

    /// The spoof flags: the recommended values for `sdk`, with the user's overrides applied.
    pub fn spoof_flags(&self, sdk: Option<u32>) -> SpoofFlags {
        let mut flags = SpoofFlags::recommended(sdk);
        for (key, value) in &self.spoof_overrides {
            if let Some(flag) = SpoofFlag::from_key(key) {
                flags.set(flag, *value);
            }
        }
        flags
    }
}
