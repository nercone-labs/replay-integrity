use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Component, Layout, PatchDate, ReplayError, SpoofFlag, SpoofFlags, Target, TargetMode};

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
}

/// The settings of the engine: what the user chose for the attestation targets and the spoof
/// flags. The application passes them with `--settings`, and `apply` saves a copy in the store,
/// so that the boot hook, which runs without the application, applies the same choices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Packages added to the attestation targets.
    pub extra_packages: Vec<String>,
    /// Installed packages left out of the attestation targets. The Play stack
    /// (`TargetList::ALWAYS`) cannot be left out.
    pub excluded_packages: Vec<String>,
    /// How TEESimulator-RS handles the keys of every target.
    pub target_mode: TargetMode,
    /// Overrides of the spoof flags, by their key.
    pub spoof_overrides: Vec<(String, bool)>,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { extra_packages: Vec::new(), excluded_packages: Vec::new(), target_mode: TargetMode::Auto, spoof_overrides: Vec::new() }
    }
}

impl Settings {
    /// Parses settings and checks them: every package must be a package name, so that nothing
    /// else can reach `target.txt`, and every override must name a known spoof flag.
    pub fn parse(bytes: &[u8]) -> Result<Settings, ReplayError> {
        let settings: Settings = serde_json::from_slice(bytes).map_err(|error| ReplayError::Rejected(vec![format!("invalid settings: {error}")]))?;
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
