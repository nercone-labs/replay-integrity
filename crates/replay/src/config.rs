use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Component, Fingerprint, Layout, PatchDate, SpoofFlags};

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

/// The settings the engine keeps for itself, written by the application through the engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Whether the keybox is refreshed automatically; off when the user keeps their own.
    pub auto_keybox: bool,
    /// Whether the fingerprint is refreshed automatically; off when the user keeps their own.
    pub auto_fingerprint: bool,
    /// Extra packages the user added to the attestation targets.
    pub extra_packages: Vec<String>,
    /// Overrides of the spoof flags, by their key.
    pub spoof_overrides: Vec<(String, bool)>,
    /// Whether the boot hook is installed.
    pub boot_hook: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { auto_keybox: true, auto_fingerprint: true, extra_packages: Vec::new(), spoof_overrides: Vec::new(), boot_hook: true }
    }
}

impl Settings {
    /// The spoof flags: the recommended values for `sdk`, with the user's overrides applied.
    pub fn spoof_flags(&self, sdk: Option<u32>) -> SpoofFlags {
        let mut flags = SpoofFlags::recommended(sdk);
        for (key, value) in &self.spoof_overrides {
            if let Some(flag) = crate::SpoofFlag::from_key(key) {
                flags.set(flag, *value);
            }
        }
        flags
    }
}

/// Applies the spoof flags and the security patch of `fingerprint` and returns the file to
/// write for PlayIntegrityFork.
pub fn fingerprint_for_integrity(fingerprint: &Fingerprint, spoof: &SpoofFlags) -> Fingerprint {
    fingerprint.with_settings(spoof)
}
