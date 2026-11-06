use serde::Serialize;

use crate::{Files, Layout, Module, ReplayError};

/// A module that Replay Integrity configures, and how it is recognized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Component {
    /// TEESimulator-RS: simulates key attestation from the keybox, in module `tricky_store`.
    Keystore,
    /// PlayIntegrityFork: spoofs the build of Google Play services, in module `playintegrityfix`.
    Integrity,
}

/// How an installed module of a component's ID relates to the supported module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Flavor {
    /// The supported module.
    Supported,
    /// Another module with the same ID, which reads other files or patches the supported one.
    Other,
}

/// The state of a component on the device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentState {
    pub component: Component,
    pub module: Option<Module>,
    pub flavor: Option<Flavor>,
}

impl Component {
    pub const ALL: [Component; 2] = [Component::Keystore, Component::Integrity];

    pub fn module_id(&self) -> &'static str {
        match self {
            Component::Keystore => "tricky_store",
            Component::Integrity => "playintegrityfix",
        }
    }

    /// The `name` of `module.prop` of the supported module.
    pub fn module_name(&self) -> &'static str {
        match self {
            Component::Keystore => "TEESimulator-RS",
            Component::Integrity => "Play Integrity Fork",
        }
    }

    /// The GitHub repository whose releases hold the supported module.
    pub fn repository(&self) -> &'static str {
        match self {
            Component::Keystore => "Enginex0/TEESimulator-RS",
            Component::Integrity => "osm0sis/PlayIntegrityFork",
        }
    }

    /// Recognizes the supported module by its name, exactly: other modules share these IDs
    /// (TrickyStore, TrickyStoreOSS and AlwaysStrong use `tricky_store`; PlayIntegrityFix uses
    /// `playintegrityfix`) but read other files or are patched, so they are not assumed to work.
    pub fn flavor(&self, module: &Module) -> Flavor {
        if module.name.as_deref() == Some(self.module_name()) { Flavor::Supported } else { Flavor::Other }
    }

    pub fn state(&self, layout: &Layout) -> ComponentState {
        let module = Module::read(layout, self.module_id());
        let flavor = module.as_ref().map(|module| self.flavor(module));
        ComponentState { component: *self, module, flavor }
    }
}

impl ComponentState {
    /// Whether the supported module is installed and active, possibly waiting for a reboot.
    pub fn is_ready(&self) -> bool {
        self.flavor == Some(Flavor::Supported) && self.module.as_ref().is_some_and(Module::is_active)
    }

    /// Whether the module is active since the last boot, without a pending change.
    pub fn is_running(&self) -> bool {
        self.is_ready() && self.module.as_ref().is_some_and(|module| module.installed && !module.update_pending)
    }
}

/// Modules that change the same things as the components and break their results: other
/// keystore simulators, other Play Integrity fixes, and tools that rewrite the configuration of
/// TEESimulator-RS. This list follows the one AlwaysStrong removes at installation.
pub struct Conflicts;

impl Conflicts {
    pub const MODULES: [&'static str; 21] = [
        "tricky_store_v2",
        "TrickyStore",
        "tee_simulator",
        "TEESimulator",
        "TEESimulator-RS",
        "teesim",
        "safetynet-fix",
        "Universal_SafetyNet_Fix",
        "MagiskHidePropsConf",
        "TA_utl",
        "tricky_addon",
        "TA_enhanced",
        "tsupport-advance",
        "Yurikey",
        "specter",
        "playintegrityfork",
        "play_integrity_fix",
        "playcurl",
        "playcurlNEXT",
        "pif_strong",
        "pif_force",
    ];

    /// The conflicting modules that will run after the next boot.
    pub fn active(layout: &Layout) -> Vec<Module> {
        Conflicts::MODULES.iter().filter_map(|id| Module::read(layout, id)).filter(Module::is_active).collect()
    }

    pub fn is_conflict(id: &str) -> bool {
        Conflicts::MODULES.contains(&id)
    }

    /// Disables every active conflicting module with the `disable` marker of the root managers,
    /// which takes effect at the next boot. The marker is written to the installed module and to
    /// a pending update of it, because the update replaces the installed directory at the next
    /// boot. Disabling is chosen over removal (AlwaysStrong marks them for removal) because the
    /// user can enable the module again in the root manager, and its files and settings stay.
    /// Returns the modules as they are afterwards.
    pub fn disable(layout: &Layout) -> Result<Vec<Module>, ReplayError> {
        let mut disabled = Vec::new();
        for module in Conflicts::active(layout) {
            for directory in [layout.modules().join(&module.id), layout.modules_update().join(&module.id)] {
                if directory.join(Module::PROP).is_file() {
                    Files::write_atomic(&directory.join(Module::DISABLE), b"", Module::MARKER_MODE)?;
                }
            }
            disabled.extend(Module::read(layout, &module.id));
        }
        Ok(disabled)
    }
}
