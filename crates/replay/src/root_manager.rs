use std::path::PathBuf;

use android::SystemCommand;
use serde::Serialize;

use crate::{Layout, Module, ReplayError};

/// A root manager that installs modules into `/data/adb/modules`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RootManager {
    Magisk,
    KernelSU,
    APatch,
}

/// Which Zygisk implementation can load the modules that need one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Zygisk {
    /// Whether the built-in Zygisk of Magisk is enabled; `None` when it cannot be asked.
    pub magisk_builtin: Option<bool>,
    /// The enabled modules that provide Zygisk, by module ID.
    pub modules: Vec<String>,
}

impl Zygisk {
    /// The module IDs of the standalone Zygisk implementations: Zygisk Next, ReZygisk, NeoZygisk.
    pub const MODULES: [&'static str; 3] = ["zygisksu", "rezygisk", "neozygisk"];

    pub fn available(&self) -> bool {
        self.magisk_builtin == Some(true) || !self.modules.is_empty()
    }
}

impl RootManager {
    pub const ALL: [RootManager; 3] = [RootManager::Magisk, RootManager::KernelSU, RootManager::APatch];

    /// A path that exists while the root manager is installed.
    pub fn marker(&self) -> &'static str {
        match self {
            RootManager::Magisk => "/data/adb/magisk",
            RootManager::KernelSU => "/data/adb/ksud",
            RootManager::APatch => "/data/adb/apd",
        }
    }

    /// The paths at which the command-line program of the root manager may be. Magisk keeps
    /// its binaries in `/data/adb/magisk` (`magisk`, or `magisk64`/`magisk32` before v26), and
    /// also mounts `magisk` into the path; KernelSU and APatch have one daemon program each.
    pub fn programs(&self) -> &'static [&'static str] {
        match self {
            RootManager::Magisk => &[
                "/data/adb/magisk/magisk",
                "/data/adb/magisk/magisk64",
                "/data/adb/magisk/magisk32",
                "/system/bin/magisk",
                "/debug_ramdisk/magisk",
                "/sbin/magisk",
            ],
            RootManager::KernelSU => &["/data/adb/ksud"],
            RootManager::APatch => &["/data/adb/apd"],
        }
    }

    /// The installed root managers. Leftovers of an earlier root manager may make several
    /// appear.
    pub fn installed(layout: &Layout) -> Vec<RootManager> {
        RootManager::ALL.into_iter().filter(|manager| std::fs::symlink_metadata(layout.path(manager.marker())).is_ok()).collect()
    }

    /// The one installed root manager. Several are refused, because installing a module with
    /// the wrong one would leave it uninstalled.
    pub fn single(layout: &Layout) -> Result<RootManager, ReplayError> {
        match RootManager::installed(layout).as_slice() {
            [manager] => Ok(*manager),
            [] => Err(ReplayError::refused("no supported root manager (Magisk, KernelSU, APatch) is installed")),
            several => Err(ReplayError::refused(format!(
                "several root managers appear to be installed ({}); remove the leftovers of the unused ones from /data/adb",
                several.iter().map(|manager| format!("{manager:?}")).collect::<Vec<_>>().join(", ")
            ))),
        }
    }

    pub fn program(&self, layout: &Layout) -> Option<PathBuf> {
        self.programs().iter().map(|path| layout.path(path)).find(|path| path.is_file())
    }

    /// The arguments that install a module zip: `magisk --install-module ZIP`,
    /// `ksud module install ZIP`, `apd module install ZIP`.
    pub fn install_arguments(&self, zip: &str) -> Vec<String> {
        match self {
            RootManager::Magisk => vec!["--install-module".to_string(), zip.to_string()],
            RootManager::KernelSU | RootManager::APatch => vec!["module".to_string(), "install".to_string(), zip.to_string()],
        }
    }

    /// Installs a module zip, which takes effect at the next boot. Returns the output of the
    /// root manager.
    pub fn install_module(&self, layout: &Layout, zip: &str) -> Result<String, ReplayError> {
        let program = self.program(layout).ok_or_else(|| ReplayError::refused(format!("the program of {self:?} was not found")))?;
        let program = program.to_string_lossy().into_owned();
        let arguments = self.install_arguments(zip);
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let output = SystemCommand::output(&program, &arguments)?;
        let text = format!("{}{}", output.stdout, output.stderr);
        if !output.success() {
            return Err(ReplayError::Command(android::CommandError::Failed {
                command: format!("{program} {}", arguments.join(" ")),
                status: output.status,
                output: text,
            }));
        }
        Ok(text)
    }

    /// Which Zygisk is available.
    pub fn zygisk(&self, layout: &Layout) -> Zygisk {
        let modules = Zygisk::MODULES.iter().filter(|id| Module::read(layout, id).is_some_and(|module| module.is_active())).map(|id| id.to_string()).collect();
        let magisk_builtin = match self {
            RootManager::Magisk => self.program(layout).and_then(|program| {
                let output = SystemCommand::output(&program.to_string_lossy(), &["--sqlite", "SELECT value FROM settings WHERE key='zygisk'"]).ok()?;
                // The setting is absent until it is changed once; its default is off.
                Some(output.stdout.lines().any(|line| line.trim() == "value=1"))
            }),
            RootManager::KernelSU | RootManager::APatch => Some(false),
        };
        Zygisk { magisk_builtin, modules }
    }
}
