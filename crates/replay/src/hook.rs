use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{Files, Layout, ReplayError, RootManager, Store, Target};

/// A boot script of a root manager that runs the engine's `boot` at every boot, before the
/// Android framework starts: it removes stale persisted keys and re-applies the spoof flags and
/// the security patch with the saved settings, before the keystore daemon starts and before any
/// application attests.
///
/// The scripts run at different stages. Magisk runs `post-fs-data.d` before it mounts its
/// modules; KernelSU and APatch run `post-mount.d` after they mount theirs. Both are before the
/// `service` stage, at which TEESimulator-RS starts its daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootHook {
    /// The installed root managers, for which a script would be installed.
    pub managers: Vec<RootManager>,
    /// The installed scripts.
    pub scripts: Vec<PathBuf>,
}

impl RootManager {
    /// The directory of boot scripts of the root manager.
    pub fn hook_directory(&self, layout: &Layout) -> PathBuf {
        layout.path(match self {
            RootManager::Magisk => "/data/adb/post-fs-data.d",
            RootManager::KernelSU | RootManager::APatch => "/data/adb/post-mount.d",
        })
    }
}

impl BootHook {
    pub const FILE_NAME: &'static str = "replay-integrity.sh";
    pub const SCRIPT_MODE: u32 = 0o755;
    pub const DIRECTORY_MODE: u32 = 0o755;

    /// The hook as it is installed now.
    pub fn current(layout: &Layout) -> BootHook {
        BootHook { managers: RootManager::installed(layout), scripts: BootHook::candidates(layout).into_iter().filter(|path| path.is_file()).collect() }
    }

    /// Every path at which a script of this engine may have been installed.
    pub fn candidates(layout: &Layout) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = RootManager::ALL.iter().map(|manager| manager.hook_directory(layout).join(BootHook::FILE_NAME)).collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// The script. It runs the copy of the engine in the store (`Store::executable`) with the
    /// `boot` command; `package` is the application, so that the engine can tell when the
    /// application was uninstalled and remove the hook.
    pub fn script(layout: &Layout, package: &str) -> Result<String, ReplayError> {
        if !Target::is_package_name(package) {
            return Err(ReplayError::refused(format!("\"{package}\" is not a package name")));
        }
        let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
        let executable = Store::new(layout).executable();
        Ok(format!(
            "#!/system/bin/sh\n\
             # Replay Integrity removes stale attestation keys and re-applies its configuration here,\n\
             # before the keystore daemon and the Android framework start. It removes itself when\n\
             # Replay Integrity is uninstalled; deleting this file disables it.\n\
             {} boot --package {} --root {} >/dev/null 2>&1\n",
            quote(&executable.to_string_lossy()),
            quote(package),
            quote(&layout.root.to_string_lossy()),
        ))
    }

    /// Copies the running engine (`executable`) into the store and installs a script for every
    /// installed root manager. Without a root manager that runs boot scripts, nothing is
    /// installed and the returned hook has no scripts.
    pub fn install(layout: &Layout, executable: &Path, package: &str) -> Result<BootHook, ReplayError> {
        let managers = RootManager::installed(layout);
        let script = BootHook::script(layout, package)?;
        if managers.is_empty() {
            return Ok(BootHook::current(layout));
        }
        Store::new(layout).install_executable(executable)?;
        for manager in &managers {
            let directory = manager.hook_directory(layout);
            Files::create_directory(&directory, BootHook::DIRECTORY_MODE)?;
            Files::write_atomic(&directory.join(BootHook::FILE_NAME), script.as_bytes(), BootHook::SCRIPT_MODE)?;
        }
        Ok(BootHook::current(layout))
    }

    /// Removes every script of this engine and the copy of the engine they run.
    pub fn remove(layout: &Layout) -> Result<BootHook, ReplayError> {
        for path in BootHook::candidates(layout) {
            Files::remove(&path)?;
        }
        Files::remove(&Store::new(layout).executable())?;
        Ok(BootHook::current(layout))
    }

    pub fn is_installed(&self) -> bool {
        !self.scripts.is_empty()
    }
}
