use std::path::PathBuf;

use serde::Serialize;

use crate::{Files, Layout, ReplayError, RootManager};

/// A boot script of a root manager that runs the engine's `repair` at every boot, before the
/// Android framework starts, so that a keybox revoked or expired while the device was off is
/// replaced and the keystore daemon reloaded before any application attests.
///
/// The scripts installed by the root managers run at different stages. Magisk runs
/// `post-fs-data.d` before it mounts its modules; KernelSU and APatch run `post-mount.d` after
/// they mount theirs, the stage used there so the module files the engine needs are in place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootHook {
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

    /// The script. It runs the engine, in the native library directory of the application, with
    /// the `repair --boot` command. The path of the engine is written at installation, so that
    /// the script keeps working when the application is updated only if the path is stable; the
    /// application reinstalls the hook after each update to refresh it.
    pub fn script(executable: &str, store: &Layout) -> String {
        let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
        format!(
            "#!/system/bin/sh\n\
             # Replay Integrity re-checks the keybox and reloads the keystore here, before the\n\
             # Android framework starts, so a keybox revoked or expired while the device was off\n\
             # is replaced before any application attests. It is removed with the application;\n\
             # deleting this file disables it.\n\
             {} repair --boot --root {} >/dev/null 2>&1\n",
            quote(executable),
            quote(&store.root.to_string_lossy()),
        )
    }

    /// Installs a script for every installed root manager. Without a root manager that runs
    /// boot scripts, nothing is installed and the returned hook has no scripts.
    pub fn install(layout: &Layout, executable: &str) -> Result<BootHook, ReplayError> {
        let managers = RootManager::installed(layout);
        let script = BootHook::script(executable, layout);
        for manager in &managers {
            let directory = manager.hook_directory(layout);
            Files::create_directory(&directory, BootHook::DIRECTORY_MODE)?;
            Files::write_atomic(&directory.join(BootHook::FILE_NAME), script.as_bytes(), BootHook::SCRIPT_MODE)?;
        }
        Ok(BootHook::current(layout))
    }

    /// Removes every script of this engine.
    pub fn remove(layout: &Layout) -> Result<BootHook, ReplayError> {
        for path in BootHook::candidates(layout) {
            Files::remove(&path)?;
        }
        Ok(BootHook::current(layout))
    }

    pub fn is_installed(&self) -> bool {
        !self.scripts.is_empty()
    }
}
