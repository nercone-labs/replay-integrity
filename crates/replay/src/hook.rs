use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{Files, Layout, PackageWatcher, ReplayError, RootManager, Store, Target};

/// The boot scripts of a root manager that run the engine at every boot.
///
/// The early script runs the engine's `boot` before the Android framework starts: it removes
/// stale persisted keys and re-applies the spoof flags and the security patch with the saved
/// settings, before the keystore daemon starts and before any application attests. Magisk runs
/// it from `post-fs-data.d`, before it mounts its modules; KernelSU and APatch from
/// `post-mount.d`, after they mount theirs. Both are before the `service` stage, at which
/// TEESimulator-RS starts its daemon.
///
/// The service script, which is optional, starts the package watcher (`PackageWatcher`) at the
/// `service` stage, which every root manager runs from `service.d`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootHook {
    /// The installed root managers, for which a script would be installed.
    pub managers: Vec<RootManager>,
    /// The installed scripts.
    pub scripts: Vec<PathBuf>,
    /// Whether the service script, which starts the package watcher, is installed.
    pub watches: bool,
    /// The process ID of the running package watcher.
    pub watcher: Option<u32>,
}

impl RootManager {
    /// The directory of the early boot scripts of the root manager.
    pub fn hook_directory(&self, layout: &Layout) -> PathBuf {
        layout.path(match self {
            RootManager::Magisk => "/data/adb/post-fs-data.d",
            RootManager::KernelSU | RootManager::APatch => "/data/adb/post-mount.d",
        })
    }

    /// The directory of the scripts the root manager runs at the `service` stage; Magisk,
    /// KernelSU and APatch use the same one.
    pub fn service_directory(&self, layout: &Layout) -> PathBuf {
        layout.path("/data/adb/service.d")
    }
}

impl BootHook {
    pub const FILE_NAME: &'static str = "replay-integrity.sh";
    pub const SCRIPT_MODE: u32 = 0o755;
    pub const DIRECTORY_MODE: u32 = 0o755;

    /// The hook as it is installed now.
    pub fn current(layout: &Layout) -> BootHook {
        let scripts: Vec<PathBuf> = BootHook::candidates(layout).into_iter().filter(|path| path.is_file()).collect();
        let services = BootHook::service_candidates(layout);
        BootHook {
            managers: RootManager::installed(layout),
            watches: scripts.iter().any(|script| services.contains(script)),
            scripts,
            watcher: PackageWatcher::new(layout).running(),
        }
    }

    /// Every path at which an early script of this engine may have been installed.
    pub fn early_candidates(layout: &Layout) -> Vec<PathBuf> {
        BootHook::paths(RootManager::ALL.iter().map(|manager| manager.hook_directory(layout)))
    }

    /// Every path at which a service script of this engine may have been installed.
    pub fn service_candidates(layout: &Layout) -> Vec<PathBuf> {
        BootHook::paths(RootManager::ALL.iter().map(|manager| manager.service_directory(layout)))
    }

    /// Every path at which a script of this engine may have been installed.
    pub fn candidates(layout: &Layout) -> Vec<PathBuf> {
        let mut paths = BootHook::early_candidates(layout);
        paths.extend(BootHook::service_candidates(layout));
        paths
    }

    /// The script of this engine in each of `directories`, sorted and without duplicates.
    fn paths(directories: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = directories.map(|directory| directory.join(BootHook::FILE_NAME)).collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// The command that runs the store's copy of the engine with `arguments`, each quoted for
    /// the shell. `package` must be a package name, so that a script cannot carry anything else.
    fn command(layout: &Layout, package: &str, arguments: &[String]) -> Result<String, ReplayError> {
        if !Target::is_package_name(package) {
            return Err(ReplayError::refused(format!("\"{package}\" is not a package name")));
        }
        let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
        let mut words = vec![quote(&Store::new(layout).executable().to_string_lossy())];
        words.extend(arguments.iter().map(|argument| quote(argument)));
        Ok(words.join(" "))
    }

    /// The early script. It runs the copy of the engine in the store (`Store::executable`) with
    /// the `boot` command; `package` is the application, so that the engine can tell when the
    /// application was uninstalled and remove the hook.
    pub fn script(layout: &Layout, package: &str) -> Result<String, ReplayError> {
        let arguments = ["boot".to_string(), "--package".to_string(), package.to_string(), "--root".to_string(), layout.root.to_string_lossy().into_owned()];
        Ok(format!(
            "#!/system/bin/sh\n\
             # Replay Integrity removes stale attestation keys and re-applies its configuration here,\n\
             # before the keystore daemon and the Android framework start. It removes itself when\n\
             # Replay Integrity is uninstalled; deleting this file disables it.\n\
             {} >/dev/null 2>&1\n",
            BootHook::command(layout, package, &arguments)?,
        ))
    }

    /// The service script. It starts the package watcher in the background, so that the root
    /// manager never waits for it.
    pub fn service_script(layout: &Layout, package: &str) -> Result<String, ReplayError> {
        Ok(format!(
            "#!/system/bin/sh\n\
             # Replay Integrity adds applications installed while the system runs to the attestation\n\
             # targets from here. It removes itself when Replay Integrity is uninstalled; deleting this\n\
             # file disables it.\n\
             {} </dev/null >/dev/null 2>&1 &\n",
            BootHook::command(layout, package, &PackageWatcher::new(layout).arguments(package))?,
        ))
    }

    /// Copies the running engine (`executable`) into the store and installs, for every
    /// installed root manager, the early script and, when `watch` is set, the service script
    /// (which is removed otherwise). A watcher that runs an earlier copy of the engine, or that
    /// `watch` turns off, is ended; starting the current one is the caller's choice. Without a
    /// root manager that runs boot scripts, nothing is installed and the hook has no scripts.
    pub fn install(layout: &Layout, executable: &Path, package: &str, watch: bool) -> Result<BootHook, ReplayError> {
        let managers = RootManager::installed(layout);
        let script = BootHook::script(layout, package)?;
        let service_script = BootHook::service_script(layout, package)?;
        if managers.is_empty() {
            return Ok(BootHook::current(layout));
        }
        let replaced = Store::new(layout).install_executable(executable)?;
        if replaced || !watch {
            PackageWatcher::new(layout).stop()?;
        }
        for manager in &managers {
            let directory = manager.hook_directory(layout);
            Files::create_directory(&directory, BootHook::DIRECTORY_MODE)?;
            Files::write_if_changed(&directory.join(BootHook::FILE_NAME), script.as_bytes(), BootHook::SCRIPT_MODE)?;
            let services = manager.service_directory(layout);
            if watch {
                Files::create_directory(&services, BootHook::DIRECTORY_MODE)?;
                Files::write_if_changed(&services.join(BootHook::FILE_NAME), service_script.as_bytes(), BootHook::SCRIPT_MODE)?;
            } else {
                Files::remove(&services.join(BootHook::FILE_NAME))?;
            }
        }
        Ok(BootHook::current(layout))
    }

    /// Removes every script of this engine, ends the package watcher, and removes the copy of
    /// the engine the scripts run.
    pub fn remove(layout: &Layout) -> Result<BootHook, ReplayError> {
        for path in BootHook::candidates(layout) {
            Files::remove(&path)?;
        }
        PackageWatcher::new(layout).stop()?;
        Files::remove(&Store::new(layout).executable())?;
        Ok(BootHook::current(layout))
    }

    /// Whether a script of the hook is installed.
    pub fn is_installed(&self) -> bool {
        !self.scripts.is_empty()
    }
}
