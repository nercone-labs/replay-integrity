use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use android::{ControlGroup, ProcessInfo};
use serde::Serialize;

use crate::{Layout, ReplayError, Store};

/// The process that keeps `target.txt` current while the system runs: it waits for the package
/// manager to rewrite `/data/system/packages.list`, which it does whenever a package is
/// installed, updated or removed, and then rebuilds `target.txt` with the saved settings. An
/// application installed after the last refresh is then attested at once, not hours later.
///
/// It runs the copy of the engine in the store (`Store::executable`) as
/// `replay-integrity watch --package <application>`, started by the service script of the boot hook at
/// every boot and by `hook install` when it is not running. One runs at a time: it holds an
/// exclusive lock on `watch.lock` in the store, whose contents are its process ID. It ends when
/// the application is uninstalled (removing the boot hook) and when the boot hook is removed.
pub struct PackageWatcher {
    pub layout: Layout,
    /// How long to wait after a change before rebuilding: an installation rewrites the package
    /// list more than once, and the writes of one installation then cause one rebuild.
    pub settle: Duration,
    /// How often to check whether the system has finished booting; the package manager answers
    /// only then.
    pub boot_poll: Duration,
}

/// Why `watch` ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum WatchReport {
    /// Another watcher holds the lock.
    AlreadyRunning { pid: Option<u32> },
    /// The application is uninstalled: the boot hook was removed.
    Uninstalled,
    /// The boot hook was removed, which turns the watcher off.
    Stopped,
}

impl PackageWatcher {
    pub const LOCK: &'static str = "watch.lock";
    /// The engine command that runs the watcher.
    pub const COMMAND: &'static str = "watch";
    pub const DEFAULT_SETTLE: Duration = Duration::from_secs(3);
    pub const DEFAULT_BOOT_POLL: Duration = Duration::from_secs(5);
    /// How long `stop` waits for an ended watcher to release its lock.
    pub const STOP_TIMEOUT: Duration = Duration::from_secs(3);
    pub const STOP_POLL: Duration = Duration::from_millis(50);

    pub fn new(layout: &Layout) -> PackageWatcher {
        PackageWatcher { layout: layout.clone(), settle: PackageWatcher::DEFAULT_SETTLE, boot_poll: PackageWatcher::DEFAULT_BOOT_POLL }
    }

    pub fn lock_path(&self) -> PathBuf {
        Store::new(&self.layout).directory.join(PackageWatcher::LOCK)
    }

    /// The arguments that run the watcher for `package`, after the executable.
    pub fn arguments(&self, package: &str) -> Vec<String> {
        vec![
            PackageWatcher::COMMAND.to_string(),
            "--package".to_string(),
            package.to_string(),
            "--root".to_string(),
            self.layout.root.to_string_lossy().into_owned(),
        ]
    }

    /// Whether `arguments` (of `/proc/<pid>/cmdline`) are those of a watcher of this store:
    /// the store's copy of the engine running `watch`, under its name or one an earlier version
    /// gave it (a watcher started before an update still runs that copy). A process ID read from
    /// the lock file may have been reused by another process, which this tells apart.
    pub fn is_watcher(&self, arguments: &[String]) -> bool {
        let store = Store::new(&self.layout);
        let mut executables = store.legacy_executables();
        executables.push(store.executable());
        arguments.first().is_some_and(|first| executables.iter().any(|executable| std::path::Path::new(first) == executable))
            && arguments.get(1).is_some_and(|second| second == PackageWatcher::COMMAND)
    }

    /// Whether the watcher `pid` runs another file than the copy of the engine in the store now:
    /// a copy that was replaced since it started (by an update), or one of an earlier name. Its
    /// `/proc/<pid>/exe` still leads to the file it was started from, even once that file was
    /// replaced or removed. `false` when either cannot be read.
    pub fn is_outdated(&self, pid: u32) -> bool {
        use std::os::unix::fs::MetadataExt;
        let running = std::fs::metadata(format!("/proc/{pid}/exe"));
        let current = std::fs::metadata(Store::new(&self.layout).executable());
        match (running, current) {
            (Ok(running), Ok(current)) => (running.dev(), running.ino()) != (current.dev(), current.ino()),
            _ => false,
        }
    }

    /// The process ID of the running watcher, if one runs. The lock is not touched, so asking
    /// never makes a starting watcher think that another one runs.
    pub fn running(&self) -> Option<u32> {
        let mut text = String::new();
        File::open(self.lock_path()).ok()?.read_to_string(&mut text).ok()?;
        let pid: u32 = text.trim().parse().ok()?;
        ProcessInfo::arguments(pid).is_some_and(|arguments| self.is_watcher(&arguments)).then_some(pid)
    }

    /// Takes the lock for this process and writes its process ID into it. `None` when another
    /// process holds it. The lock is held until the returned file is closed, which the kernel
    /// does when the process ends, however it ends.
    pub fn lock(&self) -> Result<Option<File>, ReplayError> {
        let path = self.lock_path();
        Store::new(&self.layout).create()?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(Store::FILE_MODE)
            .open(&path)
            .map_err(|error| ReplayError::io_at("open", &path, error))?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => return Ok(None),
            Err(error) => return Err(ReplayError::io_at("lock", &path, error.into())),
        }
        let pid = std::process::id().to_string();
        let written = (|| -> io::Result<()> {
            file.set_len(0)?;
            file.rewind()?;
            file.write_all(pid.as_bytes())?;
            file.sync_all()
        })();
        written.map_err(|error| ReplayError::io_at("write", &path, error))?;
        Ok(Some(file))
    }

    /// Starts a watcher for `package` with the store's copy of the engine, unless one runs.
    /// It makes a session of its own (`detach`), so that it outlives the command that started it.
    /// Returns whether one was started.
    pub fn start(&self, package: &str) -> Result<bool, ReplayError> {
        if self.running().is_some() {
            return Ok(false);
        }
        let executable = Store::new(&self.layout).executable();
        Command::new(&executable)
            .args(self.arguments(package))
            .current_dir("/")
            // No process group of its own here: `detach` makes a session, which `setsid` refuses
            // to a process-group leader (EPERM), and a session gives it a group of its own anyway.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| ReplayError::io_at("start", &executable, error))?;
        Ok(true)
    }

    /// Ends the running watcher, unless it is this process, and waits up to `STOP_TIMEOUT`
    /// until it has ended, so that a watcher started right after can take the lock. An ended
    /// process releases its lock and its command line becomes empty before it is reaped, so
    /// `running` stops naming it at that point. Returns whether one was ended.
    pub fn stop(&self) -> Result<bool, ReplayError> {
        let Some(pid) = self.running() else { return Ok(false) };
        if pid == std::process::id() {
            return Ok(false);
        }
        let process = ProcessInfo { pid, name: Store::new(&self.layout).executable().to_string_lossy().into_owned() };
        match process.kill() {
            Ok(()) => {}
            // It ended between reading its ID and the signal.
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) => return Ok(false),
            Err(error) => return Err(ReplayError::io(format!("end the package watcher {pid}"), error)),
        }
        let started = std::time::Instant::now();
        while self.running() == Some(pid) {
            if started.elapsed() > PackageWatcher::STOP_TIMEOUT {
                return Err(ReplayError::refused(format!("the package watcher {pid} did not end within {} seconds", PackageWatcher::STOP_TIMEOUT.as_secs())));
            }
            std::thread::sleep(PackageWatcher::STOP_POLL);
        }
        Ok(true)
    }

    /// Moves this process out of the cgroups of the process that started it, into the root
    /// groups, and into a session of its own. A watcher started by the application through an
    /// `su` that does not leave the application's cgroup would otherwise end when the system
    /// ends the application, which it does by its cgroup. Best effort: a hierarchy that is
    /// absent or refuses the move is skipped, and the watcher still runs until then.
    pub fn detach(&self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let _ = rustix::process::setsid();
        ControlGroup::move_to_roots(&self.layout.root);
    }
}
