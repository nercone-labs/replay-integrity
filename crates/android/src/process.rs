use std::fs;
use std::io;
use std::path::Path;

/// A running process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    /// The first command-line argument. Android application processes set it to their
    /// process name: the package name, optionally followed by `:<name>`.
    pub name: String,
}

impl ProcessInfo {
    pub const SYSTEM_SERVER: &'static str = "system_server";

    /// Reads the process with `pid`, or `None` if it no longer exists.
    pub fn of(pid: u32) -> Option<ProcessInfo> {
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        Some(ProcessInfo { pid, name: ProcessInfo::name_of(&cmdline) })
    }

    /// The first argument of a NUL-separated command line, without trailing padding.
    pub fn name_of(cmdline: &[u8]) -> String {
        let end = cmdline.iter().position(|byte| *byte == 0).unwrap_or(cmdline.len());
        String::from_utf8_lossy(&cmdline[..end]).trim_end().to_string()
    }

    /// Whether this process belongs to `package` (its name is the package, or `package:<suffix>`).
    pub fn belongs_to(&self, package: &str) -> bool {
        self.name == package || self.name.strip_prefix(package).is_some_and(|rest| rest.starts_with(':'))
    }

    /// The path of the executable file of the process with `pid`, or `None` if it is gone or
    /// cannot be read.
    pub fn executable(pid: u32) -> Option<std::path::PathBuf> {
        fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    pub fn is_alive(&self) -> bool {
        ProcessInfo::of(self.pid).is_some_and(|current| current.name == self.name)
    }

    /// Sends SIGKILL, as the low-memory killer does. The system restarts persistent
    /// processes such as SystemUI, and the activity that was in front, by itself.
    pub fn kill(&self) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let pid = rustix::process::Pid::from_raw(self.pid as i32).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process ID"))?;
            Ok(rustix::process::kill_process(pid, rustix::process::Signal::KILL)?)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        Err(io::Error::new(io::ErrorKind::Unsupported, "signals require Linux"))
    }
}

/// The processes listed in `/proc`.
pub struct ProcessTable;

impl ProcessTable {
    pub fn list() -> io::Result<Vec<ProcessInfo>> {
        ProcessTable::list_in(Path::new("/proc"))
    }

    pub fn list_in(proc: &Path) -> io::Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        for entry in fs::read_dir(proc)? {
            let entry = entry?;
            let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue };
            if let Ok(cmdline) = fs::read(entry.path().join("cmdline")) {
                processes.push(ProcessInfo { pid, name: ProcessInfo::name_of(&cmdline) });
            }
        }
        Ok(processes)
    }

    /// The processes whose name is exactly `name`.
    pub fn named(name: &str) -> io::Result<Vec<ProcessInfo>> {
        Ok(ProcessTable::list()?.into_iter().filter(|process| process.name == name).collect())
    }

    /// Every process of `package`.
    pub fn of_package(package: &str) -> io::Result<Vec<ProcessInfo>> {
        Ok(ProcessTable::list()?.into_iter().filter(|process| process.belongs_to(package)).collect())
    }
}
