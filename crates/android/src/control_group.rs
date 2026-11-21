use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The control groups (cgroups) of processes, as far as Android uses them to manage
/// applications.
///
/// Android keeps a group for every application process (`uid_<uid>/pid_<pid>`). It freezes the
/// group while the application is cached, and ends every process of the group with the
/// application (`killProcessGroup` of libprocessgroup). A process an application starts stays in
/// that group, even once it runs as root: `su` of KernelSU and APatch raises the calling process
/// itself, unlike that of Magisk, whose daemon starts the root process. Such a process is frozen
/// and ended with the application unless it leaves the group.
pub struct ControlGroup;

impl ControlGroup {
    /// The roots of the hierarchies in which Android keeps the groups of application processes:
    /// the unified hierarchy (cgroup v2), and the `cpuacct` hierarchy of earlier releases.
    pub const APPLICATION_ROOTS: [&'static str; 2] = ["/sys/fs/cgroup", "/acct"];

    /// The paths of the groups in a `/proc/<pid>/cgroup` file, one for each hierarchy
    /// (`<id>:<controllers>:<path>`).
    pub fn paths_of(text: &str) -> Vec<String> {
        text.lines().filter_map(|line| line.splitn(3, ':').nth(2)).map(str::to_string).collect()
    }

    /// The first application ID: the IDs below it, in every user, belong to the system.
    pub const FIRST_APPLICATION_UID: u32 = 10000;
    /// The range of IDs of each user: the ID of a process is `user * PER_USER_RANGE + app ID`.
    pub const PER_USER_RANGE: u32 = 100000;

    /// Whether `path` is the group of an application process: it holds `uid_<uid>` followed by
    /// `pid_<pid>`, and `uid` is that of an application of any user. libprocessgroup makes the
    /// same groups for processes of the system (`uid_0/pid_<pid>`), which are not applications.
    pub fn is_application(path: &str) -> bool {
        let number = |component: &str, prefix: &str| -> Option<u32> {
            component.strip_prefix(prefix).filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))?.parse().ok()
        };
        let components: Vec<&str> = path.split('/').collect();
        components.windows(2).any(|pair| {
            number(pair[0], "uid_").is_some_and(|uid| uid % ControlGroup::PER_USER_RANGE >= ControlGroup::FIRST_APPLICATION_UID)
                && number(pair[1], "pid_").is_some()
        })
    }

    /// The paths of the groups of the calling process, or none when they cannot be read.
    pub fn current() -> Vec<String> {
        fs::read_to_string("/proc/self/cgroup").map(|text| ControlGroup::paths_of(&text)).unwrap_or_default()
    }

    /// Moves the calling process into the root group of each hierarchy of `APPLICATION_ROOTS`
    /// under `base` (`/` on a device). Best effort: a hierarchy that is not mounted (no
    /// `cgroup.procs`, which is never created here), or that refuses the move (without the
    /// privilege to make it), is skipped. Returns the roots it was moved into.
    pub fn move_to_roots(base: &Path) -> Vec<PathBuf> {
        let pid = std::process::id().to_string();
        ControlGroup::APPLICATION_ROOTS
            .iter()
            .map(|root| base.join(root.trim_start_matches('/')))
            .filter(|root| OpenOptions::new().write(true).open(root.join("cgroup.procs")).and_then(|mut file| file.write_all(pid.as_bytes())).is_ok())
            .collect()
    }

    /// Moves the calling process out of the group of an application process, into the root
    /// groups (`move_to_roots`), when it is in one; the processes it starts from then on are
    /// outside it too. Returns the roots it was moved into, none when it was in no such group.
    pub fn leave_application(base: &Path) -> Vec<PathBuf> {
        if ControlGroup::current().iter().any(|path| ControlGroup::is_application(path)) { ControlGroup::move_to_roots(base) } else { Vec::new() }
    }
}
