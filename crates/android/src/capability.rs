use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// A Linux capability, by its number in `<linux/capability.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability(pub u8);

impl Capability {
    pub const CHOWN: Capability = Capability(0);
    pub const DAC_OVERRIDE: Capability = Capability(1);
    pub const DAC_READ_SEARCH: Capability = Capability(2);
    pub const FOWNER: Capability = Capability(3);
    pub const FSETID: Capability = Capability(4);
    pub const KILL: Capability = Capability(5);
    pub const SETGID: Capability = Capability(6);
    pub const SETUID: Capability = Capability(7);
    pub const SETPCAP: Capability = Capability(8);
    pub const LINUX_IMMUTABLE: Capability = Capability(9);
    pub const NET_BIND_SERVICE: Capability = Capability(10);
    pub const NET_BROADCAST: Capability = Capability(11);
    pub const NET_ADMIN: Capability = Capability(12);
    pub const NET_RAW: Capability = Capability(13);
    pub const IPC_LOCK: Capability = Capability(14);
    pub const IPC_OWNER: Capability = Capability(15);
    pub const SYS_MODULE: Capability = Capability(16);
    pub const SYS_RAWIO: Capability = Capability(17);
    pub const SYS_CHROOT: Capability = Capability(18);
    pub const SYS_PTRACE: Capability = Capability(19);
    pub const SYS_PACCT: Capability = Capability(20);
    pub const SYS_ADMIN: Capability = Capability(21);
    pub const SYS_BOOT: Capability = Capability(22);
    pub const SYS_NICE: Capability = Capability(23);
    pub const SYS_RESOURCE: Capability = Capability(24);
    pub const SYS_TIME: Capability = Capability(25);
    pub const SYS_TTY_CONFIG: Capability = Capability(26);
    pub const MKNOD: Capability = Capability(27);
    pub const LEASE: Capability = Capability(28);
    pub const AUDIT_WRITE: Capability = Capability(29);
    pub const AUDIT_CONTROL: Capability = Capability(30);
    pub const SETFCAP: Capability = Capability(31);
    pub const MAC_OVERRIDE: Capability = Capability(32);
    pub const MAC_ADMIN: Capability = Capability(33);
    pub const SYSLOG: Capability = Capability(34);
    pub const WAKE_ALARM: Capability = Capability(35);
    pub const BLOCK_SUSPEND: Capability = Capability(36);
    pub const AUDIT_READ: Capability = Capability(37);
    pub const PERFMON: Capability = Capability(38);
    pub const BPF: Capability = Capability(39);
    pub const CHECKPOINT_RESTORE: Capability = Capability(40);

    /// The names of the known capabilities, indexed by number.
    pub const NAMES: [&'static str; 41] = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
        "CAP_LEASE",
        "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ",
        "CAP_PERFMON",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    ];

    /// The `CAP_*` name, or `None` for a capability newer than this list.
    pub fn name(self) -> Option<&'static str> {
        Capability::NAMES.get(usize::from(self.0)).copied()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => formatter.write_str(name),
            None => write!(formatter, "capability {}", self.0),
        }
    }
}

/// A set of capabilities: bit `n` stands for `Capability(n)`, as in `/proc/<pid>/status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CapabilitySet(pub u64);

impl CapabilitySet {
    pub fn contains(self, capability: Capability) -> bool {
        1u64.checked_shl(u32::from(capability.0)).is_some_and(|bit| self.0 & bit != 0)
    }

    /// Parses the hexadecimal mask of a `Cap*` field of `/proc/<pid>/status`.
    pub fn parse(mask: &str) -> Option<CapabilitySet> {
        u64::from_str_radix(mask.trim(), 16).ok().map(CapabilitySet)
    }
}

/// The capability sets of a thread, as `/proc/<pid>/status` shows them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCapabilities {
    pub inheritable: CapabilitySet,
    pub permitted: CapabilitySet,
    pub effective: CapabilitySet,
    pub bounding: CapabilitySet,
    pub ambient: CapabilitySet,
}

impl ProcessCapabilities {
    /// The capabilities of the main thread of the process with `pid`.
    pub fn of(pid: u32) -> io::Result<ProcessCapabilities> {
        ProcessCapabilities::read(Path::new(&format!("/proc/{pid}/status")))
    }

    /// The capabilities of the calling thread.
    pub fn current() -> io::Result<ProcessCapabilities> {
        ProcessCapabilities::read(Path::new("/proc/thread-self/status")).or_else(|_| ProcessCapabilities::read(Path::new("/proc/self/status")))
    }

    /// Reads a `status` file of `/proc`.
    pub fn read(path: &Path) -> io::Result<ProcessCapabilities> {
        let status = fs::read_to_string(path)?;
        ProcessCapabilities::parse(&status)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{} has no valid capability sets", path.display())))
    }

    /// Parses the `Cap*` fields of `/proc/<pid>/status`. Kernels before Linux 4.3 have no
    /// ambient capabilities and no `CapAmb` field; the ambient set is then empty.
    pub fn parse(status: &str) -> Option<ProcessCapabilities> {
        let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix(':')).map(CapabilitySet::parse);
        Some(ProcessCapabilities {
            inheritable: field("CapInh")??,
            permitted: field("CapPrm")??,
            effective: field("CapEff")??,
            bounding: field("CapBnd")??,
            ambient: field("CapAmb").unwrap_or(Some(CapabilitySet::default()))?,
        })
    }
}
