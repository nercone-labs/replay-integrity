use std::fs;
use std::io;
use std::path::Path;

/// One line of the package list: an installed package and its application ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageEntry {
    pub name: String,
    /// The application ID, the same for every user (`UserHandle.getAppId`).
    pub app_id: u32,
}

/// The list of installed packages that the package manager keeps for native daemons,
/// `/data/system/packages.list`: one package per line, its name and application ID first.
pub struct PackageList;

impl PackageList {
    pub const PATH: &'static str = "/data/system/packages.list";
    /// The number of IDs of each user (`UserHandle.PER_USER_RANGE`).
    pub const PER_USER_RANGE: u32 = 100_000;

    /// Reads the package list of the running system; only root (and the system) may.
    pub fn read() -> io::Result<Vec<PackageEntry>> {
        PackageList::read_from(Path::new(PackageList::PATH))
    }

    pub fn read_from(path: &Path) -> io::Result<Vec<PackageEntry>> {
        Ok(PackageList::parse(&fs::read_to_string(path)?))
    }

    /// Parses the lines of the list. Lines without a name and a numeric ID are skipped.
    pub fn parse(text: &str) -> Vec<PackageEntry> {
        text.lines()
            .filter_map(|line| {
                let mut fields = line.split_ascii_whitespace();
                let name = fields.next()?;
                let app_id = fields.next()?.parse().ok()?;
                Some(PackageEntry { name: name.to_string(), app_id })
            })
            .collect()
    }

    /// The application ID of `package`, or `None` if it is not installed.
    pub fn app_id_of(packages: &[PackageEntry], package: &str) -> Option<u32> {
        packages.iter().find(|entry| entry.name == package).map(|entry| entry.app_id)
    }

    /// The UID of an application for a user (`UserHandle.getUid`).
    pub fn uid(user: u32, app_id: u32) -> u32 {
        user * PackageList::PER_USER_RANGE + app_id % PackageList::PER_USER_RANGE
    }

    /// The application ID of a UID (`UserHandle.getAppId`).
    pub fn app_id(uid: u32) -> u32 {
        uid % PackageList::PER_USER_RANGE
    }
}
