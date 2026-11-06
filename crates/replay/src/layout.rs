use std::path::{Path, PathBuf};

/// Where the files the engine reads and writes are. Every path is under `root`, which is `/`
/// on a device; tests use a temporary directory instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn new(root: impl Into<PathBuf>) -> Layout {
        Layout { root: root.into() }
    }

    pub fn device() -> Layout {
        Layout::new("/")
    }

    /// A path of the device, such as `/data/adb`, under the root.
    pub fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// The directory of root managers, which holds their modules and our store.
    pub fn adb(&self) -> PathBuf {
        self.path("/data/adb")
    }

    pub fn modules(&self) -> PathBuf {
        self.path("/data/adb/modules")
    }

    /// Modules installed since the last boot, which replace `modules` at the next boot.
    pub fn modules_update(&self) -> PathBuf {
        self.path("/data/adb/modules_update")
    }

    /// The configuration directory of TEESimulator-RS (and the TrickyStore family).
    pub fn tricky_store(&self) -> PathBuf {
        self.path("/data/adb/tricky_store")
    }

    /// The store of this engine.
    pub fn store(&self) -> PathBuf {
        self.path("/data/adb/replay-integrity")
    }

    pub fn packages_list(&self) -> PathBuf {
        self.path(android::PackageList::PATH)
    }

    /// The path of `path` as the device sees it, for messages and reports.
    pub fn device_path(&self, path: &Path) -> PathBuf {
        match path.strip_prefix(&self.root) {
            Ok(relative) => Path::new("/").join(relative),
            Err(_) => path.to_path_buf(),
        }
    }
}
