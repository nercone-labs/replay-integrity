use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::ReplayError;

/// File operations that never leave a half-written file behind.
pub struct Files;

impl Files {
    /// The suffix of temporary files. It does not end in `.xml`, `.txt` or `.prop`, so that
    /// programs that watch a directory for such files do not read a file being written.
    pub const TEMPORARY_SUFFIX: &'static str = ".replay-tmp";

    /// Writes `bytes` to `path` with `mode`: a temporary file in the same directory is written,
    /// synchronized and renamed over `path`, so readers see the old or the new file, never a
    /// part of one.
    pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ReplayError> {
        let name = path.file_name().ok_or_else(|| ReplayError::refused(format!("{} is not a file path", path.display())))?;
        let temporary = path.with_file_name(format!("{}{}", name.to_string_lossy(), Files::TEMPORARY_SUFFIX));
        let result = (|| -> io::Result<()> {
            let _ = fs::remove_file(&temporary);
            let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(&temporary)?;
            file.write_all(bytes)?;
            // The mode given to `open` is reduced by the umask; set it exactly.
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            if let Some(directory) = path.parent() {
                File::open(directory)?.sync_all()?;
            }
            Ok(())
        })();
        result.map_err(|error| {
            let _ = fs::remove_file(&temporary);
            ReplayError::io_at("write", path, error)
        })
    }

    /// Creates `path` and its parents if missing, giving a created directory `mode`.
    pub fn create_directory(path: &Path, mode: u32) -> Result<(), ReplayError> {
        if path.is_dir() {
            return Ok(());
        }
        fs::create_dir_all(path).map_err(|error| ReplayError::io_at("create", path, error))?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| ReplayError::io_at("set the mode of", path, error))
    }

    pub fn read(path: &Path) -> Result<Vec<u8>, ReplayError> {
        fs::read(path).map_err(|error| ReplayError::io_at("read", path, error))
    }

    /// The contents of `path`, or `None` if it does not exist.
    pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, ReplayError> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ReplayError::io_at("read", path, error)),
        }
    }

    pub fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Removes `path`; a missing file is not an error. Returns whether a file was removed.
    pub fn remove(path: &Path) -> Result<bool, ReplayError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(ReplayError::io_at("remove", path, error)),
        }
    }
}
