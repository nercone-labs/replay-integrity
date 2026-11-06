use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::ReplayError;

/// A key that TEESimulator-RS generated for an application and keeps in `persistent_keys/`,
/// with the certificate chain it attested the key with.
///
/// The chain of a generated key is signed with the keybox in use when the key was generated,
/// and TEESimulator-RS keeps it when the keybox changes. An application that reuses the key
/// keeps receiving the old chain: once the old keybox is revoked or expires, its attestation
/// fails although a valid keybox is installed. Such keys are found here by comparing their
/// chains with the keybox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedKey {
    #[serde(skip)]
    pub path: PathBuf,
    pub uid: u32,
    pub alias: String,
    /// The encoded certificates, from the generated key to the root.
    #[serde(skip)]
    pub chain: Vec<Vec<u8>>,
}

impl PersistedKey {
    pub const DIRECTORY: &'static str = "persistent_keys";
    pub const EXTENSION: &'static str = "bin";
    /// The format of `GeneratedKeyPersistence` of TEESimulator-RS that this reader knows.
    pub const FORMAT_VERSION: i32 = 3;
    /// Bounds of the reader of TEESimulator-RS, so that a damaged file cannot make this one
    /// allocate more than it would.
    pub const MAX_LIST: i32 = 64;
    pub const MAX_PRIVATE_KEY: i32 = 8192;
    pub const MAX_CERTIFICATES: i32 = 10;
    pub const MAX_CERTIFICATE: i32 = 65536;

    /// Reads the header and the chain of a persisted key. The layout is that of
    /// `GeneratedKeyPersistence.save` (Java `DataOutputStream`, big-endian): version,
    /// security level, uid, alias (`writeUTF`), namespace, attestation-key flag, algorithm, key
    /// size, curve, purposes, digests, private key, then the chain.
    pub fn parse(path: &Path, bytes: &[u8]) -> Option<PersistedKey> {
        let mut input = Input { bytes, position: 0 };
        if input.int()? != PersistedKey::FORMAT_VERSION {
            return None;
        }
        input.int()?;
        let uid = u32::try_from(input.int()?).ok()?;
        let alias = input.utf()?;
        input.skip(8 + 1 + 4 + 4 + 4)?;
        for _ in 0..2 {
            let count = input.bounded(PersistedKey::MAX_LIST)?;
            input.skip(count * 4)?;
        }
        let private_key = input.bounded(PersistedKey::MAX_PRIVATE_KEY)?;
        input.skip(private_key)?;
        let count = input.bounded(PersistedKey::MAX_CERTIFICATES)?;
        let mut chain = Vec::with_capacity(count);
        for _ in 0..count {
            let length = input.bounded(PersistedKey::MAX_CERTIFICATE)?;
            chain.push(input.take(length)?.to_vec());
        }
        Some(PersistedKey { path: path.to_path_buf(), uid, alias, chain })
    }

    /// Every persisted key of `directory` that can be read. Files of another format are left
    /// out: they are not keys that this reader can judge.
    pub fn list(directory: &Path) -> Result<Vec<PersistedKey>, ReplayError> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ReplayError::io_at("list", directory, error)),
        };
        let mut keys = Vec::new();
        for entry in entries {
            let path = entry.map_err(|error| ReplayError::io_at("list", directory, error))?.path();
            if path.extension().is_none_or(|extension| extension != PersistedKey::EXTENSION) {
                continue;
            }
            if let Ok(bytes) = fs::read(&path)
                && let Some(key) = PersistedKey::parse(&path, &bytes)
            {
                keys.push(key);
            }
        }
        keys.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(keys)
    }

    /// The certificate that signed the certificate of the key: the attestation key of the
    /// keybox, for a chain that TEESimulator-RS generated. `None` for keys without a chain,
    /// such as symmetric keys.
    pub fn signer(&self) -> Option<&[u8]> {
        self.chain.get(1).map(Vec::as_slice)
    }

    /// Whether the chain was signed by a key other than those whose certificates are
    /// `signers` (the first certificate of each key of the keybox).
    pub fn is_stale(&self, signers: &[&[u8]]) -> bool {
        self.signer().is_some_and(|signer| !signers.contains(&signer))
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(length)?;
        let slice = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    fn skip(&mut self, length: usize) -> Option<()> {
        self.take(length).map(|_| ())
    }

    fn int(&mut self) -> Option<i32> {
        self.take(4).map(|bytes| i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// A length that must be in `0..=max`.
    fn bounded(&mut self, max: i32) -> Option<usize> {
        let value = self.int()?;
        if (0..=max).contains(&value) { usize::try_from(value).ok() } else { None }
    }

    /// A string of `DataOutputStream.writeUTF`: a 16-bit length and modified UTF-8, which
    /// equals UTF-8 for the characters of key aliases (it differs only for NUL and for
    /// characters outside the Basic Multilingual Plane).
    fn utf(&mut self) -> Option<String> {
        let length = self.take(2).map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))?;
        Some(String::from_utf8_lossy(self.take(length)?).into_owned())
    }
}
