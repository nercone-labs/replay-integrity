use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use android::{PackageEntry, PackageList};
use attestation::{Chain, ChainProblem, KeyDescription, StatusList, TrustAnchors};
use der::Time;
use serde::Serialize;
use x509::Certificate;

use crate::{KeyRemoval, KeyRemovalSettings, ReplayError, TargetList};

/// A key that TEESimulator-RS generated for an application and keeps in `persistent_keys/`,
/// with the certificate chain it attested the key with.
///
/// The chain of a generated key is signed with the keybox in use when the key was generated,
/// and TEESimulator-RS keeps it when the keybox changes. An application that reuses the key
/// keeps receiving the old chain: once the old keybox is revoked or expires, its attestation
/// fails although a valid keybox is installed. Such keys are found here by comparing their
/// chains with the keybox.
///
/// The certificate of a generated key also holds the security patch levels in use when the key
/// was generated, and TEESimulator-RS keeps them when `security_patch.txt` changes. An
/// application that reuses the key keeps attesting the old patch while the spoofed build claims
/// the new one. The attestation extension of the key (`key_description`) shows these levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedKey {
    #[serde(skip)]
    pub path: PathBuf,
    pub uid: u32,
    pub alias: String,
    /// Whether `alias` is the alias exactly. It is not when the file holds characters that
    /// modified UTF-8 encodes differently from UTF-8 (NUL, or characters outside the Basic
    /// Multilingual Plane), which are then replaced by U+FFFD: such an alias names another
    /// key, so it must not be given to the keystore.
    #[serde(skip)]
    pub alias_exact: bool,
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
        let (alias, alias_exact) = input.utf()?;
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
        Some(PersistedKey { path: path.to_path_buf(), uid, alias, alias_exact, chain })
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
    pub fn is_signed_by_other(&self, signers: &[&[u8]]) -> bool {
        self.signer().is_some_and(|signer| !signers.contains(&signer))
    }

    /// The attestation extension of the certificate of the key. `None` when the key has no
    /// certificate, the certificate has no attestation extension, or either cannot be read.
    pub fn key_description(&self) -> Option<KeyDescription> {
        let certificate = Certificate::parse(self.chain.first()?).ok()?;
        KeyDescription::parse(&certificate.extension(KeyDescription::EXTENSION)?.value).ok()
    }

    /// The packages the key belongs to: those its attestation names (`attestationApplicationId`)
    /// and those of `packages` (the package list) that run as its user. Either alone may be
    /// missing: a key attested without an application ID, or a package list that cannot be read.
    pub fn packages(&self, packages: &[PackageEntry]) -> Vec<String> {
        let mut names: Vec<String> = self
            .key_description()
            .map(|description| [description.software_enforced, description.hardware_enforced].into_iter().flat_map(|list| list.application_packages).collect())
            .unwrap_or_default();
        let app_id = PackageList::app_id(self.uid);
        names.extend(packages.iter().filter(|entry| entry.app_id == app_id).map(|entry| entry.name.clone()));
        names.sort();
        names.dedup();
        names
    }

    /// The problems at `now` of the chain that signed the key: its certificates after the key's
    /// own, which are those of the keybox key that attested it. `None` when that chain is
    /// missing or a certificate of it cannot be read, so that nothing is known about it.
    pub fn signer_problems(&self, now: Time, status: Option<&StatusList>, anchors: &TrustAnchors) -> Option<Vec<ChainProblem>> {
        let certificates = self.chain.get(1..).filter(|chain| !chain.is_empty())?;
        let certificates: Vec<Certificate> = certificates.iter().map(|der| Certificate::parse(der).ok()).collect::<Option<_>>()?;
        Some(Chain::new(certificates).problems(now, status, anchors))
    }
}

/// What a persisted key is for, which decides what its removal costs the user
/// (`KeyRemovalSettings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyCategory {
    /// The key of the Play Integrity API: an alias of `KeyCategory::INTEGRITY_ALIASES`, of a
    /// package of the Play stack. It holds nothing of the user's, and the Play Store makes it
    /// again when it is gone.
    Integrity,
    /// Another key of the Play stack (`TargetList::ALWAYS`): tap-and-pay cards, passkeys and the
    /// like, which are lost with the key.
    Play,
    /// A key of any other application, or of an application that cannot be told: its
    /// enrolment is lost with the key.
    Application,
}

impl KeyCategory {
    /// The aliases of the keys of the Play stack that are known to serve the Play Integrity
    /// API. `integrity.api.key.alias` is the key of the Play Integrity API, seen in the
    /// keystore2 database of a device as a key of the Play Store.
    pub const INTEGRITY_ALIASES: [&'static str; 1] = ["integrity.api.key.alias"];

    /// The category of `key`, which belongs to `packages` (`PersistedKey::packages`). A key
    /// whose packages are not known is an application's: the category whose removal is the
    /// most careful.
    pub fn of(key: &PersistedKey, packages: &[String]) -> KeyCategory {
        let play = packages.iter().any(|package| TargetList::ALWAYS.contains(&package.as_str()));
        if play && key.alias_exact && KeyCategory::INTEGRITY_ALIASES.contains(&key.alias.as_str()) {
            KeyCategory::Integrity
        } else if play {
            KeyCategory::Play
        } else {
            KeyCategory::Application
        }
    }
}

/// Why a persisted key is outdated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OutdatedReason {
    /// Its chain was signed by a key that is not in the installed keybox. `unusable` is whether
    /// that chain is known to be no longer valid (`PersistedKey::signer_problems`): revoked,
    /// expired, untrusted or broken. A chain that cannot be read, or a revocation that cannot be
    /// checked, is not known to be unusable.
    OldKeybox { unusable: bool },
    /// It is the key of the Play Integrity API and attests a security patch other than the
    /// configured one, which contradicts the spoofed build.
    OldPatch,
}

/// A persisted key that was attested with what is no longer configured, with whether a repair
/// removes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutdatedKey {
    #[serde(flatten)]
    pub key: PersistedKey,
    pub category: KeyCategory,
    /// The packages of the key (`PersistedKey::packages`).
    pub packages: Vec<String>,
    pub reasons: Vec<OutdatedReason>,
    /// Whether a repair removes the key with the settings it was judged by
    /// (`OutdatedKey::is_removed_by`). A key that is kept is still reported, and the user can
    /// remove it (`Engine::remove_key`).
    pub removed_by_repair: bool,
}

impl OutdatedKey {
    /// Whether `removal` removes the key: for any of its reasons, the settings of its category
    /// allow it.
    pub fn is_removed_by(category: KeyCategory, reasons: &[OutdatedReason], removal: &KeyRemovalSettings) -> bool {
        reasons.iter().any(|reason| match reason {
            OutdatedReason::OldKeybox { unusable } => match removal.of(category) {
                KeyRemoval::Never => false,
                KeyRemoval::WhenUnusable => *unusable,
                KeyRemoval::WhenReplaced => true,
            },
            OutdatedReason::OldPatch => category == KeyCategory::Integrity && removal.integrity_patch,
        })
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
    /// characters outside the Basic Multilingual Plane, whose encodings are not valid UTF-8).
    /// Returns the string and whether it was read exactly; when it was not, the bytes that
    /// are not UTF-8 are replaced by U+FFFD.
    fn utf(&mut self) -> Option<(String, bool)> {
        let length = self.take(2).map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))?;
        let bytes = self.take(length)?;
        Some(match std::str::from_utf8(bytes) {
            Ok(text) => (text.to_string(), true),
            Err(_) => (String::from_utf8_lossy(bytes).into_owned(), false),
        })
    }
}
