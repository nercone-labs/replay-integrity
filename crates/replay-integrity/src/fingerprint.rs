use std::fmt;

use prop::{PropFile, PropLine};
use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;

use crate::{PatchDate, ReplayError};

/// A spoof flag of PlayIntegrityFork (`custom.pif.prop`, "Advanced Settings").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SpoofFlag {
    #[serde(rename = "spoofBuild")]
    Build,
    #[serde(rename = "spoofProps")]
    Props,
    #[serde(rename = "spoofProvider")]
    Provider,
    #[serde(rename = "spoofSignature")]
    Signature,
    #[serde(rename = "spoofVendingFinger")]
    VendingFinger,
    #[serde(rename = "spoofVendingSdk")]
    VendingSdk,
}

impl SpoofFlag {
    pub const ALL: [SpoofFlag; 6] =
        [SpoofFlag::Build, SpoofFlag::Props, SpoofFlag::Provider, SpoofFlag::Signature, SpoofFlag::VendingFinger, SpoofFlag::VendingSdk];

    pub fn key(&self) -> &'static str {
        match self {
            SpoofFlag::Build => "spoofBuild",
            SpoofFlag::Props => "spoofProps",
            SpoofFlag::Provider => "spoofProvider",
            SpoofFlag::Signature => "spoofSignature",
            SpoofFlag::VendingFinger => "spoofVendingFinger",
            SpoofFlag::VendingSdk => "spoofVendingSdk",
        }
    }

    pub fn from_key(key: &str) -> Option<SpoofFlag> {
        SpoofFlag::ALL.into_iter().find(|flag| flag.key() == key)
    }
}

/// The values of the spoof flags, in a fixed order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SpoofFlags {
    pub values: Vec<(SpoofFlag, bool)>,
}

impl SpoofFlags {
    /// The values that reach the STRONG verdict with TEESimulator-RS, as AlwaysStrong sets them:
    /// the build and the properties are spoofed; the keystore provider is not, because
    /// TEESimulator-RS provides the attested keystore; the Play Store fingerprint is spoofed on
    /// Android 13 and later only, because on Android 12L and earlier it breaks Play Integrity.
    pub fn recommended(sdk: Option<u32>) -> SpoofFlags {
        let vending = sdk.is_none_or(|sdk| sdk >= 33);
        SpoofFlags {
            values: vec![
                (SpoofFlag::Build, true),
                (SpoofFlag::Props, true),
                (SpoofFlag::Provider, false),
                (SpoofFlag::Signature, false),
                (SpoofFlag::VendingFinger, vending),
                (SpoofFlag::VendingSdk, false),
            ],
        }
    }

    pub fn set(&mut self, flag: SpoofFlag, value: bool) {
        match self.values.iter_mut().find(|(existing, _)| *existing == flag) {
            Some(entry) => entry.1 = value,
            None => self.values.push((flag, value)),
        }
    }

    pub fn get(&self, flag: SpoofFlag) -> Option<bool> {
        self.values.iter().find(|(existing, _)| *existing == flag).map(|(_, value)| *value)
    }
}

/// A reason why a fingerprint is not acceptable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FingerprintProblem {
    Missing {
        key: String,
    },
    /// `FINGERPRINT` is not `BRAND/PRODUCT/DEVICE:RELEASE/ID/INCREMENTAL:TYPE/TAGS`.
    InvalidFingerprint,
    /// A field disagrees with the part of `FINGERPRINT` it belongs to.
    Inconsistent {
        key: String,
    },
    /// Only builds of type `user` with `release-keys` are accepted as certified.
    NotRelease,
    InvalidPatch,
    /// The estimated expiry of the build has passed.
    Expired {
        expires: i64,
    },
}

/// A Pixel identity for PlayIntegrityFork, in the format of its `custom.pif.prop`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub file: PropFile,
}

/// What a fingerprint says, for reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintReport {
    pub fingerprint: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub device: Option<String>,
    pub security_patch: Option<String>,
    /// The estimated expiry, in seconds since the Unix epoch.
    pub expires: Option<i64>,
    pub spoof: Vec<(String, String)>,
    pub problems: Vec<FingerprintProblem>,
}

impl Fingerprint {
    pub const REQUIRED: [&'static str; 7] = ["FINGERPRINT", "MANUFACTURER", "MODEL", "BRAND", "PRODUCT", "DEVICE", "SECURITY_PATCH"];
    /// The comment that the canary fingerprint sources (autopif4 of PlayIntegrityFork and
    /// get_the_canary_miner) write with the date Google stops accepting the build.
    pub const EXPIRY_COMMENT: &'static str = "Estimated Expiry:";
    pub const SECURITY_PATCH_PROPERTY: &'static str = "ro.build.version.security_patch";

    /// The prefix that comments out an entry of `custom.pif.json`, as `#` does in a prop file.
    pub const JSON_COMMENT: &'static str = "//";

    pub fn parse(text: &str) -> Fingerprint {
        Fingerprint { file: PropFile::parse(text) }
    }

    /// Parses a fingerprint in either format PlayIntegrityFork reads: a `custom.pif.prop`, or
    /// a `custom.pif.json` (its earlier format, which other tools still write), told apart by a
    /// JSON object starting with `{`.
    pub fn read(text: &str) -> Result<Fingerprint, ReplayError> {
        if text.trim_start_matches('\u{feff}').trim_start().starts_with('{') { Fingerprint::from_json(text) } else { Ok(Fingerprint::parse(text)) }
    }

    /// Converts a `custom.pif.json` to the prop format, keeping the order of its entries: a
    /// flat object whose values are strings, numbers, booleans (`1` or `0`, as the prop format
    /// writes flags) or null (empty). A key starting with `//` is an entry commented out, which
    /// becomes a `#` line. Anything that cannot be written as one `key=value` line is rejected,
    /// so that the conversion cannot produce entries that were not in the file.
    pub fn from_json(text: &str) -> Result<Fingerprint, ReplayError> {
        let object: JsonObject = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|error| ReplayError::Rejected(vec![format!("the fingerprint is not a JSON object: {error}")]))?;
        let mut file = PropFile::default();
        let mut problems = Vec::new();
        for (key, value) in object.entries {
            let value = match value {
                Value::String(text) => text,
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => if flag { "1" } else { "0" }.to_string(),
                Value::Null => String::new(),
                Value::Array(_) | Value::Object(_) => {
                    problems.push(format!("the value of \"{key}\" is not a single value"));
                    continue;
                }
            };
            let (name, commented) = match key.strip_prefix(Fingerprint::JSON_COMMENT) {
                Some(name) => (name.trim(), true),
                None => (key.trim(), false),
            };
            if !Fingerprint::is_entry(name, &value) {
                problems.push(format!("\"{key}\" cannot be written as a property"));
                continue;
            }
            file.lines.push(if commented {
                PropLine::Other(format!("#{name}={value}"))
            } else {
                PropLine::Entry { key: name.to_string(), value: value.trim().to_string() }
            });
        }
        if problems.is_empty() { Ok(Fingerprint { file }) } else { Err(ReplayError::Rejected(problems)) }
    }

    /// Whether `key=value` is one entry of a prop file that reads back as the same key and value.
    fn is_entry(key: &str, value: &str) -> bool {
        let line_break = |character: char| character == '\n' || character == '\r';
        !key.is_empty() && !key.starts_with('#') && !key.contains('=') && !key.contains(line_break) && !value.contains(line_break)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.file.get(key).filter(|value| !value.is_empty())
    }

    pub fn security_patch(&self) -> Option<PatchDate> {
        self.get("SECURITY_PATCH").and_then(PatchDate::parse)
    }

    /// The estimated expiry, in seconds since the Unix epoch, from its comment.
    pub fn expires(&self) -> Option<i64> {
        self.file
            .comments()
            .find_map(|comment| comment.strip_prefix(Fingerprint::EXPIRY_COMMENT))
            .and_then(|date| PatchDate::parse(date.trim()))
            .map(|date| date.seconds())
    }

    /// Every problem at `now` (seconds since the Unix epoch).
    pub fn problems(&self, now: i64) -> Vec<FingerprintProblem> {
        let mut problems: Vec<FingerprintProblem> =
            Fingerprint::REQUIRED.iter().filter(|key| self.get(key).is_none()).map(|key| FingerprintProblem::Missing { key: key.to_string() }).collect();
        if let Some(fingerprint) = self.get("FINGERPRINT") {
            match Fingerprint::split(fingerprint) {
                None => problems.push(FingerprintProblem::InvalidFingerprint),
                Some(parts) => {
                    let fields = [
                        ("BRAND", parts[0]),
                        ("PRODUCT", parts[1]),
                        ("DEVICE", parts[2]),
                        ("RELEASE", parts[3]),
                        ("ID", parts[4]),
                        ("INCREMENTAL", parts[5]),
                        ("TYPE", parts[6]),
                        ("TAGS", parts[7]),
                    ];
                    for (key, part) in fields {
                        if self.get(key).is_some_and(|value| value != part) {
                            problems.push(FingerprintProblem::Inconsistent { key: key.to_string() });
                        }
                    }
                    if parts[6] != "user" || parts[7] != "release-keys" {
                        problems.push(FingerprintProblem::NotRelease);
                    }
                }
            }
        }
        if self.get("SECURITY_PATCH").is_some() && self.security_patch().is_none() {
            problems.push(FingerprintProblem::InvalidPatch);
        }
        if let Some(expires) = self.expires()
            && now >= expires
        {
            problems.push(FingerprintProblem::Expired { expires });
        }
        problems
    }

    /// The eight parts of `BRAND/PRODUCT/DEVICE:RELEASE/ID/INCREMENTAL:TYPE/TAGS`
    /// (`android.os.Build.FINGERPRINT`).
    pub fn split(fingerprint: &str) -> Option<[&str; 8]> {
        let mut sections = fingerprint.split(':');
        let (first, second, third) = (sections.next()?, sections.next()?, sections.next()?);
        if sections.next().is_some() {
            return None;
        }
        let mut parts = [""; 8];
        let mut index = 0;
        for (section, count) in [(first, 3), (second, 3), (third, 2)] {
            let pieces: Vec<&str> = section.split('/').collect();
            if pieces.len() != count || pieces.iter().any(|piece| piece.is_empty()) {
                return None;
            }
            for piece in pieces {
                parts[index] = piece;
                index += 1;
            }
        }
        Some(parts)
    }

    /// The fingerprint with the spoof flags set to `spoof` and the spoofed security patch
    /// property set to `SECURITY_PATCH`, so that what Play services read agrees with the patch
    /// level that attestation reports.
    pub fn with_settings(&self, spoof: &SpoofFlags) -> Fingerprint {
        let mut file = self.file.clone();
        for (flag, value) in &spoof.values {
            file.set(flag.key(), if *value { "1" } else { "0" });
        }
        if let Some(patch) = self.security_patch() {
            file.set(Fingerprint::SECURITY_PATCH_PROPERTY, &patch.to_string());
        }
        Fingerprint { file }
    }

    pub fn report(&self, now: i64) -> FingerprintReport {
        let text = |key: &str| self.get(key).map(str::to_string);
        FingerprintReport {
            fingerprint: text("FINGERPRINT"),
            manufacturer: text("MANUFACTURER"),
            model: text("MODEL"),
            device: text("DEVICE"),
            security_patch: text("SECURITY_PATCH"),
            expires: self.expires(),
            spoof: SpoofFlag::ALL.iter().filter_map(|flag| Some((flag.key().to_string(), self.file.get(flag.key())?.to_string()))).collect(),
            problems: self.problems(now),
        }
    }
}

/// A JSON object with its entries in the order of the text; `serde_json::Map` sorts them.
struct JsonObject {
    entries: Vec<(String, Value)>,
}

impl<'de> Deserialize<'de> for JsonObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<JsonObject, D::Error> {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = JsonObject;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonObject, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, Value>()? {
                    entries.push(entry);
                }
                Ok(JsonObject { entries })
            }
        }

        deserializer.deserialize_map(ObjectVisitor).map_err(de::Error::custom)
    }
}
