use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::AttestationError;

/// The status of a certificate in the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateStatus {
    Revoked,
    Suspended,
}

/// One entry of the status list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusEntry {
    pub status: CertificateStatus,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// The certificate revocation status list of Google, published at `StatusList::URL`. It lists
/// only certificates whose status is not normal, by serial number in lowercase hexadecimal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusList {
    pub entries: HashMap<String, StatusEntry>,
}

impl StatusList {
    pub const URL: &'static str = "https://android.googleapis.com/attestation/status";

    pub fn parse(json: &str) -> Result<StatusList, AttestationError> {
        let list: StatusList = serde_json::from_str(json)?;
        // The documented key pattern: lowercase hexadecimal without leading zeros.
        if list
            .entries
            .keys()
            .any(|serial| serial.is_empty() || serial.starts_with('0') || !serial.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(AttestationError::Structure("a serial number of the status list is not lowercase hexadecimal"));
        }
        Ok(list)
    }

    /// The entry of a serial number in lowercase hexadecimal, if its status is not normal.
    pub fn status_of(&self, serial: &str) -> Option<&StatusEntry> {
        self.entries.get(serial)
    }
}
