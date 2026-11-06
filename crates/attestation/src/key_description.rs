use der::{Element, Reader, Tag};
use serde::Serialize;

use crate::AttestationError;

/// Where a key lives (`SecurityLevel` of the schema).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

impl SecurityLevel {
    pub fn from_value(value: i64) -> Result<SecurityLevel, AttestationError> {
        match value {
            0 => Ok(SecurityLevel::Software),
            1 => Ok(SecurityLevel::TrustedEnvironment),
            2 => Ok(SecurityLevel::StrongBox),
            _ => Err(AttestationError::Structure("an unknown security level")),
        }
    }

    /// Whether the level is secure hardware, as Google requires for hardware-backed keys.
    pub fn is_hardware(&self) -> bool {
        matches!(self, SecurityLevel::TrustedEnvironment | SecurityLevel::StrongBox)
    }
}

/// The verified boot state of the device (`VerifiedBootState` of the schema).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VerifiedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed,
}

impl VerifiedBootState {
    pub fn from_value(value: i64) -> Result<VerifiedBootState, AttestationError> {
        match value {
            0 => Ok(VerifiedBootState::Verified),
            1 => Ok(VerifiedBootState::SelfSigned),
            2 => Ok(VerifiedBootState::Unverified),
            3 => Ok(VerifiedBootState::Failed),
            _ => Err(AttestationError::Structure("an unknown verified boot state")),
        }
    }
}

/// `RootOfTrust` of the schema. The boot hash is present from attestation version 3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_hash: Option<Vec<u8>>,
}

impl RootOfTrust {
    pub fn parse(element: &Element) -> Result<RootOfTrust, AttestationError> {
        if element.tag != Tag::SEQUENCE {
            return Err(AttestationError::Structure("a root of trust is not a SEQUENCE"));
        }
        let mut fields = element.reader()?;
        let verified_boot_key = fields.expect(Tag::OCTET_STRING)?.octet_string()?.to_vec();
        let device_locked = fields.expect(Tag::BOOLEAN)?.boolean()?;
        let verified_boot_state = VerifiedBootState::from_value(fields.expect(Tag::ENUMERATED)?.enumerated()?)?;
        let verified_boot_hash = match fields.read_optional(Tag::OCTET_STRING)? {
            Some(hash) => Some(hash.octet_string()?.to_vec()),
            None => None,
        };
        fields.finish()?;
        Ok(RootOfTrust { verified_boot_key, device_locked, verified_boot_state, verified_boot_hash })
    }
}

/// The fields of an `AuthorizationList` that describe the device. Every field is an explicitly
/// tagged optional value; fields not listed here are skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationList {
    pub root_of_trust: Option<RootOfTrust>,
    /// `osVersion`, as `MMmmpp` (major, minor, patch).
    pub os_version: Option<u64>,
    /// `osPatchLevel`, as `YYYYMM`.
    pub os_patch_level: Option<u64>,
    /// `vendorPatchLevel`, as `YYYYMMDD`.
    pub vendor_patch_level: Option<u64>,
    /// `bootPatchLevel`, as `YYYYMMDD`.
    pub boot_patch_level: Option<u64>,
    /// The package names of `attestationApplicationId`.
    pub application_packages: Vec<String>,
}

impl AuthorizationList {
    pub const ROOT_OF_TRUST: u32 = 704;
    pub const OS_VERSION: u32 = 705;
    pub const OS_PATCH_LEVEL: u32 = 706;
    pub const ATTESTATION_APPLICATION_ID: u32 = 709;
    pub const VENDOR_PATCH_LEVEL: u32 = 718;
    pub const BOOT_PATCH_LEVEL: u32 = 719;

    pub fn parse(element: &Element) -> Result<AuthorizationList, AttestationError> {
        if element.tag != Tag::SEQUENCE {
            return Err(AttestationError::Structure("an authorization list is not a SEQUENCE"));
        }
        let mut list = AuthorizationList::default();
        let mut fields = element.reader()?;
        let mut previous: Option<u32> = None;
        while !fields.is_empty() {
            let field = fields.read()?;
            if field.tag.class != der::TagClass::ContextSpecific || !field.tag.constructed {
                return Err(AttestationError::Structure("an authorization is not an explicitly tagged value"));
            }
            // DER orders the fields of a SEQUENCE by their tags; each appears once.
            if previous.is_some_and(|previous| previous >= field.tag.number) {
                return Err(AttestationError::Structure("the authorizations are not in order of their tags"));
            }
            previous = Some(field.tag.number);
            let mut inner = field.reader()?;
            let value = inner.read()?;
            inner.finish()?;
            let integer = |value: &Element| -> Result<Option<u64>, AttestationError> {
                Ok(Some(value.integer()?.to_u64().ok_or(AttestationError::Structure("an authorization is out of range"))?))
            };
            match field.tag.number {
                AuthorizationList::ROOT_OF_TRUST => list.root_of_trust = Some(RootOfTrust::parse(&value)?),
                AuthorizationList::OS_VERSION => list.os_version = integer(&value)?,
                AuthorizationList::OS_PATCH_LEVEL => list.os_patch_level = integer(&value)?,
                AuthorizationList::VENDOR_PATCH_LEVEL => list.vendor_patch_level = integer(&value)?,
                AuthorizationList::BOOT_PATCH_LEVEL => list.boot_patch_level = integer(&value)?,
                AuthorizationList::ATTESTATION_APPLICATION_ID => {
                    list.application_packages = AuthorizationList::application_packages(value.octet_string()?)?;
                }
                _ => {}
            }
        }
        Ok(list)
    }

    /// The package names of an `AttestationApplicationId`:
    /// `SEQUENCE { package_infos SET OF SEQUENCE { package_name OCTET_STRING, version INTEGER },
    /// signature_digests SET OF OCTET_STRING }`.
    pub fn application_packages(der: &[u8]) -> Result<Vec<String>, AttestationError> {
        let identifier = Element::parse(der)?;
        let mut fields = identifier.reader()?;
        let infos = fields.expect(Tag::SET)?;
        let mut infos = infos.reader()?;
        let mut packages = Vec::new();
        while !infos.is_empty() {
            let info = infos.expect(Tag::SEQUENCE)?;
            let mut info = info.reader()?;
            let name = info.expect(Tag::OCTET_STRING)?.octet_string()?;
            packages.push(String::from_utf8_lossy(name).into_owned());
        }
        Ok(packages)
    }
}

/// The attestation extension (`KeyDescription` of the schema).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDescription {
    pub attestation_version: u64,
    pub attestation_security_level: SecurityLevel,
    pub key_mint_version: u64,
    pub key_mint_security_level: SecurityLevel,
    pub attestation_challenge: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub hardware_enforced: AuthorizationList,
}

impl KeyDescription {
    /// The identifier of the attestation extension.
    pub const EXTENSION: &'static [u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];
    /// The identifier of the provisioning information extension, present in chains of keys
    /// provisioned remotely (RKP).
    pub const PROVISIONING_INFORMATION: &'static [u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30];

    /// Parses the value of the attestation extension.
    pub fn parse(der: &[u8]) -> Result<KeyDescription, AttestationError> {
        let description = Element::parse(der)?;
        if description.tag != Tag::SEQUENCE {
            return Err(AttestationError::Structure("a key description is not a SEQUENCE"));
        }
        let mut fields = description.reader()?;
        let version = |fields: &mut Reader| -> Result<u64, AttestationError> {
            fields.expect(Tag::INTEGER)?.integer()?.to_u64().ok_or(AttestationError::Structure("a version is out of range"))
        };
        let attestation_version = version(&mut fields)?;
        let attestation_security_level = SecurityLevel::from_value(fields.expect(Tag::ENUMERATED)?.enumerated()?)?;
        let key_mint_version = version(&mut fields)?;
        let key_mint_security_level = SecurityLevel::from_value(fields.expect(Tag::ENUMERATED)?.enumerated()?)?;
        let attestation_challenge = fields.expect(Tag::OCTET_STRING)?.octet_string()?.to_vec();
        fields.expect(Tag::OCTET_STRING)?;
        let software_enforced = AuthorizationList::parse(&fields.read()?)?;
        let hardware_enforced = AuthorizationList::parse(&fields.read()?)?;
        // Later versions may append fields, which are ignored.
        Ok(KeyDescription {
            attestation_version,
            attestation_security_level,
            key_mint_version,
            key_mint_security_level,
            attestation_challenge,
            software_enforced,
            hardware_enforced,
        })
    }

    /// The root of trust, which secure hardware reports in its hardware-enforced list.
    pub fn root_of_trust(&self) -> Option<&RootOfTrust> {
        self.hardware_enforced.root_of_trust.as_ref()
    }
}
