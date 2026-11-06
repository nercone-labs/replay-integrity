//! Tests of the status list, the trust anchors, and the parsing of the attestation extension.
//! The attestation extension is built here from the Android schema, not captured, so the test
//! states the expected encoding rather than echoing this parser.

use attestation::{AttestationError, KeyDescription, SecurityLevel, StatusList, TrustAnchors, VerifiedBootState};

const STATUS: &str = include_str!("fixtures/status.json");

#[test]
fn the_status_list_is_read_by_serial_number() {
    let list = StatusList::parse(STATUS).unwrap();
    assert!(list.status_of("2c8cdddfd5e03bfc").is_some());
    assert_eq!(list.status_of("c8966fcb2fbb0d7a").unwrap().status, attestation::CertificateStatus::Suspended);
    assert!(list.status_of("notlisted").is_none());
}

#[test]
fn a_status_list_with_a_bad_serial_number_is_rejected() {
    // Serial numbers must be lowercase hexadecimal without leading zeros (the documented pattern).
    assert!(matches!(StatusList::parse(r#"{"entries":{"0abc":{"status":"REVOKED"}}}"#), Err(AttestationError::Structure(_))));
    assert!(matches!(StatusList::parse(r#"{"entries":{"ABCD":{"status":"REVOKED"}}}"#), Err(AttestationError::Structure(_))));
    // An empty list is valid.
    assert!(StatusList::parse(r#"{"entries":{}}"#).unwrap().entries.is_empty());
}

#[test]
fn the_embedded_trust_anchors_parse_and_hold_two_roots() {
    let anchors = TrustAnchors::google();
    assert_eq!(anchors.roots.len(), 2);
    // Each root trusts itself: `trusts` matches by public key.
    assert!(anchors.roots.iter().all(|root| anchors.trusts(root)));
    // One of them is the documented factory root.
    assert!(anchors.roots.iter().any(|root| root.subject.attribute(&[2, 5, 4, 5]).as_deref() == Some(TrustAnchors::FACTORY_ROOT_SERIAL_NUMBER)));
}

/// Builds a DER element `tag || length || contents` (lengths here are all below 128).
fn element(tag: u8, contents: &[u8]) -> Vec<u8> {
    assert!(contents.len() < 128);
    let mut bytes = vec![tag, contents.len() as u8];
    bytes.extend_from_slice(contents);
    bytes
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    element(0x30, &parts.concat())
}

#[test]
fn the_attestation_extension_is_parsed_per_the_schema() {
    // RootOfTrust { verifiedBootKey OCTET_STRING, deviceLocked BOOLEAN, verifiedBootState
    // ENUMERATED, verifiedBootHash OCTET_STRING }.
    let root_of_trust = sequence(&[
        element(0x04, &[0xaa; 4]), // verifiedBootKey
        element(0x01, &[0xff]),    // deviceLocked = true
        element(0x0a, &[0x00]),    // verifiedBootState = Verified (0)
        element(0x04, &[0xbb; 4]), // verifiedBootHash
    ]);
    // hardwareEnforced AuthorizationList { rootOfTrust [704], osPatchLevel [706] }.
    // 704 and 706 use the high-tag-number form: 0xbf 0x85 0x40 / 0xbf 0x85 0x42.
    let mut field_704 = vec![0xbf, 0x85, 0x40, root_of_trust.len() as u8];
    field_704.extend_from_slice(&root_of_trust);
    let os_patch = element(0x02, &[0x03, 0x14, 0x4e]); // INTEGER 0x03144e = 201806
    let mut field_706 = vec![0xbf, 0x85, 0x42, os_patch.len() as u8];
    field_706.extend_from_slice(&os_patch);
    let hardware = element(0x30, &[field_704, field_706].concat());
    let software = sequence(&[]);
    // KeyDescription { version INTEGER 300, securityLevel ENUMERATED 1 (TrustedEnvironment),
    // keyMintVersion INTEGER 300, keyMintSecurityLevel ENUMERATED 1, challenge OCTET_STRING,
    // uniqueId OCTET_STRING, softwareEnforced, hardwareEnforced }.
    let description = sequence(&[
        element(0x02, &[0x01, 0x2c]), // 300
        element(0x0a, &[0x01]),       // TrustedEnvironment
        element(0x02, &[0x01, 0x2c]),
        element(0x0a, &[0x01]),
        element(0x04, b"challenge"),
        element(0x04, &[]),
        software,
        hardware,
    ]);
    let parsed = KeyDescription::parse(&description).unwrap();
    assert_eq!(parsed.attestation_version, 300);
    assert_eq!(parsed.attestation_security_level, SecurityLevel::TrustedEnvironment);
    assert!(parsed.attestation_security_level.is_hardware());
    assert_eq!(parsed.attestation_challenge, b"challenge");
    let root = parsed.root_of_trust().unwrap();
    assert!(root.device_locked);
    assert_eq!(root.verified_boot_state, VerifiedBootState::Verified);
    assert_eq!(root.verified_boot_hash.as_deref(), Some(&[0xbb; 4][..]));
    assert_eq!(parsed.hardware_enforced.os_patch_level, Some(201_806));

    // The documented extension OIDs.
    assert_eq!(KeyDescription::EXTENSION, &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17]);
    assert_eq!(KeyDescription::PROVISIONING_INFORMATION, &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30]);
}

#[test]
fn a_software_security_level_is_not_hardware() {
    assert!(!SecurityLevel::Software.is_hardware());
    assert!(SecurityLevel::StrongBox.is_hardware());
    assert_eq!(SecurityLevel::from_value(1).unwrap(), SecurityLevel::TrustedEnvironment);
    assert!(SecurityLevel::from_value(9).is_err());
    assert_eq!(VerifiedBootState::from_value(3).unwrap(), VerifiedBootState::Failed);
}
