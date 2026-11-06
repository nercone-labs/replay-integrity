//! Tests of keybox parsing. The fixture is a keybox of throwaway keys generated for the tests,
//! not a real attestation keybox; it exercises the structure, not any particular key.

use keybox::{KeyAlgorithm, KeyboxDocument, KeyboxError};

const TEST_KEYBOX: &str = include_str!("fixtures/test-keybox.xml");

#[test]
fn a_keybox_is_parsed_with_its_keys_and_chains() {
    let document = KeyboxDocument::parse(TEST_KEYBOX).unwrap();
    assert_eq!(document.keyboxes.len(), 1);
    let keys: Vec<_> = document.keys().collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].algorithm, KeyAlgorithm::ECDSA);
    assert_eq!(keys[0].certificates.len(), 2);
    assert_eq!(keys[1].algorithm, KeyAlgorithm::RSA);
    assert_eq!(keys[1].certificates.len(), 1);
    // The private key of each key belongs to its first certificate.
    assert_eq!(keys[0].matches_certificate(), Some(true));
    assert_eq!(keys[1].matches_certificate(), Some(true));
}

#[test]
fn a_key_of_an_unknown_algorithm_is_skipped_not_fatal() {
    // Mirrors add a watermark <Key> whose algorithm attribute is a handle, not an algorithm.
    // Such a key is skipped: the keybox keeps its real keys instead of being rejected whole.
    let watermark = "<Key algorithm=\"@evokerr\"></Key>";
    let with_junk = TEST_KEYBOX.replacen("<Key algorithm=\"ecdsa\">", &format!("{watermark}\n{}", "<Key algorithm=\"ecdsa\">"), 1);
    let document = KeyboxDocument::parse(&with_junk).unwrap();
    let keys: Vec<_> = document.keys().collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].algorithm, KeyAlgorithm::ECDSA);
    assert_eq!(keys[1].algorithm, KeyAlgorithm::RSA);
}

#[test]
fn a_keybox_of_only_unknown_algorithms_is_rejected() {
    let only_junk = "<AndroidAttestation><Keybox><Key algorithm=\"@evokerr\"></Key></Keybox></AndroidAttestation>";
    assert!(matches!(KeyboxDocument::parse(only_junk), Err(KeyboxError::Structure(_))));
}

#[test]
fn a_wrong_declared_count_is_rejected() {
    let wrong = TEST_KEYBOX.replace("<NumberOfKeyboxes>1</NumberOfKeyboxes>", "<NumberOfKeyboxes>2</NumberOfKeyboxes>");
    assert!(matches!(KeyboxDocument::parse(&wrong), Err(KeyboxError::Structure(_))));
    let wrong = TEST_KEYBOX.replace("<NumberOfCertificates>2</NumberOfCertificates>", "<NumberOfCertificates>3</NumberOfCertificates>");
    assert!(matches!(KeyboxDocument::parse(&wrong), Err(KeyboxError::Structure(_))));
}

#[test]
fn a_key_whose_private_key_disagrees_with_its_algorithm_is_rejected() {
    // Claim the EC key is RSA: its PEM is then an EC key under an rsa algorithm.
    let wrong = TEST_KEYBOX.replacen("algorithm=\"ecdsa\"", "algorithm=\"rsa\"", 1);
    assert!(matches!(KeyboxDocument::parse(&wrong), Err(KeyboxError::Structure(_))));
}

#[test]
fn a_document_type_declaration_is_refused() {
    // No external entity may be referenced: a DOCTYPE is refused outright.
    let doctype = "<?xml version=\"1.0\"?>\n<!DOCTYPE AndroidAttestation>\n<AndroidAttestation></AndroidAttestation>";
    assert!(matches!(KeyboxDocument::parse(doctype), Err(KeyboxError::Syntax(_))));
}

#[test]
fn a_non_keybox_document_is_rejected() {
    assert!(matches!(KeyboxDocument::parse("<other></other>"), Err(KeyboxError::Structure(_))));
    assert!(matches!(KeyboxDocument::parse("not xml at all <"), Err(KeyboxError::Syntax(_))));
    assert!(matches!(KeyboxDocument::parse("<AndroidAttestation></AndroidAttestation>"), Err(KeyboxError::Structure(_))));
}
