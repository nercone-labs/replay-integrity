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

/// The fixture with the defect of a keybox a mirror served: the `DeviceID` value has no closing
/// quote, so the `<Key>` start tag that follows falls inside it and no XML parser reads a key.
fn unclosed_attribute() -> String {
    TEST_KEYBOX.replacen(
        "DeviceID=\"replay-integrity test (throwaway keys, not an attestation key)\">",
        "DeviceID=\"replay-integrity test (throwaway keys, not an attestation key)>",
        1,
    )
}

/// The PEM data of every private key and every certificate, in order, which is what a keystore
/// daemon reads from a keybox.
fn key_material(document: &KeyboxDocument) -> Vec<(KeyAlgorithm, Vec<u8>, Vec<Vec<u8>>)> {
    document
        .keys()
        .map(|key| (key.algorithm, key.private_key_block.data.clone(), key.certificates.iter().map(|certificate| certificate.der.clone()).collect()))
        .collect()
}

#[test]
fn a_well_formed_keybox_is_read_without_a_defect() {
    let document = KeyboxDocument::read(TEST_KEYBOX).unwrap();
    assert_eq!(document.defect, None);
    assert_eq!(document, KeyboxDocument::parse(TEST_KEYBOX).unwrap());
}

#[test]
fn a_keybox_with_an_unclosed_attribute_is_not_well_formed() {
    assert!(matches!(KeyboxDocument::parse(&unclosed_attribute()), Err(KeyboxError::Syntax(_))));
}

#[test]
fn the_keys_of_a_malformed_keybox_are_recovered_with_the_defect() {
    let broken = unclosed_attribute();
    let document = KeyboxDocument::read(&broken).unwrap();
    assert!(document.defect.as_deref().is_some_and(|defect| defect.starts_with("invalid XML")));
    // The same keys, private keys and chains as the well-formed fixture.
    assert_eq!(key_material(&document), key_material(&KeyboxDocument::parse(TEST_KEYBOX).unwrap()));
    for key in document.keys() {
        assert_eq!(key.matches_certificate(), Some(true));
    }
}

#[test]
fn a_rendered_keybox_is_well_formed_and_holds_the_same_keys() {
    for text in [TEST_KEYBOX.to_string(), unclosed_attribute()] {
        let document = KeyboxDocument::read(&text).unwrap();
        let rendered = document.render();
        let reparsed = KeyboxDocument::parse(&rendered).unwrap();
        assert_eq!(reparsed.defect, None);
        assert_eq!(key_material(&reparsed), key_material(&document));
        assert_eq!(reparsed.keyboxes.len(), document.keyboxes.len());
        for (left, right) in reparsed.keyboxes.iter().zip(&document.keyboxes) {
            assert_eq!(left.device_id, right.device_id);
        }
    }
}

#[test]
fn a_rendered_keybox_declares_its_counts() {
    let rendered = KeyboxDocument::parse(TEST_KEYBOX).unwrap().render();
    assert!(rendered.starts_with("<?xml version=\"1.0\"?>\n<AndroidAttestation>\n"));
    assert!(rendered.contains("<NumberOfKeyboxes>1</NumberOfKeyboxes>"));
    assert!(rendered.contains("<NumberOfCertificates>2</NumberOfCertificates>"));
    assert!(rendered.contains("<NumberOfCertificates>1</NumberOfCertificates>"));
    assert!(rendered.contains("<Key algorithm=\"ecdsa\">") && rendered.contains("<Key algorithm=\"rsa\">"));
}

#[test]
fn a_device_id_is_escaped_when_rendered() {
    let mut document = KeyboxDocument::parse(TEST_KEYBOX).unwrap();
    document.keyboxes[0].device_id = Some("a \"quoted\" <id> & 'more'".to_string());
    let reparsed = KeyboxDocument::parse(&document.render()).unwrap();
    assert_eq!(reparsed.keyboxes[0].device_id.as_deref(), Some("a \"quoted\" <id> & 'more'"));
}

#[test]
fn recovery_takes_the_algorithm_from_the_key_itself() {
    // The attribute says rsa, but the PEM is an EC key: the key decides.
    let wrong = unclosed_attribute().replacen("algorithm=\"ecdsa\"", "algorithm=\"rsa\"", 1);
    let document = KeyboxDocument::read(&wrong).unwrap();
    let algorithms: Vec<_> = document.keys().map(|key| key.algorithm).collect();
    assert_eq!(algorithms, [KeyAlgorithm::ECDSA, KeyAlgorithm::RSA]);
}

#[test]
fn recovery_skips_regions_that_are_not_one_key() {
    // A watermark element without PEM, and a region with two private keys, are not keys.
    let ec_key = TEST_KEYBOX.split("<Key algorithm=\"ecdsa\">").nth(1).unwrap().split("</Key>").next().unwrap();
    let doubled = format!("<Key algorithm=\"ecdsa\">{ec_key}{ec_key}</Key>");
    let text = unclosed_attribute().replacen("<Key algorithm=\"rsa\">", &format!("<Key algorithm=\"@evokerr\"></Key>\n{doubled}\n<Key algorithm=\"rsa\">"), 1);
    let document = KeyboxDocument::read(&text).unwrap();
    let algorithms: Vec<_> = document.keys().map(|key| key.algorithm).collect();
    assert_eq!(algorithms, [KeyAlgorithm::ECDSA, KeyAlgorithm::RSA]);
}

#[test]
fn recovery_tolerates_missing_end_tags() {
    let truncated = unclosed_attribute().replace("</Keybox>", "").replace("</AndroidAttestation>", "");
    assert_eq!(KeyboxDocument::read(&truncated).unwrap().keys().count(), 2);
}

#[test]
fn a_keybox_element_does_not_start_a_key_region() {
    let regions: Vec<_> = KeyboxDocument::key_regions("<Keybox><Key algorithm=\"a\"/><KeyX><Key>").collect();
    assert_eq!(regions, ["<Key algorithm=\"a\"/><KeyX>", "<Key>"]);
}

#[test]
fn a_text_without_keys_keeps_the_error_of_strict_parsing() {
    assert!(matches!(KeyboxDocument::read("not xml at all <"), Err(KeyboxError::Syntax(_))));
    assert!(matches!(KeyboxDocument::read("<AndroidAttestation></AndroidAttestation>"), Err(KeyboxError::Structure(_))));
    assert!(matches!(KeyboxDocument::recover("<Key algorithm=\"ecdsa\"></Key>"), Err(KeyboxError::Structure(_))));
}

#[test]
fn retaining_keys_leaves_out_empty_keyboxes() {
    let document = KeyboxDocument::parse(TEST_KEYBOX).unwrap();
    let ec_only = document.retain_keys(|key| key.algorithm == KeyAlgorithm::ECDSA);
    assert_eq!(ec_only.keys().map(|key| key.algorithm).collect::<Vec<_>>(), [KeyAlgorithm::ECDSA]);
    assert!(document.retain_keys(|_| false).keyboxes.is_empty());
}

#[test]
fn the_debug_form_of_a_key_holds_no_secret() {
    let document = KeyboxDocument::parse(TEST_KEYBOX).unwrap();
    for key in document.keys() {
        let encoded = key.private_key_block.encode();
        let secret_line = encoded.lines().nth(1).unwrap();
        assert!(!format!("{key:?}").contains(secret_line));
        assert!(!format!("{document:?}").contains(secret_line));
    }
}
