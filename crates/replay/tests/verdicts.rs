//! Tests of how keybox verdicts are judged and compared. The verdicts are built directly, so
//! that a usable key does not need a keybox signed by Google.

use attestation::{CertificateStatus, ChainProblem};
use replay::{KeyProblem, KeyVerdict, KeyboxVerdict};

fn key(algorithm: &str, problems: Vec<KeyProblem>) -> KeyVerdict {
    KeyVerdict { algorithm: algorithm.to_string(), serial: String::new(), root: None, expires: None, problems }
}

fn usable(algorithm: &str) -> KeyVerdict {
    key(algorithm, Vec::new())
}

fn revoked(algorithm: &str) -> KeyVerdict {
    key(algorithm, vec![KeyProblem::Chain(ChainProblem::Revoked { index: 0, serial: "1".to_string(), status: CertificateStatus::Revoked, reason: None })])
}

fn verdict(keys: Vec<KeyVerdict>) -> KeyboxVerdict {
    KeyboxVerdict { keys, revocation_checked: true, defect: None }
}

#[test]
fn a_usable_ec_key_is_enough_for_strong() {
    assert!(verdict(vec![usable("ecdsa")]).is_strong_capable());
    assert!(verdict(vec![usable("ecdsa"), revoked("rsa")]).is_strong_capable());
    assert!(!verdict(vec![usable("rsa")]).is_strong_capable());
    assert!(!verdict(vec![revoked("ecdsa"), usable("rsa")]).is_strong_capable());
    assert!(!verdict(Vec::new()).is_strong_capable());
}

#[test]
fn a_file_the_daemon_cannot_read_is_not_strong_capable() {
    let malformed = KeyboxVerdict { defect: Some("invalid XML".to_string()), ..verdict(vec![usable("ecdsa")]) };
    assert!(!malformed.is_strong_capable());
}

#[test]
fn a_better_or_equal_keybox_may_replace_the_installed_one() {
    let strong = verdict(vec![usable("ecdsa")]);
    let both = verdict(vec![usable("ecdsa"), usable("rsa")]);
    let broken = verdict(vec![revoked("ecdsa")]);
    assert!(strong.may_replace(None));
    assert!(broken.may_replace(None));
    assert!(strong.may_replace(Some(&broken)));
    assert!(both.may_replace(Some(&strong)));
    // An equal keybox replaces the installed one: a mirror rotates before a leak is listed.
    assert!(strong.may_replace(Some(&strong.clone())));
    assert!(!broken.may_replace(Some(&strong)));
    assert!(!strong.may_replace(Some(&both)));
    assert!(!verdict(vec![usable("rsa")]).may_replace(Some(&strong)));
}

#[test]
fn an_installed_file_the_daemon_cannot_read_may_always_be_replaced() {
    let installed = KeyboxVerdict { defect: Some("invalid XML".to_string()), ..verdict(vec![usable("ecdsa"), usable("rsa")]) };
    assert!(verdict(vec![revoked("ecdsa")]).may_replace(Some(&installed)));
}

#[test]
fn the_defect_of_an_offered_keybox_does_not_lower_its_rank() {
    // An offered keybox is written again as a well-formed one, so its markup does not count.
    let offered = KeyboxVerdict { defect: Some("invalid XML".to_string()), ..verdict(vec![usable("ecdsa")]) };
    assert!(offered.may_replace(Some(&verdict(vec![usable("ecdsa")]))));
}

#[test]
fn only_usable_keys_are_written_when_there_are_any() {
    assert_eq!(verdict(vec![revoked("rsa"), usable("ecdsa")]).keys_to_write(), [1]);
    assert_eq!(verdict(vec![usable("ecdsa"), usable("rsa")]).keys_to_write(), [0, 1]);
    // A keybox without a usable key keeps every key: a weak keybox the user chose is theirs.
    assert_eq!(verdict(vec![revoked("ecdsa"), revoked("rsa")]).keys_to_write(), [0, 1]);
}
