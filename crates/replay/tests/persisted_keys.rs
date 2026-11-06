//! Tests of the reader of TEESimulator-RS's persisted key files. The bytes are built here to
//! the layout of `GeneratedKeyPersistence.save` (a Java `DataOutputStream`), not captured.

use std::io::Write;

use replay::PersistedKey;

/// Builds a persisted-key file of format version 3 with the given alias and certificate chain.
fn persisted_key(uid: u32, alias: &str, chain: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let int = |bytes: &mut Vec<u8>, value: i32| bytes.write_all(&value.to_be_bytes()).unwrap();
    int(&mut bytes, 3); // FORMAT_VERSION
    int(&mut bytes, 1); // securityLevel
    int(&mut bytes, uid as i32);
    // writeUTF: a 16-bit length then the bytes.
    bytes.write_all(&(alias.len() as u16).to_be_bytes()).unwrap();
    bytes.write_all(alias.as_bytes()).unwrap();
    bytes.write_all(&0u64.to_be_bytes()).unwrap(); // nspace
    bytes.push(0); // isAttestationKey
    int(&mut bytes, 3); // algorithm
    int(&mut bytes, 256); // keySize
    int(&mut bytes, 1); // ecCurve
    int(&mut bytes, 0); // purposes count
    int(&mut bytes, 0); // digests count
    int(&mut bytes, 0); // private key length
    int(&mut bytes, chain.len() as i32);
    for certificate in chain {
        int(&mut bytes, certificate.len() as i32);
        bytes.write_all(certificate).unwrap();
    }
    bytes
}

#[test]
fn a_persisted_key_is_read_with_its_chain() {
    let chain: &[&[u8]] = &[b"leaf-certificate", b"signer-certificate", b"root"];
    let bytes = persisted_key(10_123, "my-key", chain);
    let key = PersistedKey::parse(std::path::Path::new("x.bin"), &bytes).unwrap();
    assert_eq!(key.uid, 10_123);
    assert_eq!(key.alias, "my-key");
    assert_eq!(key.chain.len(), 3);
    // The signer is the second certificate: the attestation key of the keybox.
    assert_eq!(key.signer(), Some(&b"signer-certificate"[..]));
}

#[test]
fn a_key_is_stale_when_its_signer_is_not_a_current_keybox_certificate() {
    let bytes = persisted_key(10_001, "k", &[b"leaf", b"old-attestation-key", b"root"]);
    let key = PersistedKey::parse(std::path::Path::new("x.bin"), &bytes).unwrap();
    // Current keybox signs with "new-attestation-key": the key's old signer makes it stale.
    assert!(key.is_stale(&[&b"new-attestation-key"[..]]));
    // When the current keybox still has that signer, the key is not stale.
    assert!(!key.is_stale(&[&b"old-attestation-key"[..], &b"another"[..]]));
}

#[test]
fn another_format_version_is_skipped() {
    let mut bytes = persisted_key(1, "k", &[b"leaf", b"signer"]);
    // Change the version int (first four bytes) to 2.
    bytes[0..4].copy_from_slice(&2i32.to_be_bytes());
    assert!(PersistedKey::parse(std::path::Path::new("x.bin"), &bytes).is_none());
    // A truncated file is skipped, not a panic.
    assert!(PersistedKey::parse(std::path::Path::new("x.bin"), &bytes[..10]).is_none());
}
