//! Tests of PEM decoding, certificate parsing and name formatting. The certificates are the
//! Google attestation roots that developer.android.com publishes, which are stable public data.

use x509::{Certificate, Name, Pem, PublicKey, X509Error};

/// The 2022 RSA attestation root of Google (shared public key with the 2016/2019/2021 roots).
const RSA_ROOT: &str = "-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----";

/// The EC attestation root "Key Attestation CA1".
const EC_ROOT: &str = "-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----";

#[test]
fn pem_blocks_are_read_in_order_despite_surrounding_text() {
    let text = format!("preamble\n{RSA_ROOT}\nbetween blocks\n{EC_ROOT}\ntrailer");
    let blocks = Pem::parse_all(&text).unwrap();
    assert_eq!(blocks.len(), 2);
    assert!(blocks.iter().all(|block| block.label == Pem::CERTIFICATE));
    // Round-trips: re-encoding and decoding gives the same bytes.
    let reencoded = Pem::parse_all(&blocks[0].encode()).unwrap();
    assert_eq!(reencoded[0].data, blocks[0].data);
    // Indented PEM, as keybox XML holds, is read too (RFC 7468 lax whitespace).
    let indented: String = RSA_ROOT.lines().map(|line| format!("        {line}\n")).collect();
    assert_eq!(Pem::parse_all(&indented).unwrap()[0].data, blocks[0].data);
}

#[test]
fn the_rsa_root_is_parsed_with_its_fields() {
    let certificate = Certificate::parse(&Pem::parse_all(RSA_ROOT).unwrap()[0].data).unwrap();
    assert_eq!(certificate.version, 3);
    // A root is self-issued.
    assert_eq!(certificate.issuer, certificate.subject);
    assert!(certificate.is_issued_by(&certificate));
    // The subject serial number is the one Google documents as the factory root.
    assert_eq!(certificate.subject.attribute(&[2, 5, 4, 5]).as_deref(), Some("f92009e853b6b045"));
    assert!(matches!(certificate.public_key(), PublicKey::RSA { .. }));
    // Its validity is 2022 to 2042.
    assert!(certificate.not_before.seconds < certificate.not_after.seconds);
    assert!(certificate.is_valid_at(der::Time { seconds: 1_800_000_000 }));
}

#[test]
fn the_ec_root_has_an_elliptic_curve_key_and_a_readable_name() {
    let certificate = Certificate::parse(&Pem::parse_all(EC_ROOT).unwrap()[0].data).unwrap();
    assert!(matches!(certificate.public_key(), PublicKey::EC { curve: Some(_), .. }));
    // The name is shown in order, with the short attribute names.
    assert_eq!(certificate.subject.to_string(), "CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US");
    assert_eq!(certificate.subject.common_name().as_deref(), Some("Key Attestation CA1"));
}

#[test]
fn a_subject_public_key_info_round_trips_through_the_name_type() {
    let certificate = Certificate::parse(&Pem::parse_all(EC_ROOT).unwrap()[0].data).unwrap();
    // A name parsed from its own encoding equals the original.
    assert_eq!(Name::from_element(&der::Element::parse(&certificate.subject.der).unwrap()).unwrap(), certificate.subject);
}

#[test]
fn garbage_is_rejected() {
    assert!(matches!(Certificate::parse(&[0x30, 0x00]), Err(X509Error::DER(_) | X509Error::Structure(_))));
    assert!(Pem::parse_all("-----BEGIN X-----\nnot base64 @@@\n-----END X-----").is_err());
    assert!(Certificate::parse_pem("no blocks here").unwrap().is_empty());
}
