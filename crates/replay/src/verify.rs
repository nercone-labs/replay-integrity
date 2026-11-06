use attestation::{Chain, ChainProblem, SecurityLevel, StatusList, TrustAnchors};
use der::Time;
use keybox::{KeyAlgorithm, KeyboxDocument, KeyboxKey};
use serde::Serialize;

/// Why a key of a keybox is not usable for a STRONG verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum KeyProblem {
    /// The private key does not belong to the first certificate of its chain.
    KeyMismatch,
    /// A problem of the certificate chain (link, validity, revocation, root).
    Chain(ChainProblem),
    /// A certificate carries an attestation extension that could not be parsed.
    MalformedAttestation,
    /// The chain attests a key that is not in secure hardware, so it cannot reach STRONG.
    NotHardwareBacked { level: SecurityLevel },
}

/// The result of checking one key of a keybox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyVerdict {
    pub algorithm: String,
    /// The serial number of the first certificate, in lowercase hexadecimal.
    pub serial: String,
    /// The subject of the root certificate.
    pub root: Option<String>,
    /// When the chain stops being valid, in seconds since the Unix epoch.
    pub expires: Option<i64>,
    pub problems: Vec<KeyProblem>,
}

impl KeyVerdict {
    /// Whether the key is usable now: no problems.
    pub fn is_usable(&self) -> bool {
        self.problems.is_empty()
    }
}

/// The result of checking a keybox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyboxVerdict {
    pub keys: Vec<KeyVerdict>,
    /// Whether the status list was available for the check.
    pub revocation_checked: bool,
}

impl KeyboxVerdict {
    /// Whether the keybox has a usable EC key and a usable RSA key: Play Integrity attests with
    /// an EC key, and some checks use RSA, so a keybox that keeps STRONG needs both.
    pub fn is_strong_capable(&self) -> bool {
        self.has_usable(KeyAlgorithm::ECDSA) && self.has_usable(KeyAlgorithm::RSA)
    }

    pub fn has_usable(&self, algorithm: KeyAlgorithm) -> bool {
        self.keys.iter().any(|key| key.algorithm == algorithm.name() && key.is_usable())
    }

    /// Whether the keybox is worth installing: it has at least one key and no key whose private
    /// key disagrees with its certificate. Trust, validity and revocation are reported but do
    /// not block installation, so a user may install a keybox the verdict flags as weak; the
    /// repair uses `is_strong_capable` to decide when to replace it.
    pub fn is_installable(&self) -> bool {
        !self.keys.is_empty() && !self.keys.iter().any(|key| key.problems.contains(&KeyProblem::KeyMismatch))
    }

    /// The soonest a usable key stops being valid: when the keybox needs replacing.
    pub fn expires(&self) -> Option<i64> {
        self.keys.iter().filter(|key| key.is_usable()).filter_map(|key| key.expires).min()
    }

    pub fn usable_keys(&self) -> usize {
        self.keys.iter().filter(|key| key.is_usable()).count()
    }
}

/// Checks keyboxes against the Google trust anchors and the certificate status list.
pub struct Verifier {
    pub anchors: TrustAnchors,
    pub status: Option<StatusList>,
}

impl Verifier {
    pub fn new(status: Option<StatusList>) -> Verifier {
        Verifier { anchors: TrustAnchors::google(), status }
    }

    /// Checks one key: that the private key matches its certificate, that the chain is sound at
    /// `now`, and that the attested key is in secure hardware.
    pub fn check_key(&self, key: &KeyboxKey, now: Time) -> KeyVerdict {
        let mut problems = Vec::new();
        if key.matches_certificate() == Some(false) {
            problems.push(KeyProblem::KeyMismatch);
        }
        let chain = Chain::new(key.certificates.clone());
        for problem in chain.problems(now, self.status.as_ref(), &self.anchors) {
            problems.push(KeyProblem::Chain(problem));
        }
        match chain.key_description() {
            Ok(Some((_, description))) => {
                let level = description.attestation_security_level;
                if !level.is_hardware() {
                    problems.push(KeyProblem::NotHardwareBacked { level });
                }
            }
            // A keybox certificate need not carry an attestation extension; its absence is not a
            // problem. (Google's own attestation batch certificates do not.)
            Ok(None) => {}
            Err(_) => problems.push(KeyProblem::MalformedAttestation),
        }
        KeyVerdict {
            algorithm: key.algorithm.name().to_string(),
            serial: key.certificates.first().map(|certificate| certificate.serial_hex()).unwrap_or_default(),
            root: chain.root().map(|root| root.subject.to_string()),
            expires: chain.expires().map(|time| time.seconds),
            problems,
        }
    }

    pub fn check(&self, keybox: &KeyboxDocument, now: Time) -> KeyboxVerdict {
        KeyboxVerdict { keys: keybox.keys().map(|key| self.check_key(key, now)).collect(), revocation_checked: self.status.is_some() }
    }
}
