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
    /// Why the text is not a well-formed keybox (`KeyboxDocument::defect`), when its keys were
    /// recovered from broken markup. A keystore daemon that parses XML strictly reads no key
    /// from such a file, so it must not be installed as it is.
    pub defect: Option<String>,
}

impl KeyboxVerdict {
    /// Whether the keybox can reach STRONG: it has a usable EC key and the daemon can read it.
    ///
    /// Play Integrity attests with an EC key. An RSA key is not needed: TEESimulator-RS signs a
    /// request for an RSA key with the EC key when the keybox has no RSA key, and the keyboxes
    /// that mirrors serve now are often EC only. An RSA key that is present is still checked
    /// and reported.
    pub fn is_strong_capable(&self) -> bool {
        self.defect.is_none() && self.has_usable(KeyAlgorithm::ECDSA)
    }

    pub fn has_usable(&self, algorithm: KeyAlgorithm) -> bool {
        self.keys.iter().any(|key| key.algorithm == algorithm.name() && key.is_usable())
    }

    /// Whether the keybox is worth installing: it has at least one key and no key whose private
    /// key disagrees with its certificate. Trust, validity and revocation are reported but do
    /// not block installation, so a user may install a keybox the verdict flags as weak.
    pub fn is_installable(&self) -> bool {
        !self.keys.is_empty() && !self.keys.iter().any(|key| key.problems.contains(&KeyProblem::KeyMismatch))
    }

    /// How good the keys of the keybox are, for comparing two: whether one is a usable EC key,
    /// then how many are usable. `defect` is left out, because a keybox is written again as a
    /// well-formed one before it is installed. Expiry is left out on purpose: a mirror replaces
    /// a keybox before it leaks, not when it expires, so a newer keybox that expires sooner is
    /// not worse.
    pub fn rank(&self) -> (bool, usize) {
        (self.has_usable(KeyAlgorithm::ECDSA), self.usable_keys())
    }

    /// Whether this keybox may replace `installed` without making the device worse off: none
    /// is installed, the installed file is not well-formed (the daemon reads no key from it),
    /// or this one ranks at least as high.
    pub fn may_replace(&self, installed: Option<&KeyboxVerdict>) -> bool {
        installed.is_none_or(|installed| installed.defect.is_some() || self.rank() >= installed.rank())
    }

    /// The indices of the keys worth writing: the usable ones when there are any, so that the
    /// daemon never picks a revoked or untrusted key over a usable one; otherwise every key,
    /// because a weak keybox the user chose is still theirs to install.
    pub fn keys_to_write(&self) -> Vec<usize> {
        let usable: Vec<usize> = self.keys.iter().enumerate().filter(|(_, key)| key.is_usable()).map(|(index, _)| index).collect();
        if usable.is_empty() { (0..self.keys.len()).collect() } else { usable }
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
        KeyboxVerdict {
            keys: keybox.keys().map(|key| self.check_key(key, now)).collect(),
            revocation_checked: self.status.is_some(),
            defect: keybox.defect.clone(),
        }
    }
}
