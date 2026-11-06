use der::Time;
use serde::Serialize;
use x509::Certificate;

use crate::{AttestationError, CertificateStatus, KeyDescription, StatusList, TrustAnchors};

/// A reason why a chain is not acceptable.
// The discriminant field is `detail`, not `kind`: this enum is nested inside `replay`'s
// `KeyProblem`, which is itself tagged `kind`, and two `kind` fields in one object would collide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "detail", rename_all = "camelCase")]
pub enum ChainProblem {
    /// The chain has no certificates.
    Empty,
    /// The certificate at `index` does not name the next one as its issuer.
    BrokenLink { index: usize },
    /// The last certificate is not issued by itself.
    NotSelfIssued,
    /// The root does not hold a public key of the trust anchors.
    UntrustedRoot { subject: String },
    /// The certificate at `index` is not valid yet.
    NotYetValid { index: usize, not_before: i64 },
    /// The certificate at `index` has expired.
    Expired { index: usize, not_after: i64 },
    /// The status list lists the certificate at `index`.
    Revoked { index: usize, serial: String, status: CertificateStatus, reason: Option<String> },
}

/// A certificate chain, from the end-entity (or lowest) certificate to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub certificates: Vec<Certificate>,
}

impl Chain {
    pub fn new(certificates: Vec<Certificate>) -> Chain {
        Chain { certificates }
    }

    pub fn root(&self) -> Option<&Certificate> {
        self.certificates.last()
    }

    /// Whether the validity periods of the chain must be checked. Google trusts factory keys
    /// after their certificates expire: chains to the RSA root (`SERIALNUMBER=f92009e853b6b045`)
    /// without the provisioning information extension. Every other chain, in particular one of
    /// a remotely provisioned key, must be within its validity periods.
    pub fn requires_validity(&self) -> bool {
        let factory_root =
            self.root().and_then(|root| root.subject.attribute(&[2, 5, 4, 5])).is_some_and(|serial| serial == TrustAnchors::FACTORY_ROOT_SERIAL_NUMBER);
        let provisioned = self.certificates.iter().any(|certificate| certificate.extension(KeyDescription::PROVISIONING_INFORMATION).is_some());
        !factory_root || provisioned
    }

    /// Every problem of the chain at `now`. Without a status list, revocation is not checked.
    pub fn problems(&self, now: Time, status: Option<&StatusList>, anchors: &TrustAnchors) -> Vec<ChainProblem> {
        let Some(root) = self.root() else { return vec![ChainProblem::Empty] };
        let mut problems = Vec::new();
        for (index, pair) in self.certificates.windows(2).enumerate() {
            if !pair[0].is_issued_by(&pair[1]) {
                problems.push(ChainProblem::BrokenLink { index });
            }
        }
        if !root.is_issued_by(root) {
            problems.push(ChainProblem::NotSelfIssued);
        }
        if !anchors.trusts(root) {
            problems.push(ChainProblem::UntrustedRoot { subject: root.subject.to_string() });
        }
        let validity = self.requires_validity();
        for (index, certificate) in self.certificates.iter().enumerate() {
            if validity && now < certificate.not_before {
                problems.push(ChainProblem::NotYetValid { index, not_before: certificate.not_before.seconds });
            }
            if validity && now > certificate.not_after {
                problems.push(ChainProblem::Expired { index, not_after: certificate.not_after.seconds });
            }
            if let Some(entry) = status.and_then(|status| status.status_of(&certificate.serial_hex())) {
                problems.push(ChainProblem::Revoked { index, serial: certificate.serial_hex(), status: entry.status, reason: entry.reason.clone() });
            }
        }
        problems
    }

    /// The earliest end of a validity period in the chain: when the chain stops being valid.
    pub fn expires(&self) -> Option<Time> {
        self.certificates.iter().map(|certificate| certificate.not_after).min()
    }

    /// The attestation extension nearest the root, with the index of its certificate. Only
    /// that occurrence was issued by the secure hardware; later ones may have been added by
    /// anyone who extended the chain.
    pub fn key_description(&self) -> Result<Option<(usize, KeyDescription)>, AttestationError> {
        for (index, certificate) in self.certificates.iter().enumerate().rev() {
            if let Some(extension) = certificate.extension(KeyDescription::EXTENSION) {
                return Ok(Some((index, KeyDescription::parse(&extension.value)?)));
            }
        }
        Ok(None)
    }
}
