use x509::{Certificate, Pem};

use crate::AttestationError;

/// Root certificates that attestation chains may end in, recognized by their public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchors {
    pub roots: Vec<Certificate>,
}

impl TrustAnchors {
    /// The JSON array of PEM certificates that Google publishes.
    pub const URL: &'static str = "https://android.googleapis.com/attestation/root";
    /// The roots that developer.android.com lists, as of the release of this crate.
    pub const GOOGLE_PEM: &'static str = include_str!("../roots/google.pem");
    /// The serial number attribute of the subject of the RSA root of Google. Chains to it that
    /// carry no provisioning information hold factory keys, which Google trusts after their
    /// certificates expire.
    pub const FACTORY_ROOT_SERIAL_NUMBER: &'static str = "f92009e853b6b045";

    pub fn google() -> TrustAnchors {
        TrustAnchors { roots: Certificate::parse_pem(TrustAnchors::GOOGLE_PEM).expect("the embedded roots are valid") }
    }

    /// Parses the published JSON array of PEM certificates.
    pub fn from_json(json: &str) -> Result<TrustAnchors, AttestationError> {
        let texts: Vec<String> = serde_json::from_str(json)?;
        let mut roots = Vec::new();
        for text in texts {
            for block in Pem::parse_all(&text)? {
                if block.label == Pem::CERTIFICATE {
                    roots.push(Certificate::parse(&block.data)?);
                }
            }
        }
        if roots.is_empty() {
            return Err(AttestationError::Structure("the trust anchor list is empty"));
        }
        Ok(TrustAnchors { roots })
    }

    /// Whether `certificate` holds the public key of one of the roots.
    pub fn trusts(&self, certificate: &Certificate) -> bool {
        self.roots.iter().any(|root| root.subject_public_key_info == certificate.subject_public_key_info)
    }
}
