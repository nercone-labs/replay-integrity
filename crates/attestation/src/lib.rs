//! Android key attestation (https://source.android.com/docs/security/features/keystore/attestation
//! and https://developer.android.com/privacy-and-security/security-key-attestation):
//!
//! - `KeyDescription` parses the attestation extension of a certificate.
//! - `TrustAnchors` holds the root certificates of Google, compared by public key.
//! - `StatusList` is the certificate revocation status list of Google.
//! - `Chain` checks a certificate chain: links, validity, revocation and the root.
//!
//! Signatures are not verified. The checks tell whether a chain is shaped as Google requires,
//! which is what a device needs to know about the chains it hands out; they are not a
//! replacement for verification on a trusted server.

mod chain;
mod error;
mod key_description;
mod status;
mod trust;

pub use chain::{Chain, ChainProblem};
pub use error::AttestationError;
pub use key_description::{AuthorizationList, KeyDescription, RootOfTrust, SecurityLevel, VerifiedBootState};
pub use status::{CertificateStatus, StatusEntry, StatusList};
pub use trust::TrustAnchors;
