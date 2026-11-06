//! X.509 certificates as RFC 5280 profiles them, the public and private keys they hold, and the
//! PEM text encoding of RFC 7468.
//!
//! Certificates are parsed, not verified: signatures are not checked. What a parsed certificate
//! offers is its fields, so that a caller can compare them (issuer and subject names, validity,
//! serial numbers, public keys) with what it expects.

mod certificate;
mod error;
mod key;
mod name;
mod pem;

pub use certificate::{AlgorithmIdentifier, Certificate, Extension};
pub use error::X509Error;
pub use key::{PrivateKey, PublicKey};
pub use name::Name;
pub use pem::Pem;
