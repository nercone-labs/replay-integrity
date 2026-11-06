use std::fmt;

use der::DERError;
use x509::X509Error;

#[derive(Debug)]
pub enum AttestationError {
    DER(DERError),
    X509(X509Error),
    /// The data is valid DER, but not of the structure of the schema.
    Structure(&'static str),
    /// A status list or trust anchor list that is not valid JSON of the documented format.
    JSON(serde_json::Error),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::DER(error) => write!(formatter, "invalid DER: {error}"),
            AttestationError::X509(error) => write!(formatter, "{error}"),
            AttestationError::Structure(reason) => write!(formatter, "invalid attestation data: {reason}"),
            AttestationError::JSON(error) => write!(formatter, "invalid JSON: {error}"),
        }
    }
}

impl std::error::Error for AttestationError {}

impl From<DERError> for AttestationError {
    fn from(error: DERError) -> AttestationError {
        AttestationError::DER(error)
    }
}

impl From<X509Error> for AttestationError {
    fn from(error: X509Error) -> AttestationError {
        AttestationError::X509(error)
    }
}

impl From<serde_json::Error> for AttestationError {
    fn from(error: serde_json::Error) -> AttestationError {
        AttestationError::JSON(error)
    }
}
