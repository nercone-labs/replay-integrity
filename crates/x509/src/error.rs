use std::fmt;

use der::DERError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X509Error {
    /// The data is not valid DER.
    DER(DERError),
    /// The DER is valid, but not of the expected structure.
    Structure(&'static str),
    /// The text is not valid PEM.
    PEM(&'static str),
    /// A key algorithm that is not supported.
    UnsupportedAlgorithm(String),
}

impl fmt::Display for X509Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X509Error::DER(error) => write!(formatter, "invalid DER: {error}"),
            X509Error::Structure(reason) => write!(formatter, "invalid structure: {reason}"),
            X509Error::PEM(reason) => write!(formatter, "invalid PEM: {reason}"),
            X509Error::UnsupportedAlgorithm(oid) => write!(formatter, "unsupported key algorithm {oid}"),
        }
    }
}

impl std::error::Error for X509Error {}

impl From<DERError> for X509Error {
    fn from(error: DERError) -> X509Error {
        X509Error::DER(error)
    }
}
