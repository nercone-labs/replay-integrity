use std::fmt;

use x509::X509Error;

#[derive(Debug)]
pub enum KeyboxError {
    /// The text is not well-formed XML.
    Syntax(String),
    /// The XML is well-formed, but not a keybox document.
    Structure(String),
    /// A key or a certificate cannot be read.
    X509(X509Error),
}

impl KeyboxError {
    pub fn structure(message: impl Into<String>) -> KeyboxError {
        KeyboxError::Structure(message.into())
    }
}

impl fmt::Display for KeyboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyboxError::Syntax(message) => write!(formatter, "invalid XML: {message}"),
            KeyboxError::Structure(message) => write!(formatter, "not a keybox: {message}"),
            KeyboxError::X509(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for KeyboxError {}

impl From<X509Error> for KeyboxError {
    fn from(error: X509Error) -> KeyboxError {
        KeyboxError::X509(error)
    }
}
