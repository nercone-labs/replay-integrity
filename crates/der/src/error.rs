use std::fmt;

use crate::Tag;

/// Data that is not valid DER, or not of the expected structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DERError {
    /// The data ends inside an element.
    Truncated,
    /// A length is not in the shortest form, or does not fit the platform.
    InvalidLength,
    /// The indefinite-length form, which DER forbids.
    IndefiniteLength,
    /// A tag number is not in the shortest form, or is too large.
    InvalidTag,
    UnexpectedTag {
        expected: Tag,
        found: Tag,
    },
    /// The contents of an element are not a valid value of its type.
    InvalidValue(&'static str),
    /// Data follows the last expected element.
    TrailingData,
}

impl fmt::Display for DERError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DERError::Truncated => formatter.write_str("the data ends inside an element"),
            DERError::InvalidLength => formatter.write_str("invalid length"),
            DERError::IndefiniteLength => formatter.write_str("indefinite lengths are not allowed in DER"),
            DERError::InvalidTag => formatter.write_str("invalid tag"),
            DERError::UnexpectedTag { expected, found } => write!(formatter, "expected {expected}, found {found}"),
            DERError::InvalidValue(reason) => write!(formatter, "invalid value: {reason}"),
            DERError::TrailingData => formatter.write_str("unexpected data after the last element"),
        }
    }
}

impl std::error::Error for DERError {}
