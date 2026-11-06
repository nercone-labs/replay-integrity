//! A reader of data in the Distinguished Encoding Rules of ASN.1 (ITU-T X.690): tags, lengths
//! and the primitive types that certificates and other structures are made of.
//!
//! The reader borrows the data it reads; nothing is copied. It accepts only the definite-length
//! form and the shortest encodings that DER requires, so that every value has one encoding.

mod element;
mod error;
mod integer;
mod object_identifier;
mod reader;
mod tag;
mod time;

pub use element::{BitString, Element};
pub use error::DERError;
pub use integer::Integer;
pub use object_identifier::ObjectIdentifier;
pub use reader::Reader;
pub use tag::{Tag, TagClass};
pub use time::Time;
