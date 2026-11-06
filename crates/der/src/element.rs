use crate::{DERError, Integer, ObjectIdentifier, Reader, Tag, Time};

/// One element: its tag, its contents, and its whole encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    pub tag: Tag,
    pub contents: &'a [u8],
    /// The identifier, the length and the contents.
    pub encoded: &'a [u8],
}

/// The contents of a BIT STRING (X.690 8.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitString<'a> {
    /// The number of unused bits in the last byte, 0 to 7.
    pub unused_bits: u8,
    pub bytes: &'a [u8],
}

impl<'a> Element<'a> {
    /// Parses exactly one element that fills `data`.
    pub fn parse(data: &'a [u8]) -> Result<Element<'a>, DERError> {
        let (element, length) = Reader::parse(data)?;
        if length != data.len() {
            return Err(DERError::TrailingData);
        }
        Ok(element)
    }

    /// A reader of the elements inside a constructed element.
    pub fn reader(&self) -> Result<Reader<'a>, DERError> {
        if !self.tag.constructed {
            return Err(DERError::InvalidValue("a primitive element has no inner elements"));
        }
        Ok(Reader::new(self.contents))
    }

    fn require(&self, tag: Tag) -> Result<(), DERError> {
        if self.tag.number != tag.number || self.tag.class != tag.class || self.tag.constructed != tag.constructed {
            return Err(DERError::UnexpectedTag { expected: tag, found: self.tag });
        }
        Ok(())
    }

    /// The value of a BOOLEAN; DER encodes TRUE as 0xff (X.690 11.1).
    pub fn boolean(&self) -> Result<bool, DERError> {
        self.require(Tag::BOOLEAN)?;
        match self.contents {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DERError::InvalidValue("a BOOLEAN is not 0x00 or 0xff")),
        }
    }

    pub fn integer(&self) -> Result<Integer<'a>, DERError> {
        self.require(Tag::INTEGER)?;
        Integer::new(self.contents)
    }

    /// The value of an ENUMERATED, which is encoded like an INTEGER.
    pub fn enumerated(&self) -> Result<i64, DERError> {
        self.require(Tag::ENUMERATED)?;
        Integer::new(self.contents)?.to_i64().ok_or(DERError::InvalidValue("an ENUMERATED is too large"))
    }

    /// The contents of an INTEGER of a type that is not a universal INTEGER, such as an
    /// implicitly tagged one, after checking that they are a valid INTEGER.
    pub fn integer_contents(&self) -> Result<Integer<'a>, DERError> {
        if self.tag.constructed {
            return Err(DERError::InvalidValue("an INTEGER is primitive"));
        }
        Integer::new(self.contents)
    }

    pub fn octet_string(&self) -> Result<&'a [u8], DERError> {
        self.require(Tag::OCTET_STRING)?;
        Ok(self.contents)
    }

    pub fn bit_string(&self) -> Result<BitString<'a>, DERError> {
        self.require(Tag::BIT_STRING)?;
        let (&unused_bits, bytes) = self.contents.split_first().ok_or(DERError::InvalidValue("a BIT STRING has no contents"))?;
        if unused_bits > 7 || (bytes.is_empty() && unused_bits != 0) {
            return Err(DERError::InvalidValue("a BIT STRING has an invalid number of unused bits"));
        }
        if let Some(last) = bytes.last()
            && last & ((1u8 << unused_bits) - 1) != 0
        {
            return Err(DERError::InvalidValue("the unused bits of a BIT STRING are not zero"));
        }
        Ok(BitString { unused_bits, bytes })
    }

    pub fn object_identifier(&self) -> Result<ObjectIdentifier, DERError> {
        self.require(Tag::OBJECT_IDENTIFIER)?;
        ObjectIdentifier::decode(self.contents)
    }

    pub fn null(&self) -> Result<(), DERError> {
        self.require(Tag::NULL)?;
        if self.contents.is_empty() { Ok(()) } else { Err(DERError::InvalidValue("a NULL has contents")) }
    }

    /// A UTCTime or a GeneralizedTime.
    pub fn time(&self) -> Result<Time, DERError> {
        if self.tag == Tag::UTC_TIME {
            Time::from_utc_time(self.contents)
        } else if self.tag == Tag::GENERALIZED_TIME {
            Time::from_generalized_time(self.contents)
        } else {
            Err(DERError::UnexpectedTag { expected: Tag::UTC_TIME, found: self.tag })
        }
    }

    /// The text of a character string type whose characters are a subset of UTF-8:
    /// UTF8String, PrintableString, IA5String and TeletexString (read as Latin-1 when it is not
    /// ASCII, the common practice of certificate authorities). Other string types are rejected.
    pub fn string(&self) -> Result<String, DERError> {
        if self.tag == Tag::UTF8_STRING {
            std::str::from_utf8(self.contents).map(str::to_string).map_err(|_| DERError::InvalidValue("a UTF8String is not UTF-8"))
        } else if self.tag == Tag::PRINTABLE_STRING || self.tag == Tag::IA5_STRING {
            if self.contents.is_ascii() {
                Ok(String::from_utf8_lossy(self.contents).into_owned())
            } else {
                Err(DERError::InvalidValue("an ASCII string has non-ASCII characters"))
            }
        } else if self.tag == Tag::TELETEX_STRING {
            Ok(self.contents.iter().map(|byte| char::from(*byte)).collect())
        } else {
            Err(DERError::UnexpectedTag { expected: Tag::UTF8_STRING, found: self.tag })
        }
    }
}
