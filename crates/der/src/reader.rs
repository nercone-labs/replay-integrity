use crate::{DERError, Element, Tag, TagClass};

/// Reads consecutive elements from DER data.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, position: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.position >= self.data.len()
    }

    /// The data not read yet.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.position..]
    }

    /// Reads the next element.
    pub fn read(&mut self) -> Result<Element<'a>, DERError> {
        let (element, length) = Reader::parse(self.remaining())?;
        self.position += length;
        Ok(element)
    }

    /// Reads the next element, which must have `tag`.
    pub fn expect(&mut self, tag: Tag) -> Result<Element<'a>, DERError> {
        let element = self.read()?;
        if element.tag != tag {
            return Err(DERError::UnexpectedTag { expected: tag, found: element.tag });
        }
        Ok(element)
    }

    /// The tag of the next element, or `None` at the end.
    pub fn peek_tag(&self) -> Result<Option<Tag>, DERError> {
        if self.is_empty() {
            return Ok(None);
        }
        Reader::parse_tag(self.remaining()).map(|(tag, _)| Some(tag))
    }

    /// Reads the next element if it has `tag`; an absent optional element is `None`.
    pub fn read_optional(&mut self, tag: Tag) -> Result<Option<Element<'a>>, DERError> {
        if self.peek_tag()? == Some(tag) { self.read().map(Some) } else { Ok(None) }
    }

    /// Fails unless every element has been read.
    pub fn finish(&self) -> Result<(), DERError> {
        if self.is_empty() { Ok(()) } else { Err(DERError::TrailingData) }
    }

    /// Parses one element at the start of `data`, and returns it with its encoded length.
    pub fn parse(data: &'a [u8]) -> Result<(Element<'a>, usize), DERError> {
        let (tag, tag_length) = Reader::parse_tag(data)?;
        let (length, length_length) = Reader::parse_length(&data[tag_length..])?;
        let header = tag_length + length_length;
        let end = header.checked_add(length).ok_or(DERError::InvalidLength)?;
        if end > data.len() {
            return Err(DERError::Truncated);
        }
        Ok((Element { tag, contents: &data[header..end], encoded: &data[..end] }, end))
    }

    /// Parses an identifier (X.690 8.1.2), including the high-tag-number form.
    pub fn parse_tag(data: &[u8]) -> Result<(Tag, usize), DERError> {
        let first = *data.first().ok_or(DERError::Truncated)?;
        let class = match first >> 6 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            _ => TagClass::Private,
        };
        let constructed = first & 0x20 != 0;
        if first & 0x1f != 0x1f {
            return Ok((Tag { class, constructed, number: u32::from(first & 0x1f) }, 1));
        }
        let mut number: u32 = 0;
        for (index, byte) in data[1..].iter().enumerate() {
            // A leading 0x80 would be a longer encoding of a smaller number.
            if index == 0 && *byte == 0x80 {
                return Err(DERError::InvalidTag);
            }
            // Checked before the shift so a crafted overlong encoding cannot wrap past the limit.
            if number > Tag::MAX_NUMBER >> 7 {
                return Err(DERError::InvalidTag);
            }
            number = (number << 7) | u32::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                // Numbers below 31 must use the short form.
                if number < 0x1f {
                    return Err(DERError::InvalidTag);
                }
                return Ok((Tag { class, constructed, number }, index + 2));
            }
        }
        Err(DERError::Truncated)
    }

    /// Parses a definite length in its shortest form (X.690 8.1.3, 10.1).
    pub fn parse_length(data: &[u8]) -> Result<(usize, usize), DERError> {
        let first = *data.first().ok_or(DERError::Truncated)?;
        if first < 0x80 {
            return Ok((usize::from(first), 1));
        }
        if first == 0x80 {
            return Err(DERError::IndefiniteLength);
        }
        let count = usize::from(first & 0x7f);
        if count > std::mem::size_of::<usize>() || count == 0x7f {
            return Err(DERError::InvalidLength);
        }
        let bytes = data.get(1..1 + count).ok_or(DERError::Truncated)?;
        if bytes[0] == 0 {
            return Err(DERError::InvalidLength);
        }
        let length = bytes.iter().fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
        if length < 0x80 {
            return Err(DERError::InvalidLength);
        }
        Ok((length, 1 + count))
    }
}
