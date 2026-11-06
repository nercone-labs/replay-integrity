use std::fmt::Write;

use crate::DERError;

/// The contents of an INTEGER, a two's complement number of any size (X.690 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Integer<'a> {
    pub bytes: &'a [u8],
}

impl<'a> Integer<'a> {
    /// Checks that `bytes` are a minimal two's complement encoding.
    pub fn new(bytes: &'a [u8]) -> Result<Integer<'a>, DERError> {
        match bytes {
            [] => Err(DERError::InvalidValue("an INTEGER has no contents")),
            [0x00, next, ..] if next & 0x80 == 0 => Err(DERError::InvalidValue("an INTEGER is not minimal")),
            [0xff, next, ..] if next & 0x80 != 0 => Err(DERError::InvalidValue("an INTEGER is not minimal")),
            _ => Ok(Integer { bytes }),
        }
    }

    pub fn is_negative(&self) -> bool {
        self.bytes[0] & 0x80 != 0
    }

    /// The bytes of a non-negative number without the leading zero byte of the sign.
    pub fn magnitude(&self) -> &'a [u8] {
        match self.bytes {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            bytes => bytes,
        }
    }

    /// The value, if it is non-negative and fits.
    pub fn to_u64(&self) -> Option<u64> {
        if self.is_negative() || self.magnitude().len() > 8 {
            return None;
        }
        Some(self.magnitude().iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
    }

    /// The value, if it fits.
    pub fn to_i64(&self) -> Option<i64> {
        if self.bytes.len() > 8 {
            return None;
        }
        let start: i64 = if self.is_negative() { -1 } else { 0 };
        Some(self.bytes.iter().fold(start, |value, byte| (value << 8) | i64::from(*byte)))
    }

    /// A non-negative number in lowercase hexadecimal without leading zeros, as certificate
    /// serial numbers are commonly written; `None` for a negative number.
    pub fn to_hex(&self) -> Option<String> {
        if self.is_negative() {
            return None;
        }
        let mut text = String::with_capacity(self.magnitude().len() * 2);
        for byte in self.magnitude() {
            let _ = write!(text, "{byte:02x}");
        }
        let trimmed = text.trim_start_matches('0');
        Some(if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() })
    }
}
