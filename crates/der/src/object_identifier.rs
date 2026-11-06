use std::fmt;

use crate::DERError;

/// An OBJECT IDENTIFIER, as its sequence of arcs (X.690 8.19).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier {
    pub arcs: Vec<u64>,
}

impl ObjectIdentifier {
    pub fn new(arcs: &[u64]) -> ObjectIdentifier {
        ObjectIdentifier { arcs: arcs.to_vec() }
    }

    /// Decodes the contents of an OBJECT IDENTIFIER element.
    pub fn decode(contents: &[u8]) -> Result<ObjectIdentifier, DERError> {
        if contents.is_empty() {
            return Err(DERError::InvalidValue("an OBJECT IDENTIFIER has no contents"));
        }
        let mut values = Vec::new();
        let mut value: u64 = 0;
        let mut starting = true;
        for byte in contents {
            if starting && *byte == 0x80 {
                return Err(DERError::InvalidValue("an OBJECT IDENTIFIER arc is not minimal"));
            }
            if value > u64::MAX >> 7 {
                return Err(DERError::InvalidValue("an OBJECT IDENTIFIER arc is too large"));
            }
            value = (value << 7) | u64::from(byte & 0x7f);
            starting = byte & 0x80 == 0;
            if starting {
                values.push(value);
                value = 0;
            }
        }
        if !starting {
            return Err(DERError::InvalidValue("an OBJECT IDENTIFIER ends inside an arc"));
        }
        // The first value combines the first two arcs (8.19.4).
        let first = values[0];
        let mut arcs = Vec::with_capacity(values.len() + 1);
        match first {
            0..=39 => arcs.extend([0, first]),
            40..=79 => arcs.extend([1, first - 40]),
            _ => arcs.extend([2, first - 80]),
        }
        arcs.extend_from_slice(&values[1..]);
        Ok(ObjectIdentifier { arcs })
    }

    /// Whether this identifier has the arcs `arcs`.
    pub fn is(&self, arcs: &[u64]) -> bool {
        self.arcs == arcs
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, arc) in self.arcs.iter().enumerate() {
            if index > 0 {
                formatter.write_str(".")?;
            }
            write!(formatter, "{arc}")?;
        }
        Ok(())
    }
}
