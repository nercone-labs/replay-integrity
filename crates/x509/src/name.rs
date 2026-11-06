use der::{Element, ObjectIdentifier, Tag};

use crate::X509Error;

/// A distinguished name (RFC 5280 4.1.2.4), kept as its encoding. Names are compared by their
/// encoding, which certificate authorities keep identical between a certificate's issuer and
/// the subject of the certificate that issued it (RFC 5280 7.1 allows nothing simpler to be
/// relied on in general, but every chain this crate is used for satisfies it).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    pub der: Vec<u8>,
}

impl Name {
    /// The short names of the attribute types of RFC 4519 that are common in certificates.
    pub const SHORT_NAMES: [(&'static [u64], &'static str); 9] = [
        (&[2, 5, 4, 3], "CN"),
        (&[2, 5, 4, 5], "serialNumber"),
        (&[2, 5, 4, 6], "C"),
        (&[2, 5, 4, 7], "L"),
        (&[2, 5, 4, 8], "ST"),
        (&[2, 5, 4, 10], "O"),
        (&[2, 5, 4, 11], "OU"),
        (&[2, 5, 4, 12], "title"),
        (&[1, 2, 840, 113549, 1, 9, 1], "emailAddress"),
    ];

    /// Checks that `element` is an RDNSequence.
    pub fn from_element(element: &Element) -> Result<Name, X509Error> {
        if element.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("a name is not a SEQUENCE"));
        }
        let name = Name { der: element.encoded.to_vec() };
        name.attributes()?;
        Ok(name)
    }

    /// The attributes, in order of encoding, as (type, value) pairs. Values of string types
    /// that cannot be shown are given as `#` and their encoding in hexadecimal (RFC 4514 2.4).
    pub fn attributes(&self) -> Result<Vec<(ObjectIdentifier, String)>, X509Error> {
        let mut attributes = Vec::new();
        let mut sequence = Element::parse(&self.der)?.reader()?;
        while !sequence.is_empty() {
            let set = sequence.expect(Tag::SET)?;
            let mut set = set.reader()?;
            while !set.is_empty() {
                let pair = set.expect(Tag::SEQUENCE)?;
                let mut pair = pair.reader()?;
                let kind = pair.expect(Tag::OBJECT_IDENTIFIER)?.object_identifier()?;
                let value = pair.read()?;
                pair.finish()?;
                let text = value.string().unwrap_or_else(|_| format!("#{}", value.encoded.iter().map(|byte| format!("{byte:02x}")).collect::<String>()));
                attributes.push((kind, text));
            }
        }
        Ok(attributes)
    }

    /// The value of the first attribute of type `kind`.
    pub fn attribute(&self, kind: &[u64]) -> Option<String> {
        self.attributes().ok()?.into_iter().find(|(oid, _)| oid.is(kind)).map(|(_, value)| value)
    }

    pub fn common_name(&self) -> Option<String> {
        self.attribute(&[2, 5, 4, 3])
    }
}

impl std::fmt::Display for Name {
    /// Writes the attributes in order of encoding, as `O=Google LLC, CN=Droid CA3`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Ok(attributes) = self.attributes() else { return formatter.write_str("(invalid name)") };
        for (index, (kind, value)) in attributes.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            match Name::SHORT_NAMES.iter().find(|(arcs, _)| kind.is(arcs)) {
                Some((_, short)) => write!(formatter, "{short}={value}")?,
                None => write!(formatter, "{kind}={value}")?,
            }
        }
        Ok(())
    }
}
