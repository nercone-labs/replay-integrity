use der::{Element, Integer, ObjectIdentifier, Reader, Tag, Time};

use crate::{Name, PublicKey, X509Error};

/// An algorithm and its parameters (RFC 5280 4.1.1.2), the parameters kept as their encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    pub fn from_element(element: &Element) -> Result<AlgorithmIdentifier, X509Error> {
        if element.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("an algorithm identifier is not a SEQUENCE"));
        }
        let mut reader = element.reader()?;
        let algorithm = reader.expect(Tag::OBJECT_IDENTIFIER)?.object_identifier()?;
        let parameters = if reader.is_empty() { None } else { Some(reader.read()?.encoded.to_vec()) };
        reader.finish()?;
        Ok(AlgorithmIdentifier { algorithm, parameters })
    }
}

/// A certificate extension (RFC 5280 4.1.2.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub id: ObjectIdentifier,
    pub critical: bool,
    /// The contents of the extnValue OCTET STRING: the encoding of the extension's value.
    pub value: Vec<u8>,
}

/// An X.509 certificate (RFC 5280 4.1), parsed but not verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The whole encoding of the certificate.
    pub der: Vec<u8>,
    /// The version number: 1, 2 or 3.
    pub version: u8,
    /// The serial number, as the contents of its INTEGER.
    pub serial: Vec<u8>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub issuer: Name,
    pub subject: Name,
    pub not_before: Time,
    pub not_after: Time,
    /// The encoding of the SubjectPublicKeyInfo.
    pub subject_public_key_info: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl Certificate {
    /// Parses the DER encoding of one certificate, which must fill `der` exactly.
    pub fn parse(der: &[u8]) -> Result<Certificate, X509Error> {
        let certificate = Element::parse(der)?;
        if certificate.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("a certificate is not a SEQUENCE"));
        }
        let mut outer = certificate.reader()?;
        let tbs = outer.expect(Tag::SEQUENCE)?;
        let signature_algorithm = AlgorithmIdentifier::from_element(&outer.read()?)?;
        outer.expect(Tag::BIT_STRING)?.bit_string()?;
        outer.finish()?;

        let mut fields = tbs.reader()?;
        let version = match fields.read_optional(Tag::context(0, true))? {
            None => 1,
            Some(explicit) => {
                let mut inner = explicit.reader()?;
                let number = inner.expect(Tag::INTEGER)?.integer()?.to_u64();
                inner.finish()?;
                match number {
                    // DER omits a DEFAULT value (X.690 11.5), so an explicit v1 is invalid.
                    Some(1) => 2,
                    Some(2) => 3,
                    _ => return Err(X509Error::Structure("an unknown certificate version")),
                }
            }
        };
        let serial = fields.expect(Tag::INTEGER)?.integer()?.bytes.to_vec();
        let inner_algorithm = AlgorithmIdentifier::from_element(&fields.read()?)?;
        if inner_algorithm != signature_algorithm {
            // RFC 5280 4.1.1.2: the two fields MUST be identical.
            return Err(X509Error::Structure("the signature algorithms of the certificate and its contents differ"));
        }
        let issuer = Name::from_element(&fields.read()?)?;
        let validity = fields.expect(Tag::SEQUENCE)?;
        let mut validity = validity.reader()?;
        let not_before = validity.read()?.time()?;
        let not_after = validity.read()?.time()?;
        validity.finish()?;
        let subject = Name::from_element(&fields.read()?)?;
        let key = fields.expect(Tag::SEQUENCE)?;
        PublicKey::from_subject_public_key_info(key.encoded)?;
        let subject_public_key_info = key.encoded.to_vec();
        // issuerUniqueID and subjectUniqueID (RFC 5280 4.1.2.8): only versions 2 and 3 may carry them.
        let unique_ids = fields.read_optional(Tag::context(1, false))?.is_some() | fields.read_optional(Tag::context(2, false))?.is_some();
        if version == 1 && unique_ids {
            return Err(X509Error::Structure("a version 1 certificate must not carry unique identifiers"));
        }
        let extensions = match fields.read_optional(Tag::context(3, true))? {
            None => Vec::new(),
            Some(explicit) => {
                if version != 3 {
                    return Err(X509Error::Structure("only version 3 certificates have extensions"));
                }
                let mut inner = explicit.reader()?;
                let list = inner.expect(Tag::SEQUENCE)?;
                inner.finish()?;
                Certificate::parse_extensions(list.reader()?)?
            }
        };
        fields.finish()?;
        Ok(Certificate { der: der.to_vec(), version, serial, signature_algorithm, issuer, subject, not_before, not_after, subject_public_key_info, extensions })
    }

    fn parse_extensions(mut list: Reader) -> Result<Vec<Extension>, X509Error> {
        let mut extensions: Vec<Extension> = Vec::new();
        while !list.is_empty() {
            let extension = list.expect(Tag::SEQUENCE)?;
            let mut fields = extension.reader()?;
            let id = fields.expect(Tag::OBJECT_IDENTIFIER)?.object_identifier()?;
            let critical = match fields.read_optional(Tag::BOOLEAN)? {
                // DER omits the DEFAULT FALSE.
                Some(element) if element.boolean()? => true,
                Some(_) => return Err(X509Error::Structure("an extension encodes the default criticality")),
                None => false,
            };
            let value = fields.expect(Tag::OCTET_STRING)?.octet_string()?.to_vec();
            fields.finish()?;
            // RFC 5280 4.2: a certificate MUST NOT include more than one instance of an extension.
            if extensions.iter().any(|existing| existing.id == id) {
                return Err(X509Error::Structure("an extension appears twice"));
            }
            extensions.push(Extension { id, critical, value });
        }
        Ok(extensions)
    }

    /// Parses every CERTIFICATE block of PEM text, in order.
    pub fn parse_pem(text: &str) -> Result<Vec<Certificate>, X509Error> {
        crate::Pem::parse_all(text)?.into_iter().filter(|block| block.label == crate::Pem::CERTIFICATE).map(|block| Certificate::parse(&block.data)).collect()
    }

    /// The serial number in lowercase hexadecimal without leading zeros, the form of the
    /// Android attestation status list.
    pub fn serial_hex(&self) -> String {
        Integer::new(&self.serial).ok().and_then(|serial| serial.to_hex()).unwrap_or_default()
    }

    pub fn public_key(&self) -> PublicKey {
        // Checked by `parse`.
        PublicKey::from_subject_public_key_info(&self.subject_public_key_info).expect("the public key was checked when parsing")
    }

    pub fn extension(&self, id: &[u64]) -> Option<&Extension> {
        self.extensions.iter().find(|extension| extension.id.is(id))
    }

    /// Whether `time` is inside the validity period, both ends included (RFC 5280 4.1.2.5).
    pub fn is_valid_at(&self, time: Time) -> bool {
        self.not_before <= time && time <= self.not_after
    }

    /// Whether this certificate names `issuer` as its issuer.
    pub fn is_issued_by(&self, issuer: &Certificate) -> bool {
        self.issuer == issuer.subject
    }
}
