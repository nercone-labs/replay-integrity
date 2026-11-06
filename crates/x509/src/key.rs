use der::{Element, ObjectIdentifier, Tag};

use crate::{AlgorithmIdentifier, Pem, X509Error};

/// A public key, by algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// An elliptic curve key (RFC 5480): the named curve and the encoded point.
    EC { curve: Option<ObjectIdentifier>, point: Vec<u8> },
    /// An RSA key (RFC 8017): the modulus and the exponent, without leading zeros.
    RSA { modulus: Vec<u8>, exponent: Vec<u8> },
    /// A key of another algorithm, as the contents of its BIT STRING.
    Other { algorithm: ObjectIdentifier, key: Vec<u8> },
}

impl PublicKey {
    pub const EC_PUBLIC_KEY: &'static [u64] = &[1, 2, 840, 10045, 2, 1];
    pub const RSA_ENCRYPTION: &'static [u64] = &[1, 2, 840, 113549, 1, 1, 1];

    /// Parses a SubjectPublicKeyInfo (RFC 5280 4.1.2.7).
    pub fn from_subject_public_key_info(der: &[u8]) -> Result<PublicKey, X509Error> {
        let info = Element::parse(der)?;
        if info.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("a public key is not a SEQUENCE"));
        }
        let mut fields = info.reader()?;
        let algorithm = AlgorithmIdentifier::from_element(&fields.read()?)?;
        let key = fields.expect(Tag::BIT_STRING)?.bit_string()?;
        fields.finish()?;
        if key.unused_bits != 0 {
            return Err(X509Error::Structure("a public key is not a whole number of bytes"));
        }
        if algorithm.algorithm.is(PublicKey::EC_PUBLIC_KEY) {
            Ok(PublicKey::EC { curve: PublicKey::named_curve(algorithm.parameters.as_deref())?, point: key.bytes.to_vec() })
        } else if algorithm.algorithm.is(PublicKey::RSA_ENCRYPTION) {
            PublicKey::from_rsa_public_key(key.bytes)
        } else {
            Ok(PublicKey::Other { algorithm: algorithm.algorithm, key: key.bytes.to_vec() })
        }
    }

    /// The curve of ECParameters, when they name one (RFC 5480 2.1.1).
    pub fn named_curve(parameters: Option<&[u8]>) -> Result<Option<ObjectIdentifier>, X509Error> {
        match parameters {
            None => Ok(None),
            Some(der) => {
                let element = Element::parse(der)?;
                if element.tag == Tag::OBJECT_IDENTIFIER { Ok(Some(element.object_identifier()?)) } else { Ok(None) }
            }
        }
    }

    /// Parses an RSAPublicKey (RFC 8017 A.1.1).
    pub fn from_rsa_public_key(der: &[u8]) -> Result<PublicKey, X509Error> {
        let key = Element::parse(der)?;
        if key.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("an RSA public key is not a SEQUENCE"));
        }
        let mut fields = key.reader()?;
        let modulus = fields.expect(Tag::INTEGER)?.integer()?.magnitude().to_vec();
        let exponent = fields.expect(Tag::INTEGER)?.integer()?.magnitude().to_vec();
        fields.finish()?;
        Ok(PublicKey::RSA { modulus, exponent })
    }

    /// A short name of the algorithm: `ec`, `rsa` or the identifier of another one.
    pub fn algorithm_name(&self) -> String {
        match self {
            PublicKey::EC { .. } => "ec".to_string(),
            PublicKey::RSA { .. } => "rsa".to_string(),
            PublicKey::Other { algorithm, .. } => algorithm.to_string(),
        }
    }
}

/// What can be learned of a private key without using it: its algorithm and the public key
/// that its encoding carries. The secret parts are not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateKey {
    /// An elliptic curve key; SEC 1 encodings may omit the curve and the public point.
    EC { curve: Option<ObjectIdentifier>, public_point: Option<Vec<u8>> },
    /// An RSA key, which always carries its modulus and public exponent.
    RSA { modulus: Vec<u8>, exponent: Vec<u8> },
}

impl PrivateKey {
    /// Parses a PEM block of a private key: `PRIVATE KEY` (PKCS #8, RFC 5958),
    /// `EC PRIVATE KEY` (SEC 1, RFC 5915) or `RSA PRIVATE KEY` (PKCS #1, RFC 8017).
    pub fn from_pem(block: &Pem) -> Result<PrivateKey, X509Error> {
        match block.label.as_str() {
            Pem::PRIVATE_KEY => PrivateKey::from_pkcs8(&block.data),
            Pem::EC_PRIVATE_KEY => PrivateKey::from_sec1(&block.data, None),
            Pem::RSA_PRIVATE_KEY => PrivateKey::from_pkcs1(&block.data),
            _ => Err(X509Error::PEM("the block is not a private key")),
        }
    }

    /// Parses a OneAsymmetricKey (RFC 5958 2), versions 1 and 2.
    pub fn from_pkcs8(der: &[u8]) -> Result<PrivateKey, X509Error> {
        let info = Element::parse(der)?;
        if info.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("a private key is not a SEQUENCE"));
        }
        let mut fields = info.reader()?;
        let version = fields.expect(Tag::INTEGER)?.integer()?.to_u64();
        if !matches!(version, Some(0) | Some(1)) {
            return Err(X509Error::Structure("an unknown private key version"));
        }
        let algorithm = AlgorithmIdentifier::from_element(&fields.read()?)?;
        let key = fields.expect(Tag::OCTET_STRING)?.octet_string()?;
        if algorithm.algorithm.is(PublicKey::EC_PUBLIC_KEY) {
            PrivateKey::from_sec1(key, PublicKey::named_curve(algorithm.parameters.as_deref())?)
        } else if algorithm.algorithm.is(PublicKey::RSA_ENCRYPTION) {
            PrivateKey::from_pkcs1(key)
        } else {
            Err(X509Error::UnsupportedAlgorithm(algorithm.algorithm.to_string()))
        }
    }

    /// Parses an ECPrivateKey (RFC 5915 3); `curve` is the curve named outside it, if any.
    pub fn from_sec1(der: &[u8], curve: Option<ObjectIdentifier>) -> Result<PrivateKey, X509Error> {
        let key = Element::parse(der)?;
        if key.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("an EC private key is not a SEQUENCE"));
        }
        let mut fields = key.reader()?;
        if fields.expect(Tag::INTEGER)?.integer()?.to_u64() != Some(1) {
            return Err(X509Error::Structure("an EC private key is not version 1"));
        }
        fields.expect(Tag::OCTET_STRING)?;
        let inner_curve = match fields.read_optional(Tag::context(0, true))? {
            Some(explicit) => {
                let mut inner = explicit.reader()?;
                let parameters = inner.read()?;
                inner.finish()?;
                PublicKey::named_curve(Some(parameters.encoded))?
            }
            None => None,
        };
        let public_point = match fields.read_optional(Tag::context(1, true))? {
            Some(explicit) => {
                let mut inner = explicit.reader()?;
                let point = inner.expect(Tag::BIT_STRING)?.bit_string()?;
                inner.finish()?;
                Some(point.bytes.to_vec())
            }
            None => None,
        };
        fields.finish()?;
        if let (Some(outer), Some(inner)) = (&curve, &inner_curve)
            && outer != inner
        {
            return Err(X509Error::Structure("an EC private key names two different curves"));
        }
        Ok(PrivateKey::EC { curve: inner_curve.or(curve), public_point })
    }

    /// Parses an RSAPrivateKey (RFC 8017 A.1.2).
    pub fn from_pkcs1(der: &[u8]) -> Result<PrivateKey, X509Error> {
        let key = Element::parse(der)?;
        if key.tag != Tag::SEQUENCE {
            return Err(X509Error::Structure("an RSA private key is not a SEQUENCE"));
        }
        let mut fields = key.reader()?;
        fields.expect(Tag::INTEGER)?;
        let modulus = fields.expect(Tag::INTEGER)?.integer()?.magnitude().to_vec();
        let exponent = fields.expect(Tag::INTEGER)?.integer()?.magnitude().to_vec();
        Ok(PrivateKey::RSA { modulus, exponent })
    }

    /// Whether this key belongs to `public`: `Some(true)` or `Some(false)` when the encodings
    /// tell, `None` when they cannot (an EC key without its public point).
    pub fn matches(&self, public: &PublicKey) -> Option<bool> {
        match (self, public) {
            (PrivateKey::EC { curve, public_point }, PublicKey::EC { curve: public_curve, point }) => {
                if let (Some(curve), Some(public_curve)) = (curve, public_curve)
                    && curve != public_curve
                {
                    return Some(false);
                }
                public_point.as_ref().map(|own| own == point)
            }
            (PrivateKey::RSA { modulus, exponent }, PublicKey::RSA { modulus: public_modulus, exponent: public_exponent }) => {
                Some(modulus == public_modulus && exponent == public_exponent)
            }
            _ => Some(false),
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            PrivateKey::EC { .. } => "ec",
            PrivateKey::RSA { .. } => "rsa",
        }
    }
}
