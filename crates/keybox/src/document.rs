use x509::{Certificate, Pem, PrivateKey};

use crate::{KeyboxError, Node};

/// The algorithm of a key, as the `algorithm` attribute names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    ECDSA,
    RSA,
}

impl KeyAlgorithm {
    pub fn parse(name: &str) -> Option<KeyAlgorithm> {
        match name.to_ascii_lowercase().as_str() {
            "ecdsa" | "ec" => Some(KeyAlgorithm::ECDSA),
            "rsa" => Some(KeyAlgorithm::RSA),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            KeyAlgorithm::ECDSA => "ecdsa",
            KeyAlgorithm::RSA => "rsa",
        }
    }
}

/// One attestation key: its algorithm, what its encoding tells of it, and its certificate
/// chain, from the certificate of the key to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyboxKey {
    pub algorithm: KeyAlgorithm,
    pub private_key: PrivateKey,
    pub certificates: Vec<Certificate>,
}

impl KeyboxKey {
    /// Whether the private key belongs to the first certificate (see `PrivateKey::matches`).
    pub fn matches_certificate(&self) -> Option<bool> {
        self.certificates.first().and_then(|certificate| self.private_key.matches(&certificate.public_key()))
    }
}

/// The keys of one device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keybox {
    pub device_id: Option<String>,
    pub keys: Vec<KeyboxKey>,
}

/// A whole keybox document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyboxDocument {
    pub keyboxes: Vec<Keybox>,
}

impl KeyboxDocument {
    pub const ROOT: &'static str = "AndroidAttestation";

    /// Parses a document and checks its structure: the declared numbers of keyboxes and
    /// certificates match, every key is a PEM private key of its declared algorithm, and every
    /// chain has at least one certificate.
    pub fn parse(text: &str) -> Result<KeyboxDocument, KeyboxError> {
        let root = Node::parse(text)?;
        if root.name != KeyboxDocument::ROOT {
            return Err(KeyboxError::structure(format!("the root element is <{}>, not <{}>", root.name, KeyboxDocument::ROOT)));
        }
        let keyboxes = root.children_named("Keybox").map(KeyboxDocument::keybox).collect::<Result<Vec<_>, _>>()?;
        if keyboxes.is_empty() {
            return Err(KeyboxError::structure("there is no <Keybox>"));
        }
        if let Some(declared) = root.child("NumberOfKeyboxes") {
            let declared: usize = declared.text.trim().parse().map_err(|_| KeyboxError::structure("<NumberOfKeyboxes> is not a number"))?;
            if declared != keyboxes.len() {
                return Err(KeyboxError::structure(format!("<NumberOfKeyboxes> is {declared}, but there are {} keyboxes", keyboxes.len())));
            }
        }
        Ok(KeyboxDocument { keyboxes })
    }

    fn keybox(node: &Node) -> Result<Keybox, KeyboxError> {
        let keys = node.children_named("Key").filter_map(|key| KeyboxDocument::key(key).transpose()).collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Err(KeyboxError::structure("a <Keybox> has no key of a known algorithm"));
        }
        Ok(Keybox { device_id: node.attribute("DeviceID").map(str::to_string), keys })
    }

    /// Parses one `<Key>`. A key whose `algorithm` attribute names an algorithm the keybox
    /// format does not define is not an attestation key this engine understands, so it is
    /// skipped (`Ok(None)`) rather than failing the whole keybox: a mirror may add a watermark
    /// `<Key>` of its own, and a keybox that still has a usable key is weak, not broken. A key of
    /// a known algorithm that is malformed stays a genuine error.
    fn key(node: &Node) -> Result<Option<KeyboxKey>, KeyboxError> {
        let name = node.attribute("algorithm").ok_or_else(|| KeyboxError::structure("a <Key> has no algorithm"))?;
        let Some(algorithm) = KeyAlgorithm::parse(name) else { return Ok(None) };
        let private = node.child("PrivateKey").ok_or_else(|| KeyboxError::structure("a <Key> has no <PrivateKey>"))?;
        let blocks = Pem::parse_all(&private.text)?;
        let [block] = blocks.as_slice() else { return Err(KeyboxError::structure("a <PrivateKey> does not hold exactly one PEM block")) };
        let private_key = PrivateKey::from_pem(block)?;
        let expected = match algorithm {
            KeyAlgorithm::ECDSA => "ec",
            KeyAlgorithm::RSA => "rsa",
        };
        if private_key.algorithm_name() != expected {
            return Err(KeyboxError::structure(format!("a {} key holds a private key of another algorithm", algorithm.name())));
        }
        let chain = node.child("CertificateChain").ok_or_else(|| KeyboxError::structure("a <Key> has no <CertificateChain>"))?;
        let mut certificates = Vec::new();
        for certificate in chain.children_named("Certificate") {
            let mut parsed = Certificate::parse_pem(&certificate.text)?;
            if parsed.len() != 1 {
                return Err(KeyboxError::structure("a <Certificate> does not hold exactly one certificate"));
            }
            certificates.append(&mut parsed);
        }
        if certificates.is_empty() {
            return Err(KeyboxError::structure("a <CertificateChain> has no <Certificate>"));
        }
        if let Some(declared) = chain.child("NumberOfCertificates") {
            let declared: usize = declared.text.trim().parse().map_err(|_| KeyboxError::structure("<NumberOfCertificates> is not a number"))?;
            if declared != certificates.len() {
                return Err(KeyboxError::structure(format!("<NumberOfCertificates> is {declared}, but there are {} certificates", certificates.len())));
            }
        }
        Ok(Some(KeyboxKey { algorithm, private_key, certificates }))
    }

    /// Every key of every keybox.
    pub fn keys(&self) -> impl Iterator<Item = &KeyboxKey> {
        self.keyboxes.iter().flat_map(|keybox| keybox.keys.iter())
    }
}
