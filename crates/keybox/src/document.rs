use std::fmt;

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

    /// The algorithm of a private key, which its encoding tells.
    pub fn of(private_key: &PrivateKey) -> KeyAlgorithm {
        match private_key {
            PrivateKey::EC { .. } => KeyAlgorithm::ECDSA,
            PrivateKey::RSA { .. } => KeyAlgorithm::RSA,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            KeyAlgorithm::ECDSA => "ecdsa",
            KeyAlgorithm::RSA => "rsa",
        }
    }
}

/// One attestation key: its algorithm, its private key, and its certificate chain, from the
/// certificate of the key to the root.
///
/// `private_key_block` is the PEM block of the private key as the document held it, secret
/// included, so that the key can be written again (`KeyboxDocument::render`). `Debug` leaves
/// it out, so that a log line or a panic message never carries a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyboxKey {
    pub algorithm: KeyAlgorithm,
    pub private_key: PrivateKey,
    pub private_key_block: Pem,
    pub certificates: Vec<Certificate>,
}

impl KeyboxKey {
    /// Whether the private key belongs to the first certificate (see `PrivateKey::matches`).
    pub fn matches_certificate(&self) -> Option<bool> {
        self.certificates.first().and_then(|certificate| self.private_key.matches(&certificate.public_key()))
    }
}

impl fmt::Debug for KeyboxKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyboxKey")
            .field("algorithm", &self.algorithm)
            .field("private_key", &self.private_key)
            .field("private_key_block", &format_args!("<{} bytes of {}>", self.private_key_block.data.len(), self.private_key_block.label))
            .field("certificates", &self.certificates)
            .finish()
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
    /// Why the text is not a well-formed keybox, when `read` had to recover the keys from it;
    /// `None` when it is one. A keystore daemon that parses XML strictly reads no key from such
    /// a text, so it must be written again (`render`) before it is installed.
    pub defect: Option<String>,
}

impl KeyboxDocument {
    pub const ROOT: &'static str = "AndroidAttestation";
    /// The PEM labels of private keys that a keybox may hold.
    pub const PRIVATE_KEY_LABELS: [&'static str; 3] = [Pem::EC_PRIVATE_KEY, Pem::PRIVATE_KEY, Pem::RSA_PRIVATE_KEY];

    /// Reads a document: `parse` when it is well-formed, and `recover` when it is not, with
    /// the reason `parse` gave in `defect`. When nothing can be recovered either, the error of
    /// `parse` is returned, because it names what is wrong with the text.
    pub fn read(text: &str) -> Result<KeyboxDocument, KeyboxError> {
        match KeyboxDocument::parse(text) {
            Ok(document) => Ok(document),
            Err(error) => match KeyboxDocument::recover(text) {
                Ok(document) => Ok(KeyboxDocument { defect: Some(error.to_string()), ..document }),
                Err(_) => Err(error),
            },
        }
    }

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
        Ok(KeyboxDocument { keyboxes, defect: None })
    }

    /// Recovers the keys of a text that is not a well-formed keybox, without reading it as XML.
    ///
    /// Every `<Key` start tag begins the region of one key, which ends where the next one
    /// begins. A region that holds exactly one PEM private key and at least one PEM certificate
    /// is a key: the private key, its algorithm (from the key itself, not from an attribute),
    /// and the certificates in their order. Any other region is skipped. The result is one
    /// keybox without a device ID; it is an error when no key is found.
    ///
    /// The markup around the PEM blocks is never trusted, so broken attributes, a missing end
    /// tag or a watermark element of a mirror cannot hide the keys, and cannot add any either:
    /// every key that is returned is a parsed private key with parsed certificates.
    pub fn recover(text: &str) -> Result<KeyboxDocument, KeyboxError> {
        let keys: Vec<KeyboxKey> = KeyboxDocument::key_regions(text).filter_map(KeyboxDocument::recover_key).collect();
        if keys.is_empty() {
            return Err(KeyboxError::structure("no key with a private key and a certificate chain can be recovered"));
        }
        Ok(KeyboxDocument { keyboxes: vec![Keybox { device_id: None, keys }], defect: None })
    }

    /// The regions of `text` that each begin with a `<Key` start tag (`<Key` followed by white
    /// space, `>` or `/`, so not `<Keybox`) and end where the next begins, or at the end.
    pub fn key_regions(text: &str) -> impl Iterator<Item = &str> {
        let starts: Vec<usize> = text
            .match_indices("<Key")
            .filter(|(index, marker)| text[index + marker.len()..].chars().next().is_some_and(|next| next.is_whitespace() || next == '>' || next == '/'))
            .map(|(index, _)| index)
            .collect();
        let ends: Vec<usize> = starts.iter().skip(1).copied().chain(std::iter::once(text.len())).collect();
        starts.into_iter().zip(ends).map(move |(start, end)| &text[start..end])
    }

    fn recover_key(region: &str) -> Option<KeyboxKey> {
        let blocks = Pem::parse_all(region).ok()?;
        let mut private_keys = blocks.iter().filter(|block| KeyboxDocument::PRIVATE_KEY_LABELS.contains(&block.label.as_str()));
        let block = private_keys.next()?;
        if private_keys.next().is_some() {
            return None;
        }
        let private_key = PrivateKey::from_pem(block).ok()?;
        let certificates =
            blocks.iter().filter(|block| block.label == Pem::CERTIFICATE).map(|block| Certificate::parse(&block.data)).collect::<Result<Vec<_>, _>>().ok()?;
        if certificates.is_empty() {
            return None;
        }
        Some(KeyboxKey { algorithm: KeyAlgorithm::of(&private_key), private_key, private_key_block: block.clone(), certificates })
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
        if KeyAlgorithm::of(&private_key) != algorithm {
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
        Ok(Some(KeyboxKey { algorithm, private_key, private_key_block: block.clone(), certificates }))
    }

    /// Every key of every keybox.
    pub fn keys(&self) -> impl Iterator<Item = &KeyboxKey> {
        self.keyboxes.iter().flat_map(|keybox| keybox.keys.iter())
    }

    /// The document with only the keys for which `keep` is true; a keybox left without keys is
    /// left out.
    pub fn retain_keys(&self, mut keep: impl FnMut(&KeyboxKey) -> bool) -> KeyboxDocument {
        let keyboxes = self
            .keyboxes
            .iter()
            .map(|keybox| Keybox { device_id: keybox.device_id.clone(), keys: keybox.keys.iter().filter(|key| keep(key)).cloned().collect() })
            .filter(|keybox| !keybox.keys.is_empty())
            .collect();
        KeyboxDocument { keyboxes, defect: self.defect.clone() }
    }

    /// The document as a well-formed keybox, in the layout of the format's own documents: the
    /// declared numbers of keyboxes and certificates, each private key as the PEM block it was
    /// read from, and each certificate as a `CERTIFICATE` block. `parse` reads it back as the
    /// same keys, and so does any XML parser, however strict.
    pub fn render(&self) -> String {
        let mut text = String::from("<?xml version=\"1.0\"?>\n<AndroidAttestation>\n");
        text.push_str(&format!("<NumberOfKeyboxes>{}</NumberOfKeyboxes>\n", self.keyboxes.len()));
        for keybox in &self.keyboxes {
            match &keybox.device_id {
                Some(id) => text.push_str(&format!("<Keybox DeviceID=\"{}\">\n", KeyboxDocument::escape(id))),
                None => text.push_str("<Keybox>\n"),
            }
            for key in &keybox.keys {
                text.push_str(&format!("<Key algorithm=\"{}\">\n<PrivateKey format=\"pem\">\n", key.algorithm.name()));
                text.push_str(&key.private_key_block.encode());
                text.push_str("</PrivateKey>\n<CertificateChain>\n");
                text.push_str(&format!("<NumberOfCertificates>{}</NumberOfCertificates>\n", key.certificates.len()));
                for certificate in &key.certificates {
                    text.push_str("<Certificate format=\"pem\">\n");
                    text.push_str(&Pem { label: Pem::CERTIFICATE.to_string(), data: certificate.der.clone() }.encode());
                    text.push_str("</Certificate>\n");
                }
                text.push_str("</CertificateChain>\n</Key>\n");
            }
            text.push_str("</Keybox>\n");
        }
        text.push_str("</AndroidAttestation>\n");
        text
    }

    /// `value` with the characters that XML gives a meaning to replaced by their references,
    /// so that it can be written as an attribute value.
    pub fn escape(value: &str) -> String {
        let mut escaped = String::with_capacity(value.len());
        for character in value.chars() {
            match character {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&apos;"),
                _ => escaped.push(character),
            }
        }
        escaped
    }
}
