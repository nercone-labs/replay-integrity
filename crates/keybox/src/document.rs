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
    /// Why the text is not well-formed XML, when `read` had to recover the keys from it; `None`
    /// when it is. A keystore daemon that parses XML strictly reads no key from such a text, so
    /// it must be written again (`render`) before it is installed.
    pub defect: Option<String>,
}

impl KeyboxDocument {
    pub const ROOT: &'static str = "AndroidAttestation";
    /// The PEM labels of private keys that a keybox may hold.
    pub const PRIVATE_KEY_LABELS: [&'static str; 3] = [Pem::EC_PRIVATE_KEY, Pem::PRIVATE_KEY, Pem::RSA_PRIVATE_KEY];

    /// Reads a document: `parse` when it is a well-formed keybox, and `recover` when it is not.
    /// `defect` is set only when the text is not well-formed XML (`KeyboxError::Syntax`): a
    /// document that is XML but breaks a rule of the format (a wrong declared count, say) is
    /// still read by a keystore daemon, which ignores those rules. When nothing can be
    /// recovered, the error of `parse` is returned, because it names what is wrong.
    pub fn read(text: &str) -> Result<KeyboxDocument, KeyboxError> {
        match KeyboxDocument::parse(text) {
            Ok(document) => Ok(document),
            Err(error) => match KeyboxDocument::recover(text) {
                Ok(document) => {
                    let defect = matches!(error, KeyboxError::Syntax(_)).then(|| error.to_string());
                    Ok(KeyboxDocument { defect, ..document })
                }
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
    /// Comments (`<!-- ... -->`) are removed first. Then every PEM block is read in order, and a
    /// block that is not valid PEM is skipped. Each PEM private key begins a key; the
    /// certificates that follow it, up to the next private key, are its chain, in their order,
    /// as a keystore daemon takes them. A private key without a certificate is skipped, and so
    /// are certificates before the first private key. The algorithm comes from the private key itself, not from an
    /// attribute.
    ///
    /// The markup between the PEM blocks is never read, so broken attributes, missing end tags
    /// and watermark elements of a mirror do not matter, and every key returned is a parsed
    /// private key with parsed certificates. The boundaries of keyboxes are markup too: the
    /// result is one keybox, without a device ID. It is an error when no key is found.
    pub fn recover(text: &str) -> Result<KeyboxDocument, KeyboxError> {
        let text = KeyboxDocument::without_comments(text);
        let mut keys: Vec<KeyboxKey> = Vec::new();
        let mut current: Option<KeyboxKey> = None;
        for block in KeyboxDocument::pem_blocks(&text) {
            if KeyboxDocument::PRIVATE_KEY_LABELS.contains(&block.label.as_str()) {
                keys.extend(current.take().filter(|key| !key.certificates.is_empty()));
                current = PrivateKey::from_pem(&block).ok().map(|private_key| KeyboxKey {
                    algorithm: KeyAlgorithm::of(&private_key),
                    private_key,
                    private_key_block: block,
                    certificates: Vec::new(),
                });
            } else if block.label == Pem::CERTIFICATE
                && let Some(key) = &mut current
                && let Ok(certificate) = Certificate::parse(&block.data)
            {
                key.certificates.push(certificate);
            }
        }
        keys.extend(current.filter(|key| !key.certificates.is_empty()));
        if keys.is_empty() {
            return Err(KeyboxError::structure("no key with a private key and a certificate chain can be recovered"));
        }
        Ok(KeyboxDocument { keyboxes: vec![Keybox { device_id: None, keys }], defect: None })
    }

    /// `text` without its XML comments. A comment that is not closed runs to the end.
    pub fn without_comments(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("<!--") {
            result.push_str(&rest[..start]);
            rest = match rest[start + 4..].find("-->") {
                Some(end) => &rest[start + 4 + end + 3..],
                None => "",
            };
        }
        result.push_str(rest);
        result
    }

    /// Every valid PEM block of `text`, in order; a block that is not valid PEM is skipped
    /// instead of ending the search.
    pub fn pem_blocks(text: &str) -> Vec<Pem> {
        let marker = "-----BEGIN ";
        let starts: Vec<usize> = text.match_indices(marker).map(|(index, _)| index).collect();
        let ends = starts.iter().skip(1).copied().chain(std::iter::once(text.len()));
        starts.iter().zip(ends).filter_map(|(&start, end)| Pem::parse_all(&text[start..end]).ok()?.into_iter().next()).collect()
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
    /// same keys, and so does any conforming XML parser, however strict.
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

    /// `value` written as an attribute value: the characters that XML gives a meaning to, and
    /// tab, line feed and carriage return (which attribute-value normalization would turn into
    /// spaces), as character references; characters that XML 1.0 does not allow at all (other
    /// control characters, U+FFFE, U+FFFF) as U+FFFD, the replacement character.
    pub fn escape(value: &str) -> String {
        let mut escaped = String::with_capacity(value.len());
        for character in value.chars() {
            match character {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&apos;"),
                '\t' => escaped.push_str("&#x9;"),
                '\n' => escaped.push_str("&#xA;"),
                '\r' => escaped.push_str("&#xD;"),
                '\u{0}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}' => escaped.push('\u{fffd}'),
                _ => escaped.push(character),
            }
        }
        escaped
    }
}
