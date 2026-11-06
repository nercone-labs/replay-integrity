use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::X509Error;

/// One PEM block: `-----BEGIN <label>-----`, the base64 of the data, `-----END <label>-----`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pem {
    pub label: String,
    pub data: Vec<u8>,
}

impl Pem {
    pub const CERTIFICATE: &'static str = "CERTIFICATE";
    pub const PRIVATE_KEY: &'static str = "PRIVATE KEY";
    pub const EC_PRIVATE_KEY: &'static str = "EC PRIVATE KEY";
    pub const RSA_PRIVATE_KEY: &'static str = "RSA PRIVATE KEY";

    /// Every block of `text`, in order. Text between blocks is ignored, and so is whitespace
    /// inside a block, including the indentation that XML documents give embedded PEM (the
    /// lax parsing that RFC 7468 section 3 describes).
    pub fn parse_all(text: &str) -> Result<Vec<Pem>, X509Error> {
        let mut blocks = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("-----BEGIN ") {
            let after = &rest[start + "-----BEGIN ".len()..];
            let label_end = after.find("-----").ok_or(X509Error::PEM("a BEGIN line does not end with -----"))?;
            let label = &after[..label_end];
            if label.contains(['\n', '\r']) {
                return Err(X509Error::PEM("a BEGIN line does not end with -----"));
            }
            let body = &after[label_end + "-----".len()..];
            let end_line = format!("-----END {label}-----");
            let body_end = body.find(&end_line).ok_or(X509Error::PEM("a block has no matching END line"))?;
            let encoded: String = body[..body_end].chars().filter(|character| !character.is_whitespace()).collect();
            let data = STANDARD.decode(encoded.as_bytes()).map_err(|_| X509Error::PEM("a block is not valid base64"))?;
            blocks.push(Pem { label: label.to_string(), data });
            rest = &body[body_end + end_line.len()..];
        }
        Ok(blocks)
    }

    /// Encodes the block with lines of 64 characters, as RFC 7468 section 2 requires of generators.
    pub fn encode(&self) -> String {
        let encoded = STANDARD.encode(&self.data);
        let mut text = format!("-----BEGIN {}-----\n", self.label);
        for line in encoded.as_bytes().chunks(64) {
            text.push_str(&String::from_utf8_lossy(line));
            text.push('\n');
        }
        text.push_str(&format!("-----END {}-----\n", self.label));
        text
    }
}
