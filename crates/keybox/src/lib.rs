//! The keybox format of Android attestation keys: an `AndroidAttestation` XML document of
//! keyboxes, each with keys in PEM and the certificate chain of each key.
//!
//! ```xml
//! <AndroidAttestation>
//!   <NumberOfKeyboxes>1</NumberOfKeyboxes>
//!   <Keybox DeviceID="...">
//!     <Key algorithm="ecdsa">
//!       <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY-----...</PrivateKey>
//!       <CertificateChain>
//!         <NumberOfCertificates>2</NumberOfCertificates>
//!         <Certificate format="pem">-----BEGIN CERTIFICATE-----...</Certificate>
//!         ...
//!       </CertificateChain>
//!     </Key>
//!   </Keybox>
//! </AndroidAttestation>
//! ```
//!
//! `KeyboxDocument::parse` reads a well-formed document and checks its structure.
//! `KeyboxDocument::recover` reads the keys of a text that is not one (keybox mirrors serve
//! documents with broken markup), and `KeyboxDocument::read` uses whichever works.
//! `KeyboxDocument::render` writes a document back as a well-formed keybox.
//!
//! Each key keeps the PEM block of its private key, so that it can be written again; the
//! `Debug` form of a key leaves that block out.

mod document;
mod error;
mod node;

pub use document::{KeyAlgorithm, Keybox, KeyboxDocument, KeyboxKey};
pub use error::KeyboxError;
pub use node::Node;
