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
//! Parsing keeps only public information: the algorithm of each key, the public key its
//! encoding carries, and the certificates. The secret parts of keys are not kept.

mod document;
mod error;
mod node;

pub use document::{KeyAlgorithm, Keybox, KeyboxDocument, KeyboxKey};
pub use error::KeyboxError;
pub use node::Node;
