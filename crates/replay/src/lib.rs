//! The engine of Replay Integrity: it keeps the pieces that make Play Integrity report STRONG on
//! a rooted device consistent and valid, without a reboot.
//!
//! Replay Integrity drives two modules rather than replacing them:
//!
//! - TEESimulator-RS (module `tricky_store`) simulates hardware key attestation from a keybox.
//! - PlayIntegrityFork (module `playintegrityfix`) spoofs the build of Google Play services.
//!
//! The engine installs and updates these modules through the root manager, writes their
//! configuration (`keybox.xml`, `target.txt`, `security_patch.txt`, `custom.pif.prop`), and
//! checks the keybox against the Google trust anchors and the certificate status list.
//!
//! The verdict of such a setup decays over days for reasons the modules do not handle on their
//! own: the keybox is revoked or expires, the fingerprint's build stops being accepted, the
//! spoof flags are reset by the modules' own refresh scripts, and — the subtlest — TEESimulator
//! keeps per-application keys it generated with an older keybox, so those applications keep
//! receiving a chain built from a keybox that is no longer valid. `Engine::apply` re-applies the
//! configuration and removes those stale keys; run at boot (through the boot hook, `Engine::boot`) and
//! periodically (by the application), it is what keeps the verdict from decaying.
//!
//! The network is left to the application, which has ordinary TLS: it downloads the keybox, the
//! fingerprint and the certificate status list and hands the bytes to the engine, which parses,
//! checks and installs them. The engine performs no network access.

mod components;
mod config;
mod engine;
mod error;
mod files;
mod fingerprint;
mod hook;
mod keystore_daemon;
mod layout;
mod log;
mod module;
mod patch_date;
mod persistent_keys;
mod root_manager;
mod store;
mod targets;
mod verify;

pub use components::{Component, ComponentState, Conflicts, Flavor};
pub use config::{KeystoreConfig, Settings};
pub use engine::{ApplyMode, ApplyReport, BootReport, Engine, InstallReport, REFRESH_PROCESSES, StatusReport};
pub use error::ReplayError;
pub use files::Files;
pub use fingerprint::{Fingerprint, FingerprintProblem, FingerprintReport, SpoofFlag, SpoofFlags};
pub use hook::BootHook;
pub use keystore_daemon::{DaemonState, KeystoreDaemon};
pub use layout::Layout;
pub use log::{Log, LogLevel, LogLine};
pub use module::Module;
pub use patch_date::PatchDate;
pub use persistent_keys::PersistedKey;
pub use root_manager::{RootManager, Zygisk};
pub use store::{InstalledFile, State, Store};
pub use targets::{Target, TargetList, TargetMode};
pub use verify::{KeyProblem, KeyVerdict, KeyboxVerdict, Verifier};
