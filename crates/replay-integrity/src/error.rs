use std::fmt;
use std::io;
use std::path::Path;

use android::{Capability, CommandError};
use attestation::AttestationError;
use keybox::KeyboxError;

/// An error of the engine. Every variant names what it was working on.
#[derive(Debug)]
pub enum ReplayError {
    /// An input file was read, but is not acceptable; the reasons are listed.
    Rejected(Vec<String>),
    Keybox(KeyboxError),
    Attestation(AttestationError),
    /// A file operation failed.
    IO {
        context: String,
        source: io::Error,
    },
    Command(CommandError),
    /// The engine refuses to act in the current situation.
    Refused(String),
    /// The engine runs as root, but without these capabilities: the root manager restricts root.
    Restricted(Vec<Capability>),
}

impl ReplayError {
    pub fn io(context: impl Into<String>, source: io::Error) -> ReplayError {
        ReplayError::IO { context: context.into(), source }
    }

    pub fn io_at(action: &str, path: &Path, source: io::Error) -> ReplayError {
        ReplayError::IO { context: format!("{action} {}", path.display()), source }
    }

    pub fn refused(reason: impl Into<String>) -> ReplayError {
        ReplayError::Refused(reason.into())
    }

    /// A short machine-readable name of the variant, for user interfaces.
    pub fn kind(&self) -> &'static str {
        match self {
            ReplayError::Rejected(_) => "rejected",
            ReplayError::Keybox(_) => "keybox",
            ReplayError::Attestation(_) => "attestation",
            ReplayError::IO { .. } => "io",
            ReplayError::Command(_) => "command",
            ReplayError::Refused(_) => "refused",
            ReplayError::Restricted(_) => "restricted",
        }
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::Rejected(reasons) => write!(formatter, "rejected: {}", reasons.join("; ")),
            ReplayError::Keybox(error) => write!(formatter, "{error}"),
            ReplayError::Attestation(error) => write!(formatter, "{error}"),
            ReplayError::IO { context, source } => write!(formatter, "cannot {context}: {source}"),
            ReplayError::Command(error) => write!(formatter, "{error}"),
            ReplayError::Refused(reason) => formatter.write_str(reason),
            ReplayError::Restricted(missing) => {
                let names: Vec<String> = missing.iter().map(Capability::to_string).collect();
                write!(formatter, "the engine runs as root, but without {}: the root manager restricts root for this application", names.join(", "))
            }
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<KeyboxError> for ReplayError {
    fn from(error: KeyboxError) -> ReplayError {
        ReplayError::Keybox(error)
    }
}

impl From<AttestationError> for ReplayError {
    fn from(error: AttestationError) -> ReplayError {
        ReplayError::Attestation(error)
    }
}

impl From<CommandError> for ReplayError {
    fn from(error: CommandError) -> ReplayError {
        ReplayError::Command(error)
    }
}
