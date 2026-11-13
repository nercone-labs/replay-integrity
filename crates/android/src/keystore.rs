use std::path::PathBuf;

use crate::{CommandError, CommandOutput, SystemCommand};

/// The keys of the device's keystore (keystore2), through its command-line client
/// `keystore_cli_v2`.
///
/// keystore2 names a key of an application by the calling user and an alias (`Domain::APP`), so
/// the client runs as the user that owns the key: no other caller, root included, can name it.
/// The client asks keystore2 without waiting for it (`AServiceManager_checkService`), so it
/// fails at once while keystore2 does not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeystore {
    pub client: PathBuf,
}

/// What deleting a key did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyDeletion {
    /// A key with the alias was deleted.
    Deleted,
    /// The user has no key with the alias.
    NotFound,
}

impl DeviceKeystore {
    pub const CLIENT: &'static str = "/system/bin/keystore_cli_v2";
    /// `ResponseCode::KEY_NOT_FOUND` of `android.system.keystore2`. The client exits with the
    /// response code of a failed call.
    pub const KEY_NOT_FOUND: i32 = 7;

    pub fn new(client: impl Into<PathBuf>) -> DeviceKeystore {
        DeviceKeystore { client: client.into() }
    }

    pub fn device() -> DeviceKeystore {
        DeviceKeystore::new(DeviceKeystore::CLIENT)
    }

    /// Whether the client exists. AOSP installs it with keystore2 (`keystore2_defaults`
    /// requires it), but a device maker can leave it out.
    pub fn is_available(&self) -> bool {
        self.client.is_file()
    }

    /// Deletes the key `alias` of the user `uid`, running the client as `uid` and `gid`. The
    /// caller must be root unless `uid` and `gid` are its own. The client reads the alias as
    /// ASCII (`GetSwitchValueASCII`) and takes any other alias as an empty one.
    pub fn delete(&self, uid: u32, gid: u32, alias: &str) -> Result<KeyDeletion, CommandError> {
        let client = self.client.to_string_lossy();
        let name = format!("--name={alias}");
        let arguments = ["delete", name.as_str()];
        let output = SystemCommand::output_as(uid, gid, &client, &arguments)?;
        KeyDeletion::from_output(&output).ok_or_else(|| CommandError::Failed {
            command: format!("{client} {}", arguments.join(" ")),
            status: output.status,
            output: format!("{}{}", output.stdout, output.stderr),
        })
    }
}

impl KeyDeletion {
    /// The outcome of `keystore_cli_v2 delete` from its exit status: 0 when a key was
    /// deleted, `DeviceKeystore::KEY_NOT_FOUND` when there was none, and `None` for any other
    /// failure.
    pub fn from_output(output: &CommandOutput) -> Option<KeyDeletion> {
        match output.status {
            Some(0) => Some(KeyDeletion::Deleted),
            Some(DeviceKeystore::KEY_NOT_FOUND) => Some(KeyDeletion::NotFound),
            _ => None,
        }
    }
}
