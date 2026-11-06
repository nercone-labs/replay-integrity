use crate::{CommandError, SystemCommand};

/// The activity manager, driven through `cmd activity`.
pub struct ActivityManager;

impl ActivityManager {
    /// The ID of the user in the foreground.
    pub fn current_user() -> Result<u32, CommandError> {
        let output = SystemCommand::run(SystemCommand::CMD, &["activity", "get-current-user"])?;
        output.trim().parse().map_err(|_| CommandError::Failed {
            command: "cmd activity get-current-user".to_string(),
            status: Some(0),
            output: output.clone(),
        })
    }

    /// Kills every process that the activity manager considers safe to kill: cached and other
    /// background processes. Visible and persistent processes are left alone.
    pub fn kill_background() -> Result<(), CommandError> {
        SystemCommand::run(SystemCommand::CMD, &["activity", "kill-all"]).map(|_| ())
    }
}
