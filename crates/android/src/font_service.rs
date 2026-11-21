use crate::{CommandError, SystemCommand};

/// The system font service (`FontManagerService`), driven through `cmd font`.
/// Only the shell and root users may run these commands.
pub struct FontService;

impl FontService {
    /// Re-initializes the font service as at boot: it parses the font configuration
    /// documents again and serves the new font map to processes started afterwards.
    /// Processes that are already running keep the font map they received at start.
    pub fn restart() -> Result<(), CommandError> {
        let output = SystemCommand::output(SystemCommand::CMD, &["font", "restart"])?;
        if output.success() && output.stdout.contains("Success") {
            Ok(())
        } else {
            Err(CommandError::Failed { command: "cmd font restart".to_string(), status: output.status, output: format!("{}{}", output.stdout, output.stderr) })
        }
    }

    /// The current font configuration of the service, in its human-readable dump format.
    pub fn dump() -> Result<String, CommandError> {
        SystemCommand::run(SystemCommand::CMD, &["font", "dump"])
    }

    /// The font file paths listed in a dump (`path = /system/fonts/...`).
    pub fn paths(dump: &str) -> Vec<&str> {
        dump.lines()
            .filter_map(|line| {
                let start = line.find("path = ")? + "path = ".len();
                let rest = &line[start..];
                Some(rest.split(',').next().unwrap_or(rest).trim())
            })
            .collect()
    }
}
