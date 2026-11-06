use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use replay::{ApplyMode, Component, Engine, Layout, LogLine, ReplayError, Settings};
use serde::Serialize;
use serde_json::{Value, json};

/// A subcommand of the command line.
enum Command {
    Status,
    InspectKeybox { file: PathBuf },
    InspectFingerprint { file: PathBuf },
    InstallKeybox { file: PathBuf, source: Option<String> },
    InstallFingerprint { file: PathBuf, source: Option<String> },
    Targets,
    Apply { mode: ApplyMode },
    Boot { package: String },
    Restart,
    StaleKeys,
    InstallModule { component: Component, zip: PathBuf },
    InstallHook { package: String },
    RemoveHook,
    Version,
}

/// The parsed command line: `replay <command> [arguments] [--root DIR] [--status FILE] [--settings FILE]`.
///
/// Every command prints one JSON object to standard output:
/// `{"ok": true, "result": ..., "log": [...]}` or
/// `{"ok": false, "error": {"kind": ..., "message": ...}, "log": [...]}`, and exits with status
/// 0 or 1. A command line that cannot be parsed prints the usage to standard error and the
/// error object to standard output, and exits with status 2.
///
/// `--status FILE` is a JSON copy of Google's certificate status list, which the application
/// fetches; without it, revocation is not checked and the result says so. `--settings FILE` is
/// the settings of the user (`Settings`); without it, the defaults are used. `--source` records
/// where an installed file came from. `--root` is the base directory, `/` on a device.
struct CommandLine {
    command: Command,
    root: PathBuf,
    status: Option<PathBuf>,
    settings: Option<PathBuf>,
}

impl CommandLine {
    const USAGE: &'static str = "usage: replay status [--status STATUS.json]
       replay inspect-keybox <keybox.xml> [--status STATUS.json]
       replay inspect-fingerprint <fingerprint.prop>
       replay install-keybox <keybox.xml> [--source TEXT] [--status STATUS.json]
       replay install-fingerprint <fingerprint.prop> [--source TEXT] [--settings SETTINGS.json]
       replay targets [--settings SETTINGS.json]
       replay apply [--no-restart] [--settings SETTINGS.json]
       replay boot --package PACKAGE
       replay restart | stale-keys | version
       replay install-module <keystore|integrity> <module.zip>
       replay hook install --package PACKAGE | replay hook remove
options: --root DIR   the base directory, an absolute path (default /)";

    fn parse() -> Result<CommandLine, lexopt::Error> {
        use lexopt::prelude::*;
        let mut parser = lexopt::Parser::from_env();
        let mut name: Option<String> = None;
        let mut positional: Vec<String> = Vec::new();
        let mut root = PathBuf::from("/");
        let mut status: Option<PathBuf> = None;
        let mut settings: Option<PathBuf> = None;
        let mut source: Option<String> = None;
        let mut package: Option<String> = None;
        let mut no_restart = false;
        while let Some(argument) = parser.next()? {
            match argument {
                Long("root") => root = parser.value()?.parse()?,
                Long("status") => status = Some(parser.value()?.parse()?),
                Long("settings") => settings = Some(parser.value()?.parse()?),
                Long("source") => source = Some(parser.value()?.string()?),
                Long("package") => package = Some(parser.value()?.string()?),
                Long("no-restart") => no_restart = true,
                Value(value) if name.is_none() => name = Some(value.string()?),
                Value(value) => positional.push(value.string()?),
                _ => return Err(argument.unexpected()),
            }
        }
        let first = |positional: &[String]| positional.first().cloned().ok_or_else(|| lexopt::Error::from("a file argument is missing"));
        let required = |package: Option<String>, command: &str| package.ok_or_else(|| lexopt::Error::from(format!("{command} needs --package")));
        let command = match name.as_deref() {
            Some("status") => Command::Status,
            Some("inspect-keybox") => Command::InspectKeybox { file: first(&positional)?.into() },
            Some("inspect-fingerprint") => Command::InspectFingerprint { file: first(&positional)?.into() },
            Some("install-keybox") => Command::InstallKeybox { file: first(&positional)?.into(), source },
            Some("install-fingerprint") => Command::InstallFingerprint { file: first(&positional)?.into(), source },
            Some("targets") => Command::Targets,
            Some("apply") => Command::Apply { mode: if no_restart { ApplyMode::NoRestart } else { ApplyMode::Restart } },
            Some("boot") => Command::Boot { package: required(package, "boot")? },
            Some("restart") => Command::Restart,
            Some("stale-keys") => Command::StaleKeys,
            Some("install-module") => {
                let component = match positional.first().map(String::as_str) {
                    Some("keystore") => Component::Keystore,
                    Some("integrity") => Component::Integrity,
                    _ => return Err(lexopt::Error::from("install-module needs keystore or integrity, then a zip")),
                };
                let zip = positional.get(1).ok_or_else(|| lexopt::Error::from("install-module needs a module zip"))?;
                Command::InstallModule { component, zip: zip.into() }
            }
            Some("hook") => match positional.first().map(String::as_str) {
                Some("install") => Command::InstallHook { package: required(package, "hook install")? },
                Some("remove") => Command::RemoveHook,
                _ => return Err(lexopt::Error::from("hook needs install or remove")),
            },
            Some("version") => Command::Version,
            Some(other) => return Err(lexopt::Error::from(format!("unknown command {other}"))),
            None => return Err(lexopt::Error::from("a command is missing")),
        };
        if !root.is_absolute() {
            return Err(lexopt::Error::from("--root must be an absolute path"));
        }
        Ok(CommandLine { command, root, status, settings })
    }

    fn json<T: Serialize>(value: &T) -> Result<Value, ReplayError> {
        serde_json::to_value(value).map_err(|error| ReplayError::io("serialize the result", std::io::Error::other(error)))
    }

    fn read(path: &PathBuf) -> Result<Vec<u8>, ReplayError> {
        fs::read(path).map_err(|error| ReplayError::io_at("read", path, error))
    }

    /// The settings of `--settings`, or the defaults.
    fn settings(&self) -> Result<Settings, ReplayError> {
        match &self.settings {
            None => Ok(Settings::default()),
            Some(path) => Settings::parse(&CommandLine::read(path)?),
        }
    }

    /// The certificate status list of `--status`, as text.
    fn status_list(&self) -> Result<Option<String>, ReplayError> {
        match &self.status {
            None => Ok(None),
            Some(path) => {
                String::from_utf8(CommandLine::read(path)?).map(Some).map_err(|_| ReplayError::Rejected(vec!["the status list is not UTF-8 text".to_string()]))
            }
        }
    }

    fn run(self) -> (Result<Value, ReplayError>, Vec<LogLine>) {
        let mut engine = Engine::new(Layout::new(&self.root));
        let result = self.execute(&mut engine);
        (result, engine.log.lines)
    }

    /// Runs the command. Commands that change the system check first that the engine runs as
    /// unrestricted root, so that a restricted root reports that, not a failure to read a file
    /// of the application.
    fn execute(&self, engine: &mut Engine) -> Result<Value, ReplayError> {
        let status = self.status_list()?;
        let status = status.as_deref();
        match &self.command {
            Command::Status => CommandLine::json(&engine.status(status)?),
            Command::InspectKeybox { file } => CommandLine::json(&engine.inspect_keybox(&CommandLine::read(file)?, status)?),
            Command::InspectFingerprint { file } => CommandLine::json(&engine.inspect_fingerprint(&CommandLine::read(file)?)?),
            Command::InstallKeybox { file, source } => {
                Engine::require_root()?;
                CommandLine::json(&engine.install_keybox(&CommandLine::read(file)?, source.clone(), status)?)
            }
            Command::InstallFingerprint { file, source } => {
                Engine::require_root()?;
                let settings = self.settings()?;
                CommandLine::json(&engine.install_fingerprint(&CommandLine::read(file)?, source.clone(), &settings)?)
            }
            Command::Targets => {
                Engine::require_root()?;
                CommandLine::json(&engine.build_targets(&self.settings()?)?)
            }
            Command::Apply { mode } => {
                Engine::require_root()?;
                CommandLine::json(&engine.apply(&self.settings()?, *mode)?)
            }
            Command::Boot { package } => CommandLine::json(&engine.boot(package)?),
            Command::Restart => {
                Engine::require_root()?;
                Ok(json!({ "restarted": engine.restart()? }))
            }
            Command::StaleKeys => CommandLine::json(&engine.stale_keys()?),
            Command::InstallModule { component, zip } => {
                Engine::require_root()?;
                Ok(json!({ "output": engine.install_module(*component, &zip.to_string_lossy())? }))
            }
            Command::InstallHook { package } => {
                Engine::require_root()?;
                CommandLine::json(&engine.install_hook(package)?)
            }
            Command::RemoveHook => {
                Engine::require_root()?;
                CommandLine::json(&engine.remove_hook()?)
            }
            Command::Version => Ok(json!({ "version": env!("CARGO_PKG_VERSION") })),
        }
    }
}

fn main() -> ExitCode {
    let command_line = match CommandLine::parse() {
        Ok(command_line) => command_line,
        Err(error) => {
            eprintln!("replay: {error}\n{}", CommandLine::USAGE);
            println!("{}", json!({ "ok": false, "error": { "kind": "usage", "message": error.to_string() }, "log": [] }));
            return ExitCode::from(2);
        }
    };
    let (result, log) = command_line.run();
    let (output, status) = match result {
        Ok(result) => (json!({ "ok": true, "result": result, "log": log }), ExitCode::SUCCESS),
        Err(error) => (json!({ "ok": false, "error": { "kind": error.kind(), "message": error.to_string() }, "log": log }), ExitCode::FAILURE),
    };
    println!("{output}");
    status
}
