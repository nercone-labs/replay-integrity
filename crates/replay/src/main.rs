use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use replay::{Component, Engine, Layout, LogLine, ReplayError, Settings};
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
    Apply { restart: bool },
    Repair { restart: bool },
    Restart,
    StaleKeys,
    InstallModule { component: Component, zip: PathBuf },
    InstallHook { executable: String },
    RemoveHook,
    Version,
}

/// The parsed command line: `replay <command> [arguments] [--root DIR] [--status FILE]`.
///
/// Every command prints one JSON object to standard output:
/// `{"ok": true, "result": ..., "log": [...]}` or
/// `{"ok": false, "error": {"kind": ..., "message": ...}, "log": [...]}`, and exits with status
/// 0 or 1. A command line that cannot be parsed prints the usage to standard error and the
/// error object to standard output, and exits with status 2.
///
/// `--status FILE` is a JSON copy of Google's certificate status list, which the application
/// fetches; without it, revocation is not checked and the result says so. `--source` records
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
       replay install-keybox <keybox.xml> [--source URL] [--status STATUS.json]
       replay install-fingerprint <fingerprint.prop> [--source URL] [--settings SETTINGS.json]
       replay targets [--settings SETTINGS.json]
       replay apply [--no-restart] [--settings SETTINGS.json]
       replay repair [--boot] [--settings SETTINGS.json]
       replay restart | stale-keys | version
       replay install-module <keystore|integrity> <module.zip>
       replay hook install --executable PATH | replay hook remove
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
        let mut executable: Option<String> = None;
        let mut boot = false;
        let mut no_restart = false;
        while let Some(argument) = parser.next()? {
            match argument {
                Long("root") => root = parser.value()?.parse()?,
                Long("status") => status = Some(parser.value()?.parse()?),
                Long("settings") => settings = Some(parser.value()?.parse()?),
                Long("source") => source = Some(parser.value()?.string()?),
                Long("executable") => executable = Some(parser.value()?.string()?),
                Long("boot") => boot = true,
                Long("no-restart") => no_restart = true,
                Value(value) if name.is_none() => name = Some(value.string()?),
                Value(value) => positional.push(value.string()?),
                _ => return Err(argument.unexpected()),
            }
        }
        let first = |positional: &[String]| positional.first().cloned().ok_or_else(|| lexopt::Error::from("a file argument is missing"));
        let command = match name.as_deref() {
            Some("status") => Command::Status,
            Some("inspect-keybox") => Command::InspectKeybox { file: first(&positional)?.into() },
            Some("inspect-fingerprint") => Command::InspectFingerprint { file: first(&positional)?.into() },
            Some("install-keybox") => Command::InstallKeybox { file: first(&positional)?.into(), source },
            Some("install-fingerprint") => Command::InstallFingerprint { file: first(&positional)?.into(), source },
            Some("targets") => Command::Targets,
            Some("apply") => Command::Apply { restart: !no_restart },
            Some("repair") => Command::Repair { restart: !no_restart && !boot },
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
                Some("install") => Command::InstallHook { executable: executable.ok_or_else(|| lexopt::Error::from("hook install needs --executable"))? },
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

    fn run(self) -> (Result<Value, ReplayError>, Vec<LogLine>) {
        let status_text = match self.status.as_ref().map(CommandLine::read) {
            Some(Ok(bytes)) => match String::from_utf8(bytes) {
                Ok(text) => Some(text),
                Err(_) => return (Err(ReplayError::Rejected(vec!["the status list is not UTF-8 text".to_string()])), Vec::new()),
            },
            Some(Err(error)) => return (Err(error), Vec::new()),
            None => None,
        };
        let status = status_text.as_deref();
        let mut engine = Engine::new(Layout::new(self.root));
        let result = match self.command {
            Command::Status => engine.status(status).and_then(|report| CommandLine::json(&report)),
            Command::InspectKeybox { file } => {
                CommandLine::read(&file).and_then(|bytes| engine.inspect_keybox(&bytes, status)).and_then(|verdict| CommandLine::json(&verdict))
            }
            Command::InspectFingerprint { file } => {
                CommandLine::read(&file).and_then(|bytes| engine.inspect_fingerprint(&bytes)).and_then(|report| CommandLine::json(&report))
            }
            Command::InstallKeybox { file, source } => Engine::require_root()
                .and_then(|()| CommandLine::read(&file))
                .and_then(|bytes| engine.install_keybox(&bytes, source, status))
                .and_then(|report| CommandLine::json(&report)),
            Command::InstallFingerprint { file, source } => load_settings(&self.settings)
                .and_then(|settings| {
                    Engine::require_root().and_then(|()| CommandLine::read(&file)).and_then(|bytes| engine.install_fingerprint(&bytes, source, &settings))
                })
                .and_then(|report| CommandLine::json(&report)),
            Command::Targets => load_settings(&self.settings)
                .and_then(|settings| Engine::require_root().and_then(|()| engine.build_targets(&settings)))
                .and_then(|list| CommandLine::json(&list)),
            Command::Apply { restart } => load_settings(&self.settings)
                .and_then(|settings| Engine::require_root().and_then(|()| engine.apply(&settings, restart)))
                .and_then(|report| CommandLine::json(&report)),
            Command::Repair { restart } => load_settings(&self.settings)
                .and_then(|settings| Engine::require_root().and_then(|()| engine.apply(&settings, restart)))
                .and_then(|report| CommandLine::json(&report)),
            Command::Restart => Engine::require_root().and_then(|()| engine.restart()).map(|restarted| json!({ "restarted": restarted })),
            Command::StaleKeys => engine.stale_keys().and_then(|keys| CommandLine::json(&keys)),
            Command::InstallModule { component, zip } => {
                Engine::require_root().and_then(|()| engine.install_module(component, &zip.to_string_lossy())).map(|output| json!({ "output": output }))
            }
            Command::InstallHook { executable } => {
                Engine::require_root().and_then(|()| engine.install_hook(&executable)).and_then(|hook| CommandLine::json(&hook))
            }
            Command::RemoveHook => Engine::require_root().and_then(|()| engine.remove_hook()).and_then(|hook| CommandLine::json(&hook)),
            Command::Version => Ok(json!({ "version": env!("CARGO_PKG_VERSION") })),
        };
        (result, engine.log.lines)
    }
}

/// Loads the settings from `--settings`, or the defaults.
fn load_settings(path: &Option<PathBuf>) -> Result<Settings, ReplayError> {
    match path {
        None => Ok(Settings::default()),
        Some(path) => {
            let bytes = fs::read(path).map_err(|error| ReplayError::io_at("read", path, error))?;
            serde_json::from_slice(&bytes).map_err(|error| ReplayError::Rejected(vec![format!("invalid settings: {error}")]))
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
