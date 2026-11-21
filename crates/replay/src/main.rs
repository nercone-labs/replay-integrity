use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use replay::{ApplyMode, Component, Engine, KeyboxPolicy, Layout, LogLine, PackageWatcher, ReplayError, Settings};
use serde::Serialize;
use serde_json::{Value, json};

/// A subcommand of the command line.
enum Command {
    Status,
    InspectKeybox { file: PathBuf, lenient: bool },
    InspectFingerprint { file: PathBuf },
    InstallKeybox { file: PathBuf, source: Option<String>, policy: KeyboxPolicy, lenient: bool },
    InstallFingerprint { file: PathBuf, source: Option<String> },
    Targets,
    Apply { mode: ApplyMode },
    Boot { package: String },
    Watch { package: String },
    Restart,
    OutdatedKeys,
    RemoveKey { uid: u32, alias: String },
    DisableConflicts,
    InstallModule { component: Component, zip: PathBuf },
    InstallHook { package: String, watch: bool },
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
/// the settings of the user (`Settings`); without it, the defaults are used, except by `restart`
/// and `outdated-keys`, which use the settings `apply` saved. `--source` records where an
/// installed file came from. `--policy` says when `install-keybox` replaces the installed
/// keybox (`KeyboxPolicy`): `replace` (the default, for a file the user chose), `no-downgrade`
/// or `when-needed`, with `--expiry-margin HOURS` (default `CommandLine::DEFAULT_EXPIRY_MARGIN_HOURS`).
/// `apply`, `status`, `outdated-keys` and `remove-key` judge persisted keys with `--status`, or
/// the copy of it that `apply` saved last. `--root` is the base directory, `/` on a device.
struct CommandLine {
    command: Command,
    root: PathBuf,
    status: Option<PathBuf>,
    settings: Option<PathBuf>,
}

impl CommandLine {
    /// How long before it expires a keybox is replaced with `--policy when-needed`: longer than
    /// the longest interval of the application's scheduled refresh (24 hours), so that a
    /// refresh comes in time.
    const DEFAULT_EXPIRY_MARGIN_HOURS: i64 = 48;

    const USAGE: &'static str = "usage: replay status [--status STATUS.json]
       replay inspect-keybox <keybox.xml> [--status STATUS.json] [--lenient]
       replay inspect-fingerprint <fingerprint.prop|fingerprint.json>
       replay install-keybox <keybox.xml> [--source TEXT] [--status STATUS.json] [--lenient]
                             [--policy replace|no-downgrade|when-needed] [--expiry-margin HOURS]
       replay install-fingerprint <fingerprint.prop|fingerprint.json> [--source TEXT] [--settings SETTINGS.json]
       replay targets [--settings SETTINGS.json]
       replay apply [--no-restart] [--settings SETTINGS.json] [--status STATUS.json]
       replay boot --package PACKAGE | replay watch --package PACKAGE
       replay restart [--settings SETTINGS.json]
       replay outdated-keys [--settings SETTINGS.json] [--status STATUS.json]
       replay remove-key --uid UID --alias ALIAS [--status STATUS.json]
       replay disable-conflicts | version
       replay install-module <keystore|integrity> <module.zip>
       replay hook install --package PACKAGE [--no-watch] | replay hook remove
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
        let mut no_watch = false;
        let mut lenient = false;
        let mut policy: Option<String> = None;
        let mut expiry_margin = CommandLine::DEFAULT_EXPIRY_MARGIN_HOURS;
        let mut uid: Option<u32> = None;
        let mut alias: Option<String> = None;
        while let Some(argument) = parser.next()? {
            match argument {
                Long("root") => root = parser.value()?.parse()?,
                Long("status") => status = Some(parser.value()?.parse()?),
                Long("settings") => settings = Some(parser.value()?.parse()?),
                Long("source") => source = Some(parser.value()?.string()?),
                Long("package") => package = Some(parser.value()?.string()?),
                Long("no-restart") => no_restart = true,
                Long("no-watch") => no_watch = true,
                Long("lenient") => lenient = true,
                Long("policy") => policy = Some(parser.value()?.string()?),
                Long("expiry-margin") => expiry_margin = parser.value()?.parse()?,
                Long("uid") => uid = Some(parser.value()?.parse()?),
                Long("alias") => alias = Some(parser.value()?.string()?),
                Value(value) if name.is_none() => name = Some(value.string()?),
                Value(value) => positional.push(value.string()?),
                _ => return Err(argument.unexpected()),
            }
        }
        let first = |positional: &[String]| positional.first().cloned().ok_or_else(|| lexopt::Error::from("a file argument is missing"));
        let required = |package: Option<String>, command: &str| package.ok_or_else(|| lexopt::Error::from(format!("{command} needs --package")));
        let command = match name.as_deref() {
            Some("status") => Command::Status,
            Some("inspect-keybox") => Command::InspectKeybox { file: first(&positional)?.into(), lenient },
            Some("inspect-fingerprint") => Command::InspectFingerprint { file: first(&positional)?.into() },
            Some("install-keybox") => {
                if !(0..=i64::MAX / 3600).contains(&expiry_margin) {
                    return Err(lexopt::Error::from("--expiry-margin must be a number of hours, 0 or more"));
                }
                let policy = match policy.as_deref() {
                    None | Some("replace") => KeyboxPolicy::Replace,
                    Some("no-downgrade") => KeyboxPolicy::NoDowngrade,
                    Some("when-needed") => KeyboxPolicy::WhenNeeded { margin_seconds: expiry_margin * 3600 },
                    Some(other) => return Err(lexopt::Error::from(format!("unknown keybox policy {other}"))),
                };
                Command::InstallKeybox { file: first(&positional)?.into(), source, policy, lenient }
            }
            Some("install-fingerprint") => Command::InstallFingerprint { file: first(&positional)?.into(), source },
            Some("targets") => Command::Targets,
            Some("apply") => Command::Apply { mode: if no_restart { ApplyMode::NoRestart } else { ApplyMode::Restart } },
            Some("boot") => Command::Boot { package: required(package, "boot")? },
            Some("watch") => Command::Watch { package: required(package, "watch")? },
            Some("restart") => Command::Restart,
            Some("outdated-keys") => Command::OutdatedKeys,
            Some("remove-key") => Command::RemoveKey {
                uid: uid.ok_or_else(|| lexopt::Error::from("remove-key needs --uid"))?,
                alias: alias.ok_or_else(|| lexopt::Error::from("remove-key needs --alias"))?,
            },
            Some("disable-conflicts") => Command::DisableConflicts,
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
                Some("install") => Command::InstallHook { package: required(package, "hook install")?, watch: !no_watch },
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

    /// The settings of `--settings`, or those `apply` saved.
    fn settings_or_saved(&self, engine: &Engine) -> Result<Settings, ReplayError> {
        match &self.settings {
            None => engine.store.settings(),
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
            Command::InspectKeybox { file, lenient } => CommandLine::json(&engine.inspect_keybox(&CommandLine::read(file)?, status, *lenient)?),
            Command::InspectFingerprint { file } => CommandLine::json(&engine.inspect_fingerprint(&CommandLine::read(file)?)?),
            Command::InstallKeybox { file, source, policy, lenient } => {
                Engine::require_root()?;
                CommandLine::json(&engine.install_keybox(&CommandLine::read(file)?, source.clone(), status, *policy, *lenient)?)
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
                CommandLine::json(&engine.apply(&self.settings()?, *mode, status)?)
            }
            Command::Boot { package } => CommandLine::json(&engine.boot(package)?),
            Command::Watch { package } => CommandLine::json(&engine.watch(package, &PackageWatcher::new(&engine.layout))?),
            Command::Restart => {
                Engine::require_root()?;
                let settings = self.settings_or_saved(engine)?;
                Ok(json!({ "restarted": engine.restart(settings.end_background_applications)? }))
            }
            Command::OutdatedKeys => {
                let settings = self.settings_or_saved(engine)?;
                CommandLine::json(&engine.outdated_keys_of(&settings, status)?)
            }
            Command::RemoveKey { uid, alias } => {
                Engine::require_root()?;
                let (removed, kept) = engine.remove_key(*uid, alias, status)?;
                Ok(json!({ "removed": removed, "kept": kept }))
            }
            Command::DisableConflicts => {
                Engine::require_root()?;
                CommandLine::json(&engine.disable_conflicts()?)
            }
            Command::InstallModule { component, zip } => {
                Engine::require_root()?;
                Ok(json!({ "output": engine.install_module(*component, &zip.to_string_lossy())? }))
            }
            Command::InstallHook { package, watch } => {
                Engine::require_root()?;
                CommandLine::json(&engine.install_hook(package, *watch)?)
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
