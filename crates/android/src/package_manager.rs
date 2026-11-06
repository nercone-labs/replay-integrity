use std::fmt;

use crate::{CommandError, SystemCommand};

/// An application component, written as `package/class` (the class may start with `.`,
/// meaning it is relative to the package).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentName {
    pub package: String,
    pub class: String,
}

impl ComponentName {
    pub fn parse(text: &str) -> Option<ComponentName> {
        let (package, class) = text.split_once('/')?;
        if package.is_empty() || class.is_empty() || class == "." || text.contains(char::is_whitespace) {
            return None;
        }
        Some(ComponentName { package: package.to_string(), class: class.to_string() })
    }

    /// The fully qualified class name.
    pub fn class_name(&self) -> String {
        match self.class.strip_prefix('.') {
            Some(relative) => format!("{}.{relative}", self.package),
            None => self.class.clone(),
        }
    }
}

impl fmt::Display for ComponentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.package, self.class)
    }
}

/// The enabled setting of a component for one user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentState {
    /// No explicit setting: the state declared in the manifest applies.
    Default,
    Enabled,
    Disabled,
}

impl ComponentState {
    pub fn name(&self) -> &'static str {
        match self {
            ComponentState::Default => "default",
            ComponentState::Enabled => "enabled",
            ComponentState::Disabled => "disabled",
        }
    }

    pub fn from_name(name: &str) -> Option<ComponentState> {
        match name {
            "default" => Some(ComponentState::Default),
            "enabled" => Some(ComponentState::Enabled),
            "disabled" => Some(ComponentState::Disabled),
            _ => None,
        }
    }
}

/// The package manager, driven through `cmd package` and `dumpsys package`.
pub struct PackageManager;

impl PackageManager {
    /// The header of the section of `dumpsys package` that holds the current package settings.
    pub const PACKAGES_SECTION: &'static str = "Packages:";
    /// The package of the activity the system shows when no default home application is set.
    pub const SYSTEM_PACKAGE: &'static str = "android";

    /// The IDs of every user on the device.
    pub fn users() -> Result<Vec<u32>, CommandError> {
        Ok(PackageManager::parse_users(&SystemCommand::run(SystemCommand::CMD, &["package", "list", "users"])?))
    }

    /// Parses `UserInfo{<id>:<name>:<flags>}` entries of `cmd package list users`.
    pub fn parse_users(output: &str) -> Vec<u32> {
        output
            .lines()
            .filter_map(|line| {
                let start = line.find("UserInfo{")? + "UserInfo{".len();
                line[start..].split(':').next()?.parse().ok()
            })
            .collect()
    }

    /// The explicit enabled setting of `component` for `user`.
    pub fn component_state(user: u32, component: &ComponentName) -> Result<ComponentState, CommandError> {
        let dump = SystemCommand::run(SystemCommand::DUMPSYS, &["package", &component.package])?;
        Ok(PackageManager::parse_component_state(&dump, user, &component.class_name()))
    }

    /// Finds `class` in the `disabledComponents:` or `enabledComponents:` list of the
    /// `User <user>:` section of a `dumpsys package` output. Only the `Packages:` section is
    /// read: other sections, such as `Hidden system packages:` (the settings of the system
    /// version of an updated application) or `Queries:`, have `User` blocks of their own.
    pub fn parse_component_state(dump: &str, user: u32, class: &str) -> ComponentState {
        let indent = |line: &str| line.len() - line.trim_start().len();
        let header = format!("User {user}:");
        let mut in_packages = false;
        let mut in_user = false;
        let mut list: Option<(ComponentState, usize)> = None;
        for line in dump.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && indent(line) == 0 {
                in_packages = trimmed == PackageManager::PACKAGES_SECTION;
                in_user = false;
                list = None;
                continue;
            }
            if !in_packages {
                continue;
            }
            if trimmed.starts_with("User ") && trimmed.split(' ').nth(1).is_some_and(|id| id.ends_with(':') && id[..id.len() - 1].parse::<u32>().is_ok()) {
                in_user = trimmed.starts_with(&header);
                list = None;
                continue;
            }
            if !in_user {
                continue;
            }
            if let Some((_, level)) = list
                && indent(line) <= level
            {
                list = None;
            }
            match trimmed {
                "disabledComponents:" => list = Some((ComponentState::Disabled, indent(line))),
                "enabledComponents:" => list = Some((ComponentState::Enabled, indent(line))),
                _ => {
                    if let Some((state, _)) = list
                        && trimmed == class
                    {
                        return state;
                    }
                }
            }
        }
        ComponentState::Default
    }

    /// Sets the enabled setting of `component` for `user`.
    pub fn set_component_state(user: u32, component: &ComponentName, state: ComponentState) -> Result<(), CommandError> {
        let action = match state {
            ComponentState::Default => "default-state",
            ComponentState::Enabled => "enable",
            ComponentState::Disabled => "disable",
        };
        let user = user.to_string();
        let name = component.to_string();
        let output = SystemCommand::output(SystemCommand::CMD, &["package", action, "--user", &user, &name])?;
        if output.success() && output.stdout.contains("new state:") {
            Ok(())
        } else {
            Err(CommandError::Failed {
                command: format!("cmd package {action} --user {user} {name}"),
                status: output.status,
                output: format!("{}{}", output.stdout, output.stderr),
            })
        }
    }

    /// Whether `package` is installed. The answer comes from the full list of packages, which
    /// the package manager gives only when it works; a failure of the command, or a list
    /// without the system package itself, is an error rather than "not installed".
    pub fn is_installed(package: &str) -> Result<bool, CommandError> {
        let output = SystemCommand::run(SystemCommand::CMD, &["package", "list", "packages"])?;
        let packages = PackageManager::parse_packages(&output);
        if !packages.contains(&PackageManager::SYSTEM_PACKAGE) {
            return Err(CommandError::Failed {
                command: "cmd package list packages".to_string(),
                status: Some(0),
                output: "the list has no system package".to_string(),
            });
        }
        Ok(packages.contains(&package))
    }

    /// The packages that were installed by the user or an application store, not with the system
    /// image (`cmd package list packages -3`).
    pub fn third_party() -> Result<Vec<String>, CommandError> {
        let output = SystemCommand::run(SystemCommand::CMD, &["package", "list", "packages", "-3"])?;
        Ok(PackageManager::parse_packages(&output).into_iter().map(str::to_string).collect())
    }

    /// The package names of `cmd package list packages` output (`package:<name>` lines).
    pub fn parse_packages(output: &str) -> Vec<&str> {
        output.lines().filter_map(|line| line.trim().strip_prefix("package:")).filter(|name| !name.is_empty()).collect()
    }

    /// The package of the default home activity of `user`, or `None` if there is no default.
    pub fn home_package(user: u32) -> Result<Option<String>, CommandError> {
        let user = user.to_string();
        let output = SystemCommand::run(
            SystemCommand::CMD,
            &["package", "resolve-activity", "--brief", "--user", &user, "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"],
        )?;
        // Without a default, the activity is the chooser of the system, which is not a home application.
        Ok(output
            .lines()
            .rev()
            .find_map(|line| ComponentName::parse(line.trim()))
            .map(|component| component.package)
            .filter(|package| package != PackageManager::SYSTEM_PACKAGE))
    }
}
