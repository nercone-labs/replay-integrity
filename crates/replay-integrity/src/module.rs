use std::path::PathBuf;

use prop::PropFile;
use serde::Serialize;

use crate::Layout;

/// A module of the root manager, as `module.prop` and its marker files describe it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Module {
    pub id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub version_code: Option<u64>,
    pub author: Option<String>,
    #[serde(skip)]
    pub directory: PathBuf,
    /// The module is in `modules`, so it runs since the last boot.
    pub installed: bool,
    /// The module has a `disable` file.
    pub disabled: bool,
    /// The module has a `remove` file: it is removed at the next boot.
    pub removing: bool,
    /// A version is installed into `modules_update`, which becomes the module at the next boot.
    pub update_pending: bool,
}

impl Module {
    pub const PROP: &'static str = "module.prop";
    /// The marker that disables a module from the next boot.
    pub const DISABLE: &'static str = "disable";
    /// The marker that removes a module at the next boot.
    pub const REMOVE: &'static str = "remove";
    pub const MARKER_MODE: u32 = 0o644;

    /// Whether `id` is a valid module ID, as the root managers require: a letter, then
    /// letters, digits, `.`, `_` and `-`.
    pub fn is_id(id: &str) -> bool {
        let mut characters = id.chars();
        characters.next().is_some_and(|first| first.is_ascii_alphabetic())
            && characters.all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    }

    /// The module `id`, installed or waiting for the next boot in `modules_update`.
    pub fn read(layout: &Layout, id: &str) -> Option<Module> {
        if !Module::is_id(id) {
            return None;
        }
        let installed = layout.modules().join(id);
        let update = layout.modules_update().join(id);
        let update_pending = update.join(Module::PROP).is_file();
        let is_installed = installed.join(Module::PROP).is_file();
        let directory = if is_installed {
            installed
        } else if update_pending {
            update
        } else {
            return None;
        };
        let properties = PropFile::parse(&std::fs::read_to_string(directory.join(Module::PROP)).ok()?);
        let text = |key: &str| properties.get(key).map(str::to_string);
        Some(Module {
            id: id.to_string(),
            name: text("name"),
            version: text("version"),
            version_code: properties.get("versionCode").and_then(|code| code.parse().ok()),
            author: text("author"),
            installed: is_installed,
            disabled: directory.join(Module::DISABLE).exists(),
            removing: directory.join(Module::REMOVE).exists(),
            update_pending,
            directory,
        })
    }

    /// Whether the module runs after the next boot: neither disabled nor being removed.
    pub fn is_active(&self) -> bool {
        !self.disabled && !self.removing
    }

    /// The directory the module will have after the next boot: the pending update, if any.
    pub fn next_directory(&self, layout: &Layout) -> PathBuf {
        if self.update_pending { layout.modules_update().join(&self.id) } else { self.directory.clone() }
    }
}
