//! Interfaces to the running Android system: system properties, the package manager
//! (`cmd package`, `dumpsys package`, `/data/system/packages.list`), the activity manager,
//! processes and their capabilities, and watches of files.
//!
//! Every system program is started directly, without a shell. Parsing of their output is
//! separated from running them, so that it can be tested on any system.

mod activity_manager;
mod capability;
mod command;
mod file_watch;
mod package_list;
mod package_manager;
mod process;
mod property;

pub use activity_manager::ActivityManager;
pub use capability::{Capability, CapabilitySet, ProcessCapabilities};
pub use command::{CommandError, CommandOutput, SystemCommand};
pub use file_watch::FileWatch;
pub use package_list::{PackageEntry, PackageList};
pub use package_manager::{ComponentName, ComponentState, PackageManager};
pub use process::{ProcessInfo, ProcessTable};
pub use property::SystemProperty;
