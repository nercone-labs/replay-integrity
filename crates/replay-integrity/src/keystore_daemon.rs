use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use android::{ProcessInfo, ProcessTable};
use serde::Serialize;

use crate::{Layout, Log, ReplayError};

/// The daemon of TEESimulator-RS and the supervisor that restarts it.
///
/// The module's `service.sh` runs `./supervisor ./daemon <module>` in the module directory;
/// `daemon` starts `app_process` with the process name `TEESimulator`. The supervisor starts
/// the daemon again when it dies, so restarting the daemon means ending it and waiting.
pub struct KeystoreDaemon {
    pub module: PathBuf,
}

/// The processes of the daemon.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonState {
    pub daemons: Vec<u32>,
    pub supervisors: Vec<u32>,
}

impl DaemonState {
    pub fn is_running(&self) -> bool {
        !self.daemons.is_empty()
    }
}

impl KeystoreDaemon {
    pub const PROCESS_NAME: &'static str = "TEESimulator";
    pub const SUPERVISOR: &'static str = "supervisor";
    pub const DAEMON: &'static str = "daemon";
    /// How long the supervisor may take to start the daemon again.
    pub const RESTART_TIMEOUT: Duration = Duration::from_secs(15);
    pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

    pub fn new(layout: &Layout) -> KeystoreDaemon {
        KeystoreDaemon { module: layout.modules().join(crate::Component::Keystore.module_id()) }
    }

    pub fn state(&self) -> DaemonState {
        let processes = ProcessTable::list().unwrap_or_default();
        let supervisor = self.module.join(KeystoreDaemon::SUPERVISOR);
        let daemons = processes.iter().filter(|process| process.name == KeystoreDaemon::PROCESS_NAME).map(|process| process.pid).collect();
        let supervisors =
            processes.iter().filter(|process| ProcessInfo::executable(process.pid).is_some_and(|path| path == supervisor)).map(|process| process.pid).collect();
        DaemonState { daemons, supervisors }
    }

    /// Ends the daemon and waits until it runs again, so that it reloads its configuration and
    /// its persisted keys. Without a supervisor, one is started the way `service.sh` does.
    pub fn restart(&self, log: &mut Log) -> Result<DaemonState, ReplayError> {
        let before = self.state();
        if before.supervisors.is_empty() {
            log.warning("the supervisor of TEESimulator-RS is not running; starting it");
        }
        for pid in &before.daemons {
            let process = ProcessInfo { pid: *pid, name: KeystoreDaemon::PROCESS_NAME.to_string() };
            if process.is_alive() {
                process.kill().map_err(|error| ReplayError::io(format!("end the TEESimulator daemon {pid}"), error))?;
            }
        }
        if before.supervisors.is_empty() {
            self.start_supervisor()?;
        }
        let started = Instant::now();
        loop {
            let state = self.state();
            if state.daemons.iter().any(|pid| !before.daemons.contains(pid)) {
                log.info(format!("the TEESimulator daemon runs again as {:?}", state.daemons));
                return Ok(state);
            }
            if started.elapsed() > KeystoreDaemon::RESTART_TIMEOUT {
                return Err(ReplayError::refused(format!(
                    "the TEESimulator daemon did not start again within {} seconds; reboot the device",
                    KeystoreDaemon::RESTART_TIMEOUT.as_secs()
                )));
            }
            thread::sleep(KeystoreDaemon::POLL_INTERVAL);
        }
    }

    fn start_supervisor(&self) -> Result<(), ReplayError> {
        let supervisor = self.module.join(KeystoreDaemon::SUPERVISOR);
        if !Path::new(&supervisor).is_file() {
            return Err(ReplayError::refused(format!("{} does not exist; is TEESimulator-RS installed and booted?", supervisor.display())));
        }
        Command::new(&supervisor)
            .arg(format!("./{}", KeystoreDaemon::DAEMON))
            .arg(&self.module)
            .current_dir(&self.module)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|error| ReplayError::io_at("start", &supervisor, error))
    }
}
