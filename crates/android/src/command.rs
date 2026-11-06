use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// A failed system command.
#[derive(Debug)]
pub enum CommandError {
    /// The program could not be started.
    Spawn { program: String, source: io::Error },
    /// The program ran but reported a failure.
    Failed { command: String, status: Option<i32>, output: String },
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::Spawn { program, source } => write!(formatter, "cannot run {program}: {source}"),
            CommandError::Failed { command, status, output } => {
                let status = status.map_or_else(|| "no status".to_string(), |code| format!("status {code}"));
                write!(formatter, "{command} exited with {status}: {}", output.trim())
            }
        }
    }
}

impl std::error::Error for CommandError {}

/// The result of a finished command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

/// Runs Android system programs with no shell in between, so arguments are never reinterpreted.
pub struct SystemCommand;

impl SystemCommand {
    pub const CMD: &'static str = "/system/bin/cmd";
    pub const DUMPSYS: &'static str = "/system/bin/dumpsys";

    /// How long a system program may run. Binder calls can hang, for example while the system
    /// is starting; the engine must not hang with them.
    pub const TIMEOUT: Duration = Duration::from_secs(120);
    pub const POLL_INTERVAL: Duration = Duration::from_millis(20);

    /// Runs `program` and returns its output, whatever its exit status. A program that runs
    /// longer than `SystemCommand::TIMEOUT` is killed, and reported as failed.
    ///
    /// The output goes to unlinked temporary files rather than pipes, so that no thread is
    /// needed to drain them: callers may change their mount namespace afterwards, which the
    /// kernel only allows in a single-threaded process.
    pub fn output(program: &str, arguments: &[&str]) -> Result<CommandOutput, CommandError> {
        let spawn = |source| CommandError::Spawn { program: program.to_string(), source };
        let mut stdout = SystemCommand::scratch_file().map_err(spawn)?;
        let mut stderr = SystemCommand::scratch_file().map_err(spawn)?;
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(stdout.try_clone().map_err(spawn)?)
            .stderr(stderr.try_clone().map_err(spawn)?)
            .spawn()
            .map_err(spawn)?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(spawn)? {
                break Some(status);
            }
            if started.elapsed() > SystemCommand::TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(SystemCommand::POLL_INTERVAL);
        };
        let read = |file: &mut File| -> io::Result<String> {
            let mut bytes = Vec::new();
            file.seek(SeekFrom::Start(0))?;
            file.read_to_end(&mut bytes)?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        };
        let stdout = read(&mut stdout).map_err(spawn)?;
        let stderr = read(&mut stderr).map_err(spawn)?;
        match status {
            Some(status) => Ok(CommandOutput { status: status.code(), stdout, stderr }),
            None => Err(CommandError::Failed {
                command: format!("{program} {}", arguments.join(" ")),
                status: None,
                output: format!("did not finish within {} seconds", SystemCommand::TIMEOUT.as_secs()),
            }),
        }
    }

    /// A new, empty file that no longer has a name: it disappears when it is closed.
    pub fn scratch_file() -> io::Result<File> {
        let directory = std::env::temp_dir();
        for attempt in 0..100u32 {
            let path = directory.join(format!(".android-command-{}-{attempt}", std::process::id()));
            match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
                Ok(file) => {
                    fs::remove_file(&path)?;
                    return Ok(file);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary file name"))
    }

    /// Runs `program` and returns its standard output, failing unless it exits with status 0.
    pub fn run(program: &str, arguments: &[&str]) -> Result<String, CommandError> {
        let output = SystemCommand::output(program, arguments)?;
        if output.success() {
            Ok(output.stdout)
        } else {
            Err(CommandError::Failed {
                command: format!("{program} {}", arguments.join(" ")),
                status: output.status,
                output: format!("{}{}", output.stdout, output.stderr),
            })
        }
    }
}
