use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// The severity of a log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl LogLevel {
    pub fn name(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogLine {
    /// Seconds since the Unix epoch.
    pub time: u64,
    pub level: LogLevel,
    pub message: String,
}

/// The engine log: lines are kept for the command's report and appended to a file,
/// which is rotated to `<file>.old` when it exceeds `Log::MAX_FILE_SIZE`.
pub struct Log {
    file: Option<PathBuf>,
    pub lines: Vec<LogLine>,
}

impl Log {
    pub const MAX_FILE_SIZE: u64 = 64 * 1024;

    pub fn new(file: Option<PathBuf>) -> Log {
        if let Some(path) = &file
            && fs::metadata(path).is_ok_and(|metadata| metadata.len() > Log::MAX_FILE_SIZE)
        {
            let _ = fs::rename(path, path.with_extension("log.old"));
        }
        Log { file, lines: Vec::new() }
    }

    pub fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
    }

    pub fn write(&mut self, level: LogLevel, message: impl Into<String>) {
        let line = LogLine { time: Log::now(), level, message: message.into() };
        if let Some(path) = &self.file {
            // The log is diagnostic only; failing to write it must not fail the operation.
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{} {} {}", line.time, line.level.name(), line.message);
            }
        }
        self.lines.push(line);
    }

    pub fn info(&mut self, message: impl Into<String>) {
        self.write(LogLevel::Info, message);
    }

    pub fn warning(&mut self, message: impl Into<String>) {
        self.write(LogLevel::Warning, message);
    }

    pub fn error(&mut self, message: impl Into<String>) {
        self.write(LogLevel::Error, message);
    }
}
