use std::ffi::OsString;
use std::io;
use std::path::Path;

/// Waits for a file to change: to be written, created, replaced by a rename, or removed.
///
/// The directory of the file is watched, not the file itself, because a file replaced
/// atomically (written to a temporary file and renamed over it, as the package manager writes
/// `packages.list`) gets a new inode, and a watch on the old inode would see nothing more.
/// Events of other files in the directory are read and ignored; files in its subdirectories
/// cause no events at all. A watch that blocks costs nothing until the kernel reports an event.
pub struct FileWatch {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    descriptor: std::os::fd::OwnedFd,
    name: OsString,
}

impl FileWatch {
    /// The size of the buffer events are read into: room for many events with names up to
    /// `NAME_MAX` (255) bytes. A shorter buffer would fail with `EINVAL` on a long name.
    pub const BUFFER_SIZE: usize = 4096;

    /// Starts watching `path`. Its directory must exist; the file need not.
    pub fn new(path: &Path) -> io::Result<FileWatch> {
        let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the path has no file name"))?.to_os_string();
        let directory = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use rustix::fs::inotify;
            let descriptor = inotify::init(inotify::CreateFlags::CLOEXEC)?;
            let flags = inotify::WatchFlags::CLOSE_WRITE
                | inotify::WatchFlags::MOVED_TO
                | inotify::WatchFlags::CREATE
                | inotify::WatchFlags::DELETE
                | inotify::WatchFlags::DELETE_SELF
                | inotify::WatchFlags::MOVE_SELF
                | inotify::WatchFlags::ONLYDIR;
            inotify::add_watch(&descriptor, directory, flags)?;
            Ok(FileWatch { descriptor, name })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (directory, name);
            Err(io::Error::new(io::ErrorKind::Unsupported, "file watches require Linux"))
        }
    }

    /// Blocks until the file changes. Changes that happened since the last call are reported at
    /// once. A lost event (the kernel's queue overflowed) counts as a change, because it may
    /// have been one. When the directory itself is removed or moved, the watch ends and this
    /// returns an error of kind `NotFound`.
    pub fn wait(&mut self) -> io::Result<()> {
        loop {
            if self.read(true)? {
                return Ok(());
            }
        }
    }

    /// Reads the events that are pending without blocking, and returns whether the file
    /// changed. Used after a change to absorb the further events of the same change.
    pub fn take_pending(&mut self) -> io::Result<bool> {
        self.read(false)
    }

    /// Reads one buffer of events, blocking first when `block` is set. Returns whether one of
    /// them is about the file.
    fn read(&mut self, block: bool) -> io::Result<bool> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl, inotify};
            use std::mem::MaybeUninit;
            let flags = fcntl_getfl(&self.descriptor)?;
            let wanted = if block { flags - OFlags::NONBLOCK } else { flags | OFlags::NONBLOCK };
            if wanted != flags {
                fcntl_setfl(&self.descriptor, wanted)?;
            }
            let mut buffer = [MaybeUninit::<u8>::uninit(); FileWatch::BUFFER_SIZE];
            let mut reader = inotify::Reader::new(&self.descriptor, &mut buffer);
            let mut changed = false;
            loop {
                let event = match reader.next() {
                    Ok(event) => event,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(rustix::io::Errno::AGAIN) => return Ok(changed),
                    Err(error) => return Err(error.into()),
                };
                let events = event.events();
                if events.intersects(inotify::ReadFlags::DELETE_SELF | inotify::ReadFlags::MOVE_SELF | inotify::ReadFlags::IGNORED) {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "the watched directory was removed or moved"));
                }
                if events.contains(inotify::ReadFlags::QUEUE_OVERFLOW) {
                    changed = true;
                } else if let Some(name) = event.file_name() {
                    changed |= std::os::unix::ffi::OsStrExt::as_bytes(self.name.as_os_str()) == name.to_bytes();
                }
                // A blocking read stops at the end of what one read returned, so that it waits
                // only once: the caller decides whether to wait again. A read without blocking
                // goes on until nothing is pending.
                if block && reader.is_buffer_empty() {
                    return Ok(changed);
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = block;
            Err(io::Error::new(io::ErrorKind::Unsupported, "file watches require Linux"))
        }
    }

    /// The name of the watched file.
    pub fn name(&self) -> &OsString {
        &self.name
    }
}
