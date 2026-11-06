//! Tests of `FileWatch` against the kernel's inotify, in a temporary directory.

use std::fs;
use std::path::PathBuf;

use android::FileWatch;

fn temporary_directory() -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("android-watch-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn a_write_of_the_file_is_a_change_and_a_write_of_another_is_not() {
    let directory = temporary_directory();
    let path = directory.join("packages.list");
    let mut watch = FileWatch::new(&path).unwrap();
    assert!(!watch.take_pending().unwrap());
    fs::write(directory.join("packages.xml"), "other").unwrap();
    assert!(!watch.take_pending().unwrap());
    fs::write(&path, "a 10001\n").unwrap();
    assert!(watch.take_pending().unwrap());
    // Every pending event was read: nothing is left.
    assert!(!watch.take_pending().unwrap());
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn a_replacement_by_rename_is_a_change() {
    // The package manager writes the list to a temporary file and renames it over the list,
    // which gives the list a new inode.
    let directory = temporary_directory();
    let path = directory.join("packages.list");
    fs::write(&path, "a 10001\n").unwrap();
    let mut watch = FileWatch::new(&path).unwrap();
    let temporary = directory.join("packages.list.tmp");
    fs::write(&temporary, "a 10001\nb 10002\n").unwrap();
    // Writing the temporary file is not a change of the list.
    assert!(!watch.take_pending().unwrap());
    fs::rename(&temporary, &path).unwrap();
    // `wait` returns at once for a change that already happened.
    watch.wait().unwrap();
    // A second replacement after the first was read is seen too: the watch follows the name.
    fs::write(&temporary, "b 10002\n").unwrap();
    fs::rename(&temporary, &path).unwrap();
    assert!(watch.take_pending().unwrap());
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn removing_the_file_is_a_change_and_removing_the_directory_ends_the_watch() {
    let directory = temporary_directory();
    let path = directory.join("packages.list");
    fs::write(&path, "a 10001\n").unwrap();
    let mut watch = FileWatch::new(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(watch.take_pending().unwrap());
    fs::remove_dir(&directory).unwrap();
    assert_eq!(watch.wait().unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn a_file_without_a_directory_cannot_be_watched() {
    let directory = temporary_directory();
    assert!(FileWatch::new(&directory.join("missing/packages.list")).is_err());
    let _ = fs::remove_dir_all(&directory);
}
