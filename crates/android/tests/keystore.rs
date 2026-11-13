//! Tests of the keystore client against the contract of AOSP `keystore_cli_v2`
//! (`system/security/keystore/keystore_cli_v2.cpp`): `delete --name=<alias>` names the key of
//! the calling user (`Domain::APP`), exits with 0 when it deleted the key and with the
//! keystore2 `ResponseCode` otherwise (`KEY_NOT_FOUND` is 7), and exits with -1 (255) when it
//! cannot reach keystore2. A script stands in for the client.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use android::{CommandError, CommandOutput, DeviceKeystore, KeyDeletion};

/// A new directory of its own for the test `name`: tests run at once, so the time alone may
/// not tell their directories apart.
fn temporary_directory(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("android-keystore-test-{}-{name}-{nanos}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    directory
}

/// A stand-in client that writes its arguments and its user to `record`, then exits with
/// `status`.
fn client(directory: &Path, status: u8) -> PathBuf {
    let path = directory.join("keystore_cli_v2");
    let record = directory.join("record");
    fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nid -u >> '{}'\nexit {status}\n", record.display(), record.display())).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn own(flag: &str) -> u32 {
    let output = Command::new("id").arg(flag).output().unwrap();
    String::from_utf8(output.stdout).unwrap().trim().parse().unwrap()
}

fn output(status: Option<i32>) -> CommandOutput {
    CommandOutput { status, stdout: String::new(), stderr: String::new() }
}

#[test]
fn exit_statuses_are_read_as_the_client_reports_them() {
    assert_eq!(DeviceKeystore::KEY_NOT_FOUND, 7);
    assert_eq!(KeyDeletion::from_output(&output(Some(0))), Some(KeyDeletion::Deleted));
    assert_eq!(KeyDeletion::from_output(&output(Some(7))), Some(KeyDeletion::NotFound));
    // SYSTEM_ERROR, PERMISSION_DENIED, keystore2 not running (-1), and a killed client.
    for status in [Some(4), Some(6), Some(255), None] {
        assert_eq!(KeyDeletion::from_output(&output(status)), None, "{status:?}");
    }
}

#[test]
fn a_key_is_deleted_by_its_alias_as_its_user() {
    let directory = temporary_directory("a_key_is_deleted_by_its_alias_as_its_user");
    let keystore = DeviceKeystore::new(client(&directory, 0));
    assert!(keystore.is_available());
    // The alias is passed as one argument, whatever it holds.
    let alias = "a key=with spaces;$(true)";
    assert_eq!(keystore.delete(own("-u"), own("-g"), alias).unwrap(), KeyDeletion::Deleted);
    let record = fs::read_to_string(directory.join("record")).unwrap();
    let lines: Vec<&str> = record.lines().collect();
    assert_eq!(lines, vec!["delete", &format!("--name={alias}"), &own("-u").to_string()]);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn a_missing_key_is_not_an_error() {
    let directory = temporary_directory("a_missing_key_is_not_an_error");
    let keystore = DeviceKeystore::new(client(&directory, 7));
    assert_eq!(keystore.delete(own("-u"), own("-g"), "k").unwrap(), KeyDeletion::NotFound);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn other_failures_are_errors_with_their_status() {
    let directory = temporary_directory("other_failures_are_errors_with_their_status");
    let keystore = DeviceKeystore::new(client(&directory, 255));
    match keystore.delete(own("-u"), own("-g"), "k") {
        Err(CommandError::Failed { status, .. }) => assert_eq!(status, Some(255)),
        other => panic!("{other:?}"),
    }
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn a_missing_client_is_not_available() {
    let directory = temporary_directory("a_missing_client_is_not_available");
    let keystore = DeviceKeystore::new(directory.join("keystore_cli_v2"));
    assert!(!keystore.is_available());
    assert!(matches!(keystore.delete(own("-u"), own("-g"), "k"), Err(CommandError::Spawn { .. })));
    let _ = fs::remove_dir_all(&directory);
}
