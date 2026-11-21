//! Tests of the reading of control groups, against the format of `/proc/<pid>/cgroup`
//! (cgroups(7): `hierarchy-ID:controller-list:cgroup-path`) and the groups Android makes for
//! application processes (`uid_<uid>/pid_<pid>`).

use std::fs;

use android::ControlGroup;

#[test]
fn each_hierarchy_gives_its_path() {
    // An Android 13 process: the unified hierarchy, and v1 hierarchies with their controllers.
    let text = "0::/uid_10123/pid_4567\n2:cpuset:/top-app\n1:cpu:/foreground\n";
    assert_eq!(ControlGroup::paths_of(text), ["/uid_10123/pid_4567", "/top-app", "/foreground"]);
    // A path may hold colons: only the first two separate the fields.
    assert_eq!(ControlGroup::paths_of("0::/a:b\n"), ["/a:b"]);
    assert!(ControlGroup::paths_of("").is_empty());
}

#[test]
fn groups_of_application_processes_are_told_apart() {
    assert!(ControlGroup::is_application("/uid_10123/pid_4567"));
    assert!(ControlGroup::is_application("/apps/uid_10123/pid_4567"));
    // An application of another user (user 10, app ID 10123).
    assert!(ControlGroup::is_application("/apps/uid_1010123/pid_4567"));
    // The groups of processes of the system are not those of applications.
    assert!(!ControlGroup::is_application("/system/uid_0/pid_450"));
    assert!(!ControlGroup::is_application("/system/uid_1000/pid_450"));
    assert!(!ControlGroup::is_application("/system/uid_1001000/pid_450"));
    assert!(!ControlGroup::is_application("/"));
    assert!(!ControlGroup::is_application("/system"));
    assert!(!ControlGroup::is_application("/uid_0"));
    assert!(!ControlGroup::is_application("/uid_/pid_1"));
    assert!(!ControlGroup::is_application("/uid_1x/pid_2"));
    assert!(!ControlGroup::is_application("/pid_2/uid_1"));
}

#[test]
fn a_move_writes_the_process_into_each_root_that_exists() {
    let base = std::env::temp_dir().join(format!("android-cgroup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("sys/fs/cgroup")).unwrap();
    fs::write(base.join("sys/fs/cgroup/cgroup.procs"), "").unwrap();
    // `/acct` is a directory without `cgroup.procs`, as when it is not mounted: it is skipped,
    // and no file is created in it.
    fs::create_dir_all(base.join("acct")).unwrap();
    let moved = ControlGroup::move_to_roots(&base);
    assert_eq!(moved, [base.join("sys/fs/cgroup")]);
    assert_eq!(fs::read_to_string(base.join("sys/fs/cgroup/cgroup.procs")).unwrap(), std::process::id().to_string());
    assert!(!base.join("acct/cgroup.procs").exists());
    let _ = fs::remove_dir_all(&base);
}
