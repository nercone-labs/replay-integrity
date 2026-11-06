//! Tests of the parsers of Android system program output, using output captured from
//! Android 17 (API 37), the formats documented by `cmd package help`, and the format of
//! `/data/system/packages.list` written by `PackageManagerService` (`Settings.writePackageListLPr`).

use android::{Capability, CapabilitySet, ComponentName, ComponentState, PackageList, PackageManager, ProcessCapabilities, ProcessInfo};

#[test]
fn component_names_expand_relative_classes() {
    let component = ComponentName::parse("com.google.android.gms/.fonts.provider.FontsProvider").unwrap();
    assert_eq!(component.package, "com.google.android.gms");
    assert_eq!(component.class_name(), "com.google.android.gms.fonts.provider.FontsProvider");
    assert_eq!(component.to_string(), "com.google.android.gms/.fonts.provider.FontsProvider");
    let absolute = ComponentName::parse("a.b/c.d.Service").unwrap();
    assert_eq!(absolute.class_name(), "c.d.Service");
    for invalid in ["nopackage", "/x", "a.b/", "a.b/.", "a b/c"] {
        assert!(ComponentName::parse(invalid).is_none(), "{invalid}");
    }
}

#[test]
fn users_are_read_from_user_info_entries() {
    let output = "Users:\n\tUserInfo{0:Owner:4c13} running\n\tUserInfo{10:Work profile:1030}\n\tUserInfo{150:Private:1090} running\n";
    assert_eq!(PackageManager::parse_users(output), vec![0, 10, 150]);
    assert!(PackageManager::parse_users("Error: no users").is_empty());
}

const DUMP: &str = "Activity Resolver Table:
  Non-Data Actions:
    User 0:
      disabledComponents:
        com.google.android.gms.fonts.update.UpdateSchedulerService
Packages:
  Package [com.google.android.gms] (41cd270):
    User 0: ceDataInode=1 installed=true hidden=false
      gids=[3003]
      disabledComponents:
        com.google.android.gms.pay.deeplink.AliasProcessImageResourceActivity
        com.google.android.gms.fonts.provider.FontsProvider
      enabledComponents:
        com.google.android.gms.fonts.update.UpdateSchedulerService
      lastDisabledCaller: shell
    User 1: ceDataInode=2 installed=true
      enabledComponents:
        com.google.android.gms.fonts.provider.FontsProvider
    User 10: ceDataInode=3 installed=true
      disabledComponents:
        com.google.android.gms.fonts.update.UpdateSchedulerService

Hidden system packages:
  Package [com.google.android.gms] (1a2b3c):
    User 1: ceDataInode=0 installed=true
      disabledComponents:
        com.google.android.gms.fonts.update.UpdateSchedulerService
Queries:
  User 2:
      disabledComponents:
        com.google.android.gms.fonts.provider.FontsProvider
";

#[test]
fn component_states_are_read_per_user() {
    let provider = "com.google.android.gms.fonts.provider.FontsProvider";
    let scheduler = "com.google.android.gms.fonts.update.UpdateSchedulerService";
    assert_eq!(PackageManager::parse_component_state(DUMP, 0, provider), ComponentState::Disabled);
    assert_eq!(PackageManager::parse_component_state(DUMP, 0, scheduler), ComponentState::Enabled);
    assert_eq!(PackageManager::parse_component_state(DUMP, 1, provider), ComponentState::Enabled);
    assert_eq!(PackageManager::parse_component_state(DUMP, 1, scheduler), ComponentState::Default);
    assert_eq!(PackageManager::parse_component_state(DUMP, 10, scheduler), ComponentState::Disabled);
    // "User 1:" must not match the section of user 10, and lines after a list end it.
    assert_eq!(PackageManager::parse_component_state(DUMP, 10, provider), ComponentState::Default);
    assert_eq!(PackageManager::parse_component_state(DUMP, 0, "lastDisabledCaller: shell"), ComponentState::Default);
    // Sections other than Packages: describe other settings and are ignored.
    assert_eq!(PackageManager::parse_component_state(DUMP, 2, provider), ComponentState::Default);
    assert_eq!(PackageManager::parse_component_state(DUMP, 1, scheduler), ComponentState::Default);
    for state in [ComponentState::Default, ComponentState::Enabled, ComponentState::Disabled] {
        assert_eq!(ComponentState::from_name(state.name()), Some(state));
    }
}

#[test]
fn process_names_are_the_first_argument() {
    assert_eq!(ProcessInfo::name_of(b"system_server\0\0\0\0"), "system_server");
    assert_eq!(ProcessInfo::name_of(b"/system/bin/sh\0-c\0x\0"), "/system/bin/sh");
    let process = ProcessInfo { pid: 1, name: "com.android.systemui:screenshot".to_string() };
    assert!(process.belongs_to("com.android.systemui"));
    assert!(!process.belongs_to("com.android.system"));
    assert!(ProcessInfo { pid: 1, name: "com.android.systemui".to_string() }.belongs_to("com.android.systemui"));
}

#[test]
fn capabilities_have_the_numbers_and_names_of_linux() {
    // <linux/capability.h>
    let expected = [
        (Capability::CHOWN, 0, "CAP_CHOWN"),
        (Capability::DAC_OVERRIDE, 1, "CAP_DAC_OVERRIDE"),
        (Capability::DAC_READ_SEARCH, 2, "CAP_DAC_READ_SEARCH"),
        (Capability::FOWNER, 3, "CAP_FOWNER"),
        (Capability::FSETID, 4, "CAP_FSETID"),
        (Capability::KILL, 5, "CAP_KILL"),
        (Capability::SETGID, 6, "CAP_SETGID"),
        (Capability::SETUID, 7, "CAP_SETUID"),
        (Capability::SETPCAP, 8, "CAP_SETPCAP"),
        (Capability::LINUX_IMMUTABLE, 9, "CAP_LINUX_IMMUTABLE"),
        (Capability::NET_BIND_SERVICE, 10, "CAP_NET_BIND_SERVICE"),
        (Capability::NET_BROADCAST, 11, "CAP_NET_BROADCAST"),
        (Capability::NET_ADMIN, 12, "CAP_NET_ADMIN"),
        (Capability::NET_RAW, 13, "CAP_NET_RAW"),
        (Capability::IPC_LOCK, 14, "CAP_IPC_LOCK"),
        (Capability::IPC_OWNER, 15, "CAP_IPC_OWNER"),
        (Capability::SYS_MODULE, 16, "CAP_SYS_MODULE"),
        (Capability::SYS_RAWIO, 17, "CAP_SYS_RAWIO"),
        (Capability::SYS_CHROOT, 18, "CAP_SYS_CHROOT"),
        (Capability::SYS_PTRACE, 19, "CAP_SYS_PTRACE"),
        (Capability::SYS_PACCT, 20, "CAP_SYS_PACCT"),
        (Capability::SYS_ADMIN, 21, "CAP_SYS_ADMIN"),
        (Capability::SYS_BOOT, 22, "CAP_SYS_BOOT"),
        (Capability::SYS_NICE, 23, "CAP_SYS_NICE"),
        (Capability::SYS_RESOURCE, 24, "CAP_SYS_RESOURCE"),
        (Capability::SYS_TIME, 25, "CAP_SYS_TIME"),
        (Capability::SYS_TTY_CONFIG, 26, "CAP_SYS_TTY_CONFIG"),
        (Capability::MKNOD, 27, "CAP_MKNOD"),
        (Capability::LEASE, 28, "CAP_LEASE"),
        (Capability::AUDIT_WRITE, 29, "CAP_AUDIT_WRITE"),
        (Capability::AUDIT_CONTROL, 30, "CAP_AUDIT_CONTROL"),
        (Capability::SETFCAP, 31, "CAP_SETFCAP"),
        (Capability::MAC_OVERRIDE, 32, "CAP_MAC_OVERRIDE"),
        (Capability::MAC_ADMIN, 33, "CAP_MAC_ADMIN"),
        (Capability::SYSLOG, 34, "CAP_SYSLOG"),
        (Capability::WAKE_ALARM, 35, "CAP_WAKE_ALARM"),
        (Capability::BLOCK_SUSPEND, 36, "CAP_BLOCK_SUSPEND"),
        (Capability::AUDIT_READ, 37, "CAP_AUDIT_READ"),
        (Capability::PERFMON, 38, "CAP_PERFMON"),
        (Capability::BPF, 39, "CAP_BPF"),
        (Capability::CHECKPOINT_RESTORE, 40, "CAP_CHECKPOINT_RESTORE"),
    ];
    assert_eq!(expected.len(), Capability::NAMES.len());
    for (capability, number, name) in expected {
        assert_eq!(capability, Capability(number));
        assert_eq!(capability.name(), Some(name));
        assert_eq!(capability.to_string(), name);
    }
    assert_eq!(Capability(41).name(), None);
    assert_eq!(Capability(41).to_string(), "capability 41");
}

#[test]
fn capability_sets_have_one_bit_per_capability() {
    let set = CapabilitySet::parse("0000000000200080").unwrap();
    assert!(set.contains(Capability::SETUID));
    assert!(set.contains(Capability::SYS_ADMIN));
    assert!(!set.contains(Capability::CHOWN));
    assert!(!set.contains(Capability::SYS_PTRACE));
    let full = CapabilitySet::parse("ffffffffffffffff").unwrap();
    assert!(full.contains(Capability(63)));
    assert!(!full.contains(Capability(64)));
    assert!(!full.contains(Capability(u8::MAX)));
    for invalid in ["", "xyz", "10000000000000000"] {
        assert_eq!(CapabilitySet::parse(invalid), None, "{invalid}");
    }
}

/// The capability fields of `/proc/self/status`, as `cat` shows them in a root shell of
/// Magisk 30.7 with the "Restrict" policy (Android 16).
const RESTRICTED_STATUS: &str = "Name:\tcat
Umask:\t0077
State:\tR (running)
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000080
CapAmb:\t0000000000000000
NoNewPrivs:\t0
";

#[test]
fn process_capabilities_are_read_from_the_status_file() {
    let restricted = ProcessCapabilities::parse(RESTRICTED_STATUS).unwrap();
    assert_eq!(restricted.inheritable, CapabilitySet(0));
    assert_eq!(restricted.permitted, CapabilitySet(0));
    assert_eq!(restricted.effective, CapabilitySet(0));
    assert_eq!(restricted.bounding, CapabilitySet(1 << 7));
    assert_eq!(restricted.ambient, CapabilitySet(0));

    let full =
        RESTRICTED_STATUS.replace("CapPrm:\t0000000000000000", "CapPrm:\t000001ffffffffff").replace("CapEff:\t0000000000000000", "CapEff:\t000001ffffffffff");
    let full = ProcessCapabilities::parse(&full).unwrap();
    assert_eq!(full.effective, CapabilitySet(0x1ff_ffff_ffff));
    assert!(full.effective.contains(Capability::SYS_ADMIN));

    // Kernels before Linux 4.3 have no ambient capabilities.
    let old = RESTRICTED_STATUS.replace("CapAmb:\t0000000000000000\n", "");
    assert_eq!(ProcessCapabilities::parse(&old).unwrap().ambient, CapabilitySet(0));

    assert_eq!(ProcessCapabilities::parse(&RESTRICTED_STATUS.replace("CapEff:\t0000000000000000\n", "")), None);
    assert_eq!(ProcessCapabilities::parse(&RESTRICTED_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\tinvalid")), None);
    assert_eq!(ProcessCapabilities::parse(&RESTRICTED_STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\tinvalid")), None);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn process_capabilities_of_the_calling_thread_are_readable() {
    let current = ProcessCapabilities::current().unwrap();
    assert_eq!(current, ProcessCapabilities::of(std::process::id()).unwrap());
}

#[test]
fn package_names_are_read_from_package_lines() {
    let output = "package:com.android.systemui\npackage:android\n\npackage:\nWARNING: linker\n";
    assert_eq!(PackageManager::parse_packages(output), ["com.android.systemui", "android"]);
    assert!(PackageManager::parse_packages("").is_empty());
}

#[test]
fn package_list_lines_give_names_and_application_ids() {
    // `name uid debuggable dataDir seinfo gids profileable versionCode isSystem installer`.
    let list = "com.google.android.gms 10145 0 /data/user/0/com.google.android.gms default:privapp:targetSdkVersion=36 3002,3003 0 254832035 1 com.android.vending\n\
                com.google.android.gsf 10145 0 /data/user/0/com.google.android.gsf default:privapp:targetSdkVersion=36 3003 0 36 1 @system\n\
                com.android.vending 10160 0 /data/user/0/com.android.vending default:privapp:targetSdkVersion=36 none 0 84831230 1 @system\n\
                \n\
                broken\n\
                bad.uid abc 0 /data\n";
    let packages = PackageList::parse(list);
    assert_eq!(packages.len(), 3);
    assert_eq!(packages[0].name, "com.google.android.gms");
    assert_eq!(packages[0].app_id, 10145);
    assert_eq!(PackageList::app_id_of(&packages, "com.android.vending"), Some(10160));
    assert_eq!(PackageList::app_id_of(&packages, "missing"), None);
}

#[test]
fn uids_combine_users_and_application_ids() {
    // `UserHandle.getUid`: userId * PER_USER_RANGE + appId.
    assert_eq!(PackageList::uid(0, 10145), 10145);
    assert_eq!(PackageList::uid(10, 10145), 1_010_145);
    assert_eq!(PackageList::app_id(1_010_145), 10145);
}
