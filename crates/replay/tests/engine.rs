//! Tests of the engine's pieces and of an `apply` against a temporary root directory, so no
//! device is needed. The keybox fixture holds throwaway keys generated for the tests.

use std::fs;
use std::path::PathBuf;

use replay::{
    ApplyMode, BootHook, BootReport, Conflicts, Engine, Files, Fingerprint, FingerprintProblem, Layout, Log, Module, PackageWatcher, PatchDate, Settings,
    SpoofFlag, SpoofFlags, Target, TargetList, TargetMode, WatchReport,
};

const TEST_KEYBOX: &str = include_str!("../../keybox/tests/fixtures/test-keybox.xml");

fn temporary_root() -> PathBuf {
    let base = std::env::temp_dir().join(format!("replay-test-{}-{}", std::process::id(), nanos()));
    fs::create_dir_all(base.join("data/adb/tricky_store")).unwrap();
    base
}

fn nanos() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
}

#[test]
fn patch_dates_convert_to_attestation_levels() {
    let date = PatchDate::parse("2026-02-05").unwrap();
    assert_eq!(date.os_patch_level(), 202_602);
    assert_eq!(date.long_patch_level(), 20_260_205);
    assert_eq!(date.to_string(), "2026-02-05");
    // Invalid dates are refused.
    assert!(PatchDate::parse("2026-13-01").is_none());
    assert!(PatchDate::parse("2026-02-30").is_none());
    assert!(PatchDate::parse("2026-2-5").is_none());
}

#[test]
fn a_well_formed_fingerprint_has_no_problems() {
    let text = "FINGERPRINT=google/bluejay_beta/bluejay:CANARY/ZP11.000000.000/12345678:user/release-keys\n\
                MANUFACTURER=Google\nMODEL=Pixel 6a\nBRAND=google\nPRODUCT=bluejay_beta\nDEVICE=bluejay\n\
                SECURITY_PATCH=2026-11-05\n# Estimated Expiry: 2099-01-01\n";
    let fingerprint = Fingerprint::parse(text);
    assert!(fingerprint.problems(0).is_empty());
    assert_eq!(fingerprint.security_patch(), PatchDate::parse("2026-11-05"));
    assert!(fingerprint.expires().is_some());
}

#[test]
fn an_inconsistent_or_expired_fingerprint_is_flagged() {
    // DEVICE disagrees with the fingerprint's device field.
    let text = "FINGERPRINT=google/bluejay_beta/bluejay:CANARY/ZP11.000000.000/1:user/release-keys\n\
                MANUFACTURER=Google\nMODEL=Pixel\nBRAND=google\nPRODUCT=bluejay_beta\nDEVICE=raven\n\
                SECURITY_PATCH=2026-11-05\n# Estimated Expiry: 2000-01-01\n";
    let problems = Fingerprint::parse(text).problems(1_000_000_000);
    assert!(problems.contains(&FingerprintProblem::Inconsistent { key: "DEVICE".to_string() }));
    assert!(problems.iter().any(|problem| matches!(problem, FingerprintProblem::Expired { .. })));
    // A userdebug/test-keys build is not accepted as a certified build.
    let test_keys = text.replace("user/release-keys", "userdebug/test-keys");
    assert!(Fingerprint::parse(&test_keys).problems(0).contains(&FingerprintProblem::NotRelease));
}

#[test]
fn applying_settings_writes_flags_and_the_patch_property() {
    let text =
        "FINGERPRINT=google/p/p:CANARY/A/1:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel\nBRAND=google\nPRODUCT=p\nDEVICE=p\nSECURITY_PATCH=2026-11-05\n";
    let spoof = SpoofFlags::recommended(Some(34));
    let prepared = Fingerprint::parse(text).with_settings(&spoof);
    assert_eq!(prepared.file.get("spoofProvider"), Some("0"));
    assert_eq!(prepared.file.get("spoofBuild"), Some("1"));
    assert_eq!(prepared.file.get("spoofVendingFinger"), Some("1"));
    assert_eq!(prepared.file.get("ro.build.version.security_patch"), Some("2026-11-05"));
    // On Android 12L and earlier the Play Store fingerprint spoof is off.
    assert_eq!(SpoofFlags::recommended(Some(32)).get(SpoofFlag::VendingFinger), Some(false));
    assert_eq!(SpoofFlags::recommended(Some(33)).get(SpoofFlag::VendingFinger), Some(true));
}

#[test]
fn the_target_list_always_includes_the_play_stack_and_excludes_xposed() {
    let third_party = ["com.example.bank".to_string(), "org.lsposed.manager".to_string()];
    // A wallet application that came with the system image is still a target.
    let installed = ["android".to_string(), "com.google.android.apps.walletnfcrel".to_string()];
    let settings = Settings { extra_packages: vec!["com.extra.app".to_string()], ..Settings::default() };
    let list = TargetList::build(&installed, &third_party, &settings);
    let packages: Vec<&str> = list.packages().collect();
    assert!(packages.contains(&"com.google.android.gms"));
    assert!(packages.contains(&"com.android.vending"));
    assert!(packages.contains(&"com.example.bank"));
    assert!(packages.contains(&"com.extra.app"));
    assert!(packages.contains(&"com.google.android.apps.walletnfcrel"));
    // Xposed managers are kept out, since a hooked attestation breaks STRONG.
    assert!(!packages.contains(&"org.lsposed.manager"));
    // No package appears twice.
    let mut sorted = packages.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), packages.len());
    // The rendered list round-trips, keeping modes.
    let rendered = TargetList {
        targets: vec![replay::Target { package: "a".into(), mode: TargetMode::Generate }, replay::Target { package: "b".into(), mode: TargetMode::Auto }],
    }
    .render();
    let parsed = TargetList::parse(&rendered);
    assert_eq!(parsed.targets[0].mode, TargetMode::Generate);
    assert_eq!(parsed.targets[1].mode, TargetMode::Auto);
}

#[test]
fn a_fresh_keybox_is_installed_and_the_previous_one_kept() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let keybox_path = layout.tricky_store().join("keybox.xml");
    // Seed an old keybox so installing a new one keeps the old.
    fs::write(&keybox_path, "old keybox").unwrap();
    let mut engine = Engine::new(layout.clone());
    let report = engine.install_keybox(TEST_KEYBOX.as_bytes(), Some("test".to_string()), None).unwrap();
    assert!(report.changed);
    // The throwaway keybox has no Google-signed chain, so no key is "usable" (STRONG) — but it is installable (structurally sound).
    assert!(report.verdict.unwrap().is_installable());
    assert_eq!(fs::read_to_string(&keybox_path).unwrap(), TEST_KEYBOX);
    assert_eq!(fs::read_to_string(layout.store().join("previous-keybox.xml")).unwrap(), "old keybox");
    // Installing the same keybox again reports no change.
    assert!(!engine.install_keybox(TEST_KEYBOX.as_bytes(), None, None).unwrap().changed);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn apply_writes_the_configuration_from_the_installed_fingerprint() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    // Install a fingerprint first (no restart, so no device is needed).
    let text =
        "FINGERPRINT=google/p/p:CANARY/A/1:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel\nBRAND=google\nPRODUCT=p\nDEVICE=p\nSECURITY_PATCH=2026-11-05\n";
    let mut engine = Engine::new(layout.clone());
    engine.install_fingerprint(text.as_bytes(), None, &Settings::default()).unwrap();
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot).unwrap();
    assert_eq!(report.security_patch.as_deref(), Some("2026-11-05"));
    assert!(!report.daemon_restarted);
    // At boot the target list is kept: the package manager does not run yet.
    assert!(!report.targets_rebuilt);
    // security_patch.txt is written in the per-component form TEESimulator-RS reads.
    let patch = fs::read_to_string(layout.tricky_store().join("security_patch.txt")).unwrap();
    assert!(patch.contains("system=2026-11-05") && patch.contains("boot=2026-11-05") && patch.contains("vendor=2026-11-05"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn excluded_packages_and_the_target_mode_shape_the_list() {
    let third_party = ["com.example.bank".to_string(), "com.example.game".to_string()];
    let settings = Settings {
        excluded_packages: vec!["com.example.game".to_string(), "com.google.android.gms".to_string()],
        target_mode: TargetMode::Generate,
        ..Settings::default()
    };
    let list = TargetList::build(&[], &third_party, &settings);
    let packages: Vec<&str> = list.packages().collect();
    assert!(packages.contains(&"com.example.bank"));
    assert!(!packages.contains(&"com.example.game"));
    // The Play stack cannot be excluded.
    assert!(packages.contains(&"com.google.android.gms"));
    assert!(list.targets.iter().all(|target| target.mode == TargetMode::Generate));
    assert!(list.render().lines().all(|line| line.ends_with('!')));
}

#[test]
fn package_names_follow_the_rules_of_the_package_manager() {
    for valid in ["com.example", "a.b", "com.example.app_2", "A.B9"] {
        assert!(Target::is_package_name(valid), "{valid}");
    }
    for invalid in ["", "example", "com..example", "com.1example", ".com.example", "com.example.", "com.exa mple", "com.example\nevil.app", "com/example"] {
        assert!(!Target::is_package_name(invalid), "{invalid:?}");
    }
}

#[test]
fn settings_that_could_corrupt_the_target_list_are_rejected() {
    assert!(Settings::parse(br#"{"extraPackages":["com.example.app"]}"#).is_ok());
    assert!(Settings::parse(br#"{"extraPackages":["com.example.app\nother"]}"#).is_err());
    assert!(Settings::parse(br#"{"excludedPackages":["not a package"]}"#).is_err());
    assert!(Settings::parse(br#"{"spoofOverrides":[["spoofNothing",true]]}"#).is_err());
    assert!(Settings::parse(br#"{"spoofOverrides":[["spoofProvider",true]]}"#).is_ok());
    assert!(Settings::parse(b"not json").is_err());
    // Missing fields take their defaults.
    assert_eq!(Settings::parse(b"{}").unwrap(), Settings::default());
}

#[test]
fn apply_saves_the_settings_that_boot_applies_again() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let text =
        "FINGERPRINT=google/p/p:CANARY/A/1:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel\nBRAND=google\nPRODUCT=p\nDEVICE=p\nSECURITY_PATCH=2026-11-05\n";
    fs::create_dir_all(layout.modules().join("playintegrityfix")).unwrap();
    let settings = Settings { spoof_overrides: vec![("spoofProvider".to_string(), true)], ..Settings::default() };
    let mut engine = Engine::new(layout.clone());
    engine.install_fingerprint(text.as_bytes(), None, &settings).unwrap();
    engine.apply(&settings, ApplyMode::NoRestart).unwrap();
    assert_eq!(engine.store.settings().unwrap(), settings);
    // Something else (a script of the module) resets the flag; applying the saved settings at boot restores it.
    let pif = layout.modules().join("playintegrityfix/custom.pif.prop");
    fs::write(&pif, fs::read_to_string(&pif).unwrap().replace("spoofProvider=1", "spoofProvider=0")).unwrap();
    let saved = engine.store.settings().unwrap();
    engine.apply(&saved, ApplyMode::EarlyBoot).unwrap();
    assert!(fs::read_to_string(&pif).unwrap().contains("spoofProvider=1"));
    // The fingerprint is kept in the store as it was installed, without flags.
    let stored = fs::read_to_string(layout.store().join("fingerprint.prop")).unwrap();
    assert!(!stored.contains("spoofProvider"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_boot_hook_runs_a_copy_of_the_engine_at_a_fixed_path() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    fs::create_dir_all(root.join("data/adb/magisk")).unwrap();
    let executable = root.join("engine-binary");
    fs::write(&executable, b"#!/system/bin/sh\n").unwrap();
    let hook = BootHook::install(&layout, &executable, "dev.nercone.replayintegrity", false).unwrap();
    assert!(hook.is_installed());
    let script = fs::read_to_string(&hook.scripts[0]).unwrap();
    let copy = layout.store().join("replay");
    assert!(script.contains(&format!("'{}' 'boot' '--package' 'dev.nercone.replayintegrity'", copy.display())), "{script}");
    // Without the package watcher, no service script is installed.
    assert!(!hook.watches);
    assert!(!root.join("data/adb/service.d").join(BootHook::FILE_NAME).exists());
    assert_eq!(fs::read(&copy).unwrap(), b"#!/system/bin/sh\n");
    // A package name that is not one is refused, so the script cannot carry anything else.
    assert!(BootHook::script(&layout, "x'; rm -rf /; '").is_err());
    let removed = BootHook::remove(&layout).unwrap();
    assert!(!removed.is_installed());
    assert!(!copy.exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_uninstalled_application_is_told_from_the_package_list() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let package = "dev.nercone.replayintegrity";
    // Without a readable package list, the application counts as installed.
    assert!(Engine::is_package_present(&layout, package));
    fs::create_dir_all(root.join("data/system")).unwrap();
    let list = root.join("data/system/packages.list");
    fs::write(&list, "com.other.app 10100 0 /data/user/0/com.other.app default:targetSdkVersion=36 3003 0 1 1 com.android.vending\n").unwrap();
    assert!(!Engine::is_package_present(&layout, package));
    fs::write(&list, format!("com.other.app 10100 0 /data/user/0/com.other.app default 3003\n{package} 10232 0 /data/user/0/{package} default none\n"))
        .unwrap();
    assert!(Engine::is_package_present(&layout, package));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_package_listed_twice_in_target_txt_appears_once() {
    let list = TargetList::parse("com.example\n[other.xml]\ncom.example!\ncom.other?\n");
    let packages: Vec<&str> = list.packages().collect();
    assert_eq!(packages, ["com.example", "com.other"]);
    assert_eq!(list.targets[0].mode, TargetMode::Auto);
}

#[test]
fn boot_reports_its_outcome_by_name() {
    let report = serde_json::to_value(BootReport::Uninstalled).unwrap();
    assert_eq!(report["outcome"], "uninstalled");
}

#[test]
fn settings_as_the_application_writes_them_are_read() {
    // The JSON kotlinx.serialization writes for the application's `EngineSettings`.
    let settings =
        Settings::parse(br#"{"extraPackages":["com.extra"],"excludedPackages":[],"targetMode":"patch","spoofOverrides":[["spoofProvider",true]]}"#).unwrap();
    assert_eq!(settings.target_mode, TargetMode::Patch);
    assert_eq!(settings.spoof_flags(Some(34)).get(SpoofFlag::Provider), Some(true));
    assert_eq!(settings.extra_packages, vec!["com.extra".to_string()]);
}

fn write_module(directory: &std::path::Path, name: &str) {
    fs::create_dir_all(directory).unwrap();
    fs::write(directory.join("module.prop"), format!("id={}\nname={name}\nversion=v1\nversionCode=1\n", directory.file_name().unwrap().to_string_lossy()))
        .unwrap();
}

#[test]
fn conflicting_modules_are_disabled_with_the_marker_of_the_root_managers() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    // An installed conflict with a pending update, a conflict waiting only in modules_update, a
    // conflict the user already disabled, and a module that does not conflict.
    write_module(&layout.modules().join("TrickyStore"), "Tricky Store");
    write_module(&layout.modules_update().join("TrickyStore"), "Tricky Store");
    write_module(&layout.modules_update().join("playcurl"), "playcurl");
    write_module(&layout.modules().join("safetynet-fix"), "Universal SafetyNet Fix");
    fs::write(layout.modules().join("safetynet-fix/disable"), "").unwrap();
    write_module(&layout.modules().join("zygisksu"), "Zygisk Next");
    let mut engine = Engine::new(layout.clone());
    let disabled = engine.disable_conflicts().unwrap();
    let ids: Vec<&str> = disabled.iter().map(|module| module.id.as_str()).collect();
    assert_eq!(ids, ["TrickyStore", "playcurl"]);
    assert!(disabled.iter().all(|module| module.disabled && !module.is_active()));
    // The marker is in the installed directory and in the pending update, which replaces it at
    // the next boot; nothing is removed, so the user can enable the module again.
    assert!(layout.modules().join("TrickyStore").join(Module::DISABLE).is_file());
    assert!(layout.modules_update().join("TrickyStore").join(Module::DISABLE).is_file());
    assert!(layout.modules_update().join("playcurl").join(Module::DISABLE).is_file());
    assert!(layout.modules().join("TrickyStore/module.prop").is_file());
    assert!(!layout.modules().join("TrickyStore").join(Module::REMOVE).exists());
    // A module that does not conflict is left alone.
    assert!(!layout.modules().join("zygisksu").join(Module::DISABLE).exists());
    assert!(Conflicts::active(&layout).is_empty());
    // Doing it again changes nothing.
    assert!(engine.disable_conflicts().unwrap().is_empty());
    let _ = fs::remove_dir_all(&root);
}

/// A `custom.pif.json` as PlayIntegrityFork documents it: a flat object of strings, with
/// entries commented out by a `//` prefix, and numbers where other tools write them.
const PIF_JSON: &str = r#"{
  "MANUFACTURER": "Google",
  "MODEL": "Pixel 6a",
  "FINGERPRINT": "google/bluejay_beta/bluejay:CANARY/ZP11.000000.000/12345678:user/release-keys",
  "BRAND": "google",
  "PRODUCT": "bluejay_beta",
  "DEVICE": "bluejay",
  "SECURITY_PATCH": "2026-11-05",
  "DEVICE_INITIAL_SDK_INT": 32,
  "*.build.id": "ZP11.000000.000",
  "//*.security_patch": "2026-11-05",
  "spoofProvider": "0",
  "verboseLogs": false
}"#;

#[test]
fn a_json_fingerprint_reads_as_its_prop_form() {
    let fingerprint = Fingerprint::read(PIF_JSON).unwrap();
    assert!(fingerprint.problems(0).is_empty(), "{:?}", fingerprint.problems(0));
    assert_eq!(fingerprint.file.get("MODEL"), Some("Pixel 6a"));
    assert_eq!(fingerprint.file.get("DEVICE_INITIAL_SDK_INT"), Some("32"));
    assert_eq!(fingerprint.file.get("*.build.id"), Some("ZP11.000000.000"));
    assert_eq!(fingerprint.file.get("spoofProvider"), Some("0"));
    assert_eq!(fingerprint.file.get("verboseLogs"), Some("0"));
    // A commented-out entry stays commented out, and is not an entry.
    assert_eq!(fingerprint.file.get("*.security_patch"), None);
    let rendered = fingerprint.file.render();
    assert!(rendered.lines().any(|line| line == "#*.security_patch=2026-11-05"), "{rendered}");
    // The entries keep the order of the file.
    let keys: Vec<&str> = fingerprint.file.entries().map(|(key, _)| key).collect();
    assert_eq!(&keys[..3], ["MANUFACTURER", "MODEL", "FINGERPRINT"]);
    // A prop file is read as one; a byte order mark before a JSON object is allowed.
    assert_eq!(Fingerprint::read("MODEL=Pixel\n").unwrap().file.get("MODEL"), Some("Pixel"));
    assert_eq!(Fingerprint::read("\u{feff}{\"MODEL\":\"Pixel\"}").unwrap().file.get("MODEL"), Some("Pixel"));
}

#[test]
fn a_json_fingerprint_that_cannot_be_one_prop_file_is_rejected() {
    // A value or key that would become more than one line, or a key that would read back as
    // another key, could add entries that were not in the file.
    for json in [
        r#"{"MODEL": "Pixel\nspoofProvider=1"}"#,
        r#"{"MODEL\nspoofProvider": "1"}"#,
        r#"{"MODEL=x": "1"}"#,
        r#"{"": "1"}"#,
        r#"{"MODEL": ["Pixel"]}"#,
        r#"{"MODEL": {"name": "Pixel"}}"#,
        r#"{"MODEL": "Pixel""#,
    ] {
        assert!(Fingerprint::read(json).is_err(), "{json}");
    }
    // Only an object is a `custom.pif.json`.
    assert!(Fingerprint::from_json(r#"["MODEL"]"#).is_err());
}

#[test]
fn a_json_fingerprint_is_installed_in_the_prop_format() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    fs::create_dir_all(layout.modules().join("playintegrityfix")).unwrap();
    let mut engine = Engine::new(layout.clone());
    let report = engine.install_fingerprint(PIF_JSON.as_bytes(), None, &Settings::default()).unwrap();
    assert!(report.changed);
    let stored = fs::read_to_string(layout.store().join("fingerprint.prop")).unwrap();
    assert!(stored.contains("MODEL=Pixel 6a\n") && !stored.contains('{'), "{stored}");
    let pif = fs::read_to_string(layout.modules().join("playintegrityfix/custom.pif.prop")).unwrap();
    assert!(pif.contains("FINGERPRINT=google/bluejay_beta/bluejay:") && pif.contains("spoofBuild=1"), "{pif}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unchanged_files_are_not_written_again() {
    let root = temporary_root();
    let path = root.join("data/adb/tricky_store/target.txt");
    assert!(Files::write_if_changed(&path, b"com.example\n", 0o644).unwrap());
    let before = fs::metadata(&path).unwrap();
    // The same contents leave the file alone, so programs that watch it see no write.
    assert!(!Files::write_if_changed(&path, b"com.example\n", 0o644).unwrap());
    let after = fs::metadata(&path).unwrap();
    assert_eq!(std::os::unix::fs::MetadataExt::ino(&before), std::os::unix::fs::MetadataExt::ino(&after));
    assert!(Files::write_if_changed(&path, b"com.other\n", 0o644).unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"com.other\n");
    // No temporary file is left behind.
    let names: Vec<String> = fs::read_dir(path.parent().unwrap()).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, ["target.txt"]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_service_script_starts_the_package_watcher() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    fs::create_dir_all(root.join("data/adb/ksud")).unwrap();
    let executable = root.join("engine-binary");
    fs::write(&executable, b"#!/system/bin/sh\n").unwrap();
    let package = "dev.nercone.replayintegrity";
    let hook = BootHook::install(&layout, &executable, package, true).unwrap();
    assert!(hook.watches);
    let service = root.join("data/adb/service.d").join(BootHook::FILE_NAME);
    let script = fs::read_to_string(&service).unwrap();
    let copy = layout.store().join("replay");
    // It runs the store's copy with `watch`, in the background, so the root manager does not wait.
    assert!(script.contains(&format!("'{}' 'watch' '--package' '{package}'", copy.display())), "{script}");
    assert!(script.trim_end().ends_with('&'), "{script}");
    // The early script is installed too, in the directory of KernelSU.
    assert!(root.join("data/adb/post-mount.d").join(BootHook::FILE_NAME).is_file());
    // Turning the watcher off removes the service script and keeps the early one.
    let hook = BootHook::install(&layout, &executable, package, false).unwrap();
    assert!(!hook.watches && hook.is_installed());
    assert!(!service.exists());
    BootHook::remove(&layout).unwrap();
    assert!(!BootHook::current(&layout).is_installed());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn one_package_watcher_holds_the_lock_at_a_time() {
    let root = temporary_root();
    let watcher = PackageWatcher::new(&Layout::new(&root));
    let first = watcher.lock().unwrap();
    assert!(first.is_some());
    // A second holder is refused while the first holds the lock.
    assert!(watcher.lock().unwrap().is_none());
    // The lock names this process, but this process is not a watcher, so none is running: a
    // process ID that was reused by another program is not taken for a watcher.
    assert_eq!(fs::read_to_string(watcher.lock_path()).unwrap(), std::process::id().to_string());
    assert_eq!(watcher.running(), None);
    drop(first);
    assert!(watcher.lock().unwrap().is_some());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_watcher_is_told_by_the_engine_copy_and_the_command() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let watcher = PackageWatcher::new(&layout);
    let copy = layout.store().join("replay").to_string_lossy().into_owned();
    let mut arguments = vec![copy.clone()];
    arguments.extend(watcher.arguments("dev.nercone.replayintegrity"));
    assert!(watcher.is_watcher(&arguments));
    assert!(!watcher.is_watcher(&[copy.clone(), "boot".to_string()]));
    assert!(!watcher.is_watcher(&["/system/bin/sh".to_string(), "watch".to_string()]));
    assert!(!watcher.is_watcher(&[copy]));
    assert!(!watcher.is_watcher(&[]));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_watcher_reports_its_outcome_by_name() {
    assert_eq!(serde_json::to_value(WatchReport::Stopped).unwrap()["outcome"], "stopped");
    assert_eq!(serde_json::to_value(WatchReport::AlreadyRunning { pid: Some(7) }).unwrap()["pid"], 7);
}

#[test]
fn the_log_file_is_rotated_while_it_is_written() {
    let root = temporary_root();
    let path = root.join("replay.log");
    let mut log = Log::new(Some(path.clone()));
    let line = "x".repeat(1024);
    for _ in 0..(Log::MAX_FILE_SIZE / 1024 + 8) {
        log.info(line.clone());
    }
    // The file never grows much past the limit; the older lines are in `.old`.
    assert!(fs::metadata(&path).unwrap().len() <= Log::MAX_FILE_SIZE + 2048);
    assert!(root.join("replay.log.old").is_file());
    let _ = fs::remove_dir_all(&root);
}
