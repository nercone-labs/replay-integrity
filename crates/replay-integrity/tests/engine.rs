//! Tests of the engine's pieces and of an `apply` against a temporary root directory, so no
//! device is needed. The keybox fixture holds throwaway keys generated for the tests.

use std::fs;
use std::path::{Path, PathBuf};

use keybox::{KeyAlgorithm, KeyboxDocument};
use replay_integrity::{
    ApplyMode, BootHook, BootReport, Conflicts, Declined, Engine, Files, Fingerprint, FingerprintProblem, KeyCategory, KeyProblem, KeyRemoval,
    KeyRemovalSettings, KeyVerdict, KeyboxPolicy, KeyboxVerdict, KeystoreConfig, Layout, Log, Module, OutdatedReason, PackageWatcher, PatchDate, PersistedKey,
    Settings, SpoofFlag, SpoofFlags, Target, TargetList, TargetMode, TargetScope, WatchReport,
};

const TEST_KEYBOX: &str = include_str!("../../keybox/tests/fixtures/test-keybox.xml");

/// A new root directory. Tests run at once, and the clock alone may give two of them the same
/// time, so a counter tells them apart.
fn temporary_root() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let count = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("replay-test-{}-{}-{count}", std::process::id(), nanos()));
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
        targets: vec![
            replay_integrity::Target { package: "a".into(), mode: TargetMode::Generate },
            replay_integrity::Target { package: "b".into(), mode: TargetMode::Auto },
        ],
    }
    .render();
    let parsed = TargetList::parse(&rendered);
    assert_eq!(parsed.targets[0].mode, TargetMode::Generate);
    assert_eq!(parsed.targets[1].mode, TargetMode::Auto);
}

/// The private keys and certificates of a keybox, which is what a keystore daemon reads.
fn key_material(text: &str) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    KeyboxDocument::read(text)
        .unwrap()
        .keys()
        .map(|key| (key.private_key_block.data.clone(), key.certificates.iter().map(|certificate| certificate.der.clone()).collect()))
        .collect()
}

/// The keybox fixture with the defect of a keybox a mirror served: a `DeviceID` value without
/// its closing quote, which hides every `<Key>` from an XML parser.
fn malformed_keybox() -> String {
    TEST_KEYBOX.replacen("not an attestation key)\">", "not an attestation key)>", 1)
}

#[test]
fn a_fresh_keybox_is_installed_and_the_previous_one_kept() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let keybox_path = layout.tricky_store().join("keybox.xml");
    // Seed an old keybox so installing a new one keeps the old.
    fs::write(&keybox_path, "old keybox").unwrap();
    let mut engine = Engine::new(layout.clone());
    let report = engine.install_keybox(TEST_KEYBOX.as_bytes(), Some("test".to_string()), None, KeyboxPolicy::Replace, false).unwrap();
    assert!(report.changed);
    assert_eq!(report.declined, None);
    // The throwaway keybox has no Google-signed chain, so no key is "usable" (STRONG) — but it is installable (structurally sound).
    assert!(report.verdict.unwrap().is_installable());
    // What is installed is a well-formed keybox with the same keys.
    let installed = fs::read_to_string(&keybox_path).unwrap();
    assert_eq!(KeyboxDocument::parse(&installed).unwrap().defect, None);
    assert_eq!(key_material(&installed), key_material(TEST_KEYBOX));
    assert_eq!(report.sha256, Files::sha256(installed.as_bytes()));
    assert_eq!(fs::read_to_string(layout.store().join("previous-keybox.xml")).unwrap(), "old keybox");
    // Installing the same keybox again reports no change.
    assert!(!engine.install_keybox(TEST_KEYBOX.as_bytes(), None, None, KeyboxPolicy::Replace, false).unwrap().changed);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_malformed_keybox_is_installed_as_a_well_formed_one() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let mut engine = Engine::new(layout.clone());
    let malformed = malformed_keybox();
    let report = engine.install_keybox(malformed.as_bytes(), None, None, KeyboxPolicy::NoDowngrade, true).unwrap();
    assert!(report.changed);
    assert!(report.verdict.unwrap().defect.is_some());
    let installed = fs::read_to_string(layout.tricky_store().join("keybox.xml")).unwrap();
    assert_eq!(KeyboxDocument::parse(&installed).unwrap().defect, None);
    assert_eq!(key_material(&installed), key_material(TEST_KEYBOX));
    // The same malformed keybox offered again changes nothing and is not declined.
    let again = engine.install_keybox(malformed.as_bytes(), None, None, KeyboxPolicy::NoDowngrade, true).unwrap();
    assert!(!again.changed);
    assert_eq!(again.declined, None);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_malformed_keybox_is_rejected_when_not_lenient() {
    // The recovery of broken markup is a concession to one mirror, reached with `lenient`, not a
    // general one. Offered without it, a malformed keybox is an error, so another source's broken
    // keybox is declined and the next source tried rather than salvaged. The installed keybox is
    // left untouched.
    let root = temporary_root();
    let layout = Layout::new(&root);
    let keybox_path = layout.tricky_store().join("keybox.xml");
    fs::write(&keybox_path, TEST_KEYBOX).unwrap();
    let mut engine = Engine::new(layout.clone());
    let malformed = malformed_keybox();
    assert!(engine.install_keybox(malformed.as_bytes(), None, None, KeyboxPolicy::Replace, false).is_err());
    assert!(engine.inspect_keybox(malformed.as_bytes(), None, false).is_err());
    // With the concession, the same bytes are read.
    assert!(engine.inspect_keybox(malformed.as_bytes(), None, true).is_ok());
    assert_eq!(fs::read_to_string(&keybox_path).unwrap(), TEST_KEYBOX);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_malformed_installed_keybox_is_replaced_by_one_of_equal_rank() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let keybox_path = layout.tricky_store().join("keybox.xml");
    fs::write(&keybox_path, malformed_keybox()).unwrap();
    let mut engine = Engine::new(layout.clone());
    let report = engine.install_keybox(TEST_KEYBOX.as_bytes(), None, None, KeyboxPolicy::NoDowngrade, false).unwrap();
    assert!(report.changed);
    assert_eq!(report.declined, None);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn apply_writes_a_malformed_installed_keybox_again() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let keybox_path = layout.tricky_store().join("keybox.xml");
    let malformed = malformed_keybox();
    fs::write(&keybox_path, &malformed).unwrap();
    let mut engine = Engine::new(layout.clone());
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert!(report.keybox_repaired);
    let installed = fs::read_to_string(&keybox_path).unwrap();
    assert_eq!(KeyboxDocument::parse(&installed).unwrap().defect, None);
    assert_eq!(key_material(&installed), key_material(TEST_KEYBOX));
    assert_eq!(fs::read_to_string(layout.store().join("previous-keybox.xml")).unwrap(), malformed);
    // A well-formed keybox is left alone.
    assert!(!engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap().keybox_repaired);
    let _ = fs::remove_dir_all(&root);
}

/// A keybox from which no key can be read is no reason to stop an `apply` (or the boot hook)
/// half-way: the rest of the configuration is applied and recorded, the file is kept as it is,
/// and no persisted key is judged outdated against it.
#[test]
fn apply_completes_with_an_unreadable_installed_keybox() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let keybox_path = layout.tricky_store().join("keybox.xml");
    let unreadable = "<AndroidAttestation><Keybox>truncated";
    fs::write(&keybox_path, unreadable).unwrap();
    let mut engine = Engine::new(layout.clone());
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert!(!report.keybox_repaired);
    assert_eq!(report.stale_keys_removed, 0);
    assert_eq!(fs::read_to_string(&keybox_path).unwrap(), unreadable);
    assert!(engine.status(None).unwrap().applied_at.is_some());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_keybox_without_a_key_is_rejected_and_the_installed_one_kept() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let keybox_path = layout.tricky_store().join("keybox.xml");
    fs::write(&keybox_path, TEST_KEYBOX).unwrap();
    let mut engine = Engine::new(layout.clone());
    assert!(engine.install_keybox(b"<AndroidAttestation></AndroidAttestation>", None, None, KeyboxPolicy::Replace, false).is_err());
    assert_eq!(fs::read_to_string(&keybox_path).unwrap(), TEST_KEYBOX);
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
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
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
fn the_play_stack_generates_its_keys_by_default() {
    // TEESimulator-RS documents `com.google.android.gms!`: Play Integrity always gets a key
    // attested with the keybox, whatever the mode of the other targets.
    let third_party = ["com.example.bank".to_string()];
    let list = TargetList::build(&[], &third_party, &Settings::default());
    for target in &list.targets {
        let expected = if TargetList::ALWAYS.contains(&target.package.as_str()) { TargetMode::Generate } else { TargetMode::Auto };
        assert_eq!(target.mode, expected, "{}", target.package);
    }
    assert!(list.render().contains("com.google.android.gms!\n"));
    assert!(list.render().contains("com.example.bank\n"));
}

#[test]
fn the_mode_of_the_play_stack_is_a_setting_of_its_own() {
    let settings = Settings { play_target_mode: TargetMode::Auto, target_mode: TargetMode::Patch, ..Settings::default() };
    let list = TargetList::build(&[], &["com.example.bank".to_string()], &settings);
    for target in &list.targets {
        let expected = if TargetList::ALWAYS.contains(&target.package.as_str()) { TargetMode::Auto } else { TargetMode::Patch };
        assert_eq!(target.mode, expected, "{}", target.package);
    }
}

#[test]
fn settings_saved_before_the_play_mode_existed_generate_for_the_play_stack() {
    let settings = Settings::parse(br#"{"extraPackages":[],"excludedPackages":[],"targetMode":"auto","spoofOverrides":[]}"#).unwrap();
    assert_eq!(settings.play_target_mode, TargetMode::Generate);
    // A mode the user chose for every target before keeps applying to the Play stack.
    let settings = Settings::parse(br#"{"targetMode":"patch"}"#).unwrap();
    assert_eq!(settings.play_target_mode, TargetMode::Patch);
    let settings = Settings::parse(br#"{"targetMode":"auto","playTargetMode":"patch"}"#).unwrap();
    assert_eq!(settings.play_target_mode, TargetMode::Patch);
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
    engine.apply(&settings, ApplyMode::NoRestart, None).unwrap();
    assert_eq!(engine.store.settings().unwrap(), settings);
    // Something else (a script of the module) resets the flag; applying the saved settings at boot restores it.
    let pif = layout.modules().join("playintegrityfix/custom.pif.prop");
    fs::write(&pif, fs::read_to_string(&pif).unwrap().replace("spoofProvider=1", "spoofProvider=0")).unwrap();
    let saved = engine.store.settings().unwrap();
    engine.apply(&saved, ApplyMode::EarlyBoot, None).unwrap();
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
    // The copy an earlier version installed under its earlier name is removed with the new scripts.
    let legacy = layout.store().join("replay");
    fs::create_dir_all(layout.store()).unwrap();
    fs::write(&legacy, b"old").unwrap();
    let hook = BootHook::install(&layout, &executable, "dev.nercone.replayintegrity", false).unwrap();
    assert!(hook.is_installed());
    assert!(!legacy.exists());
    let script = fs::read_to_string(&hook.scripts[0]).unwrap();
    let copy = layout.store().join("replay-integrity");
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
    let copy = layout.store().join("replay-integrity");
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

// `flock` locks are taken on Linux and Android only (`Files::lock`).
#[cfg(any(target_os = "linux", target_os = "android"))]
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
    // Released with the last descriptor of the file. A test running beside this one in the same
    // process may be starting a child, which holds a copy of every descriptor until it executes
    // its program (descriptors are closed on exec only then), so the lock is taken again within
    // a short wait rather than at once.
    let started = std::time::Instant::now();
    loop {
        if watcher.lock().unwrap().is_some() {
            break;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "the lock was not released");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_watcher_is_told_by_the_engine_copy_and_the_command() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let watcher = PackageWatcher::new(&layout);
    let copy = layout.store().join("replay-integrity").to_string_lossy().into_owned();
    let mut arguments = vec![copy.clone()];
    arguments.extend(watcher.arguments("dev.nercone.replayintegrity"));
    assert!(watcher.is_watcher(&arguments));
    // A watcher started before an update runs the copy under the name of the earlier version,
    // and must still be found, so that installing the hook ends it.
    let mut legacy = vec![layout.store().join("replay").to_string_lossy().into_owned()];
    legacy.extend(watcher.arguments("dev.nercone.replayintegrity"));
    assert!(watcher.is_watcher(&legacy));
    assert!(!watcher.is_watcher(&[layout.store().join("other").to_string_lossy().into_owned(), "watch".to_string()]));
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

#[test]
fn temporary_files_of_ended_writers_are_removed() {
    let root = temporary_root();
    let directory = root.join("data/adb/tricky_store");
    // A writer that no longer runs (no process has this ID) left its temporary file.
    let orphan = directory.join(format!("target.txt.{}{}", u32::MAX - 1, Files::TEMPORARY_SUFFIX));
    fs::write(&orphan, "part").unwrap();
    // A temporary file of another name is not this file's.
    let other = directory.join(format!("keybox.xml.{}{}", u32::MAX - 1, Files::TEMPORARY_SUFFIX));
    fs::write(&other, "part").unwrap();
    Files::write_atomic(&directory.join("target.txt"), b"com.example\n", 0o644).unwrap();
    assert!(!orphan.exists());
    assert!(other.exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_apply_lock_is_released_when_its_holder_closes_it() {
    let root = temporary_root();
    let store = replay_integrity::Store::new(&Layout::new(&root));
    let first = store.lock_apply().unwrap();
    drop(first);
    // Taking it again does not wait for anyone.
    drop(store.lock_apply().unwrap());
    let _ = fs::remove_dir_all(&root);
}

// `flock` locks are taken on Linux and Android only (`Files::lock`).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn stopping_a_watcher_waits_until_it_has_ended() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let watcher = PackageWatcher::new(&layout);
    // A stand-in watcher: a copy of the shell at the path of the engine copy, running a script
    // named `watch`, so its command line is that of a watcher.
    fs::create_dir_all(layout.store()).unwrap();
    let shell = layout.store().join("replay-integrity");
    fs::copy("/bin/sh", &shell).unwrap();
    fs::write(root.join("watch"), "sleep 30\n").unwrap();
    let mut child = std::process::Command::new(&shell).arg("watch").current_dir(&root).spawn().unwrap();
    fs::write(watcher.lock_path(), child.id().to_string()).unwrap();
    // Wait until the shell has replaced its command line with ours (it runs at once).
    let started = std::time::Instant::now();
    while watcher.running() != Some(child.id()) {
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "the stand-in did not start");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(watcher.stop().unwrap());
    // Right after `stop`, no watcher is listed, so one can be started at once.
    assert_eq!(watcher.running(), None);
    let _ = child.wait();
    let _ = fs::remove_dir_all(&root);
}

/// A persisted key of TEESimulator-RS (format version 3 of `GeneratedKeyPersistence.save`)
/// whose alias is the raw `alias` bytes (`writeUTF`) and whose chain is signed by `signer`.
fn persisted_key(uid: u32, alias: &[u8], signer: &[u8]) -> Vec<u8> {
    attested_key(uid, alias, b"leaf", signer)
}

/// Like `persisted_key`, with `leaf` as the certificate of the key.
fn attested_key(uid: u32, alias: &[u8], leaf: &[u8], signer: &[u8]) -> Vec<u8> {
    persisted_key_with_chain(uid, alias, &[leaf, signer, b"root"])
}

/// Like `persisted_key`, with `chain` as its certificate chain, from the key to the root.
fn persisted_key_with_chain(uid: u32, alias: &[u8], chain: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let int = |bytes: &mut Vec<u8>, value: i32| bytes.extend_from_slice(&value.to_be_bytes());
    int(&mut bytes, 3);
    int(&mut bytes, 1);
    int(&mut bytes, uid as i32);
    bytes.extend_from_slice(&(alias.len() as u16).to_be_bytes());
    bytes.extend_from_slice(alias);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.push(0);
    for value in [3, 256, 1, 0, 0, 0] {
        int(&mut bytes, value);
    }
    int(&mut bytes, chain.len() as i32);
    for certificate in chain.iter() {
        int(&mut bytes, certificate.len() as i32);
        bytes.extend_from_slice(certificate);
    }
    bytes
}

/// A root with TEESimulator-RS installed, the test keybox, and one persisted key signed by a
/// key not in it.
fn root_with_a_stale_key(alias: &[u8]) -> (PathBuf, Layout, PathBuf) {
    let root = temporary_root();
    let layout = Layout::new(&root);
    write_module(&layout.modules().join("tricky_store"), "TEESimulator-RS");
    fs::write(layout.tricky_store().join("keybox.xml"), TEST_KEYBOX).unwrap();
    let directory = layout.tricky_store().join("persistent_keys");
    fs::create_dir_all(&directory).unwrap();
    let key = directory.join("stale.bin");
    fs::write(&key, persisted_key(10_140, alias, b"an old attestation key")).unwrap();
    // uid 10140 is the Play Store's, so the key is the integrity key, which a repair removes, and
    // the Play Store is a target, so the keystore is asked to delete it.
    write_packages_list(&layout, &[("com.android.vending", 10_140)]);
    fs::write(layout.tricky_store().join("target.txt"), "com.android.vending!\n").unwrap();
    (root, layout, key)
}

/// Settings that remove every outdated key as soon as its keybox is replaced, for the tests of
/// how a key is removed: a key under another alias than the integrity key's is kept by default.
fn removing_every_key() -> Settings {
    let removal = KeyRemovalSettings {
        integrity: KeyRemoval::WhenReplaced,
        play: KeyRemoval::WhenReplaced,
        applications: KeyRemoval::WhenReplaced,
        integrity_patch: true,
    };
    Settings { key_removal: removal, ..Settings::default() }
}

/// A package list (`/data/system/packages.list`) of `packages`, by name and application ID.
fn write_packages_list(layout: &Layout, packages: &[(&str, u32)]) {
    let path = layout.packages_list();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let lines: String = packages.iter().map(|(name, app_id)| format!("{name} {app_id} 0 /data/user/0/{name} default:targetSdkVersion=36 none 0 0\n")).collect();
    fs::write(path, lines).unwrap();
}

/// A keystore client at the device path of `layout` that exits with `status`.
fn keystore_client(layout: &Layout, status: u8) {
    let client = layout.keystore_client();
    fs::create_dir_all(client.parent().unwrap()).unwrap();
    fs::write(&client, format!("#!/bin/sh\nexit {status}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&client, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_stale_key_is_kept_while_the_keystore_cannot_delete_its_alias() {
    // The client exits with -1 when it cannot reach keystore2. Run by a test that is not root,
    // the engine cannot even start it as the application, which must keep the key as well.
    let (root, layout, key) = root_with_a_stale_key(b"integrity.api.key.alias");
    keystore_client(&layout, 255);
    let mut engine = Engine::new(layout.clone());
    assert_eq!(engine.stale_keys(&KeyRemovalSettings::default(), None).unwrap().len(), 1);
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (0, 1));
    assert!(key.exists(), "a key of the device's keystore under that alias would become the application's key");
    assert_eq!(engine.stale_keys(&KeyRemovalSettings::default(), None).unwrap().len(), 1);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_stale_key_is_removed_without_a_keystore_client() {
    let (root, layout, key) = root_with_a_stale_key(b"integrity.api.key.alias");
    let mut engine = Engine::new(layout.clone());
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (1, 0));
    assert!(!key.exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_alias_that_is_not_read_exactly_is_not_given_to_the_keystore() {
    // Modified UTF-8 encodes NUL as C0 80, which is not UTF-8: the alias read is not the key's.
    let (root, layout, key) = root_with_a_stale_key(b"key\xC0\x80name");
    // A client that would keep the key if it were asked.
    keystore_client(&layout, 4);
    let mut engine = Engine::new(layout.clone());
    let stale = engine.stale_keys(&removing_every_key().key_removal, None).unwrap();
    assert!(!stale[0].key.alias_exact);
    let report = engine.apply(&removing_every_key(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (1, 0));
    assert!(!key.exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_device_key_is_left_alone_while_teesimulator_is_not_active() {
    // Without the module, or with it disabled, a device key under the alias is the
    // application's own key in use: the keystore is not asked, and the inert file is removed.
    for disable in [false, true] {
        let (root, layout, key) = root_with_a_stale_key(b"integrity.api.key.alias");
        let module = layout.modules().join("tricky_store");
        if disable {
            fs::write(module.join("disable"), "").unwrap();
        } else {
            fs::remove_dir_all(&module).unwrap();
        }
        // A client that would keep the key if it were asked.
        keystore_client(&layout, 4);
        let mut engine = Engine::new(layout.clone());
        let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
        assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (1, 0), "disable={disable}");
        assert!(!key.exists());
        let _ = fs::remove_dir_all(&root);
    }
}

#[test]
fn an_alias_that_is_not_ascii_is_not_given_to_the_keystore() {
    // keystore_cli_v2 reads the alias with GetSwitchValueASCII, which makes any other alias
    // an empty one.
    let (root, layout, key) = root_with_a_stale_key("鍵".as_bytes());
    keystore_client(&layout, 4);
    let mut engine = Engine::new(layout.clone());
    let report = engine.apply(&removing_every_key(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (1, 0));
    assert!(!key.exists());
    let _ = fs::remove_dir_all(&root);
}

/// Certificates in the layout of the keys that TEESimulator-RS generates, attesting the patch
/// 2026-10-05: one for Google Play services and one for another application. They are built
/// by `fixtures/attested-keys.py` from the schema of the attestation extension, self-signed with
/// throwaway keys, not captured from a device.
const PLAY_KEY_2026_10_05: &[u8] = include_bytes!("fixtures/play-key-2026-10-05.der");
const PLAY_STORE_KEY_2026_10_05: &[u8] = include_bytes!("fixtures/play-store-key-2026-10-05.der");
/// A key of Google Play services that reports the OS patch level only, not the vendor and boot ones.
const PLAY_KEY_2026_10: &[u8] = include_bytes!("fixtures/play-key-2026-10.der");
const APP_KEY_2026_10_05: &[u8] = include_bytes!("fixtures/app-key-2026-10-05.der");
const INTEGRITY: &str = "integrity.api.key.alias";

/// The contents of `security_patch.txt` that the engine writes for `date`.
fn security_patch(date: &str) -> String {
    KeystoreConfig::security_patch_contents(PatchDate::parse(date).unwrap())
}

/// A root with TEESimulator-RS installed, the test keybox (none without `keybox`),
/// `security_patch` as `security_patch.txt` (none for `None`), and one persisted key for each
/// certificate and alias of `keys`, signed by the keybox. Returns the paths of the keys, in order.
fn root_with_attested_keys(keybox: bool, security_patch: Option<&str>, keys: &[(&[u8], &str)]) -> (PathBuf, Layout, Vec<PathBuf>) {
    let root = temporary_root();
    let layout = Layout::new(&root);
    write_module(&layout.modules().join("tricky_store"), "TEESimulator-RS");
    if keybox {
        fs::write(layout.tricky_store().join("keybox.xml"), TEST_KEYBOX).unwrap();
    }
    if let Some(contents) = security_patch {
        fs::write(layout.tricky_store().join("security_patch.txt"), contents).unwrap();
    }
    let signer = key_material(TEST_KEYBOX)[0].1[0].clone();
    let directory = layout.tricky_store().join("persistent_keys");
    fs::create_dir_all(&directory).unwrap();
    let mut paths = Vec::new();
    for (index, (leaf, alias)) in keys.iter().enumerate() {
        let path = directory.join(format!("{index}.bin"));
        fs::write(&path, attested_key(10_100 + index as u32, alias.as_bytes(), leaf, &signer)).unwrap();
        paths.push(path);
    }
    (root, layout, paths)
}

fn stale_paths(engine: &Engine) -> Vec<PathBuf> {
    engine.stale_keys(&KeyRemovalSettings::default(), None).unwrap().into_iter().map(|outdated| outdated.key.path).collect()
}

#[test]
fn the_security_patch_file_is_read_back_only_in_the_form_the_engine_writes() {
    let patch = PatchDate::parse("2026-11-05").unwrap();
    let contents = KeystoreConfig::security_patch_contents(patch);
    assert_eq!(KeystoreConfig::security_patch_of(&contents), Some(patch));
    // Forms that TEESimulator-RS resolves by itself: the engine does not guess their levels.
    for other in [
        "2026-11-05\n",
        "all=2026-11-05\n",
        "system=prop\nvendor=prop\nboot=prop\n",
        "system=no\nvendor=no\nboot=no\n",
        "system=2026-11-05\nvendor=2026-11-01\nboot=2026-11-05\n",
        "system=2026-11-05\r\nvendor=2026-11-05\r\nboot=2026-11-05\r\n",
        "system=2026-11-05\nvendor=2026-11-05\nboot=2026-11-05\n[com.google.android.gms]\nall=2026-10-05\n",
        "",
    ] {
        assert_eq!(KeystoreConfig::security_patch_of(other), None, "{other:?}");
    }
}

#[test]
fn an_attested_patch_differs_when_any_reported_level_differs() {
    let read = |leaf: &[u8]| PersistedKey::parse(Path::new("x.bin"), &attested_key(10_100, b"k", leaf, b"signer")).unwrap().key_description().unwrap();
    let full = read(PLAY_KEY_2026_10_05);
    let date = |text: &str| PatchDate::parse(text).unwrap();
    assert!(!date("2026-10-05").differs_from_attested(&full));
    // Another month changes every level; another day of the month only vendor and boot.
    assert!(date("2026-11-05").differs_from_attested(&full));
    assert!(date("2026-10-01").differs_from_attested(&full));
    // Levels that are not reported are not compared: only the month is.
    let os_only = read(PLAY_KEY_2026_10);
    assert!(!date("2026-10-01").differs_from_attested(&os_only));
    assert!(date("2026-11-01").differs_from_attested(&os_only));
    // A certificate without an attestation extension has no description to compare.
    let plain = PersistedKey::parse(Path::new("x.bin"), &persisted_key(10_100, b"k", b"signer")).unwrap();
    assert!(plain.key_description().is_none());
}

#[test]
fn an_integrity_key_that_attests_another_patch_is_stale() {
    let leaves: [(&[u8], &str); 5] = [
        (PLAY_STORE_KEY_2026_10_05, INTEGRITY),
        (PLAY_KEY_2026_10_05, INTEGRITY),
        // Other keys keep the patch they were made with, as on a genuine device: another key of
        // the Play stack (tap-and-pay, a passkey), and the key of another application, even
        // under the alias of the integrity key.
        (PLAY_KEY_2026_10_05, "tapandpay"),
        (APP_KEY_2026_10_05, INTEGRITY),
        (APP_KEY_2026_10_05, "enrolment"),
    ];
    for date in ["2026-11-05", "2026-10-01"] {
        let (root, layout, keys) = root_with_attested_keys(true, Some(&security_patch(date)), &leaves);
        let mut engine = Engine::new(layout.clone());
        assert_eq!(stale_paths(&engine), keys[..2], "{date}");
        let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
        assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (2, 0), "{date}");
        assert!(!keys[0].exists() && !keys[1].exists(), "{date}");
        assert!(keys[2..].iter().all(|key| key.exists()), "{date}");
        let _ = fs::remove_dir_all(&root);
    }
}

#[test]
fn apply_compares_the_keys_with_the_patch_of_the_installed_fingerprint() {
    // The case seen with AlwaysStrong: the monthly patch moves with the fingerprint, the keybox
    // stays, and the integrity key keeps attesting the previous patch.
    let (root, layout, keys) = root_with_attested_keys(true, None, &[(PLAY_STORE_KEY_2026_10_05, INTEGRITY), (APP_KEY_2026_10_05, "enrolment")]);
    let mut engine = Engine::new(layout.clone());
    let text =
        "FINGERPRINT=google/p/p:CANARY/A/1:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel\nBRAND=google\nPRODUCT=p\nDEVICE=p\nSECURITY_PATCH=2026-11-05\n";
    engine.install_fingerprint(text.as_bytes(), None, &Settings::default()).unwrap();
    // A module script writes the previous patch back: apply writes the fingerprint's again
    // before it compares the keys.
    fs::write(layout.tricky_store().join("security_patch.txt"), security_patch("2026-10-05")).unwrap();
    assert!(stale_paths(&engine).is_empty());
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!(report.security_patch.as_deref(), Some("2026-11-05"));
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (1, 0));
    assert!(!keys[0].exists() && keys[1].exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_integrity_key_that_attests_the_configured_patch_is_kept() {
    let (root, layout, keys) =
        root_with_attested_keys(true, Some(&security_patch("2026-10-05")), &[(PLAY_KEY_2026_10_05, INTEGRITY), (PLAY_KEY_2026_10, INTEGRITY)]);
    let mut engine = Engine::new(layout.clone());
    assert!(stale_paths(&engine).is_empty());
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (0, 0));
    assert!(keys.iter().all(|key| key.exists()));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn keys_are_not_judged_by_a_patch_the_engine_cannot_resolve() {
    let newer = security_patch("2026-11-05");
    let cases = [(true, Some("system=prop\nvendor=prop\nboot=prop\n")), (true, None), (false, Some(newer.as_str()))];
    for (keybox, contents) in cases {
        let (root, layout, keys) = root_with_attested_keys(keybox, contents, &[(PLAY_KEY_2026_10_05, INTEGRITY)]);
        let engine = Engine::new(layout.clone());
        assert!(stale_paths(&engine).is_empty(), "keybox={keybox} {contents:?}");
        assert!(keys[0].exists());
        let _ = fs::remove_dir_all(&root);
    }
}

/// A root with TEESimulator-RS installed, `keybox` as `keybox.xml`, the package list of
/// `packages`, and one persisted key for each user, alias and chain of `keys`. Returns the paths
/// of the keys, in order.
fn root_with_keys(keybox: &str, packages: &[(&str, u32)], keys: &[(u32, &str, Vec<&[u8]>)]) -> (PathBuf, Layout, Vec<PathBuf>) {
    let root = temporary_root();
    let layout = Layout::new(&root);
    write_module(&layout.modules().join("tricky_store"), "TEESimulator-RS");
    fs::write(layout.tricky_store().join("keybox.xml"), keybox).unwrap();
    write_packages_list(&layout, packages);
    let directory = layout.tricky_store().join("persistent_keys");
    fs::create_dir_all(&directory).unwrap();
    let mut paths = Vec::new();
    for (index, (uid, alias, chain)) in keys.iter().enumerate() {
        let path = directory.join(format!("{index}.bin"));
        fs::write(&path, persisted_key_with_chain(*uid, alias.as_bytes(), chain)).unwrap();
        paths.push(path);
    }
    (root, layout, paths)
}

const PLAY_STORE: (&str, u32) = ("com.android.vending", 10_140);
const PLAY_SERVICES: (&str, u32) = ("com.google.android.gms", 10_150);
const BANK: (&str, u32) = ("com.example.bank", 10_200);
const OLD_SIGNER: &[u8] = b"an old attestation key";

/// The keys of an old keybox under every category: the integrity key, a tap-and-pay key of
/// Play services and a banking application's enrolment.
fn keys_of_an_old_keybox() -> Vec<(u32, &'static str, Vec<&'static [u8]>)> {
    vec![
        (PLAY_STORE.1, INTEGRITY, vec![b"leaf", OLD_SIGNER, b"root"]),
        (PLAY_SERVICES.1, "tapandpay", vec![b"leaf", OLD_SIGNER, b"root"]),
        (BANK.1, "enrolment", vec![b"leaf", OLD_SIGNER, b"root"]),
    ]
}

#[test]
fn by_default_only_the_integrity_key_of_an_old_keybox_is_removed() {
    // The keybox changed: tap-and-pay cards and a bank's enrolment must survive it, while the
    // integrity key, which holds nothing of the user's, is made again for Play Integrity.
    let (root, layout, keys) = root_with_keys(TEST_KEYBOX, &[PLAY_STORE, PLAY_SERVICES, BANK], &keys_of_an_old_keybox());
    let mut engine = Engine::new(layout.clone());
    let outdated = engine.outdated_keys(&KeyRemovalSettings::default(), None).unwrap();
    let categories: Vec<KeyCategory> = outdated.iter().map(|key| key.category).collect();
    assert_eq!(categories, [KeyCategory::Integrity, KeyCategory::Play, KeyCategory::Application]);
    assert!(outdated.iter().all(|key| key.reasons == [OutdatedReason::OldKeybox { unusable: false }]));
    assert_eq!(outdated.iter().map(|key| key.removed_by_repair).collect::<Vec<_>>(), [true, false, false]);
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept, report.outdated_keys_kept), (1, 0, 2));
    assert!(!keys[0].exists() && keys[1].exists() && keys[2].exists());
    // The kept keys are still reported as outdated, and a repair that is told to removes them.
    assert_eq!(engine.outdated_keys(&KeyRemovalSettings::default(), None).unwrap().len(), 2);
    let report = engine.apply(&removing_every_key(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.outdated_keys_kept), (2, 0));
    assert!(keys.iter().all(|key| !key.exists()));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn never_keeps_even_the_integrity_key() {
    let (root, layout, keys) = root_with_keys(TEST_KEYBOX, &[PLAY_STORE], &keys_of_an_old_keybox()[..1]);
    let mut engine = Engine::new(layout.clone());
    let removal = KeyRemovalSettings { integrity: KeyRemoval::Never, ..KeyRemovalSettings::default() };
    let settings = Settings { key_removal: removal, ..Settings::default() };
    let report = engine.apply(&settings, ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.outdated_keys_kept), (0, 1));
    assert!(keys[0].exists());
    let _ = fs::remove_dir_all(&root);
}

/// The test keybox with its RSA key only, and the certificates of its EC key: a keybox whose
/// EC key was replaced, and the chain that key attested with.
fn keybox_without_its_ec_key() -> (String, Vec<Vec<u8>>) {
    let document = KeyboxDocument::read(TEST_KEYBOX).unwrap();
    let ec = document.keys().find(|key| key.algorithm == KeyAlgorithm::ECDSA).unwrap();
    let chain = ec.certificates.iter().map(|certificate| certificate.der.clone()).collect();
    (document.retain_keys(|key| key.algorithm == KeyAlgorithm::RSA).render(), chain)
}

#[test]
fn when_unusable_removes_a_key_only_once_its_old_chain_is_known_to_fail() {
    // The old chain of the first key is readable and does not lead to a Google root, so its
    // attestation fails already; the old chain of the second cannot be read, so nothing is
    // known against it.
    let (keybox, old_chain) = keybox_without_its_ec_key();
    let chain: Vec<&[u8]> = std::iter::once(b"leaf".as_slice()).chain(old_chain.iter().map(Vec::as_slice)).collect();
    let keys = [(PLAY_SERVICES.1, "broken", chain), (PLAY_SERVICES.1, "unknown", vec![b"leaf".as_slice(), OLD_SIGNER, b"root"])];
    let (root, layout, paths) = root_with_keys(&keybox, &[PLAY_SERVICES], &keys);
    let mut engine = Engine::new(layout.clone());
    let removal = KeyRemovalSettings { play: KeyRemoval::WhenUnusable, ..KeyRemovalSettings::default() };
    let outdated = engine.outdated_keys(&removal, None).unwrap();
    assert_eq!(outdated[0].reasons, [OutdatedReason::OldKeybox { unusable: true }]);
    assert_eq!(outdated[1].reasons, [OutdatedReason::OldKeybox { unusable: false }]);
    assert_eq!(outdated.iter().map(|key| key.removed_by_repair).collect::<Vec<_>>(), [true, false]);
    let report = engine.apply(&Settings { key_removal: removal, ..Settings::default() }, ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.outdated_keys_kept), (1, 1));
    assert!(!paths[0].exists() && paths[1].exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_integrity_key_on_another_patch_is_kept_when_that_removal_is_off() {
    let (root, layout, keys) = root_with_attested_keys(true, Some(&security_patch("2026-11-05")), &[(PLAY_STORE_KEY_2026_10_05, INTEGRITY)]);
    let mut engine = Engine::new(layout.clone());
    let removal = KeyRemovalSettings { integrity_patch: false, ..KeyRemovalSettings::default() };
    let outdated = engine.outdated_keys(&removal, None).unwrap();
    assert_eq!(outdated.len(), 1);
    assert_eq!(outdated[0].reasons, [OutdatedReason::OldPatch]);
    assert!(!outdated[0].removed_by_repair);
    let report = engine.apply(&Settings { key_removal: removal, ..Settings::default() }, ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.outdated_keys_kept), (0, 1));
    assert!(keys[0].exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_category_of_a_key_follows_its_packages_and_alias() {
    let key = |uid: u32, alias: &[u8], leaf: &[u8]| PersistedKey::parse(Path::new("x.bin"), &attested_key(uid, alias, leaf, b"signer")).unwrap();
    let list = android::PackageList::parse("com.google.android.gms 10150 0 /data\ncom.google.android.gsf 10150 0 /data\ncom.example.bank 10200 0 /data\n");
    // From the attestation: the Play Store's key under the integrity alias.
    let store = key(10_999, INTEGRITY.as_bytes(), PLAY_STORE_KEY_2026_10_05);
    assert_eq!(KeyCategory::of(&store, &store.packages(&[])), KeyCategory::Integrity);
    // Another application under the same alias is not the integrity key.
    let app = key(10_999, INTEGRITY.as_bytes(), APP_KEY_2026_10_05);
    assert_eq!(KeyCategory::of(&app, &app.packages(&[])), KeyCategory::Application);
    // From the package list, for a key without an attestation, in another user too.
    let services = key(1_010_150, b"tapandpay", b"leaf");
    assert_eq!(services.packages(&list), ["com.google.android.gms", "com.google.android.gsf"]);
    assert_eq!(KeyCategory::of(&services, &services.packages(&list)), KeyCategory::Play);
    let integrity = key(10_150, INTEGRITY.as_bytes(), b"leaf");
    assert_eq!(KeyCategory::of(&integrity, &integrity.packages(&list)), KeyCategory::Integrity);
    // A key whose packages are not known is an application's: the most careful category.
    let unknown = key(10_300, INTEGRITY.as_bytes(), b"leaf");
    assert!(unknown.packages(&list).is_empty());
    assert_eq!(KeyCategory::of(&unknown, &[]), KeyCategory::Application);
}

#[test]
fn an_outdated_key_is_reported_as_the_application_reads_it() {
    let (root, layout, _) = root_with_keys(TEST_KEYBOX, &[PLAY_STORE], &keys_of_an_old_keybox()[..1]);
    let engine = Engine::new(layout.clone());
    let outdated = engine.outdated_keys(&KeyRemovalSettings::default(), None).unwrap();
    let json = serde_json::to_value(&outdated[0]).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "uid": 10140,
            "alias": INTEGRITY,
            "category": "integrity",
            "packages": ["com.android.vending"],
            "reasons": [{ "kind": "oldKeybox", "unusable": false }],
            "removedByRepair": true,
        })
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_kept_outdated_key_is_removed_when_the_user_asks() {
    let mut keys = keys_of_an_old_keybox();
    // A current key of the same application, signed by the installed keybox.
    let signer = key_material(TEST_KEYBOX)[0].1[0].clone();
    let signer: &'static [u8] = Box::leak(signer.into_boxed_slice());
    keys.push((BANK.1, "current", vec![b"leaf", signer, b"root"]));
    let (root, layout, paths) = root_with_keys(TEST_KEYBOX, &[PLAY_STORE, PLAY_SERVICES, BANK], &keys);
    let mut engine = Engine::new(layout.clone());
    assert_eq!(engine.remove_key(BANK.1, "enrolment", None).unwrap(), (1, 0));
    assert!(!paths[2].exists());
    // A current key, another user's key and a missing key are refused, and nothing is removed.
    assert!(engine.remove_key(BANK.1, "current", None).is_err());
    assert!(engine.remove_key(BANK.1, "tapandpay", None).is_err());
    assert!(engine.remove_key(BANK.1, "enrolment", None).is_err());
    assert!(paths[1].exists() && paths[3].exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_target_scope_decides_which_applications_are_targets() {
    let installed = ["com.google.android.apps.walletnfcrel".to_string(), "com.example.app".to_string()];
    let third_party = ["com.example.app".to_string()];
    let packages = |scope: TargetScope| -> Vec<String> {
        let settings = Settings { target_scope: scope, extra_packages: vec!["com.example.extra".to_string()], ..Settings::default() };
        TargetList::build(&installed, &third_party, &settings).packages().map(str::to_string).collect()
    };
    let play = TargetList::ALWAYS.map(str::to_string).to_vec();
    let with = |more: &[&str]| -> Vec<String> { play.iter().cloned().chain(more.iter().map(|package| package.to_string())).collect() };
    assert_eq!(packages(TargetScope::Play), with(&["com.example.extra"]));
    assert_eq!(packages(TargetScope::PlayAndWallets), with(&["com.google.android.apps.walletnfcrel", "com.example.extra"]));
    assert_eq!(packages(TargetScope::AllApplications), with(&["com.example.app", "com.google.android.apps.walletnfcrel", "com.example.extra"]));
    assert_eq!(Settings::default().target_scope, TargetScope::AllApplications);
}

#[test]
fn settings_saved_before_the_safety_settings_existed_read_as_the_defaults() {
    let settings =
        Settings::parse(br#"{"extraPackages":[],"excludedPackages":[],"targetMode":"auto","playTargetMode":"generate","spoofOverrides":[]}"#).unwrap();
    assert_eq!(settings, Settings::default());
    assert_eq!(
        settings.key_removal,
        KeyRemovalSettings { integrity: KeyRemoval::WhenReplaced, play: KeyRemoval::Never, applications: KeyRemoval::Never, integrity_patch: true }
    );
    assert!(!settings.end_background_applications);
}

#[test]
fn safety_settings_as_the_application_writes_them_are_read() {
    let json = br#"{"targetScope":"playAndWallets","keyRemoval":{"integrity":"whenReplaced","play":"whenUnusable","applications":"never","integrityPatch":false},"endBackgroundApplications":true}"#;
    let settings = Settings::parse(json).unwrap();
    assert_eq!(settings.target_scope, TargetScope::PlayAndWallets);
    assert_eq!(
        settings.key_removal,
        KeyRemovalSettings { integrity: KeyRemoval::WhenReplaced, play: KeyRemoval::WhenUnusable, applications: KeyRemoval::Never, integrity_patch: false }
    );
    assert!(settings.end_background_applications);
    assert!(Settings::parse(br#"{"keyRemoval":{"play":"always"}}"#).is_err());
}

#[test]
fn apply_keeps_the_status_list_it_was_given_for_the_boot_hook() {
    let root = temporary_root();
    let layout = Layout::new(&root);
    let mut engine = Engine::new(layout.clone());
    assert_eq!(engine.store.status_list(), None);
    let list = r#"{"entries":{"1a":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"#;
    engine.apply(&Settings::default(), ApplyMode::NoRestart, Some(list)).unwrap();
    assert_eq!(engine.store.status_list().as_deref(), Some(list));
    // An invalid list is not saved over a valid one.
    engine.apply(&Settings::default(), ApplyMode::NoRestart, Some("not a status list")).unwrap();
    assert_eq!(engine.store.status_list().as_deref(), Some(list));
    let _ = fs::remove_dir_all(&root);
}

/// A verdict of keys of `algorithms`, each usable or with a problem.
fn verdict(keys: &[(KeyAlgorithm, bool)]) -> KeyboxVerdict {
    let keys = keys
        .iter()
        .map(|(algorithm, usable)| KeyVerdict {
            algorithm: algorithm.name().to_string(),
            serial: "1".to_string(),
            root: None,
            expires: None,
            problems: if *usable { Vec::new() } else { vec![KeyProblem::KeyMismatch] },
        })
        .collect();
    KeyboxVerdict { keys, revocation_checked: true, defect: None }
}

#[test]
fn a_keybox_policy_keeps_the_installed_keybox_as_it_says() {
    let usable = verdict(&[(KeyAlgorithm::ECDSA, true)]);
    let unusable = verdict(&[(KeyAlgorithm::ECDSA, false)]);
    let needed = KeyboxPolicy::WhenNeeded { margin_seconds: 48 * 3600 };
    // A keybox the user chose is always installed.
    assert_eq!(KeyboxPolicy::Replace.declines(&unusable, Some(&usable), Some(&usable)), None);
    // Without downgrading, a mirror's keybox of the same rank replaces a working one.
    assert_eq!(KeyboxPolicy::NoDowngrade.declines(&usable, Some(&usable), None), None);
    assert_eq!(KeyboxPolicy::NoDowngrade.declines(&unusable, Some(&usable), None), Some(Declined::Worse));
    assert_eq!(KeyboxPolicy::NoDowngrade.declines(&unusable, None, None), None);
    // When needed: a keybox still usable at the end of the margin is kept, however good the offer.
    assert_eq!(needed.declines(&usable, Some(&usable), Some(&usable)), Some(Declined::NotNeeded));
    // One that expires within the margin, or is unusable now, is replaced, but not by a worse one.
    assert_eq!(needed.declines(&usable, Some(&usable), Some(&unusable)), None);
    assert_eq!(needed.declines(&unusable, Some(&usable), Some(&unusable)), Some(Declined::Worse));
    assert_eq!(needed.declines(&usable, Some(&unusable), Some(&unusable)), None);
    // Without an installed keybox, any installable one is installed.
    assert_eq!(needed.declines(&unusable, None, None), None);
}

#[test]
fn a_keybox_that_is_needed_is_installed_when_needed() {
    // The installed keybox has no usable key (its root is not Google's), so a replacement is
    // needed, and one of the same rank is installed.
    let root = temporary_root();
    let layout = Layout::new(&root);
    let mut engine = Engine::new(layout.clone());
    engine.install_keybox(TEST_KEYBOX.as_bytes(), None, None, KeyboxPolicy::Replace, false).unwrap();
    let (other, _) = keybox_without_its_ec_key();
    let report = engine.install_keybox(other.as_bytes(), None, None, KeyboxPolicy::WhenNeeded { margin_seconds: 48 * 3600 }, false).unwrap();
    assert_eq!(report.declined, None);
    assert!(report.changed);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_device_key_of_an_application_that_is_not_a_target_is_left_alone() {
    // The Play Store is not in target.txt: TEESimulator-RS would pass the deletion to keystore2,
    // which would delete the application's own key. A client that would keep the key if it
    // were asked shows that it is not asked: the inert file alone is removed.
    let (root, layout, key) = root_with_a_stale_key(INTEGRITY.as_bytes());
    fs::write(layout.tricky_store().join("target.txt"), "com.example.other\n").unwrap();
    keystore_client(&layout, 4);
    let mut engine = Engine::new(layout.clone());
    let report = engine.apply(&Settings::default(), ApplyMode::EarlyBoot, None).unwrap();
    assert_eq!((report.stale_keys_removed, report.stale_keys_kept), (1, 0));
    assert!(!key.exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_invalid_status_list_falls_back_to_the_saved_one() {
    // A run given a list that cannot be read keeps the copy saved last, and judges with it.
    let root = temporary_root();
    let layout = Layout::new(&root);
    let mut engine = Engine::new(layout.clone());
    let list = r#"{"entries":{"1a":{"status":"REVOKED"}}}"#;
    engine.apply(&Settings::default(), ApplyMode::NoRestart, Some(list)).unwrap();
    engine.apply(&Settings::default(), ApplyMode::NoRestart, Some("{")).unwrap();
    assert_eq!(engine.store.status_list().as_deref(), Some(list));
    let _ = fs::remove_dir_all(&root);
}
