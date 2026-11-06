//! Tests of the engine's pieces and of an `apply` against a temporary root directory, so no
//! device is needed. The keybox fixture holds throwaway keys generated for the tests.

use std::fs;
use std::path::PathBuf;

use replay::{Engine, Fingerprint, FingerprintProblem, Layout, PatchDate, Settings, SpoofFlag, SpoofFlags, TargetList, TargetMode};

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
    let third_party = ["com.example.bank".to_string(), "org.lsposed.manager".to_string(), "com.google.android.apps.walletnfcrel".to_string()];
    let list = TargetList::build(&third_party, &["com.extra.app".to_string()]);
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
    let report = engine.apply(&Settings::default(), false).unwrap();
    assert_eq!(report.security_patch.as_deref(), Some("2026-11-05"));
    assert!(!report.daemon_restarted);
    // security_patch.txt is written in the per-component form TEESimulator-RS reads.
    let patch = fs::read_to_string(layout.tricky_store().join("security_patch.txt")).unwrap();
    assert!(patch.contains("system=2026-11-05") && patch.contains("boot=2026-11-05") && patch.contains("vendor=2026-11-05"));
    let _ = fs::remove_dir_all(&root);
}
