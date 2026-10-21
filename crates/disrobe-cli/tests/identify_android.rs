#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::run_disrobe;

fn corpus(rel: &str) -> String {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push(rel);
    path.to_str().expect("utf-8 path").to_owned()
}

#[test]
fn identify_names_the_apk_writer_signatures_and_anti_analysis_checks() {
    let run = run_disrobe(&["identify", &corpus("recon/android-audit/audit-plants.apk")]);
    assert_eq!(run.code, 0, "identify failed: {}", run.stderr);
    for needle in [
        "format: apk (1 dex file, 0 class files)",
        "compiler      d8/r8  (85%)",
        "signature     v2  (100%)",
        "             - 1 signer, integrity verified",
        "anti-analysis debugger check  (90%)",
        "anti-analysis emulator check  (90%)",
        "anti-analysis root check  (90%)",
    ] {
        assert!(
            run.stdout.contains(needle),
            "missing {needle:?} in:\n{}",
            run.stdout
        );
    }
    let json = run_disrobe(&[
        "identify",
        &corpus("recon/android-audit/audit-plants.apk"),
        "--json",
    ]);
    assert_eq!(json.code, 0, "{}", json.stderr);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).expect("identity json");
    assert_eq!(value["format"], "apk");
    assert!(
        value["hits"]
            .as_array()
            .is_some_and(|hits: &Vec<serde_json::Value>| hits
                .iter()
                .any(|h: &serde_json::Value| h["kind"] == "Compiler" && h["name"] == "d8/r8")),
        "{value}"
    );
}

#[test]
fn identify_on_a_minified_dex_reports_renaming_and_the_clean_dex_does_not() {
    let minified = run_disrobe(&["identify", &corpus("jvm/dex/obfuscators/r8/Widget-r8.dex")]);
    assert_eq!(minified.code, 0, "{}", minified.stderr);
    assert!(
        minified
            .stdout
            .contains("obfuscator    ProGuard/R8 renaming  (70%)"),
        "{}",
        minified.stdout
    );
    let clean = run_disrobe(&[
        "identify",
        &corpus("jvm/dex/obfuscators/r8/Widget-clean.dex"),
    ]);
    assert_eq!(clean.code, 0, "{}", clean.stderr);
    assert!(!clean.stdout.contains("obfuscator"), "{}", clean.stdout);
    assert!(
        clean
            .stdout
            .starts_with("format: dex (1 dex file, 0 class files)"),
        "{}",
        clean.stdout
    );
}
