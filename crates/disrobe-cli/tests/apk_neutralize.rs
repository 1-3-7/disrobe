#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn plants() -> String {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit/audit-plants.apk");
    path.to_str().expect("utf-8 path").to_owned()
}

fn list(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e: std::fs::DirEntry| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn without_the_flag_the_apk_command_writes_no_patched_dex() {
    let scratch = temp_dir("apk-no-neutralize");
    let out: PathBuf = scratch.path().join("out");
    let run = run_disrobe(&["apk", &plants(), "--out", out.to_str().expect("utf-8 path")]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let names: Vec<String> = list(&out);
    assert!(
        names.iter().all(|n: &String| !n.contains("neutraliz")),
        "no patch output without the opt-in flag: {names:?}"
    );
    assert!(!run.stderr.contains("apk neutralize"), "{}", run.stderr);
}

#[test]
fn apply_writes_the_patched_dex_and_a_report_and_the_json_carries_the_plan() {
    let scratch = temp_dir("apk-neutralize-apply");
    let out: PathBuf = scratch.path().join("out");
    let run = run_disrobe(&[
        "apk",
        &plants(),
        "--out",
        out.to_str().expect("utf-8 path"),
        "--neutralize",
        "apply",
    ]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains(
            "apk neutralize (apply) classes.dex: 3 patch(es) offered, 1 refused; applied 3, declined 0, skipped 0; wrote "
        ),
        "{}",
        run.stderr
    );
    let patched: PathBuf = out.join("classes.neutralized.dex");
    assert!(
        patched.is_file(),
        "patched dex written beside the report: {:?}",
        list(&out)
    );
    let original: Vec<u8> = std::fs::read(plants()).expect("read apk");
    assert!(!original.is_empty());
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("android-neutralization.json")).expect("report written"),
    )
    .expect("report json");
    assert_eq!(report["schema"], "disrobe.apk.neutralization/v1");
    assert_eq!(report["mode"], "apply");
    assert_eq!(report["dex"][0]["entry"], "classes.dex");
    assert_eq!(
        report["dex"][0]["report"]["applied"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        report["dex"][0]["plan"]["refusals"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let json = run_disrobe(&[
        "apk",
        &plants(),
        "--out",
        scratch
            .path()
            .join("json-out")
            .to_str()
            .expect("utf-8 path"),
        "--neutralize",
        "skip",
        "--json",
    ]);
    assert_eq!(json.code, 0, "{}", json.stderr);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).expect("apk json");
    assert_eq!(value["neutralization"]["mode"], "skip");
    assert_eq!(
        value["neutralization"]["dex"][0]["plan"]["patches"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        value["neutralization"]["dex"][0]["report"]["applied"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "skip applies nothing"
    );
    assert!(
        !scratch
            .path()
            .join("json-out/classes.neutralized.dex")
            .exists(),
        "skip writes no patched dex"
    );
}
