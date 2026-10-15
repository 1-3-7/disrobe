#![cfg(feature = "swift")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::run_disrobe;

fn nib(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/mobile/nib/sdcalertview")
        .join(name)
        .to_str()
        .expect("utf8 path")
        .to_owned()
}

#[test]
fn macho_nib_names_the_outlets_and_matches_the_reference_object_count() {
    let reference: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../corpus/mobile/nib/reference.json"),
        )
        .expect("reference"),
    )
    .expect("json");
    let run: common::Run = run_disrobe(&["macho", "nib", &nib("TextFieldCell.nib"), "--json"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("json report");
    assert_eq!(
        report["objects"].as_array().expect("objects").len(),
        reference["TextFieldCell.nib"]["objects"]
            .as_array()
            .expect("reference objects")
            .len()
    );
    assert!(
        report["connections"]
            .as_array()
            .expect("connections")
            .iter()
            .any(|connection| connection["kind"] == "outlet" && connection["label"].is_string()),
        "{}",
        run.stdout
    );

    let text: common::Run = run_disrobe(&["macho", "nib", &nib("ActionCell.runtime.nib")]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(
        text.stdout.starts_with("NIBArchive version 1"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("\noutlet "), "{}", text.stdout);
}

#[test]
fn macho_nib_refuses_a_non_nib_by_name() {
    let run: common::Run = run_disrobe(&[
        "macho",
        "nib",
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/mobile/nib/MANIFEST.toml")
            .to_str()
            .expect("utf8 path"),
    ]);
    assert_ne!(run.code, 0);
    let flat: String = run
        .stderr
        .chars()
        .filter(|c: &char| !c.is_whitespace() && *c != '\u{2502}')
        .collect();
    assert!(flat.contains("DR-CLI-0506"), "{}", run.stderr);
    assert!(flat.contains("DR-IOS-0022"), "{}", run.stderr);
}
