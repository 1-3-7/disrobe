#![cfg(feature = "dotnet")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::run_disrobe;

fn corpus(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/dotnet/build-compare")
        .join(relative)
}

fn arg(relative: &str) -> String {
    corpus(relative).to_str().expect("utf8 path").to_owned()
}

#[test]
fn dotnet_compare_prints_the_reference_findings() {
    let old: String = arg("pinvoke/old/Platform.dll");
    let new: String = arg("pinvoke/new/Platform.dll");
    let expected: String =
        std::fs::read_to_string(corpus("pinvoke/reference.txt")).expect("reference output");

    let text: common::Run = run_disrobe(&["dotnet", "compare", &old, &new]);
    assert_eq!(
        text.code, 0,
        "disrobe dotnet compare failed: {}",
        text.stderr
    );
    let printed: Vec<&str> = text
        .stdout
        .lines()
        .filter(|line: &&str| {
            line.starts_with("added ")
                || line.starts_with("removed ")
                || line.starts_with("changed ")
        })
        .collect();
    let reference: Vec<&str> = expected.lines().collect();
    assert_eq!(printed, reference, "{}", text.stdout);

    let json: common::Run = run_disrobe(&["dotnet", "compare", &old, &new, "--json"]);
    assert_eq!(
        json.code, 0,
        "disrobe dotnet compare --json failed: {}",
        json.stderr
    );
    let report: serde_json::Value = serde_json::from_str(&json.stdout).expect("JSON report");
    assert_eq!(report["schema"], "disrobe.dotnet.build-compare/v1");
    assert_eq!(
        report["findings"].as_array().expect("findings").len(),
        reference.len()
    );
    assert_eq!(report["counts"]["pinvoke"]["changed"], 3);
}

#[test]
fn dotnet_compare_refuses_an_input_that_is_not_an_assembly() {
    let manifest: String = arg("MANIFEST.toml");
    let new: String = arg("pinvoke/new/Platform.dll");
    let run: common::Run = run_disrobe(&["dotnet", "compare", &manifest, &new]);
    assert_ne!(run.code, 0);
    assert!(run.stderr.contains("DR-DOTNET-0960"), "{}", run.stderr);
}
