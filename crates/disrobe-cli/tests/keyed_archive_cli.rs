#![cfg(feature = "swift")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

#[test]
fn macho_keyed_archive_prints_the_object_graph_with_back_references() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("keyed-archive-cli");
    let script: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-pass-swift-objc/tests/support/make_keyed_archives.py");
    let python: &str = ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| {
            std::process::Command::new(candidate)
                .args(["-c", "import plistlib; plistlib.UID(1)"])
                .status()
                .is_ok_and(|status: std::process::ExitStatus| status.success())
        })
        .expect("the keyed-archive caller case needs CPython 3.8 or later");
    let status: std::process::ExitStatus = std::process::Command::new(python)
        .arg(&script)
        .arg(scratch.path())
        .status()
        .expect("run the archive writer");
    assert!(status.success());
    let graph: PathBuf = scratch.path().join("graph.bplist");
    let graph: &str = graph.to_str().expect("utf8 path");

    let text: common::Run = run_disrobe(&["macho", "keyed-archive", graph]);
    assert_eq!(
        text.code, 0,
        "disrobe macho keyed-archive failed: {}",
        text.stderr
    );
    assert!(
        text.stdout.contains("root: Person : NSObject"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("<back-reference to object 1>"),
        "{}",
        text.stdout
    );

    let json: common::Run = run_disrobe(&["macho", "keyed-archive", graph, "--json"]);
    assert_eq!(json.code, 0, "{}", json.stderr);
    let report: serde_json::Value = serde_json::from_str(&json.stdout).expect("JSON report");
    assert_eq!(report["top"]["root"]["kind"], "object");
    assert_eq!(report["top"]["root"]["fields"]["name"]["value"], "Alice");
}
