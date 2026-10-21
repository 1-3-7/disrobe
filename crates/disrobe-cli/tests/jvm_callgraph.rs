#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn fixture(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit");
    path.push(name);
    path
}

#[test]
fn jvm_callgraph_writes_json_and_dot_for_an_apk() {
    let scratch = temp_dir("jvm-callgraph");
    let json_path: PathBuf = scratch.path().join("plants.json");
    let run = run_disrobe(&[
        "jvm",
        "callgraph",
        fixture("audit-plants.apk").to_str().expect("utf-8 path"),
        "-o",
        json_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(run.code, 0, "jvm callgraph failed: {}", run.stderr);
    assert!(run.stdout.contains("  edges:        77"), "{}", run.stdout);
    assert!(run.stdout.contains("(57 external)"), "{}", run.stdout);
    let graph: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("json written"))
            .expect("call graph json");
    assert_eq!(graph["edges"].as_array().expect("edges").len(), 77);
    assert_eq!(graph["dex_files"], 1);
    let dot_path: PathBuf = scratch.path().join("plants.dot");
    let dot_run = run_disrobe(&[
        "jvm",
        "callgraph",
        fixture("audit-plants.apk").to_str().expect("utf-8 path"),
        "--emit",
        "dot",
        "-o",
        dot_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(dot_run.code, 0, "{}", dot_run.stderr);
    let dot: String = std::fs::read_to_string(&dot_path).expect("dot written");
    assert!(dot.starts_with("digraph calls {"), "{dot}");
    assert!(
        dot.contains("\"Lcom/planted/audit/Plants;->rootSuCommand()Ljava/lang/Process;\" -> \"Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;\""),
        "{dot}"
    );
}
