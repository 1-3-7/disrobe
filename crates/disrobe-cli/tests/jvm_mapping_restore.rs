#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{cli_binary, run_disrobe, temp_dir};

fn corpus(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    p
}

#[test]
fn jvm_decompile_applies_proguard_mapping_to_real_jar() {
    let jar: PathBuf = corpus("corpus/jvm/proguard/EdgeCases-pg.jar");
    let mapping: PathBuf = corpus("corpus/jvm/proguard/EdgeCases-mapping.txt");
    if !jar.exists() || !mapping.exists() {
        eprintln!("SKIP: missing corpus {jar:?} / {mapping:?}");
        return;
    }
    if !cli_binary().exists() {
        eprintln!("SKIP: disrobe binary not built");
        return;
    }

    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-mapping-jar");

    let out: PathBuf = out_scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        jar.to_str().expect("utf8 jar"),
        "--out",
        out.to_str().expect("utf8 out"),
        "--mapping",
        mapping.to_str().expect("utf8 mapping"),
    ]);
    assert_eq!(
        run.code, 0,
        "jvm decompile --mapping failed: {}",
        run.stderr
    );
    assert!(
        run.stdout.contains("names restored"),
        "stdout must report restored names: {}",
        run.stdout
    );

    let report: String = std::fs::read_to_string(out.join("name-restoration.json"))
        .expect("name-restoration.json must be written for the jar");
    let json: serde_json::Value =
        serde_json::from_str(&report).expect("name-restoration.json is valid json");

    assert_eq!(
        json["schema"], "disrobe.jvm.name-restoration/v1",
        "report carries the v1 schema"
    );
    let classes: &Vec<serde_json::Value> =
        json["classes"].as_array().expect("classes array present");
    let edge: &serde_json::Value = classes
        .iter()
        .find(|c| c["class"] == "EdgeCases")
        .expect("EdgeCases class restoration present");

    let methods: &serde_json::Map<String, serde_json::Value> =
        edge["methods"].as_object().expect("methods object");
    assert_eq!(
        methods.get("a(I)I").and_then(|v| v.as_str()),
        Some("recursiveFactorial"),
        "descriptor disambiguation must reach the CLI report: {methods:?}"
    );
    assert_eq!(
        methods
            .get("a(Ljava/lang/String;)Ljava/lang/String;")
            .and_then(|v| v.as_str()),
        Some("multiCatch"),
        "the String overload must restore to multiCatch in the report"
    );

    let restored: u64 = json["restored_count"].as_u64().expect("restored_count");
    assert!(
        restored >= 40,
        "the EdgeCases jar should restore many names, got {restored}"
    );

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn jvm_decompile_mapping_splits_same_letter_fields_by_type() {
    let jar: PathBuf = corpus("corpus/jvm/proguard/Hello-obf.jar");
    let mapping: PathBuf = corpus("corpus/jvm/proguard/mapping.txt");
    if !jar.exists() || !mapping.exists() {
        eprintln!("SKIP: missing corpus {jar:?} / {mapping:?}");
        return;
    }
    if !cli_binary().exists() {
        eprintln!("SKIP: disrobe binary not built");
        return;
    }

    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-mapping-hello");

    let out: PathBuf = out_scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "jvm",
        "decompile",
        jar.to_str().expect("utf8 jar"),
        "--out",
        out.to_str().expect("utf8 out"),
        "--mapping",
        mapping.to_str().expect("utf8 mapping"),
    ]);
    assert_eq!(
        run.code, 0,
        "hello mapping decompile failed: {}",
        run.stderr
    );

    let report: String = std::fs::read_to_string(out.join("name-restoration.json"))
        .expect("name-restoration.json written");
    let json: serde_json::Value = serde_json::from_str(&report).expect("valid json");
    let classes: &Vec<serde_json::Value> = json["classes"].as_array().expect("classes");
    let hello: &serde_json::Value = classes
        .iter()
        .find(|c| c["class"] == "Hello")
        .expect("Hello restoration present");
    let fields: &serde_json::Map<String, serde_json::Value> =
        hello["fields"].as_object().expect("fields object");
    assert_eq!(
        fields.get("a:I").and_then(|v| v.as_str()),
        Some("counter"),
        "int field 'a' restores to counter: {fields:?}"
    );
    assert_eq!(
        fields.get("a:Ljava/lang/String;").and_then(|v| v.as_str()),
        Some("name"),
        "String field 'a' restores to name: {fields:?}"
    );

    let _ = std::fs::remove_dir_all(&out);
}
