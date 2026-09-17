#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fmt::Write as _;

use disrobe_pass_native::{AuditableCrate, AuditableSbom, Error, parse_auditable_section};
use serde_json::Value;

mod common;

const AUDITABLE_JSON: &[u8] = br#"{"packages":[
  {"name":"serde","version":"1.0.203","source":"registry+https://github.com/rust-lang/crates.io-index"},
  {"name":"anyhow","version":"1.0.86","source":"registry+https://github.com/rust-lang/crates.io-index"}
]}"#;
const REAL_AUDITABLE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../corpus/native/formats/hello.auditable.exe"
);

#[test]
fn parse_auditable_section_yields_expected_crates() {
    let sbom: AuditableSbom = parse_auditable_section(AUDITABLE_JSON).expect("parse auditable");
    assert_eq!(sbom.crates.len(), 2);

    let serde: &AuditableCrate = &sbom.crates[0];
    assert_eq!(serde.name, "serde");
    assert_eq!(serde.version, "1.0.203");
    assert_eq!(
        serde.source.as_deref(),
        Some("registry+https://github.com/rust-lang/crates.io-index")
    );

    let anyhow: &AuditableCrate = &sbom.crates[1];
    assert_eq!(anyhow.name, "anyhow");
    assert_eq!(anyhow.version, "1.0.86");
}

#[test]
fn missing_packages_array_is_rejected() {
    let result: disrobe_pass_native::Result<AuditableSbom> =
        parse_auditable_section(br#"{"not_packages":[]}"#);
    assert!(
        matches!(result, Err(Error::SignatureDb(ref msg)) if msg.contains("missing 'packages' array")),
        "expected SignatureDb(missing 'packages' array), got {result:?}"
    );
}

#[test]
fn native_sbom_extracts_real_pe_section_and_emits_exact_cargo_purl() {
    let (_scratch, output_path): (disrobe_core::scratch::ScratchDir, std::path::PathBuf) =
        common::temp_path("native-cyclonedx", "json");
    let output: &str = output_path.to_str().expect("UTF-8 scratch path");
    let run: common::Run =
        common::run_disrobe(&["native", "sbom", REAL_AUDITABLE_PATH, "--out", output]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout.contains("native sbom: OK"), "{}", run.stdout);

    let bytes: Vec<u8> = std::fs::read(&output_path).expect("read emitted CycloneDX document");
    let bom: Value = serde_json::from_slice(&bytes).expect("parse emitted CycloneDX document");
    let components: &Vec<Value> = bom["components"]
        .as_array()
        .expect("CycloneDX components array");
    assert_eq!(components.len(), 3);
    let adler2: &Value = components
        .iter()
        .find(|component: &&Value| component["name"] == "adler2")
        .expect("adler2 from the committed PE auditable section");
    assert_eq!(adler2["version"], "2.0.1");
    assert_eq!(adler2["purl"], "pkg:cargo/adler2@2.0.1");
    assert_eq!(adler2["bom-ref"], "pkg:cargo/adler2@2.0.1");
}

#[test]
fn native_sbom_preserves_distinct_sources_and_collapses_exact_duplicates() {
    let (input_scratch, input_path): (disrobe_core::scratch::ScratchDir, std::path::PathBuf) =
        common::temp_path("native-cyclonedx-sources-input", "json");
    let (output_scratch, output_path): (disrobe_core::scratch::ScratchDir, std::path::PathBuf) =
        common::temp_path("native-cyclonedx-sources-output", "json");
    let json: &[u8] = br#"{"packages":[
        {"name":"shared","version":"1.0.0","source":"registry+https://packages.example.invalid/index"},
        {"name":"shared","version":"1.0.0","source":"registry+https://packages.example.invalid/index"},
        {"name":"shared","version":"1.0.0","source":"git+https://example.invalid/shared?rev=abc"}
    ]}"#;
    std::fs::write(&input_path, json).expect("write auditable JSON input");

    let input_arg: &str = input_path.to_str().expect("UTF-8 input path");
    let output_arg: &str = output_path.to_str().expect("UTF-8 output path");
    let run: common::Run = common::run_disrobe(&["native", "sbom", input_arg, "--out", output_arg]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);

    let bytes: Vec<u8> = std::fs::read(&output_path).expect("read emitted CycloneDX document");
    let bom: Value = serde_json::from_slice(&bytes).expect("parse emitted CycloneDX document");
    let components: &Vec<Value> = bom["components"]
        .as_array()
        .expect("CycloneDX components array");
    let shared: Vec<&Value> = components
        .iter()
        .filter(|component: &&Value| component["name"] == "shared")
        .collect();
    assert_eq!(shared.len(), 2);
    assert_eq!(shared[0]["purl"], "pkg:cargo/shared@1.0.0");
    assert_eq!(shared[1]["purl"], "pkg:cargo/shared@1.0.0");
    assert_ne!(shared[0]["bom-ref"], shared[1]["bom-ref"]);
    let component_references: Vec<&str> = components
        .iter()
        .filter_map(|component: &Value| component["bom-ref"].as_str())
        .collect();
    let unique_references: std::collections::BTreeSet<&str> =
        component_references.iter().copied().collect();
    assert_eq!(unique_references.len(), component_references.len());
    let mut sources: Vec<&str> = shared
        .iter()
        .map(|component: &&Value| {
            component["properties"][0]["value"]
                .as_str()
                .expect("source property value")
        })
        .collect();
    sources.sort_unstable();
    assert_eq!(
        sources,
        [
            "git+https://example.invalid/shared?rev=abc",
            "registry+https://packages.example.invalid/index"
        ]
    );
    drop((input_scratch, output_scratch));
}

#[test]
fn native_sbom_rejects_output_above_the_cyclonedx_byte_limit() {
    let (input_scratch, input_path): (disrobe_core::scratch::ScratchDir, std::path::PathBuf) =
        common::temp_path("native-cyclonedx-input", "json");
    let (output_scratch, output_path): (disrobe_core::scratch::ScratchDir, std::path::PathBuf) =
        common::temp_path("native-cyclonedx-output", "json");
    let escaped_name: String = r"\u0000".repeat(16_000);
    let mut input: String = String::from(r#"{"packages":["#);
    for index in 0usize..170 {
        if index != 0 {
            input.push(',');
        }
        write!(
            &mut input,
            r#"{{"name":"{escaped_name}","version":"{index}"}}"#
        )
        .expect("write auditable package");
    }
    input.push_str("]}");
    assert!(input.len() < 16 * 1024 * 1024);
    std::fs::write(&input_path, input).expect("write auditable JSON input");

    let input_arg: &str = input_path.to_str().expect("UTF-8 input path");
    let output_arg: &str = output_path.to_str().expect("UTF-8 output path");
    let run: common::Run = common::run_disrobe(&["native", "sbom", input_arg, "--out", output_arg]);
    assert_ne!(run.code, 0, "stdout: {}", run.stdout);
    assert!(run.stderr.contains("DR-NATIVE-0063"), "{}", run.stderr);
    assert!(run.stderr.contains("output"), "{}", run.stderr);
    assert!(!output_path.exists());
    drop((input_scratch, output_scratch));
}

#[test]
fn native_sbom_rejects_sparse_input_above_the_file_limit() {
    let (input_scratch, input_path): (disrobe_core::scratch::ScratchDir, std::path::PathBuf) =
        common::temp_path("native-cyclonedx-large-input", "exe");
    let (output_scratch, output_path): (disrobe_core::scratch::ScratchDir, std::path::PathBuf) =
        common::temp_path("native-cyclonedx-large-output", "json");
    let input_file: std::fs::File =
        std::fs::File::create(&input_path).expect("create sparse input");
    input_file
        .set_len(256 * 1024 * 1024 + 1)
        .expect("set sparse input length");

    let input_arg: &str = input_path.to_str().expect("UTF-8 input path");
    let output_arg: &str = output_path.to_str().expect("UTF-8 output path");
    let run: common::Run = common::run_disrobe(&["native", "sbom", input_arg, "--out", output_arg]);
    assert_ne!(run.code, 0, "stdout: {}", run.stdout);
    assert!(run.stderr.contains("DR-NATIVE-0060"), "{}", run.stderr);
    assert!(
        run.stderr.contains("268435456-byte limit"),
        "{}",
        run.stderr
    );
    assert!(!output_path.exists());
    drop((input_scratch, output_scratch));
}
