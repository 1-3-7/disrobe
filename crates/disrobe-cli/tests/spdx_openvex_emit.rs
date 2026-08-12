#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
};
use disrobe_ir::{Envelope, Rung};
use jsonschema::Validator;
use serde_json::Value;

mod common;

const REAL_AUDITABLE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../corpus/native/formats/hello.auditable.exe"
);
const SPDX_SCHEMA: &str = include_str!("schemas/spdx-2.3.schema.json");
const OPENVEX_SCHEMA: &str = include_str!("schemas/openvex-0.2.0.schema.json");
const FIXED_TIMESTAMP: &str = "2026-08-12T12:34:56Z";

fn validate(schema_text: &str, value: &Value) {
    let schema: Value = serde_json::from_str(schema_text).expect("published schema parses");
    let validator: Validator =
        jsonschema::validator_for(&schema).expect("published schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|error: jsonschema::ValidationError<'_>| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "schema errors: {errors:#?}\ndocument: {value:#}"
    );
}

fn write_reachable_gets_fixture(path: &Path) {
    let payload: DisasmPayload = DisasmPayload {
        source_hash: [0u8; 32],
        instructions: vec![
            DisasmInstruction {
                offset: 0x10,
                bytes: vec![0xe8, 0, 0, 0, 0],
                mnemonic: "call".to_owned(),
                operands: vec!["gets".to_owned()],
                flow: InsnFlow::Call,
                branch_target: Some(0x20),
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x15,
                bytes: vec![0xe8, 0, 0, 0, 0],
                mnemonic: "call".to_owned(),
                operands: vec!["gets".to_owned()],
                flow: InsnFlow::Call,
                branch_target: Some(0x20),
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x1a,
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: Vec::new(),
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ],
        symbol_table: vec![
            DisasmSymbol {
                address: 0x10,
                name: "main".to_owned(),
                kind: DisasmSymbolKind::Export,
            },
            DisasmSymbol {
                address: 0x20,
                name: "gets".to_owned(),
                kind: DisasmSymbolKind::Import,
            },
        ],
    };
    let hot: Vec<u8> = encode_disasm(&payload).expect("encode disassembly payload");
    let bytes: Vec<u8> = Envelope::new(Rung::Disasm, hot, Vec::new())
        .encode()
        .expect("encode envelope");
    common::write_bytes(path, &bytes);
}

#[test]
fn native_sbom_emits_schema_valid_spdx_2_3_from_real_pe() {
    let (_scratch, output_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        common::temp_path("native-spdx", "json");
    let output: &str = output_path.to_str().expect("UTF-8 scratch path");
    let run: common::Run = common::run_disrobe(&[
        "native",
        "sbom",
        REAL_AUDITABLE_PATH,
        "--format",
        "spdx",
        "--timestamp",
        FIXED_TIMESTAMP,
        "--out",
        output,
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout.contains("SPDX 2.3"), "stdout: {}", run.stdout);

    let bytes: Vec<u8> = std::fs::read(&output_path).expect("read emitted SPDX document");
    let document: Value = serde_json::from_slice(&bytes).expect("parse emitted SPDX document");
    validate(SPDX_SCHEMA, &document);
    assert_eq!(document["spdxVersion"], "SPDX-2.3");
    assert_eq!(document["creationInfo"]["created"], FIXED_TIMESTAMP);
    assert_eq!(document["packages"].as_array().expect("packages").len(), 3);

    let packages: &Vec<Value> = document["packages"].as_array().expect("packages");
    let adler2: &Value = packages
        .iter()
        .find(|package: &&Value| package["name"] == "adler2")
        .expect("adler2 package");
    assert_eq!(adler2["versionInfo"], "2.0.1");
    assert_eq!(
        adler2["externalRefs"][0]["referenceLocator"],
        "pkg:cargo/adler2@2.0.1"
    );
    assert!(adler2.get("supplier").is_none());
    assert!(adler2.get("licenseDeclared").is_none());

    let relationships: &Vec<Value> = document["relationships"].as_array().expect("relationships");
    assert!(relationships.iter().any(|relationship: &Value| {
        relationship["relationshipType"] == "DESCRIBES"
            && relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
    }));
    assert_eq!(
        relationships
            .iter()
            .filter(|relationship: &&Value| relationship["relationshipType"] == "CONTAINS")
            .count(),
        2
    );
}

#[test]
fn native_spdx_is_byte_deterministic_for_an_explicit_timestamp() {
    let (_first_scratch, first_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        common::temp_path("native-spdx-first", "json");
    let (_second_scratch, second_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        common::temp_path("native-spdx-second", "json");
    for path in [&first_path, &second_path] {
        let output: &str = path.to_str().expect("UTF-8 scratch path");
        let run: common::Run = common::run_disrobe(&[
            "native",
            "sbom",
            REAL_AUDITABLE_PATH,
            "--format",
            "spdx",
            "--timestamp",
            FIXED_TIMESTAMP,
            "--out",
            output,
        ]);
        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    }
    assert_eq!(
        std::fs::read(first_path).expect("read first SPDX"),
        std::fs::read(second_path).expect("read second SPDX")
    );
}

#[test]
fn vulnmatch_emits_schema_valid_openvex_from_real_reachability_verdict() {
    let (_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        common::temp_path("openvex-reachable", "dr");
    write_reachable_gets_fixture(&input);
    let input_arg: String = input.display().to_string();
    let run: common::Run = common::run_disrobe(&[
        "vulnmatch",
        &input_arg,
        "--openvex",
        "--author",
        "Organization: disrobe",
        "--timestamp",
        FIXED_TIMESTAMP,
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let document: Value = serde_json::from_str(&run.stdout).expect("parse OpenVEX document");
    validate(OPENVEX_SCHEMA, &document);
    assert_eq!(document["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(document["timestamp"], FIXED_TIMESTAMP);
    assert_eq!(
        document["statements"].as_array().expect("statements").len(),
        1
    );
    assert_eq!(document["statements"][0]["status"], "affected");
    assert_eq!(
        document["statements"][0]["vulnerability"]["name"],
        "cwe-242-gets"
    );
    assert!(
        document["statements"][0]["products"][0]["@id"]
            .as_str()
            .is_some_and(|id: &str| id.starts_with("urn:sha256:"))
    );
}

#[test]
fn new_formats_are_visible_in_command_help() {
    let sbom_help: common::Run = common::run_disrobe(&["native", "sbom", "--help"]);
    assert_eq!(sbom_help.code, 0, "stderr: {}", sbom_help.stderr);
    assert!(sbom_help.stdout.contains("cyclonedx"));
    assert!(sbom_help.stdout.contains("spdx"));

    let vulnmatch_help: common::Run = common::run_disrobe(&["vulnmatch", "--help"]);
    assert_eq!(vulnmatch_help.code, 0, "stderr: {}", vulnmatch_help.stderr);
    assert!(vulnmatch_help.stdout.contains("--openvex"));
    assert!(vulnmatch_help.stdout.contains("--author"));
    assert!(vulnmatch_help.stdout.contains("--timestamp"));
}

#[test]
fn document_formats_reject_missing_or_noncanonical_metadata() {
    let invalid_cyclonedx_timestamp: common::Run = common::run_disrobe(&[
        "native",
        "sbom",
        REAL_AUDITABLE_PATH,
        "--timestamp",
        "2026-08-12 12:34:56",
    ]);
    assert_ne!(invalid_cyclonedx_timestamp.code, 0);
    assert!(
        invalid_cyclonedx_timestamp.stderr.contains("canonical UTC"),
        "stderr: {}",
        invalid_cyclonedx_timestamp.stderr
    );

    let spdx: common::Run =
        common::run_disrobe(&["native", "sbom", REAL_AUDITABLE_PATH, "--format", "spdx"]);
    assert_ne!(spdx.code, 0);
    assert!(spdx.stderr.contains("timestamp"), "stderr: {}", spdx.stderr);

    let (_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        common::temp_path("openvex-invalid-metadata", "dr");
    write_reachable_gets_fixture(&input);
    let input_arg: String = input.display().to_string();
    let empty_author: common::Run = common::run_disrobe(&[
        "vulnmatch",
        &input_arg,
        "--openvex",
        "--author",
        "",
        "--timestamp",
        FIXED_TIMESTAMP,
    ]);
    assert_ne!(empty_author.code, 0);
    assert!(empty_author.stderr.contains("author must not be empty"));

    let invalid_timestamp: common::Run = common::run_disrobe(&[
        "vulnmatch",
        &input_arg,
        "--openvex",
        "--author",
        "Organization: disrobe",
        "--timestamp",
        "2026-08-12 12:34:56",
    ]);
    assert_ne!(invalid_timestamp.code, 0);
    assert!(
        invalid_timestamp.stderr.contains("canonical UTC"),
        "stderr: {}",
        invalid_timestamp.stderr
    );

    let incompatible_modes: common::Run = common::run_disrobe(&[
        "vulnmatch",
        &input_arg,
        "--osv-db",
        &input_arg,
        "--openvex",
        "--author",
        "Organization: disrobe",
        "--timestamp",
        FIXED_TIMESTAMP,
    ]);
    assert_ne!(incompatible_modes.code, 0);
    assert!(incompatible_modes.stderr.contains("cannot be combined"));
}
