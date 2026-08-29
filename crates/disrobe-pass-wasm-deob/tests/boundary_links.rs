#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use disrobe_pass_wasm_deob::name_recovery::{
    BoundaryDirection, BoundaryEvidence, BoundaryIdentitySource, BoundaryRelation,
    JavaScriptBoundaryIdentity, WebAssemblyBoundaryIdentity,
};
use disrobe_pass_wasm_deob::{ModuleSignatures, extract_signatures, strip_name_section};

const KEPT_NAMES: &str = r#"
(module
  (import "host" "host_log" (func $kept_host_dispatch (param i32)))
  (func $kept_compute_kernel (param i32) (result i32)
    local.get 0
    call $kept_host_dispatch
    local.get 0)
  (export "compute" (func $kept_compute_kernel)))
"#;

type RelationIdentity = (
    BoundaryDirection,
    Option<String>,
    String,
    u32,
    String,
    BoundaryIdentitySource,
);

fn relation_identities(relations: &[BoundaryRelation]) -> BTreeSet<RelationIdentity> {
    relations
        .iter()
        .map(|relation: &BoundaryRelation| {
            (
                relation.direction,
                relation.javascript.module.clone(),
                relation.javascript.name.clone(),
                relation.webassembly.function_index,
                relation.webassembly.name.clone(),
                relation.webassembly.source,
            )
        })
        .collect()
}

fn kept_ground_truth() -> BTreeSet<RelationIdentity> {
    BTreeSet::from([
        (
            BoundaryDirection::JavaScriptToWebAssembly,
            Some("host".to_owned()),
            "host_log".to_owned(),
            0,
            "kept_host_dispatch".to_owned(),
            BoundaryIdentitySource::NameSection,
        ),
        (
            BoundaryDirection::WebAssemblyToJavaScript,
            None,
            "compute".to_owned(),
            1,
            "kept_compute_kernel".to_owned(),
            BoundaryIdentitySource::NameSection,
        ),
    ])
}

fn stripped_ground_truth() -> BTreeSet<RelationIdentity> {
    BTreeSet::from([
        (
            BoundaryDirection::JavaScriptToWebAssembly,
            Some("host".to_owned()),
            "host_log".to_owned(),
            0,
            "host_log".to_owned(),
            BoundaryIdentitySource::BoundaryField,
        ),
        (
            BoundaryDirection::WebAssemblyToJavaScript,
            None,
            "compute".to_owned(),
            1,
            "compute".to_owned(),
            BoundaryIdentitySource::BoundaryField,
        ),
    ])
}

fn assert_exact_grade(
    recovered: &BTreeSet<RelationIdentity>,
    expected: &BTreeSet<RelationIdentity>,
) {
    let matched: usize = recovered.intersection(expected).count();
    assert_eq!((matched, recovered.len()), (2, 2), "precision is 2/2");
    assert_eq!((matched, expected.len()), (2, 2), "recall is 2/2");
    assert_eq!(recovered, expected, "exact relation identities");
}

#[test]
fn kept_then_stripped_module_recovers_exact_direct_boundary_relations() {
    let kept: Vec<u8> = wat::parse_str(KEPT_NAMES).expect("kept-name module");
    let stripped: Vec<u8> = strip_name_section(&kept).expect("strip name section");
    let kept_signatures: ModuleSignatures = extract_signatures(&kept).expect("kept signatures");
    let stripped_signatures: ModuleSignatures =
        extract_signatures(&stripped).expect("stripped signatures");
    let kept_recovered: BTreeSet<RelationIdentity> =
        relation_identities(kept_signatures.boundary_relations());
    let stripped_recovered: BTreeSet<RelationIdentity> =
        relation_identities(stripped_signatures.boundary_relations());

    assert_exact_grade(&kept_recovered, &kept_ground_truth());
    assert_exact_grade(&stripped_recovered, &stripped_ground_truth());
}

#[test]
fn direct_evidence_is_typed_and_recheckable() {
    let kept: Vec<u8> = wat::parse_str(KEPT_NAMES).expect("kept-name module");
    let signatures: ModuleSignatures = extract_signatures(&kept).expect("signatures");
    assert_eq!(
        signatures.boundary_relations(),
        [
            BoundaryRelation {
                direction: BoundaryDirection::JavaScriptToWebAssembly,
                javascript: JavaScriptBoundaryIdentity {
                    module: Some("host".to_owned()),
                    name: "host_log".to_owned(),
                },
                webassembly: WebAssemblyBoundaryIdentity {
                    function_index: 0,
                    name: "kept_host_dispatch".to_owned(),
                    source: BoundaryIdentitySource::NameSection,
                },
                evidence: BoundaryEvidence::WasmImport {
                    module: "host".to_owned(),
                    field: "host_log".to_owned(),
                },
            },
            BoundaryRelation {
                direction: BoundaryDirection::WebAssemblyToJavaScript,
                javascript: JavaScriptBoundaryIdentity {
                    module: None,
                    name: "compute".to_owned(),
                },
                webassembly: WebAssemblyBoundaryIdentity {
                    function_index: 1,
                    name: "kept_compute_kernel".to_owned(),
                    source: BoundaryIdentitySource::NameSection,
                },
                evidence: BoundaryEvidence::WasmExport {
                    field: "compute".to_owned(),
                },
            },
        ]
    );
    let value: serde_json::Value =
        serde_json::to_value(signatures.boundary_relations()).expect("serialize relations");
    assert_eq!(
        value,
        serde_json::json!([
            {
                "direction": "java_script_to_web_assembly",
                "javascript": {"module": "host", "name": "host_log"},
                "webassembly": {
                    "function_index": 0,
                    "name": "kept_host_dispatch",
                    "source": "name_section"
                },
                "evidence": {"kind": "wasm_import", "module": "host", "field": "host_log"}
            },
            {
                "direction": "web_assembly_to_java_script",
                "javascript": {"name": "compute"},
                "webassembly": {
                    "function_index": 1,
                    "name": "kept_compute_kernel",
                    "source": "name_section"
                },
                "evidence": {"kind": "wasm_export", "field": "compute"}
            }
        ])
    );
}

#[test]
fn no_direct_evidence_produces_no_relation() {
    let bytes: Vec<u8> = wat::parse_str("(module (func (result i32) i32.const 1))")
        .expect("module without boundary evidence");
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    assert!(signatures.boundary_relations().is_empty());
}

#[test]
fn duplicate_cyclic_boundary_input_is_idempotent() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (import "host" "callback" (func $callback))
          (export "callback" (func $callback))
          (export "callback" (func $callback)))"#,
    )
    .expect("cyclic boundary module");
    let first: ModuleSignatures = extract_signatures(&bytes).expect("first extraction");
    let second: ModuleSignatures = extract_signatures(&bytes).expect("second extraction");
    assert_eq!(first.boundary_relations(), second.boundary_relations());
    assert_eq!(first.boundary_relations().len(), 2);
}

#[test]
fn direct_field_collision_does_not_replace_name_section_identity() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (func $trusted_identity)
          (export "weak_alias" (func $trusted_identity)))"#,
    )
    .expect("colliding identity module");
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let relation: &BoundaryRelation = signatures
        .boundary_relations()
        .first()
        .expect("export relation");
    assert_eq!(relation.webassembly.name, "trusted_identity");
    assert_eq!(
        relation.webassembly.source,
        BoundaryIdentitySource::NameSection
    );
    assert_eq!(relation.javascript.name, "weak_alias");
}
