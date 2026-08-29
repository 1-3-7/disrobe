#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use disrobe_pass_wasm_deob::{
    BoundaryEvidence, BoundaryIdentitySource, BoundaryLanguage, BoundaryLink, BoundaryLinks,
    BoundaryLinksError, MAX_BOUNDARY_LINK_STRING_BYTES, MAX_BOUNDARY_LINKS,
    MAX_BOUNDARY_LINKS_JSON_BYTES, ModuleSignatures, extract_signatures, strip_name_section,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BoundaryDirection {
    JavaScriptToWebAssembly,
    WebAssemblyToJavaScript,
}

fn link_identities(links: &[BoundaryLink]) -> BTreeSet<RelationIdentity> {
    links
        .iter()
        .map(|link: &BoundaryLink| {
            if link.source.language.as_str() == "javascript" {
                (
                    BoundaryDirection::JavaScriptToWebAssembly,
                    link.source.module.clone(),
                    link.source.name.clone(),
                    link.target.index.expect("webassembly function index"),
                    link.target.name.clone(),
                    link.target.identity_source,
                )
            } else {
                assert_eq!(link.source.language.as_str(), "webassembly");
                assert_eq!(link.target.language.as_str(), "javascript");
                (
                    BoundaryDirection::WebAssemblyToJavaScript,
                    link.target.module.clone(),
                    link.target.name.clone(),
                    link.source.index.expect("webassembly function index"),
                    link.source.name.clone(),
                    link.source.identity_source,
                )
            }
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
        link_identities(kept_signatures.boundary_relations());
    let stripped_recovered: BTreeSet<RelationIdentity> =
        link_identities(stripped_signatures.boundary_relations());

    assert_exact_grade(&kept_recovered, &kept_ground_truth());
    assert_exact_grade(&stripped_recovered, &stripped_ground_truth());
}

#[test]
fn signature_caller_round_trips_kept_and_stripped_relations_through_versioned_sidecar() {
    let kept: Vec<u8> = wat::parse_str(KEPT_NAMES).expect("kept-name module");
    let stripped: Vec<u8> = strip_name_section(&kept).expect("strip name section");
    for (bytes, expected) in [
        (kept.as_slice(), kept_ground_truth()),
        (stripped.as_slice(), stripped_ground_truth()),
    ] {
        let signatures: ModuleSignatures = extract_signatures(bytes).expect("signatures");
        let encoded: Vec<u8> = signatures
            .boundary_links()
            .to_json()
            .expect("serialize boundary links");
        let decoded: BoundaryLinks =
            BoundaryLinks::from_json(&encoded).expect("read boundary links");
        let reencoded: Vec<u8> = decoded.to_json().expect("re-serialize boundary links");

        assert_eq!(encoded, reencoded, "canonical sidecar bytes");
        assert_exact_grade(&link_identities(decoded.links()), &expected);
    }
}

#[test]
fn unknown_sidecar_version_is_a_typed_refusal() {
    let result: Result<BoundaryLinks, BoundaryLinksError> =
        BoundaryLinks::from_json(br#"{"schema_version":2,"links":[]}"#);
    assert!(matches!(
        result,
        Err(BoundaryLinksError::UnsupportedVersion { version: 2 })
    ));
}

fn valid_link_json() -> serde_json::Value {
    serde_json::json!({
        "source": {
            "language": "javascript",
            "kind": "function",
            "module": "host",
            "name": "host_log",
            "identity_source": "boundary_field"
        },
        "target": {
            "language": "webassembly",
            "kind": "function",
            "name": "kept_host_dispatch",
            "index": 0,
            "identity_source": "name_section"
        },
        "evidence": {"kind": "wasm_import", "module": "host", "field": "host_log"}
    })
}

#[test]
fn sidecar_reader_rejects_noncanonical_language_tags() {
    let mut link: serde_json::Value = valid_link_json();
    link["source"]["language"] = serde_json::Value::String(" javascript ".to_owned());
    let encoded: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": [link]
    }))
    .expect("encode sidecar");
    let result: Result<BoundaryLinks, BoundaryLinksError> = BoundaryLinks::from_json(&encoded);
    assert!(matches!(
        result,
        Err(BoundaryLinksError::NonCanonicalLanguage {
            link_index: 0,
            endpoint: "source"
        })
    ));
}

#[test]
fn public_language_deserialization_enforces_constructor_validation() {
    let result: Result<BoundaryLanguage, serde_json::Error> =
        serde_json::from_str(r#"" javascript ""#);
    assert!(result.is_err());
}

#[test]
fn sidecar_reader_rejects_unknown_evidence_fields() {
    let mut link: serde_json::Value = valid_link_json();
    link["evidence"]["unexpected"] = serde_json::Value::Bool(true);
    let encoded: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": [link]
    }))
    .expect("encode sidecar");
    let result: Result<BoundaryLinks, BoundaryLinksError> = BoundaryLinks::from_json(&encoded);
    assert!(matches!(result, Err(BoundaryLinksError::Json(_))));
}

#[test]
fn sidecar_reader_bounds_input_bytes_before_parsing() {
    let encoded: Vec<u8> = vec![b' '; MAX_BOUNDARY_LINKS_JSON_BYTES + 1];
    let result: Result<BoundaryLinks, BoundaryLinksError> = BoundaryLinks::from_json(&encoded);
    assert!(matches!(
        result,
        Err(BoundaryLinksError::InputTooLarge { .. })
    ));
}

#[test]
fn sidecar_reader_bounds_link_population() {
    let encoded: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": vec![valid_link_json(); MAX_BOUNDARY_LINKS + 1]
    }))
    .expect("encode sidecar");
    assert!(encoded.len() <= MAX_BOUNDARY_LINKS_JSON_BYTES);
    let result: Result<BoundaryLinks, BoundaryLinksError> = BoundaryLinks::from_json(&encoded);
    assert!(matches!(
        result,
        Err(BoundaryLinksError::TooManyLinks { .. })
    ));
}

#[test]
fn sidecar_reader_bounds_individual_strings() {
    let mut link: serde_json::Value = valid_link_json();
    link["source"]["name"] =
        serde_json::Value::String("x".repeat(MAX_BOUNDARY_LINK_STRING_BYTES + 1));
    let encoded: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": [link]
    }))
    .expect("encode sidecar");
    let result: Result<BoundaryLinks, BoundaryLinksError> = BoundaryLinks::from_json(&encoded);
    assert!(matches!(
        result,
        Err(BoundaryLinksError::StringTooLong {
            link_index: 0,
            field: "source.name",
            ..
        })
    ));
}

#[test]
fn direct_evidence_is_typed_and_recheckable() {
    let kept: Vec<u8> = wat::parse_str(KEPT_NAMES).expect("kept-name module");
    let signatures: ModuleSignatures = extract_signatures(&kept).expect("signatures");
    let links: &[BoundaryLink] = signatures.boundary_relations();
    assert_eq!(links.len(), 2);
    assert!(matches!(
        &links[0].evidence,
        BoundaryEvidence::WasmImport { module, field }
            if module == "host" && field == "host_log"
    ));
    assert!(matches!(
        &links[1].evidence,
        BoundaryEvidence::WasmExport { field } if field == "compute"
    ));
    let encoded: Vec<u8> = signatures
        .boundary_links()
        .to_json()
        .expect("serialize boundary links");
    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("sidecar json");
    assert_eq!(
        value,
        serde_json::json!({
            "schema_version": 1,
            "links": [
                {
                    "source": {
                        "language": "javascript",
                        "kind": "function",
                        "module": "host",
                        "name": "host_log",
                        "identity_source": "boundary_field"
                    },
                    "target": {
                        "language": "webassembly",
                        "kind": "function",
                        "name": "kept_host_dispatch",
                        "index": 0,
                        "identity_source": "name_section"
                    },
                    "evidence": {"kind": "wasm_import", "module": "host", "field": "host_log"}
                },
                {
                    "source": {
                        "language": "webassembly",
                        "kind": "function",
                        "name": "kept_compute_kernel",
                        "index": 1,
                        "identity_source": "name_section"
                    },
                    "target": {
                        "language": "javascript",
                        "kind": "function",
                        "name": "compute",
                        "identity_source": "boundary_field"
                    },
                    "evidence": {"kind": "wasm_export", "field": "compute"}
                }
            ]
        })
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
    let relation: &BoundaryLink = signatures
        .boundary_relations()
        .first()
        .expect("export relation");
    assert_eq!(relation.source.name, "trusted_identity");
    assert_eq!(
        relation.source.identity_source,
        BoundaryIdentitySource::NameSection
    );
    assert_eq!(relation.target.name, "weak_alias");
}
