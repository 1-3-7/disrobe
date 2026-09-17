#![allow(clippy::expect_used)]

use std::{collections::BTreeSet, fmt::Write};

use disrobe_pass_wasm_deob::{
    BoundaryConfidence, BoundaryEvidence, BoundaryIdentitySource, BoundaryLanguage, BoundaryLink,
    BoundaryLinks, BoundaryLinksError, BoundarySymbol, BoundarySymbolKind,
    BoundaryWasmAbstractHeapType, BoundaryWasmReferenceType, BoundaryWasmType,
    BoundaryWasmValueType, MAX_BOUNDARY_LINK_STRING_BYTES, MAX_BOUNDARY_LINKS,
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
fn sidecar_reader_rejects_invalid_wasm_value_and_reference_types() {
    let mut table_link: serde_json::Value = valid_link_json();
    table_link["source"]["kind"] = serde_json::Value::String("table".to_owned());
    table_link["target"]["kind"] = serde_json::Value::String("table".to_owned());
    table_link["evidence"] = serde_json::json!({
        "kind": "resource_import",
        "module": "host",
        "field": "host_log",
        "index": 0,
        "resource_type": {
            "kind": "table",
            "element_type": "not_a_reference",
            "minimum": 0,
            "table64": false,
            "shared": false
        }
    });
    let table_json: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": [table_link]
    }))
    .expect("encode table sidecar");
    assert!(BoundaryLinks::from_json(&table_json).is_err());

    let mut global_link: serde_json::Value = valid_link_json();
    global_link["source"]["kind"] = serde_json::Value::String("global".to_owned());
    global_link["target"]["kind"] = serde_json::Value::String("global".to_owned());
    global_link["evidence"] = serde_json::json!({
        "kind": "resource_import",
        "module": "host",
        "field": "host_log",
        "index": 0,
        "resource_type": {
            "kind": "global",
            "value_type": "not_a_value",
            "mutable": false,
            "shared": false
        }
    });
    let global_json: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": [global_link]
    }))
    .expect("encode global sidecar");
    assert!(BoundaryLinks::from_json(&global_json).is_err());
}

#[test]
fn wasm_type_values_are_closed_and_serialize_as_schema_v1_strings() {
    let value: BoundaryWasmValueType =
        BoundaryWasmValueType::Reference(BoundaryWasmReferenceType::Abstract {
            heap_type: BoundaryWasmAbstractHeapType::Func,
            nullable: true,
            shared: false,
        });
    assert_eq!(
        serde_json::to_string(&value).expect("serialize value"),
        "\"funcref\""
    );
    assert!(serde_json::from_str::<BoundaryWasmValueType>("\"unknownref\"").is_err());
}

#[test]
fn mismatched_confidence_is_refused_by_constructor_and_json_reader() {
    let source: BoundarySymbol = BoundarySymbol {
        language: BoundaryLanguage::new("javascript".to_owned()).expect("javascript"),
        kind: BoundarySymbolKind::Function,
        module: Some("host".to_owned()),
        name: "host_log".to_owned(),
        index: None,
        identity_source: BoundaryIdentitySource::BoundaryField,
    };
    let target: BoundarySymbol = BoundarySymbol {
        language: BoundaryLanguage::new("webassembly".to_owned()).expect("webassembly"),
        kind: BoundarySymbolKind::Function,
        module: None,
        name: "host_log".to_owned(),
        index: Some(0),
        identity_source: BoundaryIdentitySource::BoundaryField,
    };
    let evidence: BoundaryEvidence = BoundaryEvidence::WasmImport {
        module: "host".to_owned(),
        field: "host_log".to_owned(),
    };
    assert!(matches!(
        BoundaryLink::new(source, target, evidence, BoundaryConfidence::Low),
        Err(BoundaryLinksError::InconsistentEvidence { link_index: 0 })
    ));

    let mut link: serde_json::Value = valid_link_json();
    link["confidence"] = serde_json::Value::String("low".to_owned());
    let encoded: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": [link]
    }))
    .expect("encode sidecar");
    assert!(matches!(
        BoundaryLinks::from_json(&encoded),
        Err(BoundaryLinksError::InconsistentEvidence { link_index: 0 })
    ));
}

#[test]
fn parser_refuses_resources_above_the_combined_ceiling() {
    let resources: String = "(memory 0)".repeat(MAX_BOUNDARY_LINKS + 1);
    let bytes: Vec<u8> = wat::parse_str(format!("(module {resources})")).expect("module");
    assert!(extract_signatures(&bytes).is_err());
}

#[test]
fn parser_refuses_resource_export_aliases_above_the_link_ceiling() {
    let mut exports: String = String::new();
    for index in 0..=MAX_BOUNDARY_LINKS {
        write!(exports, "(export \"resource_{index}\" (memory 0))").expect("write export");
    }
    let bytes: Vec<u8> = wat::parse_str(format!("(module (memory 0) {exports})")).expect("module");
    assert!(extract_signatures(&bytes).is_err());
}

#[test]
fn indexed_reference_types_preserve_nullability_in_resource_evidence() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
            (type $node (struct))
            (type $shared_node (shared (struct)))
            (table 1 (ref null $node))
            (table shared 1 (ref null $shared_node))
            (table shared 1 (ref null (shared func)))
            (global (ref null (exact $node)) (ref.null $node))
            (export "nodes" (table 0))
            (export "shared_nodes" (table 1))
            (export "shared_functions" (table 2))
            (export "head" (global 0)))"#,
    )
    .expect("module");
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    assert!(
        signatures
            .boundary_relations()
            .iter()
            .any(|link: &BoundaryLink| {
                matches!(
                    &link.evidence,
                    BoundaryEvidence::ResourceExport {
                        resource_type: BoundaryWasmType::Table { element_type, .. },
                        ..
                    } if matches!(element_type, BoundaryWasmReferenceType::Indexed {
                        type_index: 0,
                        nullable: true,
                        exact: false,
                    })
                )
            })
    );
    assert!(
        signatures
            .boundary_relations()
            .iter()
            .any(|link: &BoundaryLink| {
                matches!(
                    &link.evidence,
                    BoundaryEvidence::ResourceExport {
                        resource_type: BoundaryWasmType::Table {
                            element_type: BoundaryWasmReferenceType::Abstract {
                                heap_type: BoundaryWasmAbstractHeapType::Func,
                                nullable: true,
                                shared: true,
                            },
                            shared: true,
                            maximum: None,
                            ..
                        },
                        ..
                    }
                )
            })
    );
    assert!(
        signatures
            .boundary_relations()
            .iter()
            .any(|link: &BoundaryLink| {
                matches!(
                    &link.evidence,
                    BoundaryEvidence::ResourceExport {
                        resource_type: BoundaryWasmType::Table { element_type, shared: true, .. },
                        ..
                    } if matches!(element_type, BoundaryWasmReferenceType::Indexed {
                        type_index: 1,
                        nullable: true,
                        exact: false,
                    })
                )
            })
    );
    assert!(
        signatures
            .boundary_relations()
            .iter()
            .any(|link: &BoundaryLink| {
                matches!(
                    &link.evidence,
                    BoundaryEvidence::ResourceExport {
                        resource_type: BoundaryWasmType::Global {
                            value_type: BoundaryWasmValueType::Reference(
                                BoundaryWasmReferenceType::Indexed {
                                    type_index: 0,
                                    nullable: true,
                                    exact: true,
                                }
                            ),
                            ..
                        },
                        ..
                    }
                )
            })
    );
}

#[test]
fn empty_resource_boundary_fields_retain_evidence_and_wasm_identity() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
            (import "" "" (memory 0))
            (memory 0)
            (export "" (memory 1)))"#,
    )
    .expect("module");
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let links: &[BoundaryLink] = signatures.boundary_relations();
    assert_eq!(links.len(), 2);
    assert!(links.iter().any(|link: &BoundaryLink| {
        matches!(
            &link.evidence,
            BoundaryEvidence::ResourceImport { module, field, .. }
                if module.is_empty() && field.is_empty()
        ) && link.target.name == "_"
    }));
    assert!(links.iter().any(|link: &BoundaryLink| {
        matches!(
            &link.evidence,
            BoundaryEvidence::ResourceExport { field, .. } if field.is_empty()
        ) && link.source.name == "_"
    }));
}

#[test]
fn sidecar_reader_rejects_semantically_invalid_resource_limits() {
    let mut link: serde_json::Value = valid_link_json();
    link["source"]["kind"] = serde_json::Value::String("memory".to_owned());
    link["target"]["kind"] = serde_json::Value::String("memory".to_owned());
    link["evidence"] = serde_json::json!({
        "kind": "resource_import",
        "module": "host",
        "field": "host_log",
        "index": 0,
        "resource_type": {
            "kind": "memory",
            "minimum": 2,
            "maximum": 1,
            "memory64": false,
            "shared": false
        }
    });
    let encoded: Vec<u8> = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "links": [link]
    }))
    .expect("encode sidecar");
    assert!(matches!(
        BoundaryLinks::from_json(&encoded),
        Err(BoundaryLinksError::InconsistentEvidence { link_index: 0 })
    ));
}

#[test]
fn sidecar_reader_rejects_wasmparser_resource_limit_invariants() {
    let invalid_memories: [serde_json::Value; 3] = [
        serde_json::json!({"minimum": 1, "memory64": false, "shared": false, "page_size_log2": 12}),
        serde_json::json!({"minimum": 65_537, "memory64": false, "shared": false}),
        serde_json::json!({"minimum": 1, "memory64": false, "shared": true}),
    ];
    for mut resource_type in invalid_memories {
        resource_type["kind"] = serde_json::Value::String("memory".to_owned());
        let mut link: serde_json::Value = valid_link_json();
        link["source"]["kind"] = serde_json::Value::String("memory".to_owned());
        link["target"]["kind"] = serde_json::Value::String("memory".to_owned());
        link["evidence"] = serde_json::json!({
            "kind": "resource_import", "module": "host", "field": "host_log", "index": 0,
            "resource_type": resource_type
        });
        let encoded: Vec<u8> =
            serde_json::to_vec(&serde_json::json!({"schema_version": 1, "links": [link]}))
                .expect("encode sidecar");
        assert!(matches!(
            BoundaryLinks::from_json(&encoded),
            Err(BoundaryLinksError::InconsistentEvidence { .. })
        ));
    }

    let mut link: serde_json::Value = valid_link_json();
    link["source"]["kind"] = serde_json::Value::String("table".to_owned());
    link["target"]["kind"] = serde_json::Value::String("table".to_owned());
    link["evidence"] = serde_json::json!({
        "kind": "resource_import", "module": "host", "field": "host_log", "index": 0,
        "resource_type": {"kind": "table", "element_type": "funcref", "minimum": 4_294_967_296u64, "table64": false, "shared": false}
    });
    let encoded: Vec<u8> =
        serde_json::to_vec(&serde_json::json!({"schema_version": 1, "links": [link]}))
            .expect("encode sidecar");
    assert!(matches!(
        BoundaryLinks::from_json(&encoded),
        Err(BoundaryLinksError::InconsistentEvidence { .. })
    ));

    let mut shared_link: serde_json::Value = valid_link_json();
    shared_link["source"]["kind"] = serde_json::Value::String("table".to_owned());
    shared_link["target"]["kind"] = serde_json::Value::String("table".to_owned());
    shared_link["evidence"] = serde_json::json!({
        "kind": "resource_import", "module": "host", "field": "host_log", "index": 0,
        "resource_type": {"kind": "table", "element_type": "funcref", "minimum": 0, "maximum": 1, "table64": false, "shared": true}
    });
    let encoded: Vec<u8> =
        serde_json::to_vec(&serde_json::json!({"schema_version": 1, "links": [shared_link]}))
            .expect("encode sidecar");
    assert!(matches!(
        BoundaryLinks::from_json(&encoded),
        Err(BoundaryLinksError::InconsistentEvidence { .. })
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

#[test]
fn non_function_boundary_links_preserve_evidence_and_confidence() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (import "host" "imported_memory" (memory 1 2))
          (import "host" "imported_table" (table 1 3 funcref))
          (import "host" "imported_global" (global i32))
          (memory $exported_memory 2 4)
          (table $exported_table 2 5 funcref)
          (global $exported_global (mut i64) (i64.const 0))
          (export "memory" (memory $exported_memory))
          (export "table" (table $exported_table))
          (export "global" (global $exported_global)))"#,
    )
    .expect("non-function boundary module");
    let stripped: Vec<u8> = strip_name_section(&bytes).expect("strip name section");

    for module in [&bytes, &stripped] {
        let signatures: ModuleSignatures = extract_signatures(module).expect("signatures");
        let links: &[BoundaryLink] = signatures.boundary_relations();
        assert_eq!(links.len(), 6);
        assert!(links.iter().all(|link: &BoundaryLink| {
            link.confidence() == BoundaryConfidence::Certain
                && link.confidence() == link.evidence.confidence()
        }));
        assert!(links.iter().any(|link: &BoundaryLink| {
            matches!(
                &link.evidence,
                BoundaryEvidence::ResourceImport {
                    module,
                    field,
                    index: 0,
                    resource_type: BoundaryWasmType::Memory {
                        minimum: 1,
                        maximum: Some(2),
                        memory64: false,
                        shared: false,
                        page_size_log2: None,
                    },
                } if module == "host" && field == "imported_memory"
            ) && link.source.kind == BoundarySymbolKind::Memory
                && link.target.kind == BoundarySymbolKind::Memory
        }));
        assert!(links.iter().any(|link: &BoundaryLink| {
            matches!(
                &link.evidence,
                BoundaryEvidence::ResourceImport {
                    module,
                    field,
                    index: 0,
                    resource_type: BoundaryWasmType::Table {
                        element_type,
                        minimum: 1,
                        maximum: Some(3),
                        table64: false,
                        shared: false,
                    },
                } if module == "host" && field == "imported_table"
                    && matches!(element_type, BoundaryWasmReferenceType::Abstract {
                        heap_type: BoundaryWasmAbstractHeapType::Func,
                        nullable: true,
                        shared: false,
                    })
            ) && link.source.kind == BoundarySymbolKind::Table
                && link.target.kind == BoundarySymbolKind::Table
        }));
        assert!(links.iter().any(|link: &BoundaryLink| {
            matches!(
                &link.evidence,
                BoundaryEvidence::ResourceImport {
                    module,
                    field,
                    index: 0,
                    resource_type: BoundaryWasmType::Global {
                        value_type,
                        mutable: false,
                        shared: false,
                    },
                } if module == "host" && field == "imported_global"
                    && *value_type == BoundaryWasmValueType::I32
            ) && link.source.kind == BoundarySymbolKind::Global
                && link.target.kind == BoundarySymbolKind::Global
        }));
        assert!(links.iter().any(|link: &BoundaryLink| {
            matches!(
                &link.evidence,
                BoundaryEvidence::ResourceExport {
                    field,
                    index: 1,
                    resource_type: BoundaryWasmType::Memory {
                        minimum: 2,
                        maximum: Some(4),
                        memory64: false,
                        shared: false,
                        page_size_log2: None,
                    },
                } if field == "memory"
            )
        }));
        assert!(links.iter().any(|link: &BoundaryLink| {
            matches!(
                &link.evidence,
                BoundaryEvidence::ResourceExport {
                    field,
                    index: 1,
                    resource_type: BoundaryWasmType::Table {
                        element_type,
                        minimum: 2,
                        maximum: Some(5),
                        table64: false,
                        shared: false,
                    },
                } if field == "table" && matches!(element_type, BoundaryWasmReferenceType::Abstract {
                    heap_type: BoundaryWasmAbstractHeapType::Func,
                    nullable: true,
                    shared: false,
                })
            )
        }));
        assert!(links.iter().any(|link: &BoundaryLink| {
            matches!(
                &link.evidence,
                BoundaryEvidence::ResourceExport {
                    field,
                    index: 1,
                    resource_type: BoundaryWasmType::Global {
                        value_type,
                        mutable: true,
                        shared: false,
                    },
                } if field == "global" && *value_type == BoundaryWasmValueType::I64
            )
        }));
        let encoded: Vec<u8> = signatures
            .boundary_links()
            .to_json()
            .expect("serialize boundary links");
        let decoded: BoundaryLinks = BoundaryLinks::from_json(&encoded).expect("read sidecar");
        assert_eq!(decoded.links(), links);
        assert_eq!(decoded.to_json().expect("re-serialize sidecar"), encoded);
    }
}

#[test]
fn resource_evidence_rejects_tampered_wasm_endpoint_names() {
    let import: BoundaryLink = BoundaryLink {
        source: BoundarySymbol {
            language: BoundaryLanguage::new("javascript".to_owned()).expect("javascript"),
            kind: BoundarySymbolKind::Memory,
            module: Some("host".to_owned()),
            name: "memory".to_owned(),
            index: None,
            identity_source: BoundaryIdentitySource::BoundaryField,
        },
        target: BoundarySymbol {
            language: BoundaryLanguage::new("webassembly".to_owned()).expect("webassembly"),
            kind: BoundarySymbolKind::Memory,
            module: None,
            name: "tampered".to_owned(),
            index: Some(0),
            identity_source: BoundaryIdentitySource::BoundaryField,
        },
        evidence: BoundaryEvidence::ResourceImport {
            module: "host".to_owned(),
            field: "memory".to_owned(),
            index: 0,
            resource_type: BoundaryWasmType::Memory {
                minimum: 1,
                maximum: None,
                memory64: false,
                shared: false,
                page_size_log2: None,
            },
        },
    };
    let export: BoundaryLink = BoundaryLink {
        source: BoundarySymbol {
            language: BoundaryLanguage::new("webassembly".to_owned()).expect("webassembly"),
            kind: BoundarySymbolKind::Global,
            module: None,
            name: "tampered".to_owned(),
            index: Some(0),
            identity_source: BoundaryIdentitySource::BoundaryField,
        },
        target: BoundarySymbol {
            language: BoundaryLanguage::new("javascript".to_owned()).expect("javascript"),
            kind: BoundarySymbolKind::Global,
            module: None,
            name: "state".to_owned(),
            index: None,
            identity_source: BoundaryIdentitySource::BoundaryField,
        },
        evidence: BoundaryEvidence::ResourceExport {
            field: "state".to_owned(),
            index: 0,
            resource_type: BoundaryWasmType::Global {
                value_type: BoundaryWasmValueType::I32,
                mutable: false,
                shared: false,
            },
        },
    };

    for link in [import, export] {
        assert!(matches!(
            BoundaryLinks::new(vec![link.clone()]),
            Err(BoundaryLinksError::InconsistentEvidence { link_index: 0 })
        ));
        let encoded: Vec<u8> = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "links": [link],
        }))
        .expect("encode tampered sidecar");
        assert!(matches!(
            BoundaryLinks::from_json(&encoded),
            Err(BoundaryLinksError::InconsistentEvidence { link_index: 0 })
        ));
    }
}
