#![allow(clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;

use disrobe_pass_wasm_deob::{
    BoundaryEvidence, BoundaryIdentitySource, BoundaryLanguage, BoundaryNameConfidence,
    BoundaryNameEvidence, BoundaryNamePropagationError, BoundaryNameRecoveryStatus, BoundarySymbol,
    BoundarySymbolKind, MAX_BOUNDARY_LINK_STRING_BYTES, MAX_BOUNDARY_NAME_SEEDS, ModuleSignatures,
    RecoveredBoundaryName, extract_signatures, propagate_boundary_names,
};

const LINKED_NAMES: &str = r#"
(module
  (import "left" "a" (func $first (param i32)))
  (import "right" "b" (func $dispatch (param i32)))
  (export "a" (func $first)))
"#;

fn imported_source(signatures: &ModuleSignatures, module: &str) -> BoundarySymbol {
    signatures
        .boundary_relations()
        .iter()
        .find_map(|link| match &link.evidence {
            BoundaryEvidence::WasmImport {
                module: candidate, ..
            } if candidate == module => Some(link.source.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {module} import relation"))
}

fn wasm_name(names: &[RecoveredBoundaryName], index: u32) -> &RecoveredBoundaryName {
    names
        .iter()
        .find(|name| {
            name.symbol().language.as_str() == "webassembly" && name.symbol().index == Some(index)
        })
        .unwrap_or_else(|| panic!("missing propagated WASM name for index {index}"))
}

#[test]
fn caller_propagates_names_to_a_cycle_once_and_disambiguates_receiver_collisions() {
    let bytes: Vec<u8> = wat::parse_str(LINKED_NAMES).expect("linked module");
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let certain: RecoveredBoundaryName = RecoveredBoundaryName::seed(
        imported_source(&signatures, "left"),
        "dispatch".to_owned(),
        BoundaryNameConfidence::Certain,
        BoundaryNameEvidence::SourceMap { name_index: 7 },
    )
    .expect("certain seed");
    let arity_only: RecoveredBoundaryName = RecoveredBoundaryName::seed(
        imported_source(&signatures, "right"),
        "candidate".to_owned(),
        BoundaryNameConfidence::Low,
        BoundaryNameEvidence::MatchingArity {
            parameters: 1,
            results: 0,
        },
    )
    .expect("low-confidence seed");

    let first: Vec<RecoveredBoundaryName> =
        propagate_boundary_names(signatures.boundary_links(), &[certain, arity_only])
            .expect("first propagation");
    let second: Vec<RecoveredBoundaryName> =
        propagate_boundary_names(signatures.boundary_links(), &first).expect("second propagation");

    assert_eq!(first, second, "the fixed point must be idempotent");
    assert_eq!(
        first.len(),
        5,
        "two seeds must reach all five endpoints once"
    );
    let first_wasm: &RecoveredBoundaryName = wasm_name(&first, 0);
    assert_eq!(first_wasm.symbol().name, "first", "original identifier");
    assert_eq!(first_wasm.name(), "dispatch_2", "collision-safe alias");
    assert_eq!(first_wasm.confidence(), BoundaryNameConfidence::Certain);
    let second_wasm: &RecoveredBoundaryName = wasm_name(&first, 1);
    assert_eq!(second_wasm.symbol().name, "dispatch", "existing identifier");
    assert_eq!(second_wasm.name(), "candidate");
    assert_eq!(second_wasm.confidence(), BoundaryNameConfidence::Low);
    let javascript_export: &RecoveredBoundaryName = first
        .iter()
        .find(|name| {
            name.symbol().language.as_str() == "javascript"
                && name.symbol().module.is_none()
                && name.symbol().name == "a"
        })
        .expect("transitive JavaScript export name");
    assert_eq!(javascript_export.name(), "dispatch");
    assert_eq!(javascript_export.link_path().len(), 2);
    assert!(first.iter().all(|name| {
        name.link_path()
            .iter()
            .all(|index| *index < signatures.boundary_relations().len())
    }));
    assert_eq!(
        first
            .iter()
            .filter(|name| name.link_path().is_empty())
            .count(),
        2,
        "only evidence-bearing input names are fixed-point roots"
    );
}

#[test]
fn arity_only_and_resource_limit_violations_are_typed_refusals() {
    let bytes: Vec<u8> = wat::parse_str(LINKED_NAMES).expect("linked module");
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let symbol: BoundarySymbol = imported_source(&signatures, "left");
    let certain_arity: Result<RecoveredBoundaryName, BoundaryNamePropagationError> =
        RecoveredBoundaryName::seed(
            symbol.clone(),
            "unsupported".to_owned(),
            BoundaryNameConfidence::Certain,
            BoundaryNameEvidence::MatchingArity {
                parameters: 1,
                results: 0,
            },
        );
    assert!(matches!(
        certain_arity,
        Err(BoundaryNamePropagationError::CertainArityOnly)
    ));
    let oversized: Result<RecoveredBoundaryName, BoundaryNamePropagationError> =
        RecoveredBoundaryName::seed(
            symbol.clone(),
            "x".repeat(MAX_BOUNDARY_LINK_STRING_BYTES + 1),
            BoundaryNameConfidence::Low,
            BoundaryNameEvidence::MatchingArity {
                parameters: 1,
                results: 0,
            },
        );
    assert!(matches!(
        oversized,
        Err(BoundaryNamePropagationError::NameTooLong { .. })
    ));
    let seed: RecoveredBoundaryName = RecoveredBoundaryName::seed(
        symbol,
        "bounded".to_owned(),
        BoundaryNameConfidence::Low,
        BoundaryNameEvidence::MatchingArity {
            parameters: 1,
            results: 0,
        },
    )
    .expect("bounded seed");
    let too_many: Vec<RecoveredBoundaryName> =
        vec![seed; MAX_BOUNDARY_NAME_SEEDS.saturating_add(1)];
    let result: Result<Vec<RecoveredBoundaryName>, BoundaryNamePropagationError> =
        propagate_boundary_names(signatures.boundary_links(), &too_many);
    assert!(matches!(
        result,
        Err(BoundaryNamePropagationError::TooManyNames { .. })
    ));

    let unlinked: BoundarySymbol = BoundarySymbol {
        language: BoundaryLanguage::new("javascript".to_owned()).expect("language"),
        kind: BoundarySymbolKind::Function,
        module: Some("missing".to_owned()),
        name: "missing".to_owned(),
        index: None,
        identity_source: BoundaryIdentitySource::BoundaryField,
    };
    let unlinked_seed: RecoveredBoundaryName = RecoveredBoundaryName::seed(
        unlinked,
        "named".to_owned(),
        BoundaryNameConfidence::Certain,
        BoundaryNameEvidence::SourceMap { name_index: 0 },
    )
    .expect("unlinked seed construction");
    let unlinked_result: Result<Vec<RecoveredBoundaryName>, BoundaryNamePropagationError> =
        propagate_boundary_names(signatures.boundary_links(), &[unlinked_seed]);
    assert!(matches!(
        unlinked_result,
        Err(BoundaryNamePropagationError::UnknownSeedSymbol { .. })
    ));
}

#[test]
fn signature_extraction_propagates_trusted_boundary_names_deterministically() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (import "host" "receiver" (func $dispatch))
          (import "host" "dispatch" (func $other)))"#,
    )
    .expect("named export module");

    let first: ModuleSignatures = extract_signatures(&bytes).expect("first extraction");
    let second: ModuleSignatures = extract_signatures(&bytes).expect("second extraction");

    assert_eq!(
        first.boundary_name_recovery_status(),
        &BoundaryNameRecoveryStatus::Complete
    );
    assert_eq!(
        first.recovered_boundary_names(),
        second.recovered_boundary_names()
    );
    assert_eq!(
        first.boundary_name_recovery_status(),
        second.boundary_name_recovery_status()
    );
    let javascript: &RecoveredBoundaryName = first
        .recovered_boundary_names()
        .iter()
        .find(|name: &&RecoveredBoundaryName| {
            name.symbol().language.as_str() == "javascript" && name.symbol().name == "receiver"
        })
        .expect("propagated JavaScript name");
    assert_eq!(javascript.symbol().name, "receiver");
    assert_eq!(javascript.name(), "dispatch_2");
    assert_eq!(javascript.confidence(), BoundaryNameConfidence::Certain);
    assert!(matches!(
        javascript.evidence(),
        BoundaryNameEvidence::NameSection { function_index: 0 }
    ));
}

#[test]
fn signature_extraction_emits_no_names_without_boundary_evidence() {
    let bytes: Vec<u8> = wat::parse_str("(module (func $hidden))").expect("internal named module");
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");

    assert!(signatures.recovered_boundary_names().is_empty());
    assert_eq!(
        signatures.boundary_name_recovery_status(),
        &BoundaryNameRecoveryStatus::Complete
    );
}

#[test]
fn signature_extraction_reports_deterministic_root_truncation() {
    let mut wat: String = "(module".to_owned();
    for index in 0..=MAX_BOUNDARY_NAME_SEEDS {
        write!(
            wat,
            " (import \"host\" \"field_{index}\" (func $trusted_{index}))"
        )
        .expect("write WAT import");
    }
    wat.push(')');
    let bytes: Vec<u8> = wat::parse_str(&wat).expect("large named import module");

    let first: ModuleSignatures = extract_signatures(&bytes).expect("first extraction");
    let second: ModuleSignatures = extract_signatures(&bytes).expect("second extraction");

    assert_eq!(
        first.boundary_name_recovery_status(),
        &BoundaryNameRecoveryStatus::Truncated {
            root_count: MAX_BOUNDARY_NAME_SEEDS + 1,
            retained_root_count: MAX_BOUNDARY_NAME_SEEDS,
        }
    );
    assert_eq!(
        first.recovered_boundary_names(),
        second.recovered_boundary_names()
    );
    assert_eq!(
        first.recovered_boundary_names().len(),
        MAX_BOUNDARY_NAME_SEEDS * 2
    );
}
