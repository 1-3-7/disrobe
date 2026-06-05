#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_core::recovery::ConfidenceTier;
use disrobe_llm_metadata::{ANNOTATION_SCHEMA, AnnotationError, AnnotationFile, SymbolAnnotation};
use serde_json::{Value as Json, json};

fn demo_file() -> AnnotationFile {
    let mut file: AnnotationFile = AnnotationFile::new("demo.py");
    file.push(SymbolAnnotation::new(
        "parse_header",
        "fn",
        "decodes the leading magic",
        ConfidenceTier::Semantic,
    ))
    .expect("single-line note must validate");
    file
}

#[test]
fn schema_const_is_stable() {
    assert_eq!(ANNOTATION_SCHEMA, "disrobe.annotations/v1");
}

#[test]
fn serde_round_trip_preserves_all_fields() {
    let file: AnnotationFile = demo_file();
    let wire: String = serde_json::to_string(&file).expect("serialize");
    let parsed: AnnotationFile = serde_json::from_str(&wire).expect("deserialize");

    assert_eq!(file, parsed);

    assert_eq!(parsed.schema, ANNOTATION_SCHEMA);
    assert_eq!(parsed.file, "demo.py");
    assert_eq!(parsed.annotations.len(), 1);

    let first: &SymbolAnnotation = &parsed.annotations[0];
    assert_eq!(first.symbol, "parse_header");
    assert_eq!(first.kind, "fn");
    assert_eq!(first.note, "decodes the leading magic");
    assert_eq!(first.confidence, ConfidenceTier::Semantic);
}

#[test]
fn confidence_serializes_kebab_case() {
    let tiers: [(ConfidenceTier, &str); 4] = [
        (ConfidenceTier::Exact, "exact"),
        (ConfidenceTier::Semantic, "semantic"),
        (ConfidenceTier::Partial, "partial"),
        (ConfidenceTier::Skeleton, "skeleton"),
    ];

    for (tier, expected) in tiers {
        let mut file: AnnotationFile = AnnotationFile::new("demo.py");
        file.push(SymbolAnnotation::new("s", "fn", "note", tier))
            .expect("valid note");
        let value: Json = serde_json::to_value(&file).expect("to_value");
        assert_eq!(value["annotations"][0]["confidence"], json!(expected));
    }
}

#[test]
fn schema_field_serializes() {
    let file: AnnotationFile = demo_file();
    let value: Json = serde_json::to_value(&file).expect("to_value");
    assert_eq!(value["schema"], json!("disrobe.annotations/v1"));
}

#[test]
fn single_line_note_ok() {
    let annotation: SymbolAnnotation =
        SymbolAnnotation::new("f", "fn", "one line", ConfidenceTier::Exact);
    assert_eq!(annotation.validate(), Ok(()));
}

#[test]
fn empty_note_ok() {
    let annotation: SymbolAnnotation = SymbolAnnotation::new("f", "fn", "", ConfidenceTier::Exact);
    assert_eq!(annotation.validate(), Ok(()));
}

#[test]
fn two_line_note_ok() {
    let annotation: SymbolAnnotation =
        SymbolAnnotation::new("f", "fn", "a\nb", ConfidenceTier::Exact);
    assert_eq!(annotation.validate(), Ok(()));
}

#[test]
fn three_line_note_rejected() {
    let annotation: SymbolAnnotation =
        SymbolAnnotation::new("widget", "fn", "a\nb\nc", ConfidenceTier::Exact);
    let err: AnnotationError = annotation.validate().expect_err("3 lines must reject");
    assert!(matches!(err, AnnotationError::NoteTooLong { found: 3, .. }));
    let AnnotationError::NoteTooLong { symbol, found } = err;
    assert_eq!(found, 3);
    assert_eq!(symbol, "widget");
}

#[test]
fn trailing_newline_counts() {
    let two: SymbolAnnotation = SymbolAnnotation::new("f", "fn", "a\n", ConfidenceTier::Exact);
    assert_eq!(two.validate(), Ok(()));

    let three: SymbolAnnotation = SymbolAnnotation::new("f", "fn", "a\nb\n", ConfidenceTier::Exact);
    let err: AnnotationError = three.validate().expect_err("trailing newline pushes to 3");
    let AnnotationError::NoteTooLong { found, .. } = err;
    assert_eq!(found, 3);
}

#[test]
fn push_rejects_long_note() {
    let mut file: AnnotationFile = AnnotationFile::new("demo.py");
    let err: AnnotationError = file
        .push(SymbolAnnotation::new(
            "f",
            "fn",
            "a\nb\nc",
            ConfidenceTier::Exact,
        ))
        .expect_err("push of 3-line note must reject");
    assert!(matches!(err, AnnotationError::NoteTooLong { found: 3, .. }));
    assert!(file.annotations.is_empty());
}

#[test]
fn file_validate_catches_deserialized_bad_note() {
    let wire: String = json!({
        "file": "demo.py",
        "annotations": [
            { "symbol": "g", "kind": "fn", "note": "a\nb\nc", "confidence": "partial" }
        ]
    })
    .to_string();

    let file: AnnotationFile = serde_json::from_str(&wire).expect("deserialize bad note");
    let err: AnnotationError = file.validate().expect_err("validate must catch bad note");
    let AnnotationError::NoteTooLong { found, .. } = err;
    assert_eq!(found, 3);
}
