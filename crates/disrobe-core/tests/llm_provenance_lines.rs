#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_core::{
    ConfidenceTier, LineProvenance, MAX_NOTE_LINES, PROVENANCE_MAP_SCHEMA, ProvenanceMap,
    ProvenanceMapBuilder, ProvenanceMapError,
};

#[test]
fn schema_constant_is_v1() {
    assert_eq!(PROVENANCE_MAP_SCHEMA, "disrobe.provenance-map/v1");
    assert_eq!(MAX_NOTE_LINES, 2);
}

#[test]
fn built_map_carries_schema_const() {
    let builder: ProvenanceMapBuilder = ProvenanceMapBuilder::new("a.pyc", "0.10.0");
    let map: ProvenanceMap = builder.build();
    assert_eq!(map.schema, PROVENANCE_MAP_SCHEMA);
    assert_eq!(map.tool_version, "0.10.0");
    assert_eq!(map.file, "a.pyc");
    assert!(map.lines.is_empty());
}

#[test]
fn line_entry_fields_are_real_typed_values() {
    let entry: LineProvenance = LineProvenance::new(7, "py.disasm", ConfidenceTier::Semantic)
        .with_source_offset(42)
        .with_opcode_range(10, 18);
    let mut builder: ProvenanceMapBuilder = ProvenanceMapBuilder::new("m.pyc", "0.10.0");
    builder.push_line(entry).expect("valid entry pushes");
    let map: ProvenanceMap = builder.build();
    let e: &LineProvenance = &map.lines[0];
    assert_eq!(e.line, 7);
    assert_eq!(e.pass, "py.disasm");
    assert_eq!(e.source_offset, Some(42));
    assert_eq!(e.opcode_range, Some([10, 18]));
    assert_eq!(e.confidence, ConfidenceTier::Semantic);
    assert!(e.note.is_none());
}

#[test]
fn opcode_range_serializes_as_two_element_array() {
    let entry: LineProvenance =
        LineProvenance::new(7, "py.disasm", ConfidenceTier::Semantic).with_opcode_range(10, 18);
    let mut builder: ProvenanceMapBuilder = ProvenanceMapBuilder::new("m.pyc", "0.10.0");
    builder.push_line(entry).expect("valid entry pushes");
    let map: ProvenanceMap = builder.build();
    let value: serde_json::Value = serde_json::to_value(&map).expect("serialize map");
    let range: &serde_json::Value = &value["lines"][0]["opcode_range"];
    let array: &Vec<serde_json::Value> = range.as_array().expect("opcode_range is an array");
    assert_eq!(array.len(), 2);
    assert_eq!(array[0].as_u64(), Some(10));
    assert_eq!(array[1].as_u64(), Some(18));
    assert_eq!(value["lines"][0]["confidence"].as_str(), Some("semantic"));
}

#[test]
fn note_at_cap_is_accepted() {
    let two_lines: LineProvenance = LineProvenance::new(1, "p", ConfidenceTier::Partial)
        .with_note("line one\nline two")
        .expect("two-line note is accepted");
    assert_eq!(two_lines.note.as_deref(), Some("line one\nline two"));

    let trailing_newline: LineProvenance = LineProvenance::new(2, "p", ConfidenceTier::Partial)
        .with_note("a\nb\n")
        .expect("trailing-newline note counts two lines");
    assert_eq!(trailing_newline.note.as_deref(), Some("a\nb\n"));
}

#[test]
fn note_over_cap_is_rejected() {
    let err: ProvenanceMapError = LineProvenance::new(5, "p", ConfidenceTier::Partial)
        .with_note("a\nb\nc")
        .expect_err("three-line note must be rejected");
    assert_eq!(
        err,
        ProvenanceMapError::NoteTooManyLines { line: 5, found: 3 }
    );

    let hand_built: LineProvenance = LineProvenance {
        line: 9,
        pass: "p".to_owned(),
        source_offset: None,
        opcode_range: None,
        confidence: ConfidenceTier::Partial,
        note: Some("x\ny\nz".to_owned()),
    };
    let mut builder: ProvenanceMapBuilder = ProvenanceMapBuilder::new("m.pyc", "0.10.0");
    let push_err: ProvenanceMapError = builder
        .push_line(hand_built)
        .expect_err("builder defensively rejects over-cap note");
    assert_eq!(
        push_err,
        ProvenanceMapError::NoteTooManyLines { line: 9, found: 3 }
    );
}

#[test]
fn empty_note_normalizes_to_none() {
    let empty: LineProvenance = LineProvenance::new(1, "p", ConfidenceTier::Skeleton)
        .with_note("")
        .expect("empty note is accepted");
    assert!(empty.note.is_none());

    let whitespace: LineProvenance = LineProvenance::new(2, "p", ConfidenceTier::Skeleton)
        .with_note("   ")
        .expect("whitespace-only note is accepted");
    assert!(whitespace.note.is_none());
}

#[test]
fn map_serde_round_trip() {
    let with_note: LineProvenance = LineProvenance::new(3, "py.disasm", ConfidenceTier::Exact)
        .with_source_offset(8)
        .with_note("recovered from\nline table")
        .expect("two-line note");
    let with_range: LineProvenance =
        LineProvenance::new(11, "py.lift", ConfidenceTier::Semantic).with_opcode_range(20, 44);
    let mut builder: ProvenanceMapBuilder = ProvenanceMapBuilder::new("mod.pyc", "0.10.0");
    builder.push_line(with_note).expect("push note line");
    builder.push_line(with_range).expect("push range line");
    let original: ProvenanceMap = builder.build();

    let json: String = serde_json::to_string(&original).expect("serialize");
    let parsed: ProvenanceMap = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, original);
    assert_eq!(parsed.schema, PROVENANCE_MAP_SCHEMA);
}
