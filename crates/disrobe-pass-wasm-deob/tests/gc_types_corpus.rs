#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_wasm_deob::{
    ArrayTypeRecord, GcFieldRecord, GcRefKind, GcStorageKind, GcTypeGraph, StructTypeRecord,
    recover_gc_types,
};

fn fixture_path(name: &str) -> PathBuf {
    let workspace_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();
    workspace_root.join("corpus/src/wasm/sources").join(name)
}

fn load_fixture(name: &str) -> Option<String> {
    let path: PathBuf = fixture_path(name);
    std::fs::read_to_string(&path).ok()
}

#[test]
fn recovers_struct_array_and_i31_from_corpus_fixture() {
    let Some(wat_src): Option<String> = load_fixture("gc_types.wat") else {
        eprintln!("skip: gc_types.wat fixture absent");
        return;
    };
    let bytes: Vec<u8> = wat::parse_str(&wat_src).expect("parse wat");
    let graph: GcTypeGraph = recover_gc_types(&bytes).expect("recover");

    assert_eq!(graph.struct_count(), 1, "expected one struct type");
    assert_eq!(graph.array_count(), 1, "expected one array type");

    let pt: &StructTypeRecord = graph.structs.values().next().expect("struct present");
    assert_eq!(pt.fields.len(), 2, "point has two fields");
    let x: &GcFieldRecord = pt.fields.get(&0).expect("field x");
    assert!(matches!(x.storage, GcStorageKind::I32));
    assert!(x.mutable, "x is mutable");
    let y: &GcFieldRecord = pt.fields.get(&1).expect("field y");
    assert!(!y.mutable, "y is immutable");

    let row: &ArrayTypeRecord = graph.arrays.values().next().expect("array present");
    assert!(matches!(row.element.storage, GcStorageKind::I32));
    assert!(row.element.mutable, "array element mutable");

    assert!(graph.observed_ref_kinds.contains(&GcRefKind::I31Ref));
    assert!(!graph.used_struct_types.is_empty(), "struct ops observed");
    assert!(!graph.used_array_types.is_empty(), "array ops observed");
}
