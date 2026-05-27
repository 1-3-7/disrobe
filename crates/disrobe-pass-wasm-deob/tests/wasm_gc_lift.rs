#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{
    GcHirModule, GcHirStruct, GcTypeGraph, lift_gc_module, recover_gc_types,
};

const GC_WAT: &str = r#"
    (module
      (type $point (struct (field $x (mut i32)) (field $y i32)))
      (type $row (array (mut i32)))
      (func (export "make_pt") (result (ref $point))
        i32.const 1 i32.const 2 struct.new $point)
      (func (export "make_row") (result (ref $row))
        i32.const 7 i32.const 3 array.new $row)
      (func (export "i31") (result (ref i31))
        i32.const 42 ref.i31))
"#;

#[test]
fn full_lift_round_trip_to_typed_rust_struct_and_array() {
    let bytes: Vec<u8> = wat::parse_str(GC_WAT).expect("parse wat");
    let graph: GcTypeGraph = recover_gc_types(&bytes).expect("graph");
    let hir: GcHirModule = lift_gc_module(&graph);

    assert_eq!(hir.structs.len(), 1, "one struct");
    assert_eq!(hir.arrays.len(), 1, "one array");
    let s: &GcHirStruct = hir.structs.values().next().expect("struct");
    assert_eq!(s.fields.len(), 2);
    assert!(s.fields[0].mutable, "field x mut");
    assert!(!s.fields[1].mutable, "field y immut");

    let rust: &str = hir.rust_source.as_str();
    assert!(rust.contains("pub struct Struct0"));
    assert!(rust.contains("pub f0: i32"));
    assert!(rust.contains("pub f1: i32"));
    assert!(rust.contains("pub struct Array1(pub Vec<i32>);"));

    let ts: &str = hir.ts_source.as_str();
    assert!(ts.contains("export interface Struct0"));
    assert!(ts.contains("readonly f1: number"));
    assert!(ts.contains("export type Array1"));
}

#[test]
fn empty_module_yields_empty_hir() {
    let bytes: Vec<u8> = wat::parse_str("(module)").expect("parse");
    let graph: GcTypeGraph = recover_gc_types(&bytes).expect("graph");
    let hir: GcHirModule = lift_gc_module(&graph);
    assert!(hir.is_empty());
}
