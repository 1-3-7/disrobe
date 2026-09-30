#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fmt::Write as _;

use disrobe_pass_wasm_deob::{
    FunctionSig, LiftResult, LiftTarget, ModuleSignatures, ModuleSourceLift, extract_signatures,
    lift_module_faithful_wat, lift_module_source, lift_module_to_wat,
    try_lift_function_from_module,
};
use wasmparser::{ExternalKind, FunctionBody, Parser, Payload};

const SHARED_FUNCTION_ALIASES: usize = 2049;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportEntry {
    name: String,
    kind: ExternalKind,
    index: u32,
}

fn alias_module() -> Vec<u8> {
    let mut source: String = String::from(
        r#"(module
  (import "env" "host" (func $host (param i32) (result i32)))
  (memory $mem 1)
  (table $tbl 1 funcref)
  (global $counter (mut i32) (i32.const 0))
  (func $internal_add (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.add)
  (func $internal_seven (result i32)
    i32.const 7)
  (export "add" (func $internal_add))
  (export "seven" (func $internal_seven))
  (export "memory" (memory $mem))
  (export "memory_alias" (memory $mem))
  (export "table" (table $tbl))
  (export "table_alias" (table $tbl))
  (export "counter" (global $counter))
  (export "counter_alias" (global $counter))
  (export "quote\"d" (func $internal_seven))
  (export "caf\c3\a9" (func $internal_seven))
"#,
    );
    for alias in 1..SHARED_FUNCTION_ALIASES {
        writeln!(source, "  (export \"add_{alias}\" (func $internal_add))").expect("write alias");
    }
    source.push_str("  (export \"seven_last\" (func $internal_seven)))\n");
    wat::parse_str(&source).expect("alias module assembles")
}

fn exports_of(bytes: &[u8]) -> Vec<ExportEntry> {
    let mut out: Vec<ExportEntry> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::ExportSection(reader) = payload.expect("module parses") {
            for export in reader {
                let export: wasmparser::Export<'_> = export.expect("export decodes");
                out.push(ExportEntry {
                    name: export.name.to_owned(),
                    kind: export.kind,
                    index: export.index,
                });
            }
        }
    }
    out
}

fn function_exports_of(bytes: &[u8]) -> Vec<ExportEntry> {
    exports_of(bytes)
        .into_iter()
        .filter(|entry: &ExportEntry| entry.kind == ExternalKind::Func)
        .collect()
}

fn reassembled_exports(tag: &str, wat_source: &str) -> Vec<ExportEntry> {
    let bytes: Vec<u8> = wat::parse_str(wat_source)
        .unwrap_or_else(|error| panic!("{tag}: recovered WAT does not assemble: {error}"));
    exports_of(&bytes)
}

fn assert_same_exports(tag: &str, recovered: &[ExportEntry], reference: &[ExportEntry]) {
    assert_eq!(
        recovered.len(),
        reference.len(),
        "{tag}: recovered {} exports, input has {}",
        recovered.len(),
        reference.len()
    );
    for (position, (got, want)) in recovered.iter().zip(reference).enumerate() {
        assert_eq!(got, want, "{tag}: export {position} differs");
    }
}

#[test]
fn reference_module_shares_one_function_across_2049_exports() {
    let reference: Vec<ExportEntry> = exports_of(&alias_module());
    let shared: usize = reference
        .iter()
        .filter(|entry: &&ExportEntry| entry.kind == ExternalKind::Func && entry.index == 1)
        .count();
    assert_eq!(shared, SHARED_FUNCTION_ALIASES);
}

#[test]
fn module_source_wat_keeps_every_export_alias_of_every_kind() {
    let bytes: Vec<u8> = alias_module();
    let lifted: ModuleSourceLift =
        lift_module_source(&bytes, LiftTarget::Wat).expect("module lifts to WAT");
    let recovered: Vec<ExportEntry> = reassembled_exports("module source", &lifted.source);
    assert_same_exports("module source", &recovered, &exports_of(&bytes));
}

#[test]
fn module_to_wat_keeps_every_function_export_alias() {
    let bytes: Vec<u8> = alias_module();
    let signatures: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let pairs: Vec<(FunctionBody<'_>, FunctionSig)> = Parser::new(0)
        .parse_all(&bytes)
        .filter_map(|payload| match payload.expect("module parses") {
            Payload::CodeSectionEntry(body) => Some(body),
            _ => None,
        })
        .zip(signatures.defined().iter().cloned())
        .collect();
    assert_eq!(pairs.len(), signatures.defined().len());
    let offset: u32 = u32::try_from(signatures.imported_function_count()).expect("import count");
    let wat_source: String = lift_module_to_wat(&pairs, offset);
    let recovered: Vec<ExportEntry> = reassembled_exports("module to wat", &wat_source);
    assert_same_exports("module to wat", &recovered, &function_exports_of(&bytes));
}

#[test]
fn single_function_wat_keeps_every_export_name_of_that_function() {
    let bytes: Vec<u8> = alias_module();
    let lifted: LiftResult =
        try_lift_function_from_module(&bytes, 0, LiftTarget::Wat).expect("function lifts");
    let recovered: Vec<ExportEntry> = reassembled_exports("single function", &lifted.pseudo_source);
    let reference: Vec<ExportEntry> = function_exports_of(&bytes)
        .into_iter()
        .filter(|entry: &ExportEntry| entry.index == 1)
        .map(|entry: ExportEntry| ExportEntry { index: 0, ..entry })
        .collect();
    assert_same_exports("single function", &recovered, &reference);
}

#[test]
fn faithful_wat_keeps_every_export_alias_of_every_kind() {
    let bytes: Vec<u8> = alias_module();
    let wat_source: String = lift_module_faithful_wat(&bytes).expect("faithful lift");
    let recovered: Vec<ExportEntry> = reassembled_exports("faithful", &wat_source);
    assert_same_exports("faithful", &recovered, &exports_of(&bytes));
}
