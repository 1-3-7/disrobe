#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_wasm_deob::{
    FuncRefOpKind, FuncRefReport, LiftTarget, ModuleSourceLift, lift_module_source,
    scan_function_refs,
};
use wasmparser::{Parser, Payload, Validator, WasmFeatures};

const WAT_TYPED_CALL_REF: &str = r#"
    (module
      (type $ft (func (param i32) (result i32)))
      (func $square (param i32) (result i32)
        local.get 0
        local.get 0
        i32.mul)
      (func (export "go") (param i32) (result i32)
        local.get 0
        ref.func $square
        call_ref $ft))
"#;

const WAT_TAIL_CALL_REF: &str = r#"
    (module
      (type $ft (func (param i32) (result i32)))
      (func $square (param i32) (result i32)
        local.get 0
        local.get 0
        i32.mul)
      (func (export "go") (param i32) (result i32)
        local.get 0
        ref.func $square
        return_call_ref $ft))
"#;

const WAT_BR_ON_NULL: &str = r#"
    (module
      (type $ft (func))
      (func (export "go") (param (ref null $ft))
        block $b
          local.get 0
          br_on_null $b
          call_ref $ft
        end))
"#;

fn baked(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("the authored module assembles")
}

#[test]
fn detects_typed_function_refs_and_call_ref() {
    let bytes: Vec<u8> = baked(WAT_TYPED_CALL_REF);
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    assert!(report.kinds.contains_key(&FuncRefOpKind::CallRef));
    assert!(report.kinds.contains_key(&FuncRefOpKind::RefFunc));
    assert!(report.typed_function_ref_count >= 1usize);
}

#[test]
fn detects_return_call_ref_as_tail_call_ref() {
    let bytes: Vec<u8> = baked(WAT_TAIL_CALL_REF);
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    assert!(report.uses_tail_call_ref, "{report:?}");
}

#[test]
fn detects_br_on_null_family() {
    let bytes: Vec<u8> = baked(WAT_BR_ON_NULL);
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    assert!(report.uses_br_on_null_family);
}

#[test]
fn empty_module_is_empty() {
    let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    assert!(report.is_empty());
}

fn declared_memories_and_tables(bytes: &[u8]) -> (u32, u32) {
    let mut counts: (u32, u32) = (0, 0);
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.expect("the module parses") {
            Payload::MemorySection(reader) => counts.0 += reader.count(),
            Payload::TableSection(reader) => counts.1 += reader.count(),
            _ => {}
        }
    }
    counts
}

#[test]
fn lifted_wat_declares_only_the_memories_and_tables_of_the_input() {
    for (name, source) in [
        (
            "function_refs",
            include_str!("../../../corpus/wasm/wat/function_refs.wat"),
        ),
        ("tail_call_ref", WAT_TAIL_CALL_REF),
        ("br_on_null", WAT_BR_ON_NULL),
    ] {
        let original: Vec<u8> = baked(source);
        Validator::new_with_features(WasmFeatures::all())
            .validate_all(&original)
            .unwrap_or_else(|e| panic!("{name}: the authored module must validate: {e}"));
        let lifted: ModuleSourceLift =
            lift_module_source(&original, LiftTarget::Wat).expect("the module lifts");
        let recovered: Vec<u8> = wat::parse_str(&lifted.source).unwrap_or_else(|e| {
            panic!(
                "{name}: the lifted WAT must assemble: {e}\n{}",
                lifted.source
            )
        });
        Validator::new_with_features(WasmFeatures::all())
            .validate_all(&recovered)
            .unwrap_or_else(|e| {
                panic!(
                    "{name}: the lifted module must validate: {e}\n{}",
                    lifted.source
                )
            });
        assert_eq!(
            declared_memories_and_tables(&recovered),
            declared_memories_and_tables(&original),
            "{name}: the lift must not invent a memory or table:\n{}",
            lifted.source
        );
    }
}
