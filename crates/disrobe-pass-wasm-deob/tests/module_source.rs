#![allow(clippy::expect_used)]

use disrobe_pass_wasm_deob::{
    DEFAULT_MODULE_SOURCE_LIMIT_BYTES, Error, LiftTarget, lift_module_source,
    lift_module_source_with_limit, try_lift_typescript_module,
};

const SIMPLE_MODULE: &str = "(module (func (export \"answer\") (result i32) i32.const 42))";

const SHARED_MODULE: &str = r#"
(module
  (memory (export "memory") 1 1 shared)
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.atomic.rmw.add)
  (func (export "wait") (param i32 i32 i64) (result i32)
    local.get 0
    local.get 1
    local.get 2
    memory.atomic.wait32)
  (func (export "notify") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    memory.atomic.notify)
  (func (export "fence") atomic.fence))
"#;

#[test]
fn module_source_assembles_every_public_target() {
    let bytes: Vec<u8> = wat::parse_str(SIMPLE_MODULE).expect("assemble module");
    for (target, name) in [
        (LiftTarget::Rust, "rust"),
        (LiftTarget::TypeScript, "typescript"),
        (LiftTarget::C, "c"),
        (LiftTarget::Wat, "wat"),
    ] {
        let report = lift_module_source(&bytes, target).expect("module lifts");
        assert_eq!(report.target, name);
        assert_eq!(report.functions_emitted, 1);
        assert!(!report.source.is_empty());
        assert_eq!(report.coverage.total_ops, report.coverage.translated_ops);
        assert!(report.coverage.untranslated.is_empty());
    }
}

#[test]
fn module_source_limit_is_exact_for_every_public_target() {
    let bytes: Vec<u8> = wat::parse_str(SIMPLE_MODULE).expect("assemble module");
    for target in [
        LiftTarget::Rust,
        LiftTarget::TypeScript,
        LiftTarget::C,
        LiftTarget::Wat,
    ] {
        let expected = lift_module_source(&bytes, target).expect("module lifts");
        let exact = lift_module_source_with_limit(&bytes, target, expected.source.len())
            .expect("exact source limit accepts output");
        assert_eq!(exact.source, expected.source);
        let limit: usize = expected.source.len().saturating_sub(1);
        assert!(matches!(
            lift_module_source_with_limit(&bytes, target, limit),
            Err(Error::ModuleSourceLimit { actual, limit: rejected_limit })
                if actual == expected.source.len() && rejected_limit == limit
        ));
    }
}

#[test]
fn module_source_limit_rejects_oversized_input_before_parsing() {
    let bytes: Vec<u8> = wat::parse_str(SIMPLE_MODULE).expect("assemble module");
    let limit: usize = bytes.len().saturating_sub(1);
    assert!(matches!(
        lift_module_source_with_limit(&bytes, LiftTarget::Rust, limit),
        Err(Error::ModuleInputLimit { actual, limit: rejected_limit })
            if actual == bytes.len() && rejected_limit == limit
    ));
}

#[test]
fn shared_typescript_compatibility_lift_rejects_oversized_input_before_parsing() {
    let mut bytes: Vec<u8> = wat::parse_str(SHARED_MODULE).expect("assemble shared module");
    bytes.resize(DEFAULT_MODULE_SOURCE_LIMIT_BYTES + 1, 0);

    assert!(matches!(
        try_lift_typescript_module(&bytes),
        Err(Error::ModuleInputLimit { actual, limit })
            if actual == bytes.len() && limit == DEFAULT_MODULE_SOURCE_LIMIT_BYTES
    ));
}

#[test]
fn module_source_limit_stops_wat_and_shared_typescript_before_full_assembly() {
    for (wat, target) in [
        (SIMPLE_MODULE, LiftTarget::Wat),
        (SHARED_MODULE, LiftTarget::TypeScript),
    ] {
        let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble module");
        let complete = lift_module_source(&bytes, target).expect("module lifts");
        let limit: usize = bytes.len();
        assert!(matches!(
            lift_module_source_with_limit(&bytes, target, limit),
            Err(Error::ModuleSourceLimit { actual, limit: rejected_limit })
                if actual > rejected_limit
                    && actual < complete.source.len()
                    && rejected_limit == limit
        ));
    }
}

#[test]
fn shared_typescript_limit_stops_before_a_precharged_function_segment() {
    let bytes: Vec<u8> = wat::parse_str(SHARED_MODULE).expect("assemble shared module");
    let complete = lift_module_source(&bytes, LiftTarget::TypeScript).expect("shared module lifts");
    let function_start: usize = complete
        .source
        .find("  function disrobeWasmFunction0")
        .expect("lifted function is present");
    let function_end: usize = complete
        .source
        .find("  return { memory")
        .expect("instance return is present");
    let function_block: &str = complete
        .source
        .get(function_start..function_end)
        .expect("function block range is valid");
    let indentation_bytes: usize = function_block
        .split_inclusive('\n')
        .count()
        .checked_mul(2)
        .expect("function indentation count fits");
    let precharged_bytes: usize = function_block
        .len()
        .checked_sub(indentation_bytes)
        .expect("function block contains indentation");
    let limit: usize = precharged_bytes
        .checked_add(function_start)
        .and_then(|total: usize| total.checked_add(1))
        .expect("shared module budget fits");
    assert!(matches!(
        lift_module_source_with_limit(&bytes, LiftTarget::TypeScript, limit),
        Err(Error::ModuleSourceLimit { actual, limit: rejected_limit })
            if actual == limit + 1
                && actual < complete.source.len()
                && rejected_limit == limit
    ));
}

#[test]
fn module_source_limit_accounts_for_untranslated_coverage_bytes() {
    let mut bytes: Vec<u8> = wat::parse_str(SIMPLE_MODULE).expect("assemble module");
    let final_byte: &mut u8 = bytes.last_mut().expect("module has a function terminator");
    *final_byte = 0xff;
    let complete = lift_module_source(&bytes, LiftTarget::Rust).expect("fallback module lifts");
    assert!(!complete.coverage.untranslated.is_empty());
    let coverage_bytes: usize = complete.coverage.untranslated.iter().map(String::len).sum();
    let limit: usize = complete
        .source
        .len()
        .checked_add(coverage_bytes)
        .and_then(|total: usize| total.checked_sub(1))
        .expect("fallback output has coverage bytes");
    assert!(matches!(
        lift_module_source_with_limit(&bytes, LiftTarget::Rust, limit),
        Err(Error::ModuleSourceLimit { actual, limit: rejected_limit })
            if actual > rejected_limit && rejected_limit == limit
    ));
}

#[test]
fn shared_typescript_source_uses_the_instance_owned_atomic_runtime() {
    let bytes: Vec<u8> = wat::parse_str(SHARED_MODULE).expect("assemble shared module");
    let report = lift_module_source(&bytes, LiftTarget::TypeScript).expect("shared module lifts");
    assert_eq!(report.functions_emitted, 4);
    assert!(report.source.contains("export const instantiate"));
    assert!(report.source.contains("new WebAssembly.Memory"));
    assert!(report.source.contains("SharedArrayBuffer"));
    assert!(report.source.contains("Atomics.add"));
    assert!(report.source.contains("Atomics.wait"));
    assert!(report.source.contains("Atomics.notify"));
    assert!(report.source.contains("wasmAtomicFence"));
    assert!(report.coverage.fully_recovered());
}
