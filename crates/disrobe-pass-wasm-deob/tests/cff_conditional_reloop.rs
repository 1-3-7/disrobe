#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
#[cfg(feature = "chain")]
use disrobe_pass_wasm_deob::chain_detector::WASM_DEOB_PASS;
use disrobe_pass_wasm_deob::{RecoveredModule, recover_module};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

const FUEL_BUDGET: u64 = 20_000_000;

fn real_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/wasm/obf/real")
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn assemble_path(path: PathBuf, hint: Option<&str>) -> Vec<u8> {
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e: std::io::Error| {
        hint.map_or_else(
            || panic!("read {}: {e}", path.display()),
            |hint: &str| panic!("read {}: {e}\n{hint}", path.display()),
        )
    });
    wat::parse_str(&text).unwrap_or_else(|e| panic!("assemble {}: {e}", path.display()))
}

fn assemble(name: &str) -> Vec<u8> {
    assemble_path(
        real_dir().join(name),
        Some("run corpus/wasm/obf/build.sh to produce the real toolchain wat"),
    )
}

fn assemble_fixture(name: &str) -> Vec<u8> {
    assemble_path(fixture_dir().join(name), None)
}

fn engine() -> Engine {
    let mut config: Config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config).expect("engine")
}

struct Inst {
    store: Store<()>,
    instance: wasmtime::Instance,
}

fn instantiate(eng: &Engine, bytes: &[u8]) -> Inst {
    let module: Module = Module::new(eng, bytes).expect("module compiles");
    let mut store: Store<()> = Store::new(eng, ());
    store.set_fuel(FUEL_BUDGET).expect("fuel");
    let mut linker: Linker<()> = Linker::new(eng);
    linker
        .define_unknown_imports_as_traps(&module)
        .expect("trap imports");
    let instance: wasmtime::Instance = linker.instantiate(&mut store, &module).expect("instance");
    Inst { store, instance }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ret(i32),
    Trap,
}

fn call_i32(inst: &mut Inst, export: &str, arg: i32) -> Outcome {
    let func: wasmtime::Func = match inst.instance.get_func(&mut inst.store, export) {
        Some(f) => f,
        None => return Outcome::Trap,
    };
    let mut results: [Val; 1] = [Val::I32(0)];
    inst.store.set_fuel(FUEL_BUDGET).ok();
    if func
        .call(&mut inst.store, &[Val::I32(arg)], &mut results)
        .is_err()
    {
        return Outcome::Trap;
    }
    match results[0] {
        Val::I32(v) => Outcome::Ret(v),
        _ => Outcome::Trap,
    }
}

fn battery() -> Vec<i32> {
    vec![
        -1000, -100, -5, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 20, 63, 100, 257, 1000,
    ]
}

fn assert_equivalent(reference: &mut Inst, candidate: &mut Inst, export: &str) {
    for arg in battery() {
        let want: Outcome = call_i32(reference, export, arg);
        let got: Outcome = call_i32(candidate, export, arg);
        assert_eq!(
            got, want,
            "export `{export}` diverged on {arg}: reference={want:?} candidate={got:?}"
        );
    }
}

fn assert_distinguished(reference: &mut Inst, candidate: &mut Inst, export: &str) {
    let distinguished: bool = battery()
        .into_iter()
        .any(|arg: i32| call_i32(reference, export, arg) != call_i32(candidate, export, arg));
    assert!(
        distinguished,
        "the runtime battery must reject a conditional-transition mutation for `{export}`"
    );
}

struct CondCase {
    clean: &'static str,
    obf: &'static str,
    export: &'static str,
}

fn cond_cases() -> Vec<CondCase> {
    vec![
        CondCase {
            clean: "cff_cond_diamond.clean.wat",
            obf: "cff_cond_diamond.obf.wat",
            export: "classify",
        },
        CondCase {
            clean: "cff_cond_loop.clean.wat",
            obf: "cff_cond_loop.obf.wat",
            export: "accumulate",
        },
    ]
}

fn assert_reloops_to_clean_behavior(
    clean_bytes: &[u8],
    obf_bytes: &[u8],
    export: &str,
    name: &str,
) {
    let eng: Engine = engine();

    let mut clean_pre: Inst = instantiate(&eng, clean_bytes);
    let mut obf_pre: Inst = instantiate(&eng, obf_bytes);
    assert_equivalent(&mut clean_pre, &mut obf_pre, export);

    let recovered: RecoveredModule =
        recover_module(obf_bytes).unwrap_or_else(|e| panic!("recover {name}: {e}"));

    assert!(
        recovered.report.flattened_conditional_restructured >= 1,
        "CFF dispatcher must reloop {name}: {:?}",
        recovered.report
    );
    assert!(
        wasmparser::validate(&recovered.bytes).is_ok(),
        "recovered {name} must validate"
    );
    assert!(
        !contains_br_table(&recovered.bytes),
        "recovered {name} must remove the br_table dispatcher"
    );

    let mut clean_inst: Inst = instantiate(&eng, clean_bytes);
    let mut recovered_inst: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut clean_inst, &mut recovered_inst, export);
}

#[test]
fn conditional_cff_reloops_to_clean_behavior_under_wasmtime() {
    for case in cond_cases() {
        let clean_bytes: Vec<u8> = assemble(case.clean);
        let obf_bytes: Vec<u8> = assemble(case.obf);
        assert_reloops_to_clean_behavior(&clean_bytes, &obf_bytes, case.export, case.obf);
    }
}

#[test]
#[cfg(feature = "chain")]
fn nested_dispatch_loops_reloop_inner_first_under_wasmtime() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_nested_dispatch.clean.wat");
    let obf_bytes: Vec<u8> = assemble_fixture("cff_nested_dispatch.obf.wat");
    let mutant_bytes: Vec<u8> = assemble_fixture("cff_nested_dispatch.mutant.wat");
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut obfuscated: Inst = instantiate(&eng, &obf_bytes);
    assert_equivalent(&mut clean, &mut obfuscated, "nested_dispatch");
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut mutant: Inst = instantiate(&eng, &mutant_bytes);
    assert_distinguished(&mut clean, &mut mutant, "nested_dispatch");

    let recovered: RecoveredModule =
        recover_module(&obf_bytes).expect("recover nested dispatch loops");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 2,
        "both nested dispatchers must be reported: {:?}",
        recovered.report
    );
    assert!(
        !contains_br_table(&recovered.bytes),
        "both nested br_table dispatchers must be removed"
    );
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut recovered: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut clean, &mut recovered, "nested_dispatch");

    let input: Artifact = Artifact::new(Rung::Raw, obf_bytes, [0x25; 32]);
    let surfaced: Artifact = WASM_DEOB_PASS
        .run(&input)
        .expect("registered wasm pass must surface nested dispatch recovery");
    assert_eq!(surfaced.rung, Rung::Surface);
    let source: &str = std::str::from_utf8(&surfaced.envelope).expect("surface WAT is UTF-8");
    assert!(source.contains("(module"));
    assert!(!source.contains("br_table"));
}

#[test]
fn nested_dispatch_refusals_preserve_ancestor_reads_and_loop_branch_semantics() {
    let fixture: String =
        std::fs::read_to_string(fixture_dir().join("cff_nested_dispatch.obf.wat"))
            .expect("read nested dispatcher fixture");
    let module_prefix: &str = fixture
        .strip_suffix(")\n")
        .expect("fixture module terminator");
    let source: String = format!(
        r#"{module_prefix}
  (func (export "observe_nested_state") (result i32)
    (local i32)
    block $root
      i32.const 0
      local.set 0
      loop $dispatch
        block $default
          block $case3
            block $case2
              block $case1
                block $case0
                  local.get 0
                  br_table $case0 $case1 $case2 $case3
                end
                i32.const 1
                local.set 0
                br $default
              end
              i32.const 3
              local.set 0
              br $default
            end
            i32.const 3
            local.set 0
            br $default
          end
          br $root
        end
        br $dispatch
      end
    end
    local.get 0)
  (func
    (local i32)
    loop $candidate
      i32.const 0
      local.set 0
      loop $dispatch
        block $default
          block $case3
            block $case2
              block $case1
                block $case0
                  local.get 0
                  br_table $case0 $case1 $case2 $case3
                end
                i32.const 1
                local.set 0
                br $default
              end
              i32.const 3
              local.set 0
              br $default
            end
            i32.const 3
            local.set 0
            br $default
          end
          br $candidate
        end
        br $dispatch
      end
    end)
)"#
    );
    let bytes: Vec<u8> = wat::parse_str(&source).expect("assemble mixed nested dispatchers");
    let recovered: RecoveredModule = recover_module(&bytes).expect("recover mixed dispatchers");

    assert_eq!(recovered.report.flattened_conditional_restructured, 2);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 2);
    assert_eq!(count_br_tables(&recovered.bytes), 2);
    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_eq!(
        call_no_args(&mut original, "observe_nested_state"),
        call_no_args(&mut candidate, "observe_nested_state")
    );
}

#[test]
fn clang_select_transition_reloops_through_the_public_recovery_api() {
    let clean_bytes: &[u8] = include_bytes!("fixtures/cff_cond_select.clean.wasm");
    let obf_bytes: &[u8] = include_bytes!("fixtures/cff_cond_select.obf.wasm");
    assert_reloops_to_clean_behavior(
        clean_bytes,
        obf_bytes,
        "classify_select",
        "cff_cond_select.obf.wasm",
    );
}

#[test]
fn arithmetic_select_successors_reloop_under_wasmtime() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    let obf_bytes: Vec<u8> = computed_select_state_variant(false);
    assert_reloops_to_clean_behavior(
        &clean_bytes,
        &obf_bytes,
        "classify_local",
        "computed select successors",
    );
}

#[test]
fn runtime_differential_rejects_swapped_arithmetic_select_successors() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    let mutant_bytes: Vec<u8> = computed_select_state_variant(true);
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut mutant: Inst = instantiate(&eng, &mutant_bytes);
    assert_distinguished(&mut clean, &mut mutant, "classify_local");
}

#[test]
fn effectful_select_successor_expression_remains_walled() {
    let mut source: String = computed_select_state_source(
        "call 1",
        "i32.const 1\n              i32.const 1\n              i32.add",
    );
    let module_end: usize = source.rfind(')').expect("module terminator");
    source.insert_str(module_end, "  (func (result i32) i32.const 1)\n");
    let bytes: Vec<u8> = wat::parse_str(&source).expect("assemble effectful select state");
    let recovered: RecoveredModule = recover_module(&bytes).expect("recover effectful select");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
}

#[test]
fn runtime_differential_rejects_swapped_select_successors() {
    let clean_bytes: &[u8] = include_bytes!("fixtures/cff_cond_select.clean.wasm");
    let mutant_bytes: &[u8] = include_bytes!("fixtures/cff_cond_select.mutant.wasm");
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, clean_bytes);
    let mut mutant: Inst = instantiate(&eng, mutant_bytes);
    assert_distinguished(&mut clean, &mut mutant, "classify_select");
}

#[test]
fn select_transition_that_consumes_candidate_values_remains_walled() {
    let bytes: Vec<u8> = assemble_fixture("cff_select_stack_alias.obf.wat");
    let recovered: RecoveredModule = recover_module(&bytes).expect("recover bounded stack alias");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
}

fn assert_fixture_reloops(clean: &str, obf: &str, export: &str) {
    let clean_bytes: Vec<u8> = assemble_fixture(clean);
    let obf_bytes: Vec<u8> = assemble_fixture(obf);
    assert_reloops_to_clean_behavior(&clean_bytes, &obf_bytes, export, obf);
}

#[test]
fn state_held_in_a_local_reloops_under_wasmtime() {
    assert_fixture_reloops(
        "cff_local_state.clean.wat",
        "cff_local_state.obf.wat",
        "classify_local",
    );
}

#[test]
fn constant_arithmetic_state_updates_reloop_under_wasmtime() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    let obf_bytes: Vec<u8> = assemble_fixture("cff_computed_state.obf.wat");
    assert_reloops_to_clean_behavior(
        &clean_bytes,
        &obf_bytes,
        "classify_local",
        "cff_computed_state.obf.wat",
    );

    let recovered: RecoveredModule = recover_module(&obf_bytes).expect("recover computed state");
    assert!(!contains_computed_state_binop(&recovered.bytes));
}

#[test]
fn wrapping_and_masked_shift_state_updates_reloop_under_wasmtime() {
    let overflow: Vec<u8> = computed_state_variant(
        "i32.const 2147483647\n            i32.const 1\n            i32.add\n            i32.const -2147483645\n            i32.add",
    );
    let shifted: Vec<u8> = computed_state_variant(
        "i32.const 1\n            i32.const 33\n            i32.shl\n            i32.const 1\n            i32.or",
    );
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    assert_reloops_to_clean_behavior(&clean_bytes, &overflow, "classify_local", "wrapping state");
    assert_reloops_to_clean_behavior(&clean_bytes, &shifted, "classify_local", "shifted state");
}

#[test]
fn observed_entry_state_write_is_preserved_when_relooping() {
    let path: PathBuf = fixture_dir().join("cff_computed_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read computed-state fixture");
    let original: &str = "i32.const 5\n    i32.const 5\n    i32.xor\n    local.set 2";
    let replacement: &str = concat!(
        "i32.const 5\n    i32.const 5\n    i32.xor\n    local.set 2\n    ",
        "local.get 2\n    drop"
    );
    let variant: String = source.replacen(original, replacement, 1);
    assert_ne!(variant, source, "entry-state read must be inserted");
    let obf_bytes: Vec<u8> = wat::parse_str(&variant).expect("assemble observed entry state");
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    assert_reloops_to_clean_behavior(
        &clean_bytes,
        &obf_bytes,
        "classify_local",
        "observed entry state",
    );
    let recovered: RecoveredModule = recover_module(&obf_bytes).expect("recover observed entry");
    assert!(contains_computed_state_binop(&recovered.bytes));
}

#[test]
fn guarded_arithmetic_state_updates_reloop_under_wasmtime() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    let obf_bytes: Vec<u8> = computed_guard_state_variant(false);
    assert_reloops_to_clean_behavior(
        &clean_bytes,
        &obf_bytes,
        "classify_local",
        "computed guarded states",
    );
}

#[test]
fn runtime_differential_rejects_swapped_guarded_arithmetic_successors() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    let mutant_bytes: Vec<u8> = computed_guard_state_variant(true);
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut mutant: Inst = instantiate(&eng, &mutant_bytes);
    assert_distinguished(&mut clean, &mut mutant, "classify_local");
}

#[test]
fn effectful_guarded_state_expression_remains_walled() {
    let path: PathBuf = fixture_dir().join("cff_computed_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read computed-state fixture");
    let mut variant: String = source.replacen(
        "i32.const 1\n                  local.set 2",
        "call 1\n                  local.set 2",
        1,
    );
    assert_ne!(variant, source, "guarded state expression must be replaced");
    let module_end: usize = variant.rfind(')').expect("module terminator");
    variant.insert_str(module_end, "  (func (result i32) i32.const 1)\n");
    let bytes: Vec<u8> = wat::parse_str(&variant).expect("assemble effectful guarded state");
    let recovered: RecoveredModule = recover_module(&bytes).expect("recover effectful guard");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
}

#[test]
fn unsafe_or_oversized_state_expressions_remain_walled() {
    let input_dependent: Vec<u8> =
        computed_state_variant("local.get 0\n            i32.const 0\n            i32.add");
    let trapping: Vec<u8> =
        computed_state_variant("i32.const 1\n            i32.const 0\n            i32.div_s");
    let unsupported: Vec<u8> = computed_state_variant("i32.const 3\n            i32.clz");
    let effectful: Vec<u8> = computed_state_call_variant();
    let mut oversized_expression: String = String::from("i32.const 3");
    for _index in 0..64 {
        oversized_expression.push_str("\n            i32.const 0\n            i32.add");
    }
    let oversized: Vec<u8> = computed_state_variant(&oversized_expression);

    for (name, bytes) in [
        ("input-dependent", input_dependent),
        ("trapping", trapping),
        ("unsupported", unsupported),
        ("effectful", effectful),
        ("oversized", oversized),
    ] {
        let recovered: RecoveredModule =
            recover_module(&bytes).unwrap_or_else(|error| panic!("recover {name}: {error}"));
        assert_eq!(
            recovered.report.flattened_conditional_restructured, 0,
            "{name}"
        );
        assert_eq!(recovered.report.flattened_dispatchers_walled, 1, "{name}");
    }
}

#[test]
fn runtime_differential_rejects_swapped_computed_state_successors() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    let mutant_bytes: Vec<u8> = assemble_fixture("cff_computed_state.mutant.wat");
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut mutant: Inst = instantiate(&eng, &mutant_bytes);

    assert_distinguished(&mut clean, &mut mutant, "classify_local");
}

fn computed_state_variant(replacement: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join("cff_computed_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read computed-state fixture");
    let original: &str = "i32.const 5\n            i32.const 6\n            i32.xor";
    let variant: String = source.replacen(original, replacement, 1);
    assert_ne!(
        variant, source,
        "computed-state expression must be replaced"
    );
    wat::parse_str(&variant).expect("assemble computed-state variant")
}

fn computed_state_call_variant() -> Vec<u8> {
    let path: PathBuf = fixture_dir().join("cff_computed_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read computed-state fixture");
    let original: &str = "i32.const 5\n            i32.const 6\n            i32.xor";
    let mut variant: String = source.replacen(original, "call 1", 1);
    assert_ne!(
        variant, source,
        "computed-state expression must be replaced"
    );
    let module_end: usize = variant.rfind(')').expect("module terminator");
    variant.insert_str(module_end, "  (func (result i32) i32.const 3)\n");
    wat::parse_str(&variant).expect("assemble effectful computed-state variant")
}

fn computed_guard_state_variant(swapped: bool) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join("cff_computed_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read computed-state fixture");
    let (nonzero, zero): (&str, &str) = if swapped {
        (
            "i32.const 6\n                  i32.const 4\n                  i32.xor",
            "i32.const 5\n                i32.const 4\n                i32.xor",
        )
    } else {
        (
            "i32.const 5\n                  i32.const 4\n                  i32.xor",
            "i32.const 6\n                i32.const 4\n                i32.xor",
        )
    };
    let with_nonzero: String = source.replacen(
        "i32.const 1\n                  local.set 2",
        &format!("{nonzero}\n                  local.set 2"),
        1,
    );
    let variant: String = with_nonzero.replacen(
        "i32.const 2\n                local.set 2",
        &format!("{zero}\n                local.set 2"),
        1,
    );
    assert_ne!(
        variant, source,
        "guarded state expressions must be replaced"
    );
    wat::parse_str(&variant).expect("assemble computed guarded states")
}

fn computed_select_state_variant(swapped: bool) -> Vec<u8> {
    let (then_expression, else_expression): (&str, &str) = if swapped {
        (
            "i32.const 1\n              i32.const 1\n              i32.add",
            "i32.const 1\n              i32.const 0\n              i32.add",
        )
    } else {
        (
            "i32.const 1\n              i32.const 0\n              i32.add",
            "i32.const 1\n              i32.const 1\n              i32.add",
        )
    };
    let source: String = computed_select_state_source(then_expression, else_expression);
    wat::parse_str(&source).expect("assemble computed select states")
}

fn computed_select_state_source(then_expression: &str, else_expression: &str) -> String {
    let path: PathBuf = fixture_dir().join("cff_local_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read local-state fixture");
    let original: &str = r"block ;; label = @6
                block ;; label = @7
                  local.get 0
                  i32.const 10
                  i32.gt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 0 (;@7;)
                  i32.const 1
                  local.set 2
                  br 1 (;@6;)
                end
                i32.const 2
                local.set 2
              end";
    let replacement: String = format!(
        "{then_expression}\n              {else_expression}\n              local.get 0\n              i32.const 10\n              i32.gt_s\n              select\n              local.set 2"
    );
    let variant: String = source.replacen(original, &replacement, 1);
    assert_ne!(variant, source, "select transition must be replaced");
    variant
}

#[test]
fn state_held_in_a_global_reloops_under_wasmtime() {
    assert_fixture_reloops(
        "cff_global_state.clean.wat",
        "cff_global_state.obf.wat",
        "classify_global",
    );
}

#[test]
fn state_global_copied_through_local_tee_reloops_under_wasmtime() {
    assert_fixture_reloops(
        "cff_global_state.clean.wat",
        "cff_global_tee_state.obf.wat",
        "classify_global",
    );
}

#[test]
fn runtime_differential_rejects_swapped_global_tee_successors() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_global_state.clean.wat");
    let mutant_bytes: Vec<u8> = assemble_fixture("cff_global_tee_state.mutant.wat");
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut mutant: Inst = instantiate(&eng, &mutant_bytes);
    assert_distinguished(&mut clean, &mut mutant, "classify_global");
}

#[test]
fn a_nested_suffix_read_of_the_tee_source_global_is_walled() {
    let bytes: Vec<u8> = assemble_fixture("cff_global_tee_state_suffix_read.obf.wat");
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover global tee module with nested suffix read");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 0,
        "a nested suffix read must prevent state-global elision: {:?}",
        recovered.report
    );
    assert_eq!(
        recovered.report.flattened_dispatchers_walled, 1,
        "a nested suffix read must wall the dispatcher: {:?}",
        recovered.report
    );
    assert!(
        contains_br_table(&recovered.bytes),
        "a walled dispatcher must retain its br_table"
    );

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut original, &mut candidate, "classify_global");
}

#[test]
fn an_effectful_global_tee_selector_prefix_is_not_relooped() {
    let bytes: Vec<u8> = assemble_fixture("cff_global_tee_state_effectful_prefix.obf.wat");
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover global tee module with effectful selector prefix");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 0,
        "an effectful selector prefix must not be erased: {:?}",
        recovered.report
    );
    assert!(
        contains_br_table(&recovered.bytes),
        "an effectful selector prefix must retain the dispatcher"
    );

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_eq!(
        call_i32(&mut candidate, "classify_global", 5),
        call_i32(&mut original, "classify_global", 5),
        "the walled dispatcher must preserve the classified result"
    );
    assert_eq!(
        read_global_i32(&mut candidate, "effect_count"),
        read_global_i32(&mut original, "effect_count"),
        "the selector-prefix effect must be preserved"
    );
    assert_eq!(
        read_global_i32(&mut original, "effect_count"),
        Some(3),
        "the dispatcher executes the selector prefix once per dispatched state"
    );

    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut original, &mut candidate, "classify_global");
}

#[test]
fn a_trapping_global_tee_selector_prefix_is_not_relooped() {
    let source: String =
        std::fs::read_to_string(fixture_dir().join("cff_global_tee_state.obf.wat"))
            .expect("read global tee fixture");
    let marker: &str = "      global.get 0\n      local.tee 2\n      drop\n      block";
    let replacement: &str = "      global.get 0\n      local.tee 2\n      drop\n      i32.const 1\n      i32.const 0\n      i32.div_s\n      drop\n      block";
    let variant: String = source.replacen(marker, replacement, 1);
    assert_ne!(variant, source, "trapping selector prefix must be inserted");
    let bytes: Vec<u8> = wat::parse_str(&variant).expect("assemble trapping selector prefix");
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover global tee module with trapping selector prefix");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 0,
        "a trapping selector prefix must not be erased: {:?}",
        recovered.report
    );
    assert!(
        contains_br_table(&recovered.bytes),
        "a trapping selector prefix must retain the dispatcher"
    );

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_eq!(
        call_i32(&mut original, "classify_global", 5),
        Outcome::Trap,
        "the original selector prefix must exercise its trap"
    );
    assert_eq!(
        call_i32(&mut candidate, "classify_global", 5),
        Outcome::Trap,
        "the recovered selector prefix must preserve its trap"
    );
}

#[test]
fn state_held_in_a_memory_slot_reloops_under_wasmtime() {
    assert_fixture_reloops(
        "cff_memory_state.clean.wat",
        "cff_memory_state.obf.wat",
        "classify_memory",
    );
}

#[test]
fn state_held_at_a_fixed_memory_address_reloops_under_wasmtime() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_memory_state.clean.wat");
    let obf_bytes: Vec<u8> = fixed_memory_state_variant(FixedMemoryMutation::None);
    assert_reloops_to_clean_behavior(
        &clean_bytes,
        &obf_bytes,
        "classify_memory",
        "fixed-address memory state",
    );
}

#[test]
fn equivalent_constant_expression_memory_addresses_reloop_under_wasmtime() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_memory_state.clean.wat");
    let obf_bytes: Vec<u8> =
        fixed_memory_state_variant(FixedMemoryMutation::ConstantExpressionAddress);
    assert_reloops_to_clean_behavior(
        &clean_bytes,
        &obf_bytes,
        "classify_memory",
        "constant-expression memory state",
    );
}

#[test]
fn input_dependent_memory_address_remains_walled_and_preserves_traps() {
    let bytes: Vec<u8> = fixed_memory_state_variant(FixedMemoryMutation::InputDependentAddress);
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover input-dependent memory state");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
    assert!(contains_br_table(&recovered.bytes));

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_eq!(
        call_i32(&mut original, "classify_memory", -1),
        Outcome::Trap
    );
    assert_eq!(
        call_i32(&mut candidate, "classify_memory", -1),
        Outcome::Trap
    );
    assert_equivalent(&mut original, &mut candidate, "classify_memory");
}

#[test]
fn out_of_bounds_local_memory_address_remains_walled_and_preserves_traps() {
    let bytes: Vec<u8> = fixed_memory_state_variant(FixedMemoryMutation::LocalOutOfBoundsAddress);
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover out-of-bounds local memory state");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
    assert!(contains_br_table(&recovered.bytes));

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_eq!(call_i32(&mut original, "classify_memory", 0), Outcome::Trap);
    assert_eq!(
        call_i32(&mut candidate, "classify_memory", 0),
        Outcome::Trap
    );
}

#[test]
fn unresolved_local_address_reloops_with_a_preceding_in_bounds_access() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_memory_state.clean.wat");
    let obf_bytes: Vec<u8> = unresolved_local_memory_state_variant(UnresolvedLocalProof::Preceding);
    assert_reloops_to_clean_behavior(
        &clean_bytes,
        &obf_bytes,
        "classify_memory",
        "preceding unresolved-local bounds proof",
    );
}

#[test]
fn unresolved_local_address_rejects_a_later_access_before_observable_effects_move() {
    let bytes: Vec<u8> = unresolved_local_memory_state_variant(UnresolvedLocalProof::Later);
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover later unresolved-local bounds proof");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
    assert!(contains_br_table(&recovered.bytes));

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_eq!(call_i32(&mut original, "classify_memory", 0), Outcome::Trap);
    assert_eq!(
        call_i32(&mut candidate, "classify_memory", 0),
        Outcome::Trap
    );
    assert_eq!(read_global_i32(&mut original, "marker"), Some(0));
    assert_eq!(read_global_i32(&mut candidate, "marker"), Some(0));
}

#[test]
fn unresolved_local_address_rejects_conditional_or_incompatible_bounds_evidence() {
    for proof in [
        UnresolvedLocalProof::Conditional,
        UnresolvedLocalProof::AddressMismatch,
        UnresolvedLocalProof::KindMismatch,
        UnresolvedLocalProof::Weaker,
    ] {
        let bytes: Vec<u8> = unresolved_local_memory_state_variant(proof);
        let recovered: RecoveredModule =
            recover_module(&bytes).expect("recover incompatible unresolved-local bounds proof");
        assert_eq!(
            recovered.report.flattened_conditional_restructured, 0,
            "incompatible proof {proof:?} must not reloop"
        );
        assert_eq!(
            recovered.report.flattened_dispatchers_walled, 1,
            "incompatible proof {proof:?} must wall"
        );
        assert!(contains_br_table(&recovered.bytes));
    }
}

#[test]
fn runtime_differential_rejects_swapped_fixed_memory_successors() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_memory_state.clean.wat");
    let mutant_bytes: Vec<u8> = fixed_memory_state_variant(FixedMemoryMutation::SwapSuccessors);
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut mutant: Inst = instantiate(&eng, &mutant_bytes);
    assert_distinguished(&mut clean, &mut mutant, "classify_memory");
}

#[test]
fn fixed_memory_selector_with_mismatched_store_metadata_remains_walled() {
    for mutation in [
        FixedMemoryMutation::AddressMismatch,
        FixedMemoryMutation::OffsetMismatch,
    ] {
        let bytes: Vec<u8> = fixed_memory_state_variant(mutation);
        let recovered: RecoveredModule =
            recover_module(&bytes).expect("recover mismatched fixed slot");
        assert_eq!(recovered.report.flattened_conditional_restructured, 0);
        assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
        assert!(contains_br_table(&recovered.bytes));
    }
}

#[test]
fn fixed_memory_selector_without_private_in_bounds_storage_remains_walled() {
    for mutation in [
        FixedMemoryMutation::ZeroPageMemory,
        FixedMemoryMutation::OutOfBoundsAddress,
        FixedMemoryMutation::ExportedMemory,
    ] {
        let bytes: Vec<u8> = fixed_memory_state_variant(mutation);
        let recovered: RecoveredModule =
            recover_module(&bytes).expect("recover non-private fixed slot");
        assert_eq!(recovered.report.flattened_conditional_restructured, 0);
        assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
        assert!(contains_br_table(&recovered.bytes));
    }
}

#[derive(Clone, Copy)]
enum FixedMemoryMutation {
    None,
    ConstantExpressionAddress,
    InputDependentAddress,
    LocalOutOfBoundsAddress,
    SwapSuccessors,
    AddressMismatch,
    OffsetMismatch,
    ZeroPageMemory,
    OutOfBoundsAddress,
    ExportedMemory,
}

fn fixed_memory_state_variant(mutation: FixedMemoryMutation) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join("cff_memory_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read memory-state fixture");
    let mut variant: String = source.replace("local.get 2", "i32.const 32");
    match mutation {
        FixedMemoryMutation::None => {}
        FixedMemoryMutation::ConstantExpressionAddress => {
            variant = variant.replace(
                "i32.const 32",
                "i32.const 48\n    i32.const 16\n    i32.sub",
            );
            variant = variant.replacen(
                "i32.const 48\n    i32.const 16\n    i32.sub",
                "i32.const 64\n    i32.const 32\n    i32.sub",
                1,
            );
        }
        FixedMemoryMutation::InputDependentAddress => {
            variant = source.replace("local.get 2", "local.get 0");
        }
        FixedMemoryMutation::LocalOutOfBoundsAddress => {
            variant = source.replacen(
                "i32.const 32\n    local.set 2",
                "i32.const 65532\n    local.set 2",
                1,
            );
        }
        FixedMemoryMutation::SwapSuccessors => {
            let with_nonzero: String = variant.replacen(
                "i32.const 32\n                  i32.const 1\n                  i32.store offset=4",
                "i32.const 32\n                  i32.const 2\n                  i32.store offset=4",
                1,
            );
            variant = with_nonzero.replacen(
                "i32.const 32\n                i32.const 2\n                i32.store offset=4",
                "i32.const 32\n                i32.const 1\n                i32.store offset=4",
                1,
            );
        }
        FixedMemoryMutation::AddressMismatch => {
            variant = variant.replacen(
                "i32.const 32\n            i32.const 3\n            i32.store offset=4",
                "i32.const 36\n            i32.const 3\n            i32.store offset=4",
                1,
            );
        }
        FixedMemoryMutation::OffsetMismatch => {
            variant = variant.replacen(
                "i32.const 32\n            i32.const 3\n            i32.store offset=4",
                "i32.const 32\n            i32.const 3\n            i32.store offset=8",
                1,
            );
        }
        FixedMemoryMutation::ZeroPageMemory => {
            variant = variant.replacen("(memory (;0;) 1)", "(memory (;0;) 0)", 1);
        }
        FixedMemoryMutation::OutOfBoundsAddress => {
            variant = variant.replace("i32.const 32", "i32.const 65532");
        }
        FixedMemoryMutation::ExportedMemory => {
            variant = variant.replacen(
                "(memory (;0;) 1)",
                "(memory (;0;) 1)\n  (export \"state_memory\" (memory 0))",
                1,
            );
        }
    }
    wat::parse_str(&variant).expect("assemble fixed-address memory state")
}

#[derive(Debug, Clone, Copy)]
enum UnresolvedLocalProof {
    Preceding,
    Later,
    Conditional,
    AddressMismatch,
    KindMismatch,
    Weaker,
}

fn unresolved_local_memory_state_variant(proof: UnresolvedLocalProof) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join("cff_memory_state.obf.wat");
    let source: String = std::fs::read_to_string(&path).expect("read memory-state fixture");
    let global_value: i32 = match proof {
        UnresolvedLocalProof::Later => 65_532,
        UnresolvedLocalProof::Preceding
        | UnresolvedLocalProof::Conditional
        | UnresolvedLocalProof::AddressMismatch
        | UnresolvedLocalProof::KindMismatch
        | UnresolvedLocalProof::Weaker => 32,
    };
    let mut variant: String = source.replacen(
        "(memory (;0;) 1)",
        &format!("(global (;0;) (mut i32) (i32.const {global_value}))\n  (memory (;0;) 1)"),
        1,
    );
    variant = variant.replacen(
        "i32.const 32\n    local.set 2",
        "global.get 0\n    local.set 2",
        1,
    );
    let initial_write: &str = "local.get 2\n    i32.const 0\n    i32.store offset=4";
    let replacement: String = match proof {
        UnresolvedLocalProof::Preceding => {
            format!("local.get 2\n    i32.const 91\n    i32.store offset=8\n    {initial_write}")
        }
        UnresolvedLocalProof::Later => {
            variant = variant.replacen(
                "(memory (;0;) 1)",
                "(memory (;0;) 1)\n  (global (;1;) (mut i32) (i32.const 0))\n  (export \"marker\" (global 1))",
                1,
            );
            format!(
                "{initial_write}\n    i32.const 1\n    global.set 1\n    local.get 2\n    i32.const 91\n    i32.store offset=8"
            )
        }
        UnresolvedLocalProof::Conditional => format!(
            "i32.const 0\n    if\n      local.get 2\n      i32.const 91\n      i32.store offset=8\n    end\n    {initial_write}"
        ),
        UnresolvedLocalProof::AddressMismatch => {
            format!("i32.const 48\n    i32.const 91\n    i32.store offset=8\n    {initial_write}")
        }
        UnresolvedLocalProof::KindMismatch => {
            format!("local.get 2\n    i64.const 91\n    i64.store offset=8\n    {initial_write}")
        }
        UnresolvedLocalProof::Weaker => {
            format!("local.get 2\n    i32.const 91\n    i32.store\n    {initial_write}")
        }
    };
    variant = variant.replacen(initial_write, &replacement, 1);
    wat::parse_str(&variant).expect("assemble unresolved-local memory state")
}

#[test]
fn runtime_differential_rejects_swapped_local_state_successors() {
    let clean_bytes: Vec<u8> = assemble_fixture("cff_local_state.clean.wat");
    let mutant_bytes: Vec<u8> = assemble_fixture("cff_local_state.mutant.wat");
    let eng: Engine = engine();
    let mut clean: Inst = instantiate(&eng, &clean_bytes);
    let mut mutant: Inst = instantiate(&eng, &mutant_bytes);
    assert_distinguished(&mut clean, &mut mutant, "classify_local");
}

fn read_global_i32(inst: &mut Inst, name: &str) -> Option<i32> {
    let global: wasmtime::Global = inst.instance.get_global(&mut inst.store, name)?;
    match global.get(&mut inst.store) {
        Val::I32(v) => Some(v),
        _ => None,
    }
}

fn call_no_args(inst: &mut Inst, export: &str) -> Outcome {
    let func: wasmtime::Func = match inst.instance.get_func(&mut inst.store, export) {
        Some(f) => f,
        None => return Outcome::Trap,
    };
    let mut results: [Val; 1] = [Val::I32(0)];
    inst.store.set_fuel(FUEL_BUDGET).ok();
    if func.call(&mut inst.store, &[], &mut results).is_err() {
        return Outcome::Trap;
    }
    match results[0] {
        Val::I32(v) => Outcome::Ret(v),
        _ => Outcome::Trap,
    }
}

#[test]
fn an_exported_state_global_is_walled_rather_than_elided() {
    let bytes: Vec<u8> = assemble_fixture("cff_global_state_observable.obf.wat");
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover exported state global module");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 0,
        "an exported state global must not be relooped: {:?}",
        recovered.report
    );
    assert_eq!(
        recovered.report.flattened_dispatchers_walled, 1,
        "an exported state global must be walled: {:?}",
        recovered.report
    );

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut original, &mut candidate, "classify_global");
    assert_eq!(
        call_i32(&mut original, "classify_global", 5),
        Outcome::Ret(-1)
    );
    assert_eq!(
        call_i32(&mut candidate, "classify_global", 5),
        Outcome::Ret(-1)
    );
    assert_eq!(
        read_global_i32(&mut candidate, "state"),
        read_global_i32(&mut original, "state"),
        "the exported state global must keep the value the original leaves behind"
    );
    assert_eq!(
        read_global_i32(&mut original, "state"),
        Some(3),
        "the original module leaves the terminal dispatch state in the exported global"
    );
}

#[test]
fn a_state_global_read_by_another_function_is_walled_rather_than_elided() {
    let bytes: Vec<u8> = assemble_fixture("cff_global_state_shared.obf.wat");
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover shared state global module");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 0,
        "a state global read elsewhere must not be relooped: {:?}",
        recovered.report
    );
    assert_eq!(
        recovered.report.flattened_dispatchers_walled, 1,
        "a state global read elsewhere must be walled: {:?}",
        recovered.report
    );

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut original, &mut candidate, "classify_global");
    assert_eq!(
        call_i32(&mut original, "classify_global", 5),
        Outcome::Ret(-1)
    );
    assert_eq!(
        call_i32(&mut candidate, "classify_global", 5),
        Outcome::Ret(-1)
    );
    assert_eq!(
        call_no_args(&mut candidate, "peek_state"),
        call_no_args(&mut original, "peek_state"),
        "the second reader of the state global must observe the same value"
    );
    assert_eq!(
        call_no_args(&mut original, "peek_state"),
        Outcome::Ret(3),
        "the original module leaves the terminal dispatch state in the shared global"
    );
}

#[test]
fn a_state_memory_slot_read_by_another_function_is_walled_rather_than_elided() {
    let bytes: Vec<u8> = assemble_fixture("cff_memory_state_shared.obf.wat");
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover shared state memory module");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 0,
        "a state memory slot read elsewhere must not be relooped: {:?}",
        recovered.report
    );
    assert_eq!(
        recovered.report.flattened_dispatchers_walled, 1,
        "a state memory slot read elsewhere must be walled: {:?}",
        recovered.report
    );

    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, &bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut original, &mut candidate, "classify_memory");
    assert_eq!(
        call_i32(&mut original, "classify_memory", 5),
        Outcome::Ret(-1)
    );
    assert_eq!(
        call_i32(&mut candidate, "classify_memory", 5),
        Outcome::Ret(-1)
    );
    assert_eq!(
        call_no_args(&mut candidate, "peek_state"),
        call_no_args(&mut original, "peek_state"),
        "the second reader of the state slot must observe the same value"
    );
    assert_eq!(
        call_no_args(&mut original, "peek_state"),
        Outcome::Ret(3),
        "the original module leaves the terminal dispatch state in the shared slot"
    );
}

const WALL_HARNESS_ENV: &str = "DISROBE_WASM_DEOB_WALL_HARNESS";
const OBSERVABLE_CELL_REASON: &str =
    "[debug:wasm-deob] unflatten-wall = state cell is observable outside the dispatcher";
const UNSUPPORTED_TRANSITION_REASON: &str =
    "[debug:wasm-deob] unflatten-wall = state transition is not a resolvable constant edge";

#[test]
#[ignore = "spawned as a subprocess by the wall-reason contract test"]
fn wall_reason_harness_entrypoint() {
    if std::env::var_os(WALL_HARNESS_ENV).is_none() {
        return;
    }
    let observable: Vec<u8> = assemble_fixture("cff_global_state_observable.obf.wat");
    recover_module(&observable).expect("recover exported state global module");
    let unsupported: Vec<u8> = computed_state_call_variant();
    recover_module(&unsupported).expect("recover effectful state transition module");
}

#[test]
fn every_wall_names_the_reason_it_refused() {
    let exe: PathBuf = std::env::current_exe().expect("test executable path");
    let mut cmd: Command = Command::new(exe);
    cmd.env(WALL_HARNESS_ENV, "1");
    cmd.env("DISROBE_DEBUG", "wasm-deob");
    cmd.env_remove("DISROBE_DEBUG_FORMAT");
    cmd.env("NO_COLOR", "1");
    cmd.arg("--ignored");
    cmd.arg("--exact");
    cmd.arg("--nocapture");
    cmd.arg("--test-threads=1");
    cmd.arg("wall_reason_harness_entrypoint");
    let out: Output = cmd.output().expect("spawn wall-reason harness child");
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains(OBSERVABLE_CELL_REASON),
        "an exported state global must name the observability refusal, got:\n{stderr}"
    );
    assert!(
        stderr.contains(UNSUPPORTED_TRANSITION_REASON),
        "an unresolvable transition must name its own refusal, got:\n{stderr}"
    );
}

#[test]
#[cfg(feature = "chain")]
fn a_real_rustc_next_state_temporary_reloops_through_the_registered_pass() {
    let bytes: &[u8] = include_bytes!("fixtures/cff_rustc_temp_state.obf.wasm");
    let recovered: RecoveredModule =
        recover_module(bytes).expect("recover rustc next-state-temporary module");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 1,
        "the real rustc next-state-temporary lowering must reloop: {:?}",
        recovered.report
    );
    assert_eq!(
        recovered.report.flattened_dispatchers_walled, 0,
        "the admitted rustc lowering must not retain a wall: {:?}",
        recovered.report
    );
    assert!(
        wasmparser::validate(&recovered.bytes).is_ok(),
        "the recovered module must validate"
    );
    assert!(
        !contains_br_table(&recovered.bytes),
        "the recovered module must remove the dispatcher"
    );
    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut original, &mut candidate, "classify_local");

    let input: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0x25; 32]);
    let surfaced: Artifact = WASM_DEOB_PASS
        .run(&input)
        .expect("registered wasm pass must surface rustc temporary-state recovery");
    assert_eq!(surfaced.rung, Rung::Surface);
    let source: &str = std::str::from_utf8(&surfaced.envelope).expect("surface WAT is UTF-8");
    assert!(source.contains("(module"));
    assert!(!source.contains("br_table"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryMutation {
    Load,
    Store,
}

fn mutate_first_memory_offset(
    bytes: &[u8],
    mutation: MemoryMutation,
    from: u32,
    to: u32,
) -> Vec<u8> {
    let mut module: walrus::Module = walrus::Module::from_buffer(bytes).expect("parse mutation");
    let mut changed: usize = 0;
    for (_function_id, function) in module.funcs.iter_local_mut() {
        let sequences: Vec<walrus::ir::InstrSeqId> = func_seq_ids(function);
        for sequence in sequences {
            for (instruction, _location) in &mut function.block_mut(sequence).instrs {
                let offset: Option<&mut u32> = match (mutation, instruction) {
                    (MemoryMutation::Load, walrus::ir::Instr::Load(load))
                        if load.arg.offset == from =>
                    {
                        Some(&mut load.arg.offset)
                    }
                    (MemoryMutation::Store, walrus::ir::Instr::Store(store))
                        if store.arg.offset == from =>
                    {
                        Some(&mut store.arg.offset)
                    }
                    _ => None,
                };
                if changed == 0
                    && let Some(offset) = offset
                {
                    *offset = to;
                    changed = 1;
                }
            }
        }
    }
    assert_eq!(changed, 1, "memory mutation must change one instruction");
    module.emit_wasm()
}

fn add_temporary_read(bytes: &[u8]) -> Vec<u8> {
    let mut module: walrus::Module = walrus::Module::from_buffer(bytes).expect("parse read escape");
    let mut changed: usize = 0;
    for (_function_id, function) in module.funcs.iter_local_mut() {
        let sequences: Vec<walrus::ir::InstrSeqId> = func_seq_ids(function);
        for sequence in sequences {
            let body: &mut Vec<(walrus::ir::Instr, walrus::ir::InstrLocId)> =
                &mut function.block_mut(sequence).instrs;
            let Some(load_index): Option<usize> = body.iter().position(|(instruction, _location)| {
                matches!(instruction, walrus::ir::Instr::Load(load) if load.arg.offset == 12)
            }) else {
                continue;
            };
            let address_index: usize = load_index
                .checked_sub(1)
                .expect("load must have an address");
            assert!(matches!(
                body.get(address_index),
                Some((walrus::ir::Instr::LocalGet(_), _))
            ));
            let address: (walrus::ir::Instr, walrus::ir::InstrLocId) = body[address_index].clone();
            let load: (walrus::ir::Instr, walrus::ir::InstrLocId) = body[load_index].clone();
            let location: walrus::ir::InstrLocId = load.1;
            body.splice(
                address_index..address_index,
                [
                    address,
                    load,
                    (walrus::ir::Instr::Drop(walrus::ir::Drop {}), location),
                ],
            );
            changed = changed.checked_add(1).expect("read mutation count");
            if changed == 1 {
                break;
            }
        }
    }
    assert_eq!(changed, 1, "read mutation must add one escaped read");
    module.emit_wasm()
}

fn mutate_first_successor(bytes: &[u8], offset: u32, from: i32, to: i32) -> Vec<u8> {
    let mut module: walrus::Module =
        walrus::Module::from_buffer(bytes).expect("parse successor mutation");
    let mut changed: usize = 0;
    for (_function_id, function) in module.funcs.iter_local_mut() {
        let sequences: Vec<walrus::ir::InstrSeqId> = func_seq_ids(function);
        for sequence in sequences {
            let body: &mut Vec<(walrus::ir::Instr, walrus::ir::InstrLocId)> =
                &mut function.block_mut(sequence).instrs;
            for index in 1..body.len() {
                let [(_, _), (store_instruction, _)] = &mut body[index - 1..=index] else {
                    unreachable!()
                };
                let walrus::ir::Instr::Store(store) = store_instruction else {
                    continue;
                };
                if store.arg.offset != offset {
                    continue;
                }
                let walrus::ir::Instr::Const(constant) = &mut body[index - 1].0 else {
                    continue;
                };
                if matches!(constant.value, walrus::ir::Value::I32(value) if value == from) {
                    constant.value = walrus::ir::Value::I32(to);
                    changed = changed.checked_add(1).expect("successor mutation count");
                    break;
                }
            }
            if changed == 1 {
                break;
            }
        }
    }
    assert_eq!(changed, 1, "successor mutation must change one mapping");
    module.emit_wasm()
}

#[test]
fn rustc_temporary_state_runtime_evidence_rejects_a_successor_mutation() {
    let original: &[u8] = include_bytes!("fixtures/cff_rustc_temp_state.obf.wasm");
    let mutant: Vec<u8> = mutate_first_successor(original, 12, 2, 1);
    let recovered: RecoveredModule =
        recover_module(&mutant).expect("recover mutated successor mapping");
    assert_eq!(recovered.report.flattened_conditional_restructured, 1);
    let eng: Engine = engine();
    let mut reference: Inst = instantiate(&eng, original);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_distinguished(&mut reference, &mut candidate, "classify_local");
    let mut mutant_runtime: Inst = instantiate(&eng, &mutant);
    let mut recovered_runtime: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(
        &mut mutant_runtime,
        &mut recovered_runtime,
        "classify_local",
    );
}

#[test]
fn rustc_temporary_state_escape_and_partial_transfer_remain_walled() {
    let original: &[u8] = include_bytes!("fixtures/cff_rustc_temp_state.obf.wasm");
    for (name, mutant) in [
        ("extra temporary read", add_temporary_read(original)),
        (
            "mixed dispatcher assignment",
            mutate_first_memory_offset(original, MemoryMutation::Store, 12, 4),
        ),
        (
            "partial temporary assignment",
            mutate_first_memory_offset(original, MemoryMutation::Store, 12, 16),
        ),
        (
            "mismatched latch source",
            mutate_first_memory_offset(original, MemoryMutation::Load, 12, 16),
        ),
    ] {
        let recovered: RecoveredModule =
            recover_module(&mutant).unwrap_or_else(|error| panic!("recover {name}: {error}"));
        assert_eq!(
            recovered.report.flattened_conditional_restructured, 0,
            "{name} must not be admitted: {:?}",
            recovered.report
        );
        assert_eq!(
            recovered.report.flattened_dispatchers_walled, 1,
            "{name} must retain the named wall: {:?}",
            recovered.report
        );
        assert!(contains_br_table(&recovered.bytes), "{name}");
    }
}

#[test]
fn default_dispatch_state_reloops_under_wasmtime() {
    assert_fixture_reloops(
        "cff_default_state.clean.wat",
        "cff_default_state.obf.wat",
        "classify",
    );
}

#[test]
fn default_entry_and_conditional_state_reloop_under_wasmtime() {
    assert_fixture_reloops(
        "cff_default_entry_cond.clean.wat",
        "cff_default_entry_cond.obf.wat",
        "entry_cond",
    );
}

fn contains_br_table(bytes: &[u8]) -> bool {
    count_br_tables(bytes) != 0
}

fn count_br_tables(bytes: &[u8]) -> usize {
    let module: walrus::Module = walrus::Module::from_buffer(bytes).expect("round-trip");
    module
        .funcs
        .iter_local()
        .map(|(_, func): (walrus::FunctionId, &walrus::LocalFunction)| {
            func_seq_ids(func)
                .into_iter()
                .map(|seq: walrus::ir::InstrSeqId| {
                    func.block(seq)
                        .instrs
                        .iter()
                        .filter(|(instr, _location)| matches!(instr, walrus::ir::Instr::BrTable(_)))
                        .count()
                })
                .sum::<usize>()
        })
        .sum()
}

fn contains_computed_state_binop(bytes: &[u8]) -> bool {
    let module: walrus::Module = walrus::Module::from_buffer(bytes).expect("round-trip");
    module.funcs.iter_local().any(|(_, func)| {
        func_seq_ids(func).into_iter().any(|seq| {
            func.block(seq).instrs.iter().any(|(instr, _)| {
                matches!(
                    instr,
                    walrus::ir::Instr::Binop(walrus::ir::Binop {
                        op: walrus::ir::BinaryOp::I32Xor | walrus::ir::BinaryOp::I32Or,
                    })
                )
            })
        })
    })
}

fn func_seq_ids(func: &walrus::LocalFunction) -> Vec<walrus::ir::InstrSeqId> {
    let mut out: Vec<walrus::ir::InstrSeqId> = Vec::new();
    let mut stack: Vec<walrus::ir::InstrSeqId> = vec![func.entry_block()];
    while let Some(id) = stack.pop() {
        out.push(id);
        for (instr, _) in &func.block(id).instrs {
            match instr {
                walrus::ir::Instr::Block(b) => stack.push(b.seq),
                walrus::ir::Instr::Loop(l) => stack.push(l.seq),
                walrus::ir::Instr::IfElse(ie) => {
                    stack.push(ie.consequent);
                    stack.push(ie.alternative);
                }
                _ => {}
            }
        }
    }
    out
}
