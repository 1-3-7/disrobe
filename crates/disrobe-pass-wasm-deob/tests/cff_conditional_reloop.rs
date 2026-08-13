#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
fn state_held_in_a_global_reloops_under_wasmtime() {
    assert_fixture_reloops(
        "cff_global_state.clean.wat",
        "cff_global_state.obf.wat",
        "classify_global",
    );
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
    let temp_state: &[u8] = include_bytes!("fixtures/cff_rustc_temp_state.obf.wasm");
    recover_module(temp_state).expect("recover rustc next-state-temporary module");
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
fn a_real_rustc_next_state_temporary_is_walled_not_mis_structured() {
    let bytes: &[u8] = include_bytes!("fixtures/cff_rustc_temp_state.obf.wasm");
    let recovered: RecoveredModule =
        recover_module(bytes).expect("recover rustc next-state-temporary module");
    assert_eq!(
        recovered.report.flattened_conditional_restructured, 0,
        "the rustc next-state-temporary lowering is not a supported shape: {:?}",
        recovered.report
    );
    assert_eq!(
        recovered.report.flattened_dispatchers_walled, 1,
        "an unsupported real lowering must be walled, never silently skipped: {:?}",
        recovered.report
    );
    assert!(
        wasmparser::validate(&recovered.bytes).is_ok(),
        "the walled module must still validate"
    );
    let eng: Engine = engine();
    let mut original: Inst = instantiate(&eng, bytes);
    let mut candidate: Inst = instantiate(&eng, &recovered.bytes);
    assert_equivalent(&mut original, &mut candidate, "classify_local");
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
    let module: walrus::Module = walrus::Module::from_buffer(bytes).expect("round-trip");
    module.funcs.iter_local().any(|(_, func)| {
        func_seq_ids(func).into_iter().any(|seq| {
            func.block(seq)
                .instrs
                .iter()
                .any(|(instr, _)| matches!(instr, walrus::ir::Instr::BrTable(_)))
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
