#![cfg(all(feature = "sandbox", feature = "chain"))]
#![allow(clippy::expect_used, clippy::panic)]

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_wasm_deob::chain_detector::WASM_DEOB_PASS;
use disrobe_pass_wasm_deob::{RecoveredModule, recover_module};
use walrus::ir::{Instr, InstrSeqId};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

const CLEAN: &str = include_str!("fixtures/cff_memory_state.clean.wat");
const OBFUSCATED: &str = include_str!("fixtures/cff_memory_state.obf.wat");
const FUEL_BUDGET: u64 = 20_000_000;
const ADDRESS: &str = "local.get 2\n    i32.const 16\n    i32.add";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Return(i32),
    Trap,
}

struct Instance {
    store: Store<()>,
    instance: wasmtime::Instance,
}

fn engine() -> Engine {
    let mut config: Config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config).expect("create Wasmtime engine")
}

fn instantiate(engine: &Engine, bytes: &[u8]) -> Instance {
    let module: Module = Module::new(engine, bytes).expect("compile module");
    let mut store: Store<()> = Store::new(engine, ());
    store.set_fuel(FUEL_BUDGET).expect("set fuel");
    let mut linker: Linker<()> = Linker::new(engine);
    linker
        .define_unknown_imports_as_traps(&module)
        .expect("define imports");
    let instance: wasmtime::Instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate module");
    Instance { store, instance }
}

fn call(instance: &mut Instance, argument: i32) -> Outcome {
    let Some(function): Option<wasmtime::Func> = instance
        .instance
        .get_func(&mut instance.store, "classify_memory")
    else {
        return Outcome::Trap;
    };
    let mut results: [Val; 1] = [Val::I32(0)];
    let _ignored: Result<(), wasmtime::Error> = instance.store.set_fuel(FUEL_BUDGET);
    if function
        .call(&mut instance.store, &[Val::I32(argument)], &mut results)
        .is_err()
    {
        return Outcome::Trap;
    }
    match results[0] {
        Val::I32(value) => Outcome::Return(value),
        _ => Outcome::Trap,
    }
}

const fn battery() -> [i32; 13] {
    [-1000, -5, -1, 0, 1, 5, 9, 10, 11, 12, 20, 257, 1000]
}

fn assert_equivalent(reference: &[u8], candidate: &[u8]) {
    let engine: Engine = engine();
    let mut reference: Instance = instantiate(&engine, reference);
    let mut candidate: Instance = instantiate(&engine, candidate);
    for argument in battery() {
        assert_eq!(
            call(&mut candidate, argument),
            call(&mut reference, argument),
            "recovered module diverged for input {argument}"
        );
    }
}

fn contains_br_table(bytes: &[u8]) -> bool {
    let mut module: walrus::Module =
        walrus::Module::from_buffer(bytes).expect("parse module for br_table scan");
    module.funcs.iter_local_mut().any(|(_id, function)| {
        sequence_ids(function)
            .into_iter()
            .any(|sequence: InstrSeqId| {
                function
                    .block(sequence)
                    .instrs
                    .iter()
                    .any(|(instruction, _location)| matches!(instruction, Instr::BrTable(_)))
            })
    })
}

fn sequence_ids(function: &walrus::LocalFunction) -> Vec<InstrSeqId> {
    let mut pending: Vec<InstrSeqId> = vec![function.entry_block()];
    let mut found: Vec<InstrSeqId> = Vec::new();
    while let Some(sequence) = pending.pop() {
        found.push(sequence);
        for (instruction, _location) in &function.block(sequence).instrs {
            match instruction {
                Instr::Block(block) => pending.push(block.seq),
                Instr::Loop(loop_) => pending.push(loop_.seq),
                Instr::IfElse(if_else) => {
                    pending.push(if_else.consequent);
                    pending.push(if_else.alternative);
                }
                _ => {}
            }
        }
    }
    found
}

fn local_offset_source() -> String {
    let initialized: String = OBFUSCATED.replacen(
        "i32.const 32\n    local.set 2",
        "i32.const 16\n    local.set 2",
        1,
    );
    assert_ne!(initialized, OBFUSCATED);
    assert_eq!(initialized.matches("local.get 2").count(), 6);
    initialized.replace("local.get 2", ADDRESS)
}

fn assemble(source: &str) -> Vec<u8> {
    wat::parse_str(source).expect("assemble WAT")
}

fn assert_walled(source: &str) {
    let bytes: Vec<u8> = assemble(source);
    let recovered: RecoveredModule =
        recover_module(&bytes).expect("recover unsupported local-offset memory dispatcher");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
    assert!(contains_br_table(&recovered.bytes));
}

fn insert_before_dispatch(source: &str, instructions: &str) -> String {
    let mutated: String = source.replacen(
        "i32.const 0\n    i32.store offset=4\n    loop",
        &format!("i32.const 0\n    i32.store offset=4\n    {instructions}\n    loop"),
        1,
    );
    assert_ne!(mutated, source);
    mutated
}

fn assert_behavior_changed(reference: &str, mutant: &str) {
    let engine: Engine = engine();
    let mut reference: Instance = instantiate(&engine, &assemble(reference));
    let mut mutant: Instance = instantiate(&engine, &assemble(mutant));
    assert!(
        battery()
            .into_iter()
            .any(|argument: i32| call(&mut reference, argument) != call(&mut mutant, argument))
    );
}

fn mutate_store(bytes: &[u8], memory: bool) -> Vec<u8> {
    let mut module: walrus::Module =
        walrus::Module::from_buffer(bytes).expect("parse memory mutation");
    let other_memory: Option<walrus::MemoryId> =
        memory.then(|| module.memories.add_local(false, false, 1, None, None));
    let mut stores: usize = 0;
    for (_function_id, function) in module.funcs.iter_local_mut() {
        for sequence in sequence_ids(function) {
            for (instruction, _location) in &mut function.block_mut(sequence).instrs {
                let Instr::Store(store) = instruction else {
                    continue;
                };
                if store.arg.offset != 4 {
                    continue;
                }
                stores = stores.saturating_add(1);
                if stores == 2 {
                    if memory {
                        store.memory = other_memory.expect("second memory");
                    } else {
                        store.arg.offset = 8;
                    }
                }
            }
        }
    }
    assert_eq!(stores, 5);
    module.emit_wasm()
}

#[test]
fn immutable_local_plus_offset_reloops_through_public_callers_under_wasmtime() {
    let clean: Vec<u8> = assemble(CLEAN);
    let obfuscated: Vec<u8> = assemble(&local_offset_source());
    assert_equivalent(&clean, &obfuscated);

    let recovered: RecoveredModule =
        recover_module(&obfuscated).expect("recover immutable local plus offset selector");
    assert_eq!(recovered.report.flattened_conditional_restructured, 1);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 0);
    assert!(!contains_br_table(&recovered.bytes));
    assert_equivalent(&clean, &recovered.bytes);

    let input: Artifact = Artifact::new(Rung::Raw, obfuscated, [0x25; 32]);
    let surfaced: Artifact = WASM_DEOB_PASS
        .run(&input)
        .expect("registered pass must surface local-offset recovery");
    assert_eq!(surfaced.rung, Rung::Surface);
    let source: &str =
        std::str::from_utf8(&surfaced.envelope).expect("surface envelope must be UTF-8 WAT");
    assert!(!source.contains("br_table"));
    assert!(!source.contains("i32.const 16"));
    assert_equivalent(&clean, &assemble(source));
}

#[test]
fn wrong_successor_mutation_is_distinguished_under_wasmtime() {
    let clean: Vec<u8> = assemble(CLEAN);
    let mut mutant: String = local_offset_source();
    mutant = mutant.replacen(
        "i32.const 1\n                  i32.store offset=4",
        "i32.const 2\n                  i32.store offset=4",
        1,
    );
    mutant = mutant.replacen(
        "i32.const 2\n                i32.store offset=4",
        "i32.const 1\n                i32.store offset=4",
        1,
    );
    let mutant: Vec<u8> = assemble(&mutant);
    let engine: Engine = engine();
    let mut clean: Instance = instantiate(&engine, &clean);
    let mut mutant: Instance = instantiate(&engine, &mutant);
    assert!(
        battery()
            .into_iter()
            .any(|argument: i32| call(&mut clean, argument) != call(&mut mutant, argument))
    );
}

#[test]
fn unstable_dynamic_overflowing_and_effectful_address_setups_remain_walled() {
    let base: String = local_offset_source();
    let multiple_definitions: String = base.replacen(
        "i32.const 16\n    local.set 2",
        "i32.const 16\n    local.set 2\n    i32.const 16\n    local.set 2",
        1,
    );
    let dynamic: String = base.replace("local.get 2", "local.get 0");
    let overflow: String = base
        .replacen(
            "i32.const 16\n    local.set 2",
            "i32.const 2147483647\n    local.set 2",
            1,
        )
        .replace(
            "i32.const 16\n    i32.add",
            "i32.const 2147483647\n    i32.add",
        );
    let called: String = base.replacen(
        "i32.const 16\n    local.set 2",
        "call 1\n    local.set 2",
        1,
    );
    let called: String = format!(
        "{}  (func (result i32) i32.const 16)\n)\n",
        called.strip_suffix(")\n").expect("module terminator")
    );
    for source in [&multiple_definitions, &dynamic, &overflow, &called] {
        assert_walled(source);
    }
}

#[test]
fn aliases_mismatched_accesses_and_observable_memories_remain_walled() {
    let base: String = local_offset_source();
    let alias: String = base.replacen(
        "i32.const 0\n    i32.store offset=4\n    loop",
        "i32.const 0\n    i32.store offset=4\n    i32.const 36\n    i32.load\n    drop\n    loop",
        1,
    );
    let exported: String = base.replacen(
        "(memory (;0;) 1)",
        "(memory (;0;) 1)\n  (export \"state_memory\" (memory 0))",
        1,
    );
    let shared: String = base.replacen("(memory (;0;) 1)", "(memory (;0;) 1 1 shared)", 1);
    for source in [&alias, &exported] {
        assert_walled(source);
    }
    let shared_error: disrobe_pass_wasm_deob::Error = recover_module(&assemble(&shared))
        .expect_err("shared memory must remain outside local-offset recovery");
    assert!(
        shared_error.to_string().contains("threads must be enabled"),
        "shared memory must retain its named feature refusal: {shared_error}"
    );

    let bytes: Vec<u8> = assemble(&base);
    let mismatched_memarg: Vec<u8> = mutate_store(&bytes, false);
    let recovered: RecoveredModule =
        recover_module(&mismatched_memarg).expect("recover mismatched memory argument");
    assert_eq!(recovered.report.flattened_conditional_restructured, 0);
    assert_eq!(recovered.report.flattened_dispatchers_walled, 1);
    assert!(contains_br_table(&recovered.bytes));

    let mismatched_memory: Vec<u8> = mutate_store(&bytes, true);
    let memory_error: disrobe_pass_wasm_deob::Error = recover_module(&mismatched_memory)
        .expect_err("a different memory must remain outside local-offset recovery");
    assert!(
        memory_error.to_string().contains("multiple memories"),
        "mismatched memory must retain its named feature refusal: {memory_error}"
    );
}

#[test]
fn scalar_accesses_overlapping_either_selector_boundary_remain_walled() {
    let base: String = local_offset_source();
    let overlap_left_i64: String =
        insert_before_dispatch(&base, "i32.const 32\n    i64.load\n    drop");
    let overlap_left_i32: String =
        insert_before_dispatch(&base, "i32.const 35\n    i32.load\n    drop");
    let overlap_right_i64: String = insert_before_dispatch(
        &base,
        "i32.const 37\n    i64.const 72623859790382856\n    i64.store",
    );
    for source in [&overlap_left_i64, &overlap_left_i32, &overlap_right_i64] {
        assert_walled(source);
    }
}

#[test]
fn bulk_memory_writes_that_can_touch_the_selector_remain_walled() {
    let base: String = local_offset_source();
    let fill: String = insert_before_dispatch(
        &base,
        "i32.const 36\n    i32.const 1\n    i32.const 1\n    memory.fill",
    );
    let initialized: String = insert_before_dispatch(
        &base,
        "i32.const 36\n    i32.const 0\n    i32.const 1\n    memory.init 0\n    data.drop 0",
    );
    let initialized: String =
        initialized.replacen("  (func (;0;)", "  (data \"\\01\")\n  (func (;0;)", 1);
    let copied: String = insert_before_dispatch(
        &base,
        "i32.const 40\n    i32.const 1\n    i32.store8\n    i32.const 36\n    i32.const 40\n    i32.const 1\n    memory.copy",
    );
    for source in [&fill, &initialized, &copied] {
        assert_behavior_changed(&base, source);
        assert_walled(source);
    }
}
