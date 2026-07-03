#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_wasm_deob::{RecoveredModule, recover_module};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

const FUEL_BUDGET: u64 = 20_000_000;

fn real_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/wasm/obf/real")
}

fn assemble(name: &str) -> Vec<u8> {
    let path: PathBuf = real_dir().join(name);
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}\nrun corpus/wasm/obf/build.sh to produce the real toolchain wat",
            path.display()
        )
    });
    wat::parse_str(&text).unwrap_or_else(|e| panic!("assemble {}: {e}", path.display()))
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

#[test]
fn conditional_cff_reloops_to_clean_behavior_under_wasmtime() {
    let eng: Engine = engine();
    for case in cond_cases() {
        let clean_bytes: Vec<u8> = assemble(case.clean);
        let obf_bytes: Vec<u8> = assemble(case.obf);

        let mut clean_pre: Inst = instantiate(&eng, &clean_bytes);
        let mut obf_pre: Inst = instantiate(&eng, &obf_bytes);
        assert_equivalent(&mut clean_pre, &mut obf_pre, case.export);

        let recovered: RecoveredModule =
            recover_module(&obf_bytes).unwrap_or_else(|e| panic!("recover {}: {e}", case.obf));

        assert!(
            recovered.report.flattened_conditional_restructured >= 1,
            "data-dependent CFF must be relooped (not left WalledBranching) for {}: {:?}",
            case.obf,
            recovered.report
        );
        assert!(
            wasmparser::validate(&recovered.bytes).is_ok(),
            "recovered {} must validate",
            case.obf
        );
        assert!(
            !contains_br_table(&recovered.bytes),
            "recovered {} must no longer contain a br_table dispatcher",
            case.obf
        );

        let mut clean_inst: Inst = instantiate(&eng, &clean_bytes);
        let mut recovered_inst: Inst = instantiate(&eng, &recovered.bytes);
        assert_equivalent(&mut clean_inst, &mut recovered_inst, case.export);
    }
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
