#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_wasm_deob::{ModuleSignatures, extract_signatures, lift_module_faithful_wat};
use wasmparser::ValType;
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

fn corpus_dirs() -> Vec<PathBuf> {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        root.join("../../corpus/src/wasm/sources"),
        root.join("../../corpus/src/wasm/edge_cases"),
        root.join("../../corpus/wasm/wat"),
    ]
}

fn wat_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in corpus_dirs() {
        let Ok(entries): Result<fs::ReadDir, _> = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.extension().is_some_and(|e| e == "wat") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn config() -> Config {
    let mut c: Config = Config::new();
    c.wasm_gc(true)
        .wasm_function_references(true)
        .wasm_tail_call(true)
        .wasm_simd(true)
        .wasm_relaxed_simd(true)
        .wasm_multi_memory(true)
        .wasm_memory64(true)
        .consume_fuel(true);
    c
}

fn seeds(ty: ValType) -> Vec<Val> {
    match ty {
        ValType::I32 => vec![Val::I32(0), Val::I32(1), Val::I32(3), Val::I32(255)],
        ValType::I64 => vec![Val::I64(0), Val::I64(1), Val::I64(255)],
        _ => vec![],
    }
}

fn battery(params: &[ValType], cap: usize) -> Vec<Vec<Val>> {
    if params.is_empty() {
        return vec![vec![]];
    }
    let mut out: Vec<Vec<Val>> = vec![vec![]];
    for ty in params {
        let mut next: Vec<Vec<Val>> = Vec::new();
        for prefix in &out {
            for s in seeds(*ty) {
                let mut e: Vec<Val> = prefix.clone();
                e.push(s);
                next.push(e);
                if next.len() >= cap {
                    break;
                }
            }
            if next.len() >= cap {
                break;
            }
        }
        out = next;
    }
    out.truncate(cap);
    out
}

fn run(eng: &Engine, bytes: &[u8], export: &str, arg: &[Val], arity: usize) -> Option<Vec<i64>> {
    let m: Module = Module::new(eng, bytes).ok()?;
    let mut store: Store<()> = Store::new(eng, ());
    store.set_fuel(2_000_000).ok()?;
    let mut linker: Linker<()> = Linker::new(eng);
    linker.define_unknown_imports_as_traps(&m).ok()?;
    let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).ok()?;
    let f: wasmtime::Func = inst.get_func(&mut store, export)?;
    let mut res: Vec<Val> = vec![Val::I32(0); arity];
    if f.call(&mut store, arg, &mut res).is_err() {
        return None;
    }
    Some(
        res.iter()
            .map(|v| match v {
                Val::I32(x) => i64::from(*x),
                Val::I64(x) => *x,
                _ => -999,
            })
            .collect(),
    )
}

const fn numeric(ty: ValType) -> bool {
    matches!(ty, ValType::I32 | ValType::I64)
}

struct Outcome {
    eligible: usize,
    equiv: usize,
    diverged: Vec<String>,
    lift_failures: Vec<String>,
}

fn measure() -> Outcome {
    let eng: Engine = Engine::new(&config()).expect("engine");
    let mut eligible: usize = 0;
    let mut equiv: usize = 0;
    let mut diverged: Vec<String> = Vec::new();
    let mut lift_failures: Vec<String> = Vec::new();

    for path in wat_files() {
        let text: String = fs::read_to_string(&path).expect("read wat");
        let Ok(original): Result<Vec<u8>, _> = wat::parse_str(&text) else {
            continue;
        };
        let Ok(sigs): Result<ModuleSignatures, _> = extract_signatures(&original) else {
            continue;
        };
        if Module::new(&eng, &original).is_err() {
            continue;
        }
        let Some(lifted_wat): Option<String> = lift_module_faithful_wat(&original) else {
            lift_failures.push(format!("{}: faithful lift returned None", path.display()));
            continue;
        };
        let Ok(lifted): Result<Vec<u8>, _> = wat::parse_str(&lifted_wat) else {
            lift_failures.push(format!("{}: lifted WAT did not reassemble", path.display()));
            continue;
        };
        if Module::new(&eng, &lifted).is_err() {
            lift_failures.push(format!("{}: lifted module did not compile", path.display()));
            continue;
        }

        for s in sigs.defined() {
            if !s.exported {
                continue;
            }
            let ok_abi: bool =
                s.params.iter().all(|t| numeric(*t)) && s.results.iter().all(|t| numeric(*t));
            if !ok_abi {
                continue;
            }
            let cases: Vec<Vec<Val>> = battery(&s.params, 16);
            let orig_runs: Vec<Option<Vec<i64>>> = cases
                .iter()
                .map(|a| run(&eng, &original, &s.name, a, s.results.len()))
                .collect();
            if orig_runs.iter().all(Option::is_none) {
                continue;
            }
            eligible += 1;
            let mut all_eq: bool = true;
            for (args, orig) in cases.iter().zip(orig_runs.iter()) {
                let got: Option<Vec<i64>> = run(&eng, &lifted, &s.name, args, s.results.len());
                if *orig != got {
                    all_eq = false;
                    diverged.push(format!(
                        "{} :: {} {args:?} orig={orig:?} lifted={got:?}",
                        path.display(),
                        s.name
                    ));
                    break;
                }
            }
            if all_eq {
                equiv += 1;
            }
        }
    }

    Outcome {
        eligible,
        equiv,
        diverged,
        lift_failures,
    }
}

#[test]
fn faithful_lift_is_behaviorally_identical_across_corpus() {
    let outcome: Outcome = measure();
    eprintln!(
        "wasm whole-module behavioral differential (wasmtime, non-circular): eligible={} equiv={} lift_failures={}",
        outcome.eligible,
        outcome.equiv,
        outcome.lift_failures.len()
    );

    assert!(
        outcome.lift_failures.is_empty(),
        "faithful whole-module lift must produce a compilable module for every corpus file:\n{}",
        outcome.lift_failures.join("\n")
    );

    assert!(
        outcome.eligible >= 40,
        "expected the numeric-export corpus battery to stay non-trivial, saw {} eligible functions; \
         a collapse here means the corpus or the exporter regressed",
        outcome.eligible
    );

    assert_eq!(
        outcome.equiv,
        outcome.eligible,
        "every wasmtime-runnable numeric export must execute bit-identically after faithful lift; \
         {} of {} diverged:\n{}",
        outcome.eligible - outcome.equiv,
        outcome.eligible,
        outcome.diverged.join("\n")
    );
}
