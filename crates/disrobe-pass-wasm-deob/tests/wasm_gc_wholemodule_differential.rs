#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[cfg(feature = "sandbox")]
use std::path::Path;

#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::{
    FunctionSig, ModuleSignatures, extract_signatures, lift_module_to_wat,
};
#[cfg(feature = "sandbox")]
use wasmparser::{FunctionBody, Parser, Payload, ValType};
#[cfg(feature = "sandbox")]
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val};

#[cfg(feature = "sandbox")]
#[path = "common/wat_corpus.rs"]
mod wat_corpus;

#[cfg(feature = "sandbox")]
const FUEL_BUDGET: u64 = 2_000_000;
#[cfg(feature = "sandbox")]
const STORE_MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "sandbox")]
fn rich() -> Config {
    let mut c: Config = Config::new();
    c.wasm_gc(true)
        .wasm_function_references(true)
        .wasm_tail_call(true)
        .consume_fuel(true);
    c
}

#[cfg(feature = "sandbox")]
fn store_limits() -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(STORE_MEMORY_LIMIT_BYTES)
        .table_elements(10_000)
        .instances(1)
        .tables(1)
        .memories(1)
        .build()
}

#[cfg(feature = "sandbox")]
fn bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for p in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(b)) = p {
            out.push(b);
        }
    }
    out
}

#[cfg(feature = "sandbox")]
fn seeds(ty: ValType) -> Vec<Val> {
    match ty {
        ValType::I32 => vec![
            Val::I32(0),
            Val::I32(1),
            Val::I32(-1),
            Val::I32(3),
            Val::I32(-7),
            Val::I32(100),
        ],
        ValType::I64 => vec![
            Val::I64(0),
            Val::I64(1),
            Val::I64(-1),
            Val::I64(123_456_789),
        ],
        _ => vec![],
    }
}

#[cfg(feature = "sandbox")]
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

#[cfg(feature = "sandbox")]
fn run(eng: &Engine, bytes: &[u8], export: &str, arg: &[Val], arity: usize) -> Option<Vec<i64>> {
    let m: Module = Module::new(eng, bytes).ok()?;
    let mut store: Store<StoreLimits> = Store::new(eng, store_limits());
    store.limiter(|limits: &mut StoreLimits| limits);
    store.set_fuel(FUEL_BUDGET).ok()?;
    let mut linker: Linker<StoreLimits> = Linker::new(eng);
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

#[cfg(feature = "sandbox")]
#[test]
fn execution_store_rejects_modules_above_the_memory_limit() {
    let eng: Engine = Engine::new(&rich()).expect("bounded engine");
    let oversized: Vec<u8> =
        wat::parse_str("(module (memory 257) (func (export \"value\") (result i32) i32.const 7))")
            .expect("oversized test module");
    assert_eq!(
        run(&eng, &oversized, "value", &[], 1),
        None,
        "the Wasmtime store memory limit must reject oversized modules"
    );
}

#[cfg(feature = "sandbox")]
#[test]
fn execution_store_rejects_fuel_exhausting_loops() {
    let eng: Engine = Engine::new(&rich()).expect("bounded engine");
    let loop_forever: Vec<u8> = wat::parse_str(
        "(module (func (export \"spin\") (result i32) (loop $spin br $spin) unreachable))",
    )
    .expect("infinite-loop mutation-control module");
    assert_eq!(
        run(&eng, &loop_forever, "spin", &[], 1),
        None,
        "the fuel budget must reject an infinite Wasmtime execution"
    );
}

#[cfg(feature = "sandbox")]
const fn numeric(ty: ValType) -> bool {
    matches!(ty, ValType::I32 | ValType::I64)
}

#[cfg(feature = "sandbox")]
fn check(path: &Path) {
    let eng: Engine = Engine::new(&rich()).expect("eng");
    let text: String = wat_corpus::verified_wat_text(path);
    let original: Vec<u8> = wat::parse_str(&text).expect("wat");
    let sigs: ModuleSignatures = extract_signatures(&original).expect("sigs");
    let defined: &[FunctionSig] = sigs.defined();
    let mut pairs: Vec<(FunctionBody<'_>, FunctionSig)> = Vec::new();
    for (i, b) in bodies(&original).into_iter().enumerate() {
        if let Some(s) = defined.get(i) {
            pairs.push((b, s.clone()));
        }
    }
    let off: u32 = sigs.imported_function_count() as u32;
    let lifted_wat: String = lift_module_to_wat(&pairs, off);
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat).expect("lifted reparse");
    assert!(
        Module::new(&eng, &original).is_ok(),
        "ORIG compile {}",
        path.display()
    );
    assert!(
        Module::new(&eng, &lifted).is_ok(),
        "LIFT compile {}\n{lifted_wat}",
        path.display()
    );

    let mut eligible: usize = 0;
    let mut equiv: usize = 0;
    for s in defined {
        if !s.exported {
            continue;
        }
        let ok_abi: bool =
            s.params.iter().all(|t| numeric(*t)) && s.results.iter().all(|t| numeric(*t));
        if !ok_abi {
            continue;
        }
        eligible += 1;
        let mut all_eq: bool = true;
        for args in battery(&s.params, 36) {
            let a: Option<Vec<i64>> = run(&eng, &original, &s.name, &args, s.results.len());
            let b: Option<Vec<i64>> = run(&eng, &lifted, &s.name, &args, s.results.len());
            if a != b {
                all_eq = false;
                eprintln!("  DIVERGE {} {args:?} orig={a:?} lift={b:?}", s.name);
                break;
            }
        }
        if all_eq {
            equiv += 1;
        }
    }
    eprintln!("[{}] eligible={eligible} equiv={equiv}", path.display());
    assert_eq!(eligible, equiv, "{}", path.display());
}

#[cfg(feature = "sandbox")]
#[test]
fn corpus_gc_funcref_equiv() {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    check(&root.join("../../corpus/wasm/wat/gc_numeric_roundtrip.wat"));
    check(&root.join("../../corpus/wasm/wat/funcref_numeric.wat"));
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn wasm_gc_wholemodule_differential_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "wasm_gc_wholemodule_differential`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}
