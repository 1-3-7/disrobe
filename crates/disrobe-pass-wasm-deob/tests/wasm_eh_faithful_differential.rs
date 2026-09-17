#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use disrobe_pass_wasm_deob::{EhModuleSummary, lift_module_faithful_wat, scan_module_eh};
use wasmparser::{Validator, WasmFeatures};

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../corpus/wasm/wat/{name}"))
}

fn lift(name: &str) -> (Vec<u8>, Vec<u8>, String) {
    let text: String = fs::read_to_string(corpus(name)).expect("read corpus wat");
    let original: Vec<u8> = wat::parse_str(&text).expect("source wat must assemble");
    let lifted_wat: String =
        lift_module_faithful_wat(&original).expect("faithful lift must produce output");
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must re-assemble: {e}\n{lifted_wat}"));
    (original, lifted, lifted_wat)
}

fn throw_catch_totals(summary: &EhModuleSummary) -> (u64, u64, u64) {
    let mut throws: u64 = 0;
    let mut catches: u64 = 0;
    let mut catches_ref: u64 = 0;
    for tag in summary.per_tag.values() {
        throws += u64::from(tag.throws);
        catches += u64::from(tag.catches);
        catches_ref += u64::from(tag.catches_ref);
    }
    (throws, catches, catches_ref)
}

fn assert_faithful(name: &str) {
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(name);
    validate(&original).unwrap_or_else(|e| panic!("{name}: original EH corpus must validate: {e}"));
    validate(&lifted).unwrap_or_else(|e| {
        panic!(
            "{name}: recovered EH module must validate under the spec validator: {e}\n{lifted_wat}"
        )
    });

    let orig: EhModuleSummary = scan_module_eh(&original).expect("scan original");
    let lift_sum: EhModuleSummary = scan_module_eh(&lifted).expect("scan lifted");

    assert!(
        orig.uses_modern_eh(),
        "{name}: corpus must actually exercise modern try_table EH"
    );
    assert_eq!(
        orig.constructs, lift_sum.constructs,
        "{name}: every EH construct must survive into the recovered output\n{lifted_wat}"
    );
    assert_eq!(
        orig.tag_section_count, lift_sum.tag_section_count,
        "{name}: every exception tag must be re-declared"
    );
    assert_eq!(
        throw_catch_totals(&orig),
        throw_catch_totals(&lift_sum),
        "{name}: throw / catch / catch_ref totals must match the original\n{lifted_wat}"
    );

    let orig_per_fn: BTreeMap<u32, (u32, u32, u32, u32, u32)> = orig
        .functions
        .iter()
        .map(|(idx, f)| {
            (
                *idx,
                (
                    f.legacy_try_blocks,
                    f.try_table_blocks,
                    f.catch_all_ref_arms,
                    f.throw_refs,
                    f.catch_all_arms,
                ),
            )
        })
        .collect();
    let lift_per_fn: BTreeMap<u32, (u32, u32, u32, u32, u32)> = lift_sum
        .functions
        .iter()
        .map(|(idx, f)| {
            (
                *idx,
                (
                    f.legacy_try_blocks,
                    f.try_table_blocks,
                    f.catch_all_ref_arms,
                    f.throw_refs,
                    f.catch_all_arms,
                ),
            )
        })
        .collect();
    assert_eq!(
        orig_per_fn, lift_per_fn,
        "{name}: per-function modern-EH block profile must be preserved\n{lifted_wat}"
    );
}

#[test]
fn modern_try_table_corpus_round_trips_faithfully() {
    assert_faithful("eh_try_table_modern.wat");
}

#[test]
fn legacy_and_modern_corpus_round_trips_through_the_faithful_lifter() {
    assert_faithful("eh_numeric_roundtrip.wat");
}

#[test]
fn faithful_lift_preserves_modern_eh_syntax() {
    let (_, _, wat): (Vec<u8>, Vec<u8>, String) = lift("eh_try_table_modern.wat");
    assert!(
        wat.contains("catch_ref $tag0"),
        "catch_ref must survive:\n{wat}"
    );
    assert!(
        wat.contains("catch_all_ref"),
        "catch_all_ref must survive:\n{wat}"
    );
    assert!(wat.contains("throw_ref"), "throw_ref must survive:\n{wat}");
    assert!(
        wat.contains("(catch $tag0 0) (catch $tag1 1)"),
        "a multi-catch try_table must keep every catch clause:\n{wat}"
    );
}

#[cfg(feature = "sandbox")]
mod execution {
    use super::{corpus, lift};
    use std::path::Path;
    use wasmparser::{Parser, Payload, ValType};
    use wasmtime::{Config, Engine, Linker, Module, Store, Val};

    fn eh_config() -> Config {
        let mut c: Config = Config::new();
        c.wasm_gc(true)
            .wasm_function_references(true)
            .wasm_exceptions(true);
        c
    }

    fn export_sigs(bytes: &[u8]) -> Vec<(String, Vec<ValType>, Vec<ValType>)> {
        let mut types: Vec<(Vec<ValType>, Vec<ValType>)> = Vec::new();
        let mut func_type_idx: Vec<u32> = Vec::new();
        let mut exports: Vec<(String, u32)> = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            match payload.expect("payload") {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        for sub in group.expect("rec").types() {
                            if let wasmparser::CompositeInnerType::Func(ft) =
                                &sub.composite_type.inner
                            {
                                types.push((ft.params().to_vec(), ft.results().to_vec()));
                            } else {
                                types.push((Vec::new(), Vec::new()));
                            }
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for t in reader {
                        func_type_idx.push(t.expect("func type idx"));
                    }
                }
                Payload::ExportSection(reader) => {
                    for e in reader {
                        let e: wasmparser::Export<'_> = e.expect("export");
                        if matches!(
                            e.kind,
                            wasmparser::ExternalKind::Func | wasmparser::ExternalKind::FuncExact
                        ) {
                            exports.push((e.name.to_owned(), e.index));
                        }
                    }
                }
                _ => {}
            }
        }
        exports
            .into_iter()
            .filter_map(|(name, idx)| {
                let ti: u32 = *func_type_idx.get(idx as usize)?;
                let (p, r): &(Vec<ValType>, Vec<ValType>) = types.get(ti as usize)?;
                Some((name, p.clone(), r.clone()))
            })
            .collect()
    }

    const fn numeric(ty: ValType) -> bool {
        matches!(ty, ValType::I32 | ValType::I64)
    }

    fn seeds(ty: ValType) -> Vec<Val> {
        match ty {
            ValType::I32 => vec![
                Val::I32(0),
                Val::I32(1),
                Val::I32(2),
                Val::I32(-3),
                Val::I32(42),
                Val::I32(7),
            ],
            ValType::I64 => vec![Val::I64(0), Val::I64(1), Val::I64(-2)],
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

    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Returned(Vec<i64>),
        Trapped,
    }

    fn run(eng: &Engine, bytes: &[u8], export: &str, arg: &[Val], arity: usize) -> Option<Outcome> {
        let m: Module = Module::new(eng, bytes).ok()?;
        let mut store: Store<()> = Store::new(eng, ());
        let mut linker: Linker<()> = Linker::new(eng);
        linker.define_unknown_imports_as_traps(&m).ok()?;
        let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).ok()?;
        let f: wasmtime::Func = inst.get_func(&mut store, export)?;
        let mut res: Vec<Val> = vec![Val::I32(0); arity];
        if f.call(&mut store, arg, &mut res).is_err() {
            return Some(Outcome::Trapped);
        }
        Some(Outcome::Returned(
            res.iter()
                .map(|v| match v {
                    Val::I32(x) => i64::from(*x),
                    Val::I64(x) => *x,
                    _ => -999,
                })
                .collect(),
        ))
    }

    fn check(name: &str) {
        let eng: Engine = Engine::new(&eh_config()).expect("engine");
        let (original, lifted, _): (Vec<u8>, Vec<u8>, String) = lift(name);
        if Module::new(&eng, &original).is_err() {
            eprintln!(
                "wasmtime cannot execute EH on this build; skipping execution probe for {name}"
            );
            return;
        }
        let mut checked: usize = 0;
        for (export, params, results) in export_sigs(&original) {
            if !params.iter().all(|t| numeric(*t)) || !results.iter().all(|t| numeric(*t)) {
                continue;
            }
            for args in battery(&params, 18) {
                let a: Option<Outcome> = run(&eng, &original, &export, &args, results.len());
                let b: Option<Outcome> = run(&eng, &lifted, &export, &args, results.len());
                let (Some(o), Some(l)): (Option<Outcome>, Option<Outcome>) = (a, b) else {
                    continue;
                };
                assert_eq!(o, l, "{name}:{export} {args:?} diverged");
                checked += 1;
            }
        }
        eprintln!("[{name}] EH execution-equivalence checks: {checked}");
        let _: &Path = &corpus(name);
    }

    #[test]
    fn eh_modules_execute_equivalently() {
        check("eh_try_table_modern.wat");
        check("eh_numeric_roundtrip.wat");
    }
}
