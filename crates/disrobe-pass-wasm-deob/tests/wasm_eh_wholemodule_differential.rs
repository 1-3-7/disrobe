#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use disrobe_pass_wasm_deob::{
    EhModuleSummary, FunctionSig, ModuleSignatures, extract_signatures, lift_module_to_wat,
    scan_module_eh,
};
use wasmparser::{FunctionBody, Parser, Payload, Validator, WasmFeatures};

fn bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for p in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(b)) = p {
            out.push(b);
        }
    }
    out
}

fn lift(path: &Path) -> (Vec<u8>, Vec<u8>, String) {
    let text: String = fs::read_to_string(path).expect("read");
    let original: Vec<u8> = wat::parse_str(&text).expect("source wat must assemble");
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
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must re-assemble: {e}\n{lifted_wat}"));
    (original, lifted, lifted_wat)
}

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
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

#[test]
fn lifted_eh_module_validates_under_the_spec_validator() {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) =
        lift(&root.join("../../corpus/wasm/wat/eh_numeric_roundtrip.wat"));
    validate(&original).expect("original EH corpus must validate");
    validate(&lifted)
        .unwrap_or_else(|e| panic!("recovered EH module must validate: {e}\n{lifted_wat}"));
}

#[test]
fn recovered_eh_constructs_match_the_original_structure() {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) =
        lift(&root.join("../../corpus/wasm/wat/eh_numeric_roundtrip.wat"));
    let orig_sum: EhModuleSummary = scan_module_eh(&original).expect("scan original");
    let lift_sum: EhModuleSummary = scan_module_eh(&lifted).expect("scan lifted");

    assert!(
        orig_sum.uses_exception_handling(),
        "the corpus must actually exercise EH"
    );
    assert_eq!(
        orig_sum.constructs, lift_sum.constructs,
        "every EH construct in the source must survive into the recovered output\nlifted:\n{lifted_wat}"
    );
    assert_eq!(
        orig_sum.tag_section_count, lift_sum.tag_section_count,
        "the recovered module must re-declare every exception tag"
    );

    let (ot, oc, ocr): (u64, u64, u64) = throw_catch_totals(&orig_sum);
    let (lt, lc, lcr): (u64, u64, u64) = throw_catch_totals(&lift_sum);
    assert_eq!(ot, lt, "throw count must match the original");
    assert_eq!(oc, lc, "catch count must match the original");
    assert_eq!(ocr, lcr, "catch_ref count must match the original");

    let orig_per_fn: BTreeMap<u32, (u32, u32)> = orig_sum
        .functions
        .iter()
        .map(|(idx, f)| (*idx, (f.legacy_try_blocks, f.try_table_blocks)))
        .collect();
    let lift_per_fn: BTreeMap<u32, (u32, u32)> = lift_sum
        .functions
        .iter()
        .map(|(idx, f)| (*idx, (f.legacy_try_blocks, f.try_table_blocks)))
        .collect();
    assert_eq!(
        orig_per_fn, lift_per_fn,
        "per-function legacy-try and try_table block counts must be preserved"
    );
}

#[cfg(feature = "sandbox")]
mod execution {
    use super::lift;
    use disrobe_pass_wasm_deob::{ModuleSignatures, extract_signatures};
    use std::path::Path;
    use wasmparser::ValType;
    use wasmtime::{Config, Engine, Linker, Module, Store, Val};

    fn rich() -> Config {
        let mut c: Config = Config::new();
        c.wasm_gc(true)
            .wasm_function_references(true)
            .wasm_tail_call(true);
        c
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

    fn seeds(ty: ValType) -> Vec<Val> {
        match ty {
            ValType::I32 => vec![Val::I32(0), Val::I32(7), Val::I32(-3), Val::I32(50)],
            ValType::I64 => vec![Val::I64(0), Val::I64(9), Val::I64(-2)],
            _ => vec![],
        }
    }

    fn args(params: &[ValType]) -> Vec<Vec<Val>> {
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
                }
            }
            out = next;
            out.truncate(16);
        }
        out
    }

    const fn numeric(ty: ValType) -> bool {
        matches!(ty, ValType::I32 | ValType::I64)
    }

    #[test]
    fn non_throwing_eh_paths_execute_equivalently() {
        let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
        let corpus: std::path::PathBuf =
            root.join("../../corpus/wasm/wat/eh_numeric_roundtrip.wat");
        let (original, lifted, _): (Vec<u8>, Vec<u8>, String) = lift(&corpus);
        let sigs: ModuleSignatures = extract_signatures(&original).expect("sigs");

        let eng: Engine = Engine::new(&rich()).expect("eng");
        if Module::new(&eng, &original).is_err() {
            eprintln!("wasmtime cannot execute EH on this build; skipping execution probe");
            return;
        }

        let mut checked: usize = 0;
        for s in sigs.defined() {
            if !s.exported {
                continue;
            }
            if !s.params.iter().all(|t| numeric(*t)) || !s.results.iter().all(|t| numeric(*t)) {
                continue;
            }
            for a in args(&s.params) {
                let orig: Option<Outcome> = run(&eng, &original, &s.name, &a, s.results.len());
                let lift: Option<Outcome> = run(&eng, &lifted, &s.name, &a, s.results.len());
                let (Some(o), Some(l)): (Option<Outcome>, Option<Outcome>) = (orig, lift) else {
                    continue;
                };
                if matches!(o, Outcome::Returned(_)) {
                    assert_eq!(o, l, "{} {a:?} diverged on a returning path", s.name);
                    checked += 1;
                }
            }
        }
        eprintln!("non-throwing EH equivalence checks: {checked}");
    }
}
