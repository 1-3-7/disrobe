#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::Path;

use disrobe_pass_wasm_deob::{
    StackSwitchOpKind, StackSwitchReport, lift_module_faithful_wat, scan_stack_switching,
};
use wasmparser::{Validator, WasmFeatures};

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn lift(path: &Path) -> (Vec<u8>, Vec<u8>, String) {
    let text: String = fs::read_to_string(path).expect("read corpus wat");
    let original: Vec<u8> = wat::parse_str(&text).expect("source wat must assemble");
    let lifted_wat: String =
        lift_module_faithful_wat(&original).expect("faithful lift must produce output");
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must re-assemble: {e}\n{lifted_wat}"));
    (original, lifted, lifted_wat)
}

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../corpus/wasm/wat/{name}"))
}

fn kind_totals(report: &StackSwitchReport) -> Vec<(StackSwitchOpKind, usize)> {
    let mut totals: Vec<(StackSwitchOpKind, usize)> =
        report.kinds.iter().map(|(k, c)| (*k, *c)).collect();
    totals.sort_by_key(|(k, _)| *k);
    totals
}

fn assert_round_trip(name: &str) {
    let path: std::path::PathBuf = corpus(name);
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(&path);

    validate(&original)
        .unwrap_or_else(|e| panic!("{name}: original stack-switching corpus must validate: {e}"));
    validate(&lifted).unwrap_or_else(|e| {
        panic!("{name}: recovered stack-switching module must validate under the spec validator: {e}\n{lifted_wat}")
    });

    let orig_report: StackSwitchReport = scan_stack_switching(&original).expect("scan original");
    let lift_report: StackSwitchReport = scan_stack_switching(&lifted).expect("scan lifted");

    assert!(
        !orig_report.is_empty(),
        "{name}: the corpus must actually exercise stack-switching operators"
    );
    assert_eq!(
        orig_report.op_count(),
        lift_report.op_count(),
        "{name}: every stack-switching operator must survive into the recovered output\n{lifted_wat}"
    );
    assert_eq!(
        kind_totals(&orig_report),
        kind_totals(&lift_report),
        "{name}: per-kind stack-switching operator counts must be preserved\n{lifted_wat}"
    );
    assert_eq!(
        orig_report.uses_switch, lift_report.uses_switch,
        "{name}: switch usage must be preserved"
    );
    assert_eq!(
        orig_report.uses_resume_throw, lift_report.uses_resume_throw,
        "{name}: resume_throw usage must be preserved"
    );
}

#[test]
fn generator_round_trips_validator_and_structure() {
    assert_round_trip("stack_switching.wat");
}

#[test]
fn cont_bind_resume_throw_round_trips_validator_and_structure() {
    assert_round_trip("stack_switching_bind_throw.wat");
}

#[test]
fn faithful_lift_preserves_cont_types_and_block_signatures() {
    let (_, _, generator): (Vec<u8>, Vec<u8>, String) = lift(&corpus("stack_switching.wat"));
    assert!(
        generator.contains("(cont $t0)"),
        "the continuation type must be recovered as a real cont type, not collapsed to func:\n{generator}"
    );
    assert!(
        generator.contains("(result i32) (result (ref $t1))"),
        "the resume handler block's multi-value type must be recovered faithfully:\n{generator}"
    );
}

#[cfg(feature = "sandbox")]
mod execution {
    use super::{corpus, lift};
    use wasmtime::{Config, Engine, Linker, Module, Store, Val};

    fn stack_switching_config() -> Config {
        let mut c: Config = Config::new();
        c.wasm_gc(true)
            .wasm_function_references(true)
            .wasm_tail_call(true)
            .wasm_exceptions(true);
        let _ = c.wasm_stack_switching(true);
        c
    }

    fn run(eng: &Engine, bytes: &[u8], export: &str) -> Option<Vec<i64>> {
        let m: Module = Module::new(eng, bytes).ok()?;
        let mut store: Store<()> = Store::new(eng, ());
        let mut linker: Linker<()> = Linker::new(eng);
        linker.define_unknown_imports_as_traps(&m).ok()?;
        let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).ok()?;
        let f: wasmtime::Func = inst.get_func(&mut store, export)?;
        let arity: usize = f.ty(&store).results().len();
        let mut res: Vec<Val> = vec![Val::I32(0); arity];
        if f.call(&mut store, &[], &mut res).is_err() {
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

    #[test]
    fn execution_equivalence_when_the_runtime_supports_stack_switching() {
        let Ok(eng): Result<Engine, _> = Engine::new(&stack_switching_config()) else {
            eprintln!(
                "wasmtime/cranelift on this build cannot execute stack-switching; \
                 the spec validator + structural differential remain the oracle here"
            );
            return;
        };
        let (original, lifted, _): (Vec<u8>, Vec<u8>, String) =
            lift(&corpus("stack_switching.wat"));
        let compiles: bool = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Module::new(&eng, &original).is_ok()
        }))
        .unwrap_or(false);
        if !compiles {
            eprintln!(
                "wasmtime/cranelift on this build cannot codegen stack-switching; skipping execution probe (spec validator + structural differential remain the oracle)"
            );
            return;
        }
        let orig: Option<Vec<i64>> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&eng, &original, "main")
        }))
        .ok()
        .flatten();
        let recovered: Option<Vec<i64>> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&eng, &lifted, "main")))
                .ok()
                .flatten();
        if orig.is_none() && recovered.is_none() {
            eprintln!(
                "wasmtime could not execute either module on this build; skipping execution probe"
            );
            return;
        }
        assert_eq!(
            orig, recovered,
            "recovered stack-switching module must execute equivalently to the original"
        );
    }
}
