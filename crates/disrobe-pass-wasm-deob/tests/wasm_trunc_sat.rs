#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[cfg(feature = "sandbox")]
use std::path::{Path, PathBuf};

#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body, lift_module_to_wat,
};
#[cfg(feature = "sandbox")]
use wasmparser::{FunctionBody, Parser, Payload};
#[cfg(feature = "sandbox")]
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

#[cfg(feature = "sandbox")]
const FUEL_BUDGET: u64 = 2_000_000;

#[cfg(feature = "sandbox")]
fn real_wat() -> String {
    let path: PathBuf =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/wasm/obf/real/trunc_sat.obf.wat");
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}\nrun corpus/wasm/obf/build.sh to produce the real -O0 toolchain wat",
            path.display()
        )
    })
}

#[cfg(feature = "sandbox")]
fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

#[cfg(feature = "sandbox")]
fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

#[cfg(feature = "sandbox")]
fn engine() -> Engine {
    let mut config: Config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config).expect("engine")
}

#[cfg(feature = "sandbox")]
struct Inst {
    store: Store<()>,
    instance: wasmtime::Instance,
}

#[cfg(feature = "sandbox")]
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

#[cfg(feature = "sandbox")]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Outcome {
    F32ToI32(i32),
    F64ToI32(i32),
    F32ToI64(i64),
    F64ToI64(i64),
    Trap,
}

#[cfg(feature = "sandbox")]
fn call(inst: &mut Inst, export: &str, arg: Val, want: ResultKind) -> Outcome {
    let func: wasmtime::Func = match inst.instance.get_func(&mut inst.store, export) {
        Some(f) => f,
        None => return Outcome::Trap,
    };
    let mut results: [Val; 1] = [Val::I32(0)];
    inst.store.set_fuel(FUEL_BUDGET).ok();
    if func.call(&mut inst.store, &[arg], &mut results).is_err() {
        return Outcome::Trap;
    }
    match (want, results[0]) {
        (ResultKind::I32, Val::I32(v)) => match arg {
            Val::F32(_) => Outcome::F32ToI32(v),
            _ => Outcome::F64ToI32(v),
        },
        (ResultKind::I64, Val::I64(v)) => match arg {
            Val::F32(_) => Outcome::F32ToI64(v),
            _ => Outcome::F64ToI64(v),
        },
        _ => Outcome::Trap,
    }
}

#[cfg(feature = "sandbox")]
#[derive(Debug, Clone, Copy)]
enum ResultKind {
    I32,
    I64,
}

#[cfg(feature = "sandbox")]
fn f32_battery() -> Vec<Val> {
    let raw: [f32; 14] = [
        0.0,
        -0.0,
        1.5,
        -1.5,
        42.9,
        -42.9,
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        4.0e9,
        -4.0e9,
        2_147_483_648.0,
        -2_147_483_904.0,
        1.8e19,
    ];
    raw.into_iter().map(|f| Val::F32(f.to_bits())).collect()
}

#[cfg(feature = "sandbox")]
fn f64_battery() -> Vec<Val> {
    let raw: [f64; 16] = [
        0.0,
        -0.0,
        1.5,
        -1.5,
        42.9,
        -42.9,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        4.0e9,
        -4.0e9,
        2_147_483_648.0,
        -2_147_483_649.0,
        9.3e18,
        -9.3e18,
        1.9e19,
    ];
    raw.into_iter().map(|f| Val::F64(f.to_bits())).collect()
}

#[cfg(feature = "sandbox")]
fn case_for(export: &str) -> (ResultKind, &'static str) {
    if export.starts_with("i32_from") {
        (
            ResultKind::I32,
            if export.contains("f32") { "f32" } else { "f64" },
        )
    } else {
        (
            ResultKind::I64,
            if export.contains("f32") { "f32" } else { "f64" },
        )
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn real_o0_trunc_sat_lifts_fully_and_executes_identically_under_wasmtime() {
    let text: String = real_wat();
    let original: Vec<u8> = wat::parse_str(&text).expect("assemble real wat");
    let sigs: ModuleSignatures = extract_signatures(&original).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let calls: CalleeNames = callees(&sigs);

    let mut trunc_sat_functions: usize = 0;
    for (i, body) in defined_bodies(&original).iter().enumerate() {
        let sig: &FunctionSig = &defined[i];
        let lifted: LiftResult = lift_function_body(body, sig, &calls, LiftTarget::Wat);
        assert!(
            lifted.coverage.fully_recovered(),
            "function `{}` still has untranslated ops after the trunc_sat handler landed: {:?}",
            sig.name,
            lifted.coverage.untranslated
        );
        trunc_sat_functions += 1;
    }
    assert_eq!(
        trunc_sat_functions, 9,
        "the real -O0 trunc_sat sample must expose all nine conversion functions"
    );

    let pairs: Vec<(FunctionBody<'_>, FunctionSig)> = defined_bodies(&original)
        .into_iter()
        .zip(defined.iter().cloned())
        .collect();
    let offset: u32 = u32::try_from(sigs.imported_function_count()).unwrap_or(u32::MAX);
    let lifted_wat: String = lift_module_to_wat(&pairs, offset);
    let lifted_bytes: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted trunc_sat wat must reassemble: {e}\n{lifted_wat}"));

    let eng: Engine = engine();
    let mut original_inst: Inst = instantiate(&eng, &original);
    let mut lifted_inst: Inst = instantiate(&eng, &lifted_bytes);

    let mut checked: usize = 0;
    for sig in defined {
        if !sig.exported || sig.name == "mixed" {
            continue;
        }
        let (kind, operand): (ResultKind, &str) = case_for(&sig.name);
        let battery: Vec<Val> = if operand == "f32" {
            f32_battery()
        } else {
            f64_battery()
        };
        for arg in battery {
            let want: Outcome = call(&mut original_inst, &sig.name, arg, kind);
            let got: Outcome = call(&mut lifted_inst, &sig.name, arg, kind);
            assert_eq!(
                got, want,
                "export `{}` diverged on {arg:?}: original={want:?} lifted={got:?}",
                sig.name
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 8 * 14,
        "expected the full float edge-case battery across all eight trunc_sat exports, ran {checked}"
    );
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn wasm_trunc_sat_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "wasm_trunc_sat`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}
