#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::lift_module_faithful_wat;
#[cfg(feature = "sandbox")]
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val};

#[cfg(feature = "sandbox")]
const FUEL_BUDGET: u64 = 2_000_000;

#[cfg(feature = "sandbox")]
fn engine() -> Engine {
    let mut c: Config = Config::new();
    c.wasm_multi_memory(true).consume_fuel(true);
    Engine::new(&c).expect("engine")
}

#[cfg(feature = "sandbox")]
fn bounded_store(eng: &Engine) -> Store<StoreLimits> {
    let limits: StoreLimits = StoreLimitsBuilder::new()
        .memory_size(16 * 1024 * 1024)
        .table_elements(10_000)
        .instances(1)
        .tables(8)
        .memories(8)
        .build();
    let mut store: Store<StoreLimits> = Store::new(eng, limits);
    store.limiter(|limits: &mut StoreLimits| limits);
    store.set_fuel(FUEL_BUDGET).expect("fuel-enabled engine");
    store
}

#[cfg(feature = "sandbox")]
fn call_i32(eng: &Engine, bytes: &[u8], export: &str) -> i32 {
    let m: Module = Module::new(eng, bytes).expect("module compiles");
    let mut store: Store<StoreLimits> = bounded_store(eng);
    let mut linker: Linker<StoreLimits> = Linker::new(eng);
    linker
        .define_unknown_imports_as_traps(&m)
        .expect("trap unknown imports");
    let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).expect("instantiate");
    let f: wasmtime::Func = inst.get_func(&mut store, export).expect("export present");
    let mut res: [Val; 1] = [Val::I32(0)];
    f.call(&mut store, &[], &mut res).expect("call");
    match res[0] {
        Val::I32(x) => x,
        other => panic!("expected i32 result, got {other:?}"),
    }
}

#[cfg(feature = "sandbox")]
fn call_i64(eng: &Engine, bytes: &[u8], export: &str) -> i64 {
    let m: Module = Module::new(eng, bytes).expect("module compiles");
    let mut store: Store<StoreLimits> = bounded_store(eng);
    let mut linker: Linker<StoreLimits> = Linker::new(eng);
    linker
        .define_unknown_imports_as_traps(&m)
        .expect("trap unknown imports");
    let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).expect("instantiate");
    let f: wasmtime::Func = inst.get_func(&mut store, export).expect("export present");
    let mut res: [Val; 1] = [Val::I64(0)];
    f.call(&mut store, &[], &mut res).expect("call");
    match res[0] {
        Val::I64(x) => x,
        other => panic!("expected i64 result, got {other:?}"),
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn authored_loop_exhausts_the_wasmtime_fuel_budget() {
    let eng: Engine = engine();
    let bytes: Vec<u8> =
        wat::parse_str("(module (func (export \"spin\") (result i32) (loop br 0) i32.const 0))")
            .expect("assemble authored loop");
    let module: Module = Module::new(&eng, &bytes).expect("compile authored loop");
    let mut store: Store<StoreLimits> = bounded_store(&eng);
    let mut linker: Linker<StoreLimits> = Linker::new(&eng);
    linker
        .define_unknown_imports_as_traps(&module)
        .expect("trap unknown imports");
    let instance: wasmtime::Instance = linker
        .instantiate(&mut store, &module)
        .expect("loop module instantiates");
    let function: wasmtime::Func = instance.get_func(&mut store, "spin").expect("spin export");
    let mut result: [Val; 1] = [Val::I32(0)];
    let error: wasmtime::Error = function
        .call(&mut store, &[], &mut result)
        .expect_err("infinite loop must exhaust fuel");
    assert!(format!("{error:#}").contains("fuel"), "{error:#}");
}

#[cfg(feature = "sandbox")]
#[test]
fn authored_memory_above_the_store_limit_is_rejected() {
    let eng: Engine = engine();
    let bytes: Vec<u8> = wat::parse_str("(module (memory 257))").expect("assemble authored memory");
    let module: Module = Module::new(&eng, &bytes).expect("compile authored memory");
    let mut store: Store<StoreLimits> = bounded_store(&eng);
    let mut linker: Linker<StoreLimits> = Linker::new(&eng);
    linker
        .define_unknown_imports_as_traps(&module)
        .expect("trap unknown imports");
    let error: wasmtime::Error = match linker.instantiate(&mut store, &module) {
        Ok(_) => panic!("a 257-page memory must exceed the 16 MiB store limit"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("memory"), "{error:#}");
}

#[cfg(feature = "sandbox")]
const SRC: &str = r#"(module
    (global $gf32 f32 (f32.const nan:0x400001))
    (func (export "f32_body_quiet") (result i32)
        f32.const nan:0x400001 i32.reinterpret_f32)
    (func (export "f32_body_neg") (result i32)
        f32.const -nan:0x400001 i32.reinterpret_f32)
    (func (export "f32_body_signaling") (result i32)
        f32.const nan:0x200001 i32.reinterpret_f32)
    (func (export "f32_global") (result i32)
        global.get $gf32 i32.reinterpret_f32)
    (func (export "f64_body_quiet") (result i64)
        f64.const nan:0x8000000000001 i64.reinterpret_f64)
    (func (export "f64_body_neg") (result i64)
        f64.const -nan:0x8000000000001 i64.reinterpret_f64)
    (func (export "f64_body_signaling") (result i64)
        f64.const nan:0x4000000000001 i64.reinterpret_f64))"#;

#[cfg(feature = "sandbox")]
#[test]
fn faithful_lift_preserves_nan_sign_and_payload_bits() {
    let eng: Engine = engine();
    let original: Vec<u8> = wat::parse_str(SRC).expect("source wat parses");
    let lifted_wat: String =
        lift_module_faithful_wat(&original).expect("faithful lift produced output");
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat).expect("lifted wat reassembles");

    for export in [
        "f32_body_quiet",
        "f32_body_neg",
        "f32_body_signaling",
        "f32_global",
    ] {
        let orig: i32 = call_i32(&eng, &original, export);
        let got: i32 = call_i32(&eng, &lifted, export);
        assert_eq!(
            orig, got,
            "{export}: orig=0x{orig:08x} lifted=0x{got:08x}\n{lifted_wat}"
        );
    }
    for export in ["f64_body_quiet", "f64_body_neg", "f64_body_signaling"] {
        let orig: i64 = call_i64(&eng, &original, export);
        let got: i64 = call_i64(&eng, &lifted, export);
        assert_eq!(
            orig, got,
            "{export}: orig=0x{orig:016x} lifted=0x{got:016x}\n{lifted_wat}"
        );
    }
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn wasm_float_const_nan_bits_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "wasm_float_const_nan_bits`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}
