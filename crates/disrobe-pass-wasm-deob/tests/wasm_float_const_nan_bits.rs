#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_wasm_deob::lift_module_faithful_wat;
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

fn engine() -> Engine {
    let mut c: Config = Config::new();
    c.wasm_multi_memory(true);
    Engine::new(&c).expect("engine")
}

fn call_i32(eng: &Engine, bytes: &[u8], export: &str) -> i32 {
    let m: Module = Module::new(eng, bytes).expect("module compiles");
    let mut store: Store<()> = Store::new(eng, ());
    let linker: Linker<()> = Linker::new(eng);
    let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).expect("instantiate");
    let f: wasmtime::Func = inst.get_func(&mut store, export).expect("export present");
    let mut res: [Val; 1] = [Val::I32(0)];
    f.call(&mut store, &[], &mut res).expect("call");
    match res[0] {
        Val::I32(x) => x,
        other => panic!("expected i32 result, got {other:?}"),
    }
}

fn call_i64(eng: &Engine, bytes: &[u8], export: &str) -> i64 {
    let m: Module = Module::new(eng, bytes).expect("module compiles");
    let mut store: Store<()> = Store::new(eng, ());
    let linker: Linker<()> = Linker::new(eng);
    let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).expect("instantiate");
    let f: wasmtime::Func = inst.get_func(&mut store, export).expect("export present");
    let mut res: [Val; 1] = [Val::I64(0)];
    f.call(&mut store, &[], &mut res).expect("call");
    match res[0] {
        Val::I64(x) => x,
        other => panic!("expected i64 result, got {other:?}"),
    }
}

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
