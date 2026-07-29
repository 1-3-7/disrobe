#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[path = "common/div_cases.rs"]
mod div_cases;

use disrobe_pass_wasm_deob::lift_module_faithful_wat;
use div_cases::{DIV_REM_MODULE as SOURCE, i32_cases, i64_cases};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

const FUEL_BUDGET: u64 = 2_000_000;

const OPCODES: [&str; 8] = [
    "i32.div_s",
    "i32.div_u",
    "i32.rem_s",
    "i32.rem_u",
    "i64.div_s",
    "i64.div_u",
    "i64.rem_s",
    "i64.rem_u",
];

struct Inst {
    store: Store<()>,
    instance: wasmtime::Instance,
}

fn engine() -> Engine {
    let mut config: Config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config).expect("engine")
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

fn call_i32(inst: &mut Inst, export: &str, a: i32, b: i32) -> Option<i32> {
    let func: wasmtime::Func = inst.instance.get_func(&mut inst.store, export)?;
    let mut results: [Val; 1] = [Val::I32(0)];
    inst.store.set_fuel(FUEL_BUDGET).ok();
    if func
        .call(&mut inst.store, &[Val::I32(a), Val::I32(b)], &mut results)
        .is_err()
    {
        return None;
    }
    match results[0] {
        Val::I32(v) => Some(v),
        _ => None,
    }
}

fn call_i64(inst: &mut Inst, export: &str, a: i64, b: i64) -> Option<i64> {
    let func: wasmtime::Func = inst.instance.get_func(&mut inst.store, export)?;
    let mut results: [Val; 1] = [Val::I64(0)];
    inst.store.set_fuel(FUEL_BUDGET).ok();
    if func
        .call(&mut inst.store, &[Val::I64(a), Val::I64(b)], &mut results)
        .is_err()
    {
        return None;
    }
    match results[0] {
        Val::I64(v) => Some(v),
        _ => None,
    }
}

#[test]
fn signed_unsigned_div_rem_survive_faithful_wat_roundtrip() {
    let original: Vec<u8> = wat::parse_str(SOURCE).expect("assemble source module");
    let lifted_wat: String = lift_module_faithful_wat(&original).expect("faithful lift");
    for op in OPCODES {
        assert!(
            lifted_wat.contains(op),
            "faithful lift dropped or swapped `{op}`:\n{lifted_wat}"
        );
    }
    let lifted_bytes: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must reassemble: {e}\n{lifted_wat}"));

    let eng: Engine = engine();
    let mut orig: Inst = instantiate(&eng, &original);
    let mut lifted: Inst = instantiate(&eng, &lifted_bytes);

    for case in i32_cases() {
        let expected: [(&str, i32); 4] = [
            ("i32_div_s", case.div_s),
            ("i32_div_u", case.div_u),
            ("i32_rem_s", case.rem_s),
            ("i32_rem_u", case.rem_u),
        ];
        for (export, want) in expected {
            let got_orig: Option<i32> = call_i32(&mut orig, export, case.a, case.b);
            let got_lift: Option<i32> = call_i32(&mut lifted, export, case.a, case.b);
            assert_eq!(
                got_orig,
                Some(want),
                "original `{export}` on ({}, {}) must match wasm semantics",
                case.a,
                case.b
            );
            assert_eq!(
                got_lift, got_orig,
                "lifted `{export}` diverged on ({}, {}): original={got_orig:?} lifted={got_lift:?}",
                case.a, case.b
            );
        }
        assert_ne!(
            case.div_s, case.div_u,
            "i32 div operands ({}, {}) must distinguish signed from unsigned",
            case.a, case.b
        );
        assert_ne!(
            case.rem_s, case.rem_u,
            "i32 rem operands ({}, {}) must distinguish signed from unsigned",
            case.a, case.b
        );
    }

    for case in i64_cases() {
        let expected: [(&str, i64); 4] = [
            ("i64_div_s", case.div_s),
            ("i64_div_u", case.div_u),
            ("i64_rem_s", case.rem_s),
            ("i64_rem_u", case.rem_u),
        ];
        for (export, want) in expected {
            let got_orig: Option<i64> = call_i64(&mut orig, export, case.a, case.b);
            let got_lift: Option<i64> = call_i64(&mut lifted, export, case.a, case.b);
            assert_eq!(
                got_orig,
                Some(want),
                "original `{export}` on ({}, {}) must match wasm semantics",
                case.a,
                case.b
            );
            assert_eq!(
                got_lift, got_orig,
                "lifted `{export}` diverged on ({}, {}): original={got_orig:?} lifted={got_lift:?}",
                case.a, case.b
            );
        }
        assert_ne!(
            case.div_s, case.div_u,
            "i64 div operands ({}, {}) must distinguish signed from unsigned",
            case.a, case.b
        );
        assert_ne!(
            case.rem_s, case.rem_u,
            "i64 rem operands ({}, {}) must distinguish signed from unsigned",
            case.a, case.b
        );
    }
}
