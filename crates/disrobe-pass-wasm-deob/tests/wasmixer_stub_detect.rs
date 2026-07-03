#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{StubInfo, detect_decrypt_stubs};
use walrus::ir::{BinaryOp, LoadKind, MemArg, StoreKind};
use walrus::{FunctionBuilder, FunctionId, LocalId, MemoryId, Module, ValType};

fn build_module_with_xor_decrypt_stub(key: u8) -> Vec<u8> {
    let mut module: Module = Module::default();
    let memory_id: MemoryId = module.memories.add_local(false, false, 1, Some(1), None);

    let mut builder: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    let off_param: LocalId = module.locals.add(ValType::I32);
    let len_param: LocalId = module.locals.add(ValType::I32);
    let cursor: LocalId = module.locals.add(ValType::I32);
    let remaining: LocalId = module.locals.add(ValType::I32);

    let mem_arg: MemArg = MemArg {
        align: 0,
        offset: 0,
    };

    {
        let mut body = builder.func_body();
        body.local_get(off_param)
            .local_set(cursor)
            .local_get(len_param)
            .local_set(remaining)
            .loop_(None, |loop_| {
                let loop_id = loop_.id();
                loop_.local_get(remaining).if_else(
                    None,
                    |then| {
                        then.local_get(cursor)
                            .local_get(cursor)
                            .load(
                                memory_id,
                                LoadKind::I32_8 {
                                    kind: walrus::ir::ExtendedLoad::ZeroExtend,
                                },
                                mem_arg,
                            )
                            .i32_const(i32::from(key))
                            .binop(BinaryOp::I32Xor)
                            .store(memory_id, StoreKind::I32_8 { atomic: false }, mem_arg)
                            .local_get(cursor)
                            .i32_const(1)
                            .binop(BinaryOp::I32Add)
                            .local_set(cursor)
                            .local_get(remaining)
                            .i32_const(1)
                            .binop(BinaryOp::I32Sub)
                            .local_set(remaining)
                            .br(loop_id);
                    },
                    |_else| {},
                );
            })
            .local_get(off_param);
    }

    let fid: FunctionId = builder.finish(vec![off_param, len_param], &mut module.funcs);
    module.exports.add("decrypt", fid);
    module.emit_wasm()
}

fn build_module_with_regular_fn() -> Vec<u8> {
    let mut module: Module = Module::default();
    let mut builder: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    let a: LocalId = module.locals.add(ValType::I32);
    let b: LocalId = module.locals.add(ValType::I32);
    builder
        .func_body()
        .local_get(a)
        .local_get(b)
        .binop(BinaryOp::I32Add);
    let fid: FunctionId = builder.finish(vec![a, b], &mut module.funcs);
    module.exports.add("add", fid);
    module.emit_wasm()
}

#[test]
fn detect_decrypt_stub_with_xor_pattern() {
    let bytes: Vec<u8> = build_module_with_xor_decrypt_stub(0x42);
    let stubs: Vec<StubInfo> = detect_decrypt_stubs(&bytes).expect("detect");
    assert!(
        !stubs.is_empty(),
        "must classify the synthesised xor-loop stub as a decrypt helper"
    );
    let stub: &StubInfo = &stubs[0];
    assert!(
        stub.confidence > 0.5,
        "confidence must clear the 0.5 reporting threshold; got {}",
        stub.confidence
    );
    assert_eq!(
        stub.key,
        Some(0x42),
        "the constant XOR key must be recovered"
    );
    assert!(
        stub.op_histogram.contains_key("i32.load8_u"),
        "histogram must record the byte-walking load"
    );
    assert!(
        stub.op_histogram.contains_key("i32.store8"),
        "histogram must record the byte-walking store"
    );
    assert!(
        stub.op_histogram.contains_key("i32.xor"),
        "histogram must record the keying op"
    );
}

#[test]
fn detect_skips_non_stub_functions() {
    let bytes: Vec<u8> = build_module_with_regular_fn();
    let stubs: Vec<StubInfo> = detect_decrypt_stubs(&bytes).expect("detect");
    assert!(
        stubs.is_empty(),
        "a plain `a + b` fn must not classify as a decrypt stub; got {} match(es)",
        stubs.len()
    );
}
