#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeSet;

use disrobe_pass_wasm_deob::{
    CanonicalizeStats, DataDecryptStats, DeadFunctionStats, DemangleStats, StubInfo,
    canonicalize_substitutions, decrypt_data_sections, demangle_names, demangle_symbol,
    detect_decrypt_stubs, strip_dead_functions,
};
use walrus::ir::BinaryOp;
use walrus::{ConstExpr, DataKind, FunctionBuilder, FunctionId, Module, ValType};
use wasmparser::{Operator, Parser, Payload, Validator, WasmFeatures};

fn data_segment_bytes(bytes: &[u8]) -> Vec<u8> {
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::DataSection(reader) = payload.expect("payload parses")
            && let Some(seg) = reader.into_iter().flatten().next()
        {
            return seg.data.to_vec();
        }
    }
    Vec::new()
}

fn body_opcodes(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("payload parses") {
            let reader: wasmparser::OperatorsReader<'_> =
                body.get_operators_reader().expect("operators reader");
            for op in reader {
                let op: Operator<'_> = op.expect("operator");
                out.push(
                    format!("{op:?}")
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
            }
        }
    }
    out
}

fn validate(bytes: &[u8]) {
    let mut validator: Validator = Validator::new_with_features(WasmFeatures::all());
    validator
        .validate_all(bytes)
        .expect("reversed module must re-validate against the wasm spec");
}

fn export_names(bytes: &[u8]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::ExportSection(reader) = payload.expect("payload parses") {
            for export in reader.into_iter().flatten() {
                out.insert(export.name.to_owned());
            }
        }
    }
    out
}

fn local_function_count(bytes: &[u8]) -> usize {
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::FunctionSection(reader) = payload.expect("payload parses") {
            return reader.count() as usize;
        }
    }
    0
}

fn add_identity(module: &mut Module, export_name: &str) -> FunctionId {
    let mut builder: FunctionBuilder =
        FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
    let p: walrus::LocalId = module.locals.add(ValType::I32);
    builder.func_body().local_get(p);
    let fid: FunctionId = builder.finish(vec![p], &mut module.funcs);
    module.exports.add(export_name, fid);
    fid
}

fn add_dead_trash(module: &mut Module) -> FunctionId {
    let mut builder: FunctionBuilder =
        FunctionBuilder::new(&mut module.types, &[], &[ValType::I32]);
    builder
        .func_body()
        .i32_const(0xDEAD)
        .i32_const(0xBEEF)
        .binop(walrus::ir::BinaryOp::I32Xor);
    builder.finish(Vec::new(), &mut module.funcs)
}

fn clean_original() -> Vec<u8> {
    let mut module: Module = Module::default();
    add_identity(&mut module, "decode");
    add_identity(&mut module, "run");
    module.emit_wasm()
}

fn obfuscated_pair() -> (Vec<u8>, Vec<u8>) {
    let original: Vec<u8> = clean_original();

    let mut module: Module = Module::default();
    let decode: FunctionId = add_identity(&mut module, "_Z6decodei");
    let _run: FunctionId = add_identity(&mut module, "_Z3runv");
    let _ = decode;
    add_dead_trash(&mut module);
    add_dead_trash(&mut module);
    let obfuscated: Vec<u8> = module.emit_wasm();
    (original, obfuscated)
}

#[test]
fn name_demangle_recovers_original_export_names() {
    let (original, obfuscated): (Vec<u8>, Vec<u8>) = obfuscated_pair();
    assert_ne!(
        export_names(&original),
        export_names(&obfuscated),
        "obfuscated fixture must actually differ from the original"
    );

    let (reversed, stats): (Vec<u8>, DemangleStats) =
        demangle_names(&obfuscated).expect("demangle succeeds");
    validate(&reversed);

    assert_eq!(stats.exports_demangled, 2, "both _Z exports demangled");
    let recovered: BTreeSet<String> = export_names(&reversed);
    assert!(recovered.contains("decode"), "decode export recovered");
    assert!(recovered.contains("run"), "run export recovered");
    assert_eq!(
        recovered,
        export_names(&original),
        "demangled export-name set must structurally match the clean original"
    );
}

#[test]
fn dead_function_removal_matches_original_body_count() {
    let (original, obfuscated): (Vec<u8>, Vec<u8>) = obfuscated_pair();
    assert_eq!(
        local_function_count(&obfuscated),
        4,
        "obfuscated has 2 live + 2 trash functions"
    );

    let (reversed, stats): (Vec<u8>, DeadFunctionStats) =
        strip_dead_functions(&obfuscated).expect("strip succeeds");
    validate(&reversed);

    assert_eq!(stats.removed, 2, "both trash functions removed");
    assert_eq!(
        local_function_count(&reversed),
        local_function_count(&original),
        "live function count must match the clean original"
    );
}

#[test]
fn full_reverse_pipeline_reaches_original_shape() {
    let (original, obfuscated): (Vec<u8>, Vec<u8>) = obfuscated_pair();

    let (after_dead, _): (Vec<u8>, DeadFunctionStats) =
        strip_dead_functions(&obfuscated).expect("strip succeeds");
    let (reversed, _): (Vec<u8>, DemangleStats) =
        demangle_names(&after_dead).expect("demangle succeeds");
    validate(&reversed);

    assert_eq!(
        export_names(&reversed),
        export_names(&original),
        "pipeline export set matches original"
    );
    assert_eq!(
        local_function_count(&reversed),
        local_function_count(&original),
        "pipeline function count matches original"
    );
}

#[test]
fn demangle_is_idempotent_on_clean_module() {
    let original: Vec<u8> = clean_original();
    let (reversed, stats): (Vec<u8>, DemangleStats) =
        demangle_names(&original).expect("clean module demangles to no-op");
    validate(&reversed);
    assert_eq!(stats.exports_demangled, 0, "clean names are untouched");
    assert_eq!(export_names(&reversed), export_names(&original));
}

#[test]
fn demangle_symbol_unit_cases() {
    assert_eq!(demangle_symbol("_Z6decodei").as_deref(), Some("decode"));
    assert_eq!(demangle_symbol("_Z3runv").as_deref(), Some("run"));
    assert_eq!(demangle_symbol("main"), None);
}

fn clean_arith_module() -> Vec<u8> {
    let mut module: Module = Module::default();
    let mut builder: FunctionBuilder =
        FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
    let p: walrus::LocalId = module.locals.add(ValType::I32);
    builder
        .func_body()
        .local_get(p)
        .i32_const(5)
        .binop(BinaryOp::I32Add);
    let fid: FunctionId = builder.finish(vec![p], &mut module.funcs);
    module.exports.add("f", fid);
    module.emit_wasm()
}

fn mutated_arith_module() -> Vec<u8> {
    let mut module: Module = Module::default();
    let mut builder: FunctionBuilder =
        FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
    let p: walrus::LocalId = module.locals.add(ValType::I32);
    builder
        .func_body()
        .local_get(p)
        .i32_const(0)
        .binop(BinaryOp::I32Add)
        .i32_const(1)
        .binop(BinaryOp::I32Mul)
        .i32_const(5)
        .binop(BinaryOp::I32Add)
        .i32_const(0)
        .binop(BinaryOp::I32Or);
    let fid: FunctionId = builder.finish(vec![p], &mut module.funcs);
    module.exports.add("f", fid);
    module.emit_wasm()
}

#[test]
fn canonicalize_folds_identity_trash_to_original_shape() {
    let original: Vec<u8> = clean_arith_module();
    let mutated: Vec<u8> = mutated_arith_module();
    assert_ne!(
        body_opcodes(&original),
        body_opcodes(&mutated),
        "mutated fixture must differ from the clean original"
    );

    let (reversed, stats): (Vec<u8>, CanonicalizeStats) =
        canonicalize_substitutions(&mutated).expect("canonicalize succeeds");
    validate(&reversed);

    assert_eq!(
        stats.identity_ops_folded, 3,
        "x+0, x*1, x|0 are the three identity trash pairs"
    );
    assert_eq!(
        body_opcodes(&reversed),
        body_opcodes(&original),
        "reversed body opcode sequence must structurally match the clean original"
    );
}

#[test]
fn canonicalize_is_noop_on_clean_module() {
    let original: Vec<u8> = clean_arith_module();
    let (reversed, stats): (Vec<u8>, CanonicalizeStats) =
        canonicalize_substitutions(&original).expect("clean module canonicalizes to no-op");
    validate(&reversed);
    assert_eq!(stats.identity_ops_folded, 0, "no identity trash present");
    assert_eq!(body_opcodes(&reversed), body_opcodes(&original));
}

const PLAINTEXT: &[u8] = b"HELLO_DISROBE_WASM";
const XOR_KEY: u8 = 0x5a;

fn add_xor_decrypt_stub(module: &mut Module) {
    use walrus::ir::{BinaryOp as Op, ExtendedLoad, LoadKind, MemArg, StoreKind};
    let memory_id: walrus::MemoryId = module.memories.add_local(false, false, 1, Some(1), None);
    let mut builder: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    let off: walrus::LocalId = module.locals.add(ValType::I32);
    let len: walrus::LocalId = module.locals.add(ValType::I32);
    let cursor: walrus::LocalId = module.locals.add(ValType::I32);
    let remaining: walrus::LocalId = module.locals.add(ValType::I32);
    let mem_arg: MemArg = MemArg {
        align: 0,
        offset: 0,
    };
    {
        let mut body: walrus::InstrSeqBuilder<'_> = builder.func_body();
        body.local_get(off)
            .local_set(cursor)
            .local_get(len)
            .local_set(remaining)
            .loop_(None, |loop_| {
                let loop_id: walrus::ir::InstrSeqId = loop_.id();
                loop_.local_get(remaining).if_else(
                    None,
                    |then| {
                        then.local_get(cursor)
                            .local_get(cursor)
                            .load(
                                memory_id,
                                LoadKind::I32_8 {
                                    kind: ExtendedLoad::ZeroExtend,
                                },
                                mem_arg,
                            )
                            .i32_const(i32::from(XOR_KEY))
                            .binop(Op::I32Xor)
                            .store(memory_id, StoreKind::I32_8 { atomic: false }, mem_arg)
                            .local_get(cursor)
                            .i32_const(1)
                            .binop(Op::I32Add)
                            .local_set(cursor)
                            .local_get(remaining)
                            .i32_const(1)
                            .binop(Op::I32Sub)
                            .local_set(remaining)
                            .br(loop_id);
                    },
                    |_else| {},
                );
            })
            .local_get(off);
    }
    let fid: FunctionId = builder.finish(vec![off, len], &mut module.funcs);
    module.exports.add("decrypt", fid);
}

fn clean_data_module() -> Vec<u8> {
    let mut module: Module = Module::default();
    add_xor_decrypt_stub(&mut module);
    let mid: walrus::MemoryId = module.memories.iter().next().expect("memory exists").id();
    module.data.add(
        DataKind::Active {
            memory: mid,
            offset: ConstExpr::Value(walrus::ir::Value::I32(0)),
        },
        PLAINTEXT.to_vec(),
    );
    module.emit_wasm()
}

fn encrypted_data_module() -> Vec<u8> {
    let mut module: Module = Module::default();
    add_xor_decrypt_stub(&mut module);
    let mid: walrus::MemoryId = module.memories.iter().next().expect("memory exists").id();
    let encrypted: Vec<u8> = PLAINTEXT.iter().map(|b| b ^ XOR_KEY).collect();
    module.data.add(
        DataKind::Active {
            memory: mid,
            offset: ConstExpr::Value(walrus::ir::Value::I32(0)),
        },
        encrypted,
    );
    module.emit_wasm()
}

#[test]
fn data_section_decrypt_recovers_plaintext_via_emulated_key() {
    let original: Vec<u8> = clean_data_module();
    let obfuscated: Vec<u8> = encrypted_data_module();
    assert_ne!(
        data_segment_bytes(&original),
        data_segment_bytes(&obfuscated),
        "encrypted data must differ from plaintext"
    );

    let stubs: Vec<StubInfo> = detect_decrypt_stubs(&obfuscated).expect("stub detection runs");
    let key: u8 = stubs
        .iter()
        .find_map(|s| s.key)
        .expect("constant XOR key recovered from stub");
    assert_eq!(key, XOR_KEY, "recovered key must match the obfuscator key");

    let (reversed, stats): (Vec<u8>, DataDecryptStats) =
        decrypt_data_sections(&obfuscated, key).expect("static decrypt succeeds");
    validate(&reversed);

    assert_eq!(
        stats.segments_decrypted, 1,
        "the single data segment decrypted"
    );
    assert_eq!(stats.bytes_decrypted, PLAINTEXT.len());
    assert_eq!(
        data_segment_bytes(&reversed),
        PLAINTEXT.to_vec(),
        "statically decrypted data must equal the clean original plaintext"
    );
    assert_eq!(
        data_segment_bytes(&reversed),
        data_segment_bytes(&original),
        "reversed data segment must structurally match the clean original"
    );
}
