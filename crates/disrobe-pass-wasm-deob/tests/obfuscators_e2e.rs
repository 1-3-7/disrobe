#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::redundant_pub_crate,
    clippy::cast_possible_truncation,
    unreachable_pub
)]

use disrobe_pass_wasm_deob::{
    BlockId, BlockTarget, CalleeNames, ConstVal, DispatcherInfo, FunctionCfg, FunctionSig,
    IntegrityStripStats, LiftResult, LiftTarget, LoadKind, NameStrategy, OpKind, OpaquePredStats,
    SideEffect, SsaBlock, SsaFunction, SsaMemArg, SsaTerm, StoreKind, StubInfo, UnflattenStats,
    ValueDef, ValueId, WasmDetection, WasmObfuscator, WobfuscatorTable, build_function_cfg,
    classify_export_strategy, detect, detect_decrypt_stubs, detect_dispatcher, extract_optable,
    kill_opaque_predicates, lift_function_body, lift_op_to_rust_fn, strip_integrity_imports,
    unflatten,
};
use smallvec::{SmallVec, smallvec};
use walrus::ir::{BinaryOp, LoadKind as WLoadKind, MemArg, StoreKind as WStoreKind};
use walrus::{FunctionBuilder, Module, ValType};
use wasmparser::{Parser, Payload, ValType as WpValType};

mod helpers {
    use super::*;

    pub fn minimal_identity_module() -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f]);
        out.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        out.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00]);
        let body: [u8; 4] = [0x00, 0x20, 0x00, 0x0b];
        out.extend_from_slice(&[0x0a, 0x06, 0x01]);
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
        out
    }

    pub fn module_with_short_exports() -> Vec<u8> {
        let mut module: Module = Module::default();
        for name in ["a", "b", "c", "d"] {
            let mut b: FunctionBuilder =
                FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
            let p: walrus::LocalId = module.locals.add(ValType::I32);
            b.func_body().local_get(p);
            let fid: walrus::FunctionId = b.finish(vec![p], &mut module.funcs);
            module.exports.add(name, fid);
        }
        module.emit_wasm()
    }

    pub fn module_with_emscripten_mangled_export() -> Vec<u8> {
        let mut module: Module = Module::default();
        let mut b: FunctionBuilder =
            FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
        let p: walrus::LocalId = module.locals.add(ValType::I32);
        b.func_body().local_get(p);
        let fid: walrus::FunctionId = b.finish(vec![p], &mut module.funcs);
        module.exports.add("_Z3foov", fid);
        module.emit_wasm()
    }

    pub fn module_with_jscrambler_import_and_call() -> Vec<u8> {
        let mut module: Module = Module::default();
        let ty: walrus::TypeId = module.types.add(&[], &[]);
        let (imp_fid, _): (walrus::FunctionId, walrus::ImportId) =
            module.add_import_func("env", "__jscrambler_integrity", ty);
        let mut builder: FunctionBuilder = FunctionBuilder::new(&mut module.types, &[], &[]);
        builder.func_body().call(imp_fid);
        let main_fid: walrus::FunctionId = builder.finish(Vec::new(), &mut module.funcs);
        module.exports.add("main", main_fid);
        module.emit_wasm()
    }

    pub fn module_with_eval_exports() -> Vec<u8> {
        let mut module: Module = Module::default();
        for (name, op) in [
            ("eval0", BinaryOp::I32Add),
            ("eval1", BinaryOp::I32Sub),
            ("eval2", BinaryOp::I32Xor),
        ] {
            let mut b: FunctionBuilder = FunctionBuilder::new(
                &mut module.types,
                &[ValType::I32, ValType::I32],
                &[ValType::I32],
            );
            let a: walrus::LocalId = module.locals.add(ValType::I32);
            let c: walrus::LocalId = module.locals.add(ValType::I32);
            b.func_body().local_get(a).local_get(c).binop(op);
            let fid: walrus::FunctionId = b.finish(vec![a, c], &mut module.funcs);
            module.exports.add(name, fid);
        }
        module.emit_wasm()
    }

    pub fn module_with_xor_decrypt_stub(key: u8) -> Vec<u8> {
        let mut module: Module = Module::default();
        let memory_id: walrus::MemoryId = module.memories.add_local(false, false, 1, Some(1), None);
        let mut builder: FunctionBuilder = FunctionBuilder::new(
            &mut module.types,
            &[ValType::I32, ValType::I32],
            &[ValType::I32],
        );
        let off_param: walrus::LocalId = module.locals.add(ValType::I32);
        let len_param: walrus::LocalId = module.locals.add(ValType::I32);
        let cursor: walrus::LocalId = module.locals.add(ValType::I32);
        let remaining: walrus::LocalId = module.locals.add(ValType::I32);
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
                                    WLoadKind::I32_8 {
                                        kind: walrus::ir::ExtendedLoad::ZeroExtend,
                                    },
                                    mem_arg,
                                )
                                .i32_const(i32::from(key))
                                .binop(BinaryOp::I32Xor)
                                .store(memory_id, WStoreKind::I32_8 { atomic: false }, mem_arg)
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
        let fid: walrus::FunctionId = builder.finish(vec![off_param, len_param], &mut module.funcs);
        module.exports.add("decrypt", fid);
        module.emit_wasm()
    }

    pub const fn memarg() -> SsaMemArg {
        SsaMemArg {
            align: 2,
            offset: 0,
            memory: 0,
        }
    }

    pub fn block_target(b: u32) -> BlockTarget {
        BlockTarget {
            block: BlockId(b),
            args: SmallVec::new(),
        }
    }

    pub fn const_eq_brif_ssa(a: i32, b: i32) -> SsaFunction {
        let values: Vec<ValueDef> = vec![
            ValueDef::Const(ConstVal::I32(a)),
            ValueDef::Const(ConstVal::I32(b)),
            ValueDef::Op {
                kind: OpKind::I32Eq,
                args: smallvec![ValueId(0), ValueId(1)],
                ty: WpValType::I32,
            },
        ];
        let blocks: Vec<SsaBlock> = vec![
            SsaBlock {
                id: BlockId(0),
                params: SmallVec::new(),
                instrs: vec![ValueId(0), ValueId(1), ValueId(2)],
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::BrIf {
                    cond: ValueId(2),
                    then_t: block_target(1),
                    else_t: block_target(2),
                },
                preds: Vec::new(),
            },
            SsaBlock {
                id: BlockId(1),
                params: SmallVec::new(),
                instrs: Vec::new(),
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Return(SmallVec::new()),
                preds: vec![BlockId(0)],
            },
            SsaBlock {
                id: BlockId(2),
                params: SmallVec::new(),
                instrs: Vec::new(),
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Return(SmallVec::new()),
                preds: vec![BlockId(0)],
            },
        ];
        SsaFunction {
            values,
            blocks,
            entry: BlockId(0),
        }
    }

    pub fn three_state_dispatcher_ssa() -> SsaFunction {
        let values: Vec<ValueDef> = vec![
            ValueDef::Param(BlockId(0), 0),
            ValueDef::Load {
                addr: ValueId(0),
                memarg: memarg(),
                kind: LoadKind::I32,
                ty: WpValType::I32,
            },
            ValueDef::Const(ConstVal::I32(0)),
            ValueDef::Const(ConstVal::I32(1)),
            ValueDef::Const(ConstVal::I32(2)),
        ];
        let dispatcher: SsaBlock = SsaBlock {
            id: BlockId(0),
            params: SmallVec::new(),
            instrs: vec![ValueId(0), ValueId(1)],
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::BrTable {
                idx: ValueId(1),
                targets: vec![block_target(1), block_target(2), block_target(3)],
                default: block_target(4),
            },
            preds: vec![BlockId(1), BlockId(2), BlockId(3)],
        };
        let case0: SsaBlock = SsaBlock {
            id: BlockId(1),
            params: SmallVec::new(),
            instrs: vec![ValueId(3)],
            stores: vec![SideEffect {
                addr: ValueId(0),
                val: ValueId(3),
                memarg: memarg(),
                kind: StoreKind::I32,
            }],
            global_sets: Vec::new(),
            terminator: SsaTerm::Br(block_target(0)),
            preds: vec![BlockId(0)],
        };
        let case1: SsaBlock = SsaBlock {
            id: BlockId(2),
            params: SmallVec::new(),
            instrs: vec![ValueId(4)],
            stores: vec![SideEffect {
                addr: ValueId(0),
                val: ValueId(4),
                memarg: memarg(),
                kind: StoreKind::I32,
            }],
            global_sets: Vec::new(),
            terminator: SsaTerm::Br(block_target(0)),
            preds: vec![BlockId(0)],
        };
        let case2_exit: SsaBlock = SsaBlock {
            id: BlockId(3),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::Return(SmallVec::new()),
            preds: vec![BlockId(0)],
        };
        let default_exit: SsaBlock = SsaBlock {
            id: BlockId(4),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::Unreachable,
            preds: vec![BlockId(0)],
        };
        SsaFunction {
            values,
            blocks: vec![dispatcher, case0, case1, case2_exit, default_exit],
            entry: BlockId(0),
        }
    }
}

#[test]
fn name_obfuscator_detect_and_classify_strategy() {
    let bytes: Vec<u8> = helpers::module_with_short_exports();
    let det: WasmDetection =
        detect(&bytes).expect("detect must parse synth name-obfuscator module");
    assert_eq!(
        det.obfuscator,
        WasmObfuscator::WasmNameObfuscator,
        "short-only-exports + no name-section must fingerprint WasmNameObfuscator"
    );
    assert!(det.confidence >= 0.5, "confidence must clear reporting bar");

    let hex_names: Vec<String> = vec![
        "36c4abdf9f8e2bcd".into(),
        "a1b2c3d4deadbeef".into(),
        "0123456789abcdef".into(),
        "f0e1d2c3b4a59687".into(),
        "8a7b6c5d4e3f2a1b".into(),
    ];
    let strategy: NameStrategy = classify_export_strategy(&hex_names);
    assert_eq!(
        strategy,
        NameStrategy::Hex,
        "high-entropy hex export names must classify as Hex strategy"
    );

    let clean_strategy: NameStrategy =
        classify_export_strategy(&["main".to_owned(), "run".to_owned(), "init".to_owned()]);
    assert_eq!(
        clean_strategy,
        NameStrategy::Clean,
        "low-entropy english names must classify as Clean"
    );
}

#[test]
fn jscrambler_detect_then_strip_and_fold_opaque() {
    let bytes: Vec<u8> = helpers::module_with_jscrambler_import_and_call();
    let det: WasmDetection = detect(&bytes).expect("detect must parse jscrambler synth module");
    assert_eq!(
        det.import_count, 1,
        "jscrambler synth module must report its single import"
    );
    assert!(
        det.confidence <= 0.5 || matches!(det.obfuscator, WasmObfuscator::Unknown),
        "synth-minimal jscrambler module is too small for classify(); confidence stays low"
    );

    let (stripped_bytes, strip_stats): (Vec<u8>, IntegrityStripStats) =
        strip_integrity_imports(&bytes, &["__jscrambler_"]).expect("strip succeeds");
    assert_eq!(
        strip_stats.imports_removed, 1,
        "the single jscrambler import must be removed"
    );
    assert_eq!(strip_stats.call_sites_rewritten, 1);
    let post: Module = Module::from_buffer(&stripped_bytes).expect("post-strip module re-parses");
    assert!(
        post.imports.find("env", "__jscrambler_integrity").is_none(),
        "jscrambler import must be gone post-strip"
    );

    let mut ssa: SsaFunction = helpers::const_eq_brif_ssa(7, 7);
    let opaque_stats: OpaquePredStats = kill_opaque_predicates(&mut ssa);
    assert_eq!(opaque_stats.found, 1);
    assert_eq!(opaque_stats.folded_true, 1);
    match &ssa.blocks[0].terminator {
        SsaTerm::Br(target) => assert_eq!(
            target.block,
            BlockId(1),
            "always-true opaque must rewrite to br(then_t)"
        ),
        other => panic!("expected Br after fold, got {other:?}"),
    }
}

#[test]
fn wobfuscator_extract_optable_and_lift_each_eval() {
    let bytes: Vec<u8> = helpers::module_with_eval_exports();
    let det: WasmDetection = detect(&bytes).expect("detect must parse wobfuscator synth module");
    assert_eq!(det.export_count, 3, "synth must report 3 exports");

    let table: WobfuscatorTable = extract_optable(&bytes).expect("extract must succeed");
    assert_eq!(table.entries.len(), 3, "all 3 eval* exports must be lifted");
    assert_eq!(table.entries.get("eval0"), Some(&OpKind::I32Add));
    assert_eq!(table.entries.get("eval1"), Some(&OpKind::I32Sub));
    assert_eq!(table.entries.get("eval2"), Some(&OpKind::I32Xor));
    assert!(table.sidecar_json.contains("\"eval0\""));

    for (name, op) in &table.entries {
        let lifted: String = lift_op_to_rust_fn(name, *op);
        assert!(
            lifted.starts_with("pub fn "),
            "lifted Rust fn must start with pub fn, got {lifted:?}"
        );
        assert!(
            lifted.contains("(a: i32, b: i32) -> i32"),
            "lifted fn must have canonical i32 binary signature, got {lifted:?}"
        );
    }
}

#[test]
fn tigress_detect_emscripten_then_unflatten_dispatcher() {
    let bytes: Vec<u8> = helpers::module_with_emscripten_mangled_export();
    let det: WasmDetection = detect(&bytes).expect("detect must parse emscripten synth module");
    assert_eq!(
        det.obfuscator,
        WasmObfuscator::TigressEmscripten,
        "_Z-prefixed export must fingerprint as TigressEmscripten"
    );
    assert!(
        det.markers.iter().any(|m| m.contains("emscripten")),
        "TigressEmscripten markers must mention emscripten"
    );

    let mut ssa: SsaFunction = helpers::three_state_dispatcher_ssa();
    let info: DispatcherInfo =
        detect_dispatcher(&ssa).expect("3-state synth must satisfy dispatcher invariants");
    assert_eq!(info.header, BlockId(0));
    assert_eq!(info.cases.len(), 3);

    let stats: UnflattenStats = unflatten(&mut ssa, &info);
    assert_eq!(
        stats.cases_inlined, 2,
        "case0 + case1 must rewrite their Br back-edges"
    );
    assert!(
        matches!(ssa.blocks[0].terminator, SsaTerm::Unreachable),
        "dispatcher header must be marked Unreachable post-unflatten"
    );
}

#[test]
fn wasmixer_detect_decrypt_stub_via_direct_api() {
    let bytes: Vec<u8> = helpers::module_with_xor_decrypt_stub(0x5a);
    let det: WasmDetection = detect(&bytes).expect("detect must parse wasmixer synth module");
    assert_eq!(
        det.function_count, 1,
        "synth must report one local function"
    );

    let stubs: Vec<StubInfo> = detect_decrypt_stubs(&bytes).expect("stub detection must run");
    assert!(
        !stubs.is_empty(),
        "the synth XOR-walk loop must be classified as a decrypt stub"
    );
    let stub: &StubInfo = &stubs[0];
    assert!(
        stub.confidence > 0.5,
        "stub confidence must clear reporting threshold (got {})",
        stub.confidence
    );
    assert_eq!(stub.key, Some(0x5a), "the constant XOR key must round-trip");
    assert!(
        stub.op_histogram.contains_key("i32.xor"),
        "histogram must record the keying op"
    );
    assert!(
        stub.op_histogram.contains_key("i32.load8_u"),
        "histogram must record the byte-walking load"
    );
    assert!(
        stub.op_histogram.contains_key("i32.store8"),
        "histogram must record the byte-walking store"
    );
}

#[test]
fn full_pipeline_smoke_detect_through_lift() {
    let bytes: Vec<u8> = helpers::minimal_identity_module();
    let det: WasmDetection = detect(&bytes).expect("detect must parse minimal identity module");
    assert_eq!(det.function_count, 1);
    assert_eq!(det.export_count, 1);

    let sig: FunctionSig = FunctionSig {
        name: "identity".to_owned(),
        params: vec![WpValType::I32],
        results: vec![WpValType::I32],
        exported: true,
        imported: false,
    };
    let callees: CalleeNames = CalleeNames::new(Vec::new());
    let mut visited: bool = false;
    for payload in Parser::new(0).parse_all(&bytes) {
        let payload: Payload<'_> = payload.expect("payload parses");
        if let Payload::CodeSectionEntry(body) = payload {
            let cfg: FunctionCfg = build_function_cfg(&body).expect("cfg builds");
            assert!(!cfg.blocks.is_empty(), "cfg must yield at least one block");

            let lifted: LiftResult = lift_function_body(&body, &sig, &callees, LiftTarget::Rust);
            assert!(
                lifted
                    .pseudo_source
                    .contains("pub fn identity(p0: i32) -> i32"),
                "Rust lift must emit the real signature, got:\n{}",
                lifted.pseudo_source
            );
            assert!(
                !lifted.pseudo_source.contains("fn lifted()"),
                "no hardcoded fn lifted() wrapper"
            );
            assert!(lifted.blocks_emitted >= 1);

            let lifted_ts: LiftResult =
                lift_function_body(&body, &sig, &callees, LiftTarget::TypeScript);
            assert!(
                lifted_ts
                    .pseudo_source
                    .contains("export function identity(p0: number): number"),
                "TS lift must emit the real signature, got:\n{}",
                lifted_ts.pseudo_source
            );
            visited = true;
        }
    }
    assert!(visited, "module must contain at least one code body");
}
