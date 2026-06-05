#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{DefragStats, defragment};
use walrus::ir::{BinaryOp, Instr};
use walrus::{
    ConstExpr, ElementId, ElementItems, ElementKind, FunctionBuilder, FunctionId, LocalId, Module,
    RefType, TableId, TypeId, ValType,
};

fn build_call_indirect_module_single_caller() -> Vec<u8> {
    let mut module: Module = Module::default();

    let frag_ty: TypeId = module
        .types
        .add(&[ValType::I32, ValType::I32], &[ValType::I32]);
    let frag_param_a: LocalId = module.locals.add(ValType::I32);
    let frag_param_b: LocalId = module.locals.add(ValType::I32);
    let mut frag_builder: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    frag_builder
        .func_body()
        .local_get(frag_param_a)
        .local_get(frag_param_b)
        .binop(BinaryOp::I32Add);
    let fragment_fid: FunctionId =
        frag_builder.finish(vec![frag_param_a, frag_param_b], &mut module.funcs);

    let table_id: TableId = module.tables.add_local(false, 1, Some(1), RefType::Funcref);
    let element_id: ElementId = module.elements.add(
        ElementKind::Active {
            table: table_id,
            offset: ConstExpr::Value(walrus::ir::Value::I32(0)),
        },
        ElementItems::Functions(vec![fragment_fid]),
    );
    module
        .tables
        .get_mut(table_id)
        .elem_segments
        .insert(element_id);

    let main_param_a: LocalId = module.locals.add(ValType::I32);
    let main_param_b: LocalId = module.locals.add(ValType::I32);
    let mut main_builder: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    main_builder
        .func_body()
        .local_get(main_param_a)
        .local_get(main_param_b)
        .i32_const(0)
        .call_indirect(frag_ty, table_id);
    let main_fid: FunctionId =
        main_builder.finish(vec![main_param_a, main_param_b], &mut module.funcs);
    module.exports.add("main", main_fid);
    module.emit_wasm()
}

fn build_call_indirect_module_multi_caller() -> Vec<u8> {
    let mut module: Module = Module::default();
    let frag_ty: TypeId = module
        .types
        .add(&[ValType::I32, ValType::I32], &[ValType::I32]);
    let frag_param_a: LocalId = module.locals.add(ValType::I32);
    let frag_param_b: LocalId = module.locals.add(ValType::I32);
    let mut frag_builder: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    frag_builder
        .func_body()
        .local_get(frag_param_a)
        .local_get(frag_param_b)
        .binop(BinaryOp::I32Mul);
    let fragment_fid: FunctionId =
        frag_builder.finish(vec![frag_param_a, frag_param_b], &mut module.funcs);

    let table_id: TableId = module.tables.add_local(false, 1, Some(1), RefType::Funcref);
    let element_id: ElementId = module.elements.add(
        ElementKind::Active {
            table: table_id,
            offset: ConstExpr::Value(walrus::ir::Value::I32(0)),
        },
        ElementItems::Functions(vec![fragment_fid]),
    );
    module
        .tables
        .get_mut(table_id)
        .elem_segments
        .insert(element_id);

    let m_param_a: LocalId = module.locals.add(ValType::I32);
    let m_param_b: LocalId = module.locals.add(ValType::I32);
    let mut main_builder: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    main_builder
        .func_body()
        .local_get(m_param_a)
        .local_get(m_param_b)
        .i32_const(0)
        .call_indirect(frag_ty, table_id)
        .local_get(m_param_a)
        .local_get(m_param_b)
        .i32_const(0)
        .call_indirect(frag_ty, table_id)
        .binop(BinaryOp::I32Add);
    let main_fid: FunctionId = main_builder.finish(vec![m_param_a, m_param_b], &mut module.funcs);
    module.exports.add("main", main_fid);
    module.emit_wasm()
}

fn count_call_indirects(module: &Module) -> usize {
    use walrus::ir::Visitor;
    struct Counter {
        n: usize,
    }
    impl Visitor<'_> for Counter {
        fn visit_call_indirect(&mut self, _: &walrus::ir::CallIndirect) {
            self.n += 1;
        }
    }
    let mut total: usize = 0usize;
    for (_id, f) in module.funcs.iter_local() {
        let mut c: Counter = Counter { n: 0 };
        walrus::ir::dfs_in_order(&mut c, f, f.entry_block());
        total += c.n;
    }
    total
}

fn count_direct_calls_to(module: &Module, target: walrus::FunctionId) -> usize {
    use walrus::ir::Visitor;
    struct Counter {
        target: walrus::FunctionId,
        n: usize,
    }
    impl<'instr> Visitor<'instr> for Counter {
        fn visit_instr(&mut self, instr: &'instr Instr, _: &walrus::ir::InstrLocId) {
            if let Instr::Call(c) = instr
                && c.func == self.target
            {
                self.n += 1;
            }
        }
    }
    let mut total: usize = 0usize;
    for (_id, f) in module.funcs.iter_local() {
        let mut c: Counter = Counter { target, n: 0 };
        walrus::ir::dfs_in_order(&mut c, f, f.entry_block());
        total += c.n;
    }
    total
}

#[test]
fn defragment_inlines_single_caller_call_indirect() {
    let bytes: Vec<u8> = build_call_indirect_module_single_caller();
    let pre: Module = Module::from_buffer(&bytes).expect("parse pre");
    assert_eq!(
        count_call_indirects(&pre),
        1,
        "synth module must start with exactly one call_indirect"
    );

    let (out_bytes, stats): (Vec<u8>, DefragStats) = defragment(&bytes).expect("defragment runs");
    assert_eq!(
        stats.fragments_inlined, 1,
        "single-caller call_indirect must be rewritten to a direct call"
    );

    let post: Module = Module::from_buffer(&out_bytes).expect("parse post");
    assert_eq!(
        count_call_indirects(&post),
        0,
        "the call_indirect must be gone post-defrag"
    );

    let main_fid: FunctionId = post
        .exports
        .iter()
        .find(|e| e.name == "main")
        .and_then(|e| match e.item {
            walrus::ExportItem::Function(fid) => Some(fid),
            _ => None,
        })
        .expect("main export must survive");
    let total_direct_calls: usize = post
        .funcs
        .iter_local()
        .filter(|(id, _)| *id == main_fid)
        .map(|(_, f)| {
            use walrus::ir::Visitor;
            struct C {
                n: usize,
            }
            impl<'i> Visitor<'i> for C {
                fn visit_instr(&mut self, i: &'i Instr, _: &walrus::ir::InstrLocId) {
                    if let Instr::Call(_) = i {
                        self.n += 1;
                    }
                }
            }
            let mut c: C = C { n: 0 };
            walrus::ir::dfs_in_order(&mut c, f, f.entry_block());
            c.n
        })
        .sum();
    assert_eq!(
        total_direct_calls, 1,
        "main must contain exactly one direct call after rewrite"
    );
}

#[test]
fn defragment_leaves_multi_caller_dead() {
    let bytes: Vec<u8> = build_call_indirect_module_multi_caller();
    let pre: Module = Module::from_buffer(&bytes).expect("parse pre");
    let pre_count: usize = count_call_indirects(&pre);
    assert_eq!(
        pre_count, 2,
        "multi-caller synth must have two call_indirects"
    );

    let (out_bytes, stats): (Vec<u8>, DefragStats) = defragment(&bytes).expect("defragment");
    assert_eq!(
        stats.fragments_inlined, 0,
        "fragments called >1x must NOT be inlined; got {stats:?}"
    );

    let post: Module = Module::from_buffer(&out_bytes).expect("parse post");
    assert_eq!(
        count_call_indirects(&post),
        2,
        "both call_indirect sites must remain"
    );
    let fragment_fid: Option<FunctionId> = post
        .funcs
        .iter()
        .find(|f| f.name.as_deref() == Some("fragment_target_2x"))
        .map(walrus::Function::id);
    if let Some(fid) = fragment_fid {
        assert_eq!(
            count_direct_calls_to(&post, fid),
            0,
            "no direct calls should have been added for a multi-caller fragment"
        );
    }
}
