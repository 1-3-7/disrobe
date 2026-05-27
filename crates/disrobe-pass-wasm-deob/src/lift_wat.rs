use std::fmt::Write;

use crate::cfg::BlockId;
use crate::lift::{LiftResult, LiftTarget};
use crate::ssa::{ConstVal, OpKind, SsaBlock, SsaFunction, SsaTerm, ValueDef};
use crate::structure::{StructuredFunction, StructuredNode};
use crate::types::{LoadKind, StoreKind};

#[must_use]
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn lift_to_wat(func: &StructuredFunction, ssa: &SsaFunction) -> LiftResult {
    let mut body: String = String::new();
    let mut emitted: usize = 0usize;
    let result_ty: &'static str = wat_func_result(ssa);
    emit_node(&func.root, ssa, &mut body, 2, &mut emitted);
    let mut wrapped: String = String::with_capacity(body.len() + 96);
    wrapped.push_str("(module\n");
    if result_ty.is_empty() {
        wrapped.push_str("  (func $lifted\n");
    } else {
        let _ = writeln!(wrapped, "  (func $lifted (result {result_ty})");
    }
    wrapped.push_str(&body);
    wrapped.push_str("  )\n");
    wrapped.push_str("  (export \"lifted\" (func $lifted))\n");
    wrapped.push_str(")\n");
    LiftResult {
        target: LiftTarget::Wat,
        pseudo_source: wrapped,
        blocks_emitted: emitted,
    }
}

fn wat_func_result(ssa: &SsaFunction) -> &'static str {
    for block in &ssa.blocks {
        if let SsaTerm::Return(vals) = &block.terminator {
            if !vals.is_empty() {
                return "i32";
            }
        }
    }
    ""
}

fn emit_node(
    node: &StructuredNode,
    ssa: &SsaFunction,
    out: &mut String,
    depth: usize,
    emitted: &mut usize,
) {
    let indent: String = "  ".repeat(depth);
    match node {
        StructuredNode::Sequence(children) => {
            for child in children {
                emit_node(child, ssa, out, depth, emitted);
            }
        }
        StructuredNode::Block(id) | StructuredNode::Return(id) => {
            emit_block(*id, ssa, out, depth);
            *emitted += 1;
        }
        StructuredNode::If {
            condition_block,
            then_branch,
            else_branch,
        } => {
            emit_block(*condition_block, ssa, out, depth);
            let _ = writeln!(out, "{indent}(if");
            let _ = writeln!(out, "{indent}  (then");
            emit_node(then_branch, ssa, out, depth + 2, emitted);
            let _ = writeln!(out, "{indent}  )");
            if let Some(e) = else_branch {
                let _ = writeln!(out, "{indent}  (else");
                emit_node(e, ssa, out, depth + 2, emitted);
                let _ = writeln!(out, "{indent}  )");
            }
            let _ = writeln!(out, "{indent})");
        }
        StructuredNode::While { header, body } => {
            let _ = writeln!(out, "{indent}(loop $loop_{}", header.0);
            emit_block(*header, ssa, out, depth + 1);
            emit_node(body, ssa, out, depth + 1, emitted);
            let _ = writeln!(out, "{indent})");
        }
    }
}

fn find_block(ssa: &SsaFunction, id: BlockId) -> Option<&SsaBlock> {
    ssa.blocks.iter().find(|b| b.id == id)
}

fn emit_block(id: BlockId, ssa: &SsaFunction, out: &mut String, depth: usize) {
    let indent: String = "  ".repeat(depth);
    let Some(block): Option<&SsaBlock> = find_block(ssa, id) else {
        let _ = writeln!(out, "{indent};; block {} missing ssa", id.0);
        return;
    };
    for vid in &block.instrs {
        let Some(def): Option<&ValueDef> = ssa.values.get(vid.0 as usize) else {
            continue;
        };
        match def {
            ValueDef::Param(_, idx) => {
                let _ = writeln!(out, "{indent}local.get {idx}");
            }
            ValueDef::Const(c) => emit_const(c, out, &indent),
            ValueDef::Op { kind, args, .. } => {
                for a in args {
                    if let Some(ValueDef::Param(_, idx)) = ssa.values.get(a.0 as usize) {
                        let _ = writeln!(out, "{indent}local.get {idx}");
                    }
                }
                let _ = writeln!(out, "{indent}{}", op_mnemonic(*kind));
            }
            ValueDef::Load { memarg, kind, .. } => {
                let _ = writeln!(
                    out,
                    "{indent}{} offset={} align={}",
                    load_mnemonic(*kind),
                    memarg.offset,
                    1u32 << memarg.align
                );
            }
            ValueDef::Phi { .. } => {}
        }
    }
    for store in &block.stores {
        let _ = writeln!(
            out,
            "{indent}{} offset={} align={}",
            store_mnemonic(store.kind),
            store.memarg.offset,
            1u32 << store.memarg.align
        );
    }
    match &block.terminator {
        SsaTerm::Return(_) => {
            let _ = writeln!(out, "{indent}return");
        }
        SsaTerm::Unreachable => {
            let _ = writeln!(out, "{indent}unreachable");
        }
        SsaTerm::Br(t) => {
            let _ = writeln!(out, "{indent}br {}", t.block.0);
        }
        SsaTerm::BrIf { then_t, .. } => {
            let _ = writeln!(out, "{indent}br_if {}", then_t.block.0);
        }
        SsaTerm::BrTable { targets, .. } => {
            let _ = writeln!(out, "{indent}br_table arms={}", targets.len());
        }
        SsaTerm::Fallthrough(_) => {}
    }
}

fn emit_const(c: &ConstVal, out: &mut String, indent: &str) {
    match c {
        ConstVal::I32(n) => {
            let _ = writeln!(out, "{indent}i32.const {n}");
        }
        ConstVal::I64(n) => {
            let _ = writeln!(out, "{indent}i64.const {n}");
        }
        ConstVal::F32Bits(b) => {
            let v: f32 = f32::from_bits(*b);
            let _ = writeln!(out, "{indent}f32.const {v}");
        }
        ConstVal::F64Bits(b) => {
            let v: f64 = f64::from_bits(*b);
            let _ = writeln!(out, "{indent}f64.const {v}");
        }
        ConstVal::Bytes(bytes) => {
            let _ = writeln!(out, "{indent};; raw bytes len={}", bytes.len());
        }
    }
}

const fn op_mnemonic(kind: OpKind) -> &'static str {
    match kind {
        OpKind::I32Add => "i32.add",
        OpKind::I32Sub => "i32.sub",
        OpKind::I32Mul => "i32.mul",
        OpKind::I32And => "i32.and",
        OpKind::I32Or => "i32.or",
        OpKind::I32Xor => "i32.xor",
        OpKind::I32Shl => "i32.shl",
        OpKind::I32ShrU => "i32.shr_u",
        OpKind::I32ShrS => "i32.shr_s",
        OpKind::I32Eq => "i32.eq",
        OpKind::I32Ne => "i32.ne",
        OpKind::I32LtS => "i32.lt_s",
        OpKind::I32LtU => "i32.lt_u",
        OpKind::I32GtS => "i32.gt_s",
        OpKind::I32GtU => "i32.gt_u",
        OpKind::I32LeS => "i32.le_s",
        OpKind::I32LeU => "i32.le_u",
        OpKind::I32GeS => "i32.ge_s",
        OpKind::I32GeU => "i32.ge_u",
    }
}

const fn load_mnemonic(kind: LoadKind) -> &'static str {
    match kind {
        LoadKind::I32 => "i32.load",
        LoadKind::I64 => "i64.load",
        LoadKind::F32 => "f32.load",
        LoadKind::F64 => "f64.load",
        LoadKind::I32_8U => "i32.load8_u",
        LoadKind::I32_8S => "i32.load8_s",
        LoadKind::I32_16U => "i32.load16_u",
        LoadKind::I32_16S => "i32.load16_s",
        LoadKind::I64_8U => "i64.load8_u",
        LoadKind::I64_8S => "i64.load8_s",
        LoadKind::I64_16U => "i64.load16_u",
        LoadKind::I64_16S => "i64.load16_s",
        LoadKind::I64_32U => "i64.load32_u",
        LoadKind::I64_32S => "i64.load32_s",
    }
}

const fn store_mnemonic(kind: StoreKind) -> &'static str {
    match kind {
        StoreKind::I32 => "i32.store",
        StoreKind::I64 => "i64.store",
        StoreKind::F32 => "f32.store",
        StoreKind::F64 => "f64.store",
        StoreKind::I32_8 => "i32.store8",
        StoreKind::I32_16 => "i32.store16",
        StoreKind::I64_8 => "i64.store8",
        StoreKind::I64_16 => "i64.store16",
        StoreKind::I64_32 => "i64.store32",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cfg::{CfgBlock, FunctionCfg, TerminatorKind};
    use crate::ssa::{ConstVal, SsaBlock, SsaFunction, SsaTerm, ValueDef, ValueId};
    use crate::structure::reloop_inverse;
    use smallvec::{SmallVec, smallvec};

    fn return_cfg() -> FunctionCfg {
        FunctionCfg {
            blocks: vec![CfgBlock {
                id: BlockId(0),
                terminator: Some(TerminatorKind::Return),
                ..Default::default()
            }],
            edges: Vec::new(),
            entry: BlockId(0),
        }
    }

    fn ssa_one_block(values: Vec<ValueDef>, instrs: Vec<ValueId>, term: SsaTerm) -> SsaFunction {
        SsaFunction {
            values,
            blocks: vec![SsaBlock {
                id: BlockId(0),
                params: SmallVec::new(),
                instrs,
                stores: Vec::new(),
                terminator: term,
                preds: Vec::new(),
            }],
            entry: BlockId(0),
        }
    }

    #[test]
    fn empty_module_wraps_in_module_func_export() {
        let func: StructuredFunction = reloop_inverse(&return_cfg());
        let ssa: SsaFunction = SsaFunction {
            values: Vec::new(),
            blocks: Vec::new(),
            entry: BlockId(0),
        };
        let out: LiftResult = lift_to_wat(&func, &ssa);
        assert_eq!(out.target, LiftTarget::Wat);
        assert!(out.pseudo_source.starts_with("(module\n"));
        assert!(out.pseudo_source.contains("(func $lifted"));
        assert!(out.pseudo_source.contains("(export \"lifted\""));
        assert!(out.pseudo_source.trim_end().ends_with(')'));
    }

    #[test]
    fn const_emits_i32_const_and_surfaces_result_type() {
        let func: StructuredFunction = reloop_inverse(&return_cfg());
        let ssa: SsaFunction = ssa_one_block(
            vec![ValueDef::Const(ConstVal::I32(42))],
            vec![ValueId(0)],
            SsaTerm::Return(smallvec![ValueId(0)]),
        );
        let out: LiftResult = lift_to_wat(&func, &ssa);
        assert!(out.pseudo_source.contains("i32.const 42"));
        assert!(out.pseudo_source.contains("(result i32)"));
    }

    #[test]
    fn load_emits_offset_and_alignment_attributes() {
        use crate::ssa::SsaMemArg;
        use wasmparser::ValType;
        let func: StructuredFunction = reloop_inverse(&return_cfg());
        let ssa: SsaFunction = ssa_one_block(
            vec![
                ValueDef::Const(ConstVal::I32(0)),
                ValueDef::Load {
                    addr: ValueId(0),
                    memarg: SsaMemArg {
                        align: 2,
                        offset: 16,
                        memory: 0,
                    },
                    kind: LoadKind::I32,
                    ty: ValType::I32,
                },
            ],
            vec![ValueId(0), ValueId(1)],
            SsaTerm::Return(smallvec![ValueId(1)]),
        );
        let out: LiftResult = lift_to_wat(&func, &ssa);
        assert!(out.pseudo_source.contains("i32.load"));
        assert!(out.pseudo_source.contains("offset=16"));
        assert!(out.pseudo_source.contains("align=4"));
    }

    #[test]
    fn binop_emits_proper_mnemonic_and_terminator() {
        use wasmparser::ValType;
        let func: StructuredFunction = reloop_inverse(&return_cfg());
        let ssa: SsaFunction = ssa_one_block(
            vec![
                ValueDef::Const(ConstVal::I32(3)),
                ValueDef::Const(ConstVal::I32(5)),
                ValueDef::Op {
                    kind: OpKind::I32Xor,
                    args: smallvec![ValueId(0), ValueId(1)],
                    ty: ValType::I32,
                },
            ],
            vec![ValueId(0), ValueId(1), ValueId(2)],
            SsaTerm::Return(smallvec![ValueId(2)]),
        );
        let out: LiftResult = lift_to_wat(&func, &ssa);
        assert!(out.pseudo_source.contains("i32.xor"));
        assert!(out.pseudo_source.contains("return"));
    }

    #[test]
    fn round_trips_through_wat_parser() {
        let func: StructuredFunction = reloop_inverse(&return_cfg());
        let ssa: SsaFunction = SsaFunction {
            values: Vec::new(),
            blocks: Vec::new(),
            entry: BlockId(0),
        };
        let out: LiftResult = lift_to_wat(&func, &ssa);
        let head: String = out.pseudo_source.lines().take(2).collect();
        assert!(head.starts_with("(module"));
        assert!(head.contains("(func"));
    }
}
