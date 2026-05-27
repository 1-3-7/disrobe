use std::fmt::Write;

use crate::lift::{LiftResult, LiftTarget};
use crate::ssa::{ConstVal, OpKind, SsaBlock, SsaFunction, SsaTerm, ValueDef};
use crate::structure::{StructuredFunction, StructuredNode};
use crate::types::{LoadKind, StoreKind};

#[must_use]
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn lift_to_c(func: &StructuredFunction, ssa: &SsaFunction) -> LiftResult {
    let mut body: String = String::with_capacity(1024);
    let mut emitted: usize = 0usize;
    let result_ty: &'static str = c_func_result(ssa);
    body.push_str("/* disrobe wasm lift target=c (wasm2c-parity) */\n");
    body.push_str("#include <stdint.h>\n");
    body.push_str("#include <stddef.h>\n\n");
    body.push_str("typedef struct { uint8_t* data; size_t len; } wasm_memory_t;\n\n");
    let _: std::fmt::Result = writeln!(body, "{result_ty} lifted(void) {{");
    emit_node(&func.root, ssa, &mut body, 1, &mut emitted);
    if result_ty == "void" {
        body.push_str("  return;\n");
    } else {
        body.push_str("  return 0;\n");
    }
    body.push_str("}\n");
    LiftResult {
        target: LiftTarget::C,
        pseudo_source: body,
        blocks_emitted: emitted,
    }
}

fn c_func_result(ssa: &SsaFunction) -> &'static str {
    for block in &ssa.blocks {
        if let SsaTerm::Return(vals) = &block.terminator {
            if !vals.is_empty() {
                return "int32_t";
            }
        }
    }
    "void"
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
            let _: std::fmt::Result = writeln!(out, "{indent}if (cond) {{");
            emit_node(then_branch, ssa, out, depth + 1, emitted);
            if let Some(e) = else_branch {
                let _: std::fmt::Result = writeln!(out, "{indent}}} else {{");
                emit_node(e, ssa, out, depth + 1, emitted);
            }
            let _: std::fmt::Result = writeln!(out, "{indent}}}");
        }
        StructuredNode::While { header, body } => {
            let _: std::fmt::Result = writeln!(out, "{indent}while (1) {{");
            emit_block(*header, ssa, out, depth + 1);
            emit_node(body, ssa, out, depth + 1, emitted);
            let _: std::fmt::Result = writeln!(out, "{indent}}}");
        }
    }
}

fn emit_block(id: crate::cfg::BlockId, ssa: &SsaFunction, out: &mut String, depth: usize) {
    let indent: String = "  ".repeat(depth);
    let Some(block): Option<&SsaBlock> = ssa.blocks.iter().find(|b: &&SsaBlock| b.id == id) else {
        let _: std::fmt::Result = writeln!(out, "{indent}/* block {} missing */", id.0);
        return;
    };
    for vid in &block.instrs {
        let Some(def): Option<&ValueDef> = ssa.values.get(vid.0 as usize) else {
            continue;
        };
        if matches!(def, ValueDef::Param(..)) {
            continue;
        }
        let expr: String = format_def(def);
        let _: std::fmt::Result = writeln!(out, "{indent}int32_t v{} = {expr};", vid.0);
    }
    for store in &block.stores {
        let _: std::fmt::Result = writeln!(
            out,
            "{indent}/* {} offset={} */",
            store_mnemonic(store.kind),
            store.memarg.offset
        );
    }
    match &block.terminator {
        SsaTerm::Return(vals) if vals.is_empty() => {
            let _: std::fmt::Result = writeln!(out, "{indent}return;");
        }
        SsaTerm::Return(vals) => {
            if let Some(v) = vals.first() {
                let _: std::fmt::Result = writeln!(out, "{indent}return v{};", v.0);
            }
        }
        SsaTerm::Unreachable => {
            let _: std::fmt::Result = writeln!(out, "{indent}__builtin_unreachable();");
        }
        SsaTerm::Br(t) => {
            let _: std::fmt::Result = writeln!(out, "{indent}goto block_{};", t.block.0);
        }
        SsaTerm::BrIf { cond, then_t, .. } => {
            let _: std::fmt::Result = writeln!(
                out,
                "{indent}if (v{}) goto block_{};",
                cond.0, then_t.block.0
            );
        }
        SsaTerm::BrTable { .. } => {
            let _: std::fmt::Result = writeln!(out, "{indent}/* br_table */");
        }
        SsaTerm::Fallthrough(_) => {}
    }
}

fn format_def(def: &ValueDef) -> String {
    match def {
        ValueDef::Param(_, idx) => format!("arg{idx}"),
        ValueDef::Phi { .. } => "/* phi */ 0".to_owned(),
        ValueDef::Const(c) => format_const(c),
        ValueDef::Op { kind, args, .. } => match (args.first(), args.get(1)) {
            (Some(a), Some(b)) => format!("v{} {} v{}", a.0, op_symbol(*kind), b.0),
            _ => "0".to_owned(),
        },
        ValueDef::Load {
            addr, memarg, kind, ..
        } => format!(
            "mem_load_{}((uint8_t*)v{} + {})",
            load_short(*kind),
            addr.0,
            memarg.offset
        ),
    }
}

fn format_const(c: &ConstVal) -> String {
    match c {
        ConstVal::I32(n) => format!("{n}"),
        ConstVal::I64(n) => format!("{n}LL"),
        ConstVal::F32Bits(b) => format!("(int32_t)0x{b:08x}"),
        ConstVal::F64Bits(b) => format!("(int64_t)0x{b:016x}"),
        ConstVal::Bytes(_) => "0".to_owned(),
    }
}

const fn op_symbol(kind: OpKind) -> &'static str {
    match kind {
        OpKind::I32Add => "+",
        OpKind::I32Sub => "-",
        OpKind::I32Mul => "*",
        OpKind::I32And => "&",
        OpKind::I32Or => "|",
        OpKind::I32Xor => "^",
        OpKind::I32Shl => "<<",
        OpKind::I32ShrU | OpKind::I32ShrS => ">>",
        OpKind::I32Eq => "==",
        OpKind::I32Ne => "!=",
        OpKind::I32LtS | OpKind::I32LtU => "<",
        OpKind::I32GtS | OpKind::I32GtU => ">",
        OpKind::I32LeS | OpKind::I32LeU => "<=",
        OpKind::I32GeS | OpKind::I32GeU => ">=",
    }
}

const fn load_short(kind: LoadKind) -> &'static str {
    match kind {
        LoadKind::I32 => "i32",
        LoadKind::I64 => "i64",
        LoadKind::F32 => "f32",
        LoadKind::F64 => "f64",
        LoadKind::I32_8U | LoadKind::I64_8U => "u8",
        LoadKind::I32_8S | LoadKind::I64_8S => "i8",
        LoadKind::I32_16U | LoadKind::I64_16U => "u16",
        LoadKind::I32_16S | LoadKind::I64_16S => "i16",
        LoadKind::I64_32U => "u32",
        LoadKind::I64_32S => "i32",
    }
}

const fn store_mnemonic(kind: StoreKind) -> &'static str {
    match kind {
        StoreKind::I32 => "i32.store",
        StoreKind::I64 => "i64.store",
        StoreKind::F32 => "f32.store",
        StoreKind::F64 => "f64.store",
        StoreKind::I32_8 | StoreKind::I64_8 => "store8",
        StoreKind::I32_16 | StoreKind::I64_16 => "store16",
        StoreKind::I64_32 => "store32",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cfg::{BlockId, CfgBlock, FunctionCfg, TerminatorKind};
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

    #[test]
    fn empty_module_emits_void_lifted_with_includes() {
        let func: StructuredFunction = reloop_inverse(&return_cfg());
        let ssa: SsaFunction = SsaFunction {
            values: Vec::new(),
            blocks: Vec::new(),
            entry: BlockId(0),
        };
        let out: LiftResult = lift_to_c(&func, &ssa);
        assert!(out.pseudo_source.contains("#include <stdint.h>"));
        assert!(out.pseudo_source.contains("void lifted(void)"));
    }

    #[test]
    fn return_with_value_emits_int32_signature() {
        let func: StructuredFunction = reloop_inverse(&return_cfg());
        let ssa: SsaFunction = SsaFunction {
            values: vec![ValueDef::Const(ConstVal::I32(42))],
            blocks: vec![SsaBlock {
                id: BlockId(0),
                params: SmallVec::new(),
                instrs: vec![ValueId(0)],
                stores: Vec::new(),
                terminator: SsaTerm::Return(smallvec![ValueId(0)]),
                preds: Vec::new(),
            }],
            entry: BlockId(0),
        };
        let out: LiftResult = lift_to_c(&func, &ssa);
        assert!(out.pseudo_source.contains("int32_t lifted(void)"));
        assert!(out.pseudo_source.contains("int32_t v0 = 42"));
        assert!(out.pseudo_source.contains("return v0;"));
    }
}
