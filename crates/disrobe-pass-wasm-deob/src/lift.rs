use std::fmt::Write;

use serde::Serialize;

use crate::cfg::BlockId;
use crate::ssa::{
    BlockTarget, ConstVal, OpKind, SsaBlock, SsaFunction, SsaTerm, ValueDef, ValueId,
};
use crate::structure::{StructuredFunction, StructuredNode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LiftTarget {
    Rust,
    TypeScript,
    Wat,
    C,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiftResult {
    pub target: LiftTarget,
    pub pseudo_source: String,
    pub blocks_emitted: usize,
}

#[inline]
#[must_use]
pub fn lift(func: &StructuredFunction, target: LiftTarget) -> LiftResult {
    let mut out: String = String::new();
    let mut emitted: usize = 0usize;
    emit_node_text_only(&func.root, target, &mut out, 0, &mut emitted);
    LiftResult {
        target,
        pseudo_source: out,
        blocks_emitted: emitted,
    }
}

#[must_use]
pub fn lift_with_ssa(
    func: &StructuredFunction,
    ssa: &SsaFunction,
    target: LiftTarget,
) -> LiftResult {
    if matches!(target, LiftTarget::Wat) {
        return crate::lift_wat::lift_to_wat(func, ssa);
    }
    if matches!(target, LiftTarget::C) {
        return crate::lift_c::lift_to_c(func, ssa);
    }
    let mut body: String = String::new();
    let mut emitted: usize = 0usize;
    emit_node_ssa(&func.root, ssa, target, &mut body, 1, &mut emitted);
    let sig: &str = match target {
        LiftTarget::Rust => "fn lifted() {",
        LiftTarget::TypeScript => "function lifted(): void {",
        LiftTarget::Wat | LiftTarget::C => unreachable!("guarded above"),
    };
    let mut wrapped: String = format!(
        "lifted from wasm \u{2014} ssa values={} blocks={}\n{sig}\n",
        ssa.values.len(),
        ssa.blocks.len()
    );
    wrapped.push_str(&body);
    wrapped.push_str("}\n");
    LiftResult {
        target,
        pseudo_source: wrapped,
        blocks_emitted: emitted,
    }
}

#[allow(clippy::only_used_in_recursion)]
fn emit_node_text_only(
    node: &StructuredNode,
    target: LiftTarget,
    out: &mut String,
    depth: usize,
    emitted: &mut usize,
) {
    let indent: String = "  ".repeat(depth);
    match node {
        StructuredNode::Sequence(children) => {
            for child in children {
                emit_node_text_only(child, target, out, depth, emitted);
            }
        }
        StructuredNode::Block(id) => {
            let _ = writeln!(out, "{indent}block {}", id.0);
            *emitted += 1;
        }
        StructuredNode::Return(id) => {
            let _ = writeln!(out, "{indent}return; block {}", id.0);
            *emitted += 1;
        }
        StructuredNode::If {
            condition_block,
            then_branch,
            else_branch,
        } => {
            let _ = writeln!(out, "{indent}if block {} {{", condition_block.0);
            emit_node_text_only(then_branch, target, out, depth + 1, emitted);
            let _ = write!(out, "{indent}}}");
            if let Some(e) = else_branch {
                out.push_str(" else {\n");
                emit_node_text_only(e, target, out, depth + 1, emitted);
                let _ = write!(out, "{indent}}}");
            }
            out.push('\n');
        }
        StructuredNode::While { header, body } => {
            let _ = writeln!(out, "{indent}while block {} {{", header.0);
            emit_node_text_only(body, target, out, depth + 1, emitted);
            let _ = writeln!(out, "{indent}}}");
        }
    }
}

fn find_block(ssa: &SsaFunction, id: BlockId) -> Option<&SsaBlock> {
    ssa.blocks.iter().find(|b| b.id == id)
}

fn emit_node_ssa(
    node: &StructuredNode,
    ssa: &SsaFunction,
    target: LiftTarget,
    out: &mut String,
    depth: usize,
    emitted: &mut usize,
) {
    let indent: String = "  ".repeat(depth);
    match node {
        StructuredNode::Sequence(children) => {
            for child in children {
                emit_node_ssa(child, ssa, target, out, depth, emitted);
            }
        }
        StructuredNode::Block(id) | StructuredNode::Return(id) => {
            emit_ssa_block(*id, ssa, target, out, depth, true);
            *emitted += 1;
        }
        StructuredNode::If {
            condition_block,
            then_branch,
            else_branch,
        } => {
            let cond: String = emit_ssa_block(*condition_block, ssa, target, out, depth, false);
            let _ = writeln!(out, "{indent}if {cond} {{");
            emit_node_ssa(then_branch, ssa, target, out, depth + 1, emitted);
            let _ = write!(out, "{indent}}}");
            if let Some(e) = else_branch {
                out.push_str(" else {\n");
                emit_node_ssa(e, ssa, target, out, depth + 1, emitted);
                let _ = write!(out, "{indent}}}");
            }
            out.push('\n');
        }
        StructuredNode::While { header, body } => {
            let cond: String = emit_ssa_block(*header, ssa, target, out, depth, false);
            let _ = writeln!(out, "{indent}while {cond} {{");
            emit_node_ssa(body, ssa, target, out, depth + 1, emitted);
            let _ = writeln!(out, "{indent}}}");
        }
    }
}

fn emit_ssa_block(
    id: BlockId,
    ssa: &SsaFunction,
    target: LiftTarget,
    out: &mut String,
    depth: usize,
    emit_term: bool,
) -> String {
    let indent: String = "  ".repeat(depth);
    let Some(block): Option<&SsaBlock> = find_block(ssa, id) else {
        let _ = writeln!(out, "{indent}block {} (no ssa)", id.0);
        return "true".to_owned();
    };

    let keyword: &str = match target {
        LiftTarget::Rust => "let",
        LiftTarget::TypeScript => "const",
        LiftTarget::Wat | LiftTarget::C => unreachable!("wat/c path handled separately"),
    };

    for vid in &block.instrs {
        let Some(def): Option<&ValueDef> = ssa.values.get(vid.0 as usize) else {
            continue;
        };
        if matches!(def, ValueDef::Param(..)) {
            continue;
        }
        let expr: String = format_def(def, ssa, target);
        let _ = writeln!(out, "{indent}{keyword} v{} = {expr};", vid.0);
    }
    for store in &block.stores {
        let _ = writeln!(
            out,
            "{indent}mem_store_{:?}(v{}, v{}, offset={});",
            store.kind, store.addr.0, store.val.0, store.memarg.offset
        );
    }
    if emit_term {
        emit_terminator_line(&block.terminator, target, out, &indent);
    }
    match &block.terminator {
        SsaTerm::BrIf { cond, .. } => name_or_inline_param(*cond, ssa),
        SsaTerm::Return(vals) if !vals.is_empty() => name_or_inline_param(vals[0], ssa),
        _ => "true".to_owned(),
    }
}

fn emit_terminator_line(term: &SsaTerm, target: LiftTarget, out: &mut String, indent: &str) {
    match term {
        SsaTerm::Return(vals) if vals.is_empty() => {
            let _ = writeln!(out, "{indent}return;");
        }
        SsaTerm::Return(vals) => {
            let joined: String = join_values(vals);
            if vals.len() == 1 {
                let _ = writeln!(out, "{indent}return {joined};");
            } else {
                let _ = writeln!(out, "{indent}return ({joined});");
            }
        }
        SsaTerm::Unreachable => {
            let msg: &str = match target {
                LiftTarget::Rust => "unreachable!();",
                LiftTarget::TypeScript => "throw new Error(\"unreachable\");",
                LiftTarget::Wat => "unreachable",
                LiftTarget::C => "__builtin_unreachable();",
            };
            let _ = writeln!(out, "{indent}{msg}");
        }
        SsaTerm::Br(t) => {
            let _ = writeln!(out, "{indent}br -> block {}", t.block.0);
            emit_block_args(t, out, indent);
        }
        SsaTerm::BrIf { then_t, else_t, .. } => {
            let _ = writeln!(
                out,
                "{indent}br_if then=block {} else=block {}",
                then_t.block.0, else_t.block.0
            );
        }
        SsaTerm::BrTable {
            targets, default, ..
        } => {
            let _ = writeln!(
                out,
                "{indent}br_table targets={} default=block {}",
                targets.len(),
                default.block.0
            );
        }
        SsaTerm::Fallthrough(t) => {
            let _ = writeln!(out, "{indent}fallthrough -> block {}", t.block.0);
            emit_block_args(t, out, indent);
        }
    }
}

fn emit_block_args(t: &BlockTarget, out: &mut String, indent: &str) {
    if !t.args.is_empty() {
        let _ = writeln!(out, "{indent}args=({})", join_values(&t.args));
    }
}

fn join_values(vs: &[ValueId]) -> String {
    let mut s: String = String::with_capacity(vs.len() * 4);
    for (i, v) in vs.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        let _ = write!(s, "v{}", v.0);
    }
    s
}

fn format_def(def: &ValueDef, ssa: &SsaFunction, target: LiftTarget) -> String {
    match def {
        ValueDef::Param(block, idx) => format!("param_{}_{}", block.0, idx),
        ValueDef::Phi { block, operands } => {
            let args: Vec<ValueId> = operands.iter().copied().collect();
            format!("phi_{}({})", block.0, join_values(&args))
        }
        ValueDef::Const(c) => format_const(c, target),
        ValueDef::Op { kind, args, .. } => match (args.first(), args.get(1)) {
            (Some(a), Some(b)) => format!(
                "{} {} {}",
                name_or_inline_param(*a, ssa),
                op_symbol(*kind),
                name_or_inline_param(*b, ssa)
            ),
            _ => format!("{kind:?}_arity_not_two"),
        },
        ValueDef::Load {
            addr, memarg, kind, ..
        } => format!("mem_load_{:?}(v{}, offset={})", kind, addr.0, memarg.offset),
    }
}

fn name_or_inline_param(v: ValueId, ssa: &SsaFunction) -> String {
    match ssa.values.get(v.0 as usize) {
        Some(ValueDef::Param(block, idx)) => format!("param_{}_{}", block.0, idx),
        _ => format!("v{}", v.0),
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

fn format_const(c: &ConstVal, target: LiftTarget) -> String {
    match (c, target) {
        (ConstVal::I32(n), LiftTarget::Rust) => format!("{n}i32"),
        (ConstVal::I32(n), LiftTarget::TypeScript) => format!("{n}"),
        (ConstVal::I64(n), LiftTarget::Rust) => format!("{n}i64"),
        (ConstVal::I64(n), LiftTarget::TypeScript) => format!("{n}n"),
        (ConstVal::F32Bits(b), LiftTarget::Rust) => format!("f32::from_bits({b}u32)"),
        (ConstVal::F32Bits(b), LiftTarget::TypeScript) => format!("f32_from_bits(0x{b:08x})"),
        (ConstVal::F64Bits(b), LiftTarget::Rust) => format!("f64::from_bits({b}u64)"),
        (ConstVal::F64Bits(b), LiftTarget::TypeScript) => format!("f64_from_bits(0x{b:016x}n)"),
        (ConstVal::Bytes(bytes), LiftTarget::Rust) => format_bytes_rust(bytes),
        (ConstVal::Bytes(bytes), LiftTarget::TypeScript) => format_bytes_ts(bytes),
        (_, LiftTarget::Wat) => unreachable!("wat path uses emit_wat_const"),
        (_, LiftTarget::C) => unreachable!("c path uses lift_c::format_const"),
    }
}

fn format_bytes_rust(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() + 2);
    out.push_str("b\"");
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push('"');
    out
}

fn format_bytes_ts(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 6 + 16);
    out.push_str("Uint8Array.of(");
    for (i, &byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "0x{byte:02x}");
    }
    out.push(')');
    out
}
