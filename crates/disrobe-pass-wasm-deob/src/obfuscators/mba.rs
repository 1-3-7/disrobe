use disrobe_mba::{
    BinOp as MbaBinOp, Expr as MbaExpr, Simplification, UnOp as MbaUnOp, Width, simplify,
};
use smallvec::smallvec;
use wasmparser::ValType;

use crate::ssa::{ConstVal, OpKind, SsaFunction, ValueDef, ValueId};

const MAX_TREE_NODES: usize = 64;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MbaSsaStats {
    pub candidates: usize,
    pub simplified: usize,
    pub nodes_removed: usize,
}

#[must_use]
pub fn simplify_mba(ssa: &mut SsaFunction) -> MbaSsaStats {
    let mut stats: MbaSsaStats = MbaSsaStats::default();
    for index in 0..ssa.values.len() {
        let root: ValueId = ValueId(index as u32);
        let Some(width): Option<Width> = integer_op_width(ssa, root) else {
            continue;
        };
        let mut leaves: Vec<ValueId> = Vec::new();
        let Some(expr): Option<MbaExpr> = lower(ssa, root, &mut leaves) else {
            continue;
        };
        if !expr.is_linear_mba() || leaves.is_empty() {
            continue;
        }
        stats.candidates += 1;
        let result: Simplification = simplify(&expr, width);
        if !result.changed() || !result.verification.is_proven() {
            continue;
        }
        if result.simplified_nodes >= result.original_nodes {
            continue;
        }
        let ty: ValType = op_val_type(width);
        let Some(new_root_def): Option<ValueDef> =
            materialize(ssa, &result.simplified, &leaves, ty)
        else {
            continue;
        };
        if let Some(slot) = ssa.values.get_mut(index) {
            *slot = new_root_def;
            stats.simplified += 1;
            stats.nodes_removed += result
                .original_nodes
                .saturating_sub(result.simplified_nodes);
        }
    }
    stats
}

fn integer_op_width(ssa: &SsaFunction, v: ValueId) -> Option<Width> {
    let ValueDef::Op { kind, .. }: &ValueDef = ssa.value_def(v)? else {
        return None;
    };
    op_kind_width(*kind)
}

const fn op_kind_width(kind: OpKind) -> Option<Width> {
    match kind {
        OpKind::I32Add
        | OpKind::I32Sub
        | OpKind::I32Mul
        | OpKind::I32And
        | OpKind::I32Or
        | OpKind::I32Xor => Some(Width::W32),
        OpKind::I64Add
        | OpKind::I64Sub
        | OpKind::I64Mul
        | OpKind::I64And
        | OpKind::I64Or
        | OpKind::I64Xor => Some(Width::W64),
        _ => None,
    }
}

const fn op_val_type(width: Width) -> ValType {
    match width.bits() {
        64 => ValType::I64,
        _ => ValType::I32,
    }
}

const fn arithmetic_binop(kind: OpKind) -> Option<MbaBinOp> {
    match kind {
        OpKind::I32Add | OpKind::I64Add => Some(MbaBinOp::Add),
        OpKind::I32Sub | OpKind::I64Sub => Some(MbaBinOp::Sub),
        OpKind::I32Mul | OpKind::I64Mul => Some(MbaBinOp::Mul),
        OpKind::I32And | OpKind::I64And => Some(MbaBinOp::And),
        OpKind::I32Or | OpKind::I64Or => Some(MbaBinOp::Or),
        OpKind::I32Xor | OpKind::I64Xor => Some(MbaBinOp::Xor),
        _ => None,
    }
}

fn lower(ssa: &SsaFunction, root: ValueId, leaves: &mut Vec<ValueId>) -> Option<MbaExpr> {
    let mut budget: usize = MAX_TREE_NODES;
    lower_inner(ssa, root, leaves, &mut budget)
}

fn lower_inner(
    ssa: &SsaFunction,
    v: ValueId,
    leaves: &mut Vec<ValueId>,
    budget: &mut usize,
) -> Option<MbaExpr> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    match ssa.value_def(v)? {
        ValueDef::Const(ConstVal::I32(n)) => Some(MbaExpr::konst(u64::from(n.cast_unsigned()))),
        ValueDef::Const(ConstVal::I64(n)) => Some(MbaExpr::konst(n.cast_unsigned())),
        ValueDef::Op { kind, args, .. } => {
            if let Some(op) = arithmetic_binop(*kind) {
                let left_id: ValueId = *args.first()?;
                let right_id: ValueId = *args.get(1)?;
                let left: MbaExpr = lower_inner(ssa, left_id, leaves, budget)?;
                let right: MbaExpr = lower_inner(ssa, right_id, leaves, budget)?;
                return Some(MbaExpr::Binary(op, Box::new(left), Box::new(right)));
            }
            Some(leaf(v, leaves))
        }
        _ => Some(leaf(v, leaves)),
    }
}

fn leaf(v: ValueId, leaves: &mut Vec<ValueId>) -> MbaExpr {
    if let Some(existing) = leaves.iter().position(|id: &ValueId| *id == v) {
        return MbaExpr::var(existing as u32);
    }
    let index: u32 = leaves.len() as u32;
    leaves.push(v);
    MbaExpr::var(index)
}

fn materialize(
    ssa: &mut SsaFunction,
    expr: &MbaExpr,
    leaves: &[ValueId],
    ty: ValType,
) -> Option<ValueDef> {
    match expr {
        MbaExpr::Var(index) => {
            let leaf_id: ValueId = *leaves.get(*index as usize)?;
            Some(passthrough(ssa, leaf_id, ty))
        }
        MbaExpr::Const(value) => Some(const_def(ty, *value)),
        MbaExpr::Unary(op, inner) => {
            let inner_id: ValueId = emit(ssa, inner, leaves, ty)?;
            let zero: ValueId = push_value(ssa, const_def(ty, 0));
            match op {
                MbaUnOp::Neg => Some(ValueDef::Op {
                    kind: sub_op(ty),
                    args: smallvec![zero, inner_id],
                    ty,
                }),
                MbaUnOp::Not => {
                    let neg_one: ValueId = push_value(ssa, const_def(ty, all_ones(ty)));
                    Some(ValueDef::Op {
                        kind: xor_op(ty),
                        args: smallvec![inner_id, neg_one],
                        ty,
                    })
                }
            }
        }
        MbaExpr::Binary(op, left, right) => {
            let left_id: ValueId = emit(ssa, left, leaves, ty)?;
            let right_id: ValueId = emit(ssa, right, leaves, ty)?;
            Some(ValueDef::Op {
                kind: binop_kind(*op, ty)?,
                args: smallvec![left_id, right_id],
                ty,
            })
        }
        MbaExpr::Ite(_, _, _)
        | MbaExpr::Slice(_, _, _)
        | MbaExpr::Compose(_, _, _)
        | MbaExpr::Mem(_, _) => None,
    }
}

fn emit(ssa: &mut SsaFunction, expr: &MbaExpr, leaves: &[ValueId], ty: ValType) -> Option<ValueId> {
    if let MbaExpr::Var(index) = expr {
        return leaves.get(*index as usize).copied();
    }
    let def: ValueDef = materialize(ssa, expr, leaves, ty)?;
    Some(push_value(ssa, def))
}

fn push_value(ssa: &mut SsaFunction, def: ValueDef) -> ValueId {
    let id: ValueId = ValueId(ssa.values.len() as u32);
    ssa.values.push(def);
    id
}

fn passthrough(ssa: &mut SsaFunction, source: ValueId, ty: ValType) -> ValueDef {
    let zero: ValueId = push_value(ssa, const_def(ty, 0));
    ValueDef::Op {
        kind: or_op(ty),
        args: smallvec![source, zero],
        ty,
    }
}

const fn const_def(ty: ValType, value: u64) -> ValueDef {
    match ty {
        ValType::I64 => ValueDef::Const(ConstVal::I64(value.cast_signed())),
        _ => ValueDef::Const(ConstVal::I32((value as u32).cast_signed())),
    }
}

const fn all_ones(ty: ValType) -> u64 {
    match ty {
        ValType::I64 => u64::MAX,
        _ => u32::MAX as u64,
    }
}

const fn sub_op(ty: ValType) -> OpKind {
    match ty {
        ValType::I64 => OpKind::I64Sub,
        _ => OpKind::I32Sub,
    }
}

const fn xor_op(ty: ValType) -> OpKind {
    match ty {
        ValType::I64 => OpKind::I64Xor,
        _ => OpKind::I32Xor,
    }
}

const fn or_op(ty: ValType) -> OpKind {
    match ty {
        ValType::I64 => OpKind::I64Or,
        _ => OpKind::I32Or,
    }
}

const fn binop_kind(op: MbaBinOp, ty: ValType) -> Option<OpKind> {
    let is64: bool = matches!(ty, ValType::I64);
    Some(match (op, is64) {
        (MbaBinOp::Add, false) => OpKind::I32Add,
        (MbaBinOp::Add, true) => OpKind::I64Add,
        (MbaBinOp::Sub, false) => OpKind::I32Sub,
        (MbaBinOp::Sub, true) => OpKind::I64Sub,
        (MbaBinOp::Mul, false) => OpKind::I32Mul,
        (MbaBinOp::Mul, true) => OpKind::I64Mul,
        (MbaBinOp::And, false) => OpKind::I32And,
        (MbaBinOp::And, true) => OpKind::I64And,
        (MbaBinOp::Or, false) => OpKind::I32Or,
        (MbaBinOp::Or, true) => OpKind::I64Or,
        (MbaBinOp::Xor, false) => OpKind::I32Xor,
        (MbaBinOp::Xor, true) => OpKind::I64Xor,
        (MbaBinOp::Shl | MbaBinOp::Shr, _) => return None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use disrobe_mba::equivalent_exhaustive;

    use super::*;

    fn xor_plus_twice_and(ssa: &mut SsaFunction, x: ValueId, y: ValueId) -> ValueId {
        let xor: ValueId = push_value(
            ssa,
            ValueDef::Op {
                kind: OpKind::I32Xor,
                args: smallvec![x, y],
                ty: ValType::I32,
            },
        );
        let and: ValueId = push_value(
            ssa,
            ValueDef::Op {
                kind: OpKind::I32And,
                args: smallvec![x, y],
                ty: ValType::I32,
            },
        );
        let two: ValueId = push_value(ssa, const_def(ValType::I32, 2));
        let scaled: ValueId = push_value(
            ssa,
            ValueDef::Op {
                kind: OpKind::I32Mul,
                args: smallvec![two, and],
                ty: ValType::I32,
            },
        );
        push_value(
            ssa,
            ValueDef::Op {
                kind: OpKind::I32Add,
                args: smallvec![xor, scaled],
                ty: ValType::I32,
            },
        )
    }

    fn empty_ssa() -> SsaFunction {
        SsaFunction {
            values: Vec::new(),
            blocks: Vec::new(),
            entry: crate::cfg::BlockId(0),
        }
    }

    #[test]
    fn lowers_and_collapses_xor_carry_identity() {
        let mut ssa: SsaFunction = empty_ssa();
        let x: ValueId = push_value(&mut ssa, ValueDef::Param(crate::cfg::BlockId(0), 0));
        let y: ValueId = push_value(&mut ssa, ValueDef::Param(crate::cfg::BlockId(0), 1));
        let root: ValueId = xor_plus_twice_and(&mut ssa, x, y);

        let mut leaves: Vec<ValueId> = Vec::new();
        let expr: MbaExpr = lower(&ssa, root, &mut leaves).expect("lowered");
        assert_eq!(leaves.len(), 2, "x and y are the two leaves");
        assert!(expr.is_linear_mba());
        let result: Simplification = simplify(&expr, Width::W32);
        assert!(result.changed());
        assert!(result.verification.is_proven());
        let expected: MbaExpr = MbaExpr::add(MbaExpr::var(0), MbaExpr::var(1));
        assert!(
            equivalent_exhaustive(&result.simplified, &expected, Width::W8, 2),
            "simplified `{}` not equal to x + y",
            result.simplified
        );
    }

    #[test]
    fn simplify_mba_rewrites_root_to_fewer_nodes() {
        let mut ssa: SsaFunction = empty_ssa();
        let x: ValueId = push_value(&mut ssa, ValueDef::Param(crate::cfg::BlockId(0), 0));
        let y: ValueId = push_value(&mut ssa, ValueDef::Param(crate::cfg::BlockId(0), 1));
        let root: ValueId = xor_plus_twice_and(&mut ssa, x, y);
        let before: usize = subtree_op_count(&ssa, root);

        let stats: MbaSsaStats = simplify_mba(&mut ssa);
        assert!(stats.simplified >= 1, "expected at least one rewrite");
        let after: usize = subtree_op_count(&ssa, root);
        assert!(
            after < before,
            "rewritten subtree must have fewer ops: {after} >= {before}"
        );

        let mut leaves: Vec<ValueId> = Vec::new();
        let rewritten: MbaExpr = lower(&ssa, root, &mut leaves).expect("re-lower");
        let expected: MbaExpr = MbaExpr::add(MbaExpr::var(0), MbaExpr::var(1));
        assert!(
            equivalent_exhaustive(&rewritten, &expected, Width::W8, 2),
            "rewritten root `{rewritten}` not equal to x + y"
        );
    }

    fn subtree_op_count(ssa: &SsaFunction, root: ValueId) -> usize {
        match ssa.value_def(root) {
            Some(ValueDef::Op { args, .. }) => {
                1 + args
                    .iter()
                    .map(|a: &ValueId| subtree_op_count(ssa, *a))
                    .sum::<usize>()
            }
            _ => 0,
        }
    }
}
