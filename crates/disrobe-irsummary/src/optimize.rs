use std::collections::BTreeSet;

use disrobe_mba::{BinOp, Expr, Width, verify_equivalent};

use crate::valuegraph::{IcmpKind, Inst, Operand, UnaryKind, ValueGraph};

const MAX_FIXPOINT_ROUNDS: usize = 16;

#[must_use]
pub(crate) fn optimize_graph(graph: &ValueGraph) -> ValueGraph {
    let mut current: ValueGraph = graph.clone();
    for _ in 0..MAX_FIXPOINT_ROUNDS {
        let folded: bool = fold_round(&mut current);
        let copied: bool = copy_propagate(&mut current);
        let pruned: bool = eliminate_dead(&mut current);
        if !folded && !copied && !pruned {
            break;
        }
    }
    current
}

fn fold_round(graph: &mut ValueGraph) -> bool {
    let width: Width = graph.width;
    let ids: Vec<u32> = graph.order.clone();
    let mut changed: bool = false;
    for id in ids {
        let Some(inst): Option<Inst> = graph.insts.get(&id).cloned() else {
            continue;
        };
        if let Some(folded) = try_fold(graph, &inst, width) {
            graph.replacements.insert(id, folded);
            changed = true;
        }
    }
    changed
}

fn try_fold(graph: &ValueGraph, inst: &Inst, width: Width) -> Option<Operand> {
    match inst {
        Inst::Bin { op, lhs, rhs } => fold_binary(graph, *op, *lhs, *rhs, width),
        Inst::Icmp { op, lhs, rhs } => fold_icmp(graph, *op, *lhs, *rhs, width),
        Inst::BoolBin { is_and, lhs, rhs } => fold_bool(graph, *is_and, *lhs, *rhs),
        Inst::Select {
            cond,
            then,
            otherwise,
        } => fold_select(graph, *cond, *then, *otherwise),
        _ => None,
    }
}

fn fold_icmp(
    graph: &ValueGraph,
    op: IcmpKind,
    lhs: Operand,
    rhs: Operand,
    width: Width,
) -> Option<Operand> {
    let (Operand::Literal(a), Operand::Literal(b)): (Operand, Operand) =
        (graph.resolve(lhs), graph.resolve(rhs))
    else {
        return None;
    };
    Some(Operand::Literal(u64::from(eval_icmp(op, a, b, width))))
}

fn fold_bool(graph: &ValueGraph, is_and: bool, lhs: Operand, rhs: Operand) -> Option<Operand> {
    let resolved_lhs: Operand = graph.resolve(lhs);
    let resolved_rhs: Operand = graph.resolve(rhs);
    if let (Operand::Literal(a), Operand::Literal(b)) = (resolved_lhs, resolved_rhs) {
        let value: u64 = if is_and {
            (a & 1) & (b & 1)
        } else {
            (a & 1) | (b & 1)
        };
        return Some(Operand::Literal(value));
    }
    None
}

fn fold_binary(
    graph: &ValueGraph,
    op: BinOp,
    lhs: Operand,
    rhs: Operand,
    width: Width,
) -> Option<Operand> {
    let resolved_lhs: Operand = graph.resolve(lhs);
    let resolved_rhs: Operand = graph.resolve(rhs);
    let mask: u64 = width.mask();
    let full: u64 = mask;

    if let (Operand::Literal(a), Operand::Literal(b)) = (resolved_lhs, resolved_rhs) {
        let value: u64 = eval_binop(op, a & mask, b & mask, width);
        return Some(Operand::Literal(value & mask));
    }

    match op {
        BinOp::Add => identity_when(resolved_rhs, 0, resolved_lhs)
            .or_else(|| identity_when(resolved_lhs, 0, resolved_rhs)),
        BinOp::Sub => {
            if let Some(folded) = identity_when(resolved_rhs, 0, resolved_lhs) {
                return Some(folded);
            }
            if operands_equal(resolved_lhs, resolved_rhs) {
                return Some(Operand::Literal(0));
            }
            None
        }
        BinOp::Mul => {
            if let Some(folded) =
                annihilate_when(resolved_rhs, 0).or_else(|| annihilate_when(resolved_lhs, 0))
            {
                return Some(folded);
            }
            identity_when(resolved_rhs, 1, resolved_lhs)
                .or_else(|| identity_when(resolved_lhs, 1, resolved_rhs))
        }
        BinOp::And => {
            if let Some(folded) =
                annihilate_when(resolved_rhs, 0).or_else(|| annihilate_when(resolved_lhs, 0))
            {
                return Some(folded);
            }
            if let Some(folded) = identity_when(resolved_rhs, full, resolved_lhs)
                .or_else(|| identity_when(resolved_lhs, full, resolved_rhs))
            {
                return Some(folded);
            }
            operands_equal(resolved_lhs, resolved_rhs).then_some(resolved_lhs)
        }
        BinOp::Or => {
            if let Some(folded) =
                saturate_when(resolved_rhs, full).or_else(|| saturate_when(resolved_lhs, full))
            {
                return Some(folded);
            }
            if let Some(folded) = identity_when(resolved_rhs, 0, resolved_lhs)
                .or_else(|| identity_when(resolved_lhs, 0, resolved_rhs))
            {
                return Some(folded);
            }
            operands_equal(resolved_lhs, resolved_rhs).then_some(resolved_lhs)
        }
        BinOp::Xor => {
            if let Some(folded) = identity_when(resolved_rhs, 0, resolved_lhs)
                .or_else(|| identity_when(resolved_lhs, 0, resolved_rhs))
            {
                return Some(folded);
            }
            operands_equal(resolved_lhs, resolved_rhs).then_some(Operand::Literal(0))
        }
        BinOp::Shl | BinOp::Shr => identity_when(resolved_rhs, 0, resolved_lhs),
    }
}

fn identity_when(probe: Operand, neutral: u64, keep: Operand) -> Option<Operand> {
    matches!(probe, Operand::Literal(value) if value == neutral).then_some(keep)
}

fn annihilate_when(probe: Operand, zero: u64) -> Option<Operand> {
    matches!(probe, Operand::Literal(value) if value == zero).then_some(Operand::Literal(0))
}

fn saturate_when(probe: Operand, full: u64) -> Option<Operand> {
    matches!(probe, Operand::Literal(value) if value == full).then_some(Operand::Literal(full))
}

const fn operands_equal(a: Operand, b: Operand) -> bool {
    match (a, b) {
        (Operand::Literal(x), Operand::Literal(y)) => x == y,
        (Operand::Value(x), Operand::Value(y)) => x == y,
        _ => false,
    }
}

fn fold_select(
    graph: &ValueGraph,
    cond: Operand,
    then: Operand,
    otherwise: Operand,
) -> Option<Operand> {
    let resolved_cond: Operand = graph.resolve(cond);
    let resolved_then: Operand = graph.resolve(then);
    let resolved_otherwise: Operand = graph.resolve(otherwise);
    if let Operand::Literal(value) = resolved_cond {
        return Some(if value != 0 {
            resolved_then
        } else {
            resolved_otherwise
        });
    }
    operands_equal(resolved_then, resolved_otherwise).then_some(resolved_then)
}

fn eval_binop(op: BinOp, a: u64, b: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    let mask: u64 = width.mask();
    let result: u64 = match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl if b < bits => u32::try_from(b).map_or(0, |shift: u32| a.wrapping_shl(shift)),
        BinOp::Shr if b < bits => {
            u32::try_from(b).map_or(0, |shift: u32| (a & mask).wrapping_shr(shift))
        }
        BinOp::Shl | BinOp::Shr => 0,
    };
    result & mask
}

fn eval_icmp(op: IcmpKind, a: u64, b: u64, width: Width) -> bool {
    let bits: u32 = width.bits();
    let mask: u64 = width.mask();
    let au: u64 = a & mask;
    let bu: u64 = b & mask;
    let sign_extend = |value: u64| -> i64 {
        if bits >= 64 {
            i64::from_ne_bytes(value.to_ne_bytes())
        } else {
            let shift: u32 = 64 - bits;
            i64::from_ne_bytes(((value & mask) << shift).to_ne_bytes()) >> shift
        }
    };
    match op {
        IcmpKind::Eq => au == bu,
        IcmpKind::Ne => au != bu,
        IcmpKind::UnsignedLt => au < bu,
        IcmpKind::UnsignedLe => au <= bu,
        IcmpKind::UnsignedGt => au > bu,
        IcmpKind::UnsignedGe => au >= bu,
        IcmpKind::SignedLt => sign_extend(a) < sign_extend(b),
        IcmpKind::SignedLe => sign_extend(a) <= sign_extend(b),
        IcmpKind::SignedGt => sign_extend(a) > sign_extend(b),
        IcmpKind::SignedGe => sign_extend(a) >= sign_extend(b),
    }
}

fn copy_propagate(graph: &mut ValueGraph) -> bool {
    let ids: Vec<u32> = graph.order.clone();
    let mut changed: bool = false;
    for id in ids {
        if graph.replacements.contains_key(&id) {
            continue;
        }
        let Some(inst): Option<Inst> = graph.insts.get(&id).cloned() else {
            continue;
        };
        if let Some(collapse) = try_collapse(graph, &inst, graph.width) {
            graph.replacements.insert(id, collapse);
            changed = true;
        }
    }
    changed
}

fn try_collapse(graph: &ValueGraph, inst: &Inst, width: Width) -> Option<Operand> {
    match inst {
        Inst::Unary { op, value } => collapse_unary(graph, *op, *value, width),
        Inst::Zext {
            source,
            from_bits,
            to_bits,
        }
        | Inst::Trunc {
            source,
            from_bits,
            to_bits,
        } => collapse_cast(graph, *source, *from_bits, *to_bits, width),
        _ => None,
    }
}

fn collapse_unary(
    graph: &ValueGraph,
    op: UnaryKind,
    value: Operand,
    width: Width,
) -> Option<Operand> {
    if !matches!(op, UnaryKind::Not) {
        return None;
    }
    let Operand::Value(inner_id): Operand = graph.resolve(value) else {
        return None;
    };
    let Some(Inst::Unary {
        op: UnaryKind::Not,
        value: inner_value,
    }): Option<&Inst> = graph.insts.get(&inner_id)
    else {
        return None;
    };
    let candidate: Operand = graph.resolve(*inner_value);
    proves_unary_pair_identity(graph, candidate, width).then_some(candidate)
}

fn proves_unary_pair_identity(graph: &ValueGraph, candidate: Operand, width: Width) -> bool {
    let Some(expr): Option<Expr> = graph.operand_expr(candidate) else {
        return false;
    };
    let folded: Expr = Expr::not(Expr::not(expr.clone()));
    verify_equivalent(&folded, &expr, width).is_proven()
}

fn collapse_cast(
    graph: &ValueGraph,
    source: Operand,
    from_bits: u32,
    to_bits: u32,
    width: Width,
) -> Option<Operand> {
    let Operand::Value(source_id): Operand = graph.resolve(source) else {
        return None;
    };
    let inner: Inst = graph.insts.get(&source_id).cloned()?;
    let (inner_from, inner_to, original): (u32, u32, Operand) = match inner {
        Inst::Trunc {
            source: original,
            from_bits: inner_from,
            to_bits: inner_to,
        }
        | Inst::Zext {
            source: original,
            from_bits: inner_from,
            to_bits: inner_to,
        } => (inner_from, inner_to, original),
        _ => return None,
    };
    if inner_to != from_bits || inner_from != to_bits {
        return None;
    }
    let candidate: Operand = graph.resolve(original);
    let candidate_expr: Expr = graph.operand_expr(candidate)?;
    let kept_bits: u32 = inner_from.min(inner_to);
    let through: Expr = mask_to_bits(candidate_expr.clone(), kept_bits);
    verify_equivalent(&through, &candidate_expr, width)
        .is_proven()
        .then_some(candidate)
}

fn mask_to_bits(value: Expr, bits: u32) -> Expr {
    let mask: u64 = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    Expr::and(value, Expr::konst(mask))
}

fn eliminate_dead(graph: &mut ValueGraph) -> bool {
    let live: BTreeSet<u32> = graph.live_values();
    let before: usize = graph.order.len();
    graph.order.retain(|id: &u32| live.contains(id));
    let removed: Vec<u32> = graph
        .insts
        .keys()
        .copied()
        .filter(|id: &u32| !live.contains(id))
        .collect();
    for id in &removed {
        graph.insts.remove(id);
    }
    before != graph.order.len()
}
