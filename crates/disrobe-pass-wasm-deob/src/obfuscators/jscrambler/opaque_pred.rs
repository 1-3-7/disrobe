use crate::ssa::{BlockTarget, ConstVal, OpKind, SsaFunction, SsaTerm, ValueDef, ValueId};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OpaquePredStats {
    pub found: usize,
    pub folded_true: usize,
    pub folded_false: usize,
}

pub fn kill_opaque_predicates(ssa: &mut SsaFunction) -> OpaquePredStats {
    let mut stats: OpaquePredStats = OpaquePredStats::default();
    for bidx in 0..ssa.blocks.len() {
        let Some(decision): Option<FoldDecision> = classify_terminator(ssa, bidx) else {
            continue;
        };
        stats.found += 1;
        let new_term: SsaTerm = match decision {
            FoldDecision::TakeThen(target) => {
                stats.folded_true += 1;
                SsaTerm::Br(target)
            }
            FoldDecision::TakeElse(target) => {
                stats.folded_false += 1;
                SsaTerm::Br(target)
            }
        };
        if let Some(block) = ssa.blocks.get_mut(bidx) {
            block.terminator = new_term;
        }
    }
    stats
}

#[derive(Debug)]
enum FoldDecision {
    TakeThen(BlockTarget),
    TakeElse(BlockTarget),
}

fn classify_terminator(ssa: &SsaFunction, bidx: usize) -> Option<FoldDecision> {
    let block: &crate::ssa::SsaBlock = ssa.blocks.get(bidx)?;
    let SsaTerm::BrIf {
        cond,
        then_t,
        else_t,
    }: &SsaTerm = &block.terminator
    else {
        return None;
    };
    let result: i32 = fold_const_binop(ssa, *cond)?;
    if result == 0 {
        Some(FoldDecision::TakeElse(else_t.clone()))
    } else {
        Some(FoldDecision::TakeThen(then_t.clone()))
    }
}

fn fold_const_binop(ssa: &SsaFunction, v: ValueId) -> Option<i32> {
    let ValueDef::Op { kind, args, .. }: &ValueDef = ssa.value_def(v)? else {
        return None;
    };
    let lhs: i32 = const_i32(ssa, *args.first()?)?;
    let rhs: i32 = const_i32(ssa, *args.get(1)?)?;
    eval_i32_binop(*kind, lhs, rhs)
}

fn const_i32(ssa: &SsaFunction, v: ValueId) -> Option<i32> {
    match ssa.value_def(v)? {
        ValueDef::Const(ConstVal::I32(n)) => Some(*n),
        _ => None,
    }
}

fn eval_i32_binop(kind: OpKind, a: i32, b: i32) -> Option<i32> {
    let ua: u32 = a.cast_unsigned();
    let ub: u32 = b.cast_unsigned();
    Some(match kind {
        OpKind::I32Add => a.wrapping_add(b),
        OpKind::I32Sub => a.wrapping_sub(b),
        OpKind::I32Mul => a.wrapping_mul(b),
        OpKind::I32DivS => a.checked_div(b)?,
        OpKind::I32DivU => ua.checked_div(ub)?.cast_signed(),
        OpKind::I32RemS => a.checked_rem(b)?,
        OpKind::I32RemU => ua.checked_rem(ub)?.cast_signed(),
        OpKind::I32And => a & b,
        OpKind::I32Or => a | b,
        OpKind::I32Xor => a ^ b,
        OpKind::I32Shl => a.wrapping_shl(ub & 31),
        OpKind::I32ShrU => ua.wrapping_shr(ub & 31).cast_signed(),
        OpKind::I32ShrS => a.wrapping_shr(ub & 31),
        OpKind::I32Rotl => a.rotate_left(ub & 31),
        OpKind::I32Rotr => a.rotate_right(ub & 31),
        OpKind::I32Eq => i32::from(a == b),
        OpKind::I32Ne => i32::from(a != b),
        OpKind::I32LtS => i32::from(a < b),
        OpKind::I32LtU => i32::from(ua < ub),
        OpKind::I32GtS => i32::from(a > b),
        OpKind::I32GtU => i32::from(ua > ub),
        OpKind::I32LeS => i32::from(a <= b),
        OpKind::I32LeU => i32::from(ua <= ub),
        OpKind::I32GeS => i32::from(a >= b),
        OpKind::I32GeU => i32::from(ua >= ub),
        _ => return None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn eval_eq_two_equal_consts_is_one() {
        assert_eq!(eval_i32_binop(OpKind::I32Eq, 7, 7), Some(1));
    }

    #[test]
    fn eval_eq_two_distinct_consts_is_zero() {
        assert_eq!(eval_i32_binop(OpKind::I32Eq, 7, 9), Some(0));
    }

    #[test]
    fn eval_unsigned_lt_treats_negatives_as_large() {
        assert_eq!(eval_i32_binop(OpKind::I32LtU, -1, 1), Some(0));
        assert_eq!(eval_i32_binop(OpKind::I32LtS, -1, 1), Some(1));
    }
}
