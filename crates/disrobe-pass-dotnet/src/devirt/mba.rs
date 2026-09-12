use disrobe_mba::{
    BinOp as MbaBinOp, Expr as MbaExpr, Simplification, UnOp as MbaUnOp, Verification, Width,
    simplify,
};

use super::ir::BinOp;
use super::state::Expr;

const MAX_DOTNET_MBA_NODES: usize = 256;
const MAX_DOTNET_MBA_VARS: usize = 6;

pub(super) fn simplify_expression(expression: &Expr) -> Option<Expr> {
    let original_nodes: usize = bounded_node_count(expression, MAX_DOTNET_MBA_NODES)?;
    let mut leaves: Vec<Expr> = Vec::new();
    let lowered: MbaExpr = lower(expression, &mut leaves)?;
    if leaves.is_empty() || leaves.len() > MAX_DOTNET_MBA_VARS {
        return None;
    }
    let simplification: Simplification = simplify(&lowered, Width::W64);
    if !simplification.changed()
        || !proof_matches_width(simplification.verification, Width::W64)
        || simplification.simplified_nodes >= simplification.original_nodes
    {
        return None;
    }
    let materialized_nodes: usize = materialized_node_count(
        &simplification.simplified,
        MAX_DOTNET_MBA_NODES.min(original_nodes.saturating_sub(1)),
    )?;
    if materialized_nodes >= original_nodes {
        return None;
    }
    let materialized: Expr = materialize(&simplification.simplified, &leaves)?;
    let mut round_trip_leaves: Vec<Expr> = leaves.clone();
    let round_trip: MbaExpr = lower_known(&materialized, &mut round_trip_leaves)?;
    if round_trip_leaves != leaves || round_trip != simplification.simplified {
        return None;
    }
    Some(materialized)
}

fn proof_matches_width(verification: Verification, width: Width) -> bool {
    verification == Verification::ExhaustiveAtWidth(width)
        || verification == Verification::LinearColumnIdentity(width)
        || verification == Verification::PolynomialIdentity(width)
}

fn bounded_node_count(expression: &Expr, limit: usize) -> Option<usize> {
    fn count(expression: &Expr, consumed: &mut usize, limit: usize) -> Option<()> {
        *consumed = consumed.checked_add(1)?;
        if *consumed > limit {
            return None;
        }
        if let Expr::Binary { left, right, .. } = expression {
            count(left, consumed, limit)?;
            count(right, consumed, limit)?;
        }
        Some(())
    }

    let mut consumed: usize = 0;
    count(expression, &mut consumed, limit)?;
    Some(consumed)
}

fn lower(expression: &Expr, leaves: &mut Vec<Expr>) -> Option<MbaExpr> {
    lower_at(expression, leaves, false)
}

fn lower_known(expression: &Expr, leaves: &mut Vec<Expr>) -> Option<MbaExpr> {
    lower_at(expression, leaves, true)
}

fn lower_at(expression: &Expr, leaves: &mut Vec<Expr>, known_only: bool) -> Option<MbaExpr> {
    match expression {
        Expr::Const(value) => Some(MbaExpr::konst(value.cast_unsigned())),
        Expr::Binary { op, left, right } => {
            let lowered_op: MbaBinOp = match op {
                BinOp::Add => MbaBinOp::Add,
                BinOp::Sub => MbaBinOp::Sub,
                BinOp::Mul => MbaBinOp::Mul,
                BinOp::And => MbaBinOp::And,
                BinOp::Or => MbaBinOp::Or,
                BinOp::Xor => MbaBinOp::Xor,
                BinOp::Ceq | BinOp::Clt | BinOp::Cgt => return None,
            };
            let lowered_left: MbaExpr = lower_at(left, leaves, known_only)?;
            let lowered_right: MbaExpr = lower_at(right, leaves, known_only)?;
            Some(MbaExpr::Binary(
                lowered_op,
                Box::new(lowered_left),
                Box::new(lowered_right),
            ))
        }
        Expr::VStackTop
        | Expr::VStackAt(_)
        | Expr::VReg(_)
        | Expr::Local(_)
        | Expr::Argument(_)
        | Expr::OperandBytes(_)
        | Expr::IpDelta(_) => intern_leaf(expression, leaves, known_only),
    }
}

fn intern_leaf(expression: &Expr, leaves: &mut Vec<Expr>, known_only: bool) -> Option<MbaExpr> {
    if let Some(index) = leaves.iter().position(|leaf: &Expr| leaf == expression) {
        let index: u32 = u32::try_from(index).ok()?;
        return Some(MbaExpr::var(index));
    }
    if known_only || leaves.len() >= MAX_DOTNET_MBA_VARS {
        return None;
    }
    let index: u32 = u32::try_from(leaves.len()).ok()?;
    leaves.push(expression.clone());
    Some(MbaExpr::var(index))
}

fn materialized_node_count(expression: &MbaExpr, limit: usize) -> Option<usize> {
    fn count(expression: &MbaExpr, consumed: &mut usize, limit: usize) -> Option<()> {
        let own_nodes: usize = match expression {
            MbaExpr::Unary(MbaUnOp::Neg | MbaUnOp::Not, _) => 2,
            MbaExpr::Const(_) | MbaExpr::Var(_) | MbaExpr::Binary(_, _, _) => 1,
            MbaExpr::Ite(_, _, _)
            | MbaExpr::Slice(_, _, _)
            | MbaExpr::Compose(_, _, _)
            | MbaExpr::Mem(_, _) => return None,
        };
        *consumed = consumed.checked_add(own_nodes)?;
        if *consumed > limit {
            return None;
        }
        match expression {
            MbaExpr::Unary(_, inner) => count(inner, consumed, limit),
            MbaExpr::Binary(_, left, right) => {
                count(left, consumed, limit)?;
                count(right, consumed, limit)
            }
            MbaExpr::Const(_) | MbaExpr::Var(_) => Some(()),
            MbaExpr::Ite(_, _, _)
            | MbaExpr::Slice(_, _, _)
            | MbaExpr::Compose(_, _, _)
            | MbaExpr::Mem(_, _) => None,
        }
    }

    let mut consumed: usize = 0;
    count(expression, &mut consumed, limit)?;
    Some(consumed)
}

fn materialize(expression: &MbaExpr, leaves: &[Expr]) -> Option<Expr> {
    match expression {
        MbaExpr::Const(value) => Some(Expr::Const(value.cast_signed())),
        MbaExpr::Var(index) => leaves.get(usize::try_from(*index).ok()?).cloned(),
        MbaExpr::Unary(op, inner) => {
            let materialized: Expr = materialize(inner, leaves)?;
            let (dotnet_op, constant): (BinOp, Expr) = match op {
                MbaUnOp::Neg => (BinOp::Sub, Expr::Const(0)),
                MbaUnOp::Not => (BinOp::Xor, Expr::Const(-1)),
            };
            Expr::binary(dotnet_op, constant, materialized).ok()
        }
        MbaExpr::Binary(op, left, right) => {
            let dotnet_op: BinOp = match op {
                MbaBinOp::Add => BinOp::Add,
                MbaBinOp::Sub => BinOp::Sub,
                MbaBinOp::Mul => BinOp::Mul,
                MbaBinOp::And => BinOp::And,
                MbaBinOp::Or => BinOp::Or,
                MbaBinOp::Xor => BinOp::Xor,
                MbaBinOp::Shl | MbaBinOp::Shr => return None,
            };
            let materialized_left: Expr = materialize(left, leaves)?;
            let materialized_right: Expr = materialize(right, leaves)?;
            Expr::binary(dotnet_op, materialized_left, materialized_right).ok()
        }
        MbaExpr::Ite(_, _, _)
        | MbaExpr::Slice(_, _, _)
        | MbaExpr::Compose(_, _, _)
        | MbaExpr::Mem(_, _) => None,
    }
}
