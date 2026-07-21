use super::ir::BinOp;
use super::state::{CanonicalEffect, ControlEffect, Expr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MicroOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Ldarg(u16),
    Starg(u16),
    Ldloc(u16),
    Stloc(u16),
    Ldc(i64),
    LdcOperand,
    Ceq,
    Clt,
    Cgt,
    Br,
    BrTrue,
    BrFalse,
    Ret,
}

#[must_use]
pub fn match_canonical_effect(effect: &CanonicalEffect) -> Option<MicroOp> {
    if effect.control == ControlEffect::Ret
        && effect.stack_inputs == 1
        && effect.stack_outputs.is_empty()
        && effect.return_value == Some(Expr::VStackTop)
        && has_no_writes(effect)
    {
        return Some(MicroOp::Ret);
    }
    if effect.control == ControlEffect::Br
        && effect.stack_inputs == 0
        && effect.stack_outputs.is_empty()
        && has_no_writes(effect)
    {
        return Some(MicroOp::Br);
    }
    if effect.control == ControlEffect::BrTrue
        && effect.stack_inputs == 1
        && effect.stack_outputs.is_empty()
        && has_no_writes(effect)
    {
        return Some(MicroOp::BrTrue);
    }
    if effect.control == ControlEffect::BrFalse
        && effect.stack_inputs == 1
        && effect.stack_outputs.is_empty()
        && has_no_writes(effect)
    {
        return Some(MicroOp::BrFalse);
    }
    if effect.control != ControlEffect::Fallthrough {
        return None;
    }
    if effect.stack_inputs == 0
        && effect.stack_outputs.len() == 1
        && has_no_writes(effect)
        && effect.return_value.is_none()
    {
        match &effect.stack_outputs[0] {
            Expr::Argument(index) => return Some(MicroOp::Ldarg(*index)),
            Expr::Local(index) => return Some(MicroOp::Ldloc(*index)),
            Expr::Const(value) => return Some(MicroOp::Ldc(*value)),
            Expr::OperandBytes(_) => return Some(MicroOp::LdcOperand),
            _ => {}
        }
    }
    if effect.stack_inputs == 1
        && effect.stack_outputs.is_empty()
        && effect.return_value.is_none()
        && effect.local_writes.len() == 1
        && effect.argument_writes.is_empty()
        && effect.register_writes.is_empty()
    {
        let local_op: Option<MicroOp> = effect.local_writes.iter().next().and_then(
            |(index, value): (&u16, &Expr)| match value {
                Expr::VStackTop => Some(MicroOp::Stloc(*index)),
                _ => None,
            },
        );
        if local_op.is_some() {
            return local_op;
        }
    }
    if effect.stack_inputs == 1
        && effect.stack_outputs.is_empty()
        && effect.return_value.is_none()
        && effect.argument_writes.len() == 1
        && effect.local_writes.is_empty()
        && effect.register_writes.is_empty()
    {
        let argument_op: Option<MicroOp> =
            effect
                .argument_writes
                .iter()
                .next()
                .and_then(|(index, value): (&u16, &Expr)| match value {
                    Expr::VStackTop => Some(MicroOp::Starg(*index)),
                    _ => None,
                });
        if argument_op.is_some() {
            return argument_op;
        }
    }
    if effect.stack_inputs == 2
        && effect.stack_outputs.len() == 1
        && has_no_writes(effect)
        && effect.return_value.is_none()
    {
        return match_binary(&effect.stack_outputs[0]);
    }
    None
}

fn has_no_writes(effect: &CanonicalEffect) -> bool {
    effect.argument_writes.is_empty()
        && effect.local_writes.is_empty()
        && effect.register_writes.is_empty()
}

fn match_binary(value: &Expr) -> Option<MicroOp> {
    let (op, left, right): (&BinOp, &Expr, &Expr) = match value {
        Expr::Binary { op, left, right } => (op, left, right),
        _ => return None,
    };
    if !is_binary_inputs(*op, left, right) {
        return None;
    }
    match op {
        BinOp::Add => Some(MicroOp::Add),
        BinOp::Sub => Some(MicroOp::Sub),
        BinOp::Mul => Some(MicroOp::Mul),
        BinOp::And => Some(MicroOp::And),
        BinOp::Or => Some(MicroOp::Or),
        BinOp::Xor => Some(MicroOp::Xor),
        BinOp::Ceq => Some(MicroOp::Ceq),
        BinOp::Clt => Some(MicroOp::Clt),
        BinOp::Cgt => Some(MicroOp::Cgt),
    }
}

fn is_binary_inputs(op: BinOp, left: &Expr, right: &Expr) -> bool {
    if op.is_commutative() {
        return (left == &Expr::VStackTop && right == &Expr::VStackAt(1))
            || (left == &Expr::VStackAt(1) && right == &Expr::VStackTop);
    }
    left == &Expr::VStackAt(1) && right == &Expr::VStackTop
}
