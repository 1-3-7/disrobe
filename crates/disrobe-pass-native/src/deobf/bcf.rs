use disrobe_mba::{
    BranchFold, CmpOp, Expr, OpaqueVerdict, Predicate, Width, classify, fold_branch,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::mba_lift::{lift_operand_pair, mem_access_width};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpaqueResult {
    AlwaysTaken,
    AlwaysNotTaken,
    DataDependent,
    NotAnalyzable,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BogusBranch {
    pub branch_address: u64,
    pub result: OpaqueResult,
    pub dead_target: Option<u64>,
    pub live_target: Option<u64>,
}

#[must_use]
pub fn analyze_block(bitness: u32, base: u64, bytes: &[u8]) -> Option<BogusBranch> {
    let insns: Vec<Instruction> = decode_all(bitness, base, bytes);
    let branch: &Instruction = insns
        .last()
        .filter(|i: &&Instruction| i.flow_control() == FlowControl::ConditionalBranch)?;
    let cmp_index: usize = insns.len().checked_sub(2)?;
    let cmp: &Instruction = &insns[cmp_index];
    let (raw, width): (Predicate, Width) =
        build_predicate(&insns[..cmp_index], cmp, branch.mnemonic())?;
    let predicate: Predicate = LoadAbstraction::over(&raw).compact();
    let verdict: OpaqueVerdict = classify(&predicate, width);
    let fold: BranchFold = fold_branch(&predicate, width);
    let taken: u64 = branch.near_branch_target();
    let fallthrough: u64 = branch.ip().saturating_add(branch.len() as u64);
    Some(resolve_fold(
        branch.ip(),
        verdict,
        &fold,
        taken,
        fallthrough,
    ))
}

fn resolve_fold(
    branch_address: u64,
    verdict: OpaqueVerdict,
    fold: &BranchFold,
    taken: u64,
    fallthrough: u64,
) -> BogusBranch {
    match fold {
        BranchFold::KeepConsequent => BogusBranch {
            branch_address,
            result: OpaqueResult::AlwaysTaken,
            dead_target: Some(fallthrough),
            live_target: Some(taken),
        },
        BranchFold::KeepAlternate => BogusBranch {
            branch_address,
            result: OpaqueResult::AlwaysNotTaken,
            dead_target: Some(taken),
            live_target: Some(fallthrough),
        },
        BranchFold::Unresolved => BogusBranch {
            branch_address,
            result: classify_residual(verdict),
            dead_target: None,
            live_target: None,
        },
    }
}

const fn classify_residual(verdict: OpaqueVerdict) -> OpaqueResult {
    match verdict {
        OpaqueVerdict::DataDependent => OpaqueResult::DataDependent,
        OpaqueVerdict::OutOfBudget => OpaqueResult::NotAnalyzable,
        OpaqueVerdict::AlwaysTrue { .. } | OpaqueVerdict::AlwaysFalse { .. } => {
            OpaqueResult::DataDependent
        }
    }
}

fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

fn build_predicate(
    prefix: &[Instruction],
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    match cmp.mnemonic() {
        Mnemonic::Cmp => Some((
            build_cmp_predicate(prefix, cmp, branch)?,
            predicate_width(cmp),
        )),
        Mnemonic::Test => build_test_predicate(prefix, cmp, branch),
        _ => None,
    }
}

fn build_cmp_predicate(
    prefix: &[Instruction],
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<Predicate> {
    let (lhs, rhs): (Expr, Expr) = lift_comparison_operands(prefix, cmp)?;
    let op: CmpOp = branch_to_cmp(branch)?;
    Some(Predicate::Compare {
        op,
        left: lhs,
        right: rhs,
    })
}

fn lift_comparison_operands(prefix: &[Instruction], cmp: &Instruction) -> Option<(Expr, Expr)> {
    if !matches!(cmp.op0_kind(), OpKind::Register | OpKind::Memory) {
        return None;
    }
    lift_operand_pair(prefix, cmp)
}

fn build_test_predicate(
    prefix: &[Instruction],
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    if cmp.op0_kind() == OpKind::Register
        && let Some((flag, width)) = build_flag_predicate(prefix, cmp.op0_register(), branch)
    {
        return Some((flag, width));
    }
    let (lhs, rhs): (Expr, Expr) = lift_comparison_operands(prefix, cmp)?;
    let masked: Expr = tested_value(lhs, rhs);
    let predicate: Predicate = match branch {
        Mnemonic::Je => Predicate::eq(masked, Expr::konst(0)),
        Mnemonic::Jne => Predicate::nonzero(masked),
        _ => return None,
    };
    Some((predicate, predicate_width(cmp)))
}

fn highest_var(predicate: &Predicate) -> Option<u32> {
    match predicate {
        Predicate::Nonzero(inner) => inner.max_var(),
        Predicate::Compare { left, right, .. } => left.max_var().max(right.max_var()),
        Predicate::Or(left, right) | Predicate::And(left, right) => {
            highest_var(left).max(highest_var(right))
        }
    }
}

#[derive(Debug, Default)]
struct LoadAbstraction {
    assigned: Vec<(Expr, u32)>,
    next_var: u32,
}

impl LoadAbstraction {
    fn over(predicate: &Predicate) -> Predicate {
        let mut abstraction: Self = Self {
            assigned: Vec::new(),
            next_var: highest_var(predicate).map_or(0, |highest: u32| highest.saturating_add(1)),
        };
        abstraction.rewrite_predicate(predicate)
    }

    fn variable_for(&mut self, load: &Expr, width: Width) -> Expr {
        let existing: Option<u32> = self
            .assigned
            .iter()
            .find(|(seen, _): &&(Expr, u32)| seen == load)
            .map(|(_, index): &(Expr, u32)| *index);
        let index: u32 = existing.unwrap_or_else(|| {
            let fresh: u32 = self.next_var;
            self.next_var = self.next_var.saturating_add(1);
            self.assigned.push((load.clone(), fresh));
            fresh
        });
        Expr::and(Expr::var(index), Expr::konst(width.mask()))
    }

    fn rewrite_expr(&mut self, expr: &Expr) -> Expr {
        match expr {
            Expr::Mem(_, width) => self.variable_for(expr, *width),
            Expr::Const(_) | Expr::Var(_) => expr.clone(),
            Expr::Unary(op, inner) => Expr::Unary(*op, Box::new(self.rewrite_expr(inner))),
            Expr::Binary(op, left, right) => Expr::Binary(
                *op,
                Box::new(self.rewrite_expr(left)),
                Box::new(self.rewrite_expr(right)),
            ),
            Expr::Ite(condition, consequent, alternate) => Expr::Ite(
                Box::new(self.rewrite_expr(condition)),
                Box::new(self.rewrite_expr(consequent)),
                Box::new(self.rewrite_expr(alternate)),
            ),
            Expr::Slice(inner, high, low) => {
                Expr::Slice(Box::new(self.rewrite_expr(inner)), *high, *low)
            }
            Expr::Compose(low, high, low_bits) => Expr::Compose(
                Box::new(self.rewrite_expr(low)),
                Box::new(self.rewrite_expr(high)),
                *low_bits,
            ),
        }
    }

    fn rewrite_predicate(&mut self, predicate: &Predicate) -> Predicate {
        match predicate {
            Predicate::Nonzero(inner) => Predicate::nonzero(self.rewrite_expr(inner)),
            Predicate::Compare { op, left, right } => Predicate::Compare {
                op: *op,
                left: self.rewrite_expr(left),
                right: self.rewrite_expr(right),
            },
            Predicate::Or(left, right) => {
                Predicate::or(self.rewrite_predicate(left), self.rewrite_predicate(right))
            }
            Predicate::And(left, right) => {
                Predicate::and(self.rewrite_predicate(left), self.rewrite_predicate(right))
            }
        }
    }
}

fn tested_value(left: Expr, right: Expr) -> Expr {
    if left == right {
        return left;
    }
    Expr::and(left, right)
}

fn full_reg(reg: Register) -> Register {
    let full: Register = reg.full_register();
    if full == Register::None { reg } else { full }
}

const fn setcc_to_cmp(mnemonic: Mnemonic) -> Option<Mnemonic> {
    match mnemonic {
        Mnemonic::Sete => Some(Mnemonic::Je),
        Mnemonic::Setne => Some(Mnemonic::Jne),
        Mnemonic::Setl => Some(Mnemonic::Jl),
        Mnemonic::Setle => Some(Mnemonic::Jle),
        Mnemonic::Setg => Some(Mnemonic::Jg),
        Mnemonic::Setge => Some(Mnemonic::Jge),
        Mnemonic::Setb => Some(Mnemonic::Jb),
        Mnemonic::Setbe => Some(Mnemonic::Jbe),
        Mnemonic::Seta => Some(Mnemonic::Ja),
        Mnemonic::Setae => Some(Mnemonic::Jae),
        _ => None,
    }
}

fn predicate_from_flag(
    prefix: &[Instruction],
    boolean_reg: Register,
) -> Option<(Predicate, Width)> {
    let want: Register = full_reg(boolean_reg);
    let pos: usize = prefix.iter().rposition(|i: &Instruction| {
        i.op0_kind() == OpKind::Register
            && full_reg(i.op0_register()) == want
            && (setcc_to_cmp(i.mnemonic()).is_some()
                || matches!(i.mnemonic(), Mnemonic::Or | Mnemonic::And))
    })?;
    let producer: &Instruction = &prefix[pos];
    match producer.mnemonic() {
        Mnemonic::Or => {
            let (left, lw): (Predicate, Width) =
                predicate_from_flag(&prefix[..pos], producer.op0_register())?;
            let (right, rw): (Predicate, Width) =
                predicate_from_flag(&prefix[..pos], producer.op1_register())?;
            Some((Predicate::or(left, right), widest(lw, rw)))
        }
        Mnemonic::And => {
            let (left, lw): (Predicate, Width) =
                predicate_from_flag(&prefix[..pos], producer.op0_register())?;
            let (right, rw): (Predicate, Width) =
                predicate_from_flag(&prefix[..pos], producer.op1_register())?;
            Some((Predicate::and(left, right), widest(lw, rw)))
        }
        other => {
            let jcc: Mnemonic = setcc_to_cmp(other)?;
            let cmp_index: usize = prefix[..pos]
                .iter()
                .rposition(|i: &Instruction| matches!(i.mnemonic(), Mnemonic::Cmp))?;
            let cmp: &Instruction = &prefix[cmp_index];
            let predicate: Predicate = build_cmp_predicate(&prefix[..cmp_index], cmp, jcc)?;
            Some((predicate, predicate_width(cmp)))
        }
    }
}

const fn widest(a: Width, b: Width) -> Width {
    if a.bits() >= b.bits() { a } else { b }
}

fn build_flag_predicate(
    prefix: &[Instruction],
    boolean_reg: Register,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    if !matches!(branch, Mnemonic::Je | Mnemonic::Jne) {
        return None;
    }
    let (base, width): (Predicate, Width) = predicate_from_flag(prefix, boolean_reg)?;
    if branch == Mnemonic::Jne {
        Some((base, width))
    } else {
        Some((negate_predicate(base), width))
    }
}

fn negate_predicate(predicate: Predicate) -> Predicate {
    match predicate {
        Predicate::Or(left, right) => {
            Predicate::and(negate_predicate(*left), negate_predicate(*right))
        }
        Predicate::And(left, right) => {
            Predicate::or(negate_predicate(*left), negate_predicate(*right))
        }
        Predicate::Nonzero(inner) => Predicate::eq(inner, Expr::konst(0)),
        Predicate::Compare { op, left, right } => Predicate::Compare {
            op: negate_cmp(op),
            left,
            right,
        },
    }
}

const fn negate_cmp(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::Eq => CmpOp::Ne,
        CmpOp::Ne => CmpOp::Eq,
        CmpOp::UnsignedLt => CmpOp::UnsignedGe,
        CmpOp::UnsignedLe => CmpOp::UnsignedGt,
        CmpOp::UnsignedGt => CmpOp::UnsignedLe,
        CmpOp::UnsignedGe => CmpOp::UnsignedLt,
        CmpOp::SignedLt => CmpOp::SignedGe,
        CmpOp::SignedLe => CmpOp::SignedGt,
        CmpOp::SignedGt => CmpOp::SignedLe,
        CmpOp::SignedGe => CmpOp::SignedLt,
    }
}

fn predicate_width(cmp: &Instruction) -> Width {
    match cmp.op0_kind() {
        OpKind::Register => register_width(cmp.op0_register()),
        OpKind::Memory => mem_access_width(cmp),
        _ => Width::W32,
    }
}

fn register_width(reg: Register) -> Width {
    match reg.size() {
        1 => Width::W8,
        2 => Width::W16,
        4 => Width::W32,
        _ => Width::W64,
    }
}

const fn branch_to_cmp(branch: Mnemonic) -> Option<CmpOp> {
    match branch {
        Mnemonic::Je => Some(CmpOp::Eq),
        Mnemonic::Jne => Some(CmpOp::Ne),
        Mnemonic::Jb => Some(CmpOp::UnsignedLt),
        Mnemonic::Jbe => Some(CmpOp::UnsignedLe),
        Mnemonic::Ja => Some(CmpOp::UnsignedGt),
        Mnemonic::Jae => Some(CmpOp::UnsignedGe),
        Mnemonic::Jl => Some(CmpOp::SignedLt),
        Mnemonic::Jle => Some(CmpOp::SignedLe),
        Mnemonic::Jg => Some(CmpOp::SignedGt),
        Mnemonic::Jge => Some(CmpOp::SignedGe),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
