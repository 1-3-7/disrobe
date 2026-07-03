use disrobe_mba::{
    BranchFold, CmpOp, Expr, OpaqueVerdict, Predicate, Width, classify, fold_branch,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::mba_lift::{RegFile, lift_arith_value};

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
    let predicate: Predicate = raw.compact();
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
    if cmp.op0_kind() != OpKind::Register {
        return None;
    }
    let dest: Register = cmp.op0_register();
    let (lhs, _): (Expr, Width) = lift_with_prefix(prefix, dest)?;
    let rhs: Expr = operand_expr(prefix, cmp, 1)?;
    let op: CmpOp = branch_to_cmp(branch)?;
    Some(Predicate::Compare {
        op,
        left: lhs,
        right: rhs,
    })
}

fn build_test_predicate(
    prefix: &[Instruction],
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    if cmp.op0_kind() != OpKind::Register {
        return None;
    }
    let dest: Register = cmp.op0_register();
    if let Some((flag, width)) = build_flag_predicate(prefix, dest, branch) {
        return Some((flag, width));
    }
    let (lhs, _): (Expr, Width) = lift_with_prefix(prefix, dest)?;
    let rhs: Expr = operand_expr(prefix, cmp, 1)?;
    let masked: Expr = Expr::and(lhs, rhs);
    let predicate: Predicate = match branch {
        Mnemonic::Je => Predicate::eq(masked, Expr::konst(0)),
        Mnemonic::Jne => Predicate::nonzero(masked),
        _ => return None,
    };
    Some((predicate, predicate_width(cmp)))
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

fn lift_with_prefix(prefix: &[Instruction], dest: Register) -> Option<(Expr, Width)> {
    if prefix.is_empty() {
        let mut regs: RegFile = RegFile::new();
        let value: Expr = regs.current(dest);
        return Some((value, register_width(dest)));
    }
    lift_arith_value(prefix, dest)
}

fn operand_expr(prefix: &[Instruction], cmp: &Instruction, operand: u32) -> Option<Expr> {
    match cmp.op_kind(operand) {
        OpKind::Register => lift_with_prefix(prefix, cmp.op_register(operand)).map(|(e, _)| e),
        OpKind::Immediate8 => Some(Expr::konst(u64::from(cmp.immediate8()))),
        OpKind::Immediate16 => Some(Expr::konst(u64::from(cmp.immediate16()))),
        OpKind::Immediate32 => Some(Expr::konst(u64::from(cmp.immediate32()))),
        OpKind::Immediate64 => Some(Expr::konst(cmp.immediate64())),
        OpKind::Immediate8to16 => Some(Expr::konst(cmp.immediate8to16().cast_unsigned().into())),
        OpKind::Immediate8to32 => Some(Expr::konst(cmp.immediate8to32().cast_unsigned().into())),
        OpKind::Immediate8to64 => Some(Expr::konst(cmp.immediate8to64().cast_unsigned())),
        OpKind::Immediate32to64 => Some(Expr::konst(cmp.immediate32to64().cast_unsigned())),
        _ => None,
    }
}

fn predicate_width(cmp: &Instruction) -> Width {
    if cmp.op0_kind() == OpKind::Register {
        register_width(cmp.op0_register())
    } else {
        Width::W32
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
