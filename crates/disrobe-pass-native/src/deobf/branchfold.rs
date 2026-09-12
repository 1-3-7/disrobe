use std::collections::BTreeSet;

use disrobe_mba::{CmpOp, Expr, OpaqueVerdict, Predicate, Width, classify};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register, UsedRegister,
};

use super::mba_lift::{RegFile, operand_expr};

const MAX_BLOCK_INSNS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FoldKind {
    ConstantCondition,
    OpaqueIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FoldVerdict {
    AlwaysTaken,
    AlwaysNotTaken,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BranchFoldFinding {
    pub branch_address: u64,
    pub kind: FoldKind,
    pub verdict: FoldVerdict,
    pub live_target: u64,
    pub dead_target: u64,
    pub free_variables: u32,
    pub verified_width: u32,
    pub lifted: bool,
    pub eliminated_dead_stores: u32,
    pub dead_store_addresses: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct BranchFoldOutcome {
    pub finding: BranchFoldFinding,
    pub kept_body: Vec<Instruction>,
}

#[must_use]
pub fn fold_block(bitness: u32, base: u64, bytes: &[u8]) -> Option<BranchFoldOutcome> {
    let insns: Vec<Instruction> = decode_all(bitness, base, bytes);
    let branch: &Instruction = insns
        .last()
        .filter(|i: &&Instruction| i.flow_control() == FlowControl::ConditionalBranch)?;
    let cmp_index: usize = insns.len().checked_sub(2)?;
    let cmp: &Instruction = &insns[cmp_index];
    let body: &[Instruction] = &insns[..cmp_index];

    if body.iter().any(|i: &Instruction| !is_straight_line(i)) {
        return None;
    }

    let mut regs: RegFile = RegFile::new();
    for insn in body {
        if !regs.apply_insn(insn) || regs.is_capped() {
            return None;
        }
    }

    let (predicate, width): (Predicate, Width) =
        build_predicate(&mut regs, cmp, branch.mnemonic())?;
    if regs.is_capped() {
        return None;
    }

    let verdict: OpaqueVerdict = classify(&predicate, width);
    let constant_value: bool = verdict.constant_value()?;

    let free_variables: u32 = {
        let mut vars: BTreeSet<u32> = BTreeSet::new();
        collect_predicate_vars(&predicate, &mut vars);
        u32::try_from(vars.len()).unwrap_or(u32::MAX)
    };
    let kind: FoldKind = if free_variables == 0 {
        FoldKind::ConstantCondition
    } else {
        FoldKind::OpaqueIdentity
    };

    let taken: u64 = branch.near_branch_target();
    let fallthrough: u64 = branch.ip().saturating_add(branch.len() as u64);
    let (verdict_label, live_target, dead_target): (FoldVerdict, u64, u64) = if constant_value {
        (FoldVerdict::AlwaysTaken, taken, fallthrough)
    } else {
        (FoldVerdict::AlwaysNotTaken, fallthrough, taken)
    };

    let (verified_width, lifted): (Width, bool) = match verdict {
        OpaqueVerdict::AlwaysTrue {
            verified_width,
            lifted,
        }
        | OpaqueVerdict::AlwaysFalse {
            verified_width,
            lifted,
        } => (verified_width, lifted),
        OpaqueVerdict::DataDependent | OpaqueVerdict::OutOfBudget => return None,
    };

    let cmp_reads: BTreeSet<Register> = read_registers(cmp);
    let mut dropped: Vec<bool> = vec![false; body.len()];
    let dead_store_addresses: Vec<u64> = mark_dead_stores(body, &cmp_reads, &mut dropped);
    let eliminated_dead_stores: u32 = u32::try_from(dead_store_addresses.len()).unwrap_or(u32::MAX);

    let kept_body: Vec<Instruction> = body
        .iter()
        .zip(dropped.iter())
        .filter_map(|(insn, drop): (&Instruction, &bool)| (!*drop).then_some(*insn))
        .collect();

    let finding: BranchFoldFinding = BranchFoldFinding {
        branch_address: branch.ip(),
        kind,
        verdict: verdict_label,
        live_target,
        dead_target,
        free_variables,
        verified_width: verified_width.bits(),
        lifted,
        eliminated_dead_stores,
        dead_store_addresses,
    };
    Some(BranchFoldOutcome { finding, kept_body })
}

fn build_predicate(
    regs: &mut RegFile,
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    if cmp.op0_kind() != OpKind::Register {
        return None;
    }
    let width: Width = register_width(cmp.op0_register());
    match cmp.mnemonic() {
        Mnemonic::Cmp => {
            let left: Expr = regs.current(cmp.op0_register());
            let right: Expr = operand_expr(regs, cmp, 1)?;
            let op: CmpOp = branch_to_cmp(branch)?;
            Some((Predicate::Compare { op, left, right }, width))
        }
        Mnemonic::Test => {
            let left: Expr = regs.current(cmp.op0_register());
            let right: Expr = operand_expr(regs, cmp, 1)?;
            let masked: Expr = Expr::and(left, right);
            let predicate: Predicate = match branch {
                Mnemonic::Je => Predicate::eq(masked, Expr::konst(0)),
                Mnemonic::Jne => Predicate::nonzero(masked),
                _ => return None,
            };
            Some((predicate, width))
        }
        _ => None,
    }
}

fn mark_dead_stores(
    body: &[Instruction],
    cmp_reads: &BTreeSet<Register>,
    dropped: &mut [bool],
) -> Vec<u64> {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut addresses: Vec<u64> = Vec::new();
    for i in 0..body.len() {
        let insn: &Instruction = &body[i];
        let Some(dest_full): Option<Register> = pure_full_register_def(insn, &mut factory) else {
            continue;
        };
        if cmp_reads.contains(&dest_full) {
            continue;
        }
        if is_dead_within_body(body, dropped, i, dest_full, &mut factory) {
            dropped[i] = true;
            addresses.push(insn.ip());
        }
    }
    addresses
}

fn is_dead_within_body(
    body: &[Instruction],
    dropped: &[bool],
    def_index: usize,
    dest_full: Register,
    factory: &mut InstructionInfoFactory,
) -> bool {
    for (j, later) in body.iter().enumerate().skip(def_index + 1) {
        if dropped[j] {
            continue;
        }
        let info: &iced_x86::InstructionInfo = factory.info(later);
        let mut redefined: bool = false;
        for r in info.used_registers() {
            if full_register(r.register()) != dest_full {
                continue;
            }
            match r.access() {
                OpAccess::Read
                | OpAccess::ReadWrite
                | OpAccess::CondRead
                | OpAccess::ReadCondWrite => return false,
                OpAccess::Write => {
                    if is_full_width(r.register()) {
                        redefined = true;
                    } else {
                        return false;
                    }
                }
                OpAccess::CondWrite => return false,
                OpAccess::None | OpAccess::NoMemAccess => {}
            }
        }
        if uses_register_in_memory(later, dest_full) {
            return false;
        }
        if redefined {
            return true;
        }
    }
    false
}

fn pure_full_register_def(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
) -> Option<Register> {
    if !matches!(
        insn.mnemonic(),
        Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Movzx | Mnemonic::Movsx
    ) {
        return None;
    }
    if insn.op0_kind() != OpKind::Register {
        return None;
    }
    let dest: Register = insn.op0_register();
    if !is_general_purpose(dest) || !is_full_width(dest) {
        return None;
    }
    if reads_memory(insn) {
        return None;
    }
    let dest_full: Register = full_register(dest);
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    if !info.used_memory().is_empty() {
        return None;
    }
    if info
        .used_registers()
        .iter()
        .any(|r: &UsedRegister| matches!(r.access(), OpAccess::CondWrite | OpAccess::ReadCondWrite))
    {
        return None;
    }
    Some(dest_full)
}

fn read_registers(insn: &Instruction) -> BTreeSet<Register> {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    info.used_registers()
        .iter()
        .filter(|r: &&UsedRegister| {
            matches!(
                r.access(),
                OpAccess::Read | OpAccess::ReadWrite | OpAccess::CondRead | OpAccess::ReadCondWrite
            )
        })
        .map(|r: &UsedRegister| full_register(r.register()))
        .collect()
}

fn collect_predicate_vars(predicate: &Predicate, into: &mut BTreeSet<u32>) {
    match predicate {
        Predicate::Nonzero(inner) => inner.collect_vars(into),
        Predicate::Compare { left, right, .. } => {
            left.collect_vars(into);
            right.collect_vars(into);
        }
        Predicate::Or(left, right) | Predicate::And(left, right) => {
            collect_predicate_vars(left, into);
            collect_predicate_vars(right, into);
        }
    }
}

fn uses_register_in_memory(insn: &Instruction, full: Register) -> bool {
    if insn.memory_base() != Register::None && full_register(insn.memory_base()) == full {
        return true;
    }
    insn.memory_index() != Register::None && full_register(insn.memory_index()) == full
}

fn reads_memory(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|op: u32| insn.op_kind(op) == OpKind::Memory)
}

fn is_straight_line(insn: &Instruction) -> bool {
    matches!(insn.flow_control(), FlowControl::Next) && !insn.has_lock_prefix()
}

fn is_general_purpose(reg: Register) -> bool {
    reg.is_gpr() && reg != Register::None
}

fn is_full_width(reg: Register) -> bool {
    reg.is_gpr32() || reg.is_gpr64()
}

fn full_register(reg: Register) -> Register {
    let full: Register = reg.full_register();
    if full == Register::None { reg } else { full }
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

fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && out.len() < MAX_BLOCK_INSNS {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
