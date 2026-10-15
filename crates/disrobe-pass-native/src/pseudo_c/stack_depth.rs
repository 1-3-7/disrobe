use std::collections::BTreeMap;

use iced_x86::{FlowControl, Instruction};

use crate::arch::{DisasmInsn, decode_one_x86};
use crate::error::{Error, Result};

use super::{
    Abi, ExtSource, Flags, FpOperand, FrameShape, Item, ItemKind, MemRef, RETURN_ADDRESS_BYTES,
    Reg, Source, StackFrameBoundary, StackFrameExtent, Stmt, VecStmt, Width,
    home_space_above_return, is_rbp_lea_frame, is_stack_pointer_move, parse_reg, rsp_delta_imm,
    writes_stack_pointer,
};

const SLOT_BYTES: i64 = 8;
const MAX_PUSHED_REGISTERS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PushFrame {
    depths: BTreeMap<u64, i64>,
    body_depth: i64,
    pushed_bytes: i64,
    allocation: i64,
    home_bytes: i64,
}

impl PushFrame {
    pub(super) fn depth_at(&self, address: u64) -> Option<i64> {
        self.depths.get(&address).copied()
    }

    pub(super) const fn shape(&self) -> FrameShape {
        FrameShape {
            base: Some(Reg::Rsp),
            rbp_is_frame: false,
            red_zone: false,
            stack_extent: Some(StackFrameExtent {
                owned_start: Some(0),
                private_end: self.allocation,
                boundary: StackFrameBoundary::ReturnAddress {
                    linkage_bytes: self.pushed_bytes.saturating_add(RETURN_ADDRESS_BYTES),
                    home_bytes: self.home_bytes,
                },
                slot_bytes: RETURN_ADDRESS_BYTES,
            }),
            stack_pointer_break: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Next(i64),
    Branch {
        target: u64,
        depth: i64,
        falls_through: bool,
    },
    Exit,
}

fn register_operand(insn: &DisasmInsn) -> Option<Reg> {
    parse_reg(insn.operands.trim())
        .filter(|register| register.width == Width::W64)
        .map(|register| register.reg)
}

fn step(
    insn: &DisasmInsn,
    decoded: &Instruction,
    depth: i64,
    start: u64,
    end: u64,
) -> Option<Step> {
    match insn.mnemonic.as_str() {
        "push" => {
            register_operand(insn)?;
            return Some(Step::Next(depth.checked_sub(SLOT_BYTES)?));
        }
        "pop" => {
            register_operand(insn)?;
            let after: i64 = depth.checked_add(SLOT_BYTES)?;
            return (after <= 0).then_some(Step::Next(after));
        }
        "sub" | "add" if writes_stack_pointer(insn) => {
            let amount: i64 = rsp_delta_imm(&insn.mnemonic, &insn.operands)?;
            let after: i64 = if insn.mnemonic == "sub" {
                depth.checked_sub(amount)?
            } else {
                depth.checked_add(amount)?
            };
            return (after <= 0).then_some(Step::Next(after));
        }
        _ => {}
    }
    if writes_stack_pointer(insn)
        || matches!(
            insn.mnemonic.as_str(),
            "pushf" | "pushfq" | "popf" | "popfq" | "enter" | "leave"
        )
    {
        return None;
    }
    match decoded.flow_control() {
        FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
            Some(Step::Next(depth))
        }
        FlowControl::Return => (depth == 0).then_some(Step::Exit),
        FlowControl::Exception => Some(Step::Exit),
        FlowControl::Interrupt => {
            (decoded.mnemonic() == iced_x86::Mnemonic::Int3).then_some(Step::Exit)
        }
        FlowControl::UnconditionalBranch => {
            let target: u64 = decoded.near_branch_target();
            if (start..end).contains(&target) {
                Some(Step::Branch {
                    target,
                    depth,
                    falls_through: false,
                })
            } else {
                (depth == 0).then_some(Step::Exit)
            }
        }
        FlowControl::ConditionalBranch => {
            let target: u64 = decoded.near_branch_target();
            if (start..end).contains(&target) {
                Some(Step::Branch {
                    target,
                    depth,
                    falls_through: true,
                })
            } else {
                (depth == 0).then_some(Step::Next(depth))
            }
        }
        FlowControl::IndirectBranch => (depth == 0).then_some(Step::Exit),
        FlowControl::XbeginXabortXend => None,
    }
}

fn entry_home_save(insn: &DisasmInsn) -> bool {
    if insn.mnemonic != "mov" {
        return false;
    }
    let Some((destination, source)): Option<(&str, &str)> = insn.operands.split_once(',') else {
        return false;
    };
    let source_is_register: bool =
        parse_reg(source.trim()).is_some_and(|register| register.width == Width::W64);
    source_is_register
        && super::rsp_relative_displacements_of(destination).is_some_and(|disp: i64| {
            (RETURN_ADDRESS_BYTES..=0x20).contains(&disp) && disp % SLOT_BYTES == 0
        })
}

fn depths(insns: &[DisasmInsn]) -> Option<BTreeMap<u64, i64>> {
    let first: &DisasmInsn = insns.first()?;
    let last: &DisasmInsn = insns.last()?;
    let start: u64 = first.address;
    let end: u64 = last
        .address
        .checked_add(u64::try_from(last.bytes.len()).ok()?)?;
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(position, insn): (usize, &DisasmInsn)| (insn.address, position))
        .collect();
    let mut depth: Vec<Option<i64>> = vec![None; insns.len()];
    let mut pending: Vec<(usize, i64)> = vec![(0, 0)];
    while let Some((position, at)) = pending.pop() {
        match depth.get(position).copied()? {
            Some(known) if known == at => continue,
            Some(_) => return None,
            None => {}
        }
        *depth.get_mut(position)? = Some(at);
        let insn: &DisasmInsn = insns.get(position)?;
        let decoded: Instruction = decode_one_x86(64, insn.address, &insn.bytes)?;
        match step(insn, &decoded, at, start, end)? {
            Step::Next(after) => pending.push((
                position.checked_add(1).filter(|next| *next < insns.len())?,
                after,
            )),
            Step::Branch {
                target,
                depth: after,
                falls_through,
            } => {
                pending.push((*index.get(&target)?, after));
                if falls_through {
                    pending.push((
                        position.checked_add(1).filter(|next| *next < insns.len())?,
                        after,
                    ));
                }
            }
            Step::Exit => {}
        }
    }
    Some(
        insns
            .iter()
            .zip(depth)
            .filter_map(|(insn, at): (&DisasmInsn, Option<i64>)| {
                at.map(|at: i64| (insn.address, at))
            })
            .collect(),
    )
}

fn leaves_the_stack_alone(insn: &DisasmInsn) -> bool {
    !writes_stack_pointer(insn)
        && !super::stack_depth_changing_mnemonic(&insn.mnemonic)
        && !insn
            .operands
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|token: &str| token == "rsp")
}

fn epilogue_instruction(insn: &DisasmInsn) -> bool {
    matches!(
        insn.mnemonic.as_str(),
        "pop" | "ret" | "jmp" | "nop" | "int3"
    ) || (insn.mnemonic == "add" && writes_stack_pointer(insn))
}

pub(super) fn plan_push_frame(insns: &[DisasmInsn], abi: Abi) -> Option<PushFrame> {
    if abi != Abi::MsX64 {
        return None;
    }
    let real: Vec<&DisasmInsn> = insns
        .iter()
        .filter(|insn: &&DisasmInsn| !matches!(insn.mnemonic.as_str(), "nop" | "endbr64"))
        .collect();
    if real.iter().any(|insn: &&DisasmInsn| {
        (insn.mnemonic == "mov" && is_stack_pointer_move(&insn.operands))
            || (insn.mnemonic == "lea" && is_rbp_lea_frame(&insn.operands))
    }) {
        return None;
    }
    let mut pushed: Vec<Reg> = Vec::new();
    let mut allocation: i64 = 0;
    let mut prologue_end: usize = 0;
    for (position, insn) in real.iter().enumerate() {
        if allocation == 0 && pushed.is_empty() && entry_home_save(insn) {
            prologue_end = position + 1;
            continue;
        }
        if allocation == 0 && insn.mnemonic == "push" {
            pushed.push(register_operand(insn)?);
            if pushed.len() > MAX_PUSHED_REGISTERS {
                return None;
            }
            prologue_end = position + 1;
            continue;
        }
        if allocation == 0 && insn.mnemonic == "sub" && writes_stack_pointer(insn) {
            allocation = rsp_delta_imm("sub", &insn.operands)?;
            prologue_end = position + 1;
            continue;
        }
        if allocation == 0 && pushed.is_empty() && leaves_the_stack_alone(insn) {
            continue;
        }
        break;
    }
    if pushed.is_empty() && allocation == 0 {
        return None;
    }
    let depths: BTreeMap<u64, i64> = depths(insns)?;
    let pushed_bytes: i64 = i64::try_from(pushed.len()).ok()?.checked_mul(SLOT_BYTES)?;
    let body_depth: i64 = pushed_bytes.checked_add(allocation)?.checked_neg()?;
    let prologue: Vec<u64> = real
        .iter()
        .take(prologue_end)
        .map(|insn: &&DisasmInsn| insn.address)
        .collect();
    for insn in insns {
        let Some(&at): Option<&i64> = depths.get(&insn.address) else {
            if super::rsp_relative_displacements(insn).next().is_some() {
                return None;
            }
            continue;
        };
        if at == body_depth || prologue.contains(&insn.address) {
            if at == body_depth && insn.mnemonic == "push" {
                return None;
            }
            continue;
        }
        if at == 0 && leaves_the_stack_alone(insn) {
            continue;
        }
        if !epilogue_instruction(insn) {
            return None;
        }
        if insn.mnemonic == "pop" {
            let slot: usize =
                usize::try_from(at.checked_sub(body_depth)?.checked_sub(allocation)? / SLOT_BYTES)
                    .ok()?;
            let expected: Reg = *pushed.iter().rev().nth(slot)?;
            if register_operand(insn)? != expected {
                return None;
            }
        }
    }
    Some(PushFrame {
        depths,
        body_depth,
        pushed_bytes,
        allocation,
        home_bytes: home_space_above_return(abi),
    })
}

fn rebase(mem: &mut MemRef, shift: i64) -> Result<()> {
    if mem.base == Some(Reg::Rsp) && mem.index.is_none() {
        mem.disp = mem.disp.checked_add(shift).ok_or_else(|| {
            Error::LlvmIr(
                "stack-relative displacement overflows after rebasing to the body frame".to_owned(),
            )
        })?;
    }
    Ok(())
}

fn rebase_source(source: &mut Source, shift: i64) -> Result<()> {
    match source {
        Source::Mem(mem) => rebase(mem, shift)?,
        Source::Lea {
            base: Some(Reg::Rsp),
            index: None,
            disp,
        } => {
            *disp = disp.checked_add(shift).ok_or_else(|| {
                Error::LlvmIr(
                    "stack-relative displacement overflows after rebasing to the body frame"
                        .to_owned(),
                )
            })?;
        }
        Source::Reg(_) | Source::Imm(_) | Source::Lea { .. } => {}
    }
    Ok(())
}

fn rebase_fp(operand: &mut FpOperand, shift: i64) -> Result<()> {
    if let FpOperand::Mem(mem) = operand {
        rebase(mem, shift)?;
    }
    Ok(())
}

fn rebase_flags(flags: &mut Flags, shift: i64) -> Result<()> {
    match flags {
        Flags::Cmp { rhs, .. } | Flags::Add { rhs, .. } => rebase_source(rhs, shift),
        Flags::CmpMem { lhs, rhs } => {
            rebase(lhs, shift)?;
            rebase_source(rhs, shift)
        }
        Flags::FpCmp { rhs, .. } => rebase_fp(rhs, shift),
        Flags::CondCmp { prior, taken, .. } => {
            rebase_flags(prior, shift)?;
            rebase_flags(taken, shift)
        }
        Flags::Test { .. }
        | Flags::TestImm { .. }
        | Flags::Sign { .. }
        | Flags::Snapshot { .. } => Ok(()),
    }
}

fn rebase_stmt(stmt: &mut Stmt, shift: i64) -> Result<()> {
    match stmt {
        Stmt::Assign { src, .. } | Stmt::BinAssign { src, .. } => rebase_source(src, shift),
        Stmt::Cond { src, flags, .. } => {
            rebase_source(src, shift)?;
            rebase_flags(flags, shift)
        }
        Stmt::SetCc { flags, .. } | Stmt::FlagSnapshot { flags, .. } => rebase_flags(flags, shift),
        Stmt::Store { addr, src } => {
            rebase(addr, shift)?;
            rebase_source(src, shift)
        }
        Stmt::MemRmw { addr, op } => {
            rebase(addr, shift)?;
            if let super::MemRmwOp::Bin { src, .. } = op {
                rebase_source(src, shift)?;
            }
            Ok(())
        }
        Stmt::Extend { src, .. } | Stmt::MulImm { src, .. } => {
            if let ExtSource::Mem(mem) = src {
                rebase(mem, shift)?;
            }
            Ok(())
        }
        Stmt::FpBin { lhs, rhs, .. } | Stmt::FpMinMax { lhs, rhs, .. } => {
            rebase_fp(lhs, shift)?;
            rebase_fp(rhs, shift)
        }
        Stmt::FpMov { src, .. }
        | Stmt::FpSqrt { src, .. }
        | Stmt::FpUnary { src, .. }
        | Stmt::FpRound { src, .. } => rebase_fp(src, shift),
        Stmt::FpFma {
            mul_lhs,
            mul_rhs,
            addend,
            ..
        } => {
            rebase_fp(mul_lhs, shift)?;
            rebase_fp(mul_rhs, shift)?;
            rebase_fp(addend, shift)
        }
        Stmt::FpCsel {
            if_true,
            if_false,
            flags,
            ..
        } => {
            rebase_fp(if_true, shift)?;
            rebase_fp(if_false, shift)?;
            rebase_flags(flags, shift)
        }
        Stmt::FpStore { addr, .. } => rebase(addr, shift),
        Stmt::Vector(VecStmt::Load { addr, .. } | VecStmt::Store { addr, .. }) => {
            rebase(addr, shift)
        }
        Stmt::UnAssign { .. }
        | Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpToInt { .. }
        | Stmt::FpConvert { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::XmmToGpr { .. }
        | Stmt::DoubleShift { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Call { .. }
        | Stmt::Packed { .. }
        | Stmt::PackedToGpr { .. }
        | Stmt::Vector(_) => Ok(()),
    }
}

pub(super) fn rebase_items_to_the_body_frame(items: &mut [Item], frame: &PushFrame) -> Result<()> {
    for item in items {
        let Some(&at): Option<&i64> = frame.depths.get(&item.address) else {
            continue;
        };
        let shift: i64 = at
            .checked_sub(frame.body_depth)
            .ok_or_else(|| Error::LlvmIr("stack depth difference overflows".to_owned()))?;
        if shift == 0 {
            continue;
        }
        match &mut item.kind {
            ItemKind::Stmt(stmt) => rebase_stmt(stmt, shift)?,
            ItemKind::Branch { flags, .. } => rebase_flags(flags, shift)?,
            ItemKind::Jmp { .. } | ItemKind::Switch { .. } | ItemKind::Ret => {}
        }
    }
    Ok(())
}
