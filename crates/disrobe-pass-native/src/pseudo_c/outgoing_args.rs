use std::collections::BTreeSet;

use crate::arch::DisasmInsn;
use crate::error::{Error, Result};

use super::{
    Abi, BinOp, CallTarget, ExtSource, Flags, FpOperand, FpWidth, FrameClass, FrameShape, Item,
    ItemKind, MS_X64_HOME_BYTES, MemRef, MemRmwOp, Reg, RegRef, Source, Stmt, VecStmt, Width,
    rsp_delta_imm, writes_stack_pointer, x86_outgoing_argument_reg,
};

const SLOT_BYTES: i64 = 8;
const VECTOR_ACCESS_BYTES: i64 = 16;

const fn fp_bytes(width: FpWidth) -> i64 {
    match width {
        FpWidth::F16 => 2,
        FpWidth::F32 => 4,
        FpWidth::F64 => 8,
    }
}

#[derive(Debug, Default)]
struct SlotUse {
    written: BTreeSet<i64>,
    read: BTreeSet<i64>,
}

impl SlotUse {
    fn note(&mut self, mem: &MemRef, bytes: i64, write: bool) {
        if mem.base != Some(Reg::Rsp) || mem.index.is_some() {
            return;
        }
        let Some(end): Option<i64> = mem.disp.checked_add(bytes) else {
            return;
        };
        if end <= MS_X64_HOME_BYTES {
            return;
        }
        let first: i64 = mem
            .disp
            .max(MS_X64_HOME_BYTES)
            .saturating_sub(MS_X64_HOME_BYTES)
            / SLOT_BYTES;
        let last: i64 = end.saturating_sub(1).saturating_sub(MS_X64_HOME_BYTES) / SLOT_BYTES;
        let target: &mut BTreeSet<i64> = if write {
            &mut self.written
        } else {
            &mut self.read
        };
        target.extend(first..=last);
    }

    fn note_scalar(&mut self, mem: &MemRef, write: bool) {
        self.note(mem, i64::from(mem.width.bits() / 8), write);
    }

    fn note_source(&mut self, source: &Source) {
        if let Source::Mem(mem) = source {
            self.note_scalar(mem, false);
        }
    }

    fn note_fp(&mut self, operand: &FpOperand, bytes: i64) {
        if let FpOperand::Mem(mem) = operand {
            self.note(mem, bytes, false);
        }
    }

    fn note_flags(&mut self, flags: &Flags) {
        match flags {
            Flags::Cmp { rhs, .. } | Flags::Add { rhs, .. } => self.note_source(rhs),
            Flags::CmpMem { lhs, rhs } => {
                self.note_scalar(lhs, false);
                self.note_source(rhs);
            }
            Flags::FpCmp { rhs, width, .. } => self.note_fp(rhs, fp_bytes(*width)),
            Flags::CondCmp { prior, taken, .. } => {
                self.note_flags(prior);
                self.note_flags(taken);
            }
            Flags::Test { .. }
            | Flags::TestImm { .. }
            | Flags::Sign { .. }
            | Flags::Snapshot { .. } => {}
        }
    }

    fn note_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { src, .. } | Stmt::BinAssign { src, .. } => self.note_source(src),
            Stmt::Cond { src, flags, .. } => {
                self.note_source(src);
                self.note_flags(flags);
            }
            Stmt::SetCc { flags, .. } | Stmt::FlagSnapshot { flags, .. } => self.note_flags(flags),
            Stmt::Store { addr, src } => {
                self.note_source(src);
                self.note_scalar(addr, true);
            }
            Stmt::MemRmw { addr, op } => {
                if let Some(src) = op.source() {
                    self.note_source(src);
                }
                if !rmw_ignores_the_old_value(op) {
                    self.note_scalar(addr, false);
                }
                self.note_scalar(addr, true);
            }
            Stmt::Extend { src, .. } | Stmt::MulImm { src, .. } => {
                if let ExtSource::Mem(mem) = src {
                    self.note_scalar(mem, false);
                }
            }
            Stmt::FpBin {
                lhs, rhs, width, ..
            }
            | Stmt::FpMinMax {
                lhs, rhs, width, ..
            } => {
                let bytes: i64 = fp_bytes(*width);
                self.note_fp(lhs, bytes);
                self.note_fp(rhs, bytes);
            }
            Stmt::FpMov { src, width, .. }
            | Stmt::FpSqrt { src, width, .. }
            | Stmt::FpUnary { src, width, .. }
            | Stmt::FpRound { src, width, .. } => self.note_fp(src, fp_bytes(*width)),
            Stmt::FpFma {
                mul_lhs,
                mul_rhs,
                addend,
                width,
                ..
            } => {
                let bytes: i64 = fp_bytes(*width);
                self.note_fp(mul_lhs, bytes);
                self.note_fp(mul_rhs, bytes);
                self.note_fp(addend, bytes);
            }
            Stmt::FpCsel {
                if_true,
                if_false,
                flags,
                width,
                ..
            } => {
                let bytes: i64 = fp_bytes(*width);
                self.note_fp(if_true, bytes);
                self.note_fp(if_false, bytes);
                self.note_flags(flags);
            }
            Stmt::FpStore { addr, width, .. } => {
                self.note(addr, fp_bytes(*width), true);
            }
            Stmt::Vector(VecStmt::Load { addr, .. }) => {
                self.note(addr, VECTOR_ACCESS_BYTES, false);
            }
            Stmt::Vector(VecStmt::Store { addr, .. }) => {
                self.note(addr, VECTOR_ACCESS_BYTES, true);
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
            | Stmt::Vector(_) => {}
        }
    }
}

fn rmw_ignores_the_old_value(op: &MemRmwOp) -> bool {
    matches!(
        op,
        MemRmwOp::Bin {
            op: BinOp::And,
            src: Source::Imm(0),
        } | MemRmwOp::Bin {
            op: BinOp::Or,
            src: Source::Imm(-1),
        }
    )
}

fn instruction_at(insns: &[DisasmInsn], address: u64) -> Option<&DisasmInsn> {
    insns
        .binary_search_by_key(&address, |insn: &DisasmInsn| insn.address)
        .ok()
        .and_then(|index: usize| insns.get(index))
}

fn allocation_address(insns: &[DisasmInsn]) -> Option<u64> {
    insns
        .iter()
        .find(|insn: &&DisasmInsn| {
            insn.mnemonic == "sub"
                && writes_stack_pointer(insn)
                && rsp_delta_imm("sub", &insn.operands).is_some()
        })
        .map(|insn: &DisasmInsn| insn.address)
}

fn unread_store_refusal(slot: i64) -> Error {
    let displacement: i64 = MS_X64_HOME_BYTES.saturating_add(slot.saturating_mul(SLOT_BYTES));
    Error::LlvmIr(format!(
        "a store to [rsp+{displacement:#x}] is never read back, so it is an outgoing stack argument of a direct call or tail jump that the call IR cannot carry"
    ))
}

pub(super) fn carry_ms_x64_outgoing_stack_arguments(
    items: &mut Vec<Item>,
    insns: &[DisasmInsn],
    abi: Abi,
    shape: FrameShape,
) -> Result<()> {
    if abi != Abi::MsX64 {
        return Ok(());
    }
    let mut call_sites: Vec<usize> = Vec::new();
    let mut tail_jump: bool = false;
    for (index, item) in items.iter().enumerate() {
        let ItemKind::Stmt(Stmt::Call {
            target: CallTarget::Address(_) | CallTarget::Slot(_) | CallTarget::Register,
            ..
        }) = &item.kind
        else {
            continue;
        };
        match instruction_at(insns, item.address) {
            Some(insn) if insn.mnemonic == "call" => call_sites.push(index),
            _ => tail_jump = true,
        }
    }
    if call_sites.is_empty() && !tail_jump {
        return Ok(());
    }
    let allocated: Option<(i64, u64)> = match (shape.class(), shape.stack_extent) {
        (FrameClass::AllocatedStackPointer, Some(extent)) => {
            allocation_address(insns).map(|address: u64| (extent.private_end, address))
        }
        _ => None,
    };
    let mut slots: SlotUse = SlotUse::default();
    for item in items.iter().filter(|item: &&Item| {
        allocated.is_none_or(|(_, allocation): (i64, u64)| item.address > allocation)
    }) {
        match &item.kind {
            ItemKind::Stmt(stmt) => slots.note_stmt(stmt),
            ItemKind::Branch { flags, .. } => slots.note_flags(flags),
            ItemKind::Jmp { .. } | ItemKind::Switch { .. } | ItemKind::Ret => {}
        }
    }
    let unread: Vec<i64> = slots.written.difference(&slots.read).copied().collect();
    let Some(&highest_unread): Option<&i64> = unread.last() else {
        return Ok(());
    };
    if tail_jump {
        return Err(unread_store_refusal(highest_unread));
    }
    let Some((frame_bytes, _)): Option<(i64, u64)> = allocated else {
        return Err(unread_store_refusal(highest_unread));
    };
    let owned_slots: i64 = frame_bytes.saturating_sub(MS_X64_HOME_BYTES) / SLOT_BYTES;
    let Some(&highest): Option<&i64> = unread.iter().rev().find(|slot: &&i64| **slot < owned_slots)
    else {
        return Ok(());
    };
    let count: usize = usize::try_from(highest.saturating_add(1)).map_err(|_| {
        Error::LlvmIr("outgoing stack argument count does not fit the call IR".to_owned())
    })?;
    let outgoing: Vec<Reg> = (0..count)
        .map(|slot: usize| {
            x86_outgoing_argument_reg(slot).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "outgoing stack argument {} exceeds the bounded eight-slot call IR",
                    slot.saturating_add(5)
                ))
            })
        })
        .collect::<Result<Vec<Reg>>>()?;
    for &site in call_sites.iter().rev() {
        let Some(item): Option<&mut Item> = items.get_mut(site) else {
            continue;
        };
        let address: u64 = item.address;
        if let ItemKind::Stmt(Stmt::Call { target, args, .. }) = &mut item.kind {
            if matches!(target, CallTarget::Slot(_)) && args.len() < abi.arg_order().len() {
                continue;
            }
            args.extend(outgoing.iter().copied());
        }
        let loads: Vec<Item> = outgoing
            .iter()
            .zip((MS_X64_HOME_BYTES..).step_by(8))
            .map(|(reg, disp): (&Reg, i64)| Item {
                address,
                kind: ItemKind::Stmt(Stmt::Assign {
                    dest: RegRef {
                        reg: *reg,
                        width: Width::W64,
                    },
                    src: Source::Mem(MemRef {
                        base: Some(Reg::Rsp),
                        index: None,
                        disp,
                        width: Width::W64,
                    }),
                }),
            })
            .collect();
        items.splice(site..site, loads);
    }
    Ok(())
}
