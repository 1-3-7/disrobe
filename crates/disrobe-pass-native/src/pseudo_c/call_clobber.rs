use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Register, UsedRegister};

use crate::arch::{Arch, DisasmInsn, decode_one_x86, disassemble};
use crate::error::{Error, Result};

use super::{
    Abi, CallTarget, ExtSource, Flags, FpOperand, Item, ItemKind, MemRef, PackedOp, Reg, RegRef,
    ResolvedCall, Source, Stmt, VecStmt, Width, callee_code_by_target, flag_operand_xmms,
    fp_stmt_result_xmm, iced_register, instruction_access_writes,
    return_channel::stmt_xmm_data_reads,
};

const SYSV_VOLATILE: [Reg; 9] = [
    Reg::Rax,
    Reg::Rcx,
    Reg::Rdx,
    Reg::Rsi,
    Reg::Rdi,
    Reg::R8,
    Reg::R9,
    Reg::R10,
    Reg::R11,
];

const MS_X64_VOLATILE: [Reg; 7] = [
    Reg::Rax,
    Reg::Rcx,
    Reg::Rdx,
    Reg::R8,
    Reg::R9,
    Reg::R10,
    Reg::R11,
];

const AAPCS64_VOLATILE: [Reg; 19] = [
    Reg::Rax,
    Reg::A64X1,
    Reg::A64X2,
    Reg::A64X3,
    Reg::A64X4,
    Reg::A64X5,
    Reg::A64X6,
    Reg::A64X7,
    Reg::A64X8,
    Reg::A64X9,
    Reg::A64X10,
    Reg::A64X11,
    Reg::A64X12,
    Reg::A64X13,
    Reg::A64X14,
    Reg::A64X15,
    Reg::A64X16,
    Reg::A64X17,
    Reg::A64X18,
];

const CALL_RESULT: Reg = Reg::Rax;

const FP_REGISTER_COUNT: u8 = 32;

const MAX_CALLEE_FUNCTIONS: usize = 64;

const MAX_CALLEE_BYTES: usize = 1 << 16;

const fn volatile_gprs(abi: Abi) -> &'static [Reg] {
    match abi {
        Abi::SysV => &SYSV_VOLATILE,
        Abi::MsX64 => &MS_X64_VOLATILE,
        Abi::Aapcs64 => &AAPCS64_VOLATILE,
    }
}

const fn fp_register_is_volatile(abi: Abi, index: u8) -> bool {
    match abi {
        Abi::SysV => true,
        Abi::MsX64 => index <= 5 || index >= 16,
        Abi::Aapcs64 => index <= 7 || index >= 16,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CalleeClobbers {
    gprs: BTreeSet<Reg>,
    fp: BTreeSet<u8>,
}

impl CalleeClobbers {
    fn note(&mut self, abi: Abi, written: Register) {
        let full: Register = written.full_register();
        if let Some(reg) = volatile_gprs(abi)
            .iter()
            .find(|reg: &&Reg| iced_register(**reg).map(Register::full_register) == Some(full))
        {
            self.gprs.insert(*reg);
            return;
        }
        let index: u32 = (full as u32).wrapping_sub(Register::ZMM0 as u32);
        if let Ok(index) = u8::try_from(index)
            && index < FP_REGISTER_COUNT
            && fp_register_is_volatile(abi, index)
        {
            self.fp.insert(index);
        }
    }

    fn absorb(&mut self, other: &Self) {
        self.gprs.extend(other.gprs.iter().copied());
        self.fp.extend(other.fp.iter().copied());
    }
}

struct CalleeScan<'a> {
    object: &'a [u8],
    abi: Abi,
    memo: BTreeMap<u64, Option<CalleeClobbers>>,
    active: BTreeSet<u64>,
    factory: InstructionInfoFactory,
}

impl CalleeScan<'_> {
    fn clobbers(&mut self, code: &[u8], base: u64) -> Option<CalleeClobbers> {
        if let Some(known) = self.memo.get(&base) {
            return known.clone();
        }
        if self.active.contains(&base)
            || self.memo.len() >= MAX_CALLEE_FUNCTIONS
            || code.len() > MAX_CALLEE_BYTES
        {
            return None;
        }
        self.active.insert(base);
        let scanned: Option<CalleeClobbers> = self.scan(code, base);
        self.active.remove(&base);
        self.memo.insert(base, scanned.clone());
        scanned
    }

    fn transfer(
        &mut self,
        decoded: &Instruction,
        own: (u64, u64),
        acc: &mut CalleeClobbers,
    ) -> Option<()> {
        let target: u64 = decoded.near_branch_target();
        match callee_code_by_target(self.object, target) {
            Some((_, base)) if base == own.0 => Some(()),
            Some((code, base)) => {
                acc.absorb(&self.clobbers(&code, base)?);
                Some(())
            }
            None => (decoded.flow_control() != FlowControl::Call
                && (own.0..own.1).contains(&target))
            .then_some(()),
        }
    }

    fn scan(&mut self, code: &[u8], base: u64) -> Option<CalleeClobbers> {
        let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, code).ok()?;
        let end: u64 = base.checked_add(u64::try_from(code.len()).ok()?)?;
        let mut acc: CalleeClobbers = CalleeClobbers::default();
        for insn in &insns {
            let decoded: Instruction = decode_one_x86(64, insn.address, &insn.bytes)?;
            let written: Vec<Register> = self
                .factory
                .info(&decoded)
                .used_registers()
                .iter()
                .filter(|used: &&UsedRegister| instruction_access_writes(used.access()))
                .map(UsedRegister::register)
                .collect();
            for register in written {
                acc.note(self.abi, register);
            }
            match decoded.flow_control() {
                FlowControl::Next | FlowControl::Return | FlowControl::Exception => {}
                FlowControl::Call
                | FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch => {
                    self.transfer(&decoded, (base, end), &mut acc)?;
                }
                FlowControl::IndirectBranch
                | FlowControl::IndirectCall
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend => return None,
            }
        }
        Some(acc)
    }
}

pub(super) fn object_callee_clobbers(
    object: &[u8],
    insns: &[DisasmInsn],
    abi: Abi,
) -> BTreeMap<u64, CalleeClobbers> {
    let mut scan: CalleeScan<'_> = CalleeScan {
        object,
        abi,
        memo: BTreeMap::new(),
        active: BTreeSet::new(),
        factory: InstructionInfoFactory::new(),
    };
    let mut sites: BTreeMap<u64, CalleeClobbers> = BTreeMap::new();
    for insn in insns {
        let Some(decoded): Option<Instruction> = decode_one_x86(64, insn.address, &insn.bytes)
        else {
            continue;
        };
        if decoded.flow_control() != FlowControl::Call {
            continue;
        }
        let Some((code, base)): Option<(Vec<u8>, u64)> =
            callee_code_by_target(object, decoded.near_branch_target())
        else {
            continue;
        };
        if let Some(clobbers) = scan.clobbers(&code, base) {
            sites.insert(insn.address, clobbers);
        }
    }
    sites
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Clobber {
    call: u64,
    defined_bits: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ClobberState {
    gpr: BTreeMap<Reg, Clobber>,
    fp: BTreeMap<u8, u64>,
}

impl ClobberState {
    fn join(&mut self, other: &Self) -> bool {
        let before: Self = self.clone();
        for (reg, incoming) in &other.gpr {
            let merged: Clobber =
                self.gpr
                    .get(reg)
                    .map_or(*incoming, |current: &Clobber| Clobber {
                        call: current.call.min(incoming.call),
                        defined_bits: current.defined_bits.min(incoming.defined_bits),
                    });
            self.gpr.insert(*reg, merged);
        }
        for (index, call) in &other.fp {
            let merged: u64 = self
                .fp
                .get(index)
                .map_or(*call, |current: &u64| (*current).min(*call));
            self.fp.insert(*index, merged);
        }
        *self != before
    }

    fn clobber(&mut self, abi: Abi, call: u64, callee: Option<&CalleeClobbers>) {
        for reg in volatile_gprs(abi) {
            if *reg != CALL_RESULT
                && callee.is_none_or(|known: &CalleeClobbers| known.gprs.contains(reg))
            {
                self.gpr.insert(
                    *reg,
                    Clobber {
                        call,
                        defined_bits: 0,
                    },
                );
            }
        }
        self.gpr.remove(&CALL_RESULT);
        for index in 0..FP_REGISTER_COUNT {
            if fp_register_is_volatile(abi, index)
                && callee.is_none_or(|known: &CalleeClobbers| known.fp.contains(&index))
            {
                self.fp.insert(index, call);
            }
        }
    }

    fn write_gpr(&mut self, reg: Reg, width: Width) {
        match width {
            Width::W32 | Width::W64 => {
                self.gpr.remove(&reg);
            }
            Width::W8 | Width::W16 => {
                if let Some(clobber) = self.gpr.get_mut(&reg) {
                    clobber.defined_bits = clobber.defined_bits.max(width.bits());
                }
            }
        }
    }
}

fn gpr_name(abi: Abi, reg: Reg) -> String {
    let variable: &str = super::reg_var(reg);
    match abi {
        Abi::Aapcs64 if reg == Reg::Rax => "x0".to_owned(),
        Abi::Aapcs64 if reg == Reg::Rbp => "x29".to_owned(),
        Abi::Aapcs64 => variable.trim_start_matches("r_a64_").to_owned(),
        Abi::SysV | Abi::MsX64 => variable.trim_start_matches("r_").to_owned(),
    }
}

fn fp_name(abi: Abi, index: u8) -> String {
    match abi {
        Abi::Aapcs64 => format!("v{index}"),
        Abi::SysV | Abi::MsX64 => format!("xmm{index}"),
    }
}

fn refusal(abi: Abi, register: &str, at: u64, call: u64) -> Error {
    let result: &str = match abi {
        Abi::Aapcs64 => "x0",
        Abi::SysV | Abi::MsX64 => "rax",
    };
    Error::LlvmIr(format!(
        "caller-saved register `{register}` is read at {at:#x} after the call at {call:#x} clobbered it: \
         under {abi:?} the callee may overwrite it, and the lifted call defines only `{result}` \
         (a second return register or a floating-point result is not modelled)"
    ))
}

fn push_mem(mem: &MemRef, acc: &mut Vec<RegRef>) {
    if let Some(base) = mem.base {
        acc.push(RegRef {
            reg: base,
            width: Width::W64,
        });
    }
    if let Some(index) = mem.index {
        acc.push(RegRef {
            reg: index.reg,
            width: Width::W64,
        });
    }
}

fn push_source(src: &Source, acc: &mut Vec<RegRef>) {
    match src {
        Source::Reg(reg) => acc.push(*reg),
        Source::Imm(_) => {}
        Source::Lea { base, index, .. } => {
            if let Some(base) = base {
                acc.push(RegRef {
                    reg: *base,
                    width: Width::W64,
                });
            }
            if let Some(index) = index {
                acc.push(RegRef {
                    reg: index.reg,
                    width: Width::W64,
                });
            }
        }
        Source::Mem(mem) => push_mem(mem, acc),
    }
}

fn push_fp_operand(operand: &FpOperand, acc: &mut Vec<RegRef>) {
    if let FpOperand::Mem(mem) = operand {
        push_mem(mem, acc);
    }
}

fn push_flags(flags: &Flags, acc: &mut Vec<RegRef>) {
    match flags {
        Flags::Cmp { lhs, rhs } | Flags::Add { lhs, rhs } => {
            acc.push(*lhs);
            push_source(rhs, acc);
        }
        Flags::CmpMem { lhs, rhs } => {
            push_mem(lhs, acc);
            push_source(rhs, acc);
        }
        Flags::Test { operand } | Flags::TestImm { operand, .. } => acc.push(*operand),
        Flags::Sign { result } => acc.push(*result),
        Flags::FpCmp { rhs, .. } => push_fp_operand(rhs, acc),
        Flags::Snapshot { .. } => {}
        Flags::CondCmp { prior, taken, .. } => {
            push_flags(prior, acc);
            push_flags(taken, acc);
        }
    }
}

const fn wide_result_width(width: Width) -> Width {
    match width {
        Width::W8 => Width::W16,
        Width::W16 | Width::W32 | Width::W64 => width,
    }
}

fn gpr_reads(stmt: &Stmt, acc: &mut Vec<RegRef>) {
    match stmt {
        Stmt::Assign { src, .. } => push_source(src, acc),
        Stmt::BinAssign { dest, src, .. } => {
            acc.push(*dest);
            push_source(src, acc);
        }
        Stmt::UnAssign { dest, .. } => acc.push(*dest),
        Stmt::Cond {
            dest, src, flags, ..
        } => {
            acc.push(*dest);
            push_source(src, acc);
            push_flags(flags, acc);
        }
        Stmt::SetCc { flags, .. } | Stmt::FlagSnapshot { flags, .. } => push_flags(flags, acc),
        Stmt::FpCsel {
            if_true,
            if_false,
            flags,
            ..
        } => {
            push_fp_operand(if_true, acc);
            push_fp_operand(if_false, acc);
            push_flags(flags, acc);
        }
        Stmt::Store { addr, src } => {
            push_mem(addr, acc);
            push_source(src, acc);
        }
        Stmt::MemRmw { addr, op } => {
            push_mem(addr, acc);
            if let Some(src) = op.source() {
                push_source(src, acc);
            }
        }
        Stmt::Extend { src, .. } | Stmt::MulImm { src, .. } => match src {
            ExtSource::Reg(reg) => acc.push(*reg),
            ExtSource::Mem(mem) => push_mem(mem, acc),
        },
        Stmt::WideMul { src, .. } => {
            acc.push(RegRef {
                reg: Reg::Rax,
                width: src.width,
            });
            acc.push(*src);
        }
        Stmt::Divide { divisor, .. } => {
            acc.push(RegRef {
                reg: Reg::Rax,
                width: wide_result_width(divisor.width),
            });
            acc.push(*divisor);
        }
        Stmt::DoubleShift { dest, src, .. } => {
            acc.push(*dest);
            acc.push(*src);
        }
        Stmt::BlockMove { .. } => {
            for reg in [Reg::Rdi, Reg::Rsi, Reg::Rcx] {
                acc.push(RegRef {
                    reg,
                    width: Width::W64,
                });
            }
        }
        Stmt::BlockFill { elem } => {
            for reg in [Reg::Rdi, Reg::Rcx] {
                acc.push(RegRef {
                    reg,
                    width: Width::W64,
                });
            }
            acc.push(RegRef {
                reg: Reg::Rax,
                width: *elem,
            });
        }
        Stmt::IntToFp { src, .. } | Stmt::GprToXmm { src, .. } => acc.push(*src),
        Stmt::FpBin { lhs, rhs, .. } | Stmt::FpMinMax { lhs, rhs, .. } => {
            push_fp_operand(lhs, acc);
            push_fp_operand(rhs, acc);
        }
        Stmt::FpFma {
            mul_lhs,
            mul_rhs,
            addend,
            ..
        } => {
            for operand in [mul_lhs, mul_rhs, addend] {
                push_fp_operand(operand, acc);
            }
        }
        Stmt::FpMov { src, .. }
        | Stmt::FpSqrt { src, .. }
        | Stmt::FpUnary { src, .. }
        | Stmt::FpRound { src, .. } => push_fp_operand(src, acc),
        Stmt::FpStore { addr, .. } => push_mem(addr, acc),
        Stmt::Packed { op, .. } => {
            if let PackedOp::FromGpr { src } = op {
                acc.push(*src);
            }
        }
        Stmt::Vector(vector) => match vector {
            VecStmt::Load { addr, .. } | VecStmt::Store { addr, .. } => push_mem(addr, acc),
            VecStmt::Dup { src, .. } | VecStmt::LaneInsert { src, .. } => acc.push(*src),
            VecStmt::Bin { .. }
            | VecStmt::Compare { .. }
            | VecStmt::MoveImm { .. }
            | VecStmt::Reduce { .. }
            | VecStmt::ExtractToGpr { .. }
            | VecStmt::WidenExtend { .. }
            | VecStmt::WidenAdd { .. } => {}
        },
        Stmt::Call { .. }
        | Stmt::FpToInt { .. }
        | Stmt::XmmToGpr { .. }
        | Stmt::FpConvert { .. }
        | Stmt::PackedToGpr { .. } => {}
    }
}

fn gpr_writes(stmt: &Stmt, acc: &mut Vec<RegRef>) {
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::Cond { dest, .. }
        | Stmt::SetCc { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. }
        | Stmt::PackedToGpr { dest, .. }
        | Stmt::Vector(VecStmt::ExtractToGpr { dest, .. }) => acc.push(*dest),
        Stmt::WideMul { src: operand, .. }
        | Stmt::Divide {
            divisor: operand, ..
        } => {
            let width: Width = wide_result_width(operand.width);
            acc.push(RegRef {
                reg: Reg::Rax,
                width,
            });
            if operand.width != Width::W8 {
                acc.push(RegRef {
                    reg: Reg::Rdx,
                    width,
                });
            }
        }
        Stmt::BlockMove { .. } => {
            for reg in [Reg::Rdi, Reg::Rsi, Reg::Rcx] {
                acc.push(RegRef {
                    reg,
                    width: Width::W64,
                });
            }
        }
        Stmt::BlockFill { .. } => {
            for reg in [Reg::Rdi, Reg::Rcx] {
                acc.push(RegRef {
                    reg,
                    width: Width::W64,
                });
            }
        }
        Stmt::Call { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::FpCsel { .. }
        | Stmt::Store { .. }
        | Stmt::MemRmw { .. }
        | Stmt::IntToFp { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpMov { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::FpStore { .. }
        | Stmt::FpConvert { .. }
        | Stmt::Packed { .. }
        | Stmt::Vector(_) => {}
    }
}

fn fp_reads(stmt: &Stmt, acc: &mut Vec<u8>) {
    let mut registers: Vec<super::Xmm> = Vec::new();
    stmt_xmm_data_reads(stmt, &mut registers);
    if let Stmt::Cond { flags, .. }
    | Stmt::SetCc { flags, .. }
    | Stmt::FpCsel { flags, .. }
    | Stmt::FlagSnapshot { flags, .. } = stmt
    {
        registers.extend(flag_operand_xmms(flags));
    }
    acc.extend(registers.into_iter().map(super::Xmm::index));
    if let Stmt::Vector(vector) = stmt {
        match vector {
            VecStmt::Store { src, .. } | VecStmt::ExtractToGpr { src, .. } => acc.push(*src),
            VecStmt::Bin { lhs, rhs, .. } => acc.extend([*lhs, *rhs]),
            VecStmt::Compare { lhs, rhs, .. } => {
                acc.push(*lhs);
                acc.extend(*rhs);
            }
            VecStmt::Reduce { reg, .. } => acc.push(*reg),
            VecStmt::LaneInsert { dest, .. } => acc.push(*dest),
            VecStmt::WidenExtend { src, .. } => acc.push(*src),
            VecStmt::WidenAdd { src1, src2, .. } => acc.extend([*src1, *src2]),
            VecStmt::Load { .. } | VecStmt::Dup { .. } | VecStmt::MoveImm { .. } => {}
        }
    }
}

fn fp_writes(stmt: &Stmt) -> Option<u8> {
    if let Some((register, _)) = fp_stmt_result_xmm(stmt) {
        return Some(register.index());
    }
    match stmt {
        Stmt::Packed { dest, .. } => Some(dest.index()),
        Stmt::Vector(
            VecStmt::Load { dest, .. }
            | VecStmt::Bin { dest, .. }
            | VecStmt::Dup { dest, .. }
            | VecStmt::LaneInsert { dest, .. }
            | VecStmt::Compare { dest, .. }
            | VecStmt::MoveImm { dest, .. }
            | VecStmt::WidenExtend { dest, .. }
            | VecStmt::WidenAdd { dest, .. },
        ) => Some(*dest),
        _ => None,
    }
}

struct Context<'a> {
    abi: Abi,
    resolved: &'a BTreeSet<u64>,
    callees: &'a BTreeMap<u64, CalleeClobbers>,
    location: &'a dyn Fn(u64) -> u64,
}

impl Context<'_> {
    fn call_reads_arguments(&self, target: &CallTarget) -> bool {
        match target {
            CallTarget::Address(address) => self.resolved.contains(address),
            CallTarget::NoreturnLibrary(_) | CallTarget::RustPanicBoundsCheck => true,
            CallTarget::DirectTrap(_) => false,
        }
    }

    fn check_gprs(&self, state: &ClobberState, reads: &[RegRef], at: u64) -> Result<()> {
        for read in reads {
            if let Some(clobber) = state.gpr.get(&read.reg)
                && read.width.bits() > clobber.defined_bits
            {
                return Err(refusal(
                    self.abi,
                    &gpr_name(self.abi, read.reg),
                    (self.location)(at),
                    (self.location)(clobber.call),
                ));
            }
        }
        Ok(())
    }

    fn check_fps(&self, state: &ClobberState, reads: &[u8], at: u64) -> Result<()> {
        for index in reads {
            if let Some(call) = state.fp.get(index) {
                return Err(refusal(
                    self.abi,
                    &fp_name(self.abi, *index),
                    (self.location)(at),
                    (self.location)(*call),
                ));
            }
        }
        Ok(())
    }

    fn transfer(&self, item: &Item, state: &mut ClobberState) -> Result<()> {
        let mut reads: Vec<RegRef> = Vec::new();
        match &item.kind {
            ItemKind::Stmt(Stmt::Call { target, args, .. }) => {
                if self.call_reads_arguments(target) {
                    reads.extend(args.iter().map(|reg: &Reg| RegRef {
                        reg: *reg,
                        width: Width::W64,
                    }));
                    self.check_gprs(state, &reads, item.address)?;
                }
                state.clobber(self.abi, item.address, self.callees.get(&item.address));
            }
            ItemKind::Stmt(stmt) => {
                gpr_reads(stmt, &mut reads);
                self.check_gprs(state, &reads, item.address)?;
                let mut fp_read: Vec<u8> = Vec::new();
                fp_reads(stmt, &mut fp_read);
                self.check_fps(state, &fp_read, item.address)?;
                let mut writes: Vec<RegRef> = Vec::new();
                gpr_writes(stmt, &mut writes);
                for write in writes {
                    state.write_gpr(write.reg, write.width);
                }
                if let Some(index) = fp_writes(stmt) {
                    state.fp.remove(&index);
                }
            }
            ItemKind::Branch { flags, .. } => {
                push_flags(flags, &mut reads);
                self.check_gprs(state, &reads, item.address)?;
                let fp_read: Vec<u8> = flag_operand_xmms(flags)
                    .into_iter()
                    .map(super::Xmm::index)
                    .collect();
                self.check_fps(state, &fp_read, item.address)?;
            }
            ItemKind::Switch { disc, .. } => {
                self.check_gprs(state, &[*disc], item.address)?;
            }
            ItemKind::Jmp { .. } | ItemKind::Ret => {}
        }
        Ok(())
    }
}

fn successors(items: &[Item], first_at: &BTreeMap<u64, usize>, index: usize) -> Vec<usize> {
    let resolve = |target: u64| -> Option<usize> {
        first_at
            .range(target..)
            .next()
            .map(|(_, position): (&u64, &usize)| *position)
    };
    let next: Option<usize> = (index + 1 < items.len()).then_some(index + 1);
    match &items[index].kind {
        ItemKind::Stmt(_) => next.into_iter().collect(),
        ItemKind::Branch { target, .. } => resolve(*target).into_iter().chain(next).collect(),
        ItemKind::Jmp { target } => resolve(*target).into_iter().collect(),
        ItemKind::Switch { cases, default, .. } => cases
            .iter()
            .map(|(_, target): &(i64, u64)| *target)
            .chain(std::iter::once(*default))
            .filter_map(resolve)
            .collect(),
        ItemKind::Ret => Vec::new(),
    }
}

pub(super) fn refuse_reads_after_calls(
    items: &[Item],
    abi: Abi,
    calls: &[ResolvedCall],
    callees: &BTreeMap<u64, CalleeClobbers>,
    location: &dyn Fn(u64) -> u64,
) -> Result<()> {
    if !items
        .iter()
        .any(|item: &Item| matches!(item.kind, ItemKind::Stmt(Stmt::Call { .. })))
    {
        return Ok(());
    }
    let resolved: BTreeSet<u64> = calls
        .iter()
        .map(|call: &ResolvedCall| call.target)
        .collect();
    let context: Context<'_> = Context {
        abi,
        resolved: &resolved,
        callees,
        location,
    };
    let mut first_at: BTreeMap<u64, usize> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        first_at.entry(item.address).or_insert(index);
    }
    let mut entry_states: Vec<Option<ClobberState>> = vec![None; items.len()];
    entry_states[0] = Some(ClobberState::default());
    let mut pending: BTreeSet<usize> = BTreeSet::from([0]);
    while let Some(index) = pending.pop_first() {
        let Some(mut state): Option<ClobberState> = entry_states[index].clone() else {
            continue;
        };
        context.transfer(&items[index], &mut state)?;
        for successor in successors(items, &first_at, index) {
            let changed: bool = match &mut entry_states[successor] {
                Some(existing) => existing.join(&state),
                slot @ None => {
                    *slot = Some(state.clone());
                    true
                }
            };
            if changed {
                pending.insert(successor);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::super::{Abi, LeafRecovery, recover_leaf_function_abi};

    const PROLOGUE: [u8; 9] = [0x53, 0x48, 0x89, 0xcb, 0xe8, 0x00, 0x01, 0x00, 0x00];
    const EPILOGUE: [u8; 8] = [0x48, 0x01, 0xd0, 0x48, 0x01, 0xd8, 0x5b, 0xc3];

    fn body(middle: &[u8]) -> Vec<u8> {
        PROLOGUE
            .iter()
            .chain(middle)
            .chain(EPILOGUE.iter())
            .copied()
            .collect()
    }

    #[test]
    fn a_byte_defined_after_the_call_and_zero_extended_lifts_with_a_callee_saved_read() {
        let code: Vec<u8> = body(&[0x85, 0xc0, 0x0f, 0x95, 0xc2, 0x0f, 0xb6, 0xd2]);
        let recovery: LeafRecovery = recover_leaf_function_abi(&code, 0x4000, Abi::MsX64)
            .expect("setne dl then movzx edx, dl defines rdx after the call");
        assert_eq!(recovery.call_targets, vec![0x4109], "{}", recovery.source);
    }

    #[test]
    fn a_byte_defined_after_the_call_read_at_full_width_refuses() {
        let code: Vec<u8> = body(&[0x85, 0xc0, 0x0f, 0x95, 0xc2]);
        let error: String = recover_leaf_function_abi(&code, 0x4000, Abi::MsX64)
            .expect_err("bits 8 to 63 of rdx still hold the callee's value")
            .to_string();
        assert!(
            error
                .contains("caller-saved register `rdx` is read at 0x400e after the call at 0x4004"),
            "{error}"
        );
    }

    #[test]
    fn a_clobber_reaching_a_read_through_the_back_edge_refuses() {
        let code: [u8; 15] = [
            0x31, 0xc9, 0x48, 0x01, 0xc8, 0xe8, 0x00, 0x01, 0x00, 0x00, 0x85, 0xc0, 0x75, 0xf4,
            0xc3,
        ];
        let error: String = recover_leaf_function_abi(&code, 0x5000, Abi::SysV)
            .expect_err("the second iteration reads rcx after the call clobbered it")
            .to_string();
        assert!(
            error
                .contains("caller-saved register `rcx` is read at 0x5002 after the call at 0x5005"),
            "{error}"
        );
    }
}
