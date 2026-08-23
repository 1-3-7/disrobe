use serde::{Deserialize, Serialize};

use crate::stub_emu::{Cpu, CpuMode, HostCall, Memory, Perm, Reg, Regs};

use super::detect::{Bitness, HandlerEntry, VmStructure};
use super::microop::{BinKind, CmpKind, MicroOp, UnKind, VmOperand};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerSemantics {
    pub index: usize,
    pub micro_op: MicroOp,
    pub operand: VmOperand,
    pub operand_width: u8,
    pub pc_advance: u8,
    pub sp_delta: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    NoHandlers,
    EmuSetupFailed,
}

const CTX_BASE: u64 = 0x0001_0000;
const REGS_BASE: u64 = 0x0002_0000;
const STACK_BASE: u64 = 0x0003_0000;
const PC_CELL: u64 = 0x0004_0000;
const PROG_BASE: u64 = 0x0004_1000;
const SP_CELL: u64 = 0x0005_0000;
const SCRATCH_BASE: u64 = 0x0006_0000;
const CODE_SCRATCH: u64 = 0x0007_0000;
const STACK_TOP: u64 = 0x000F_0000;

const NUM_PROBE_REGS: usize = 8;
const STACK_INIT_DEPTH: usize = 8;
const SLOT: u64 = 8;

const HOST_RETURN_SENTINEL: u64 = 0x00AB_CDEF_0000_0000;

const VM_HALT_PC: u64 = 0xFFFF_FFFF;

struct ProbeVector {
    regs: [i64; NUM_PROBE_REGS],
    stack: [i64; STACK_INIT_DEPTH],
    reg_index: u8,
    operand_imm: i64,
    branch_target: u32,
}

#[derive(Debug, Clone)]
struct ProbeOutcome {
    regs_after: Vec<i64>,
    stack_after: Vec<i64>,
    sp_after: i64,
    pc_after: u64,
    halted: bool,
}

pub fn fingerprint_handlers(
    _bytes: &[u8],
    bitness: Bitness,
    structure: &VmStructure,
) -> Result<Vec<HandlerSemantics>, FingerprintError> {
    if structure.handlers.is_empty() {
        return Err(FingerprintError::NoHandlers);
    }
    let mode: CpuMode = match bitness {
        Bitness::Bits32 => CpuMode::Bits32,
        Bitness::Bits64 => CpuMode::Bits64,
    };
    let mut out: Vec<HandlerSemantics> = Vec::with_capacity(structure.handlers.len());
    for handler in &structure.handlers {
        let sem: HandlerSemantics = fingerprint_one(mode, bitness, structure, handler);
        out.push(sem);
    }
    Ok(out)
}

fn fingerprint_one(
    mode: CpuMode,
    bitness: Bitness,
    structure: &VmStructure,
    handler: &HandlerEntry,
) -> HandlerSemantics {
    let vectors: Vec<ProbeVector> = probe_vectors();
    let mut outcomes: Vec<ProbeOutcome> = Vec::with_capacity(vectors.len());
    for v in &vectors {
        match run_probe(mode, bitness, structure, handler, v) {
            Some(o) => outcomes.push(o),
            None => {
                return HandlerSemantics {
                    index: handler.index,
                    micro_op: MicroOp::Unknown,
                    operand: VmOperand::None,
                    operand_width: 0,
                    pc_advance: 0,
                    sp_delta: 0,
                };
            }
        }
    }
    classify(handler.index, &vectors, &outcomes)
}

fn probe_vectors() -> Vec<ProbeVector> {
    let bases: [([i64; NUM_PROBE_REGS], [i64; STACK_INIT_DEPTH], u8, u32); 9] = [
        (
            [3, 5, 7, 11, 13, 17, 19, 23],
            [101, 103, 107, 109, 113, 127, 40, 137],
            1,
            0x0000_2A01,
        ),
        (
            [9, 4, 6, 8, 10, 12, 14, 16],
            [200, 50, 30, 70, 90, 110, 150, 90],
            2,
            0x0000_4B02,
        ),
        (
            [-3, -5, 2, 100, -100, 64, 55, 55],
            [-11, 22, -33, 44, -55, 66, 88, 88],
            0,
            0x0000_5C00,
        ),
        (
            [15, 33, 51, 69, 87, 21, 43, 65],
            [12, 34, 56, 78, 90, 21, 17, 0],
            3,
            0x0000_7D03,
        ),
        (
            [128, 256, 64, 32, 96, 5, 6, 7],
            [7, 7, 7, 7, 7, 7, 9, 0],
            4,
            0x0001_0004,
        ),
        (
            [1_000_000, -2_000_000, 3, 7, 9, 11, 13, 15],
            [5, 9, 13, 17, 21, 25, 70, 24],
            6,
            0x0002_0306,
        ),
        (
            [2, 4, 8, 16, 32, 64, 128, 5],
            [3, 6, 9, 12, 15, 18, 12, 33],
            5,
            0x0003_0405,
        ),
        (
            [-1, -2, -4, -8, 17, 19, 23, 29],
            [-2, -4, -6, -8, -10, -12, 0, 50],
            7,
            0x0004_0507,
        ),
        (
            [-7, 21, -35, 49, -63, 77, -91, 105],
            [-9, 18, -27, 36, -45, 54, -100, 3],
            2,
            0x0005_0602,
        ),
    ];
    bases
        .into_iter()
        .map(
            |(regs, stack, reg_index, branch_target): (
                [i64; NUM_PROBE_REGS],
                [i64; STACK_INIT_DEPTH],
                u8,
                u32,
            )| ProbeVector {
                regs,
                stack,
                reg_index,
                operand_imm: i64::from(branch_target as i32),
                branch_target,
            },
        )
        .collect()
}

struct HaltHost;

impl HostCall for HaltHost {
    fn dispatch(
        &mut self,
        _target: u64,
        regs: &mut Regs,
        _mem: &mut Memory,
    ) -> crate::Result<bool> {
        regs.set(Reg::Rax, HOST_RETURN_SENTINEL);
        Ok(false)
    }
}

fn run_probe(
    mode: CpuMode,
    bitness: Bitness,
    structure: &VmStructure,
    handler: &HandlerEntry,
    v: &ProbeVector,
) -> Option<ProbeOutcome> {
    let mut cpu: Cpu = Cpu::new(mode);
    cpu.mem.map(CTX_BASE & !0xFFF, 0x1000, Perm::RW).ok()?;
    cpu.mem.map(REGS_BASE & !0xFFF, 0x1000, Perm::RW).ok()?;
    cpu.mem.map(STACK_BASE & !0xFFF, 0x2000, Perm::RW).ok()?;
    cpu.mem.map(PC_CELL & !0xFFF, 0x2000, Perm::RW).ok()?;
    cpu.mem.map(SP_CELL & !0xFFF, 0x1000, Perm::RW).ok()?;
    cpu.mem.map(SCRATCH_BASE & !0xFFF, 0x1000, Perm::RW).ok()?;
    cpu.mem.map(STACK_TOP - 0x4000, 0x8000, Perm::RW).ok()?;

    for (i, value) in v.regs.iter().enumerate() {
        cpu.mem
            .write_u64(REGS_BASE + i as u64 * SLOT, *value as u64)
            .ok()?;
    }
    for (i, value) in v.stack.iter().enumerate() {
        cpu.mem
            .write_u64(STACK_BASE + i as u64 * SLOT, *value as u64)
            .ok()?;
    }
    let initial_sp: i64 = STACK_INIT_DEPTH as i64;
    cpu.mem.write_u32(SP_CELL, initial_sp as u32).ok()?;
    cpu.mem.write_u32(PC_CELL, 0).ok()?;

    let target_le: [u8; 4] = v.branch_target.to_le_bytes();
    let imm_le: [u8; 8] = v.operand_imm.to_le_bytes();
    let prog_stream: [u8; 16] = [
        target_le[0],
        target_le[1],
        target_le[2],
        target_le[3],
        imm_le[4],
        imm_le[5],
        imm_le[6],
        imm_le[7],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    debug_assert_eq!(target_le[0], v.reg_index);
    cpu.mem.write(PROG_BASE, &prog_stream).ok()?;

    let ptr: u64 = bitness.ptr_size();
    write_ptr(&mut cpu, bitness, CTX_BASE, REGS_BASE)?;
    write_ptr(&mut cpu, bitness, CTX_BASE + ptr, STACK_BASE)?;
    write_ptr(&mut cpu, bitness, CTX_BASE + ptr * 2, SP_CELL)?;
    write_ptr(&mut cpu, bitness, CTX_BASE + ptr * 3, PC_CELL)?;
    write_ptr(&mut cpu, bitness, CTX_BASE + ptr * 4, SCRATCH_BASE)?;
    write_ptr(&mut cpu, bitness, CTX_BASE + ptr * 5, PROG_BASE)?;

    map_image_segments(&mut cpu, structure).ok()?;
    let _ = CODE_SCRATCH;

    let ret_marker: u64 = 0xDEAD_0000_0000_BEEF;
    let stack_ptr: u64 = STACK_TOP - 0x200;
    cpu.regs.set(Reg::Rsp, stack_ptr);
    match bitness {
        Bitness::Bits64 => {
            cpu.mem.write_u64(stack_ptr, ret_marker).ok()?;
        }
        Bitness::Bits32 => {
            cpu.mem.write_u32(stack_ptr, ret_marker as u32).ok()?;
        }
    }

    set_arg0(&mut cpu, bitness, CTX_BASE, stack_ptr);

    cpu.regs.rip = handler.va;

    let mut host: HaltHost = HaltHost;
    let _ = run_until_return(&mut cpu, &mut host);

    let mut regs_after: Vec<i64> = Vec::with_capacity(NUM_PROBE_REGS);
    for i in 0..NUM_PROBE_REGS {
        regs_after.push(cpu.mem.read_u64(REGS_BASE + i as u64 * SLOT).ok()? as i64);
    }
    let mut stack_after: Vec<i64> = Vec::with_capacity(STACK_INIT_DEPTH + 4);
    for i in 0..(STACK_INIT_DEPTH + 4) {
        stack_after.push(cpu.mem.read_u64(STACK_BASE + i as u64 * SLOT).ok()? as i64);
    }
    let sp_after: i64 = i64::from(cpu.mem.read_u32(SP_CELL).ok()? as i32);
    let pc_after: u64 = u64::from(cpu.mem.read_u32(PC_CELL).ok()?);

    Some(ProbeOutcome {
        regs_after,
        stack_after,
        sp_after,
        pc_after,
        halted: true,
    })
}

fn write_ptr(cpu: &mut Cpu, bitness: Bitness, at: u64, value: u64) -> Option<()> {
    match bitness {
        Bitness::Bits64 => cpu.mem.write_u64(at, value).ok(),
        Bitness::Bits32 => cpu.mem.write_u32(at, value as u32).ok(),
    }
}

fn map_image_segments(cpu: &mut Cpu, structure: &VmStructure) -> crate::error::Result<()> {
    for seg in &structure.loaded {
        if seg.bytes.is_empty() {
            continue;
        }
        let perm: Perm = if seg.executable { Perm::RWX } else { Perm::RW };
        cpu.mem
            .map(seg.va & !0xFFF, seg.bytes.len() as u64 + 0x1000, perm)?;
        cpu.mem.write_unchecked(seg.va, &seg.bytes);
    }
    Ok(())
}

fn set_arg0(cpu: &mut Cpu, bitness: Bitness, value: u64, stack_ptr: u64) {
    match bitness {
        Bitness::Bits64 => {
            cpu.regs.set(Reg::Rcx, value);
            cpu.regs.set(Reg::Rdi, value);
        }
        Bitness::Bits32 => {
            let _ = cpu.mem.write_u32(stack_ptr.wrapping_add(4), value as u32);
        }
    }
}

fn run_until_return(cpu: &mut Cpu, host: &mut HaltHost) -> bool {
    const STEP_CAP: u64 = 200_000;
    matches!(
        cpu.run(host, STEP_CAP),
        Ok(crate::stub_emu::ExitReason::JumpedOutOfRange { .. })
            | Ok(crate::stub_emu::ExitReason::StepCap(_))
            | Ok(crate::stub_emu::ExitReason::HostHalt(_))
            | Ok(crate::stub_emu::ExitReason::GuestFault(_))
    )
}

fn classify(index: usize, vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> HandlerSemantics {
    let unknown: HandlerSemantics = HandlerSemantics {
        index,
        micro_op: MicroOp::Unknown,
        operand: VmOperand::None,
        operand_width: 0,
        pc_advance: 0,
        sp_delta: 0,
    };
    if outcomes.iter().any(|o: &ProbeOutcome| !o.halted) {
        return unknown;
    }

    let sp_delta: i8 = consistent_sp_delta(outcomes);

    if let Some(op) = detect_branch(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: op,
            operand: VmOperand::BranchTarget,
            operand_width: 4,
            pc_advance: 0,
            sp_delta,
        };
    }
    if detect_jump(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::Jump,
            operand: VmOperand::BranchTarget,
            operand_width: 4,
            pc_advance: 0,
            sp_delta,
        };
    }
    if detect_return(outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::Return,
            operand: VmOperand::None,
            operand_width: 0,
            pc_advance: 0,
            sp_delta,
        };
    }

    let Some(pc_advance): Option<u8> = consistent_pc_advance(outcomes) else {
        return unknown;
    };

    if let Some(op) = detect_binary(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::Binary { op },
            operand: VmOperand::None,
            operand_width: 0,
            pc_advance,
            sp_delta,
        };
    }
    if let Some(op) = detect_compare(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::Compare { op },
            operand: VmOperand::None,
            operand_width: 0,
            pc_advance,
            sp_delta,
        };
    }
    if let Some(op) = detect_unary(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::Unary { op },
            operand: VmOperand::None,
            operand_width: 0,
            pc_advance,
            sp_delta,
        };
    }
    if let Some((operand, width)) = detect_push_imm(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::PushImm,
            operand,
            operand_width: width,
            pc_advance,
            sp_delta,
        };
    }
    if let Some(width) = detect_push_reg(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::PushReg,
            operand: VmOperand::RegIndex,
            operand_width: width,
            pc_advance,
            sp_delta,
        };
    }
    if let Some(width) = detect_pop_reg(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::PopReg,
            operand: VmOperand::RegIndex,
            operand_width: width,
            pc_advance,
            sp_delta,
        };
    }
    if detect_nop(vectors, outcomes) {
        return HandlerSemantics {
            index,
            micro_op: MicroOp::Nop,
            operand: VmOperand::None,
            operand_width: 0,
            pc_advance,
            sp_delta: 0,
        };
    }
    unknown
}

fn consistent_pc_advance(outcomes: &[ProbeOutcome]) -> Option<u8> {
    let first: u64 = outcomes.first()?.pc_after;
    if outcomes.iter().all(|o: &ProbeOutcome| o.pc_after == first) && first <= 16 {
        return Some(first as u8);
    }
    None
}

fn consistent_sp_delta(outcomes: &[ProbeOutcome]) -> i8 {
    let base: i64 = STACK_INIT_DEPTH as i64;
    let first: i64 = match outcomes.first() {
        Some(o) => o.sp_after - base,
        None => return 0,
    };
    if outcomes
        .iter()
        .all(|o: &ProbeOutcome| o.sp_after - base == first)
        && (-8..=8).contains(&first)
    {
        first as i8
    } else {
        0
    }
}

fn top_of_stack(outcome: &ProbeOutcome) -> Option<i64> {
    let sp: i64 = outcome.sp_after;
    if sp <= 0 {
        return None;
    }
    let idx: usize = (sp - 1) as usize;
    outcome.stack_after.get(idx).copied()
}

fn input_top_two(vector: &ProbeVector) -> (i64, i64) {
    let sp: usize = STACK_INIT_DEPTH;
    let b: i64 = vector.stack[sp - 1];
    let a: i64 = vector.stack[sp - 2];
    (a, b)
}

fn detect_binary(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> Option<BinKind> {
    let kinds: [BinKind; 11] = [
        BinKind::Add,
        BinKind::Sub,
        BinKind::Mul,
        BinKind::And,
        BinKind::Or,
        BinKind::Xor,
        BinKind::Shl,
        BinKind::Shr,
        BinKind::Sar,
        BinKind::Div,
        BinKind::Rem,
    ];
    let mut matched: Option<BinKind> = None;
    for kind in kinds {
        let mut all: bool = true;
        for (v, o) in vectors.iter().zip(outcomes.iter()) {
            let (a, b): (i64, i64) = input_top_two(v);
            let want: i64 = kind.apply(a, b);
            let got: Option<i64> = top_of_stack(o);
            let consumed_one: bool = o.sp_after == STACK_INIT_DEPTH as i64 - 1;
            if got != Some(want) || !consumed_one {
                all = false;
                break;
            }
        }
        if all {
            if matched.is_some() {
                return None;
            }
            matched = Some(kind);
        }
    }
    matched
}

fn detect_compare(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> Option<CmpKind> {
    let kinds: [CmpKind; 6] = [
        CmpKind::Eq,
        CmpKind::Ne,
        CmpKind::Lt,
        CmpKind::Le,
        CmpKind::Gt,
        CmpKind::Ge,
    ];
    let mut matched: Option<CmpKind> = None;
    for kind in kinds {
        let mut all: bool = true;
        let mut saw_true: bool = false;
        let mut saw_false: bool = false;
        for (v, o) in vectors.iter().zip(outcomes.iter()) {
            let (a, b): (i64, i64) = input_top_two(v);
            let want: i64 = i64::from(kind.apply(a, b));
            let got: Option<i64> = top_of_stack(o);
            let consumed_one: bool = o.sp_after == STACK_INIT_DEPTH as i64 - 1;
            if got != Some(want) || !consumed_one {
                all = false;
                break;
            }
            if want == 1 {
                saw_true = true;
            } else {
                saw_false = true;
            }
        }
        if all && saw_true && saw_false {
            if matched.is_some() {
                return None;
            }
            matched = Some(kind);
        }
    }
    matched
}

fn detect_unary(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> Option<UnKind> {
    let kinds: [UnKind; 2] = [UnKind::Neg, UnKind::Not];
    let mut matched: Option<UnKind> = None;
    for kind in kinds {
        let mut all: bool = true;
        for (v, o) in vectors.iter().zip(outcomes.iter()) {
            let a: i64 = v.stack[STACK_INIT_DEPTH - 1];
            let want: i64 = kind.apply(a);
            let got: Option<i64> = top_of_stack(o);
            let same_depth: bool = o.sp_after == STACK_INIT_DEPTH as i64;
            if got != Some(want) || !same_depth {
                all = false;
                break;
            }
        }
        if all {
            if matched.is_some() {
                return None;
            }
            matched = Some(kind);
        }
    }
    matched
}

fn detect_push_imm(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> Option<(VmOperand, u8)> {
    let mut all: bool = true;
    for (v, o) in vectors.iter().zip(outcomes.iter()) {
        let grew: bool = o.sp_after == STACK_INIT_DEPTH as i64 + 1;
        let pushed: Option<i64> = top_of_stack(o);
        if !grew || pushed != Some(v.operand_imm) {
            all = false;
            break;
        }
    }
    if all {
        return Some((VmOperand::Imm, 4));
    }
    None
}

fn detect_push_reg(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> Option<u8> {
    let mut all: bool = true;
    for (v, o) in vectors.iter().zip(outcomes.iter()) {
        let grew: bool = o.sp_after == STACK_INIT_DEPTH as i64 + 1;
        let pushed: Option<i64> = top_of_stack(o);
        let idx: usize = v.reg_index as usize;
        let want: Option<i64> = v.regs.get(idx).copied();
        if !grew || want.is_none() || pushed != want {
            all = false;
            break;
        }
    }
    if all { Some(1) } else { None }
}

fn detect_pop_reg(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> Option<u8> {
    let mut all: bool = true;
    for (v, o) in vectors.iter().zip(outcomes.iter()) {
        let shrank: bool = o.sp_after == STACK_INIT_DEPTH as i64 - 1;
        let idx: usize = v.reg_index as usize;
        if idx >= NUM_PROBE_REGS {
            all = false;
            break;
        }
        let want: i64 = v.stack[STACK_INIT_DEPTH - 1];
        let got: Option<i64> = o.regs_after.get(idx).copied();
        if !shrank || got != Some(want) {
            all = false;
            break;
        }
    }
    if all { Some(1) } else { None }
}

fn detect_branch(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> Option<MicroOp> {
    let candidates: [(MicroOp, bool); 2] =
        [(MicroOp::BranchTrue, true), (MicroOp::BranchFalse, false)];
    for (op, jump_when_nonzero) in candidates {
        let mut all: bool = true;
        let mut saw_taken: bool = false;
        let mut saw_nottaken: bool = false;
        for (v, o) in vectors.iter().zip(outcomes.iter()) {
            let cond: i64 = v.stack[STACK_INIT_DEPTH - 1];
            let consumed: bool = o.sp_after == STACK_INIT_DEPTH as i64 - 1;
            if !consumed {
                all = false;
                break;
            }
            let take: bool = if jump_when_nonzero {
                cond != 0
            } else {
                cond == 0
            };
            let pc_rel: u64 = o.pc_after;
            if take {
                if o.pc_after != u64::from(v.branch_target) {
                    all = false;
                    break;
                }
                saw_taken = true;
            } else {
                if pc_rel == 0 || pc_rel > 16 {
                    all = false;
                    break;
                }
                saw_nottaken = true;
            }
        }
        if all && saw_taken && saw_nottaken {
            return Some(op);
        }
    }
    None
}

fn detect_jump(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> bool {
    let mut all: bool = true;
    for (v, o) in vectors.iter().zip(outcomes.iter()) {
        let same_depth: bool = o.sp_after == STACK_INIT_DEPTH as i64;
        if !same_depth || o.pc_after != u64::from(v.branch_target) {
            all = false;
            break;
        }
    }
    all
}

fn detect_return(outcomes: &[ProbeOutcome]) -> bool {
    outcomes
        .iter()
        .all(|o: &ProbeOutcome| o.pc_after == VM_HALT_PC)
}

fn detect_nop(vectors: &[ProbeVector], outcomes: &[ProbeOutcome]) -> bool {
    for (v, o) in vectors.iter().zip(outcomes.iter()) {
        if o.sp_after != STACK_INIT_DEPTH as i64 {
            return false;
        }
        for (i, value) in v.stack.iter().enumerate() {
            if o.stack_after.get(i) != Some(value) {
                return false;
            }
        }
        for (i, value) in v.regs.iter().enumerate() {
            if o.regs_after.get(i) != Some(value) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn binkind_apply_matches_semantics() {
        assert_eq!(BinKind::Add.apply(3, 4), 7);
        assert_eq!(BinKind::Sub.apply(10, 3), 7);
        assert_eq!(BinKind::Xor.apply(0b1010, 0b0110), 0b1100);
    }

    const BIN_KINDS: [BinKind; 11] = [
        BinKind::Add,
        BinKind::Sub,
        BinKind::Mul,
        BinKind::And,
        BinKind::Or,
        BinKind::Xor,
        BinKind::Shl,
        BinKind::Shr,
        BinKind::Sar,
        BinKind::Div,
        BinKind::Rem,
    ];

    const CMP_KINDS: [CmpKind; 6] = [
        CmpKind::Eq,
        CmpKind::Ne,
        CmpKind::Lt,
        CmpKind::Le,
        CmpKind::Gt,
        CmpKind::Ge,
    ];

    const UN_KINDS: [UnKind; 2] = [UnKind::Neg, UnKind::Not];

    #[test]
    fn every_pair_of_binary_kinds_disagrees_on_some_probe() {
        let vectors: Vec<ProbeVector> = probe_vectors();
        let mut collisions: Vec<String> = Vec::new();
        for (left_index, left) in BIN_KINDS.iter().enumerate() {
            for right in BIN_KINDS.iter().skip(left_index + 1) {
                let separated: bool = vectors.iter().any(|v: &ProbeVector| {
                    let (a, b): (i64, i64) = input_top_two(v);
                    left.apply(a, b) != right.apply(a, b)
                });
                if !separated {
                    collisions.push(format!("{left:?} and {right:?}"));
                }
            }
        }
        assert!(
            collisions.is_empty(),
            "these binary kinds agree on every probe, so the first one listed in detect_binary \
             would be reported for a handler that is really the other: {collisions:?}"
        );
    }

    #[test]
    fn every_pair_of_compare_kinds_disagrees_on_some_probe() {
        let vectors: Vec<ProbeVector> = probe_vectors();
        let mut collisions: Vec<String> = Vec::new();
        for (left_index, left) in CMP_KINDS.iter().enumerate() {
            for right in CMP_KINDS.iter().skip(left_index + 1) {
                let separated: bool = vectors.iter().any(|v: &ProbeVector| {
                    let (a, b): (i64, i64) = input_top_two(v);
                    left.apply(a, b) != right.apply(a, b)
                });
                if !separated {
                    collisions.push(format!("{left:?} and {right:?}"));
                }
            }
        }
        assert!(collisions.is_empty(), "{collisions:?}");
    }

    #[test]
    fn every_pair_of_unary_kinds_disagrees_on_some_probe() {
        let vectors: Vec<ProbeVector> = probe_vectors();
        let mut collisions: Vec<String> = Vec::new();
        for (left_index, left) in UN_KINDS.iter().enumerate() {
            for right in UN_KINDS.iter().skip(left_index + 1) {
                let separated: bool = vectors.iter().any(|v: &ProbeVector| {
                    let operand: i64 = v.stack[STACK_INIT_DEPTH - 1];
                    left.apply(operand) != right.apply(operand)
                });
                if !separated {
                    collisions.push(format!("{left:?} and {right:?}"));
                }
            }
        }
        assert!(collisions.is_empty(), "{collisions:?}");
    }

    fn probe_with_top_two(a: i64, b: i64) -> ProbeVector {
        let mut stack: [i64; STACK_INIT_DEPTH] = [0; STACK_INIT_DEPTH];
        stack[STACK_INIT_DEPTH - 2] = a;
        stack[STACK_INIT_DEPTH - 1] = b;
        ProbeVector {
            regs: [0; NUM_PROBE_REGS],
            stack,
            reg_index: 0,
            operand_imm: 0,
            branch_target: 0,
        }
    }

    fn outcome_consuming_one(result: i64) -> ProbeOutcome {
        let depth: usize = STACK_INIT_DEPTH - 1;
        let mut stack_after: Vec<i64> = vec![0; depth];
        stack_after[depth - 1] = result;
        ProbeOutcome {
            regs_after: vec![0; NUM_PROBE_REGS],
            stack_after,
            sp_after: depth as i64,
            pc_after: 0,
            halted: true,
        }
    }

    #[test]
    fn two_binary_kinds_that_both_match_abstain_instead_of_taking_the_first() {
        let vectors: Vec<ProbeVector> = vec![probe_with_top_two(40, 3), probe_with_top_two(88, 1)];
        let outcomes: Vec<ProbeOutcome> = vectors
            .iter()
            .map(|v: &ProbeVector| {
                let (a, b): (i64, i64) = input_top_two(v);
                outcome_consuming_one(BinKind::Sar.apply(a, b))
            })
            .collect();
        assert_eq!(
            BinKind::Shr.apply(40, 3),
            BinKind::Sar.apply(40, 3),
            "this case only tests ambiguity if the two kinds really do agree here"
        );
        assert_eq!(
            detect_binary(&vectors, &outcomes),
            None,
            "a logical and an arithmetic right shift both explain these probes, so the handler \
             must stay unclassified rather than be reported as whichever kind is listed first"
        );
    }

    #[test]
    fn a_probe_drives_an_arithmetic_right_shift_of_a_negative_value() {
        let vectors: Vec<ProbeVector> = probe_vectors();
        assert!(
            vectors.iter().any(|v: &ProbeVector| {
                let (a, b): (i64, i64) = input_top_two(v);
                a < 0 && b & 0x3F != 0
            }),
            "without a negative left operand shifted by a nonzero amount, a logical and an \
             arithmetic right shift produce the same value on every probe"
        );
    }

    #[test]
    fn probe_vectors_exercise_both_compare_outcomes() {
        let v: Vec<ProbeVector> = probe_vectors();
        assert!(v.len() >= 6);
        let tops: Vec<i64> = v
            .iter()
            .map(|p: &ProbeVector| p.stack[STACK_INIT_DEPTH - 1])
            .collect();
        assert!(
            tops.contains(&0),
            "a probe must drive a zero condition for branch detection"
        );
        assert!(
            tops.iter().any(|t: &i64| *t != 0),
            "a probe must drive a nonzero condition"
        );
        for p in &v {
            assert_eq!(
                p.reg_index,
                (p.branch_target & 0xFF) as u8,
                "reg index byte must equal the low operand byte so all handler readers agree"
            );
        }
    }

    #[test]
    fn inconsistent_pc_advance_keeps_data_op_unknown() {
        let vectors: Vec<ProbeVector> = probe_vectors();
        let outcomes: Vec<ProbeOutcome> = vectors
            .iter()
            .enumerate()
            .map(|(index, vector): (usize, &ProbeVector)| {
                let (a, b): (i64, i64) = input_top_two(vector);
                let mut stack_after: Vec<i64> = vector.stack.to_vec();
                stack_after[STACK_INIT_DEPTH - 2] = a.wrapping_add(b);
                ProbeOutcome {
                    regs_after: vector.regs.to_vec(),
                    stack_after,
                    sp_after: STACK_INIT_DEPTH as i64 - 1,
                    pc_after: if index % 2 == 0 { 1 } else { 2 },
                    halted: true,
                }
            })
            .collect();
        let sem: HandlerSemantics = classify(7, &vectors, &outcomes);
        assert_eq!(sem.micro_op, MicroOp::Unknown);
        assert_eq!(sem.pc_advance, 0);
    }
}
