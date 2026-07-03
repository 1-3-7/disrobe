use std::collections::BTreeSet;

use crate::packers::{PeImage, PeSection, parse_pe_image};

use super::cfg::{VmCfg, build_cfg};
use super::detect::{Bitness, DispatchKind, VmDetection};
use super::emit::{emit_pseudocode, emit_recovered_listing};
use super::fingerprint::HandlerSemantics;
use super::lift::{LiftedProgram, VmInsn};
use super::microop::{BinKind, MicroOp, VmOperand};
use super::structure::{StructuredNode, structure_program};
use super::{DevirtReport, MAX_BYTECODE_INSNS};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MAX_GUARDIAN_BYTECODE_BYTES: usize = 1 << 20;
const MACHINE_REGS_OFFSET: u64 = 16;
const MACHINE_REG_STRIDE: u64 = 8;
const X86_REG_COUNT: u8 = 16;
const X86_RAX: u8 = 0;
const X86_RCX: u8 = 1;
const X86_RDX: u8 = 2;
const X86_RBX: u8 = 3;
const X86_R8: u8 = 8;
const X86_R9: u8 = 9;
const LIFT_RAX: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum GuardianOpcode {
    Const,
    Load,
    LoadXmm,
    Store,
    StoreXmm,
    StoreReg,
    StoreRegZx,
    Add,
    Sub,
    Div,
    IDiv,
    Shr,
    Mul,
    IMul,
    And,
    Or,
    Xor,
    Not,
    Cmp,
    RotR,
    RotL,
    Jmp,
    Vmctx,
    VmAdd,
    VmMul,
    VmSub,
    VmReloc,
    VmExec,
    VmExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardianSize {
    Byte,
    Word,
    Dword,
    Qword,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuardianInsn {
    offset: usize,
    end: usize,
    opcode: GuardianOpcode,
    size: GuardianSize,
    value: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuardianEntry {
    entry_offset: usize,
    dispatcher_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackValue {
    Ctx,
    RegAddr(u8),
    Reg(u8),
    Imm { value: u64, size: GuardianSize },
    Ready,
}

pub(super) fn devirtualize_guardian_rs(
    bytes: &[u8],
    bitness: Bitness,
) -> Option<(DevirtReport, LiftedProgram, VmCfg, Vec<HandlerSemantics>)> {
    if bitness != Bitness::Bits64 {
        return None;
    }
    let image: PeImage = parse_pe_image(bytes).ok()?;
    if !image.is_pe32_plus {
        return None;
    }
    let vm_section: &PeSection = image.section_by_name(b".vm")?;
    let byte_section: &PeSection = image.section_by_name(b".byte")?;
    let entry: GuardianEntry = find_entry_stub(bytes, &image, vm_section, byte_section)?;
    let byte_section_bytes: &[u8] = section_bytes(bytes, byte_section)?;
    let bounded_len: usize = byte_section_bytes.len().min(MAX_GUARDIAN_BYTECODE_BYTES);
    if entry.entry_offset >= bounded_len {
        return None;
    }
    let program: &[u8] = &byte_section_bytes[..bounded_len];
    let decoded: Vec<GuardianInsn> = decode_guardian_program(program, entry.entry_offset)?;
    let (lifted, semantics): (LiftedProgram, Vec<HandlerSemantics>) = lower_guardian(&decoded)?;
    let cfg: VmCfg = build_cfg(&lifted);
    let structured: Vec<StructuredNode> = structure_program(&cfg);
    let pseudocode: String = emit_pseudocode(&lifted, &structured);
    let recovered_listing: String = emit_recovered_listing(&lifted);
    let fingerprinted_count: usize = semantics
        .iter()
        .filter(|s: &&HandlerSemantics| !matches!(s.micro_op, MicroOp::Unknown))
        .count();
    let bytecode_va: u64 = image.image_base + u64::from(byte_section.virtual_address);
    let bytecode_len: usize = decoded.last().map_or(0, |insn: &GuardianInsn| {
        insn.end.saturating_sub(entry.entry_offset)
    });
    let detection: VmDetection = VmDetection {
        dispatch_kind: DispatchKind::SwitchJumpTable,
        dispatcher_va: image.image_base + u64::from(entry.dispatcher_rva),
        handler_table_va: 0,
        handler_count: semantics.len(),
        bytecode_va,
        bytecode_len,
        entry_vip: entry.entry_offset as u64,
    };
    let report: DevirtReport = DevirtReport {
        detection,
        handler_count: semantics.len(),
        fingerprinted_count,
        bytecode_insn_count: lifted.insns.len(),
        block_count: cfg.blocks.len(),
        pseudocode,
        recovered_listing,
        residual: format!(
            "guardian-rs static lifter: decoded {} VM instruction(s) from .byte and folded VM-context register traffic into {} re-executable micro-op(s).",
            decoded.len(),
            lifted.insns.len()
        ),
    };
    Some((report, lifted, cfg, semantics))
}

fn find_entry_stub(
    bytes: &[u8],
    image: &PeImage,
    vm_section: &PeSection,
    byte_section: &PeSection,
) -> Option<GuardianEntry> {
    let byte_start: u32 = byte_section.virtual_address;
    let byte_end: u32 =
        byte_start.checked_add(byte_section.virtual_size.max(byte_section.raw_size))?;
    for section in image
        .sections
        .iter()
        .filter(|section: &&PeSection| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
    {
        let section_data: &[u8] = section_bytes(bytes, section)?;
        if section_data.len() < 10 {
            continue;
        }
        for offset in 0..=section_data.len() - 10 {
            if section_data[offset] != 0x68 || section_data[offset + 5] != 0xE9 {
                continue;
            }
            let bytecode_rva: u32 = read_u32_le(section_data, offset + 1)?;
            if bytecode_rva < byte_start || bytecode_rva >= byte_end {
                continue;
            }
            let rel: i32 = read_i32_le(section_data, offset + 6)?;
            let stub_next_rva: i128 =
                i128::from(section.virtual_address) + i128::try_from(offset).ok()? + 10;
            let dispatcher_rva_i128: i128 = stub_next_rva + i128::from(rel);
            if dispatcher_rva_i128 < 0 || dispatcher_rva_i128 > i128::from(u32::MAX) {
                continue;
            }
            let dispatcher_rva: u32 = dispatcher_rva_i128 as u32;
            if !rva_in_section(vm_section, dispatcher_rva) {
                continue;
            }
            return Some(GuardianEntry {
                entry_offset: bytecode_rva.checked_sub(byte_start)? as usize,
                dispatcher_rva,
            });
        }
    }
    None
}

fn decode_guardian_program(program: &[u8], entry_offset: usize) -> Option<Vec<GuardianInsn>> {
    let mut pc: usize = entry_offset;
    let mut out: Vec<GuardianInsn> = Vec::new();
    while pc < program.len() {
        if out.len() >= MAX_BYTECODE_INSNS {
            return None;
        }
        let start: usize = pc;
        let opcode: GuardianOpcode = GuardianOpcode::from_u8(*program.get(pc)?)?;
        let size: GuardianSize = GuardianSize::from_u8(*program.get(pc + 1)?)?;
        pc = pc.checked_add(2)?;
        let mut value: Option<u64> = None;
        match opcode {
            GuardianOpcode::Const | GuardianOpcode::VmReloc => {
                value = Some(read_sized_u64(program, pc, size.width())?);
                pc = pc.checked_add(size.width())?;
            }
            GuardianOpcode::Jmp => {
                pc = pc.checked_add(1)?;
                value = Some(read_sized_u64(program, pc, size.width())?);
                pc = pc.checked_add(size.width())?;
            }
            GuardianOpcode::VmExec => {
                let payload_len: usize = usize::from(*program.get(pc)?);
                pc = pc.checked_add(1)?.checked_add(payload_len)?;
                if pc > program.len() {
                    return None;
                }
            }
            _ => {}
        }
        out.push(GuardianInsn {
            offset: start,
            end: pc,
            opcode,
            size,
            value,
        });
        if opcode == GuardianOpcode::VmExit {
            return Some(out);
        }
    }
    None
}

fn lower_guardian(decoded: &[GuardianInsn]) -> Option<(LiftedProgram, Vec<HandlerSemantics>)> {
    let mut code: Vec<VmInsn> = Vec::new();
    let mut stack: Vec<StackValue> = Vec::new();
    let mut seen: BTreeSet<GuardianOpcode> = BTreeSet::new();
    let mut max_reg: u8 = 0;
    for insn in decoded {
        seen.insert(insn.opcode);
        match insn.opcode {
            GuardianOpcode::Vmctx => stack.push(StackValue::Ctx),
            GuardianOpcode::Const => stack.push(StackValue::Imm {
                value: insn.value?,
                size: insn.size,
            }),
            GuardianOpcode::Load => {
                let addr: StackValue = stack.pop()?;
                let StackValue::RegAddr(reg) = addr else {
                    return None;
                };
                stack.push(StackValue::Reg(reg));
            }
            GuardianOpcode::StoreReg | GuardianOpcode::StoreRegZx => {
                let addr: StackValue = stack.pop()?;
                let value: StackValue = stack.pop()?;
                let StackValue::RegAddr(reg) = addr else {
                    return None;
                };
                materialize(value, &mut code, &mut max_reg)?;
                let out_reg: u8 = map_x86_reg(reg)?;
                push_vm_insn(
                    &mut code,
                    GuardianOpcode::StoreReg,
                    MicroOp::PopReg,
                    None,
                    Some(out_reg),
                    None,
                )?;
                max_reg = max_reg.max(out_reg);
            }
            GuardianOpcode::Add | GuardianOpcode::VmAdd => {
                apply_binary(
                    insn.opcode,
                    BinKind::Add,
                    &mut stack,
                    &mut code,
                    &mut max_reg,
                )?;
            }
            GuardianOpcode::Sub | GuardianOpcode::VmSub => {
                apply_binary(
                    insn.opcode,
                    BinKind::Sub,
                    &mut stack,
                    &mut code,
                    &mut max_reg,
                )?;
            }
            GuardianOpcode::Mul | GuardianOpcode::IMul | GuardianOpcode::VmMul => {
                apply_binary(
                    insn.opcode,
                    BinKind::Mul,
                    &mut stack,
                    &mut code,
                    &mut max_reg,
                )?;
            }
            GuardianOpcode::Xor => {
                apply_binary(
                    insn.opcode,
                    BinKind::Xor,
                    &mut stack,
                    &mut code,
                    &mut max_reg,
                )?;
            }
            GuardianOpcode::VmExit => {
                materialize(StackValue::Reg(X86_RAX), &mut code, &mut max_reg)?;
                push_vm_insn(
                    &mut code,
                    GuardianOpcode::VmExit,
                    MicroOp::Return,
                    None,
                    None,
                    None,
                )?;
                break;
            }
            _ => return None,
        }
    }
    if code.len() < 4 {
        return None;
    }
    let semantics: Vec<HandlerSemantics> = guardian_semantics(&seen);
    if semantics.len() < 4 {
        return None;
    }
    Some((
        LiftedProgram {
            insns: code,
            entry_offset: 0,
            max_reg,
            unresolved_opcodes: Vec::new(),
        },
        semantics,
    ))
}

fn apply_binary(
    opcode: GuardianOpcode,
    op: BinKind,
    stack: &mut Vec<StackValue>,
    code: &mut Vec<VmInsn>,
    max_reg: &mut u8,
) -> Option<()> {
    let right: StackValue = stack.pop()?;
    let left: StackValue = stack.pop()?;
    if opcode == GuardianOpcode::VmAdd
        && let Some(reg) = context_register_address(left, right)
    {
        stack.push(StackValue::RegAddr(reg));
        return Some(());
    }
    materialize(left, code, max_reg)?;
    materialize(right, code, max_reg)?;
    push_vm_insn(code, opcode, MicroOp::Binary { op }, None, None, None)?;
    stack.push(StackValue::Ready);
    Some(())
}

fn context_register_address(left: StackValue, right: StackValue) -> Option<u8> {
    match (left, right) {
        (StackValue::Ctx, StackValue::Imm { value, .. })
        | (StackValue::Imm { value, .. }, StackValue::Ctx) => reg_from_ctx_offset(value),
        _ => None,
    }
}

fn materialize(value: StackValue, code: &mut Vec<VmInsn>, max_reg: &mut u8) -> Option<()> {
    match value {
        StackValue::Imm { value, size } => push_vm_insn(
            code,
            GuardianOpcode::Const,
            MicroOp::PushImm,
            Some(imm_to_i64(value, size)),
            None,
            None,
        ),
        StackValue::Reg(reg) => {
            let out_reg: u8 = map_x86_reg(reg)?;
            push_vm_insn(
                code,
                GuardianOpcode::Load,
                MicroOp::PushReg,
                None,
                Some(out_reg),
                None,
            )?;
            *max_reg = (*max_reg).max(out_reg);
            Some(())
        }
        StackValue::Ready => Some(()),
        StackValue::Ctx | StackValue::RegAddr(_) => None,
    }
}

fn push_vm_insn(
    code: &mut Vec<VmInsn>,
    opcode: GuardianOpcode,
    micro_op: MicroOp,
    imm: Option<i64>,
    reg: Option<u8>,
    branch_target: Option<u32>,
) -> Option<()> {
    let offset: u32 = u32::try_from(code.len()).ok()?;
    code.push(VmInsn {
        offset,
        opcode: opcode as u8,
        micro_op,
        imm,
        reg,
        branch_target,
    });
    Some(())
}

fn guardian_semantics(seen: &BTreeSet<GuardianOpcode>) -> Vec<HandlerSemantics> {
    let mut out: Vec<HandlerSemantics> = Vec::with_capacity(seen.len());
    for opcode in seen {
        let (micro_op, operand, sp_delta): (MicroOp, VmOperand, i8) = match opcode {
            GuardianOpcode::Const => (MicroOp::PushImm, VmOperand::Imm, 1),
            GuardianOpcode::Load => (MicroOp::PushReg, VmOperand::RegIndex, 1),
            GuardianOpcode::StoreReg | GuardianOpcode::StoreRegZx => {
                (MicroOp::PopReg, VmOperand::RegIndex, -1)
            }
            GuardianOpcode::Add | GuardianOpcode::VmAdd => {
                (MicroOp::Binary { op: BinKind::Add }, VmOperand::None, -1)
            }
            GuardianOpcode::Sub | GuardianOpcode::VmSub => {
                (MicroOp::Binary { op: BinKind::Sub }, VmOperand::None, -1)
            }
            GuardianOpcode::Mul | GuardianOpcode::IMul | GuardianOpcode::VmMul => {
                (MicroOp::Binary { op: BinKind::Mul }, VmOperand::None, -1)
            }
            GuardianOpcode::Xor => (MicroOp::Binary { op: BinKind::Xor }, VmOperand::None, -1),
            GuardianOpcode::Vmctx => (MicroOp::Nop, VmOperand::None, 1),
            GuardianOpcode::VmExit => (MicroOp::Return, VmOperand::None, 0),
            _ => (MicroOp::Unknown, VmOperand::None, 0),
        };
        out.push(HandlerSemantics {
            index: *opcode as usize,
            micro_op,
            operand,
            operand_width: 8,
            pc_advance: 0,
            sp_delta,
        });
    }
    out
}

fn map_x86_reg(reg: u8) -> Option<u8> {
    match reg {
        X86_RCX => Some(0),
        X86_RDX => Some(1),
        X86_R8 => Some(2),
        X86_R9 => Some(3),
        X86_RAX => Some(LIFT_RAX),
        X86_RBX => Some(9),
        4 => Some(10),
        5 => Some(11),
        6 => Some(12),
        7 => Some(13),
        10 => Some(4),
        11 => Some(5),
        12 => Some(6),
        13 => Some(7),
        14 => Some(14),
        15 => Some(15),
        _ => None,
    }
}

fn reg_from_ctx_offset(value: u64) -> Option<u8> {
    if value < MACHINE_REGS_OFFSET {
        return None;
    }
    let delta: u64 = value - MACHINE_REGS_OFFSET;
    if delta % MACHINE_REG_STRIDE != 0 {
        return None;
    }
    let reg: u8 = u8::try_from(delta / MACHINE_REG_STRIDE).ok()?;
    if reg < X86_REG_COUNT { Some(reg) } else { None }
}

fn imm_to_i64(value: u64, size: GuardianSize) -> i64 {
    match size {
        GuardianSize::Byte => i64::from(value as u8 as i8),
        GuardianSize::Word => i64::from(value as u16 as i16),
        GuardianSize::Dword => i64::from(value as u32 as i32),
        GuardianSize::Qword => value as i64,
    }
}

fn section_bytes<'a>(bytes: &'a [u8], section: &PeSection) -> Option<&'a [u8]> {
    let (start, end): (usize, usize) = section.raw_range(bytes.len())?;
    bytes.get(start..end)
}

fn rva_in_section(section: &PeSection, rva: u32) -> bool {
    let span: u32 = section.virtual_size.max(section.raw_size);
    rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span)
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let end: usize = off.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_i32_le(bytes: &[u8], off: usize) -> Option<i32> {
    let end: usize = off.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(off..end)?.try_into().ok()?;
    Some(i32::from_le_bytes(raw))
}

fn read_sized_u64(bytes: &[u8], off: usize, width: usize) -> Option<u64> {
    let end: usize = off.checked_add(width)?;
    let raw: &[u8] = bytes.get(off..end)?;
    let mut value: u64 = 0;
    for (index, byte) in raw.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    Some(value)
}

impl GuardianOpcode {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Const),
            1 => Some(Self::Load),
            2 => Some(Self::LoadXmm),
            3 => Some(Self::Store),
            4 => Some(Self::StoreXmm),
            5 => Some(Self::StoreReg),
            6 => Some(Self::StoreRegZx),
            7 => Some(Self::Add),
            8 => Some(Self::Sub),
            9 => Some(Self::Div),
            10 => Some(Self::IDiv),
            11 => Some(Self::Shr),
            12 => Some(Self::Mul),
            13 => Some(Self::IMul),
            14 => Some(Self::And),
            15 => Some(Self::Or),
            16 => Some(Self::Xor),
            17 => Some(Self::Not),
            18 => Some(Self::Cmp),
            19 => Some(Self::RotR),
            20 => Some(Self::RotL),
            21 => Some(Self::Jmp),
            22 => Some(Self::Vmctx),
            23 => Some(Self::VmAdd),
            24 => Some(Self::VmMul),
            25 => Some(Self::VmSub),
            26 => Some(Self::VmReloc),
            27 => Some(Self::VmExec),
            28 => Some(Self::VmExit),
            _ => None,
        }
    }
}

impl GuardianSize {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Byte),
            2 => Some(Self::Word),
            4 => Some(Self::Dword),
            8 => Some(Self::Qword),
            _ => None,
        }
    }

    const fn width(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
            Self::Qword => 8,
        }
    }
}
