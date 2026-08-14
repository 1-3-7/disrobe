use super::return_channel;
use super::{
    Abi, AggregatePlan, BinOp, Block, CondKind, Error, ExtSource, FP_ARG_ORDER, Flags, FnReturn,
    FnSignature, FpFmaKind, FpMinMaxKind, FpOp, FpOperand, FpRoundKind, FpRoundRange, FpToIntRound,
    FpUnaryOp, FpUnorderedModel, FpWidth, FrameShape, IndexExtend, IndexOperand, Item, ItemKind,
    LeafRecovery, MemRef, Node, RecoveredSignature, ReduceOp, Reg, RegRef, ResolvedCall, Result,
    RoundMode, ScalarType, Source, SretPlan, SretReturn, StackFrameExtent, Stmt, Structured, UnOp,
    VecArrangement, VecBinOp, VecElem, VecStmt, Width, Xmm, annotate_calls_block_with_abi,
    collect_call_targets, condition_is_sound, detect_sret, emit_c, emit_rust, infer_aggregate_plan,
    infer_fp_params, infer_params, plan_frame, stmt_writes_rax_int, structure_items,
};
use crate::arch::{Arch, DisasmInsn, disassemble};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU8;

#[path = "aarch64_cfg.rs"]
mod aarch64_cfg;

#[path = "aarch64_frame.rs"]
mod aarch64_frame;

const MAX_INSTRUCTIONS: usize = 4096;
const ITEM_STRIDE: u64 = 16;
const MAX_FRAME_BYTES: i64 = 1 << 20;
const MAX_SWITCH_CASES: usize = 4096;
const MAX_SWITCH_TABLE_BYTES: usize = MAX_SWITCH_CASES * 8;
const MAX_SWITCH_SLICE_INSTRUCTIONS: usize = 16;

const CALL_ARG_ORDER: [Reg; 16] = [
    Reg::Rax,
    Reg::A64X1,
    Reg::A64X2,
    Reg::A64X3,
    Reg::A64X4,
    Reg::A64X5,
    Reg::A64X6,
    Reg::A64X7,
    Reg::A64Outgoing0,
    Reg::A64Outgoing1,
    Reg::A64Outgoing2,
    Reg::A64Outgoing3,
    Reg::A64Outgoing4,
    Reg::A64Outgoing5,
    Reg::A64Outgoing6,
    Reg::A64Outgoing7,
];

const AARCH64_FP_REGISTERS: [Xmm; 32] = [
    Xmm::Xmm0,
    Xmm::Xmm1,
    Xmm::Xmm2,
    Xmm::Xmm3,
    Xmm::Xmm4,
    Xmm::Xmm5,
    Xmm::Xmm6,
    Xmm::Xmm7,
    Xmm::Xmm8,
    Xmm::Xmm9,
    Xmm::Xmm10,
    Xmm::Xmm11,
    Xmm::Xmm12,
    Xmm::Xmm13,
    Xmm::Xmm14,
    Xmm::Xmm15,
    Xmm::Xmm16,
    Xmm::Xmm17,
    Xmm::Xmm18,
    Xmm::Xmm19,
    Xmm::Xmm20,
    Xmm::Xmm21,
    Xmm::Xmm22,
    Xmm::Xmm23,
    Xmm::Xmm24,
    Xmm::Xmm25,
    Xmm::Xmm26,
    Xmm::Xmm27,
    Xmm::Xmm28,
    Xmm::Xmm29,
    Xmm::Xmm30,
    Xmm::Xmm31,
];

#[derive(Debug, Clone, Copy, Default)]
struct FrameInfo {
    sp_to_entry: i64,
    frame_bytes: i64,
    fp_to_entry: Option<i64>,
    sp_writeback_absorbed: bool,
}

#[derive(Debug, Clone)]
struct FrameAnalysis {
    info: FrameInfo,
    management: BTreeSet<usize>,
    absorbed: BTreeSet<usize>,
}

struct FinishContext<'a> {
    calls: &'a [ResolvedCall],
    vec_abi: &'a VectorAbi,
    frame_info: FrameInfo,
}

impl FrameAnalysis {
    fn info_at(&self, index: usize) -> FrameInfo {
        FrameInfo {
            sp_writeback_absorbed: self.absorbed.contains(&index),
            ..self.info
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct OutgoingSlot {
    memory_index: usize,
    slot: usize,
}

#[derive(Debug, Clone)]
struct TrackedFlags {
    value: Flags,
    nz_only: bool,
    mark: usize,
}

struct ImageContext<'resolver, 'image> {
    image: &'resolver dyn Fn(u64) -> Option<&'image [u8]>,
    relocations: &'resolver dyn Fn(u64) -> Option<u64>,
}

#[derive(Debug, Clone)]
struct SwitchDispatch {
    ignored_instructions: BTreeSet<usize>,
    disc: RegRef,
    cases: Vec<(i64, u64)>,
    default: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PcRelativeAddressFold {
    page_index: usize,
    dest: u8,
    source: u8,
    target: u64,
}

#[derive(Debug, Clone, Copy)]
enum RelativeLoadKind {
    ByteUnsigned,
    ByteSigned,
    HalfwordUnsigned,
    HalfwordSigned,
    WordSigned,
}

#[derive(Debug, Clone, Copy)]
enum SwitchAddExtend {
    ByteUnsigned,
    ByteSigned,
    HalfwordUnsigned,
    HalfwordSigned,
    WordUnsigned,
    WordSigned,
}

#[derive(Debug, Clone, Copy)]
enum SwitchTableEncoding {
    Relative(RelativeLoadKind),
    Absolute64,
}

#[derive(Debug, Clone, Copy)]
enum SwitchTargetMode {
    Relative {
        anchor: u64,
        element_size: usize,
        signed: bool,
        scale: u8,
    },
    Absolute64,
}

#[derive(Debug)]
struct SwitchSetup {
    table_base: u8,
    index: u8,
    load_index: usize,
    table_va: u64,
    target_mode: SwitchTargetMode,
    relative_aliases: Option<(u8, u8)>,
    required_indices: BTreeSet<usize>,
}

#[derive(Debug, Clone, Copy)]
enum SwitchInsn {
    Other,
    Nop,
    CmpImmediate {
        index: u8,
        limit: u16,
    },
    ConditionalBranch {
        condition: u8,
        target: u64,
    },
    DirectBranch {
        target: u64,
    },
    Adrp {
        dest: u8,
        target: u64,
    },
    AddImmediate {
        dest: u8,
        lhs: u8,
        immediate: u16,
    },
    IndexedLoad {
        dest: u8,
        base: u8,
        index: u8,
        encoding: SwitchTableEncoding,
    },
    Adr {
        dest: u8,
        target: u64,
    },
    AddExtended {
        dest: u8,
        anchor: u8,
        offset: u8,
        extension: SwitchAddExtend,
        scale: u8,
    },
    ShiftedAdd {
        dest: u8,
        anchor: u8,
        offset: u8,
        scale: u8,
    },
    IndirectBranch {
        target: u8,
    },
    SelectorAdjustment {
        dest: u8,
        source: u8,
        case_minimum: i64,
    },
    RegisterCopy {
        dest: u8,
        source: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Aarch64DirectTransfer {
    BranchLink { target: u64 },
    UnconditionalBranch { target: u64 },
    ConditionalBranch { condition: u8, target: u64 },
    CompareBranch { target: u64 },
    TestBranch { target: u64 },
}

pub(crate) const AARCH64_INSTRUCTION_BYTES: usize = 4;

pub(crate) fn aarch64_is_indirect_branch(mnemonic: &str) -> bool {
    matches!(mnemonic, "br" | "braa" | "brab" | "braaz" | "brabz")
}

pub(crate) fn aarch64_is_indirect_call(mnemonic: &str) -> bool {
    matches!(mnemonic, "blr" | "blraa" | "blrab" | "blraaz" | "blrabz")
}

pub(crate) fn aarch64_is_return(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "drps" | "eret" | "eretaa" | "eretab" | "ret" | "retaa" | "retab"
    )
}

pub(crate) fn aarch64_is_trap(mnemonic: &str) -> bool {
    matches!(mnemonic, "brk" | "hlt" | "udf")
}

pub(crate) fn aarch64_is_exception_entry(mnemonic: &str) -> bool {
    matches!(mnemonic, "svc" | "hvc" | "smc")
}

pub(crate) fn aarch64_stops_traversal(mnemonic: &str) -> bool {
    aarch64_is_indirect_branch(mnemonic) || aarch64_is_return(mnemonic) || aarch64_is_trap(mnemonic)
}

pub(crate) fn aarch64_word(bytes: &[u8]) -> Option<u32> {
    <[u8; AARCH64_INSTRUCTION_BYTES]>::try_from(bytes)
        .ok()
        .map(u32::from_le_bytes)
}

impl RelativeLoadKind {
    fn natural(self) -> Option<(usize, bool)> {
        match self {
            Self::ByteUnsigned => Some((1, false)),
            Self::HalfwordUnsigned => Some((2, false)),
            Self::WordSigned => Some((4, true)),
            Self::ByteSigned | Self::HalfwordSigned => None,
        }
    }

    fn resolve(self, extension: SwitchAddExtend) -> Option<(usize, bool)> {
        match self {
            Self::ByteUnsigned => match extension {
                SwitchAddExtend::ByteUnsigned => Some((1, false)),
                SwitchAddExtend::ByteSigned => Some((1, true)),
                SwitchAddExtend::HalfwordUnsigned
                | SwitchAddExtend::HalfwordSigned
                | SwitchAddExtend::WordUnsigned
                | SwitchAddExtend::WordSigned => None,
            },
            Self::ByteSigned => match extension {
                SwitchAddExtend::ByteSigned => Some((1, true)),
                SwitchAddExtend::ByteUnsigned
                | SwitchAddExtend::HalfwordUnsigned
                | SwitchAddExtend::HalfwordSigned
                | SwitchAddExtend::WordUnsigned
                | SwitchAddExtend::WordSigned => None,
            },
            Self::HalfwordUnsigned => match extension {
                SwitchAddExtend::HalfwordUnsigned => Some((2, false)),
                SwitchAddExtend::HalfwordSigned => Some((2, true)),
                SwitchAddExtend::ByteUnsigned
                | SwitchAddExtend::ByteSigned
                | SwitchAddExtend::WordUnsigned
                | SwitchAddExtend::WordSigned => None,
            },
            Self::HalfwordSigned => match extension {
                SwitchAddExtend::HalfwordSigned => Some((2, true)),
                SwitchAddExtend::ByteUnsigned
                | SwitchAddExtend::ByteSigned
                | SwitchAddExtend::HalfwordUnsigned
                | SwitchAddExtend::WordUnsigned
                | SwitchAddExtend::WordSigned => None,
            },
            Self::WordSigned => match extension {
                SwitchAddExtend::WordSigned => Some((4, true)),
                SwitchAddExtend::ByteUnsigned
                | SwitchAddExtend::ByteSigned
                | SwitchAddExtend::HalfwordUnsigned
                | SwitchAddExtend::HalfwordSigned
                | SwitchAddExtend::WordUnsigned => None,
            },
        }
    }
}

impl SwitchInsn {
    fn defines(self, register: u8) -> bool {
        match self {
            Self::Adrp { dest, .. }
            | Self::AddImmediate { dest, .. }
            | Self::IndexedLoad { dest, .. }
            | Self::Adr { dest, .. }
            | Self::AddExtended { dest, .. }
            | Self::ShiftedAdd { dest, .. }
            | Self::SelectorAdjustment { dest, .. }
            | Self::RegisterCopy { dest, .. } => dest == register,
            Self::Other
            | Self::Nop
            | Self::CmpImmediate { .. }
            | Self::ConditionalBranch { .. }
            | Self::DirectBranch { .. }
            | Self::IndirectBranch { .. } => false,
        }
    }
}

pub(super) fn recover_with_image<'image>(
    machine_code: &[u8],
    base: u64,
    image: &dyn Fn(u64) -> Option<&'image [u8]>,
    relocations: &dyn Fn(u64) -> Option<u64>,
) -> Result<LeafRecovery> {
    recover_with_calls_and_image(machine_code, base, &[], image, relocations)
}

pub(super) fn recover_with_calls(
    machine_code: &[u8],
    base: u64,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    recover_with_calls_and_image(
        machine_code,
        base,
        calls,
        &no_aarch64_image,
        &no_aarch64_relocation,
    )
}

fn no_aarch64_image(_: u64) -> Option<&'static [u8]> {
    None
}

fn no_aarch64_relocation(_: u64) -> Option<u64> {
    None
}

fn instruction_accesses_fpcr(insn: &DisasmInsn) -> bool {
    aarch64_instruction_word(insn)
        .is_some_and(|word: u32| matches!(word & 0xffff_ffe0, 0xd51b_4400 | 0xd53b_4400))
}

fn recover_with_calls_and_image<'image>(
    machine_code: &[u8],
    base: u64,
    calls: &[ResolvedCall],
    image: &dyn Fn(u64) -> Option<&'image [u8]>,
    relocations: &dyn Fn(u64) -> Option<u64>,
) -> Result<LeafRecovery> {
    if calls.iter().any(|call: &ResolvedCall| {
        call.signature.abi() != Abi::Aapcs64
            || call.signature.callable_arity() > Abi::Aapcs64.arg_order().len()
    }) {
        return Err(reject(
            "resolved call argument count exceeds the bounded aapcs64 stack slots",
        ));
    }
    let unique_targets: BTreeSet<u64> = calls
        .iter()
        .map(|call: &ResolvedCall| call.target)
        .collect();
    if unique_targets.len() != calls.len() {
        return Err(reject("resolved call targets contain duplicates"));
    }
    if machine_code.is_empty() {
        return Err(reject("empty machine code"));
    }
    if !machine_code.len().is_multiple_of(4) {
        return Err(reject("instruction bytes are not four-byte aligned"));
    }
    if machine_code.len() > MAX_INSTRUCTIONS * 4 {
        return Err(reject("instruction bytes exceed the bounded lift"));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::Aarch64, base, machine_code)?;
    if insns.is_empty() || insns.len() > MAX_INSTRUCTIONS {
        return Err(reject("instruction count is outside the bounded lift"));
    }
    if let Some(insn) = insns
        .iter()
        .find(|insn: &&DisasmInsn| instruction_accesses_fpcr(insn))
    {
        return Err(reject_at(
            insn,
            "FPCR-dependent scalar floating-point semantics are unsupported",
        ));
    }
    if has_bulk_q_spill(&insns) {
        return Err(reject(
            "bulk q0..q7 stack spill is outside scalar floating-point increment 1",
        ));
    }
    let image_context: ImageContext<'_, 'image> = ImageContext { image, relocations };
    let switches: BTreeMap<usize, SwitchDispatch> =
        recover_aarch64_switches(&insns, base, machine_code.len(), &image_context);
    let address_folds: BTreeMap<usize, PcRelativeAddressFold> =
        recover_pc_relative_address_folds(&insns);
    let mut ignored_instructions: BTreeSet<usize> = BTreeSet::new();
    for dispatch in switches.values() {
        ignored_instructions.extend(dispatch.ignored_instructions.iter().copied());
    }
    ignored_instructions.extend(
        address_folds
            .values()
            .filter(|fold: &&PcRelativeAddressFold| fold.dest == fold.source)
            .map(|fold: &PcRelativeAddressFold| fold.page_index),
    );
    let mut items: Vec<Item> = Vec::new();
    let mut return_width: Width = Width::W64;
    let mut flags: Option<TrackedFlags> = None;
    let mut next_sel: u32 = 0;
    let mut flag_definitions: BTreeMap<usize, TrackedFlags> = BTreeMap::new();
    let frame: FrameAnalysis = aarch64_frame::analyze(&insns, &switches)?;
    let outgoing: BTreeMap<usize, Vec<OutgoingSlot>> = outgoing_stores(&insns, calls)?;
    let vector_context: bool = insns.iter().any(instruction_has_vector_syntax);
    for (index, insn) in insns.iter().enumerate() {
        let address: u64 = item_address(base, index, 0)?;
        if let Some(dispatch) = switches.get(&index) {
            let cases: Vec<(i64, u64)> = dispatch
                .cases
                .iter()
                .map(|(value, target): &(i64, u64)| {
                    Ok((*value, normalized_switch_target(&insns, base, *target)?))
                })
                .collect::<Result<Vec<(i64, u64)>>>()?;
            let default: u64 = normalized_switch_target(&insns, base, dispatch.default)?;
            items.push(Item {
                address,
                kind: ItemKind::Switch {
                    disc: dispatch.disc,
                    cases,
                    default,
                },
            });
            continue;
        }
        if ignored_instructions.contains(&index) {
            continue;
        }
        let outgoing_slots: &[OutgoingSlot] =
            outgoing.get(&index).map(Vec::as_slice).unwrap_or_default();
        if frame.management.contains(&index) {
            continue;
        }
        if is_frame_management(insn) {
            return Err(reject_at(
                insn,
                "stack-frame instruction is outside a recognized prologue or epilogue",
            ));
        }
        if let Some(stmts) =
            try_lower_scalar_fp(insn, frame.info_at(index), vector_context, &image_context)?
        {
            push_stmts(&mut items, base, index, stmts)?;
            continue;
        }
        if let Some(stmts) = try_lower_scalar_simd(insn)? {
            push_stmts(&mut items, base, index, stmts)?;
            continue;
        }
        if matches!(insn.mnemonic.as_str(), "ldr" | "str")
            && first_operand_is_scalar_dreg(&insn.operands)
            && (vector_context || is_dreg_post_indexed(&insn.operands))
        {
            let operands: Vec<&str> = split_operands(&insn.operands);
            let stmts: Vec<Stmt> = vector_load_store(
                insn,
                &operands,
                insn.mnemonic == "ldr",
                frame.info_at(index),
            )?;
            push_stmts(&mut items, base, index, stmts)?;
            continue;
        }
        if !matches!(
            insn.mnemonic.as_str(),
            "fcmp" | "fcmpe" | "fccmp" | "fccmpe" | "fcsel"
        ) && has_unsupported_register_class(&insn.operands)
        {
            return Err(reject_at(insn, "unsupported instruction"));
        }
        if operand_is_vector(insn) {
            let stmts: Vec<Stmt> = lower_vector(insn, frame.info_at(index))?;
            push_stmts(&mut items, base, index, stmts)?;
            continue;
        }
        if insn.mnemonic == "nop" {
            continue;
        }
        if let Some(fold) = address_folds.get(&index) {
            let dest: RegRef = aarch64_switch_register(fold.dest)
                .map(|reg: RegRef| RegRef {
                    reg: reg.reg,
                    width: Width::W64,
                })
                .ok_or_else(|| reject_at(insn, "pc-relative address destination is unsupported"))?;
            push_stmts(
                &mut items,
                base,
                index,
                vec![Stmt::Assign {
                    dest,
                    src: Source::Imm(i64::from_ne_bytes(fold.target.to_ne_bytes())),
                }],
            )?;
            if dest.reg == Reg::Rax {
                return_width = dest.width;
            }
            continue;
        }
        match insn.mnemonic.as_str() {
            "add" | "adds" | "sub" | "subs" | "and" | "orr" | "eor" | "bic" | "orn" | "eon"
            | "lsl" | "lsr" | "asr" | "mul" | "sdiv" | "udiv" | "umull" | "smull" | "umulh"
            | "smulh" => {
                let (dest, mut stmts): (RegRef, Vec<Stmt>) = lower_alu(insn)?;
                let new_flags: Option<TrackedFlags> = if insn.mnemonic == "subs" {
                    let (mut snapshots, value): (Vec<Stmt>, Flags) = subtract_flags(insn)?;
                    snapshots.append(&mut stmts);
                    stmts = snapshots;
                    Some(TrackedFlags {
                        value,
                        nz_only: false,
                        mark: 0,
                    })
                } else if insn.mnemonic == "adds" {
                    let (mut snapshots, value): (Vec<Stmt>, Flags) = add_flags(insn)?;
                    snapshots.append(&mut stmts);
                    stmts = snapshots;
                    Some(TrackedFlags {
                        value,
                        nz_only: false,
                        mark: 0,
                    })
                } else {
                    None
                };
                push_stmts(&mut items, base, index, stmts)?;
                let new_flags: Option<TrackedFlags> =
                    new_flags.map(|mut definition: TrackedFlags| {
                        definition.mark = items.len();
                        definition
                    });
                if matches!(insn.mnemonic.as_str(), "subs" | "adds") {
                    flags.clone_from(&new_flags);
                }
                if let Some(definition) = new_flags {
                    flag_definitions.insert(index, definition);
                }
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "madd" | "msub" => {
                let (dest, stmts): (RegRef, Vec<Stmt>) = lower_multiply_accumulate(insn)?;
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "mov" | "movz" | "movk" | "movn" => {
                let (dest, stmts): (RegRef, Vec<Stmt>) = lower_move(insn)?;
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "ldr" | "str" | "ldur" | "stur" => {
                let (dest, stmts): (Option<RegRef>, Vec<Stmt>) =
                    lower_memory(insn, frame.info_at(index), outgoing_slots)?;
                push_stmts(&mut items, base, index, stmts)?;
                if let Some(dest) = dest
                    && dest.reg == Reg::Rax
                {
                    return_width = dest.width;
                }
            }
            mnemonic @ ("ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "ldurb" | "ldurh"
            | "ldursb" | "ldursh" | "ldursw") => {
                let (load_width, signed): (Width, bool) = match mnemonic {
                    "ldrb" | "ldurb" => (Width::W8, false),
                    "ldrh" | "ldurh" => (Width::W16, false),
                    "ldrsb" | "ldursb" => (Width::W8, true),
                    "ldrsh" | "ldursh" => (Width::W16, true),
                    _ => (Width::W32, true),
                };
                let operands: Vec<&str> = split_operands(&insn.operands);
                if !(2..=3).contains(&operands.len()) {
                    return Err(reject_at(insn, "malformed sized load"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (mut mem, pre_index): (MemRef, bool) = parse_memory(operands[1], load_width)?;
                let post_delta: Option<i64> = operands
                    .get(2)
                    .map(|token: &&str| parse_immediate(token))
                    .transpose()?;
                if pre_index && post_delta.is_some() {
                    return Err(reject_at(
                        insn,
                        "address cannot be both pre-indexed and post-indexed",
                    ));
                }
                if (pre_index || post_delta.is_some()) && mem.base == Some(dest.reg) {
                    return Err(reject_at(
                        insn,
                        "sized load writes back to its own transfer register",
                    ));
                }
                let mut stmts: Vec<Stmt> = Vec::new();
                if pre_index {
                    let delta: i64 = mem.disp;
                    mem.disp = 0;
                    stmts.extend(frame_writeback(frame.info_at(index), mem.base, delta)?);
                }
                stmts.push(Stmt::Extend {
                    dest,
                    src: ExtSource::Mem(mem),
                    signed,
                });
                if let Some(delta) = post_delta {
                    if mem.disp != 0 {
                        return Err(reject_at(
                            insn,
                            "post-indexed address has an inline displacement",
                        ));
                    }
                    stmts.extend(frame_writeback(frame.info_at(index), mem.base, delta)?);
                }
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            mnemonic @ ("strb" | "strh" | "sturb" | "sturh") => {
                let store_width: Width = match mnemonic {
                    "strb" | "sturb" => Width::W8,
                    _ => Width::W16,
                };
                let operands: Vec<&str> = split_operands(&insn.operands);
                if !(2..=3).contains(&operands.len()) {
                    return Err(reject_at(insn, "malformed sized store"));
                }
                let source: Source = if matches!(operands[0], "wzr" | "xzr") {
                    Source::Imm(0)
                } else {
                    Source::Reg(parse_reg(operands[0])?)
                };
                let (mut mem, pre_index): (MemRef, bool) = parse_memory(operands[1], store_width)?;
                let post_delta: Option<i64> = operands
                    .get(2)
                    .map(|token: &&str| parse_immediate(token))
                    .transpose()?;
                if pre_index && post_delta.is_some() {
                    return Err(reject_at(
                        insn,
                        "address cannot be both pre-indexed and post-indexed",
                    ));
                }
                if let (true, Source::Reg(value)) = (pre_index || post_delta.is_some(), &source)
                    && mem.base == Some(value.reg)
                {
                    return Err(reject_at(
                        insn,
                        "sized store writes back to its own transfer register",
                    ));
                }
                let mut stmts: Vec<Stmt> = Vec::new();
                if pre_index {
                    let delta: i64 = mem.disp;
                    mem.disp = 0;
                    stmts.extend(frame_writeback(frame.info_at(index), mem.base, delta)?);
                }
                stmts.push(Stmt::Store {
                    addr: mem,
                    src: source,
                });
                if let Some(delta) = post_delta {
                    if mem.disp != 0 {
                        return Err(reject_at(
                            insn,
                            "post-indexed address has an inline displacement",
                        ));
                    }
                    stmts.extend(frame_writeback(frame.info_at(index), mem.base, delta)?);
                }
                push_stmts(&mut items, base, index, stmts)?;
            }
            "ldp" | "stp" => {
                let (dest, stmts): (Option<RegRef>, Vec<Stmt>) =
                    lower_pair_memory(insn, frame.info_at(index), outgoing_slots)?;
                push_stmts(&mut items, base, index, stmts)?;
                if let Some(dest) = dest {
                    return_width = dest.width;
                }
            }
            "bfi" => {
                let (dest, stmts): (RegRef, Vec<Stmt>) = lower_bfi(insn)?;
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "ubfiz" | "ubfx" | "sbfiz" | "sbfx" => {
                let (dest, stmts): (RegRef, Vec<Stmt>) = lower_bitfield(insn)?;
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "cmp" | "cmn" | "tst" => {
                let (stmts, mut new_flags): (Vec<Stmt>, TrackedFlags) = lower_flag_setter(insn)?;
                push_stmts(&mut items, base, index, stmts)?;
                new_flags.mark = items.len();
                flags = Some(new_flags.clone());
                flag_definitions.insert(index, new_flags);
            }
            "cbz" | "cbnz" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 2 {
                    return Err(reject_at(insn, "malformed compare-and-branch"));
                }
                let operand: RegRef = parse_reg(operands[0])?;
                let target: u64 = normalized_target(&insns, base, insn, operands[1])?;
                let kind: CondKind = if insn.mnemonic == "cbz" {
                    CondKind::E
                } else {
                    CondKind::Ne
                };
                items.push(Item {
                    address,
                    kind: ItemKind::Branch {
                        kind,
                        flags: Flags::Test { operand },
                        target,
                    },
                });
            }
            mnemonic if mnemonic.starts_with("b.") => {
                let kind: CondKind = parse_condition(
                    mnemonic
                        .strip_prefix("b.")
                        .ok_or_else(|| reject_at(insn, "malformed conditional branch"))?,
                )?;
                let live_flags: TrackedFlags = flags
                    .clone()
                    .ok_or_else(|| reject_at(insn, "conditional branch lacks live nzcv state"))?;
                if (live_flags.nz_only && !kind.sign_zero_only())
                    || !condition_is_sound(kind, &live_flags.value)
                {
                    return Err(reject_at(
                        insn,
                        "condition is undefined for the tracked nzcv source",
                    ));
                }
                let target: u64 = normalized_target(&insns, base, insn, insn.operands.trim())?;
                items.push(Item {
                    address,
                    kind: ItemKind::Branch {
                        kind,
                        flags: live_flags.value,
                        target,
                    },
                });
            }
            "tbz" | "tbnz" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 3 {
                    return Err(reject_at(insn, "malformed test-bit-and-branch"));
                }
                let operand: RegRef = parse_reg(operands[0])?;
                let bit: i64 = parse_immediate(operands[1])?;
                if bit < 0 || bit >= i64::from(operand.width.bits()) {
                    return Err(reject_at(insn, "test bit is outside the register width"));
                }
                let bit: u32 = u32::try_from(bit)
                    .map_err(|_| reject_at(insn, "test bit conversion overflow"))?;
                let mask: u64 = 1_u64
                    .checked_shl(bit)
                    .ok_or_else(|| reject_at(insn, "test bit mask overflow"))?;
                let target: u64 = normalized_target(&insns, base, insn, operands[2])?;
                let kind: CondKind = if insn.mnemonic == "tbz" {
                    CondKind::E
                } else {
                    CondKind::Ne
                };
                items.push(Item {
                    address,
                    kind: ItemKind::Branch {
                        kind,
                        flags: Flags::TestImm {
                            operand,
                            mask: i64::from_ne_bytes(mask.to_ne_bytes()),
                        },
                        target,
                    },
                });
            }
            "b" => {
                let target: u64 = normalized_target(&insns, base, insn, insn.operands.trim())?;
                items.push(Item {
                    address,
                    kind: ItemKind::Jmp { target },
                });
            }
            "bl" => {
                let target: u64 = relative_target(insn, insn.operands.trim())?;
                let register_args: &[Reg] = &CALL_ARG_ORDER[..8];
                items.push(Item {
                    address,
                    kind: ItemKind::Stmt(Stmt::Call {
                        target,
                        args: register_args.to_vec(),
                        name: None,
                    }),
                });
                flags = None;
                return_width = Width::W64;
            }
            "ret" if insn.operands.trim().is_empty() => {
                items.push(Item {
                    address,
                    kind: ItemKind::Ret,
                });
            }
            "csel" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 4 {
                    return Err(reject_at(insn, "malformed conditional select"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (n_reg, n_src, n_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[1])?;
                let (m_reg, m_src, m_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[2])?;
                if dest.width != n_width || dest.width != m_width {
                    return Err(reject_at(insn, "mixed-width conditional select"));
                }
                let kind: CondKind = parse_condition(operands[3])?;
                let live_flags: TrackedFlags = flags
                    .clone()
                    .ok_or_else(|| reject_at(insn, "conditional select lacks live nzcv state"))?;
                if (live_flags.nz_only && !kind.sign_zero_only())
                    || !condition_is_sound(kind, &live_flags.value)
                {
                    return Err(reject_at(
                        insn,
                        "conditional select condition is undefined for the tracked nzcv source",
                    ));
                }
                let (resolved_kind, resolved_value): (CondKind, Flags) = resolve_aarch64_flags(
                    &mut items,
                    &live_flags,
                    kind,
                    &mut next_sel,
                    insn.address,
                );
                let resolved_flags: TrackedFlags = TrackedFlags {
                    value: resolved_value,
                    nz_only: live_flags.nz_only,
                    mark: live_flags.mark,
                };
                let stmts: Vec<Stmt> = build_select_stmts(
                    dest,
                    n_reg,
                    n_src,
                    m_reg,
                    m_src,
                    resolved_kind,
                    &resolved_flags,
                    &mut next_sel,
                )?;
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            mnemonic @ ("csinc" | "csinv" | "csneg") => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 4 {
                    return Err(reject_at(insn, "malformed conditional select"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (n_reg, n_src, n_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[1])?;
                let (m_reg, m_src, m_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[2])?;
                if dest.width != n_width || dest.width != m_width {
                    return Err(reject_at(insn, "mixed-width conditional select"));
                }
                let kind: CondKind = parse_condition(operands[3])?;
                let live_flags: TrackedFlags = flags
                    .clone()
                    .ok_or_else(|| reject_at(insn, "conditional select lacks live nzcv state"))?;
                let scratch: RegRef = RegRef {
                    reg: Reg::A64Tmp2,
                    width: dest.width,
                };
                if m_reg == Some(scratch.reg)
                    || n_reg == Some(scratch.reg)
                    || flags_reference_reg(&live_flags.value, scratch.reg)
                {
                    return Err(reject_at(
                        insn,
                        "conditional select aliases the scratch register",
                    ));
                }
                let mut stmts: Vec<Stmt> = vec![Stmt::Assign {
                    dest: scratch,
                    src: m_src,
                }];
                match mnemonic {
                    "csinc" => stmts.push(Stmt::BinAssign {
                        dest: scratch,
                        op: BinOp::Add,
                        src: Source::Imm(1),
                    }),
                    "csinv" => stmts.push(Stmt::UnAssign {
                        dest: scratch,
                        op: UnOp::Not,
                    }),
                    _ => stmts.push(Stmt::UnAssign {
                        dest: scratch,
                        op: UnOp::Neg,
                    }),
                }
                let (resolved_kind, resolved_value): (CondKind, Flags) = resolve_aarch64_flags(
                    &mut items,
                    &live_flags,
                    kind,
                    &mut next_sel,
                    insn.address,
                );
                let resolved_flags: TrackedFlags = TrackedFlags {
                    value: resolved_value,
                    nz_only: live_flags.nz_only,
                    mark: live_flags.mark,
                };
                stmts.extend(build_select_stmts(
                    dest,
                    n_reg,
                    n_src,
                    Some(scratch.reg),
                    Source::Reg(scratch),
                    resolved_kind,
                    &resolved_flags,
                    &mut next_sel,
                )?);
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            mnemonic @ ("cinc" | "cinv" | "cneg") => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 3 {
                    return Err(reject_at(insn, "malformed conditional select"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (n_reg, n_src, n_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[1])?;
                if dest.width != n_width {
                    return Err(reject_at(insn, "mixed-width conditional select"));
                }
                let kind: CondKind = parse_condition(operands[2])?;
                let live_flags: TrackedFlags = flags
                    .clone()
                    .ok_or_else(|| reject_at(insn, "conditional select lacks live nzcv state"))?;
                let scratch: RegRef = RegRef {
                    reg: Reg::A64Tmp2,
                    width: dest.width,
                };
                if n_reg == Some(scratch.reg) || flags_reference_reg(&live_flags.value, scratch.reg)
                {
                    return Err(reject_at(
                        insn,
                        "conditional select aliases the scratch register",
                    ));
                }
                let mut stmts: Vec<Stmt> = vec![Stmt::Assign {
                    dest: scratch,
                    src: n_src.clone(),
                }];
                match mnemonic {
                    "cinc" => stmts.push(Stmt::BinAssign {
                        dest: scratch,
                        op: BinOp::Add,
                        src: Source::Imm(1),
                    }),
                    "cinv" => stmts.push(Stmt::UnAssign {
                        dest: scratch,
                        op: UnOp::Not,
                    }),
                    _ => stmts.push(Stmt::UnAssign {
                        dest: scratch,
                        op: UnOp::Neg,
                    }),
                }
                let (resolved_kind, resolved_value): (CondKind, Flags) = resolve_aarch64_flags(
                    &mut items,
                    &live_flags,
                    kind,
                    &mut next_sel,
                    insn.address,
                );
                let resolved_flags: TrackedFlags = TrackedFlags {
                    value: resolved_value,
                    nz_only: live_flags.nz_only,
                    mark: live_flags.mark,
                };
                stmts.extend(build_select_stmts(
                    dest,
                    Some(scratch.reg),
                    Source::Reg(scratch),
                    n_reg,
                    n_src,
                    resolved_kind,
                    &resolved_flags,
                    &mut next_sel,
                )?);
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "cset" | "csetm" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 2 {
                    return Err(reject_at(insn, "malformed conditional set"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let kind: CondKind = parse_condition(operands[1])?;
                let true_value: i64 = if insn.mnemonic == "csetm" { -1 } else { 1 };
                let live_flags: TrackedFlags = flags
                    .clone()
                    .ok_or_else(|| reject_at(insn, "conditional set lacks live nzcv state"))?;
                if (live_flags.nz_only && !kind.sign_zero_only())
                    || !condition_is_sound(kind, &live_flags.value)
                {
                    return Err(reject_at(
                        insn,
                        "condition is undefined for the tracked nzcv source",
                    ));
                }
                let (resolved_kind, resolved_value): (CondKind, Flags) = resolve_aarch64_flags(
                    &mut items,
                    &live_flags,
                    kind,
                    &mut next_sel,
                    insn.address,
                );
                let stmts: Vec<Stmt> = if flags_reference_reg(&resolved_value, dest.reg) {
                    let var: u32 = next_sel;
                    next_sel += 1;
                    vec![
                        Stmt::FlagSnapshot {
                            var,
                            kind: resolved_kind,
                            flags: resolved_value,
                        },
                        Stmt::Assign {
                            dest,
                            src: Source::Imm(0),
                        },
                        Stmt::Cond {
                            dest,
                            src: Source::Imm(true_value),
                            kind: CondKind::Ne,
                            flags: Flags::Snapshot { var },
                        },
                    ]
                } else {
                    vec![
                        Stmt::Assign {
                            dest,
                            src: Source::Imm(0),
                        },
                        Stmt::Cond {
                            dest,
                            src: Source::Imm(true_value),
                            kind: resolved_kind,
                            flags: resolved_value,
                        },
                    ]
                };
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "ccmp" | "ccmn" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 4 {
                    return Err(reject_at(insn, "malformed conditional compare"));
                }
                let lhs: RegRef = parse_reg(operands[0])?;
                let rhs: Source = parse_source(operands[1], lhs.width)?;
                let nzcv_imm: i64 = parse_immediate(operands[2])?;
                if !(0..=15).contains(&nzcv_imm) {
                    return Err(reject_at(
                        insn,
                        "conditional compare nzcv immediate is outside the four-bit range",
                    ));
                }
                let nzcv: u8 = u8::try_from(nzcv_imm)
                    .map_err(|_| reject_at(insn, "conditional compare nzcv conversion overflow"))?;
                let precond: CondKind = parse_condition(operands[3])?;
                let live_flags: TrackedFlags = flags
                    .clone()
                    .ok_or_else(|| reject_at(insn, "conditional compare lacks live nzcv state"))?;
                if (live_flags.nz_only && !precond.sign_zero_only())
                    || !condition_is_sound(precond, &live_flags.value)
                {
                    return Err(reject_at(
                        insn,
                        "conditional compare precondition is undefined for the tracked nzcv source",
                    ));
                }
                let taken: Flags = if insn.mnemonic == "ccmn" {
                    Flags::Add { lhs, rhs }
                } else {
                    Flags::Cmp { lhs, rhs }
                };
                let (resolved_precond, resolved_prior): (CondKind, Flags) = resolve_aarch64_flags(
                    &mut items,
                    &live_flags,
                    precond,
                    &mut next_sel,
                    insn.address,
                );
                let definition: TrackedFlags = TrackedFlags {
                    value: Flags::CondCmp {
                        prior: Box::new(resolved_prior),
                        precond: resolved_precond,
                        taken: Box::new(taken),
                        nzcv,
                    },
                    nz_only: false,
                    mark: items.len(),
                };
                flags = Some(definition.clone());
                flag_definitions.insert(index, definition);
            }
            "fcmp" | "fcmpe" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 2 {
                    return Err(reject_at(insn, "malformed scalar floating-point compare"));
                }
                let (lhs, width): (Xmm, FpWidth) = parse_fp_register(operands[0])?
                    .ok_or_else(|| reject_at(insn, "floating-point compare lhs is not scalar"))?;
                let rhs: FpOperand = parse_fp_compare_operand(operands[1], width, insn)?;
                let definition: TrackedFlags = TrackedFlags {
                    value: Flags::FpCmp {
                        lhs,
                        rhs,
                        width,
                        model: FpUnorderedModel::UnorderedIsUnequal,
                    },
                    nz_only: false,
                    mark: items.len(),
                };
                flags = Some(definition.clone());
                flag_definitions.insert(index, definition);
            }
            "fccmp" | "fccmpe" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 4 {
                    return Err(reject_at(
                        insn,
                        "malformed scalar floating-point conditional compare",
                    ));
                }
                let (lhs, width): (Xmm, FpWidth) =
                    parse_fp_register(operands[0])?.ok_or_else(|| {
                        reject_at(insn, "floating-point conditional compare lhs is not scalar")
                    })?;
                let (rhs_reg, rhs_width): (Xmm, FpWidth) = parse_fp_register(operands[1])?
                    .ok_or_else(|| {
                        reject_at(insn, "floating-point conditional compare rhs is not scalar")
                    })?;
                if rhs_width != width {
                    return Err(reject_at(
                        insn,
                        "floating-point conditional compare uses mixed precision",
                    ));
                }
                let nzcv_imm: i64 = parse_immediate(operands[2])?;
                if !(0..=15).contains(&nzcv_imm) {
                    return Err(reject_at(
                        insn,
                        "conditional compare nzcv immediate is outside the four-bit range",
                    ));
                }
                let nzcv: u8 = u8::try_from(nzcv_imm)
                    .map_err(|_| reject_at(insn, "conditional compare nzcv conversion overflow"))?;
                let precond: CondKind = parse_condition(operands[3])?;
                let live_flags: TrackedFlags = flags.clone().ok_or_else(|| {
                    reject_at(
                        insn,
                        "floating-point conditional compare lacks live nzcv state",
                    )
                })?;
                if (live_flags.nz_only && !precond.sign_zero_only())
                    || !condition_is_sound(precond, &live_flags.value)
                {
                    return Err(reject_at(
                        insn,
                        "floating-point conditional compare precondition is undefined for the tracked nzcv source",
                    ));
                }
                let (resolved_precond, resolved_prior): (CondKind, Flags) = resolve_aarch64_flags(
                    &mut items,
                    &live_flags,
                    precond,
                    &mut next_sel,
                    insn.address,
                );
                let definition: TrackedFlags = TrackedFlags {
                    value: Flags::CondCmp {
                        prior: Box::new(resolved_prior),
                        precond: resolved_precond,
                        taken: Box::new(Flags::FpCmp {
                            lhs,
                            rhs: FpOperand::Xmm(rhs_reg),
                            width,
                            model: FpUnorderedModel::UnorderedIsUnequal,
                        }),
                        nzcv,
                    },
                    nz_only: false,
                    mark: items.len(),
                };
                flags = Some(definition.clone());
                flag_definitions.insert(index, definition);
            }
            "fcsel" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 4 {
                    return Err(reject_at(
                        insn,
                        "malformed scalar floating-point conditional select",
                    ));
                }
                let (dest, width): (Xmm, FpWidth) =
                    parse_fp_register(operands[0])?.ok_or_else(|| {
                        reject_at(
                            insn,
                            "floating-point conditional select destination is not scalar",
                        )
                    })?;
                let (if_true, true_width): (Xmm, FpWidth) = parse_fp_register(operands[1])?
                    .ok_or_else(|| {
                        reject_at(
                            insn,
                            "floating-point conditional select true operand is not scalar",
                        )
                    })?;
                let (if_false, false_width): (Xmm, FpWidth) = parse_fp_register(operands[2])?
                    .ok_or_else(|| {
                        reject_at(
                            insn,
                            "floating-point conditional select false operand is not scalar",
                        )
                    })?;
                if width != true_width || width != false_width {
                    return Err(reject_at(
                        insn,
                        "scalar floating-point conditional select uses mixed precision",
                    ));
                }
                let kind: CondKind = parse_condition(operands[3])?;
                let live_flags: TrackedFlags = flags.clone().ok_or_else(|| {
                    reject_at(
                        insn,
                        "floating-point conditional select lacks live nzcv state",
                    )
                })?;
                if (live_flags.nz_only && !kind.sign_zero_only())
                    || !condition_is_sound(kind, &live_flags.value)
                {
                    return Err(reject_at(
                        insn,
                        "floating-point conditional select condition is undefined for the tracked nzcv source",
                    ));
                }
                let (kind, resolved): (CondKind, Flags) = resolve_aarch64_flags(
                    &mut items,
                    &live_flags,
                    kind,
                    &mut next_sel,
                    insn.address,
                );
                let stmt: Stmt = Stmt::FpCsel {
                    dest,
                    if_true: FpOperand::Xmm(if_true),
                    if_false: FpOperand::Xmm(if_false),
                    kind,
                    flags: resolved,
                    width,
                };
                push_stmts(&mut items, base, index, vec![stmt])?;
            }
            "adr" | "adrp" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.is_empty() {
                    return Err(reject_at(insn, "malformed pc-relative address"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                if dest.width != Width::W64 {
                    return Err(reject_at(insn, "pc-relative address is not an x register"));
                }
                let word: u32 = aarch64_instruction_word(insn)
                    .ok_or_else(|| reject_at(insn, "malformed pc-relative address"))?;
                let target: u64 = if insn.mnemonic == "adr" {
                    aarch64_adr_target(insn.address, word)
                } else {
                    aarch64_adrp_target(insn.address, word)
                }
                .ok_or_else(|| reject_at(insn, "pc-relative address overflow"))?;
                push_stmts(
                    &mut items,
                    base,
                    index,
                    vec![Stmt::Assign {
                        dest,
                        src: Source::Imm(i64::from_ne_bytes(target.to_ne_bytes())),
                    }],
                )?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "neg" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 2 {
                    return Err(reject_at(insn, "malformed negate"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (_, m_src, m_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[1])?;
                if dest.width != m_width {
                    return Err(reject_at(insn, "mixed-width negate"));
                }
                push_stmts(
                    &mut items,
                    base,
                    index,
                    vec![
                        Stmt::Assign { dest, src: m_src },
                        Stmt::UnAssign {
                            dest,
                            op: UnOp::Neg,
                        },
                    ],
                )?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "ror" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 3 {
                    return Err(reject_at(insn, "malformed rotate"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (_, n_src, n_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[1])?;
                if dest.width != n_width {
                    return Err(reject_at(insn, "mixed-width rotate"));
                }
                let amount: Source = parse_source(operands[2], dest.width)?;
                let width_bits: i64 = i64::from(dest.width.bits());
                let left_amount: RegRef = RegRef {
                    reg: Reg::A64Tmp2,
                    width: dest.width,
                };
                let left_value: RegRef = RegRef {
                    reg: Reg::A64Tmp,
                    width: dest.width,
                };
                push_stmts(
                    &mut items,
                    base,
                    index,
                    vec![
                        Stmt::Assign {
                            dest: left_amount,
                            src: Source::Imm(width_bits),
                        },
                        Stmt::BinAssign {
                            dest: left_amount,
                            op: BinOp::Sub,
                            src: amount.clone(),
                        },
                        Stmt::Assign {
                            dest: left_value,
                            src: n_src.clone(),
                        },
                        Stmt::BinAssign {
                            dest: left_value,
                            op: BinOp::Shl,
                            src: Source::Reg(left_amount),
                        },
                        Stmt::Assign { dest, src: n_src },
                        Stmt::BinAssign {
                            dest,
                            op: BinOp::Shr,
                            src: amount,
                        },
                        Stmt::BinAssign {
                            dest,
                            op: BinOp::Or,
                            src: Source::Reg(left_value),
                        },
                    ],
                )?;
                if flags.as_ref().is_some_and(|tracked: &TrackedFlags| {
                    flags_reference_reg(&tracked.value, Reg::A64Tmp)
                        || flags_reference_reg(&tracked.value, Reg::A64Tmp2)
                }) {
                    flags = None;
                }
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "extr" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 4 {
                    return Err(reject_at(insn, "malformed extract"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let high: RegRef = parse_reg(operands[1])?;
                let low: RegRef = parse_reg(operands[2])?;
                if dest.width != high.width || dest.width != low.width {
                    return Err(reject_at(insn, "mixed-width extract"));
                }
                let lsb: i64 = parse_immediate(operands[3])?;
                let width_bits: i64 = i64::from(dest.width.bits());
                if lsb <= 0 || lsb >= width_bits {
                    return Err(reject_at(insn, "extract shift is outside the funnel range"));
                }
                let high_part: RegRef = RegRef {
                    reg: Reg::A64Tmp,
                    width: dest.width,
                };
                push_stmts(
                    &mut items,
                    base,
                    index,
                    vec![
                        Stmt::Assign {
                            dest: high_part,
                            src: Source::Reg(high),
                        },
                        Stmt::BinAssign {
                            dest: high_part,
                            op: BinOp::Shl,
                            src: Source::Imm(width_bits - lsb),
                        },
                        Stmt::Assign {
                            dest,
                            src: Source::Reg(low),
                        },
                        Stmt::BinAssign {
                            dest,
                            op: BinOp::Shr,
                            src: Source::Imm(lsb),
                        },
                        Stmt::BinAssign {
                            dest,
                            op: BinOp::Or,
                            src: Source::Reg(high_part),
                        },
                    ],
                )?;
                if flags.as_ref().is_some_and(|tracked: &TrackedFlags| {
                    flags_reference_reg(&tracked.value, Reg::A64Tmp)
                }) {
                    flags = None;
                }
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "rev" | "rev16" | "rev32" | "clz" | "rbit" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 2 {
                    return Err(reject_at(insn, "malformed unary data-processing"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (_, src, src_width): (Option<Reg>, Source, Width) =
                    select_operand(operands[1])?;
                if dest.width != src_width {
                    return Err(reject_at(insn, "mixed-width unary data-processing"));
                }
                let op: UnOp = match insn.mnemonic.as_str() {
                    "rev" => UnOp::Bswap,
                    "rev16" => UnOp::Rev16,
                    "rev32" => UnOp::Rev32,
                    "clz" => UnOp::Clz,
                    _ => UnOp::Rbit,
                };
                if matches!(op, UnOp::Rev32) && dest.width != Width::W64 {
                    return Err(reject_at(insn, "rev32 outside a 64-bit register"));
                }
                push_stmts(
                    &mut items,
                    base,
                    index,
                    vec![Stmt::Assign { dest, src }, Stmt::UnAssign { dest, op }],
                )?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            _ => return Err(reject_at(insn, "unsupported instruction")),
        }
    }
    if items
        .iter()
        .all(|item: &Item| matches!(&item.kind, ItemKind::Ret))
    {
        return Err(reject(
            "result-free return is ambiguous across integer, floating-point, and void signatures",
        ));
    }
    let has_scalar_fp: bool = items
        .iter()
        .any(|item: &Item| matches!(&item.kind, ItemKind::Stmt(stmt) if return_channel::stmt_is_scalar_fp(stmt)));
    let has_vector: bool = items
        .iter()
        .any(|item: &Item| matches!(item.kind, ItemKind::Stmt(Stmt::Vector(_))));
    if has_scalar_fp && has_vector {
        return Err(reject(
            "mixed scalar floating-point and vector register use is outside increment 1",
        ));
    }
    version_widened_registers(&mut items)?;
    resolve_vector_types(&mut items)?;
    let vec_abi: VectorAbi = scan_vector_abi(&items)?;
    let finish_context: FinishContext<'_> = FinishContext {
        calls,
        vec_abi: &vec_abi,
        frame_info: frame.info,
    };
    finish(
        &insns,
        &mut items,
        base,
        &flag_definitions,
        return_width,
        finish_context,
        &mut next_sel,
    )
}

fn recover_aarch64_switches(
    insns: &[DisasmInsn],
    base: u64,
    machine_code_len: usize,
    image: &ImageContext<'_, '_>,
) -> BTreeMap<usize, SwitchDispatch> {
    let decoded: Vec<SwitchInsn> = insns.iter().map(decode_switch_instruction).collect();
    let mut switches: BTreeMap<usize, SwitchDispatch> = BTreeMap::new();
    for index in 0..decoded.len() {
        let Some(dispatch): Option<SwitchDispatch> =
            recover_aarch64_switch(&decoded, insns, base, machine_code_len, index, image)
        else {
            continue;
        };
        switches.insert(index, dispatch);
    }
    switches
}

fn recover_aarch64_switch(
    decoded: &[SwitchInsn],
    insns: &[DisasmInsn],
    base: u64,
    machine_code_len: usize,
    branch_index: usize,
    image: &ImageContext<'_, '_>,
) -> Option<SwitchDispatch> {
    let SwitchInsn::IndirectBranch { target } = *decoded.get(branch_index)? else {
        return None;
    };
    let (target_definition_index, target_definition): (usize, SwitchInsn) =
        single_definition(decoded, branch_index, target)?;
    let setup: SwitchSetup = match target_definition {
        SwitchInsn::AddExtended {
            dest,
            anchor,
            offset,
            extension,
            scale,
        } if dest == target => {
            let (offset_load_index, offset_load): (usize, SwitchInsn) =
                single_definition(decoded, target_definition_index, offset)?;
            let SwitchInsn::IndexedLoad {
                dest: load_dest,
                base: table_base,
                index,
                encoding: SwitchTableEncoding::Relative(load_kind),
            } = offset_load
            else {
                return None;
            };
            if load_dest != offset
                || target == index
                || anchor == index
                || offset == index
                || table_base == index
            {
                return None;
            }
            let (element_size, signed): (usize, bool) = load_kind.resolve(extension)?;
            let (anchor_definition_index, anchor_definition): (usize, SwitchInsn) =
                single_definition(decoded, target_definition_index, anchor)?;
            let (table_page_index, table_add_index, table_va): (usize, usize, u64) =
                switch_table_address(decoded, offset_load_index, table_base)?;
            let (anchor_index, anchor_va): (usize, u64) = match anchor_definition {
                SwitchInsn::Adr {
                    dest: anchor_dest,
                    target: anchor_va,
                } if anchor_dest == anchor => (anchor_definition_index, anchor_va),
                SwitchInsn::AddImmediate { dest, .. }
                    if anchor == table_base
                        && dest == table_base
                        && anchor_definition_index == table_add_index =>
                {
                    (table_add_index, table_va)
                }
                SwitchInsn::Other
                | SwitchInsn::Nop
                | SwitchInsn::CmpImmediate { .. }
                | SwitchInsn::ConditionalBranch { .. }
                | SwitchInsn::DirectBranch { .. }
                | SwitchInsn::Adrp { .. }
                | SwitchInsn::Adr { .. }
                | SwitchInsn::IndexedLoad { .. }
                | SwitchInsn::AddExtended { .. }
                | SwitchInsn::ShiftedAdd { .. }
                | SwitchInsn::IndirectBranch { .. }
                | SwitchInsn::SelectorAdjustment { .. }
                | SwitchInsn::RegisterCopy { .. }
                | SwitchInsn::AddImmediate { .. } => return None,
            };
            let required: BTreeSet<usize> = BTreeSet::from([
                table_page_index,
                table_add_index,
                offset_load_index,
                anchor_index,
                target_definition_index,
            ]);
            SwitchSetup {
                table_base,
                index,
                load_index: offset_load_index,
                table_va,
                target_mode: SwitchTargetMode::Relative {
                    anchor: anchor_va,
                    element_size,
                    signed,
                    scale,
                },
                relative_aliases: Some((anchor, offset)),
                required_indices: required,
            }
        }
        SwitchInsn::ShiftedAdd {
            dest,
            anchor,
            offset,
            scale,
        } if dest == target => {
            let (offset_load_index, offset_load): (usize, SwitchInsn) =
                single_definition(decoded, target_definition_index, offset)?;
            let SwitchInsn::IndexedLoad {
                dest: load_dest,
                base: table_base,
                index,
                encoding: SwitchTableEncoding::Relative(load_kind),
            } = offset_load
            else {
                return None;
            };
            if load_dest != offset
                || target == index
                || anchor == index
                || offset == index
                || table_base == index
            {
                return None;
            }
            let (element_size, signed): (usize, bool) = load_kind.natural()?;
            let (anchor_definition_index, anchor_definition): (usize, SwitchInsn) =
                single_definition(decoded, target_definition_index, anchor)?;
            let (table_page_index, table_add_index, table_va): (usize, usize, u64) =
                switch_table_address(decoded, offset_load_index, table_base)?;
            let (anchor_index, anchor_va): (usize, u64) = match anchor_definition {
                SwitchInsn::Adr {
                    dest: anchor_dest,
                    target: anchor_va,
                } if anchor_dest == anchor => (anchor_definition_index, anchor_va),
                SwitchInsn::AddImmediate { dest, .. }
                    if anchor == table_base
                        && dest == table_base
                        && anchor_definition_index == table_add_index =>
                {
                    (table_add_index, table_va)
                }
                SwitchInsn::Other
                | SwitchInsn::Nop
                | SwitchInsn::CmpImmediate { .. }
                | SwitchInsn::ConditionalBranch { .. }
                | SwitchInsn::DirectBranch { .. }
                | SwitchInsn::Adrp { .. }
                | SwitchInsn::Adr { .. }
                | SwitchInsn::IndexedLoad { .. }
                | SwitchInsn::AddExtended { .. }
                | SwitchInsn::ShiftedAdd { .. }
                | SwitchInsn::IndirectBranch { .. }
                | SwitchInsn::SelectorAdjustment { .. }
                | SwitchInsn::RegisterCopy { .. }
                | SwitchInsn::AddImmediate { .. } => return None,
            };
            let required: BTreeSet<usize> = BTreeSet::from([
                table_page_index,
                table_add_index,
                offset_load_index,
                anchor_index,
                target_definition_index,
            ]);
            SwitchSetup {
                table_base,
                index,
                load_index: offset_load_index,
                table_va,
                target_mode: SwitchTargetMode::Relative {
                    anchor: anchor_va,
                    element_size,
                    signed,
                    scale,
                },
                relative_aliases: Some((anchor, offset)),
                required_indices: required,
            }
        }
        SwitchInsn::IndexedLoad {
            dest,
            base: table_base,
            index,
            encoding: SwitchTableEncoding::Absolute64,
        } if dest == target => {
            if target == index || table_base == index {
                return None;
            }
            let (table_page_index, table_add_index, table_va): (usize, usize, u64) =
                switch_table_address(decoded, target_definition_index, table_base)?;
            let required: BTreeSet<usize> =
                BTreeSet::from([table_page_index, table_add_index, target_definition_index]);
            SwitchSetup {
                table_base,
                index,
                load_index: target_definition_index,
                table_va,
                target_mode: SwitchTargetMode::Absolute64,
                relative_aliases: None,
                required_indices: required,
            }
        }
        SwitchInsn::Other
        | SwitchInsn::Nop
        | SwitchInsn::CmpImmediate { .. }
        | SwitchInsn::ConditionalBranch { .. }
        | SwitchInsn::DirectBranch { .. }
        | SwitchInsn::Adrp { .. }
        | SwitchInsn::AddImmediate { .. }
        | SwitchInsn::IndexedLoad { .. }
        | SwitchInsn::Adr { .. }
        | SwitchInsn::AddExtended { .. }
        | SwitchInsn::ShiftedAdd { .. }
        | SwitchInsn::IndirectBranch { .. }
        | SwitchInsn::SelectorAdjustment { .. }
        | SwitchInsn::RegisterCopy { .. } => return None,
    };
    let SwitchSetup {
        table_base,
        index,
        load_index,
        table_va,
        target_mode,
        relative_aliases,
        mut required_indices,
    } = setup;
    let (selector_source, selector_copy_index): (u8, Option<usize>) =
        match single_definition(decoded, load_index, index) {
            Some((copy_index, SwitchInsn::RegisterCopy { dest, source })) if dest == index => {
                (source, Some(copy_index))
            }
            _ => (index, None),
        };
    let (guard_index, limit, default_va, exclusive): (usize, u16, u64, bool) =
        matching_switch_guard(decoded, branch_index, selector_source)?;
    if !switch_guard_target_is_outside_dispatch(insns, guard_index, branch_index, default_va) {
        return None;
    }
    if let Some(copy_index) = selector_copy_index
        && copy_index <= guard_index
    {
        return None;
    }
    let cmp_index: usize = guard_index.checked_sub(1)?;
    let (case_min, disc, selector_index, normalizer_index): (i64, RegRef, u8, Option<usize>) =
        switch_case_minimum(decoded, cmp_index, selector_source)?;
    if target == selector_index
        || table_base == selector_index
        || relative_aliases.is_some_and(|(anchor, offset): (u8, u8)| {
            anchor == selector_index || offset == selector_index
        })
        || matches!(target_mode, SwitchTargetMode::Absolute64) && normalizer_index.is_none()
    {
        return None;
    }
    if required_indices
        .iter()
        .any(|instruction: &usize| *instruction <= guard_index)
    {
        return None;
    }
    required_indices.insert(cmp_index);
    required_indices.insert(guard_index);
    required_indices.insert(branch_index);
    if let Some(normalizer_index) = normalizer_index {
        required_indices.insert(normalizer_index);
    }
    if let Some(selector_copy_index) = selector_copy_index {
        required_indices.insert(selector_copy_index);
    }
    if !switch_slice_is_safe(decoded, guard_index, branch_index, &required_indices)
        || has_alternate_dispatch_entry(decoded, insns, guard_index, branch_index)
    {
        return None;
    }
    let count: usize = if exclusive {
        usize::from(limit)
    } else {
        usize::from(limit).checked_add(1)?
    };
    if count == 0 || count > MAX_SWITCH_CASES {
        return None;
    }
    let targets: Vec<u64> = resolve_switch_targets(
        image,
        insns,
        base,
        machine_code_len,
        table_va,
        count,
        default_va,
        target_mode,
    )?;
    let mut cases: Vec<(i64, u64)> = Vec::with_capacity(count);
    for (entry, target_va) in targets.into_iter().enumerate() {
        let case_value: i64 = case_min.checked_add(i64::try_from(entry).ok()?)?;
        cases.push((case_value, target_va));
    }
    Some(SwitchDispatch {
        ignored_instructions: required_indices,
        disc,
        cases,
        default: default_va,
    })
}

fn switch_table_address(
    decoded: &[SwitchInsn],
    load_index: usize,
    table_base: u8,
) -> Option<(usize, usize, u64)> {
    let (table_definition_index, table_definition): (usize, SwitchInsn) =
        single_definition(decoded, load_index, table_base)?;
    match table_definition {
        SwitchInsn::Adr { dest, target } if dest == table_base => {
            Some((table_definition_index, table_definition_index, target))
        }
        SwitchInsn::AddImmediate {
            dest: table_add_dest,
            lhs: table_page,
            immediate,
        } if table_add_dest == table_base && table_page == table_base => {
            let (table_page_index, table_page_definition): (usize, SwitchInsn) =
                single_definition(decoded, table_definition_index, table_page)?;
            let SwitchInsn::Adrp {
                dest: table_page_dest,
                target: table_page_va,
            } = table_page_definition
            else {
                return None;
            };
            if table_page_dest != table_page {
                return None;
            }
            let table_va: u64 = table_page_va.checked_add(u64::from(immediate))?;
            Some((table_page_index, table_definition_index, table_va))
        }
        _ => None,
    }
}

fn recover_pc_relative_address_folds(
    insns: &[DisasmInsn],
) -> BTreeMap<usize, PcRelativeAddressFold> {
    let decoded: Vec<SwitchInsn> = insns.iter().map(decode_switch_instruction).collect();
    let block_leaders: Vec<bool> = basic_block_leaders(insns, &decoded);
    let mut folds: BTreeMap<usize, PcRelativeAddressFold> = BTreeMap::new();
    for (index, instruction) in decoded.iter().copied().enumerate() {
        let SwitchInsn::AddImmediate {
            dest,
            lhs,
            immediate,
        } = instruction
        else {
            continue;
        };
        if dest > 29 || lhs > 29 {
            continue;
        }
        let Some((
            page_index,
            SwitchInsn::Adrp {
                dest: page_dest,
                target,
            },
        )) = single_block_definition(&decoded, &block_leaders, index, lhs)
        else {
            continue;
        };
        if page_dest != lhs {
            continue;
        }
        let Some(target) = target.checked_add(u64::from(immediate)) else {
            continue;
        };
        folds.insert(
            index,
            PcRelativeAddressFold {
                page_index,
                dest,
                source: lhs,
                target,
            },
        );
    }
    folds
}

fn basic_block_leaders(insns: &[DisasmInsn], decoded: &[SwitchInsn]) -> Vec<bool> {
    let mut leaders: Vec<bool> = vec![false; decoded.len()];
    if let Some(first) = leaders.first_mut() {
        *first = true;
    }
    for (index, instruction) in decoded.iter().copied().enumerate() {
        let target: Option<u64> = match instruction {
            SwitchInsn::ConditionalBranch { target, .. } | SwitchInsn::DirectBranch { target } => {
                if let Some(next) = leaders.get_mut(index.saturating_add(1)) {
                    *next = true;
                }
                Some(target)
            }
            _ => None,
        };
        let Some(target) = target else {
            continue;
        };
        if let Ok(target_index) = insns.binary_search_by_key(&target, |insn| insn.address)
            && let Some(leader) = leaders.get_mut(target_index)
        {
            *leader = true;
        }
    }
    leaders
}

fn single_block_definition(
    decoded: &[SwitchInsn],
    block_leaders: &[bool],
    before: usize,
    register: u8,
) -> Option<(usize, SwitchInsn)> {
    let bounded_start: usize = before.saturating_sub(MAX_SWITCH_SLICE_INSTRUCTIONS);
    let block_start: usize = (bounded_start..=before)
        .rev()
        .find(|index| block_leaders.get(*index).copied().unwrap_or(false))?;
    for index in (block_start..before).rev() {
        let instruction: SwitchInsn = *decoded.get(index)?;
        if instruction.defines(register) {
            return Some((index, instruction));
        }
        if matches!(instruction, SwitchInsn::Other) {
            return None;
        }
    }
    None
}

fn resolve_switch_targets(
    image: &ImageContext<'_, '_>,
    insns: &[DisasmInsn],
    base: u64,
    machine_code_len: usize,
    table_va: u64,
    count: usize,
    default_va: u64,
    target_mode: SwitchTargetMode,
) -> Option<Vec<u64>> {
    let element_size: usize = match target_mode {
        SwitchTargetMode::Relative { element_size, .. } => element_size,
        SwitchTargetMode::Absolute64 => 8,
    };
    let readable: &[u8] = readable_switch_table(image, table_va, count, element_size)?;
    let function_end: u64 = base.checked_add(u64::try_from(machine_code_len).ok()?)?;
    if !valid_switch_target(insns, base, function_end, default_va) {
        return None;
    }
    let mut targets: Vec<u64> = Vec::with_capacity(count);
    for entry in 0..count {
        let offset: usize = entry.checked_mul(element_size)?;
        let target_va: u64 = match target_mode {
            SwitchTargetMode::Relative {
                anchor,
                element_size,
                signed,
                scale,
            } => {
                let entry_value: i64 =
                    relative_switch_entry(readable, offset, element_size, signed)?;
                let multiplier: i64 = 1_i64.checked_shl(u32::from(scale))?;
                let displacement: i64 = entry_value.checked_mul(multiplier)?;
                anchor.checked_add_signed(displacement)?
            }
            SwitchTargetMode::Absolute64 => {
                let entry_end: usize = offset.checked_add(8)?;
                let entry_bytes: [u8; 8] = readable.get(offset..entry_end)?.try_into().ok()?;
                let file_target: u64 = u64::from_le_bytes(entry_bytes);
                let entry_va: u64 = table_va.checked_add(u64::try_from(offset).ok()?)?;
                (image.relocations)(entry_va)
                    .or_else(|| (file_target != 0).then_some(file_target))?
            }
        };
        if !valid_switch_target(insns, base, function_end, target_va) {
            return None;
        }
        targets.push(target_va);
    }
    Some(targets)
}

fn readable_switch_table<'image>(
    image: &ImageContext<'_, 'image>,
    table_va: u64,
    count: usize,
    element_size: usize,
) -> Option<&'image [u8]> {
    let table_bytes: usize = count.checked_mul(element_size)?;
    if table_bytes > MAX_SWITCH_TABLE_BYTES {
        return None;
    }
    let _table_end: u64 = table_va.checked_add(u64::try_from(table_bytes).ok()?)?;
    let readable: &'image [u8] = (image.image)(table_va)?;
    readable.get(..table_bytes)
}

fn relative_switch_entry(
    readable: &[u8],
    offset: usize,
    element_size: usize,
    signed: bool,
) -> Option<i64> {
    match (element_size, signed) {
        (1, true) => Some(i64::from(i8::from_ne_bytes([*readable.get(offset)?]))),
        (1, false) => Some(i64::from(*readable.get(offset)?)),
        (2, true) => {
            let end: usize = offset.checked_add(2)?;
            let bytes: [u8; 2] = readable.get(offset..end)?.try_into().ok()?;
            Some(i64::from(i16::from_le_bytes(bytes)))
        }
        (2, false) => {
            let end: usize = offset.checked_add(2)?;
            let bytes: [u8; 2] = readable.get(offset..end)?.try_into().ok()?;
            Some(i64::from(u16::from_le_bytes(bytes)))
        }
        (4, true) => {
            let end: usize = offset.checked_add(4)?;
            let bytes: [u8; 4] = readable.get(offset..end)?.try_into().ok()?;
            Some(i64::from(i32::from_le_bytes(bytes)))
        }
        (4, false) => {
            let end: usize = offset.checked_add(4)?;
            let bytes: [u8; 4] = readable.get(offset..end)?.try_into().ok()?;
            Some(i64::from(u32::from_le_bytes(bytes)))
        }
        (0 | 3 | 5.., _) => None,
    }
}

fn single_definition(
    decoded: &[SwitchInsn],
    before: usize,
    register: u8,
) -> Option<(usize, SwitchInsn)> {
    let start: usize = before.saturating_sub(MAX_SWITCH_SLICE_INSTRUCTIONS);
    for index in (start..before).rev() {
        let instruction: SwitchInsn = *decoded.get(index)?;
        if instruction.defines(register) {
            return Some((index, instruction));
        }
        if matches!(instruction, SwitchInsn::Other) {
            return None;
        }
    }
    None
}

fn matching_switch_guard(
    decoded: &[SwitchInsn],
    branch_index: usize,
    index: u8,
) -> Option<(usize, u16, u64, bool)> {
    let start: usize = branch_index.saturating_sub(MAX_SWITCH_SLICE_INSTRUCTIONS);
    for guard_index in (start..branch_index).rev() {
        let SwitchInsn::ConditionalBranch { condition, target } = *decoded.get(guard_index)? else {
            continue;
        };
        let exclusive: bool = match condition {
            8 => false,
            2 => true,
            _ => continue,
        };
        let Some(SwitchInsn::CmpImmediate {
            index: cmp_index,
            limit,
        }) = guard_index
            .checked_sub(1)
            .and_then(|cmp_index: usize| decoded.get(cmp_index))
        else {
            continue;
        };
        if *cmp_index == index {
            return Some((guard_index, *limit, target, exclusive));
        }
    }
    None
}

fn switch_slice_is_safe(
    decoded: &[SwitchInsn],
    guard_index: usize,
    branch_index: usize,
    required: &BTreeSet<usize>,
) -> bool {
    let Some(start): Option<usize> = guard_index.checked_add(1) else {
        return false;
    };
    for index in start..branch_index {
        if required.contains(&index) || matches!(decoded.get(index), Some(SwitchInsn::Nop)) {
            continue;
        }
        return false;
    }
    true
}

fn has_alternate_dispatch_entry(
    decoded: &[SwitchInsn],
    insns: &[DisasmInsn],
    guard_index: usize,
    branch_index: usize,
) -> bool {
    let Some(dispatch_index): Option<usize> = guard_index.checked_add(1) else {
        return true;
    };
    let dispatch_start: u64 = match insns.get(dispatch_index) {
        Some(insn) => insn.address,
        None => return true,
    };
    let dispatch_end: u64 = match insns.get(branch_index) {
        Some(insn) => insn.address,
        None => return true,
    };
    for (index, instruction) in decoded.iter().enumerate() {
        let target: Option<u64> = match instruction {
            SwitchInsn::ConditionalBranch { target, .. } | SwitchInsn::DirectBranch { target } => {
                Some(*target)
            }
            _ => None,
        };
        if index != guard_index
            && target
                .is_some_and(|address: u64| address >= dispatch_start && address <= dispatch_end)
        {
            return true;
        }
    }
    false
}

fn switch_guard_target_is_outside_dispatch(
    insns: &[DisasmInsn],
    guard_index: usize,
    branch_index: usize,
    target: u64,
) -> bool {
    let Some(dispatch_index): Option<usize> = guard_index.checked_add(1) else {
        return false;
    };
    let Some(dispatch_start): Option<u64> = insns
        .get(dispatch_index)
        .map(|insn: &DisasmInsn| insn.address)
    else {
        return false;
    };
    let Some(dispatch_end): Option<u64> = insns
        .get(branch_index)
        .map(|insn: &DisasmInsn| insn.address)
    else {
        return false;
    };
    target < dispatch_start || target > dispatch_end
}

fn switch_case_minimum(
    decoded: &[SwitchInsn],
    cmp_index: usize,
    normalized_index: u8,
) -> Option<(i64, RegRef, u8, Option<usize>)> {
    let disc: RegRef = aarch64_switch_register(normalized_index)?;
    let Some((definition_index, definition)): Option<(usize, SwitchInsn)> =
        single_definition(decoded, cmp_index, normalized_index)
    else {
        return Some((0, disc, normalized_index, None));
    };
    let SwitchInsn::SelectorAdjustment {
        dest,
        source,
        case_minimum,
    } = definition
    else {
        return Some((0, disc, normalized_index, None));
    };
    if dest != normalized_index {
        return None;
    }
    if !decoded
        .get(definition_index.checked_add(1)?..cmp_index)?
        .iter()
        .all(|instruction: &SwitchInsn| matches!(instruction, SwitchInsn::Nop))
    {
        return None;
    }
    Some((
        case_minimum,
        aarch64_switch_register(source)?,
        source,
        Some(definition_index),
    ))
}

fn valid_switch_target(insns: &[DisasmInsn], start: u64, end: u64, target: u64) -> bool {
    target.is_multiple_of(4)
        && target >= start
        && target < end
        && insns
            .binary_search_by_key(&target, |insn: &DisasmInsn| insn.address)
            .is_ok()
}

fn normalized_switch_target(insns: &[DisasmInsn], base: u64, target: u64) -> Result<u64> {
    let index: usize = insns
        .binary_search_by_key(&target, |insn: &DisasmInsn| insn.address)
        .map_err(|_| reject("switch target is outside the decoded function"))?;
    item_address(base, index, 0)
}

fn decode_switch_instruction(insn: &DisasmInsn) -> SwitchInsn {
    let Some(word): Option<u32> = aarch64_instruction_word(insn) else {
        return SwitchInsn::Other;
    };
    if word == 0xd503_201f {
        return SwitchInsn::Nop;
    }
    if word & 0xffc0_001f == 0x7100_001f {
        return SwitchInsn::CmpImmediate {
            index: register_field(word, 5),
            limit: immediate_field(word, 10, 12) as u16,
        };
    }
    match aarch64_direct_transfer(insn.address, word) {
        Some(Aarch64DirectTransfer::ConditionalBranch { condition, target }) => {
            return SwitchInsn::ConditionalBranch { condition, target };
        }
        Some(
            Aarch64DirectTransfer::UnconditionalBranch { target }
            | Aarch64DirectTransfer::CompareBranch { target }
            | Aarch64DirectTransfer::TestBranch { target },
        ) => {
            return SwitchInsn::DirectBranch { target };
        }
        Some(Aarch64DirectTransfer::BranchLink { .. }) | None => {}
    }
    if word & 0x9f00_0000 == 0x9000_0000 {
        let Some(target): Option<u64> = aarch64_adrp_target(insn.address, word) else {
            return SwitchInsn::Other;
        };
        return SwitchInsn::Adrp {
            dest: register_field(word, 0),
            target,
        };
    }
    if word & 0xffc0_0000 == 0x9100_0000 {
        return SwitchInsn::AddImmediate {
            dest: register_field(word, 0),
            lhs: register_field(word, 5),
            immediate: immediate_field(word, 10, 12) as u16,
        };
    }
    if word & 0xffe0_dc00 == 0x3860_4800 {
        return SwitchInsn::IndexedLoad {
            dest: register_field(word, 0),
            base: register_field(word, 5),
            index: register_field(word, 16),
            encoding: SwitchTableEncoding::Relative(RelativeLoadKind::ByteUnsigned),
        };
    }
    if word & 0xffe0_dc00 == 0x38e0_4800 {
        return SwitchInsn::IndexedLoad {
            dest: register_field(word, 0),
            base: register_field(word, 5),
            index: register_field(word, 16),
            encoding: SwitchTableEncoding::Relative(RelativeLoadKind::ByteSigned),
        };
    }
    if word & 0xffe0_dc00 == 0x7860_5800 {
        return SwitchInsn::IndexedLoad {
            dest: register_field(word, 0),
            base: register_field(word, 5),
            index: register_field(word, 16),
            encoding: SwitchTableEncoding::Relative(RelativeLoadKind::HalfwordUnsigned),
        };
    }
    if word & 0xffe0_dc00 == 0x78e0_5800 {
        return SwitchInsn::IndexedLoad {
            dest: register_field(word, 0),
            base: register_field(word, 5),
            index: register_field(word, 16),
            encoding: SwitchTableEncoding::Relative(RelativeLoadKind::HalfwordSigned),
        };
    }
    if word & 0xffe0_dc00 == 0xb8a0_5800 {
        return SwitchInsn::IndexedLoad {
            dest: register_field(word, 0),
            base: register_field(word, 5),
            index: register_field(word, 16),
            encoding: SwitchTableEncoding::Relative(RelativeLoadKind::WordSigned),
        };
    }
    if word & 0xffe0_fc00 == 0xf860_7800 {
        return SwitchInsn::IndexedLoad {
            dest: register_field(word, 0),
            base: register_field(word, 5),
            index: register_field(word, 16),
            encoding: SwitchTableEncoding::Absolute64,
        };
    }
    if word & 0x9f00_0000 == 0x1000_0000 {
        let Some(target): Option<u64> = aarch64_adr_target(insn.address, word) else {
            return SwitchInsn::Other;
        };
        return SwitchInsn::Adr {
            dest: register_field(word, 0),
            target,
        };
    }
    let extension: Option<SwitchAddExtend> = match word & 0xffe0_e000 {
        0x8b20_0000 => Some(SwitchAddExtend::ByteUnsigned),
        0x8b20_2000 => Some(SwitchAddExtend::HalfwordUnsigned),
        0x8b20_4000 => Some(SwitchAddExtend::WordUnsigned),
        0x8b20_8000 => Some(SwitchAddExtend::ByteSigned),
        0x8b20_a000 => Some(SwitchAddExtend::HalfwordSigned),
        0x8b20_c000 => Some(SwitchAddExtend::WordSigned),
        _ => None,
    };
    if let Some(extension) = extension {
        let scale: u8 = immediate_field(word, 10, 3) as u8;
        if scale > 4 {
            return SwitchInsn::Other;
        }
        return SwitchInsn::AddExtended {
            dest: register_field(word, 0),
            anchor: register_field(word, 5),
            offset: register_field(word, 16),
            extension,
            scale,
        };
    }
    if word & 0xffe0_0000 == 0x8b00_0000 {
        let scale: u8 = immediate_field(word, 10, 6) as u8;
        if scale > 4 {
            return SwitchInsn::Other;
        }
        return SwitchInsn::ShiftedAdd {
            dest: register_field(word, 0),
            anchor: register_field(word, 5),
            offset: register_field(word, 16),
            scale,
        };
    }
    if word & 0xffff_fc1f == 0xd61f_0000 {
        return SwitchInsn::IndirectBranch {
            target: register_field(word, 5),
        };
    }
    if word & 0x8000_0000 == 0 && word & 0x5fc0_0000 == 0x1100_0000 {
        return SwitchInsn::SelectorAdjustment {
            dest: register_field(word, 0),
            source: register_field(word, 5),
            case_minimum: -i64::from(immediate_field(word, 10, 12)),
        };
    }
    if word & 0x8000_0000 == 0 && word & 0x5fc0_0000 == 0x5100_0000 {
        return SwitchInsn::SelectorAdjustment {
            dest: register_field(word, 0),
            source: register_field(word, 5),
            case_minimum: i64::from(immediate_field(word, 10, 12)),
        };
    }
    if word & 0x7fe0_ffe0 == 0x2a00_03e0 {
        return SwitchInsn::RegisterCopy {
            dest: register_field(word, 0),
            source: register_field(word, 16),
        };
    }
    SwitchInsn::Other
}

fn aarch64_instruction_word(insn: &DisasmInsn) -> Option<u32> {
    aarch64_word(&insn.bytes)
}

fn aarch64_relative_target(address: u64, word: u32, shift: u8, bits: u8) -> Option<u64> {
    let immediate: u32 = immediate_field(word, shift, bits);
    let delta: i64 = signed_immediate(immediate, bits).checked_mul(4)?;
    address.checked_add_signed(delta)
}

pub(crate) fn aarch64_direct_transfer(address: u64, word: u32) -> Option<Aarch64DirectTransfer> {
    if word & 0xfc00_0000 == 0x9400_0000 {
        let target: u64 = aarch64_relative_target(address, word, 0, 26)?;
        return Some(Aarch64DirectTransfer::BranchLink { target });
    }
    if word & 0xfc00_0000 == 0x1400_0000 {
        let target: u64 = aarch64_relative_target(address, word, 0, 26)?;
        return Some(Aarch64DirectTransfer::UnconditionalBranch { target });
    }
    if word & 0xff00_0010 == 0x5400_0000 {
        let target: u64 = aarch64_relative_target(address, word, 5, 19)?;
        let condition: u8 = u8::try_from(word & 0xf).ok()?;
        return Some(Aarch64DirectTransfer::ConditionalBranch { condition, target });
    }
    if word & 0x7e00_0000 == 0x3400_0000 {
        let target: u64 = aarch64_relative_target(address, word, 5, 19)?;
        return Some(Aarch64DirectTransfer::CompareBranch { target });
    }
    if word & 0x7e00_0000 == 0x3600_0000 {
        let target: u64 = aarch64_relative_target(address, word, 5, 14)?;
        return Some(Aarch64DirectTransfer::TestBranch { target });
    }
    None
}

pub(crate) fn aarch64_adr_target(address: u64, word: u32) -> Option<u64> {
    let immediate: u32 = aarch64_adr_immediate(word);
    address.checked_add_signed(signed_immediate(immediate, 21))
}

pub(crate) fn aarch64_adrp_target(address: u64, word: u32) -> Option<u64> {
    let immediate: u32 = aarch64_adr_immediate(word);
    let delta: i64 = signed_immediate(immediate, 21).checked_mul(4096)?;
    (address & !0xfff).checked_add_signed(delta)
}

fn aarch64_adr_immediate(word: u32) -> u32 {
    let high: u32 = immediate_field(word, 5, 19);
    let low: u32 = immediate_field(word, 29, 2);
    high << 2 | low
}

pub(crate) fn immediate_field(word: u32, shift: u8, width: u8) -> u32 {
    let mask: u32 = (1_u32.checked_shl(u32::from(width)).unwrap_or(0)).wrapping_sub(1);
    word.checked_shr(u32::from(shift)).unwrap_or(0) & mask
}

pub(crate) fn register_field(word: u32, shift: u8) -> u8 {
    immediate_field(word, shift, 5) as u8
}

pub(crate) fn signed_immediate(value: u32, bits: u8) -> i64 {
    let shift: u32 = 64_u32.saturating_sub(u32::from(bits));
    (i64::from(value) << shift) >> shift
}

fn aarch64_switch_register(number: u8) -> Option<RegRef> {
    let reg: Reg = match number {
        0 => Reg::Rax,
        1 => Reg::A64X1,
        2 => Reg::A64X2,
        3 => Reg::A64X3,
        4 => Reg::A64X4,
        5 => Reg::A64X5,
        6 => Reg::A64X6,
        7 => Reg::A64X7,
        8 => Reg::A64X8,
        9 => Reg::A64X9,
        10 => Reg::A64X10,
        11 => Reg::A64X11,
        12 => Reg::A64X12,
        13 => Reg::A64X13,
        14 => Reg::A64X14,
        15 => Reg::A64X15,
        16 => Reg::A64X16,
        17 => Reg::A64X17,
        18 => Reg::A64X18,
        19 => Reg::A64X19,
        20 => Reg::A64X20,
        21 => Reg::A64X21,
        22 => Reg::A64X22,
        23 => Reg::A64X23,
        24 => Reg::A64X24,
        25 => Reg::A64X25,
        26 => Reg::A64X26,
        27 => Reg::A64X27,
        28 => Reg::A64X28,
        29 => Reg::Rbp,
        _ => return None,
    };
    Some(RegRef {
        reg,
        width: Width::W32,
    })
}

fn block_contains_switch(body: &[Node]) -> bool {
    body.iter().any(|node: &Node| match node {
        Node::If {
            then_body,
            else_body,
            ..
        } => {
            block_contains_switch(then_body)
                || else_body
                    .as_ref()
                    .is_some_and(|else_body: &Vec<Node>| block_contains_switch(else_body))
        }
        Node::DoWhile { body, .. } | Node::While { body, .. } => block_contains_switch(body),
        Node::Switch { .. } => true,
        Node::Stmt(_)
        | Node::CondSnapshot { .. }
        | Node::Break
        | Node::Continue
        | Node::BreakLoop(_)
        | Node::ContinueLoop(_)
        | Node::ResumeAt(_)
        | Node::OuterResume(_)
        | Node::Return
        | Node::Label(_)
        | Node::Goto(_) => false,
    })
}

fn aarch64_fp_params(body: &Block) -> Result<Vec<(Xmm, FpWidth)>> {
    let inferred: Vec<(Xmm, FpWidth)> = infer_fp_params(body, Abi::Aapcs64)?;
    let Some(highest): Option<usize> = inferred
        .iter()
        .map(|(register, _): &(Xmm, FpWidth)| usize::from(register.index()))
        .max()
    else {
        return Ok(Vec::new());
    };
    let mut params: Vec<(Xmm, FpWidth)> = Vec::with_capacity(highest + 1);
    for register in FP_ARG_ORDER.iter().copied().take(highest + 1) {
        let width: FpWidth = inferred
            .iter()
            .find(|(candidate, _): &&(Xmm, FpWidth)| *candidate == register)
            .map_or(FpWidth::F64, |(_, width): &(Xmm, FpWidth)| *width);
        params.push((register, width));
    }
    Ok(params)
}

fn finish(
    insns: &[DisasmInsn],
    items: &mut Vec<Item>,
    base: u64,
    flag_definitions: &BTreeMap<usize, TrackedFlags>,
    return_width: Width,
    context: FinishContext<'_>,
    next_sel: &mut u32,
) -> Result<LeafRecovery> {
    super::idiom::fuse_constant_division_idioms(items);
    let has_scalar_fp: bool = items
        .iter()
        .any(|item: &Item| matches!(&item.kind, ItemKind::Stmt(stmt) if return_channel::stmt_is_scalar_fp(stmt)));
    let mut structured: Structured =
        match aarch64_cfg::structure(items, insns, base, flag_definitions, next_sel) {
            aarch64_cfg::Attempt::Structured(structured) => structured,
            aarch64_cfg::Attempt::NotCandidate => structure_items(items)?,
            aarch64_cfg::Attempt::RejectedNzcv => {
                let _: Structured = structure_items(items)?;
                return Err(reject("conditional branch lacks live nzcv state"));
            }
        };
    if !context.calls.is_empty() {
        let call_map: BTreeMap<u64, &ResolvedCall> = context
            .calls
            .iter()
            .map(|call: &ResolvedCall| (call.target, call))
            .collect();
        annotate_calls_block_with_abi(&mut structured.body, &call_map, Abi::Aapcs64)?;
    }
    let lifted_switch: bool = block_contains_switch(&structured.body);
    let fp_args: Vec<(Xmm, FpWidth)> = if has_scalar_fp {
        aarch64_fp_params(&structured.body)?
    } else {
        Vec::new()
    };
    let ret: FnReturn = if has_scalar_fp {
        return_channel::infer_scalar_return(&structured.body)?
    } else {
        match context.vec_abi.ret {
            VectorRet::Vector(arr) => FnReturn::Vec(arr),
            VectorRet::Void => FnReturn::Void,
            VectorRet::None => FnReturn::Int(return_width),
        }
    };
    let sret_plan: Option<SretPlan> = match ret {
        FnReturn::Int(_) => detect_sret(&structured.body, Abi::Aapcs64),
        FnReturn::Fp(_) | FnReturn::Void | FnReturn::Vec(_) => None,
    };
    let mut params: Vec<Reg> = infer_params(&structured.body, Abi::Aapcs64)?;
    if let Some(plan) = &sret_plan {
        params.retain(|reg: &Reg| *reg != plan.ptr);
    }
    let signature: FnSignature = FnSignature {
        fp: fp_args,
        int: super::wide_int_signature(&params),
        vec: context.vec_abi.params.clone(),
        ret,
        exact_integer_types: false,
        abi: Abi::Aapcs64,
    };
    let frame_shape: FrameShape = classify_frame(insns, context.frame_info)?;
    let frame = plan_frame(&structured.body, frame_shape)?;
    let aggregate_plan: AggregatePlan =
        infer_aggregate_plan(&structured.body, &params, frame.as_ref());
    let emitted: Block = super::spilled_body(
        &structured.body,
        frame.as_ref(),
        sret_plan.as_ref(),
        &aggregate_plan,
    );
    let source: String = emit_c(
        &emitted,
        &signature,
        frame.as_ref(),
        sret_plan.as_ref(),
        &aggregate_plan,
    )?;
    let rust_source: Option<String> = emit_rust(
        &emitted,
        &signature,
        frame.as_ref(),
        sret_plan.as_ref(),
        &aggregate_plan,
    );
    let mut call_targets: Vec<u64> = Vec::new();
    collect_call_targets(&structured.body, &mut call_targets);
    crate::debug::dbg_kv("aarch64_lifted_instructions", || insns.len().to_string());
    let return_width_bits: u32 = match ret {
        FnReturn::Vec(arr) => arr.total_bits(),
        FnReturn::Void => 0,
        FnReturn::Int(width) => width.bits(),
        FnReturn::Fp(FpWidth::F16) => 16,
        FnReturn::Fp(FpWidth::F32) => 32,
        FnReturn::Fp(FpWidth::F64) => 64,
    };
    let returns_fp: Option<ScalarType> = match ret {
        FnReturn::Fp(FpWidth::F16) => Some(ScalarType::Half),
        FnReturn::Fp(FpWidth::F32) => Some(ScalarType::Float),
        FnReturn::Fp(FpWidth::F64) => Some(ScalarType::Double),
        FnReturn::Int(_) | FnReturn::Void | FnReturn::Vec(_) => None,
    };
    Ok(LeafRecovery {
        source,
        rust_source,
        return_width_bits,
        signature: RecoveredSignature::from_canonical_bindings(
            signature.abi,
            signature.parameter_bindings(),
        ),
        returns_fp,
        lifted_split_return: structured.lifted_split_return,
        lifted_loop: structured.lifted_loop,
        lifted_switch,
        call_targets,
        sret: sret_plan.as_ref().map(|plan: &SretPlan| SretReturn {
            field_widths: plan
                .fields
                .iter()
                .map(|(_, width): &(i64, Width)| width.bits() / 8)
                .collect(),
            size: plan.size,
        }),
        call_site_signature: None,
    })
}

fn lower_alu(insn: &DisasmInsn) -> Result<(RegRef, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if !(3..=4).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed integer alu instruction"));
    }
    let dest: RegRef = parse_reg(operands[0])?;
    let lhs: RegRef = parse_reg(operands[1])?;
    let is_widening_mul: bool = matches!(insn.mnemonic.as_str(), "umull" | "smull");
    if is_widening_mul {
        if dest.width != Width::W64 || lhs.width != Width::W32 {
            return Err(reject_at(insn, "widening multiply is not w32 into x64"));
        }
    } else if dest.width != lhs.width {
        return Err(reject_at(insn, "mixed-width integer alu instruction"));
    }
    if matches!(insn.mnemonic.as_str(), "umulh" | "smulh") && dest.width != Width::W64 {
        return Err(reject_at(
            insn,
            "high-half multiply requires 64-bit operands",
        ));
    }
    let (op, negate_rhs): (BinOp, bool) = match insn.mnemonic.as_str() {
        "add" | "adds" => (BinOp::Add, false),
        "sub" | "subs" => (BinOp::Sub, false),
        "and" => (BinOp::And, false),
        "orr" => (BinOp::Or, false),
        "eor" => (BinOp::Xor, false),
        "bic" => (BinOp::And, true),
        "orn" => (BinOp::Or, true),
        "eon" => (BinOp::Xor, true),
        "lsl" => (BinOp::Shl, false),
        "lsr" => (BinOp::Shr, false),
        "asr" => (BinOp::Sar, false),
        "mul" => (BinOp::Imul, false),
        "sdiv" => (BinOp::Sdiv, false),
        "udiv" => (BinOp::Udiv, false),
        "umull" => (BinOp::Umull, false),
        "smull" => (BinOp::Smull, false),
        "umulh" => (BinOp::Umulh, false),
        "smulh" => (BinOp::Smulh, false),
        _ => return Err(reject_at(insn, "unsupported integer alu instruction")),
    };
    let mut prefix: Vec<Stmt> = Vec::new();
    let rhs_width: Width = if is_widening_mul {
        Width::W32
    } else {
        dest.width
    };
    let encoded_extend: Option<(bool, Width, i64)> = if dest.width == Width::W64 {
        encoded_extended_register(insn)
    } else {
        None
    };
    let extend: Option<(bool, Width, i64)> = encoded_extend.or_else(|| {
        if operands.len() == 4 {
            parse_extend_modifier(operands[3])
        } else {
            None
        }
    });
    let mut rhs: Source = if let Some((signed, src_width, shift)) = extend {
        let src_reg: RegRef = parse_reg(operands[2])?;
        let expected_class: Width = extend_register_class(src_width);
        if src_reg.width != expected_class {
            let reason: &str = if expected_class == Width::W64 {
                "extended register operand requires a 64-bit source register"
            } else {
                "extended register operand requires a 32-bit source register"
            };
            return Err(reject_at(insn, reason));
        }
        let extend_source: RegRef = RegRef {
            reg: src_reg.reg,
            width: src_width,
        };
        let extended: RegRef = RegRef {
            reg: Reg::A64Tmp2,
            width: dest.width,
        };
        prefix.push(Stmt::Extend {
            dest: extended,
            src: ExtSource::Reg(extend_source),
            signed,
        });
        if shift > 0 {
            prefix.push(Stmt::BinAssign {
                dest: extended,
                op: BinOp::Shl,
                src: Source::Imm(shift),
            });
        }
        Source::Reg(extended)
    } else {
        let parsed: Source = parse_source(operands[2], rhs_width)?;
        if let Source::Reg(reg) = parsed
            && reg.width != rhs_width
        {
            return Err(reject_at(insn, "mixed-width integer alu source"));
        }
        if operands.len() == 4 {
            let Source::Reg(reg): Source = parsed else {
                return Err(reject_at(insn, "shift modifier requires a register source"));
            };
            let (shift_op, amount): (BinOp, i64) = parse_shift_modifier(operands[3], dest.width)?;
            let shifted: RegRef = RegRef {
                reg: Reg::A64Tmp2,
                width: dest.width,
            };
            prefix.push(Stmt::Assign {
                dest: shifted,
                src: Source::Reg(reg),
            });
            prefix.push(Stmt::BinAssign {
                dest: shifted,
                op: shift_op,
                src: Source::Imm(amount),
            });
            Source::Reg(shifted)
        } else {
            parsed
        }
    };
    if negate_rhs {
        rhs = match rhs {
            Source::Imm(value) => Source::Imm(!value),
            Source::Reg(reg) => {
                let scratch: RegRef = RegRef {
                    reg: Reg::A64Tmp2,
                    width: dest.width,
                };
                if reg.reg != Reg::A64Tmp2 {
                    prefix.push(Stmt::Assign {
                        dest: scratch,
                        src: Source::Reg(reg),
                    });
                }
                prefix.push(Stmt::UnAssign {
                    dest: scratch,
                    op: UnOp::Not,
                });
                Source::Reg(scratch)
            }
            Source::Lea { .. } | Source::Mem(_) => {
                return Err(reject_at(insn, "unsupported bit-clear source"));
            }
        };
    }
    prefix.extend(bin_from(dest, lhs, op, rhs));
    Ok((dest, prefix))
}

fn flag_arithmetic_operands(insn: &DisasmInsn) -> Result<(Vec<Stmt>, RegRef, Source)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if operands.len() != 3 {
        return Err(reject_at(
            insn,
            "flag-setting arithmetic has an unsupported modifier",
        ));
    }
    let lhs: RegRef = parse_reg(operands[1])?;
    let rhs: Source = parse_source(operands[2], lhs.width)?;
    let flag_lhs: RegRef = RegRef {
        reg: Reg::A64FlagLhs,
        width: lhs.width,
    };
    let flag_rhs: RegRef = RegRef {
        reg: Reg::A64FlagRhs,
        width: lhs.width,
    };
    let snapshots: Vec<Stmt> = vec![
        Stmt::Assign {
            dest: flag_lhs,
            src: Source::Reg(lhs),
        },
        Stmt::Assign {
            dest: flag_rhs,
            src: rhs,
        },
    ];
    Ok((snapshots, flag_lhs, Source::Reg(flag_rhs)))
}

fn subtract_flags(insn: &DisasmInsn) -> Result<(Vec<Stmt>, Flags)> {
    let (snapshots, lhs, rhs): (Vec<Stmt>, RegRef, Source) = flag_arithmetic_operands(insn)?;
    Ok((snapshots, Flags::Cmp { lhs, rhs }))
}

fn add_flags(insn: &DisasmInsn) -> Result<(Vec<Stmt>, Flags)> {
    let (snapshots, lhs, rhs): (Vec<Stmt>, RegRef, Source) = flag_arithmetic_operands(insn)?;
    Ok((snapshots, Flags::Add { lhs, rhs }))
}

fn lower_flag_setter(insn: &DisasmInsn) -> Result<(Vec<Stmt>, TrackedFlags)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if !(2..=3).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed flag-setting instruction"));
    }
    let lhs: RegRef = parse_reg(operands[0])?;
    let mut rhs: Source = parse_source(operands[1], lhs.width)?;
    let mut stmts: Vec<Stmt> = Vec::new();
    if operands.len() == 3 {
        let Source::Reg(reg): Source = rhs else {
            return Err(reject_at(insn, "flag shift modifier requires a register"));
        };
        let (op, amount): (BinOp, i64) = parse_shift_modifier(operands[2], lhs.width)?;
        let shifted: RegRef = RegRef {
            reg: Reg::A64Tmp2,
            width: lhs.width,
        };
        stmts.push(Stmt::Assign {
            dest: shifted,
            src: Source::Reg(reg),
        });
        stmts.push(Stmt::BinAssign {
            dest: shifted,
            op,
            src: Source::Imm(amount),
        });
        rhs = Source::Reg(shifted);
    }
    if insn.mnemonic == "cmp" {
        return Ok((
            stmts,
            TrackedFlags {
                value: Flags::Cmp { lhs, rhs },
                nz_only: false,
                mark: 0,
            },
        ));
    }
    let temp: RegRef = RegRef {
        reg: Reg::A64Tmp,
        width: lhs.width,
    };
    let op: BinOp = if insn.mnemonic == "cmn" {
        BinOp::Add
    } else {
        BinOp::And
    };
    stmts.push(Stmt::Assign {
        dest: temp,
        src: Source::Reg(lhs),
    });
    stmts.push(Stmt::BinAssign {
        dest: temp,
        op,
        src: rhs,
    });
    Ok((
        stmts,
        TrackedFlags {
            value: Flags::Test { operand: temp },
            nz_only: true,
            mark: 0,
        },
    ))
}

fn lower_multiply_accumulate(insn: &DisasmInsn) -> Result<(RegRef, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if operands.len() != 4 {
        return Err(reject_at(insn, "malformed multiply-accumulate instruction"));
    }
    let dest: RegRef = parse_reg(operands[0])?;
    let lhs: RegRef = parse_reg(operands[1])?;
    let rhs: RegRef = parse_reg(operands[2])?;
    let addend: RegRef = parse_reg(operands[3])?;
    if [lhs.width, rhs.width, addend.width]
        .into_iter()
        .any(|width: Width| width != dest.width)
    {
        return Err(reject_at(
            insn,
            "mixed-width multiply-accumulate instruction",
        ));
    }
    let temp: RegRef = RegRef {
        reg: Reg::A64Tmp,
        width: dest.width,
    };
    let final_op: BinOp = if insn.mnemonic == "madd" {
        BinOp::Add
    } else {
        BinOp::Sub
    };
    Ok((
        dest,
        vec![
            Stmt::Assign {
                dest: temp,
                src: Source::Reg(lhs),
            },
            Stmt::BinAssign {
                dest: temp,
                op: BinOp::Imul,
                src: Source::Reg(rhs),
            },
            Stmt::Assign {
                dest,
                src: Source::Reg(addend),
            },
            Stmt::BinAssign {
                dest,
                op: final_op,
                src: Source::Reg(temp),
            },
        ],
    ))
}

fn lower_move(insn: &DisasmInsn) -> Result<(RegRef, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if !(2..=3).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed move instruction"));
    }
    let dest: RegRef = parse_reg(operands[0])?;
    if !operands[1].trim().starts_with('#') {
        if insn.mnemonic != "mov" || operands.len() != 2 {
            return Err(reject_at(insn, "wide move source is not an immediate"));
        }
        if matches!(operands[1], "xzr" | "wzr") {
            return Ok((
                dest,
                vec![Stmt::Assign {
                    dest,
                    src: Source::Imm(0),
                }],
            ));
        }
        let src: RegRef = parse_reg(operands[1])?;
        if src.width != dest.width {
            return Err(reject_at(insn, "mixed-width register move"));
        }
        return Ok((
            dest,
            vec![Stmt::Assign {
                dest,
                src: Source::Reg(src),
            }],
        ));
    }
    if insn.mnemonic == "mov" {
        if operands.len() != 2 {
            return Err(reject_at(insn, "move alias cannot carry an explicit shift"));
        }
        return Ok((
            dest,
            vec![Stmt::Assign {
                dest,
                src: Source::Imm(parse_move_immediate(operands[1])?),
            }],
        ));
    }
    let immediate: i64 = parse_immediate(operands[1])?;
    let shift: u32 = if operands.len() == 3 {
        let (op, amount): (BinOp, i64) = parse_shift_modifier(operands[2], dest.width)?;
        if op != BinOp::Shl {
            return Err(reject_at(insn, "wide move requires lsl"));
        }
        u32::try_from(amount).map_err(|_| reject_at(insn, "wide move shift overflow"))?
    } else {
        0
    };
    let immediate: u64 = u64::try_from(immediate)
        .ok()
        .filter(|value: &u64| *value <= 0xffff)
        .ok_or_else(|| reject_at(insn, "wide move immediate exceeds sixteen bits"))?;
    let width_mask: u64 = match dest.width {
        Width::W32 => u64::from(u32::MAX),
        Width::W64 => u64::MAX,
        _ => return Err(reject_at(insn, "wide move destination is not w or x width")),
    };
    let shifted: u64 = immediate
        .checked_shl(shift)
        .ok_or_else(|| reject_at(insn, "wide move shift overflow"))?
        & width_mask;
    let shifted: i64 = i64::from_ne_bytes(shifted.to_ne_bytes());
    let stmts: Vec<Stmt> = match insn.mnemonic.as_str() {
        "movz" => vec![Stmt::Assign {
            dest,
            src: Source::Imm(shifted),
        }],
        "movn" => {
            let inverted: u64 = (!u64::from_ne_bytes(shifted.to_ne_bytes())) & width_mask;
            vec![Stmt::Assign {
                dest,
                src: Source::Imm(i64::from_ne_bytes(inverted.to_ne_bytes())),
            }]
        }
        "movk" => {
            let halfword_mask: u64 = 0xffff_u64
                .checked_shl(shift)
                .ok_or_else(|| reject_at(insn, "movk mask shift overflow"))?;
            let clear: u64 = (!halfword_mask) & width_mask;
            vec![
                Stmt::BinAssign {
                    dest,
                    op: BinOp::And,
                    src: Source::Imm(i64::from_ne_bytes(clear.to_ne_bytes())),
                },
                Stmt::BinAssign {
                    dest,
                    op: BinOp::Or,
                    src: Source::Imm(shifted),
                },
            ]
        }
        _ => return Err(reject_at(insn, "unsupported wide move")),
    };
    Ok((dest, stmts))
}

fn parse_fp_register(token: &str) -> Result<Option<(Xmm, FpWidth)>> {
    let name: &str = token.trim();
    let parsed: Option<(&str, FpWidth)> = name
        .strip_prefix('h')
        .map(|digits: &str| (digits, FpWidth::F16))
        .or_else(|| {
            name.strip_prefix('s')
                .map(|digits: &str| (digits, FpWidth::F32))
        })
        .or_else(|| {
            name.strip_prefix('d')
                .map(|digits: &str| (digits, FpWidth::F64))
        });
    if let Some((digits, width)) = parsed {
        let index: u8 = digits
            .parse::<u8>()
            .map_err(|_| reject("malformed scalar floating-point register"))?;
        let register: Xmm = *AARCH64_FP_REGISTERS
            .get(usize::from(index))
            .ok_or_else(|| reject("scalar floating-point register is outside v0..v31"))?;
        return Ok(Some((register, width)));
    }
    let unsupported: bool = ['q', 'v'].iter().any(|prefix: &char| {
        name.strip_prefix(*prefix)
            .is_some_and(|suffix: &str| suffix.starts_with(|ch: char| ch.is_ascii_digit()))
    });
    if unsupported {
        return Err(reject(
            "vector registers are outside scalar floating-point recovery",
        ));
    }
    Ok(None)
}

fn is_fp_zero_immediate(token: &str) -> bool {
    token
        .trim()
        .strip_prefix('#')
        .and_then(|body: &str| body.parse::<f64>().ok())
        .is_some_and(|value: f64| value == 0.0)
}

fn movi_immediate_is_zero(token: &str) -> bool {
    let trimmed: &str = token.trim();
    let body: &str = trimmed.strip_prefix('#').unwrap_or(trimmed);
    let digits: &str = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .unwrap_or(body);
    !digits.is_empty() && digits.bytes().all(|byte: u8| byte == b'0')
}

fn lower_movi_scalar_zero(operands: &[&str]) -> Result<Option<Vec<Stmt>>> {
    if operands.len() != 2 {
        return Ok(None);
    }
    let Some(index): Option<u8> = parse_dreg(operands[0]) else {
        return Ok(None);
    };
    if !movi_immediate_is_zero(operands[1]) {
        return Ok(None);
    }
    let Some(register): Option<&Xmm> = AARCH64_FP_REGISTERS.get(usize::from(index)) else {
        return Ok(None);
    };
    Ok(Some(vec![Stmt::FpMov {
        dest: *register,
        src: FpOperand::Const {
            bits: 0,
            width: FpWidth::F64,
        },
        width: FpWidth::F64,
    }]))
}

fn parse_fp_compare_operand(token: &str, width: FpWidth, insn: &DisasmInsn) -> Result<FpOperand> {
    if token.trim().starts_with('#') {
        if is_fp_zero_immediate(token) {
            return Ok(FpOperand::Const { bits: 0, width });
        }
        return Err(reject_at(
            insn,
            "floating-point compare immediate other than zero is unsupported",
        ));
    }
    let (register, register_width): (Xmm, FpWidth) = parse_fp_register(token)?
        .ok_or_else(|| reject_at(insn, "floating-point compare operand is not scalar"))?;
    if register_width != width {
        return Err(reject_at(
            insn,
            "floating-point compare uses mixed precision",
        ));
    }
    Ok(FpOperand::Xmm(register))
}

fn fp_memory_register(token: &str) -> Result<Option<(Xmm, FpWidth)>> {
    let name: &str = token.trim();
    if name.starts_with('s') || name.starts_with('d') || name.starts_with('h') {
        return parse_fp_register(name);
    }
    Ok(None)
}

fn lower_fp_literal(
    insn: &DisasmInsn,
    register: Xmm,
    width: FpWidth,
    image: &ImageContext<'_, '_>,
) -> Result<Option<Vec<Stmt>>> {
    let Some(word): Option<u32> = aarch64_instruction_word(insn) else {
        return Ok(None);
    };
    if word & 0x3f00_0000 != 0x1c00_0000 {
        return Ok(None);
    }
    let encoded_width: FpWidth = match word >> 30 {
        0 => FpWidth::F32,
        1 => FpWidth::F64,
        2 => {
            return Err(reject_at(
                insn,
                "vector literal load is outside scalar floating-point recovery",
            ));
        }
        _ => {
            return Err(reject_at(
                insn,
                "unallocated floating-point literal encoding",
            ));
        }
    };
    if encoded_width != width {
        return Err(reject_at(
            insn,
            "floating-point literal encoding and destination precision differ",
        ));
    }
    let raw_imm19: i64 = i64::from((word >> 5) & 0x7ffff);
    let signed_imm19: i64 = if raw_imm19 & (1 << 18) == 0 {
        raw_imm19
    } else {
        raw_imm19 - (1 << 19)
    };
    let displacement: i64 = signed_imm19
        .checked_mul(4)
        .ok_or_else(|| reject_at(insn, "floating-point literal displacement overflow"))?;
    let target: u64 = if displacement >= 0 {
        insn.address
            .checked_add(displacement.unsigned_abs())
            .ok_or_else(|| reject_at(insn, "floating-point literal address overflow"))?
    } else {
        insn.address
            .checked_sub(displacement.unsigned_abs())
            .ok_or_else(|| reject_at(insn, "floating-point literal address underflow"))?
    };
    let available: &[u8] = (image.image)(target).ok_or_else(|| {
        reject_at(
            insn,
            "floating-point literal bytes are unavailable from the image context",
        )
    })?;
    let byte_count: usize = usize::try_from(fp_storage_width(width).bits() / 8)
        .map_err(|_| reject_at(insn, "floating-point literal width exceeds host size"))?;
    let bytes: &[u8] = available.get(..byte_count).ok_or_else(|| {
        reject_at(
            insn,
            "floating-point literal bytes are truncated in the image context",
        )
    })?;
    let bits: u64 = match width {
        FpWidth::F16 => {
            return Err(reject_at(
                insn,
                "half-precision literal load has no scalar architectural encoding",
            ));
        }
        FpWidth::F32 => {
            let raw: [u8; 4] = bytes
                .try_into()
                .map_err(|_| reject_at(insn, "single-precision literal width is inconsistent"))?;
            u64::from(u32::from_le_bytes(raw))
        }
        FpWidth::F64 => {
            let raw: [u8; 8] = bytes
                .try_into()
                .map_err(|_| reject_at(insn, "double-precision literal width is inconsistent"))?;
            u64::from_le_bytes(raw)
        }
    };
    Ok(Some(vec![Stmt::FpMov {
        dest: register,
        src: FpOperand::Const { bits, width },
        width,
    }]))
}

const fn fp_storage_width(width: FpWidth) -> Width {
    match width {
        FpWidth::F16 => Width::W16,
        FpWidth::F32 => Width::W32,
        FpWidth::F64 => Width::W64,
    }
}

const fn fp_gpr_transfer_width(width: FpWidth) -> Width {
    match width {
        FpWidth::F16 | FpWidth::F32 => Width::W32,
        FpWidth::F64 => Width::W64,
    }
}

fn vfp_expand_imm_bits(imm8: u8, width: FpWidth) -> u64 {
    let (exponent_bits, fraction_bits): (u32, u32) = match width {
        FpWidth::F16 => (5, 10),
        FpWidth::F32 => (8, 23),
        FpWidth::F64 => (11, 52),
    };
    let sign: u64 = u64::from(imm8 >> 7);
    let repeated: u64 = u64::from((imm8 >> 6) & 1);
    let exponent_tail: u64 = u64::from((imm8 >> 4) & 3);
    let repeated_count: u32 = exponent_bits - 3;
    let repeated_mask: u64 = if repeated == 0 {
        0
    } else {
        (1_u64 << repeated_count) - 1
    };
    let exponent: u64 =
        ((1 - repeated) << (exponent_bits - 1)) | (repeated_mask << 2) | exponent_tail;
    let fraction: u64 = u64::from(imm8 & 15) << (fraction_bits - 4);
    (sign << (exponent_bits + fraction_bits)) | (exponent << fraction_bits) | fraction
}

fn fp_immediate_operand(insn: &DisasmInsn, token: &str, width: FpWidth) -> Result<FpOperand> {
    let text: &str = token
        .trim()
        .strip_prefix('#')
        .ok_or_else(|| reject_at(insn, "floating-point immediate lacks a number marker"))?;
    let parsed: f64 = text
        .parse::<f64>()
        .map_err(|_| reject_at(insn, "floating-point immediate is not a decimal value"))?;
    if !parsed.is_finite() {
        return Err(reject_at(insn, "floating-point immediate is not finite"));
    }
    let parsed_bits: u64 = match width {
        FpWidth::F16 => {
            let narrowed: f32 = parsed as f32;
            let narrowed_bits: u16 = binary16_from_f32(narrowed);
            if f64::from(binary16_to_f32(narrowed_bits)).to_bits() != parsed.to_bits() {
                return Err(reject_at(
                    insn,
                    "half-precision immediate is not exactly representable",
                ));
            }
            u64::from(narrowed_bits)
        }
        FpWidth::F32 => {
            let narrowed: f32 = parsed as f32;
            if f64::from(narrowed).to_bits() != parsed.to_bits() {
                return Err(reject_at(
                    insn,
                    "single-precision immediate is not exactly representable",
                ));
            }
            u64::from(narrowed.to_bits())
        }
        FpWidth::F64 => parsed.to_bits(),
    };
    let word: u32 = aarch64_instruction_word(insn)
        .ok_or_else(|| reject_at(insn, "floating-point immediate lacks raw instruction bits"))?;
    let imm8: u8 = u8::try_from((word >> 13) & 0xff)
        .map_err(|_| reject_at(insn, "floating-point imm8 extraction overflow"))?;
    let expanded_bits: u64 = vfp_expand_imm_bits(imm8, width);
    if parsed_bits != expanded_bits {
        return Err(reject_at(
            insn,
            "floating-point immediate does not exactly match VFPExpandImm",
        ));
    }
    Ok(FpOperand::Const {
        bits: parsed_bits,
        width,
    })
}

fn binary16_to_f32(bits: u16) -> f32 {
    let sign: u32 = u32::from(bits & 0x8000) << 16;
    let exponent: u16 = (bits >> 10) & 0x1f;
    let mut fraction: u32 = u32::from(bits & 0x03ff);
    let expanded: u32 = match (exponent, fraction) {
        (0, 0) => sign,
        (0, _) => {
            let mut unbiased: i32 = -14;
            while fraction & 0x0400 == 0 {
                fraction <<= 1;
                unbiased -= 1;
            }
            fraction &= 0x03ff;
            sign | ((unbiased + 127) as u32) << 23 | fraction << 13
        }
        (0x1f, _) => sign | 0x7f80_0000 | fraction << 13,
        _ => sign | (u32::from(exponent) + 112) << 23 | fraction << 13,
    };
    f32::from_bits(expanded)
}

fn binary16_from_f32(value: f32) -> u16 {
    let bits: u32 = value.to_bits();
    let sign: u16 = ((bits >> 16) & 0x8000) as u16;
    let exponent: u32 = (bits >> 23) & 0xff;
    let fraction: u32 = bits & 0x007f_ffff;
    if exponent == 0xff {
        if fraction == 0 {
            return sign | 0x7c00;
        }
        let narrowed: u16 = (fraction >> 13) as u16;
        let payload: u16 = if narrowed == 0 { 1 } else { narrowed };
        return sign | 0x7c00 | payload;
    }
    if exponent < 102 {
        return sign;
    }
    let significand: u32 = fraction | 0x0080_0000;
    if exponent < 113 {
        let shift: u32 = 126 - exponent;
        return sign | binary16_round_shift(significand, shift) as u16;
    }
    if exponent > 142 {
        return sign | 0x7c00;
    }
    let rounded: u32 = binary16_round_shift(fraction, 13);
    let mut half_exponent: u32 = exponent - 112;
    let half_fraction: u32 = if rounded == 0x0400 {
        half_exponent += 1;
        0
    } else {
        rounded
    };
    if half_exponent >= 0x1f {
        sign | 0x7c00
    } else {
        sign | ((half_exponent as u16) << 10) | half_fraction as u16
    }
}

fn binary16_round_shift(value: u32, shift: u32) -> u32 {
    let quotient: u32 = value >> shift;
    let remainder_mask: u32 = (1_u32 << shift) - 1;
    let remainder: u32 = value & remainder_mask;
    let halfway: u32 = 1_u32 << (shift - 1);
    quotient + u32::from(remainder > halfway || remainder == halfway && quotient & 1 != 0)
}

fn lower_fp_fmov(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(insn, "malformed scalar floating-point move"));
    }
    let dest_fp: Option<(Xmm, FpWidth)> = parse_fp_register(operands[0])?;
    let src_fp: Option<(Xmm, FpWidth)> = parse_fp_register(operands[1])?;
    match (dest_fp, src_fp) {
        (Some((dest, dest_width)), Some((src, src_width))) => {
            if dest_width != src_width {
                return Err(reject_at(
                    insn,
                    "scalar floating-point move changes precision",
                ));
            }
            Ok(vec![Stmt::FpMov {
                dest,
                src: FpOperand::Xmm(src),
                width: dest_width,
            }])
        }
        (Some((dest, width)), None) if operands[1].trim().starts_with('#') => {
            let src: FpOperand = fp_immediate_operand(insn, operands[1], width)?;
            Ok(vec![Stmt::FpMov { dest, src, width }])
        }
        (Some((dest, width)), None) => {
            let expected: Width = fp_gpr_transfer_width(width);
            let src: RegRef = parse_reg(operands[1]).map_err(|_| {
                reject_at(insn, "fmov source is not a width-matched general register")
            })?;
            if src.width != expected {
                return Err(reject_at(
                    insn,
                    "fmov source general register has the wrong width",
                ));
            }
            Ok(vec![Stmt::GprToXmm { dest, src, width }])
        }
        (None, Some((src, width))) => {
            let expected: Width = fp_gpr_transfer_width(width);
            let dest: RegRef = parse_reg(operands[0]).map_err(|_| {
                reject_at(
                    insn,
                    "fmov destination is not a width-matched general register",
                )
            })?;
            if dest.width != expected {
                return Err(reject_at(
                    insn,
                    "fmov destination general register has the wrong width",
                ));
            }
            Ok(vec![Stmt::XmmToGpr { dest, src, width }])
        }
        (None, None) => Err(reject_at(
            insn,
            "fmov does not use a supported scalar floating-point register",
        )),
    }
}

fn lower_fp_binary(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 3 {
        return Err(reject_at(
            insn,
            "malformed three-operand scalar floating-point arithmetic",
        ));
    }
    let op: FpOp = match insn.mnemonic.as_str() {
        "fadd" => FpOp::Add,
        "fsub" => FpOp::Sub,
        "fmul" => FpOp::Mul,
        "fdiv" => FpOp::Div,
        _ => {
            return Err(reject_at(
                insn,
                "unsupported scalar floating-point arithmetic",
            ));
        }
    };
    let dest: (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "floating-point arithmetic destination is not scalar"))?;
    let lhs: (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "floating-point arithmetic lhs is not scalar"))?;
    let rhs: (Xmm, FpWidth) = parse_fp_register(operands[2])?
        .ok_or_else(|| reject_at(insn, "floating-point arithmetic rhs is not scalar"))?;
    if dest.1 != lhs.1 || dest.1 != rhs.1 {
        return Err(reject_at(
            insn,
            "scalar floating-point arithmetic uses mixed precision",
        ));
    }
    Ok(vec![Stmt::FpBin {
        dest: dest.0,
        lhs: FpOperand::Xmm(lhs.0),
        rhs: FpOperand::Xmm(rhs.0),
        op,
        width: dest.1,
    }])
}

fn lower_fp_minmax(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 3 {
        return Err(reject_at(
            insn,
            "malformed three-operand scalar floating-point minimum or maximum",
        ));
    }
    let (is_max, propagate): (bool, bool) = match insn.mnemonic.as_str() {
        "fmaxnm" => (true, false),
        "fminnm" => (false, false),
        "fmax" => (true, true),
        "fmin" => (false, true),
        _ => {
            return Err(reject_at(
                insn,
                "unsupported scalar floating-point minimum or maximum",
            ));
        }
    };
    let dest: (Xmm, FpWidth) = parse_fp_register(operands[0])?.ok_or_else(|| {
        reject_at(
            insn,
            "floating-point minimum or maximum destination is not scalar",
        )
    })?;
    let lhs: (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "floating-point minimum or maximum lhs is not scalar"))?;
    let rhs: (Xmm, FpWidth) = parse_fp_register(operands[2])?
        .ok_or_else(|| reject_at(insn, "floating-point minimum or maximum rhs is not scalar"))?;
    if dest.1 != lhs.1 || dest.1 != rhs.1 {
        return Err(reject_at(
            insn,
            "scalar floating-point minimum or maximum uses mixed precision",
        ));
    }
    let kind: FpMinMaxKind = match (is_max, propagate) {
        (true, false) => FpMinMaxKind::IeeeMax,
        (false, false) => FpMinMaxKind::IeeeMin,
        (true, true) => FpMinMaxKind::PropagateMax,
        (false, true) => FpMinMaxKind::PropagateMin,
    };
    Ok(vec![Stmt::FpMinMax {
        dest: dest.0,
        lhs: FpOperand::Xmm(lhs.0),
        rhs: FpOperand::Xmm(rhs.0),
        kind,
        width: dest.1,
    }])
}

fn lower_fp_fma(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 4 {
        return Err(reject_at(
            insn,
            "malformed four-operand scalar fused multiply-add",
        ));
    }
    let kind: FpFmaKind = match insn.mnemonic.as_str() {
        "fmadd" => FpFmaKind::Madd,
        "fmsub" => FpFmaKind::Msub,
        "fnmadd" => FpFmaKind::Nmadd,
        "fnmsub" => FpFmaKind::Nmsub,
        _ => {
            return Err(reject_at(insn, "unsupported scalar fused multiply-add"));
        }
    };
    let dest: (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "fused multiply-add destination is not scalar"))?;
    let mul_lhs: (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "fused multiply-add multiplicand is not scalar"))?;
    let mul_rhs: (Xmm, FpWidth) = parse_fp_register(operands[2])?
        .ok_or_else(|| reject_at(insn, "fused multiply-add multiplier is not scalar"))?;
    let addend: (Xmm, FpWidth) = parse_fp_register(operands[3])?
        .ok_or_else(|| reject_at(insn, "fused multiply-add addend is not scalar"))?;
    if dest.1 != mul_lhs.1 || dest.1 != mul_rhs.1 || dest.1 != addend.1 {
        return Err(reject_at(
            insn,
            "scalar fused multiply-add uses mixed precision",
        ));
    }
    Ok(vec![Stmt::FpFma {
        dest: dest.0,
        mul_lhs: FpOperand::Xmm(mul_lhs.0),
        mul_rhs: FpOperand::Xmm(mul_rhs.0),
        addend: FpOperand::Xmm(addend.0),
        kind,
        width: dest.1,
    }])
}

fn lower_fp_unary(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(
            insn,
            "malformed scalar floating-point unary operation",
        ));
    }
    let op: FpUnaryOp = match insn.mnemonic.as_str() {
        "fneg" => FpUnaryOp::Neg,
        "fabs" => FpUnaryOp::Abs,
        _ => {
            return Err(reject_at(
                insn,
                "unsupported scalar floating-point unary operation",
            ));
        }
    };
    let dest: (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "floating-point unary destination is not scalar"))?;
    let src: (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "floating-point unary source is not scalar"))?;
    if dest.1 != src.1 {
        return Err(reject_at(
            insn,
            "scalar floating-point unary operation changes precision",
        ));
    }
    Ok(vec![Stmt::FpUnary {
        dest: dest.0,
        src: FpOperand::Xmm(src.0),
        op,
        width: dest.1,
    }])
}

fn lower_fp_sqrt(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(
            insn,
            "malformed scalar floating-point square root",
        ));
    }
    let dest: (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "floating-point square root destination is not scalar"))?;
    let src: (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "floating-point square root source is not scalar"))?;
    if dest.1 != src.1 {
        return Err(reject_at(
            insn,
            "scalar floating-point square root changes precision",
        ));
    }
    Ok(vec![Stmt::FpSqrt {
        dest: dest.0,
        src: FpOperand::Xmm(src.0),
        width: dest.1,
        saturating: true,
    }])
}

fn lower_fp_binary_then_unary(
    insn: &DisasmInsn,
    operands: &[&str],
    binary: FpOp,
    unary: FpUnaryOp,
) -> Result<Vec<Stmt>> {
    if operands.len() != 3 {
        return Err(reject_at(
            insn,
            "malformed three-operand scalar floating-point operation",
        ));
    }
    let dest: (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "scalar floating-point destination is not scalar"))?;
    let lhs: (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "scalar floating-point lhs is not scalar"))?;
    let rhs: (Xmm, FpWidth) = parse_fp_register(operands[2])?
        .ok_or_else(|| reject_at(insn, "scalar floating-point rhs is not scalar"))?;
    if dest.1 != lhs.1 || dest.1 != rhs.1 {
        return Err(reject_at(
            insn,
            "scalar floating-point operation uses mixed precision",
        ));
    }
    Ok(vec![
        Stmt::FpBin {
            dest: dest.0,
            lhs: FpOperand::Xmm(lhs.0),
            rhs: FpOperand::Xmm(rhs.0),
            op: binary,
            width: dest.1,
        },
        Stmt::FpUnary {
            dest: dest.0,
            src: FpOperand::Xmm(dest.0),
            op: unary,
            width: dest.1,
        },
    ])
}

fn parse_fixed_point_fraction(
    insn: &DisasmInsn,
    operands: &[&str],
    integer_width: Width,
) -> Result<Option<NonZeroU8>> {
    let Some(token): Option<&&str> = operands.get(2) else {
        return Ok(None);
    };
    if !token.trim().starts_with('#') {
        return Err(reject_at(
            insn,
            "fixed-point conversion scale is not an immediate",
        ));
    }
    let limit: i64 = match integer_width {
        Width::W32 => 32,
        Width::W64 => 64,
        Width::W8 | Width::W16 => {
            return Err(reject_at(
                insn,
                "fixed-point conversion uses a sub-word integer register",
            ));
        }
    };
    let requested: i64 = parse_immediate(token)?;
    if requested < 1 || requested > limit {
        return Err(reject_at(
            insn,
            "fixed-point conversion scale is outside the architectural range",
        ));
    }
    let fraction: NonZeroU8 = u8::try_from(requested)
        .ok()
        .and_then(NonZeroU8::new)
        .ok_or_else(|| reject_at(insn, "fixed-point conversion scale is not representable"))?;
    Ok(Some(fraction))
}

fn lower_int_to_fp(insn: &DisasmInsn, operands: &[&str], signed: bool) -> Result<Vec<Stmt>> {
    if !matches!(operands.len(), 2 | 3) {
        return Err(reject_at(
            insn,
            "malformed integer-to-floating-point conversion",
        ));
    }
    let (dest, width): (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "integer-to-floating-point destination is not scalar"))?;
    let src: RegRef = parse_reg(operands[1])
        .map_err(|_| reject_at(insn, "integer-to-floating-point source is not w or x"))?;
    let fbits: Option<NonZeroU8> = parse_fixed_point_fraction(insn, operands, src.width)?;
    Ok(vec![Stmt::IntToFp {
        dest,
        src,
        signed,
        width,
        fbits,
    }])
}

fn lower_fp_to_int(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if !matches!(operands.len(), 2 | 3) {
        return Err(reject_at(
            insn,
            "malformed floating-point-to-integer conversion",
        ));
    }
    let (signed, round): (bool, FpToIntRound) = match insn.mnemonic.as_str() {
        "fcvtzs" => (true, FpToIntRound::Zero),
        "fcvtzu" => (false, FpToIntRound::Zero),
        "fcvtns" => (true, FpToIntRound::Nearest),
        "fcvtnu" => (false, FpToIntRound::Nearest),
        "fcvtms" => (true, FpToIntRound::Floor),
        "fcvtmu" => (false, FpToIntRound::Floor),
        "fcvtps" => (true, FpToIntRound::Ceil),
        "fcvtpu" => (false, FpToIntRound::Ceil),
        "fcvtas" => (true, FpToIntRound::Away),
        "fcvtau" => (false, FpToIntRound::Away),
        _ => {
            return Err(reject_at(
                insn,
                "unsupported floating-point-to-integer conversion",
            ));
        }
    };
    let dest: RegRef = parse_reg(operands[0])
        .map_err(|_| reject_at(insn, "floating-point-to-integer destination is not w or x"))?;
    let (src, width): (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "floating-point-to-integer source is not scalar"))?;
    let fbits: Option<NonZeroU8> = parse_fixed_point_fraction(insn, operands, dest.width)?;
    if fbits.is_some() && !matches!(round, FpToIntRound::Zero) {
        return Err(reject_at(
            insn,
            "fixed-point floating-point-to-integer conversion requires truncation toward zero",
        ));
    }
    Ok(vec![Stmt::FpToInt {
        dest,
        src,
        width,
        signed,
        round,
        fbits,
        saturating: true,
    }])
}

fn lower_fp_convert(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(
            insn,
            "malformed floating-point precision conversion",
        ));
    }
    let (dest, to): (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "floating-point conversion destination is not scalar"))?;
    let (src, from): (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "floating-point conversion source is not scalar"))?;
    if from == to {
        return Err(reject_at(
            insn,
            "floating-point conversion does not change precision",
        ));
    }
    Ok(vec![Stmt::FpConvert {
        dest,
        src,
        from,
        to,
    }])
}

fn lower_fp_round(insn: &DisasmInsn, operands: &[&str], kind: FpRoundKind) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(
            insn,
            "malformed scalar floating-point round to integral",
        ));
    }
    let (dest, width): (Xmm, FpWidth) = parse_fp_register(operands[0])?
        .ok_or_else(|| reject_at(insn, "round destination is not scalar"))?;
    let (src, src_width): (Xmm, FpWidth) = parse_fp_register(operands[1])?
        .ok_or_else(|| reject_at(insn, "round source is not scalar"))?;
    if width != src_width {
        return Err(reject_at(insn, "round to integral uses mixed precision"));
    }
    if width == FpWidth::F16 && matches!(kind, FpRoundKind::SignedRange { .. }) {
        return Err(reject_at(
            insn,
            "range-limited rounding does not encode a half-precision form",
        ));
    }
    Ok(vec![Stmt::FpRound {
        dest,
        src: FpOperand::Xmm(src),
        width,
        kind,
    }])
}

fn fp_incoming_stack_source(
    mem: MemRef,
    frame: FrameInfo,
    width: FpWidth,
    insn: &DisasmInsn,
) -> Result<Option<RegRef>> {
    let threshold: Option<i64> = match mem.base {
        Some(Reg::Rsp) => Some(frame.sp_to_entry),
        Some(Reg::Rbp) => frame.fp_to_entry,
        _ => None,
    };
    let Some(threshold) = threshold else {
        return Ok(None);
    };
    if mem.disp < threshold {
        return Ok(None);
    }
    let relative: i64 = mem
        .disp
        .checked_sub(threshold)
        .ok_or_else(|| reject_at(insn, "incoming floating-point stack offset underflow"))?;
    if relative % 8 != 0 {
        return Err(reject_at(
            insn,
            "incoming floating-point stack argument is not eight-byte aligned",
        ));
    }
    let index: usize = usize::try_from(relative / 8).map_err(|_| {
        reject_at(
            insn,
            "incoming floating-point stack argument index overflow",
        )
    })?;
    let reg: Reg = match index {
        0 => Reg::A64Stack0,
        1 => Reg::A64Stack1,
        2 => Reg::A64Stack2,
        3 => Reg::A64Stack3,
        4 => Reg::A64Stack4,
        5 => Reg::A64Stack5,
        6 => Reg::A64Stack6,
        7 => Reg::A64Stack7,
        _ => {
            return Err(reject_at(
                insn,
                "incoming floating-point stack argument exceeds the bounded eight-slot lift",
            ));
        }
    };
    Ok(Some(RegRef {
        reg,
        width: fp_storage_width(width),
    }))
}

fn lower_fp_memory(
    insn: &DisasmInsn,
    operands: &[&str],
    register: Xmm,
    width: FpWidth,
    frame: FrameInfo,
) -> Result<Vec<Stmt>> {
    if !(2..=3).contains(&operands.len()) {
        return Err(reject_at(
            insn,
            "malformed scalar floating-point load or store",
        ));
    }
    let is_load: bool = matches!(insn.mnemonic.as_str(), "ldr" | "ldur");
    let storage_width: Width = fp_storage_width(width);
    let (mut mem, pre_index): (MemRef, bool) = parse_memory(operands[1], storage_width)?;
    let post_delta: Option<i64> = operands
        .get(2)
        .map(|token: &&str| parse_immediate(token))
        .transpose()?;
    if pre_index && post_delta.is_some() {
        return Err(reject_at(
            insn,
            "scalar floating-point address cannot use two writeback modes",
        ));
    }
    let incoming_stack_source: Option<RegRef> = if is_load {
        fp_incoming_stack_source(mem, frame, width, insn)?
    } else {
        None
    };
    let mut stmts: Vec<Stmt> = Vec::new();
    if pre_index {
        let delta: i64 = mem.disp;
        mem.disp = 0;
        stmts.extend(frame_writeback(frame, mem.base, delta)?);
    }
    if let Some(src) = incoming_stack_source {
        stmts.push(Stmt::GprToXmm {
            dest: register,
            src,
            width,
        });
    } else if is_load {
        stmts.push(Stmt::FpMov {
            dest: register,
            src: FpOperand::Mem(mem),
            width,
        });
    } else {
        stmts.push(Stmt::FpStore {
            addr: mem,
            src: register,
            width,
        });
    }
    if let Some(delta) = post_delta {
        if mem.disp != 0 {
            return Err(reject_at(
                insn,
                "post-indexed scalar floating-point address has an inline displacement",
            ));
        }
        stmts.extend(frame_writeback(frame, mem.base, delta)?);
    }
    Ok(stmts)
}

fn lower_fp_pair_memory(
    insn: &DisasmInsn,
    operands: &[&str],
    first: (Xmm, FpWidth),
    second: (Xmm, FpWidth),
    frame: FrameInfo,
) -> Result<Vec<Stmt>> {
    if !(3..=4).contains(&operands.len()) {
        return Err(reject_at(
            insn,
            "malformed scalar floating-point pair load or store",
        ));
    }
    if first.1 != second.1 {
        return Err(reject_at(
            insn,
            "scalar floating-point pair uses mixed precision",
        ));
    }
    let is_load: bool = insn.mnemonic == "ldp";
    let storage_width: Width = fp_storage_width(first.1);
    let (mut first_mem, pre_index): (MemRef, bool) = parse_memory(operands[2], storage_width)?;
    let post_delta: Option<i64> = operands
        .get(3)
        .map(|token: &&str| parse_immediate(token))
        .transpose()?;
    if pre_index && post_delta.is_some() {
        return Err(reject_at(
            insn,
            "scalar floating-point pair address cannot use two writeback modes",
        ));
    }
    let width_bytes: i64 = i64::from(storage_width.bits() / 8);
    let second_disp: i64 = first_mem
        .disp
        .checked_add(width_bytes)
        .ok_or_else(|| reject_at(insn, "scalar floating-point pair address overflow"))?;
    let mut second_mem: MemRef = MemRef {
        disp: second_disp,
        ..first_mem
    };
    let incoming_pair: Option<(RegRef, RegRef)> = if is_load {
        let first_source: Option<RegRef> =
            fp_incoming_stack_source(first_mem, frame, first.1, insn)?;
        let second_source: Option<RegRef> =
            fp_incoming_stack_source(second_mem, frame, second.1, insn)?;
        match (first_source, second_source) {
            (Some(first_reg), Some(second_reg)) => Some((first_reg, second_reg)),
            (None, None) => None,
            _ => {
                return Err(reject_at(
                    insn,
                    "scalar floating-point pair spans the incoming stack argument boundary",
                ));
            }
        }
    } else {
        None
    };
    let mut stmts: Vec<Stmt> = Vec::new();
    if pre_index {
        let delta: i64 = first_mem.disp;
        first_mem.disp = 0;
        second_mem.disp = width_bytes;
        stmts.extend(frame_writeback(frame, first_mem.base, delta)?);
    }
    if let Some((first_src, second_src)) = incoming_pair {
        stmts.push(Stmt::GprToXmm {
            dest: first.0,
            src: first_src,
            width: first.1,
        });
        stmts.push(Stmt::GprToXmm {
            dest: second.0,
            src: second_src,
            width: second.1,
        });
    } else if is_load {
        stmts.push(Stmt::FpMov {
            dest: first.0,
            src: FpOperand::Mem(first_mem),
            width: first.1,
        });
        stmts.push(Stmt::FpMov {
            dest: second.0,
            src: FpOperand::Mem(second_mem),
            width: second.1,
        });
    } else {
        stmts.push(Stmt::FpStore {
            addr: first_mem,
            src: first.0,
            width: first.1,
        });
        stmts.push(Stmt::FpStore {
            addr: second_mem,
            src: second.0,
            width: second.1,
        });
    }
    if let Some(delta) = post_delta {
        if first_mem.disp != 0 {
            return Err(reject_at(
                insn,
                "post-indexed scalar floating-point pair has an inline displacement",
            ));
        }
        stmts.extend(frame_writeback(frame, first_mem.base, delta)?);
    }
    Ok(stmts)
}

fn has_scalar_fp_destination(operands: &[&str]) -> bool {
    let Some(dest): Option<&&str> = operands.first() else {
        return false;
    };
    let name: &str = dest.trim();
    ['s', 'd', 'h'].iter().any(|prefix: &char| {
        name.strip_prefix(*prefix)
            .is_some_and(|suffix: &str| suffix.starts_with(|ch: char| ch.is_ascii_digit()))
    })
}

fn has_scalar_gpr_destination(operands: &[&str]) -> bool {
    let Some(dest): Option<&&str> = operands.first() else {
        return false;
    };
    parse_reg(dest).is_ok()
}

fn try_lower_scalar_fp(
    insn: &DisasmInsn,
    frame: FrameInfo,
    vector_context: bool,
    image: &ImageContext<'_, '_>,
) -> Result<Option<Vec<Stmt>>> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    match insn.mnemonic.as_str() {
        "fadd" | "fsub" | "fmul" | "fdiv" if has_scalar_fp_destination(&operands) => {
            lower_fp_binary(insn, &operands).map(Some)
        }
        "fmaxnm" | "fminnm" | "fmax" | "fmin" if has_scalar_fp_destination(&operands) => {
            lower_fp_minmax(insn, &operands).map(Some)
        }
        "fmadd" | "fmsub" | "fnmadd" | "fnmsub" if has_scalar_fp_destination(&operands) => {
            lower_fp_fma(insn, &operands).map(Some)
        }
        "fneg" | "fabs" if has_scalar_fp_destination(&operands) => {
            lower_fp_unary(insn, &operands).map(Some)
        }
        "fsqrt" if has_scalar_fp_destination(&operands) => lower_fp_sqrt(insn, &operands).map(Some),
        "fabd" if has_scalar_fp_destination(&operands) => {
            lower_fp_binary_then_unary(insn, &operands, FpOp::Sub, FpUnaryOp::Abs).map(Some)
        }
        "fnmul" if has_scalar_fp_destination(&operands) => {
            lower_fp_binary_then_unary(insn, &operands, FpOp::Mul, FpUnaryOp::Neg).map(Some)
        }
        "scvtf" if has_scalar_fp_destination(&operands) => {
            lower_int_to_fp(insn, &operands, true).map(Some)
        }
        "ucvtf" if has_scalar_fp_destination(&operands) => {
            lower_int_to_fp(insn, &operands, false).map(Some)
        }
        "fcvtzs" | "fcvtzu" | "fcvtns" | "fcvtnu" | "fcvtms" | "fcvtmu" | "fcvtps" | "fcvtpu"
        | "fcvtas" | "fcvtau"
            if has_scalar_gpr_destination(&operands) =>
        {
            lower_fp_to_int(insn, &operands).map(Some)
        }
        "fcvt" if has_scalar_fp_destination(&operands) => {
            lower_fp_convert(insn, &operands).map(Some)
        }
        "frintm" | "frintp" | "frintz" | "frintn" | "frinta" | "frintx" | "frinti"
            if has_scalar_fp_destination(&operands) =>
        {
            let mode: RoundMode = match insn.mnemonic.as_str() {
                "frintm" => RoundMode::Floor,
                "frintp" => RoundMode::Ceil,
                "frintz" => RoundMode::Trunc,
                "frinta" => RoundMode::TiesAway,
                _ => RoundMode::Nearest,
            };
            lower_fp_round(insn, &operands, FpRoundKind::Integral(mode)).map(Some)
        }
        "frint32z" | "frint64z" | "frint32x" | "frint64x"
            if has_scalar_fp_destination(&operands) =>
        {
            let range: FpRoundRange = if insn.mnemonic.starts_with("frint32") {
                FpRoundRange::I32
            } else {
                FpRoundRange::I64
            };
            let mode: RoundMode = if insn.mnemonic.ends_with('x') {
                RoundMode::Nearest
            } else {
                RoundMode::Trunc
            };
            lower_fp_round(insn, &operands, FpRoundKind::SignedRange { range, mode }).map(Some)
        }
        "fjcvtzs" if has_scalar_gpr_destination(&operands) => Err(reject_at(
            insn,
            "javascript float-to-integer conversion needs a modular wrap policy and an exact-result flag definition",
        )),
        "fadd" | "fsub" | "fmul" | "fdiv" | "fmaxnm" | "fminnm" | "fmax" | "fmin" | "fmadd"
        | "fmsub" | "fnmadd" | "fnmsub" | "fabd" | "fnmul" | "fneg" | "fabs" | "scvtf"
        | "ucvtf" | "fcvtzs" | "fcvtzu" | "fcvtns" | "fcvtnu" | "fcvtms" | "fcvtmu" | "fcvtps"
        | "fcvtpu" | "fcvtas" | "fcvtau" | "fcvt" | "frintm" | "frintp" | "frintz" | "frintn"
        | "frinta" | "frintx" | "frinti" | "frint32z" | "frint32x" | "frint64z" | "frint64x"
        | "fjcvtzs" => Ok(None),
        "movi" if !vector_context => lower_movi_scalar_zero(&operands),
        "fmov" if vector_context => {
            if !operand_is_vector(insn) && instruction_has_vector_syntax(insn) {
                return Err(reject_at(
                    insn,
                    "vector-lane floating-point move is outside scalar floating-point recovery",
                ));
            }
            Ok(None)
        }
        "fmov" => lower_fp_fmov(insn, &operands).map(Some),
        "ldr" | "str" | "ldur" | "stur" => {
            let Some(token): Option<&&str> = operands.first() else {
                return Ok(None);
            };
            if matches!(insn.mnemonic.as_str(), "ldr" | "str")
                && parse_dreg(token).is_some()
                && (vector_context || is_dreg_post_indexed(&insn.operands))
            {
                return Ok(None);
            }
            let Some((register, width)): Option<(Xmm, FpWidth)> = fp_memory_register(token)? else {
                return Ok(None);
            };
            if let Some(stmts) = lower_fp_literal(insn, register, width, image)? {
                return Ok(Some(stmts));
            }
            lower_fp_memory(insn, &operands, register, width, frame).map(Some)
        }
        "ldp" | "stp" => {
            let (Some(first_token), Some(second_token)): (Option<&&str>, Option<&&str>) =
                (operands.first(), operands.get(1))
            else {
                return Ok(None);
            };
            let first: Option<(Xmm, FpWidth)> = fp_memory_register(first_token)?;
            let second: Option<(Xmm, FpWidth)> = fp_memory_register(second_token)?;
            match (first, second) {
                (Some(first), Some(second)) => {
                    lower_fp_pair_memory(insn, &operands, first, second, frame).map(Some)
                }
                (Some(_), None) | (None, Some(_)) => Err(reject_at(
                    insn,
                    "scalar floating-point pair has a non-floating transfer register",
                )),
                (None, None) => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

fn lower_memory(
    insn: &DisasmInsn,
    frame: FrameInfo,
    outgoing: &[OutgoingSlot],
) -> Result<(Option<RegRef>, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if !(2..=3).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed load or store"));
    }
    let (value, source, width): (Option<RegRef>, Source, Width) =
        if matches!(insn.mnemonic.as_str(), "ldr" | "ldur") {
            let dest: RegRef = parse_reg(operands[0])?;
            (Some(dest), Source::Imm(0), dest.width)
        } else if operands[0] == "xzr" {
            (None, Source::Imm(0), Width::W64)
        } else if operands[0] == "wzr" {
            (None, Source::Imm(0), Width::W32)
        } else {
            let src: RegRef = parse_reg(operands[0])?;
            (None, Source::Reg(src), src.width)
        };
    let (mut mem, pre_index): (MemRef, bool) = parse_memory(operands[1], width)?;
    let post_delta: Option<i64> = operands
        .get(2)
        .map(|token: &&str| parse_immediate(token))
        .transpose()?;
    if pre_index && post_delta.is_some() {
        return Err(reject_at(
            insn,
            "address cannot be both pre-indexed and post-indexed",
        ));
    }
    let mut stmts: Vec<Stmt> = Vec::new();
    if pre_index {
        let delta: i64 = mem.disp;
        mem.disp = 0;
        stmts.extend(frame_writeback(frame, mem.base, delta)?);
    }
    let outgoing_slot: Option<usize> = outgoing
        .iter()
        .find(|entry: &&OutgoingSlot| entry.memory_index == 0)
        .map(|entry: &OutgoingSlot| entry.slot);
    let memory_stmt: Stmt = if matches!(insn.mnemonic.as_str(), "ldr" | "ldur") {
        Stmt::Assign {
            dest: value.ok_or_else(|| reject_at(insn, "load destination is missing"))?,
            src: if !pre_index && post_delta.is_none() {
                load_source(mem, frame)?
            } else {
                Source::Mem(mem)
            },
        }
    } else if let Some(slot) = outgoing_slot {
        Stmt::Assign {
            dest: RegRef {
                reg: outgoing_reg(slot)?,
                width,
            },
            src: source,
        }
    } else {
        Stmt::Store {
            addr: mem,
            src: source,
        }
    };
    stmts.push(memory_stmt);
    if let Some(delta) = post_delta {
        if mem.disp != 0 {
            return Err(reject_at(
                insn,
                "post-indexed address has an inline displacement",
            ));
        }
        stmts.extend(frame_writeback(frame, mem.base, delta)?);
    }
    Ok((value, stmts))
}

fn lower_bitfield(insn: &DisasmInsn) -> Result<(RegRef, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if operands.len() != 4 {
        return Err(reject_at(insn, "malformed bitfield move"));
    }
    if matches!(insn.mnemonic.as_str(), "sbfiz" | "sbfx") {
        return Err(reject_at(insn, "signed bitfield move is unsupported"));
    }
    let dest: RegRef = parse_reg(operands[0])?;
    let source: RegRef = parse_reg(operands[1])?;
    if dest.width != source.width {
        return Err(reject_at(insn, "mixed-width bitfield move"));
    }
    let datasize: i64 = match dest.width {
        Width::W64 => 64,
        Width::W32 => 32,
        _ => return Err(reject_at(insn, "bitfield move on a sub-register")),
    };
    let lsb: i64 = parse_immediate(operands[2])?;
    let width: i64 = parse_immediate(operands[3])?;
    if lsb < 0 || width <= 0 || lsb >= datasize || width > datasize || lsb + width > datasize {
        return Err(reject_at(insn, "bitfield range is out of bounds"));
    }
    let mask: i64 = if width >= 64 {
        -1
    } else {
        ((1u64 << width) - 1) as i64
    };
    let tmp: RegRef = RegRef {
        reg: Reg::A64Tmp2,
        width: dest.width,
    };
    let mut stmts: Vec<Stmt> = vec![Stmt::Assign {
        dest: tmp,
        src: Source::Reg(source),
    }];
    if insn.mnemonic == "ubfiz" {
        if width < datasize {
            stmts.push(Stmt::BinAssign {
                dest: tmp,
                op: BinOp::And,
                src: Source::Imm(mask),
            });
        }
        if lsb > 0 {
            stmts.push(Stmt::BinAssign {
                dest: tmp,
                op: BinOp::Shl,
                src: Source::Imm(lsb),
            });
        }
    } else {
        if lsb > 0 {
            stmts.push(Stmt::BinAssign {
                dest: tmp,
                op: BinOp::Shr,
                src: Source::Imm(lsb),
            });
        }
        if lsb + width < datasize {
            stmts.push(Stmt::BinAssign {
                dest: tmp,
                op: BinOp::And,
                src: Source::Imm(mask),
            });
        }
    }
    stmts.push(Stmt::Assign {
        dest,
        src: Source::Reg(tmp),
    });
    Ok((dest, stmts))
}

fn lower_bfi(insn: &DisasmInsn) -> Result<(RegRef, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if operands.len() != 4 {
        return Err(reject_at(insn, "malformed bitfield insert"));
    }
    let dest: RegRef = parse_reg(operands[0])?;
    let source: RegRef = parse_reg(operands[1])?;
    if dest.width != source.width {
        return Err(reject_at(insn, "mixed-width bitfield insert"));
    }
    let datasize: u32 = match dest.width {
        Width::W64 => 64,
        Width::W32 => 32,
        _ => return Err(reject_at(insn, "bitfield insert on a sub-register")),
    };
    let lsb: i64 = parse_immediate(operands[2])?;
    let width: i64 = parse_immediate(operands[3])?;
    let datasize_bits: i64 = i64::from(datasize);
    if lsb < 0
        || width <= 0
        || lsb >= datasize_bits
        || width > datasize_bits
        || lsb + width > datasize_bits
    {
        return Err(reject_at(insn, "bitfield insert range is out of bounds"));
    }
    let datasize_mask: u64 = if datasize >= 64 {
        u64::MAX
    } else {
        (1u64 << datasize) - 1
    };
    let field_mask: u64 = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << (width as u32)) - 1
    };
    let positioned_mask: u64 = (field_mask << (lsb as u32)) & datasize_mask;
    let clear_mask: u64 = !positioned_mask & datasize_mask;
    let tmp: RegRef = RegRef {
        reg: Reg::A64Tmp2,
        width: dest.width,
    };
    let mut stmts: Vec<Stmt> = vec![Stmt::Assign {
        dest: tmp,
        src: Source::Reg(source),
    }];
    if lsb > 0 {
        stmts.push(Stmt::BinAssign {
            dest: tmp,
            op: BinOp::Shl,
            src: Source::Imm(lsb),
        });
    }
    stmts.push(Stmt::BinAssign {
        dest: tmp,
        op: BinOp::And,
        src: Source::Imm(i64::from_ne_bytes(positioned_mask.to_ne_bytes())),
    });
    stmts.push(Stmt::BinAssign {
        dest,
        op: BinOp::And,
        src: Source::Imm(i64::from_ne_bytes(clear_mask.to_ne_bytes())),
    });
    stmts.push(Stmt::BinAssign {
        dest,
        op: BinOp::Or,
        src: Source::Reg(tmp),
    });
    Ok((dest, stmts))
}

fn lower_pair_memory(
    insn: &DisasmInsn,
    frame: FrameInfo,
    outgoing: &[OutgoingSlot],
) -> Result<(Option<RegRef>, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if !(3..=4).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed pair load or store"));
    }
    let first: RegRef = parse_reg(operands[0])?;
    let second: RegRef = parse_reg(operands[1])?;
    if first.width != second.width {
        return Err(reject_at(insn, "mixed-width pair load or store"));
    }
    let (mut first_mem, pre_index): (MemRef, bool) = parse_memory(operands[2], first.width)?;
    let post_delta: Option<i64> = operands
        .get(3)
        .map(|token: &&str| parse_immediate(token))
        .transpose()?;
    if pre_index && post_delta.is_some() {
        return Err(reject_at(
            insn,
            "pair address cannot use two writeback modes",
        ));
    }
    let mut stmts: Vec<Stmt> = Vec::new();
    if pre_index {
        let delta: i64 = first_mem.disp;
        first_mem.disp = 0;
        stmts.extend(frame_writeback(frame, first_mem.base, delta)?);
    }
    let width_bytes: i64 = i64::from(first.width.bits() / 8);
    let second_disp: i64 = first_mem
        .disp
        .checked_add(width_bytes)
        .ok_or_else(|| reject_at(insn, "pair address overflow"))?;
    let second_mem: MemRef = MemRef {
        disp: second_disp,
        ..first_mem
    };
    if insn.mnemonic == "ldp" {
        stmts.push(Stmt::Assign {
            dest: first,
            src: if !pre_index && post_delta.is_none() {
                load_source(first_mem, frame)?
            } else {
                Source::Mem(first_mem)
            },
        });
        stmts.push(Stmt::Assign {
            dest: second,
            src: if !pre_index && post_delta.is_none() {
                load_source(second_mem, frame)?
            } else {
                Source::Mem(second_mem)
            },
        });
    } else {
        for (memory_index, addr, src) in [
            (0_usize, first_mem, Source::Reg(first)),
            (1_usize, second_mem, Source::Reg(second)),
        ] {
            if let Some(slot) = outgoing
                .iter()
                .find(|entry: &&OutgoingSlot| entry.memory_index == memory_index)
                .map(|entry: &OutgoingSlot| entry.slot)
            {
                stmts.push(Stmt::Assign {
                    dest: RegRef {
                        reg: outgoing_reg(slot)?,
                        width: first.width,
                    },
                    src,
                });
            } else {
                stmts.push(Stmt::Store { addr, src });
            }
        }
    }
    if let Some(delta) = post_delta {
        if first_mem.disp != 0 {
            return Err(reject_at(
                insn,
                "post-indexed pair has an inline displacement",
            ));
        }
        stmts.extend(frame_writeback(frame, first_mem.base, delta)?);
    }
    let dest: Option<RegRef> = if insn.mnemonic == "ldp" {
        [first, second]
            .into_iter()
            .find(|reg: &RegRef| reg.reg == Reg::Rax)
    } else {
        None
    };
    Ok((dest, stmts))
}

fn load_source(mem: MemRef, frame: FrameInfo) -> Result<Source> {
    let threshold: Option<i64> = match mem.base {
        Some(Reg::Rsp) => Some(frame.sp_to_entry),
        Some(Reg::Rbp) => frame.fp_to_entry,
        _ => None,
    };
    let Some(threshold) = threshold else {
        return Ok(Source::Mem(mem));
    };
    if mem.disp < threshold {
        return Ok(Source::Mem(mem));
    }
    let relative: i64 = mem
        .disp
        .checked_sub(threshold)
        .ok_or_else(|| reject("incoming stack offset underflow"))?;
    if relative % 8 != 0 {
        return Err(reject("incoming stack argument is not eight-byte aligned"));
    }
    let index: usize = usize::try_from(relative / 8)
        .map_err(|_| reject("incoming stack argument index overflow"))?;
    let reg: Reg = match index {
        0 => Reg::A64Stack0,
        1 => Reg::A64Stack1,
        2 => Reg::A64Stack2,
        3 => Reg::A64Stack3,
        4 => Reg::A64Stack4,
        5 => Reg::A64Stack5,
        6 => Reg::A64Stack6,
        7 => Reg::A64Stack7,
        _ => {
            return Err(reject(
                "incoming stack argument exceeds the bounded eight-slot lift",
            ));
        }
    };
    Ok(Source::Reg(RegRef {
        reg,
        width: mem.width,
    }))
}

fn outgoing_stores(
    insns: &[DisasmInsn],
    calls: &[ResolvedCall],
) -> Result<BTreeMap<usize, Vec<OutgoingSlot>>> {
    let mut stores: BTreeMap<usize, Vec<OutgoingSlot>> = BTreeMap::new();
    for (call_index, insn) in insns.iter().enumerate() {
        if insn.mnemonic != "bl" {
            continue;
        }
        let target: u64 = relative_target(insn, insn.operands.trim())?;
        let Some(call): Option<&ResolvedCall> = calls
            .iter()
            .find(|call: &&ResolvedCall| call.target == target)
        else {
            continue;
        };
        let argument_count: usize = call.signature.callable_arity();
        if argument_count <= 8 {
            continue;
        }
        let expected: usize = argument_count - 8;
        let mut found: BTreeMap<usize, (usize, OutgoingSlot)> = BTreeMap::new();
        for candidate_index in (0..call_index).rev() {
            let candidate: &DisasmInsn = &insns[candidate_index];
            if is_control_flow(candidate) {
                break;
            }
            for slot in outgoing_store_slots(candidate)? {
                if slot.slot < expected && !found.contains_key(&slot.slot) {
                    found.insert(slot.slot, (candidate_index, slot));
                }
            }
            if found.len() == expected {
                break;
            }
        }
        if found.len() != expected {
            return Err(reject_at(
                insn,
                "resolved call stack arguments lack bounded sp-relative stores",
            ));
        }
        for (_, (instruction_index, slot)) in found {
            stores.entry(instruction_index).or_default().push(slot);
        }
    }
    Ok(stores)
}

fn outgoing_store_slots(insn: &DisasmInsn) -> Result<Vec<OutgoingSlot>> {
    if is_frame_management(insn) || !matches!(insn.mnemonic.as_str(), "str" | "stp") {
        return Ok(Vec::new());
    }
    let operands: Vec<&str> = split_operands(&insn.operands);
    let (memory_operand, widths): (&str, Vec<Width>) =
        if insn.mnemonic == "str" && operands.len() == 2 {
            let width: Width = stored_width(operands[0])?;
            (operands[1], vec![width])
        } else if insn.mnemonic == "stp" && operands.len() == 3 {
            let first: RegRef = parse_reg(operands[0])?;
            let second: RegRef = parse_reg(operands[1])?;
            if first.width != second.width {
                return Err(reject_at(insn, "mixed-width pair store"));
            }
            (operands[2], vec![first.width, second.width])
        } else {
            return Ok(Vec::new());
        };
    if !memory_operand.trim().starts_with("[sp") {
        return Ok(Vec::new());
    }
    let (mem, pre_index): (MemRef, bool) = parse_memory(memory_operand, widths[0])?;
    if pre_index || mem.base != Some(Reg::Rsp) || mem.disp < 0 {
        return Ok(Vec::new());
    }
    let mut slots: Vec<OutgoingSlot> = Vec::new();
    let mut disp: i64 = mem.disp;
    for (memory_index, width) in widths.into_iter().enumerate() {
        if disp % 8 == 0 {
            let slot: usize = usize::try_from(disp / 8)
                .map_err(|_| reject_at(insn, "outgoing stack argument index overflow"))?;
            slots.push(OutgoingSlot { memory_index, slot });
        }
        disp = disp
            .checked_add(i64::from(width.bits() / 8))
            .ok_or_else(|| reject_at(insn, "outgoing pair address overflow"))?;
    }
    Ok(slots)
}

fn stored_width(token: &str) -> Result<Width> {
    match token.trim() {
        "xzr" => Ok(Width::W64),
        "wzr" => Ok(Width::W32),
        value => parse_reg(value).map(|reg: RegRef| reg.width),
    }
}

fn outgoing_reg(slot: usize) -> Result<Reg> {
    match slot {
        0 => Ok(Reg::A64Outgoing0),
        1 => Ok(Reg::A64Outgoing1),
        2 => Ok(Reg::A64Outgoing2),
        3 => Ok(Reg::A64Outgoing3),
        4 => Ok(Reg::A64Outgoing4),
        5 => Ok(Reg::A64Outgoing5),
        6 => Ok(Reg::A64Outgoing6),
        7 => Ok(Reg::A64Outgoing7),
        _ => Err(reject("outgoing stack argument exceeds the bounded lift")),
    }
}

fn is_control_flow(insn: &DisasmInsn) -> bool {
    matches!(
        insn.mnemonic.as_str(),
        "b" | "bl" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
    ) || insn.mnemonic.starts_with("b.")
}

fn frame_writeback(frame: FrameInfo, base: Option<Reg>, delta: i64) -> Result<Option<Stmt>> {
    if frame.sp_writeback_absorbed && base == Some(Reg::Rsp) {
        return Ok(None);
    }
    base_update(base, delta).map(Some)
}

fn base_update(base: Option<Reg>, delta: i64) -> Result<Stmt> {
    let reg: Reg = base.ok_or_else(|| reject("writeback address lacks a base register"))?;
    Ok(Stmt::BinAssign {
        dest: RegRef {
            reg,
            width: Width::W64,
        },
        op: BinOp::Add,
        src: Source::Imm(delta),
    })
}

fn parse_memory(token: &str, width: Width) -> Result<(MemRef, bool)> {
    let trimmed: &str = token.trim();
    let (body, pre_index): (&str, bool) = trimmed
        .strip_suffix('!')
        .map_or((trimmed, false), |rest: &str| (rest.trim(), true));
    let body: &str = body
        .strip_prefix('[')
        .and_then(|rest: &str| rest.strip_suffix(']'))
        .ok_or_else(|| reject("memory operand is not bracketed"))?;
    let terms: Vec<&str> = body.split(',').map(str::trim).collect();
    if terms.is_empty() || terms.len() > 3 {
        return Err(reject("memory operand uses unsupported addressing"));
    }
    let base: RegRef = parse_reg(terms[0])?;
    if base.width != Width::W64 {
        return Err(reject("memory base is not a 64-bit register"));
    }
    let (index, disp): (Option<IndexOperand>, i64) = match terms.get(1) {
        None => (None, 0),
        Some(term) if term.starts_with('#') => {
            if terms.len() != 2 {
                return Err(reject("memory operand uses unsupported addressing"));
            }
            (None, parse_immediate(term)?)
        }
        Some(term) => {
            let idx: RegRef = parse_reg(term)?;
            let (scale, extend): (u8, IndexExtend) = match terms.get(2) {
                None => {
                    if idx.width != Width::W64 {
                        return Err(reject("32-bit or extended index register is unsupported"));
                    }
                    (1, IndexExtend::Full)
                }
                Some(modifier) => parse_index_modifier(modifier, idx.width)?,
            };
            (
                Some(IndexOperand {
                    reg: idx.reg,
                    scale,
                    extend,
                }),
                0,
            )
        }
    };
    Ok((
        MemRef {
            base: Some(base.reg),
            index,
            disp,
            width,
        },
        pre_index,
    ))
}

fn parse_index_modifier(token: &str, index_width: Width) -> Result<(u8, IndexExtend)> {
    let trimmed: &str = token.trim();
    let (op, rest): (&str, &str) = trimmed
        .split_once(char::is_whitespace)
        .map_or((trimmed, ""), |(op, rest): (&str, &str)| {
            (op.trim(), rest.trim())
        });
    let amount: u32 = match rest.strip_prefix('#') {
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| reject("malformed memory index shift amount"))?,
        None if rest.is_empty() => 0,
        None => return Err(reject("malformed memory index shift amount")),
    };
    if amount > 4 {
        return Err(reject("memory index shift amount is out of range"));
    }
    let scale: u8 = 1u8 << amount;
    let extend: IndexExtend = match op {
        "lsl" => {
            if index_width != Width::W64 {
                return Err(reject("lsl index requires a 64-bit register"));
            }
            IndexExtend::Full
        }
        "sxtw" => {
            if index_width != Width::W32 {
                return Err(reject("sxtw index requires a 32-bit register"));
            }
            IndexExtend::SignExtendWord
        }
        "uxtw" => {
            if index_width != Width::W32 {
                return Err(reject("uxtw index requires a 32-bit register"));
            }
            IndexExtend::ZeroExtendWord
        }
        "sxtx" => {
            if index_width != Width::W64 {
                return Err(reject("sxtx index requires a 64-bit register"));
            }
            IndexExtend::Full
        }
        "uxtx" => {
            if index_width != Width::W64 {
                return Err(reject("uxtx index requires a 64-bit register"));
            }
            IndexExtend::Full
        }
        _ => return Err(reject("memory index uses an unsupported extend or shift")),
    };
    Ok((scale, extend))
}

fn is_frame_management(insn: &DisasmInsn) -> bool {
    let operands: Vec<&str> = split_operands(&insn.operands);
    match insn.mnemonic.as_str() {
        "add" | "sub" => {
            operands.len() == 3
                && ((operands[0] == "sp" && operands[1] == "sp")
                    || (insn.mnemonic == "add" && operands[0] == "x29" && operands[1] == "sp"))
                && operands[2].starts_with('#')
        }
        "mov" => matches!(operands.as_slice(), ["x29", "sp"] | ["sp", "x29"]),
        "ldp" | "stp" => {
            operands.len() >= 3
                && operands[0] == "x29"
                && operands[1] == "x30"
                && operands[2].starts_with("[sp")
        }
        _ => false,
    }
}

fn has_unsupported_register_class(operands: &str) -> bool {
    split_operands(operands).iter().any(|operand: &&str| {
        let token: &str = operand.trim().trim_start_matches('[');
        let mut chars = token.chars();
        chars.next().is_some_and(|prefix: char| {
            matches!(prefix, 'd' | 's' | 'h' | 'b' | 'z' | 'p')
                && chars.next().is_some_and(|ch: char| ch.is_ascii_digit())
        })
    })
}

fn classify_frame(insns: &[DisasmInsn], frame_info: FrameInfo) -> Result<FrameShape> {
    let rbp_is_frame: bool = insns
        .iter()
        .any(|insn: &DisasmInsn| insn.operands.contains("[x29") && !is_frame_management(insn));
    if rbp_is_frame {
        let base_to_entry: i64 = frame_info
            .fp_to_entry
            .ok_or_else(|| {
                reject(
                    "frame-pointer-relative slots lack a proven coordinate relative to the entry stack pointer",
                )
            })?;
        let stack_extent: StackFrameExtent =
            StackFrameExtent::aarch64(frame_info.frame_bytes, base_to_entry)
                .ok_or_else(|| reject("stack-frame extent coordinate overflow"))?;
        Ok(FrameShape {
            base: Some(Reg::Rbp),
            rbp_is_frame: true,
            red_zone: false,
            stack_extent: Some(stack_extent),
            stack_pointer_break: None,
        })
    } else if insns
        .iter()
        .any(|insn: &DisasmInsn| insn.operands.contains("[sp") || is_frame_management(insn))
    {
        let stack_extent: StackFrameExtent =
            StackFrameExtent::aarch64(frame_info.sp_to_entry, frame_info.sp_to_entry)
                .ok_or_else(|| reject("stack-frame extent coordinate overflow"))?;
        Ok(FrameShape {
            base: Some(Reg::Rsp),
            rbp_is_frame: false,
            red_zone: false,
            stack_extent: Some(stack_extent),
            stack_pointer_break: None,
        })
    } else {
        Ok(FrameShape {
            base: None,
            rbp_is_frame: false,
            red_zone: false,
            stack_extent: None,
            stack_pointer_break: None,
        })
    }
}

fn bin_from(dest: RegRef, lhs: RegRef, op: BinOp, rhs: Source) -> [Stmt; 3] {
    let temp: RegRef = RegRef {
        reg: Reg::A64Tmp,
        width: dest.width,
    };
    [
        Stmt::Assign {
            dest: temp,
            src: Source::Reg(lhs),
        },
        Stmt::BinAssign {
            dest: temp,
            op,
            src: rhs,
        },
        Stmt::Assign {
            dest,
            src: Source::Reg(temp),
        },
    ]
}

fn push_stmts(items: &mut Vec<Item>, base: u64, index: usize, stmts: Vec<Stmt>) -> Result<()> {
    if stmts.len() >= ITEM_STRIDE as usize {
        return Err(reject("instruction lowered beyond its item slot bound"));
    }
    for (slot, stmt) in stmts.into_iter().enumerate() {
        items.push(Item {
            address: item_address(base, index, slot)?,
            kind: ItemKind::Stmt(stmt),
        });
    }
    Ok(())
}

fn parse_source(token: &str, width: Width) -> Result<Source> {
    if token.trim().starts_with('#') {
        return parse_immediate(token).map(Source::Imm);
    }
    let reg: RegRef = parse_reg(token)?;
    if reg.width != width {
        return Err(reject("source width does not match destination width"));
    }
    Ok(Source::Reg(reg))
}

fn parse_shift_modifier(token: &str, width: Width) -> Result<(BinOp, i64)> {
    let (name, amount): (&str, &str) = token
        .trim()
        .split_once(char::is_whitespace)
        .ok_or_else(|| reject("malformed shift modifier"))?;
    let op: BinOp = match name {
        "lsl" => BinOp::Shl,
        "lsr" => BinOp::Shr,
        "asr" => BinOp::Sar,
        _ => return Err(reject("unsupported shift modifier")),
    };
    let amount: i64 = parse_immediate(amount)?;
    if amount < 0 || amount >= i64::from(width.bits()) {
        return Err(reject("shift amount is outside the register width"));
    }
    Ok((op, amount))
}

const AARCH64_EXTEND_FORMS: [(&str, bool, Width); 8] = [
    ("uxtb", false, Width::W8),
    ("uxth", false, Width::W16),
    ("uxtw", false, Width::W32),
    ("uxtx", false, Width::W64),
    ("sxtb", true, Width::W8),
    ("sxth", true, Width::W16),
    ("sxtw", true, Width::W32),
    ("sxtx", true, Width::W64),
];

const fn extend_register_class(src_width: Width) -> Width {
    match src_width {
        Width::W64 => Width::W64,
        Width::W8 | Width::W16 | Width::W32 => Width::W32,
    }
}

fn parse_extend_modifier(token: &str) -> Option<(bool, Width, i64)> {
    let trimmed: &str = token.trim();
    let (kind, rest): (&str, Option<&str>) = match trimmed.split_once(char::is_whitespace) {
        Some((name, tail)) => (name, Some(tail)),
        None => (trimmed, None),
    };
    let &(_, signed, src_width): &(&str, bool, Width) = AARCH64_EXTEND_FORMS
        .iter()
        .find(|(name, _, _): &&(&str, bool, Width)| *name == kind)?;
    let shift: i64 = match rest {
        None => 0,
        Some(tail) => {
            let value: i64 = parse_immediate(tail).ok()?;
            if !(0..=4).contains(&value) {
                return None;
            }
            value
        }
    };
    Some((signed, src_width, shift))
}

fn encoded_extended_register(insn: &DisasmInsn) -> Option<(bool, Width, i64)> {
    if !matches!(insn.mnemonic.as_str(), "add" | "adds" | "sub" | "subs") {
        return None;
    }
    let word: u32 = aarch64_instruction_word(insn)?;
    if (word >> 24) & 0b1_1111 != 0b0_1011 || (word >> 21) & 1 != 1 {
        return None;
    }
    let option: usize = ((word >> 13) & 0b111) as usize;
    let imm3: u32 = (word >> 10) & 0b111;
    if imm3 > 4 {
        return None;
    }
    let &(_, signed, src_width): &(&str, bool, Width) = AARCH64_EXTEND_FORMS.get(option)?;
    Some((signed, src_width, i64::from(imm3)))
}

fn parse_condition(suffix: &str) -> Result<CondKind> {
    match suffix {
        "eq" => Ok(CondKind::E),
        "ne" => Ok(CondKind::Ne),
        "gt" => Ok(CondKind::G),
        "ge" => Ok(CondKind::Ge),
        "lt" => Ok(CondKind::L),
        "le" => Ok(CondKind::Le),
        "hi" => Ok(CondKind::A),
        "hs" | "cs" => Ok(CondKind::Ae),
        "lo" | "cc" => Ok(CondKind::B),
        "ls" => Ok(CondKind::Be),
        "mi" => Ok(CondKind::S),
        "pl" => Ok(CondKind::Ns),
        "vs" => Ok(CondKind::Vs),
        "vc" => Ok(CondKind::Vc),
        _ => Err(reject("unsupported aarch64 condition code")),
    }
}

fn parse_immediate(token: &str) -> Result<i64> {
    let body: &str = token
        .trim()
        .strip_prefix('#')
        .ok_or_else(|| reject("immediate lacks the aarch64 marker"))?;
    let (negative, digits): (bool, &str) = body
        .strip_prefix('-')
        .map_or((false, body), |rest: &str| (true, rest));
    let magnitude: u64 = if let Some(hex) = digits.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| reject("invalid hexadecimal immediate"))?
    } else {
        digits
            .parse::<u64>()
            .map_err(|_| reject("invalid decimal immediate"))?
    };
    if negative {
        i64::try_from(magnitude)
            .ok()
            .and_then(i64::checked_neg)
            .ok_or_else(|| reject("negative immediate overflow"))
    } else {
        Ok(i64::from_ne_bytes(magnitude.to_ne_bytes()))
    }
}

fn parse_move_immediate(token: &str) -> Result<i64> {
    let body: &str = token
        .trim()
        .strip_prefix('#')
        .ok_or_else(|| reject("move immediate lacks the aarch64 marker"))?;
    if body.starts_with('-') {
        return parse_immediate(token);
    }
    if let Some(hex) = body.strip_prefix("0x") {
        let bits: u64 =
            u64::from_str_radix(hex, 16).map_err(|_| reject("invalid move immediate"))?;
        return Ok(i64::from_ne_bytes(bits.to_ne_bytes()));
    }
    body.parse::<i64>()
        .map_err(|_| reject("invalid move immediate"))
}

fn normalized_target(
    insns: &[DisasmInsn],
    base: u64,
    insn: &DisasmInsn,
    token: &str,
) -> Result<u64> {
    let target: u64 = relative_target(insn, token)?;
    let index: usize = insns
        .binary_search_by_key(&target, |candidate: &DisasmInsn| candidate.address)
        .map_err(|_| reject_at(insn, "branch target is outside the decoded function"))?;
    item_address(base, index, 0)
}

fn relative_target(insn: &DisasmInsn, token: &str) -> Result<u64> {
    let token: &str = token.trim();
    let (negative, body): (bool, &str) = token
        .strip_prefix("$+")
        .map(|rest: &str| (false, rest))
        .or_else(|| token.strip_prefix("$-").map(|rest: &str| (true, rest)))
        .ok_or_else(|| reject_at(insn, "branch target is not decoder-relative"))?;
    let magnitude: i64 = parse_unsigned_literal(body)
        .and_then(|value: u64| i64::try_from(value).ok())
        .ok_or_else(|| reject_at(insn, "branch displacement overflow"))?;
    let delta: i64 = if negative {
        magnitude
            .checked_neg()
            .ok_or_else(|| reject_at(insn, "branch displacement overflow"))?
    } else {
        magnitude
    };
    insn.address
        .checked_add_signed(delta)
        .ok_or_else(|| reject_at(insn, "branch target overflow"))
}

pub(crate) fn parse_unsigned_literal(token: &str) -> Option<u64> {
    token.strip_prefix("0x").map_or_else(
        || token.parse::<u64>().ok(),
        |hex: &str| u64::from_str_radix(hex, 16).ok(),
    )
}

fn item_address(base: u64, index: usize, slot: usize) -> Result<u64> {
    let index: u64 = u64::try_from(index).map_err(|_| reject("instruction index overflow"))?;
    let slot: u64 = u64::try_from(slot).map_err(|_| reject("instruction slot overflow"))?;
    let offset: u64 = index
        .checked_mul(ITEM_STRIDE)
        .and_then(|value: u64| value.checked_add(slot))
        .ok_or_else(|| reject("normalized instruction address overflow"))?;
    base.checked_add(offset)
        .ok_or_else(|| reject("normalized instruction address overflow"))
}

fn split_operands(operands: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut depth: usize = 0;
    let mut start: usize = 0;
    for (index, ch) in operands.char_indices() {
        match ch {
            '[' => depth = depth.saturating_add(1),
            ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(operands[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    let tail: &str = operands[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn parse_reg(token: &str) -> Result<RegRef> {
    let name: &str = token.trim();
    if name == "sp" {
        return Ok(RegRef {
            reg: Reg::Rsp,
            width: Width::W64,
        });
    }
    let (prefix, width): (&str, Width) = if let Some(rest) = name.strip_prefix('x') {
        (rest, Width::W64)
    } else if let Some(rest) = name.strip_prefix('w') {
        (rest, Width::W32)
    } else {
        return Err(reject("operand is not a supported general register"));
    };
    let reg: Reg = match prefix {
        "0" => Reg::Rax,
        "1" => Reg::A64X1,
        "2" => Reg::A64X2,
        "3" => Reg::A64X3,
        "4" => Reg::A64X4,
        "5" => Reg::A64X5,
        "6" => Reg::A64X6,
        "7" => Reg::A64X7,
        "8" => Reg::A64X8,
        "9" => Reg::A64X9,
        "10" => Reg::A64X10,
        "11" => Reg::A64X11,
        "12" => Reg::A64X12,
        "13" => Reg::A64X13,
        "14" => Reg::A64X14,
        "15" => Reg::A64X15,
        "16" => Reg::A64X16,
        "17" => Reg::A64X17,
        "18" => Reg::A64X18,
        "19" => Reg::A64X19,
        "20" => Reg::A64X20,
        "21" => Reg::A64X21,
        "22" => Reg::A64X22,
        "23" => Reg::A64X23,
        "24" => Reg::A64X24,
        "25" => Reg::A64X25,
        "26" => Reg::A64X26,
        "27" => Reg::A64X27,
        "28" => Reg::A64X28,
        "29" => Reg::Rbp,
        _ => return Err(reject("register is outside the current bounded set")),
    };
    Ok(RegRef { reg, width })
}

fn select_operand(token: &str) -> Result<(Option<Reg>, Source, Width)> {
    match token.trim() {
        "wzr" => Ok((None, Source::Imm(0), Width::W32)),
        "xzr" => Ok((None, Source::Imm(0), Width::W64)),
        other => {
            let reg: RegRef = parse_reg(other)?;
            Ok((Some(reg.reg), Source::Reg(reg), reg.width))
        }
    }
}

fn flags_reference_reg(flags: &Flags, reg: Reg) -> bool {
    match flags {
        Flags::Cmp { lhs, rhs } | Flags::Add { lhs, rhs } => {
            lhs.reg == reg || matches!(rhs, Source::Reg(source) if source.reg == reg)
        }
        Flags::Test { operand } | Flags::TestImm { operand, .. } => operand.reg == reg,
        Flags::Sign { result } => result.reg == reg,
        Flags::CondCmp { prior, taken, .. } => {
            flags_reference_reg(prior, reg) || flags_reference_reg(taken, reg)
        }
        Flags::CmpMem { lhs, rhs } => {
            let mut regs: Vec<Reg> = Vec::new();
            super::mem_regs(lhs, &mut regs);
            super::source_regs(rhs, &mut regs);
            regs.contains(&reg)
        }
        Flags::FpCmp { .. } | Flags::Snapshot { .. } => false,
    }
}

fn resolve_aarch64_flags(
    items: &mut Vec<Item>,
    live: &TrackedFlags,
    kind: CondKind,
    next_sel: &mut u32,
    addr: u64,
) -> (CondKind, Flags) {
    let gpr_deps: Vec<Reg> = super::flag_operand_regs(&live.value);
    let fp_deps: Vec<Xmm> = super::flag_operand_xmms(&live.value);
    let start: usize = live.mark.min(items.len());
    let clobbered: bool = items[start..].iter().any(|item: &Item| {
        let ItemKind::Stmt(stmt) = &item.kind else {
            return false;
        };
        super::stmt_dest_regs(stmt)
            .iter()
            .any(|reg: &Reg| gpr_deps.contains(reg))
            || (!fp_deps.is_empty() && super::stmt_clobbers_flag_fp(stmt, &fp_deps))
    });
    if !clobbered
        || (live.nz_only && !kind.sign_zero_only())
        || !condition_is_sound(kind, &live.value)
    {
        return (kind, live.value.clone());
    }
    let var: u32 = *next_sel;
    *next_sel += 1;
    let snapshot_addr: u64 = items.get(start).map_or(addr, |item: &Item| item.address);
    items.insert(
        start,
        Item {
            address: snapshot_addr,
            kind: ItemKind::Stmt(Stmt::FlagSnapshot {
                var,
                kind,
                flags: live.value.clone(),
            }),
        },
    );
    (CondKind::Ne, Flags::Snapshot { var })
}

fn build_select_stmts(
    dest: RegRef,
    n_reg: Option<Reg>,
    n_src: Source,
    m_reg: Option<Reg>,
    m_src: Source,
    kind: CondKind,
    live_flags: &TrackedFlags,
    next_sel: &mut u32,
) -> Result<Vec<Stmt>> {
    if (live_flags.nz_only && !kind.sign_zero_only())
        || !condition_is_sound(kind, &live_flags.value)
    {
        return Err(reject("condition is undefined for the tracked nzcv source"));
    }
    let flags_value: Flags = live_flags.value.clone();
    let stmts: Vec<Stmt> = if m_reg == Some(dest.reg) {
        vec![Stmt::Cond {
            dest,
            src: n_src,
            kind,
            flags: flags_value,
        }]
    } else if n_reg == Some(dest.reg) {
        vec![Stmt::Cond {
            dest,
            src: m_src,
            kind: kind.negate(),
            flags: flags_value,
        }]
    } else if flags_reference_reg(&flags_value, dest.reg) {
        let var: u32 = *next_sel;
        *next_sel += 1;
        vec![
            Stmt::FlagSnapshot {
                var,
                kind,
                flags: flags_value,
            },
            Stmt::Assign { dest, src: m_src },
            Stmt::Cond {
                dest,
                src: n_src,
                kind: CondKind::Ne,
                flags: Flags::Snapshot { var },
            },
        ]
    } else {
        vec![
            Stmt::Assign { dest, src: m_src },
            Stmt::Cond {
                dest,
                src: n_src,
                kind,
                flags: flags_value,
            },
        ]
    };
    Ok(stmts)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VectorRet {
    None,
    Void,
    Vector(VecArrangement),
}

#[derive(Debug, Clone)]
struct VectorAbi {
    params: Vec<(u8, VecArrangement)>,
    ret: VectorRet,
}

const SIMD_RETURN_REG: u8 = 0;

fn operand_is_vector(insn: &DisasmInsn) -> bool {
    let operands: Vec<&str> = split_operands(&insn.operands);
    let Some(first): Option<&&str> = operands.first() else {
        return false;
    };
    let token: &str = first.trim();
    token.starts_with('{') || is_vector_register_token(token) || is_qreg_token(token)
}

fn instruction_has_vector_syntax(insn: &DisasmInsn) -> bool {
    split_operands(&insn.operands).iter().any(|operand: &&str| {
        let token: &str = operand.trim().trim_start_matches('{');
        is_vector_register_token(token) || is_qreg_token(token)
    })
}

fn has_bulk_q_spill(insns: &[DisasmInsn]) -> bool {
    let mut stored: usize = 0;
    for insn in insns {
        let operands: Vec<&str> = split_operands(&insn.operands);
        let count: usize = match insn.mnemonic.as_str() {
            "str"
                if operands.len() == 2
                    && operands[1].trim().starts_with("[sp")
                    && parse_qreg(operands[0]).is_some_and(|register: u8| register <= 7) =>
            {
                1
            }
            "stp"
                if operands.len() == 3
                    && operands[2].trim().starts_with("[sp")
                    && parse_qreg(operands[0]).is_some_and(|register: u8| register <= 7)
                    && parse_qreg(operands[1]).is_some_and(|register: u8| register <= 7) =>
            {
                2
            }
            _ => 0,
        };
        stored = stored.saturating_add(count);
        if stored >= 2 {
            return true;
        }
    }
    false
}

fn is_vector_register_token(token: &str) -> bool {
    let mut chars = token.trim().chars();
    chars.next() == Some('v') && chars.next().is_some_and(|ch: char| ch.is_ascii_digit())
}

fn is_qreg_token(token: &str) -> bool {
    let mut chars = token.trim().chars();
    chars.next() == Some('q') && chars.next().is_some_and(|ch: char| ch.is_ascii_digit())
}

fn parse_scalar_simd(token: &str) -> Result<(u8, VecElem)> {
    let token: &str = token.trim();
    if token.contains('.') || token.contains('[') {
        return Err(reject("operand is not a plain scalar SIMD register"));
    }
    let (letter, digits): (&str, &str) = token.split_at(1);
    let elem: VecElem = match letter {
        "b" => VecElem::I8,
        "h" => VecElem::I16,
        "s" => VecElem::I32,
        "d" => VecElem::I64,
        _ => return Err(reject("operand is not a scalar SIMD register")),
    };
    let index: u8 = digits
        .parse::<u8>()
        .ok()
        .filter(|value: &u8| *value < 32)
        .ok_or_else(|| reject("scalar SIMD register is outside v0..v31"))?;
    Ok((index, elem))
}

fn try_lower_scalar_simd(insn: &DisasmInsn) -> Result<Option<Vec<Stmt>>> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    match insn.mnemonic.as_str() {
        "addv" | "smaxv" | "sminv" | "umaxv" | "uminv" | "saddlv" | "uaddlv" | "addp" => {
            let Some(first): Option<&&str> = operands.first() else {
                return Ok(None);
            };
            if parse_scalar_simd(first).is_err() {
                return Ok(None);
            }
            Ok(Some(lower_reduce(insn, &operands)?))
        }
        "fmov" => lower_scalar_fmov(&operands),
        _ => Ok(None),
    }
}

fn lower_reduce(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(insn, "malformed SIMD reduction"));
    }
    let (dest_reg, dest_elem): (u8, VecElem) = parse_scalar_simd(operands[0])?;
    let (src, src_arr): (u8, VecArrangement) = parse_vector_operand(operands[1], false)?;
    if dest_reg != src {
        return Err(reject_at(
            insn,
            "SIMD reduction destination and source must be the same register",
        ));
    }
    if src_arr.total_bits() != 128 {
        return Err(reject_at(
            insn,
            "SIMD reduction source is not a 128-bit arrangement",
        ));
    }
    let op: ReduceOp = match insn.mnemonic.as_str() {
        "addv" | "smaxv" | "sminv" | "umaxv" | "uminv" => {
            if dest_elem != src_arr.elem {
                return Err(reject_at(insn, "SIMD reduction changes element width"));
            }
            match insn.mnemonic.as_str() {
                "smaxv" => ReduceOp::Smax,
                "sminv" => ReduceOp::Smin,
                "umaxv" => ReduceOp::Umax,
                "uminv" => ReduceOp::Umin,
                _ => ReduceOp::Add,
            }
        }
        "saddlv" | "uaddlv" => {
            if dest_elem.bits() != src_arr.elem.bits() * 2 {
                return Err(reject_at(
                    insn,
                    "widening reduction has an unexpected destination width",
                ));
            }
            if insn.mnemonic == "saddlv" {
                ReduceOp::Saddl
            } else {
                ReduceOp::Uaddl
            }
        }
        "addp" => {
            if src_arr.elem != VecElem::I64 || src_arr.lanes != 2 || dest_elem != VecElem::I64 {
                return Err(reject_at(
                    insn,
                    "scalar addp is only the 2d pairwise-sum form",
                ));
            }
            ReduceOp::Add
        }
        _ => return Err(reject_at(insn, "unsupported SIMD reduction")),
    };
    Ok(vec![Stmt::Vector(VecStmt::Reduce {
        reg: src,
        op,
        src: src_arr,
        dest: dest_elem,
    })])
}

fn lower_scalar_fmov(operands: &[&str]) -> Result<Option<Vec<Stmt>>> {
    if operands.len() != 2 {
        return Ok(None);
    }
    let Ok(dest): Result<RegRef> = parse_reg(operands[0]) else {
        return Ok(None);
    };
    let Ok((src, elem)): Result<(u8, VecElem)> = parse_scalar_simd(operands[1]) else {
        return Ok(None);
    };
    let matched: bool = matches!(
        (dest.width, elem),
        (Width::W32, VecElem::I32) | (Width::W64, VecElem::I64)
    );
    if !matched {
        return Ok(None);
    }
    Ok(Some(vec![Stmt::Vector(VecStmt::ExtractToGpr {
        dest,
        src,
        elem,
    })]))
}

fn lower_vector(insn: &DisasmInsn, frame: FrameInfo) -> Result<Vec<Stmt>> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    match insn.mnemonic.as_str() {
        "add" | "sub" | "mul" | "and" | "orr" | "eor" | "bic" | "smax" | "smin" | "umax"
        | "umin" => vector_bin(insn, &operands, false),
        "fadd" | "fsub" | "fmul" | "fdiv" => vector_bin(insn, &operands, true),
        "cmeq" => vector_compare(insn, &operands),
        "movi" => vector_moveimm(insn, &operands),
        "ldr" => vector_load_store(insn, &operands, true, frame),
        "str" => vector_load_store(insn, &operands, false, frame),
        "ldp" => vector_load_pair(insn, &operands),
        "stp" => vector_store_pair(insn, &operands),
        "sshll" | "sshll2" | "ushll" | "ushll2" => vector_widen_extend(insn, &operands),
        "saddl" | "saddl2" | "uaddl" | "uaddl2" => vector_widen_add(insn, &operands),
        "dup" => vector_dup(insn, &operands),
        "mov" => vector_mov(insn, &operands),
        _ => Err(reject_at(insn, "unsupported instruction")),
    }
}

fn vector_mov(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(insn, "unsupported instruction"));
    }
    if operands[0].contains('[') {
        return vector_lane_insert(insn, operands);
    }
    let (dest, dest_arr): (u8, VecArrangement) = parse_vector_operand(operands[0], false)?;
    let (src, src_arr): (u8, VecArrangement) = parse_vector_operand(operands[1], false)?;
    if dest_arr.elem != VecElem::I8 || dest_arr != src_arr {
        return Err(reject_at(insn, "unsupported instruction"));
    }
    Ok(vec![Stmt::Vector(VecStmt::Bin {
        dest,
        lhs: src,
        rhs: src,
        op: VecBinOp::Or,
        arr: dest_arr,
    })])
}

fn vector_lane_insert(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    let (dest, lane, elem): (u8, u8, VecElem) = parse_vector_lane_operand(operands[0])?;
    if operands[1].contains('.') || operands[1].contains('[') {
        return Err(reject_at(
            insn,
            "vector lane-to-lane element move is outside the supported subset",
        ));
    }
    let src: RegRef = parse_reg(operands[1])
        .map_err(|_| reject_at(insn, "vector lane insert source is not a general register"))?;
    let expected: Width = if elem == VecElem::I64 {
        Width::W64
    } else {
        Width::W32
    };
    if src.width != expected {
        return Err(reject_at(
            insn,
            "vector lane insert source width does not match the element form",
        ));
    }
    let arr: VecArrangement = VecArrangement::whole_register(elem);
    if u16::from(lane) >= u16::from(arr.lanes) {
        return Err(reject_at(
            insn,
            "vector lane index is outside the arrangement",
        ));
    }
    Ok(vec![Stmt::Vector(VecStmt::LaneInsert {
        dest,
        lane,
        src,
        arr,
    })])
}

fn parse_vector_lane_operand(token: &str) -> Result<(u8, u8, VecElem)> {
    let (register, suffix): (&str, &str) = token
        .trim()
        .split_once('.')
        .ok_or_else(|| reject("vector lane operand lacks an arrangement suffix"))?;
    let number: &str = register
        .strip_prefix('v')
        .ok_or_else(|| reject("vector lane operand is not a v register"))?;
    let reg: u8 = number
        .parse::<u8>()
        .ok()
        .filter(|value: &u8| *value < 32)
        .ok_or_else(|| reject("vector register is outside v0..v31"))?;
    let (letter, rest): (&str, &str) = suffix
        .split_once('[')
        .ok_or_else(|| reject("vector lane operand lacks a lane index"))?;
    let index_text: &str = rest
        .strip_suffix(']')
        .ok_or_else(|| reject("vector lane operand lane index is malformed"))?;
    let lane: u8 = index_text
        .trim()
        .parse::<u8>()
        .map_err(|_| reject("vector lane index is not a small integer"))?;
    let elem: VecElem = match letter.trim() {
        "b" => VecElem::I8,
        "h" => VecElem::I16,
        "s" => VecElem::I32,
        "d" => VecElem::I64,
        _ => {
            return Err(reject(
                "vector lane element type is outside the supported subset",
            ));
        }
    };
    Ok((reg, lane, elem))
}

fn vector_bin(insn: &DisasmInsn, operands: &[&str], float: bool) -> Result<Vec<Stmt>> {
    if operands.len() != 3 {
        return Err(reject_at(insn, "malformed vector arithmetic instruction"));
    }
    let (dest, dest_arr): (u8, VecArrangement) = parse_vector_operand(operands[0], float)?;
    let (lhs, lhs_arr): (u8, VecArrangement) = parse_vector_operand(operands[1], float)?;
    let (rhs, rhs_arr): (u8, VecArrangement) = parse_vector_operand(operands[2], float)?;
    if dest_arr != lhs_arr || dest_arr != rhs_arr {
        return Err(reject_at(insn, "mixed-arrangement vector arithmetic"));
    }
    let op: VecBinOp = match insn.mnemonic.as_str() {
        "add" | "fadd" => VecBinOp::Add,
        "sub" | "fsub" => VecBinOp::Sub,
        "mul" | "fmul" => VecBinOp::Mul,
        "fdiv" => VecBinOp::Div,
        "and" => VecBinOp::And,
        "orr" => VecBinOp::Or,
        "eor" => VecBinOp::Xor,
        "bic" => VecBinOp::AndNot,
        "smax" => VecBinOp::Smax,
        "smin" => VecBinOp::Smin,
        "umax" => VecBinOp::Umax,
        "umin" => VecBinOp::Umin,
        _ => return Err(reject_at(insn, "unsupported vector arithmetic")),
    };
    Ok(vec![Stmt::Vector(VecStmt::Bin {
        dest,
        lhs,
        rhs,
        op,
        arr: dest_arr,
    })])
}

fn vector_compare(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 3 {
        return Err(reject_at(insn, "malformed vector compare instruction"));
    }
    let (dest, dest_arr): (u8, VecArrangement) = parse_vector_operand(operands[0], false)?;
    let (lhs, lhs_arr): (u8, VecArrangement) = parse_vector_operand(operands[1], false)?;
    if dest_arr != lhs_arr {
        return Err(reject_at(insn, "mixed-arrangement vector compare"));
    }
    let rhs: Option<u8> = if matches!(operands[2], "#0" | "#0x0" | "#0.0") {
        None
    } else {
        let (reg, rhs_arr): (u8, VecArrangement) = parse_vector_operand(operands[2], false)?;
        if rhs_arr != dest_arr {
            return Err(reject_at(insn, "mixed-arrangement vector compare"));
        }
        Some(reg)
    };
    Ok(vec![Stmt::Vector(VecStmt::Compare {
        dest,
        lhs,
        rhs,
        arr: dest_arr,
    })])
}

fn vector_moveimm(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(insn, "malformed vector move-immediate"));
    }
    let (dest, arr): (u8, VecArrangement) = parse_vector_operand(operands[0], false)?;
    let imm: i64 = parse_immediate(operands[1])?;
    Ok(vec![Stmt::Vector(VecStmt::MoveImm { dest, imm, arr })])
}

fn vector_load_store(
    insn: &DisasmInsn,
    operands: &[&str],
    is_load: bool,
    frame: FrameInfo,
) -> Result<Vec<Stmt>> {
    if !(2..=3).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed vector load or store"));
    }
    let (reg, access_arr): (u8, Option<VecArrangement>) =
        if let Some(index) = parse_qreg(operands[0]) {
            (index, None)
        } else if let Some(index) = parse_dreg(operands[0]) {
            (index, Some(VEC_DOUBLEWORD_BYTES))
        } else {
            return Err(reject_at(
                insn,
                "vector load or store requires a q or d register",
            ));
        };
    let (mut mem, pre_index): (MemRef, bool) = parse_memory(operands[1], Width::W64)?;
    let post_delta: Option<i64> = operands
        .get(2)
        .map(|token: &&str| parse_immediate(token))
        .transpose()?;
    if pre_index && post_delta.is_some() {
        return Err(reject_at(
            insn,
            "vector address cannot be both pre-indexed and post-indexed",
        ));
    }
    let mut stmts: Vec<Stmt> = Vec::new();
    if pre_index {
        let delta: i64 = mem.disp;
        mem.disp = 0;
        stmts.extend(frame_writeback(frame, mem.base, delta)?);
    }
    let access: MemRef = mem;
    let memory_stmt: Stmt = if is_load {
        Stmt::Vector(VecStmt::Load {
            dest: reg,
            arr: access_arr,
            addr: access,
        })
    } else {
        Stmt::Vector(VecStmt::Store {
            src: reg,
            arr: access_arr,
            addr: access,
        })
    };
    stmts.push(memory_stmt);
    if let Some(delta) = post_delta {
        if mem.disp != 0 {
            return Err(reject_at(
                insn,
                "post-indexed vector address has an inline displacement",
            ));
        }
        stmts.extend(frame_writeback(frame, mem.base, delta)?);
    }
    Ok(stmts)
}

fn vector_widen_extend(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 3 {
        return Err(reject_at(insn, "malformed widening shift-left-long"));
    }
    let (dest, dest_arr): (u8, VecArrangement) = parse_vector_operand(operands[0], false)?;
    let (src, src_arr): (u8, VecArrangement) = parse_vector_operand(operands[1], false)?;
    if dest_arr.total_bits() != 128 || dest_arr.elem.bits() != src_arr.elem.bits() * 2 {
        return Err(reject_at(
            insn,
            "widening shift-left-long is not a 2x extend",
        ));
    }
    let shift: i64 = parse_immediate(operands[2])?;
    if shift < 0 || shift >= i64::from(src_arr.elem.bits()) {
        return Err(reject_at(insn, "widening shift amount is out of range"));
    }
    let signed: bool = insn.mnemonic.starts_with('s');
    let high: bool = insn.mnemonic.ends_with('2');
    Ok(vec![Stmt::Vector(VecStmt::WidenExtend {
        dest,
        src,
        src_elem: src_arr.elem,
        dest_elem: dest_arr.elem,
        signed,
        high,
        shift: shift as u8,
    })])
}

fn vector_widen_add(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 3 {
        return Err(reject_at(insn, "malformed widening add-long"));
    }
    let (dest, dest_arr): (u8, VecArrangement) = parse_vector_operand(operands[0], false)?;
    let (src1, s1_arr): (u8, VecArrangement) = parse_vector_operand(operands[1], false)?;
    let (src2, s2_arr): (u8, VecArrangement) = parse_vector_operand(operands[2], false)?;
    if s1_arr.elem != s2_arr.elem {
        return Err(reject_at(insn, "widening add-long has mixed source widths"));
    }
    if dest_arr.total_bits() != 128 || dest_arr.elem.bits() != s1_arr.elem.bits() * 2 {
        return Err(reject_at(insn, "widening add-long is not a 2x extend"));
    }
    let signed: bool = insn.mnemonic.starts_with('s');
    let high: bool = insn.mnemonic.ends_with('2');
    Ok(vec![Stmt::Vector(VecStmt::WidenAdd {
        dest,
        src1,
        src2,
        src_elem: s1_arr.elem,
        dest_elem: dest_arr.elem,
        signed,
        high,
    })])
}

fn vector_load_pair(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if !(3..=4).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed vector load pair"));
    }
    let reg1: u8 = parse_qreg(operands[0])
        .ok_or_else(|| reject_at(insn, "vector load pair requires q registers"))?;
    let reg2: u8 = parse_qreg(operands[1])
        .ok_or_else(|| reject_at(insn, "vector load pair requires q registers"))?;
    let (mut mem, pre_index): (MemRef, bool) = parse_memory(operands[2], Width::W64)?;
    let post_delta: Option<i64> = operands
        .get(3)
        .map(|token: &&str| parse_immediate(token))
        .transpose()?;
    if pre_index && post_delta.is_some() {
        return Err(reject_at(
            insn,
            "vector address cannot be both pre-indexed and post-indexed",
        ));
    }
    let mut stmts: Vec<Stmt> = Vec::new();
    if pre_index {
        let delta: i64 = mem.disp;
        mem.disp = 0;
        stmts.push(base_update(mem.base, delta)?);
    }
    let first: MemRef = mem;
    let second: MemRef = MemRef {
        disp: mem.disp + 16,
        ..mem
    };
    stmts.push(Stmt::Vector(VecStmt::Load {
        dest: reg1,
        arr: None,
        addr: first,
    }));
    stmts.push(Stmt::Vector(VecStmt::Load {
        dest: reg2,
        arr: None,
        addr: second,
    }));
    if let Some(delta) = post_delta {
        if mem.disp != 0 {
            return Err(reject_at(
                insn,
                "post-indexed vector address has an inline displacement",
            ));
        }
        stmts.push(base_update(mem.base, delta)?);
    }
    Ok(stmts)
}

fn vector_store_pair(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if !(3..=4).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed vector store pair"));
    }
    let reg1: u8 = parse_qreg(operands[0])
        .ok_or_else(|| reject_at(insn, "vector store pair requires q registers"))?;
    let reg2: u8 = parse_qreg(operands[1])
        .ok_or_else(|| reject_at(insn, "vector store pair requires q registers"))?;
    let (mut mem, pre_index): (MemRef, bool) = parse_memory(operands[2], Width::W64)?;
    let post_delta: Option<i64> = operands
        .get(3)
        .map(|token: &&str| parse_immediate(token))
        .transpose()?;
    if pre_index && post_delta.is_some() {
        return Err(reject_at(
            insn,
            "vector address cannot be both pre-indexed and post-indexed",
        ));
    }
    let mut stmts: Vec<Stmt> = Vec::new();
    if pre_index {
        let delta: i64 = mem.disp;
        mem.disp = 0;
        stmts.push(base_update(mem.base, delta)?);
    }
    let first: MemRef = mem;
    let second: MemRef = MemRef {
        disp: mem.disp + 16,
        ..mem
    };
    stmts.push(Stmt::Vector(VecStmt::Store {
        src: reg1,
        arr: None,
        addr: first,
    }));
    stmts.push(Stmt::Vector(VecStmt::Store {
        src: reg2,
        arr: None,
        addr: second,
    }));
    if let Some(delta) = post_delta {
        if mem.disp != 0 {
            return Err(reject_at(
                insn,
                "post-indexed vector address has an inline displacement",
            ));
        }
        stmts.push(base_update(mem.base, delta)?);
    }
    Ok(stmts)
}

fn vector_dup(insn: &DisasmInsn, operands: &[&str]) -> Result<Vec<Stmt>> {
    if operands.len() != 2 {
        return Err(reject_at(insn, "malformed vector duplicate"));
    }
    let (dest, arr): (u8, VecArrangement) = parse_vector_operand(operands[0], false)?;
    let src: RegRef = parse_reg(operands[1])
        .map_err(|_| reject_at(insn, "vector duplicate source is not a general register"))?;
    let lane_bits: u32 = arr.elem.bits();
    if src.width.bits() != lane_bits {
        return Err(reject_at(
            insn,
            "vector duplicate source width does not match the lane width",
        ));
    }
    Ok(vec![Stmt::Vector(VecStmt::Dup { dest, src, arr })])
}

fn parse_qreg(token: &str) -> Option<u8> {
    let number: &str = token.trim().strip_prefix('q')?;
    let index: u8 = number.parse::<u8>().ok()?;
    (index < 32).then_some(index)
}

fn parse_dreg(token: &str) -> Option<u8> {
    let number: &str = token.trim().strip_prefix('d')?;
    let index: u8 = number.parse::<u8>().ok()?;
    (index < 32).then_some(index)
}

fn first_operand_is_scalar_dreg(operands: &str) -> bool {
    split_operands(operands)
        .first()
        .and_then(|token: &&str| parse_dreg(token))
        .is_some()
}

fn is_dreg_post_indexed(operands: &str) -> bool {
    let tokens: Vec<&str> = split_operands(operands);
    tokens.len() == 3
        && tokens
            .first()
            .and_then(|token: &&str| parse_dreg(token))
            .is_some()
        && tokens
            .get(2)
            .is_some_and(|token: &&str| token.trim().starts_with('#'))
}

fn parse_vector_operand(token: &str, float: bool) -> Result<(u8, VecArrangement)> {
    let (register, suffix): (&str, &str) = token
        .trim()
        .split_once('.')
        .ok_or_else(|| reject("vector operand lacks an arrangement suffix"))?;
    let number: &str = register
        .strip_prefix('v')
        .ok_or_else(|| reject("vector operand is not a v register"))?;
    let index: u8 = number
        .parse::<u8>()
        .ok()
        .filter(|value: &u8| *value < 32)
        .ok_or_else(|| reject("vector register is outside v0..v31"))?;
    let arrangement: VecArrangement = parse_arrangement(suffix, float)?;
    Ok((index, arrangement))
}

fn parse_arrangement(suffix: &str, float: bool) -> Result<VecArrangement> {
    let suffix: &str = suffix.trim();
    if suffix.contains('[') {
        return Err(reject(
            "vector lane-indexed operand is outside the supported subset",
        ));
    }
    let split: usize = suffix
        .char_indices()
        .find(|(_, ch): &(usize, char)| ch.is_ascii_alphabetic())
        .map(|(index, _): (usize, char)| index)
        .ok_or_else(|| reject("vector arrangement lacks an element letter"))?;
    let (digits, letter): (&str, &str) = suffix.split_at(split);
    let lanes: u8 = digits
        .parse::<u8>()
        .ok()
        .filter(|value: &u8| *value > 0)
        .ok_or_else(|| reject("vector arrangement lane count is malformed"))?;
    let elem: VecElem = match (letter, float) {
        ("b", false) => VecElem::I8,
        ("h", false) => VecElem::I16,
        ("s", false) => VecElem::I32,
        ("s", true) => VecElem::F32,
        ("d", false) => VecElem::I64,
        ("d", true) => VecElem::F64,
        _ => {
            return Err(reject(
                "vector element type is outside the supported subset",
            ));
        }
    };
    let arrangement: VecArrangement = VecArrangement { lanes, elem };
    if arrangement.total_bits() != 64 && arrangement.total_bits() != 128 {
        return Err(reject(
            "vector arrangement is not a 64-bit or 128-bit register shape",
        ));
    }
    Ok(arrangement)
}

fn read_remap(
    reg: &mut u8,
    arr: VecArrangement,
    live: &[u8; 32],
    arr_at: &mut BTreeMap<u8, VecArrangement>,
) {
    let phys: u8 = *reg;
    if phys < 32 {
        let idx: u8 = live[usize::from(phys)];
        arr_at.entry(idx).or_insert(arr);
        *reg = idx;
    }
}

fn remap_current(reg: &mut u8, live: &[u8; 32]) {
    let phys: u8 = *reg;
    if phys < 32 {
        *reg = live[usize::from(phys)];
    }
}

fn write_remap(
    reg: &mut u8,
    new_arr: VecArrangement,
    live: &mut [u8; 32],
    arr_at: &mut BTreeMap<u8, VecArrangement>,
    next_syn: &mut u8,
) -> Result<()> {
    let phys: u8 = *reg;
    if phys >= 32 {
        return Ok(());
    }
    let cur: u8 = live[usize::from(phys)];
    if arr_at
        .get(&cur)
        .is_some_and(|existing: &VecArrangement| *existing != new_arr)
    {
        let syn: u8 = *next_syn;
        *next_syn = next_syn
            .checked_add(1)
            .ok_or_else(|| reject("too many widened vector register versions"))?;
        live[usize::from(phys)] = syn;
        arr_at.insert(syn, new_arr);
        *reg = syn;
    } else {
        arr_at.insert(cur, new_arr);
        *reg = cur;
    }
    Ok(())
}

fn remap_vec_stmt(
    vec: &mut VecStmt,
    live: &mut [u8; 32],
    arr_at: &mut BTreeMap<u8, VecArrangement>,
    next_syn: &mut u8,
) -> Result<()> {
    match vec {
        VecStmt::Bin {
            dest, lhs, rhs, op, ..
        } if op.is_bitwise() => {
            remap_current(lhs, live);
            remap_current(rhs, live);
            remap_current(dest, live);
        }
        VecStmt::Bin {
            dest,
            lhs,
            rhs,
            arr,
            ..
        } => {
            read_remap(lhs, *arr, live, arr_at);
            read_remap(rhs, *arr, live, arr_at);
            write_remap(dest, *arr, live, arr_at, next_syn)?;
        }
        VecStmt::Compare {
            dest,
            lhs,
            rhs,
            arr,
        } => {
            read_remap(lhs, *arr, live, arr_at);
            if let Some(rhs) = rhs {
                read_remap(rhs, *arr, live, arr_at);
            }
            write_remap(dest, *arr, live, arr_at, next_syn)?;
        }
        VecStmt::Dup { dest, arr, .. } => {
            write_remap(dest, *arr, live, arr_at, next_syn)?;
        }
        VecStmt::LaneInsert { dest, arr, .. } => {
            read_remap(dest, *arr, live, arr_at);
            write_remap(dest, *arr, live, arr_at, next_syn)?;
        }
        VecStmt::MoveImm { dest, imm, .. } if *imm == 0 => {
            remap_current(dest, live);
        }
        VecStmt::MoveImm { dest, arr, .. } => {
            write_remap(dest, *arr, live, arr_at, next_syn)?;
        }
        VecStmt::Load { dest, .. } => {
            if *dest < 32 {
                *dest = live[usize::from(*dest)];
            }
        }
        VecStmt::Store { src, .. } => {
            if *src < 32 {
                *src = live[usize::from(*src)];
            }
        }
        VecStmt::Reduce { reg, src, .. } => {
            read_remap(reg, *src, live, arr_at);
        }
        VecStmt::ExtractToGpr { src, elem, .. } => {
            read_remap(src, VecArrangement::whole_register(*elem), live, arr_at);
        }
        VecStmt::WidenExtend {
            dest,
            src,
            src_elem,
            dest_elem,
            ..
        } => {
            read_remap(src, VecArrangement::whole_register(*src_elem), live, arr_at);
            write_remap(
                dest,
                VecArrangement::whole_register(*dest_elem),
                live,
                arr_at,
                next_syn,
            )?;
        }
        VecStmt::WidenAdd {
            dest,
            src1,
            src2,
            src_elem,
            dest_elem,
            ..
        } => {
            let src_arr: VecArrangement = VecArrangement::whole_register(*src_elem);
            read_remap(src1, src_arr, live, arr_at);
            read_remap(src2, src_arr, live, arr_at);
            write_remap(
                dest,
                VecArrangement::whole_register(*dest_elem),
                live,
                arr_at,
                next_syn,
            )?;
        }
    }
    Ok(())
}

fn version_widened_registers(items: &mut [Item]) -> Result<()> {
    let mut live: [u8; 32] = core::array::from_fn(|index: usize| index as u8);
    let mut arr_at: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    let mut next_syn: u8 = 32;
    for item in items.iter_mut() {
        let ItemKind::Stmt(Stmt::Vector(vec)) = &mut item.kind else {
            continue;
        };
        remap_vec_stmt(vec, &mut live, &mut arr_at, &mut next_syn)?;
    }
    Ok(())
}

fn resolve_vector_types(items: &mut [Item]) -> Result<()> {
    let mut exact: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    let mut width: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    for item in items.iter() {
        let ItemKind::Stmt(Stmt::Vector(vec)) = &item.kind else {
            continue;
        };
        match vec {
            VecStmt::Bin {
                dest,
                lhs,
                rhs,
                op,
                arr,
            } if op.is_bitwise() => {
                note_vec_width(&mut width, *dest, *arr)?;
                note_vec_width(&mut width, *lhs, *arr)?;
                note_vec_width(&mut width, *rhs, *arr)?;
            }
            VecStmt::Bin {
                dest,
                lhs,
                rhs,
                arr,
                ..
            } => {
                note_vec_exact(&mut exact, *dest, *arr)?;
                note_vec_exact(&mut exact, *lhs, *arr)?;
                note_vec_exact(&mut exact, *rhs, *arr)?;
            }
            VecStmt::Compare {
                dest,
                lhs,
                rhs,
                arr,
            } => {
                note_vec_exact(&mut exact, *dest, *arr)?;
                note_vec_exact(&mut exact, *lhs, *arr)?;
                if let Some(rhs) = rhs {
                    note_vec_exact(&mut exact, *rhs, *arr)?;
                }
            }
            VecStmt::Dup { dest, arr, .. } => note_vec_exact(&mut exact, *dest, *arr)?,
            VecStmt::LaneInsert { dest, arr, .. } => note_vec_exact(&mut exact, *dest, *arr)?,
            VecStmt::MoveImm { dest, imm, arr, .. } if *imm == 0 => {
                note_vec_width(&mut width, *dest, *arr)?;
            }
            VecStmt::MoveImm { dest, arr, .. } => note_vec_exact(&mut exact, *dest, *arr)?,
            VecStmt::Load {
                dest,
                arr: Some(arr),
                ..
            } if arr.total_bits() == 64 => note_vec_width(&mut width, *dest, VEC_WHOLE_BYTES)?,
            VecStmt::Store {
                src,
                arr: Some(arr),
                ..
            } if arr.total_bits() == 64 => note_vec_width(&mut width, *src, VEC_WHOLE_BYTES)?,
            VecStmt::Load {
                dest,
                arr: Some(arr),
                ..
            } => note_vec_exact(&mut exact, *dest, *arr)?,
            VecStmt::Store {
                src,
                arr: Some(arr),
                ..
            } => note_vec_exact(&mut exact, *src, *arr)?,
            VecStmt::Load {
                dest, arr: None, ..
            } => note_vec_width(&mut width, *dest, VEC_WHOLE_BYTES)?,
            VecStmt::Store { src, arr: None, .. } => {
                note_vec_width(&mut width, *src, VEC_WHOLE_BYTES)?;
            }
            VecStmt::Reduce { reg, src, .. } => note_vec_exact(&mut exact, *reg, *src)?,
            VecStmt::ExtractToGpr { .. } => {}
            VecStmt::WidenExtend {
                dest,
                src,
                src_elem,
                dest_elem,
                ..
            } => {
                note_vec_exact(
                    &mut exact,
                    *dest,
                    VecArrangement::whole_register(*dest_elem),
                )?;
                note_vec_exact(&mut exact, *src, VecArrangement::whole_register(*src_elem))?;
            }
            VecStmt::WidenAdd {
                dest,
                src1,
                src2,
                src_elem,
                dest_elem,
                ..
            } => {
                note_vec_exact(
                    &mut exact,
                    *dest,
                    VecArrangement::whole_register(*dest_elem),
                )?;
                note_vec_exact(&mut exact, *src1, VecArrangement::whole_register(*src_elem))?;
                note_vec_exact(&mut exact, *src2, VecArrangement::whole_register(*src_elem))?;
            }
        }
    }
    let mut resolved: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    for (reg, arr) in &exact {
        if let Some(only) = width.get(reg)
            && only.total_bits() != arr.total_bits()
        {
            return Err(reject(
                "vector register mixes a bitwise width with a lane-typed width",
            ));
        }
        resolved.insert(*reg, *arr);
    }
    for (reg, arr) in &width {
        resolved.entry(*reg).or_insert(*arr);
    }
    for item in items.iter_mut() {
        let ItemKind::Stmt(Stmt::Vector(vec)) = &mut item.kind else {
            continue;
        };
        match vec {
            VecStmt::Load { dest, arr, .. } => {
                if !arr.is_some_and(|current: VecArrangement| current.total_bits() == 64) {
                    *arr = Some(resolved_wide_arrangement(&resolved, *dest)?);
                }
            }
            VecStmt::Store { src, arr, .. } => {
                if !arr.is_some_and(|current: VecArrangement| current.total_bits() == 64) {
                    *arr = Some(resolved_wide_arrangement(&resolved, *src)?);
                }
            }
            VecStmt::Bin {
                dest,
                lhs,
                rhs,
                op,
                arr,
            } if op.is_bitwise() => {
                *arr = resolved_uniform_arrangement(&resolved, &[*dest, *lhs, *rhs])?;
            }
            VecStmt::MoveImm { dest, imm, arr } if *imm == 0 => {
                *arr = resolved_arrangement(&resolved, *dest);
            }
            VecStmt::Bin { .. }
            | VecStmt::Dup { .. }
            | VecStmt::LaneInsert { .. }
            | VecStmt::Compare { .. }
            | VecStmt::MoveImm { .. }
            | VecStmt::Reduce { .. }
            | VecStmt::ExtractToGpr { .. }
            | VecStmt::WidenExtend { .. }
            | VecStmt::WidenAdd { .. } => {}
        }
    }
    Ok(())
}

const VEC_WHOLE_BYTES: VecArrangement = VecArrangement {
    lanes: 16,
    elem: VecElem::I8,
};

const VEC_DOUBLEWORD_BYTES: VecArrangement = VecArrangement {
    lanes: 8,
    elem: VecElem::I8,
};

fn note_vec_exact(
    exact: &mut BTreeMap<u8, VecArrangement>,
    reg: u8,
    arr: VecArrangement,
) -> Result<()> {
    match exact.get(&reg) {
        Some(existing) if *existing != arr => Err(reject(
            "vector register is used with conflicting arrangements",
        )),
        _ => {
            exact.insert(reg, arr);
            Ok(())
        }
    }
}

fn note_vec_width(
    width: &mut BTreeMap<u8, VecArrangement>,
    reg: u8,
    arr: VecArrangement,
) -> Result<()> {
    match width.get(&reg) {
        Some(existing) if existing.total_bits() != arr.total_bits() => Err(reject(
            "vector register mixes 64-bit and 128-bit width-only uses",
        )),
        Some(_) => Ok(()),
        None => {
            width.insert(reg, arr);
            Ok(())
        }
    }
}

fn resolved_arrangement(resolved: &BTreeMap<u8, VecArrangement>, reg: u8) -> VecArrangement {
    resolved.get(&reg).copied().unwrap_or(VEC_WHOLE_BYTES)
}

fn resolved_uniform_arrangement(
    resolved: &BTreeMap<u8, VecArrangement>,
    regs: &[u8],
) -> Result<VecArrangement> {
    let mut chosen: Option<VecArrangement> = None;
    for reg in regs {
        let arr: VecArrangement = resolved_arrangement(resolved, *reg);
        match chosen {
            Some(existing) if existing != arr => {
                return Err(reject(
                    "bitwise vector operation mixes registers of different arrangements",
                ));
            }
            _ => chosen = Some(arr),
        }
    }
    chosen.ok_or_else(|| reject("bitwise vector operation has no registers"))
}

fn resolved_wide_arrangement(
    types: &BTreeMap<u8, VecArrangement>,
    reg: u8,
) -> Result<VecArrangement> {
    match types.get(&reg) {
        Some(arr) => {
            if arr.total_bits() != 128 {
                return Err(reject(
                    "q-register access does not match a 128-bit vector arrangement",
                ));
            }
            Ok(*arr)
        }
        None => Ok(VecArrangement {
            lanes: 16,
            elem: VecElem::I8,
        }),
    }
}

fn scan_vector_abi(items: &[Item]) -> Result<VectorAbi> {
    let mut types: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    let mut written: BTreeSet<u8> = BTreeSet::new();
    let mut params: Vec<(u8, VecArrangement)> = Vec::new();
    let mut has_vector: bool = false;
    let mut wrote_int_result: bool = false;
    let mut return_defined: bool = false;
    let mut return_stored: bool = false;
    let mut widened: bool = false;
    let mut has_control_flow: bool = false;
    for item in items {
        match &item.kind {
            ItemKind::Stmt(Stmt::Vector(vec)) => {
                has_vector = true;
                record_vector_types(&mut types, vec);
                for (reg, arr) in vector_reads(vec) {
                    if reg >= 32 {
                        widened = true;
                    }
                    if !written.contains(&reg) && !params.iter().any(|(r, _)| *r == reg) {
                        params.push((reg, arr));
                    }
                }
                if let Some(dest) = vector_write(vec) {
                    if dest >= 32 {
                        widened = true;
                    }
                    if dest == SIMD_RETURN_REG {
                        return_defined = true;
                        return_stored = false;
                    }
                    written.insert(dest);
                }
                if let VecStmt::Store { src, .. } = vec
                    && *src == SIMD_RETURN_REG
                {
                    return_stored = true;
                }
                if let VecStmt::ExtractToGpr { dest, src, .. } = vec {
                    if *src == SIMD_RETURN_REG {
                        return_defined = false;
                    }
                    if dest.reg == Reg::Rax {
                        wrote_int_result = true;
                    }
                }
            }
            ItemKind::Stmt(stmt) => {
                if stmt_writes_rax_int(stmt) {
                    wrote_int_result = true;
                }
            }
            ItemKind::Branch { .. } | ItemKind::Jmp { .. } | ItemKind::Switch { .. } => {
                has_control_flow = true;
            }
            ItemKind::Ret => {}
        }
    }
    if widened && has_control_flow {
        return Err(reject(
            "widening-long register versioning across control flow is unsupported",
        ));
    }
    if widened && !wrote_int_result {
        return Err(reject(
            "widening-long chain without a scalar result is unsupported",
        ));
    }
    params.sort_by_key(|(reg, _): &(u8, VecArrangement)| *reg);
    for (position, (reg, _)) in params.iter().enumerate() {
        if usize::from(*reg) != position {
            return Err(reject(
                "vector parameters do not form a contiguous v0.. sequence",
            ));
        }
    }
    let ret: VectorRet = if has_vector && return_defined && !return_stored {
        let arr: VecArrangement = *types
            .get(&SIMD_RETURN_REG)
            .ok_or_else(|| reject("vector return register has no resolved arrangement"))?;
        VectorRet::Vector(arr)
    } else if has_vector && !wrote_int_result {
        VectorRet::Void
    } else {
        VectorRet::None
    };
    Ok(VectorAbi { params, ret })
}

fn record_vector_types(types: &mut BTreeMap<u8, VecArrangement>, vec: &VecStmt) {
    match vec {
        VecStmt::Bin {
            dest,
            lhs,
            rhs,
            arr,
            ..
        } => {
            types.entry(*dest).or_insert(*arr);
            types.entry(*lhs).or_insert(*arr);
            types.entry(*rhs).or_insert(*arr);
        }
        VecStmt::Compare {
            dest,
            lhs,
            rhs,
            arr,
        } => {
            types.entry(*dest).or_insert(*arr);
            types.entry(*lhs).or_insert(*arr);
            if let Some(rhs) = rhs {
                types.entry(*rhs).or_insert(*arr);
            }
        }
        VecStmt::Dup { dest, arr, .. } | VecStmt::LaneInsert { dest, arr, .. } => {
            types.entry(*dest).or_insert(*arr);
        }
        VecStmt::MoveImm { dest, arr, .. } => {
            types.entry(*dest).or_insert(*arr);
        }
        VecStmt::Load { dest, arr, .. } => {
            if let Some(arrangement) = arr {
                types.entry(*dest).or_insert(*arrangement);
            }
        }
        VecStmt::Store { src, arr, .. } => {
            if let Some(arrangement) = arr {
                types.entry(*src).or_insert(*arrangement);
            }
        }
        VecStmt::Reduce { reg, src, .. } => {
            types.entry(*reg).or_insert(*src);
        }
        VecStmt::ExtractToGpr { src, elem, .. } => {
            types
                .entry(*src)
                .or_insert_with(|| VecArrangement::whole_register(*elem));
        }
        VecStmt::WidenExtend {
            dest,
            src,
            src_elem,
            dest_elem,
            ..
        } => {
            types
                .entry(*dest)
                .or_insert_with(|| VecArrangement::whole_register(*dest_elem));
            types
                .entry(*src)
                .or_insert_with(|| VecArrangement::whole_register(*src_elem));
        }
        VecStmt::WidenAdd {
            dest,
            src1,
            src2,
            src_elem,
            dest_elem,
            ..
        } => {
            types
                .entry(*dest)
                .or_insert_with(|| VecArrangement::whole_register(*dest_elem));
            types
                .entry(*src1)
                .or_insert_with(|| VecArrangement::whole_register(*src_elem));
            types
                .entry(*src2)
                .or_insert_with(|| VecArrangement::whole_register(*src_elem));
        }
    }
}

fn vector_reads(vec: &VecStmt) -> Vec<(u8, VecArrangement)> {
    match vec {
        VecStmt::Bin { lhs, rhs, arr, .. } => vec![(*lhs, *arr), (*rhs, *arr)],
        VecStmt::Compare {
            lhs,
            rhs: Some(rhs),
            arr,
            ..
        } => vec![(*lhs, *arr), (*rhs, *arr)],
        VecStmt::Compare {
            lhs,
            rhs: None,
            arr,
            ..
        } => vec![(*lhs, *arr)],
        VecStmt::Store {
            src,
            arr: Some(arr),
            ..
        } => vec![(*src, *arr)],
        VecStmt::Store { src, arr: None, .. } => vec![(
            *src,
            VecArrangement {
                lanes: 16,
                elem: VecElem::I8,
            },
        )],
        VecStmt::Reduce { reg, src, .. } => vec![(*reg, *src)],
        VecStmt::ExtractToGpr { src, elem, .. } => {
            vec![(*src, VecArrangement::whole_register(*elem))]
        }
        VecStmt::WidenExtend { src, src_elem, .. } => {
            vec![(*src, VecArrangement::whole_register(*src_elem))]
        }
        VecStmt::WidenAdd {
            src1,
            src2,
            src_elem,
            ..
        } => {
            let arr: VecArrangement = VecArrangement::whole_register(*src_elem);
            vec![(*src1, arr), (*src2, arr)]
        }
        VecStmt::LaneInsert { dest, arr, .. } => vec![(*dest, *arr)],
        VecStmt::Load { .. } | VecStmt::Dup { .. } | VecStmt::MoveImm { .. } => Vec::new(),
    }
}

fn vector_write(vec: &VecStmt) -> Option<u8> {
    match vec {
        VecStmt::Bin { dest, .. }
        | VecStmt::Dup { dest, .. }
        | VecStmt::LaneInsert { dest, .. }
        | VecStmt::Load { dest, .. }
        | VecStmt::Compare { dest, .. }
        | VecStmt::MoveImm { dest, .. } => Some(*dest),
        VecStmt::Reduce { reg, .. } => Some(*reg),
        VecStmt::WidenExtend { dest, .. } | VecStmt::WidenAdd { dest, .. } => Some(*dest),
        VecStmt::Store { .. } | VecStmt::ExtractToGpr { .. } => None,
    }
}

fn reject(message: &str) -> Error {
    Error::LlvmIr(format!("aarch64 reject: {message}"))
}

fn reject_at(insn: &DisasmInsn, message: &str) -> Error {
    reject(&format!(
        "{message} `{} {}` at {:#x}",
        insn.mnemonic, insn.operands, insn.address
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        Aarch64DirectTransfer, DisasmInsn, ExtSource, FpToIntRound, FpWidth, IndexExtend, MemRef,
        Reg, RegRef, Stmt, Width, aarch64_direct_transfer, encoded_extended_register, lower_alu,
        lower_fp_fmov, lower_fp_to_int, lower_int_to_fp, parse_extend_modifier,
        parse_index_modifier, parse_memory, parse_reg, split_operands,
    };
    use crate::error::Result;

    fn lower_alu_case(mnemonic: &str, operands: &str, word: u32) -> Result<(RegRef, Vec<Stmt>)> {
        let insn: DisasmInsn = DisasmInsn {
            address: 0,
            bytes: word.to_le_bytes().to_vec(),
            mnemonic: mnemonic.to_owned(),
            operands: operands.to_owned(),
        };
        lower_alu(&insn)
    }

    fn lower(mnemonic: &str, operands: &str) -> Result<Vec<Stmt>> {
        let insn: DisasmInsn = DisasmInsn {
            address: 0,
            bytes: vec![0, 0, 0, 0],
            mnemonic: mnemonic.to_owned(),
            operands: operands.to_owned(),
        };
        let split: Vec<&str> = split_operands(&insn.operands);
        if matches!(mnemonic, "scvtf" | "ucvtf") {
            lower_int_to_fp(&insn, &split, mnemonic == "scvtf")
        } else {
            lower_fp_to_int(&insn, &split)
        }
    }

    #[test]
    fn direct_transfer_boundaries_decode_for_every_immediate_branch_family() {
        let address: u64 = 0x1000_0000;
        let cases: [(u32, Aarch64DirectTransfer); 14] = [
            (
                0x95ff_ffff,
                Aarch64DirectTransfer::BranchLink {
                    target: 0x17ff_fffc,
                },
            ),
            (
                0x9600_0000,
                Aarch64DirectTransfer::BranchLink {
                    target: 0x0800_0000,
                },
            ),
            (
                0x15ff_ffff,
                Aarch64DirectTransfer::UnconditionalBranch {
                    target: 0x17ff_fffc,
                },
            ),
            (
                0x1600_0000,
                Aarch64DirectTransfer::UnconditionalBranch {
                    target: 0x0800_0000,
                },
            ),
            (
                0x547f_ffe0,
                Aarch64DirectTransfer::ConditionalBranch {
                    condition: 0,
                    target: 0x100f_fffc,
                },
            ),
            (
                0x5480_0000,
                Aarch64DirectTransfer::ConditionalBranch {
                    condition: 0,
                    target: 0x0ff0_0000,
                },
            ),
            (
                0x347f_ffe0,
                Aarch64DirectTransfer::CompareBranch {
                    target: 0x100f_fffc,
                },
            ),
            (
                0x3480_0000,
                Aarch64DirectTransfer::CompareBranch {
                    target: 0x0ff0_0000,
                },
            ),
            (
                0x357f_ffe0,
                Aarch64DirectTransfer::CompareBranch {
                    target: 0x100f_fffc,
                },
            ),
            (
                0x3580_0000,
                Aarch64DirectTransfer::CompareBranch {
                    target: 0x0ff0_0000,
                },
            ),
            (
                0x3603_ffe0,
                Aarch64DirectTransfer::TestBranch {
                    target: 0x1000_7ffc,
                },
            ),
            (
                0x3604_0000,
                Aarch64DirectTransfer::TestBranch {
                    target: 0x0fff_8000,
                },
            ),
            (
                0x3703_ffe0,
                Aarch64DirectTransfer::TestBranch {
                    target: 0x1000_7ffc,
                },
            ),
            (
                0x3704_0000,
                Aarch64DirectTransfer::TestBranch {
                    target: 0x0fff_8000,
                },
            ),
        ];
        for (word, expected) in cases {
            let actual: Option<Aarch64DirectTransfer> = aarch64_direct_transfer(address, word);
            assert_eq!(actual, Some(expected), "{word:#010x}");
        }
    }

    fn rejection(mnemonic: &str, operands: &str) -> String {
        format!(
            "{:?}",
            lower(mnemonic, operands).expect_err("fixed-point form must reject")
        )
    }

    #[test]
    fn fixed_point_scale_recovers_only_for_the_four_conversion_mnemonics() {
        for mnemonic in ["scvtf", "ucvtf"] {
            assert!(lower(mnemonic, "s0, w0, #0x10").is_ok(), "{mnemonic}");
        }
        for mnemonic in ["fcvtzs", "fcvtzu"] {
            assert!(lower(mnemonic, "w0, s0, #0x10").is_ok(), "{mnemonic}");
        }
        for mnemonic in ["fcvtms", "fcvtmu", "fcvtps", "fcvtpu", "fcvtas", "fcvtau"] {
            let message: String = rejection(mnemonic, "w0, s0, #0x10");
            assert!(
                message.contains("truncation toward zero"),
                "{mnemonic}: {message}"
            );
        }
    }

    #[test]
    fn fixed_point_scale_of_zero_rejects() {
        for (mnemonic, operands) in [("scvtf", "s0, w0, #0x0"), ("fcvtzs", "w0, s0, #0")] {
            let message: String = rejection(mnemonic, operands);
            assert!(
                message.contains("outside the architectural range"),
                "{mnemonic}: {message}"
            );
        }
    }

    #[test]
    fn fixed_point_scale_beyond_the_integer_register_width_rejects() {
        for (mnemonic, operands) in [
            ("scvtf", "s0, w0, #0x21"),
            ("ucvtf", "d0, w0, #0x40"),
            ("fcvtzs", "w0, s0, #0x21"),
            ("fcvtzu", "x0, d0, #0x41"),
            ("scvtf", "d0, x0, #0x41"),
        ] {
            let message: String = rejection(mnemonic, operands);
            assert!(
                message.contains("outside the architectural range"),
                "{mnemonic} {operands}: {message}"
            );
        }
        assert!(lower("scvtf", "s0, w0, #0x20").is_ok());
        assert!(lower("scvtf", "s0, x0, #0x40").is_ok());
        assert!(lower("fcvtzu", "w0, d0, #0x20").is_ok());
        assert!(lower("fcvtzu", "x0, s0, #0x40").is_ok());
    }

    #[test]
    fn fixed_point_scale_that_is_not_an_immediate_rejects() {
        let message: String = rejection("fcvtzs", "w0, s0, w1");
        assert!(message.contains("not an immediate"), "{message}");
        let source: String = rejection("scvtf", "s0, w0, w1");
        assert!(source.contains("not an immediate"), "{source}");
    }

    #[test]
    fn malformed_fixed_point_operand_lists_reject() {
        let extra: String = rejection("scvtf", "s0, w0, #0x10, #0x10");
        assert!(extra.contains("malformed"), "{extra}");
        let short: String = rejection("fcvtzs", "w0");
        assert!(short.contains("malformed"), "{short}");
    }

    #[test]
    fn half_precision_fixed_point_forms_recover_while_vectors_reject() {
        assert!(lower("scvtf", "h0, w0, #0x10").is_ok());
        assert!(lower("fcvtzs", "w0, h0, #0x10").is_ok());
        let vector: String = rejection("scvtf", "v0.4s, v0.4s, #0x10");
        assert!(vector.contains("vector registers"), "{vector}");
        let scalar_simd: String = rejection("ucvtf", "s0, s0, #0x10");
        assert!(scalar_simd.contains("not w or x"), "{scalar_simd}");
    }

    #[test]
    fn half_precision_moves_use_the_architectural_32_bit_general_register_carrier() {
        let cases: [(&str, bool); 2] = [("h0, w0", true), ("w1, h2", false)];
        for (operands, to_fp) in cases {
            let insn: DisasmInsn = DisasmInsn {
                address: 0,
                bytes: vec![0, 0, 0, 0],
                mnemonic: "fmov".to_owned(),
                operands: operands.to_owned(),
            };
            let split: Vec<&str> = split_operands(&insn.operands);
            let statements: Vec<Stmt> =
                lower_fp_fmov(&insn, &split).expect("half-precision transfer");
            let correct_direction: bool = match statements.as_slice() {
                [
                    Stmt::GprToXmm {
                        src:
                            RegRef {
                                width: Width::W32, ..
                            },
                        width: FpWidth::F16,
                        ..
                    },
                ] => to_fp,
                [
                    Stmt::XmmToGpr {
                        dest:
                            RegRef {
                                width: Width::W32, ..
                            },
                        width: FpWidth::F16,
                        ..
                    },
                ] => !to_fp,
                _ => false,
            };
            assert!(correct_direction, "{operands}: {statements:?}");
        }
    }

    #[test]
    fn nearest_integer_conversions_recover_for_signed_and_unsigned_destinations() {
        for (mnemonic, signed) in [("fcvtns", true), ("fcvtnu", false)] {
            let statements: Vec<Stmt> = lower(mnemonic, "w0, h0").expect("nearest conversion");
            assert!(matches!(
                statements.as_slice(),
                [Stmt::FpToInt {
                    signed: actual_signed,
                    round: FpToIntRound::Nearest,
                    ..
                }] if *actual_signed == signed
            ));
        }
    }

    #[test]
    fn binary16_conversion_round_trip_preserves_every_bit_pattern() {
        for bits in u16::MIN..=u16::MAX {
            assert_eq!(
                super::binary16_from_f32(super::binary16_to_f32(bits)),
                bits,
                "{bits:#06x}"
            );
        }
    }

    #[test]
    fn sxtx_and_uxtx_index_modifiers_reject_a_32_bit_register() {
        for (modifier, reason) in [
            ("sxtx #3", "sxtx index requires a 64-bit register"),
            ("uxtx #3", "uxtx index requires a 64-bit register"),
        ] {
            let message: String = format!(
                "{:?}",
                parse_index_modifier(modifier, Width::W32).expect_err(modifier)
            );
            assert!(message.contains(reason), "{modifier}: {message}");
        }
    }

    #[test]
    fn sxtw_and_uxtw_index_modifiers_still_reject_a_64_bit_register() {
        for (modifier, reason) in [
            ("sxtw #0", "sxtw index requires a 32-bit register"),
            ("uxtw #0", "uxtw index requires a 32-bit register"),
        ] {
            let message: String = format!(
                "{:?}",
                parse_index_modifier(modifier, Width::W64).expect_err(modifier)
            );
            assert!(message.contains(reason), "{modifier}: {message}");
        }
    }

    #[test]
    fn sxtx_and_uxtx_index_modifiers_accept_a_64_bit_register_as_the_full_extend() {
        for (modifier, expected_scale) in [
            ("sxtx #3", 8u8),
            ("uxtx #0", 1u8),
            ("sxtx", 1u8),
            ("uxtx", 1u8),
        ] {
            let (scale, extend): (u8, IndexExtend) =
                parse_index_modifier(modifier, Width::W64).expect(modifier);
            assert_eq!(extend, IndexExtend::Full, "{modifier}");
            assert_eq!(scale, expected_scale, "{modifier}");
        }
    }

    #[test]
    fn memory_index_shift_amount_of_four_accepts_and_five_rejects_for_every_extend_modifier() {
        let cases: [(&str, Width); 5] = [
            ("lsl", Width::W64),
            ("sxtw", Width::W32),
            ("uxtw", Width::W32),
            ("sxtx", Width::W64),
            ("uxtx", Width::W64),
        ];
        for (modifier, width) in cases {
            assert!(
                parse_index_modifier(&format!("{modifier} #4"), width).is_ok(),
                "{modifier} #4"
            );
            let message: String = format!(
                "{:?}",
                parse_index_modifier(&format!("{modifier} #5"), width)
                    .expect_err(&format!("{modifier} #5"))
            );
            assert!(message.contains("out of range"), "{modifier} #5: {message}");
        }
    }

    #[test]
    fn memory_index_modifier_without_a_whitespace_separator_is_rejected_as_unsupported() {
        for modifier in ["uxtx#3", "sxtx#3", "uxtw#0", "sxtw#0", "lsl#3"] {
            let message: String = format!(
                "{:?}",
                parse_index_modifier(modifier, Width::W64).expect_err(modifier)
            );
            assert!(
                message.contains("unsupported extend or shift"),
                "{modifier}: {message}"
            );
        }
    }

    #[test]
    fn mixed_case_memory_index_modifier_tokens_reject_the_same_way_old_and_new() {
        for modifier in ["UXTX #3", "SXTX #3", "UXTW #0", "LSL #0"] {
            let message: String = format!(
                "{:?}",
                parse_index_modifier(modifier, Width::W64).expect_err(modifier)
            );
            assert!(
                message.contains("unsupported extend or shift"),
                "{modifier}: {message}"
            );
        }
    }

    #[test]
    fn memory_operand_trailing_comma_after_sxtx_rejects_the_extra_term() {
        let message: String = format!(
            "{:?}",
            parse_memory("[x1, x2, sxtx #3,]", Width::W64).expect_err("trailing comma")
        );
        assert!(message.contains("unsupported addressing"), "{message}");
    }

    #[test]
    fn memory_operand_with_extra_whitespace_around_sxtx_parses_like_a_tight_token() {
        let (mem_ref, pre_index): (MemRef, bool) =
            parse_memory("[ x1 ,  x2 ,  sxtx  #3 ]", Width::W64).expect("extra whitespace");
        assert!(!pre_index);
        let scale: u8 = mem_ref.index.expect("index operand present").scale;
        assert_eq!(scale, 8);
    }

    #[test]
    fn memory_operand_mixed_case_sxtx_rejects_the_same_way_as_mixed_case_uxtw() {
        for operand in ["[x1, x2, SXTX #3]", "[x1, x2, UXTW #0]"] {
            let message: String = format!(
                "{:?}",
                parse_memory(operand, Width::W64).expect_err(operand)
            );
            assert!(
                message.contains("unsupported extend or shift"),
                "{operand}: {message}"
            );
        }
    }

    #[test]
    fn malformed_memory_index_modifier_tokens_never_panic() {
        let adversarial: [&str; 13] = [
            "",
            "   ",
            "#",
            "uxtx #",
            "uxtx #-1",
            "uxtx #99999999999999999999",
            "uxtx #0x3",
            "\u{0}\u{0}\u{0}",
            "sxtx\t#3",
            "\u{fc}xtx #3",
            "\u{1f980} #3",
            ",,,",
            "sxtx #4294967296",
        ];
        for token in adversarial {
            let _: Result<(u8, IndexExtend)> = parse_index_modifier(token, Width::W64);
            let _: Result<(u8, IndexExtend)> = parse_index_modifier(token, Width::W32);
        }
    }

    #[test]
    fn byte_extend_with_a_w_register_operand_lifts_instead_of_rejecting_on_the_width_conflation() {
        let (dest, stmts): (RegRef, Vec<Stmt>) =
            lower_alu_case("add", "x0, x0, w1, uxtb", 0x8b21_0000).expect("real uxtb encoding");
        assert_eq!(dest.width, Width::W64);
        let extend_source_width: Width = stmts
            .iter()
            .find_map(|stmt: &Stmt| match stmt {
                Stmt::Extend {
                    src: ExtSource::Reg(r),
                    ..
                } => Some(r.width),
                _ => None,
            })
            .expect("an extend statement over a register source");
        assert_eq!(extend_source_width, Width::W8);
    }

    #[test]
    fn every_extend_option_word_decodes_to_its_architectural_source_width_and_sign() {
        let cases: [(u32, bool, Width); 8] = [
            (0b000, false, Width::W8),
            (0b001, false, Width::W16),
            (0b010, false, Width::W32),
            (0b011, false, Width::W64),
            (0b100, true, Width::W8),
            (0b101, true, Width::W16),
            (0b110, true, Width::W32),
            (0b111, true, Width::W64),
        ];
        for (option, signed, src_width) in cases {
            let word: u32 = 0x8b21_0000 | (option << 13);
            let insn: DisasmInsn = DisasmInsn {
                address: 0,
                bytes: word.to_le_bytes().to_vec(),
                mnemonic: "add".to_owned(),
                operands: "x0, x0, w1, uxtb".to_owned(),
            };
            let decoded: (bool, Width, i64) =
                encoded_extended_register(&insn).unwrap_or_else(|| panic!("option {option:03b}"));
            assert_eq!(decoded, (signed, src_width, 0), "option {option:03b}");
        }
    }

    #[test]
    fn extended_register_class_mismatch_rejects_with_a_reason_named_by_the_expected_class() {
        let byte_word: u32 = 0x8b21_0000;
        let message_for_w_class: String = format!(
            "{:?}",
            lower_alu_case("add", "x0, x0, x1, uxtb", byte_word)
                .expect_err("x1 cannot satisfy a byte extend")
        );
        assert!(
            message_for_w_class.contains("requires a 32-bit source register"),
            "{message_for_w_class}"
        );

        let x_word: u32 = 0x8b21_6000;
        let message_for_x_class: String = format!(
            "{:?}",
            lower_alu_case("add", "x0, x0, w1, uxtb", x_word)
                .expect_err("w1 cannot satisfy a full 64-bit extend")
        );
        assert!(
            message_for_x_class.contains("requires a 64-bit source register"),
            "{message_for_x_class}"
        );
    }

    #[test]
    fn imm3_of_five_is_unallocated_and_the_word_path_declines_it() {
        let word: u32 = 0x8b21_1400;
        let insn: DisasmInsn = DisasmInsn {
            address: 0,
            bytes: word.to_le_bytes().to_vec(),
            mnemonic: "add".to_owned(),
            operands: "x0, x0, w1, uxtb #5".to_owned(),
        };
        assert_eq!(encoded_extended_register(&insn), None);
    }

    #[test]
    fn adds_with_an_extended_register_now_computes_its_arithmetic_result_even_though_the_flag_snapshot_stays_unsupported()
     {
        let (_, stmts): (RegRef, Vec<Stmt>) =
            lower_alu_case("adds", "x0, x0, w1, uxtb", 0xab21_0000).expect("adds byte extend");
        assert!(
            stmts
                .iter()
                .any(|stmt: &Stmt| matches!(stmt, Stmt::Extend { .. })),
            "{stmts:?}"
        );
    }

    #[test]
    fn stack_pointer_operand_parses_to_the_stack_pointer_register_at_64_bit_width() {
        let reg: RegRef = parse_reg("sp").expect("sp is a supported operand");
        assert_eq!(reg.reg, Reg::Rsp);
        assert_eq!(reg.width, Width::W64);
    }

    #[test]
    fn malformed_extend_modifier_tokens_never_panic() {
        let adversarial: [&str; 13] = [
            "",
            "   ",
            "#",
            "uxtb #",
            "uxtb #-1",
            "uxtb #99999999999999999999",
            "uxtb #0x3",
            "\u{0}\u{0}\u{0}",
            "sxtb\t#3",
            "\u{fc}xtb #3",
            "\u{1f980} #3",
            ",,,",
            "sxtb #4294967296",
        ];
        for token in adversarial {
            let _: Option<(bool, Width, i64)> = parse_extend_modifier(token);
        }
    }

    #[test]
    fn malformed_extended_register_words_never_panic() {
        let mnemonics: [&str; 4] = ["add", "adds", "sub", "subs"];
        for mnemonic in mnemonics {
            for option in 0u32..8 {
                for imm3 in 0u32..8 {
                    let word: u32 = 0x8b21_0000 | (option << 13) | (imm3 << 10);
                    let insn: DisasmInsn = DisasmInsn {
                        address: 0,
                        bytes: word.to_le_bytes().to_vec(),
                        mnemonic: mnemonic.to_owned(),
                        operands: "x0, x0, w1, uxtb".to_owned(),
                    };
                    let _: Option<(bool, Width, i64)> = encoded_extended_register(&insn);
                    let _: Result<(RegRef, Vec<Stmt>)> = lower_alu(&insn);
                }
            }
        }
        for len in 0usize..4 {
            let insn: DisasmInsn = DisasmInsn {
                address: 0,
                bytes: vec![0xffu8; len],
                mnemonic: "add".to_owned(),
                operands: "x0, x0, w1, uxtb".to_owned(),
            };
            let _: Option<(bool, Width, i64)> = encoded_extended_register(&insn);
            let _: Result<(RegRef, Vec<Stmt>)> = lower_alu(&insn);
        }
    }
}
