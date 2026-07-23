use super::{
    Abi, AggregatePlan, BinOp, CondKind, Error, ExtSource, Flags, FnReturn, FnSignature,
    FrameShape, Item, ItemKind, LeafRecovery, MemRef, Node, Reg, RegRef, ResolvedCall, Result,
    ScalarType, Source, SretPlan, SretReturn, Stmt, Structured, UnOp, VecArrangement, VecBinOp,
    VecElem, VecStmt, Width, annotate_calls_block_with_order, collect_call_targets,
    condition_is_sound, detect_sret, emit_c, emit_rust, infer_aggregate_plan, infer_params,
    plan_frame, stmt_writes_rax_int, structure_items,
};
use crate::arch::{Arch, DisasmInsn, disassemble};
use std::collections::{BTreeMap, BTreeSet};

#[path = "aarch64_cfg.rs"]
mod aarch64_cfg;

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

#[derive(Debug, Clone, Copy, Default)]
struct FrameInfo {
    sp_to_entry: i64,
    fp_to_entry: Option<i64>,
}

#[derive(Debug, Clone)]
struct FrameAnalysis {
    info: FrameInfo,
    management: BTreeSet<usize>,
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

fn recover_with_calls_and_image<'image>(
    machine_code: &[u8],
    base: u64,
    calls: &[ResolvedCall],
    image: &dyn Fn(u64) -> Option<&'image [u8]>,
    relocations: &dyn Fn(u64) -> Option<u64>,
) -> Result<LeafRecovery> {
    if calls
        .iter()
        .any(|call: &ResolvedCall| call.arg_count > Abi::Aapcs64.arg_order().len())
    {
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
    let image_context: ImageContext<'_, 'image> = ImageContext { image, relocations };
    let switches: BTreeMap<usize, SwitchDispatch> =
        recover_aarch64_switches(&insns, base, machine_code.len(), &image_context);
    let mut ignored_instructions: BTreeSet<usize> = BTreeSet::new();
    for dispatch in switches.values() {
        ignored_instructions.extend(dispatch.ignored_instructions.iter().copied());
    }
    let mut items: Vec<Item> = Vec::new();
    let mut return_width: Width = Width::W64;
    let mut flags: Option<TrackedFlags> = None;
    let mut next_sel: u32 = 0;
    let mut flag_definitions: BTreeMap<usize, TrackedFlags> = BTreeMap::new();
    let frame: FrameAnalysis = frame_analysis(&insns)?;
    let outgoing: BTreeMap<usize, Vec<OutgoingSlot>> = outgoing_stores(&insns, calls)?;
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
        if has_unsupported_register_class(&insn.operands) {
            return Err(reject_at(insn, "unsupported instruction"));
        }
        if operand_is_vector(insn) {
            let stmts: Vec<Stmt> = lower_vector(insn)?;
            push_stmts(&mut items, base, index, stmts)?;
            continue;
        }
        if insn.mnemonic == "nop" {
            continue;
        }
        match insn.mnemonic.as_str() {
            "add" | "adds" | "sub" | "subs" | "and" | "orr" | "eor" | "bic" | "orn" | "eon"
            | "lsl" | "lsr" | "asr" | "mul" => {
                let (dest, mut stmts): (RegRef, Vec<Stmt>) = lower_alu(insn)?;
                let new_flags: Option<TrackedFlags> = if insn.mnemonic == "subs" {
                    let (mut snapshots, value): (Vec<Stmt>, Flags) = subtract_flags(insn)?;
                    snapshots.append(&mut stmts);
                    stmts = snapshots;
                    Some(TrackedFlags {
                        value,
                        nz_only: false,
                    })
                } else {
                    None
                };
                push_stmts(&mut items, base, index, stmts)?;
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
                    lower_memory(insn, frame.info, outgoing_slots)?;
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
                if operands.len() != 2 {
                    return Err(reject_at(insn, "malformed sized load"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let (mem, pre_index): (MemRef, bool) = parse_memory(operands[1], load_width)?;
                if pre_index {
                    return Err(reject_at(insn, "pre-indexed sized load is unsupported"));
                }
                push_stmts(
                    &mut items,
                    base,
                    index,
                    vec![Stmt::Extend {
                        dest,
                        src: ExtSource::Mem(mem),
                        signed,
                    }],
                )?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "ldp" | "stp" => {
                let (dest, stmts): (Option<RegRef>, Vec<Stmt>) =
                    lower_pair_memory(insn, frame.info, outgoing_slots)?;
                push_stmts(&mut items, base, index, stmts)?;
                if let Some(dest) = dest {
                    return_width = dest.width;
                }
            }
            "cmp" | "cmn" | "tst" => {
                let (stmts, new_flags): (Vec<Stmt>, TrackedFlags) = lower_flag_setter(insn)?;
                push_stmts(&mut items, base, index, stmts)?;
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
                        "condition is undefined for the tracked nzcv source",
                    ));
                }
                let stmts: Vec<Stmt> = if m_reg == Some(dest.reg) {
                    vec![Stmt::Cond {
                        dest,
                        src: n_src,
                        kind,
                        flags: live_flags.value,
                    }]
                } else if n_reg == Some(dest.reg) {
                    vec![Stmt::Cond {
                        dest,
                        src: m_src,
                        kind: kind.negate(),
                        flags: live_flags.value,
                    }]
                } else if flags_reference_reg(&live_flags.value, dest.reg) {
                    let var: u32 = next_sel;
                    next_sel += 1;
                    vec![
                        Stmt::FlagSnapshot {
                            var,
                            kind,
                            flags: live_flags.value,
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
                            flags: live_flags.value,
                        },
                    ]
                };
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
            }
            "cset" => {
                let operands: Vec<&str> = split_operands(&insn.operands);
                if operands.len() != 2 {
                    return Err(reject_at(insn, "malformed conditional set"));
                }
                let dest: RegRef = parse_reg(operands[0])?;
                let kind: CondKind = parse_condition(operands[1])?;
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
                let stmts: Vec<Stmt> = if flags_reference_reg(&live_flags.value, dest.reg) {
                    let var: u32 = next_sel;
                    next_sel += 1;
                    vec![
                        Stmt::FlagSnapshot {
                            var,
                            kind,
                            flags: live_flags.value,
                        },
                        Stmt::Assign {
                            dest,
                            src: Source::Imm(0),
                        },
                        Stmt::Cond {
                            dest,
                            src: Source::Imm(1),
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
                            src: Source::Imm(1),
                            kind,
                            flags: live_flags.value,
                        },
                    ]
                };
                push_stmts(&mut items, base, index, stmts)?;
                if dest.reg == Reg::Rax {
                    return_width = dest.width;
                }
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
            _ => return Err(reject_at(insn, "unsupported instruction")),
        }
    }
    resolve_vector_types(&mut items)?;
    let vec_abi: VectorAbi = scan_vector_abi(&items)?;
    finish(
        &insns,
        &items,
        base,
        &flag_definitions,
        return_width,
        calls,
        &vec_abi,
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
    if word & 0xff00_0010 == 0x5400_0000 {
        let Some(target): Option<u64> = aarch64_relative_target(insn.address, word, 5, 19) else {
            return SwitchInsn::Other;
        };
        return SwitchInsn::ConditionalBranch {
            condition: (word & 0xf) as u8,
            target,
        };
    }
    if word & 0xfc00_0000 == 0x1400_0000 {
        let Some(target): Option<u64> = aarch64_relative_target(insn.address, word, 0, 26) else {
            return SwitchInsn::Other;
        };
        return SwitchInsn::DirectBranch { target };
    }
    if word & 0x7e00_0000 == 0x3400_0000 {
        let Some(target): Option<u64> = aarch64_relative_target(insn.address, word, 5, 19) else {
            return SwitchInsn::Other;
        };
        return SwitchInsn::DirectBranch { target };
    }
    if word & 0x7e00_0000 == 0x3600_0000 {
        let Some(target): Option<u64> = aarch64_relative_target(insn.address, word, 5, 14) else {
            return SwitchInsn::Other;
        };
        return SwitchInsn::DirectBranch { target };
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
    let bytes: [u8; 4] = insn.bytes.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn aarch64_relative_target(address: u64, word: u32, shift: u8, bits: u8) -> Option<u64> {
    let immediate: u32 = immediate_field(word, shift, bits);
    let delta: i64 = signed_immediate(immediate, bits).checked_mul(4)?;
    address.checked_add_signed(delta)
}

fn aarch64_adr_target(address: u64, word: u32) -> Option<u64> {
    let immediate: u32 = aarch64_adr_immediate(word);
    address.checked_add_signed(signed_immediate(immediate, 21))
}

fn aarch64_adrp_target(address: u64, word: u32) -> Option<u64> {
    let immediate: u32 = aarch64_adr_immediate(word);
    let delta: i64 = signed_immediate(immediate, 21).checked_mul(4096)?;
    (address & !0xfff).checked_add_signed(delta)
}

fn aarch64_adr_immediate(word: u32) -> u32 {
    let high: u32 = immediate_field(word, 5, 19);
    let low: u32 = immediate_field(word, 29, 2);
    high << 2 | low
}

fn immediate_field(word: u32, shift: u8, width: u8) -> u32 {
    let mask: u32 = (1_u32.checked_shl(u32::from(width)).unwrap_or(0)).wrapping_sub(1);
    word.checked_shr(u32::from(shift)).unwrap_or(0) & mask
}

fn register_field(word: u32, shift: u8) -> u8 {
    immediate_field(word, shift, 5) as u8
}

fn signed_immediate(value: u32, bits: u8) -> i64 {
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
        | Node::Return
        | Node::Label(_)
        | Node::Goto(_) => false,
    })
}

fn finish(
    insns: &[DisasmInsn],
    items: &[Item],
    base: u64,
    flag_definitions: &BTreeMap<usize, TrackedFlags>,
    return_width: Width,
    calls: &[ResolvedCall],
    vec_abi: &VectorAbi,
) -> Result<LeafRecovery> {
    let mut structured: Structured =
        match aarch64_cfg::structure(items, insns, base, flag_definitions) {
            aarch64_cfg::Attempt::Structured(structured) => structured,
            aarch64_cfg::Attempt::NotCandidate => structure_items(items)?,
            aarch64_cfg::Attempt::RejectedNzcv => {
                let _: Structured = structure_items(items)?;
                return Err(reject("conditional branch lacks live nzcv state"));
            }
        };
    if !calls.is_empty() {
        let call_map = calls
            .iter()
            .map(|call: &ResolvedCall| (call.target, call))
            .collect();
        annotate_calls_block_with_order(&mut structured.body, &call_map, &CALL_ARG_ORDER);
    }
    let lifted_switch: bool = block_contains_switch(&structured.body);
    let ret: FnReturn = match vec_abi.ret {
        VectorRet::Vector(arr) => FnReturn::Vec(arr),
        VectorRet::Void => FnReturn::Void,
        VectorRet::None => FnReturn::Int(return_width),
    };
    let sret_plan: Option<SretPlan> = match ret {
        FnReturn::Int(_) => detect_sret(&structured.body, Abi::Aapcs64),
        FnReturn::Fp(_) | FnReturn::Void | FnReturn::Vec(_) => None,
    };
    let mut params: Vec<Reg> = infer_params(&structured.body, Abi::Aapcs64);
    if let Some(plan) = &sret_plan {
        params.retain(|reg: &Reg| *reg != plan.ptr);
    }
    let signature: FnSignature = FnSignature {
        fp: Vec::new(),
        int: params.clone(),
        vec: vec_abi.params.clone(),
        ret,
    };
    let frame_shape: FrameShape = classify_frame(insns);
    let frame = plan_frame(&structured.body, frame_shape)?;
    let aggregate_plan: AggregatePlan =
        infer_aggregate_plan(&structured.body, &params, frame.as_ref());
    let source: String = emit_c(
        &structured.body,
        &signature,
        frame.as_ref(),
        sret_plan.as_ref(),
        &aggregate_plan,
    );
    let rust_source: Option<String> = emit_rust(
        &structured.body,
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
        FnReturn::Int(_) | FnReturn::Fp(_) => return_width.bits(),
    };
    Ok(LeafRecovery {
        source,
        rust_source,
        return_width_bits,
        params,
        fp_params: Vec::<ScalarType>::new(),
        returns_fp: None,
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
    })
}

fn lower_alu(insn: &DisasmInsn) -> Result<(RegRef, Vec<Stmt>)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if !(3..=4).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed integer alu instruction"));
    }
    let dest: RegRef = parse_reg(operands[0])?;
    let lhs: RegRef = parse_reg(operands[1])?;
    if dest.width != lhs.width {
        return Err(reject_at(insn, "mixed-width integer alu instruction"));
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
        _ => return Err(reject_at(insn, "unsupported integer alu instruction")),
    };
    let mut prefix: Vec<Stmt> = Vec::new();
    let mut rhs: Source = parse_source(operands[2], dest.width)?;
    if let Source::Reg(reg) = rhs
        && reg.width != dest.width
    {
        return Err(reject_at(insn, "mixed-width integer alu source"));
    }
    if operands.len() == 4 {
        let Source::Reg(reg): Source = rhs else {
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
        rhs = Source::Reg(shifted);
    }
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

fn subtract_flags(insn: &DisasmInsn) -> Result<(Vec<Stmt>, Flags)> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if operands.len() != 3 {
        return Err(reject_at(
            insn,
            "flag-setting subtract has an unsupported modifier",
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
    Ok((
        vec![
            Stmt::Assign {
                dest: flag_lhs,
                src: Source::Reg(lhs),
            },
            Stmt::Assign {
                dest: flag_rhs,
                src: rhs,
            },
        ],
        Flags::Cmp {
            lhs: flag_lhs,
            rhs: Source::Reg(flag_rhs),
        },
    ))
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
        stmts.push(base_update(mem.base, delta)?);
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
        stmts.push(base_update(mem.base, delta)?);
    }
    Ok((value, stmts))
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
        stmts.push(base_update(first_mem.base, delta)?);
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
        stmts.push(base_update(first_mem.base, delta)?);
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

fn frame_analysis(insns: &[DisasmInsn]) -> Result<FrameAnalysis> {
    let mut frame: FrameInfo = FrameInfo::default();
    let mut management: BTreeSet<usize> = BTreeSet::new();
    for (index, insn) in insns.iter().enumerate() {
        let operands: Vec<&str> = split_operands(&insn.operands);
        if insn.mnemonic == "sub"
            && operands.len() == 3
            && operands[0] == "sp"
            && operands[1] == "sp"
        {
            let allocation: i64 = parse_immediate(operands[2])?;
            frame.sp_to_entry = add_frame_allocation(frame.sp_to_entry, allocation, insn)?;
            management.insert(index);
        } else if insn.mnemonic == "stp"
            && operands.len() >= 3
            && operands[0] == "x29"
            && operands[1] == "x30"
        {
            let (mem, pre_index): (MemRef, bool) = parse_memory(operands[2], Width::W64)?;
            if pre_index {
                let allocation: i64 = mem
                    .disp
                    .checked_neg()
                    .ok_or_else(|| reject_at(insn, "stack allocation overflow"))?;
                frame.sp_to_entry = add_frame_allocation(frame.sp_to_entry, allocation, insn)?;
            }
            management.insert(index);
        } else if insn.mnemonic == "mov" && operands.as_slice() == ["x29", "sp"] {
            frame.fp_to_entry = Some(frame.sp_to_entry);
            management.insert(index);
        } else if insn.mnemonic == "add"
            && operands.len() == 3
            && operands[0] == "x29"
            && operands[1] == "sp"
        {
            let adjustment: i64 = parse_immediate(operands[2])?;
            let fp_to_entry: i64 = frame
                .sp_to_entry
                .checked_sub(adjustment)
                .ok_or_else(|| reject_at(insn, "frame pointer adjustment overflow"))?;
            if !(0..=MAX_FRAME_BYTES).contains(&fp_to_entry) {
                return Err(reject_at(
                    insn,
                    "frame pointer is outside the bounded frame",
                ));
            }
            frame.fp_to_entry = Some(fp_to_entry);
            management.insert(index);
        } else if is_preserved_register_store(insn) {
            let allocation: i64 = preserved_register_store_allocation(insn)?;
            if allocation != 0 {
                frame.sp_to_entry = add_frame_allocation(frame.sp_to_entry, allocation, insn)?;
            }
            management.insert(index);
        } else {
            break;
        }
    }
    let mut saw_return: bool = false;
    let mut restored: i64 = 0;
    for (index, insn) in insns.iter().enumerate().rev() {
        if !saw_return {
            if insn.mnemonic == "ret" && insn.operands.trim().is_empty() {
                saw_return = true;
                continue;
            }
            break;
        }
        if let Some(delta) = epilogue_restore(insn, frame)? {
            if delta < 0 || delta % 16 != 0 {
                return Err(reject_at(
                    insn,
                    "stack restoration is outside the bounded aligned frame",
                ));
            }
            let next_restored: i64 = restored
                .checked_add(delta)
                .ok_or_else(|| reject_at(insn, "stack restoration overflow"))?;
            if next_restored > frame.sp_to_entry {
                break;
            }
            restored = next_restored;
            management.insert(index);
        } else {
            break;
        }
    }
    if frame.sp_to_entry != 0 && (!saw_return || restored != frame.sp_to_entry) {
        return Err(reject(
            "stack epilogue does not exactly restore the bounded frame",
        ));
    }
    Ok(FrameAnalysis {
        info: frame,
        management,
    })
}

fn preserved_register_store_allocation(insn: &DisasmInsn) -> Result<i64> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    let register_count: usize = if insn.mnemonic == "str" { 1 } else { 2 };
    let memory_operand: &str = operands
        .get(register_count)
        .ok_or_else(|| reject_at(insn, "preserved-register store lacks an address"))?;
    let (mem, pre_index): (MemRef, bool) = parse_memory(memory_operand, Width::W64)?;
    if !pre_index {
        return Ok(0);
    }
    mem.disp
        .checked_neg()
        .ok_or_else(|| reject_at(insn, "preserved-register allocation overflow"))
}

fn add_frame_allocation(current: i64, allocation: i64, insn: &DisasmInsn) -> Result<i64> {
    if allocation <= 0 || allocation % 16 != 0 {
        return Err(reject_at(
            insn,
            "stack allocation is outside the bounded aligned frame",
        ));
    }
    let total: i64 = current
        .checked_add(allocation)
        .ok_or_else(|| reject_at(insn, "stack allocation overflow"))?;
    if total > MAX_FRAME_BYTES {
        return Err(reject_at(
            insn,
            "stack allocation is outside the bounded aligned frame",
        ));
    }
    Ok(total)
}

fn epilogue_restore(insn: &DisasmInsn, frame: FrameInfo) -> Result<Option<i64>> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    if insn.mnemonic == "add" && operands.len() == 3 && operands[0] == "sp" && operands[1] == "sp" {
        return parse_immediate(operands[2]).map(Some);
    }
    if insn.mnemonic == "mov" && operands.as_slice() == ["sp", "x29"] {
        let fp_to_entry: i64 = frame
            .fp_to_entry
            .ok_or_else(|| reject_at(insn, "epilogue frame pointer was not established"))?;
        return frame
            .sp_to_entry
            .checked_sub(fp_to_entry)
            .map(Some)
            .ok_or_else(|| reject_at(insn, "epilogue frame pointer offset overflow"));
    }
    if (insn.mnemonic == "ldp"
        && operands.len() >= 3
        && operands[0] == "x29"
        && operands[1] == "x30")
        || is_preserved_register_load(insn)
    {
        let register_count: usize = if insn.mnemonic == "ldr" { 1 } else { 2 };
        let memory_operand: &str = operands
            .get(register_count)
            .ok_or_else(|| reject_at(insn, "preserved-register load lacks an address"))?;
        let (mem, pre_index): (MemRef, bool) = parse_memory(memory_operand, Width::W64)?;
        if pre_index {
            return Ok(Some(mem.disp));
        }
        return operands
            .get(register_count + 1)
            .map(|operand: &&str| parse_immediate(operand))
            .transpose()
            .map(|value: Option<i64>| Some(value.unwrap_or(0)));
    }
    Ok(None)
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
        if call.arg_count <= 8 {
            continue;
        }
        let expected: usize = call.arg_count - 8;
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
    if terms.is_empty() || terms.len() > 2 {
        return Err(reject("memory operand uses unsupported addressing"));
    }
    let base: RegRef = parse_reg(terms[0])?;
    if base.width != Width::W64 {
        return Err(reject("memory base is not a 64-bit register"));
    }
    let disp: i64 = terms
        .get(1)
        .map(|value: &&str| parse_immediate(value))
        .transpose()?
        .unwrap_or(0);
    Ok((
        MemRef {
            base: Some(base.reg),
            index: None,
            disp,
            width,
        },
        pre_index,
    ))
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

fn is_preserved_register_store(insn: &DisasmInsn) -> bool {
    if !matches!(insn.mnemonic.as_str(), "str" | "stp") {
        return false;
    }
    let operands: Vec<&str> = split_operands(&insn.operands);
    let register_count: usize = if insn.mnemonic == "str" { 1 } else { 2 };
    if operands.len() != register_count + 1 || !operands[register_count].trim().starts_with("[sp") {
        return false;
    }
    operands[..register_count].iter().all(|operand: &&str| {
        operand
            .strip_prefix('x')
            .and_then(|value: &str| value.parse::<u8>().ok())
            .is_some_and(|number: u8| (19..=28).contains(&number) || number == 30)
    })
}

fn is_preserved_register_load(insn: &DisasmInsn) -> bool {
    if !matches!(insn.mnemonic.as_str(), "ldr" | "ldp") {
        return false;
    }
    let operands: Vec<&str> = split_operands(&insn.operands);
    let register_count: usize = if insn.mnemonic == "ldr" { 1 } else { 2 };
    if !(register_count + 1..=register_count + 2).contains(&operands.len())
        || !operands[register_count].trim().starts_with("[sp")
    {
        return false;
    }
    operands[..register_count].iter().all(|operand: &&str| {
        operand
            .strip_prefix('x')
            .and_then(|value: &str| value.parse::<u8>().ok())
            .is_some_and(|number: u8| (19..=28).contains(&number) || number == 30)
    })
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

fn classify_frame(insns: &[DisasmInsn]) -> FrameShape {
    let rbp_is_frame: bool = insns
        .iter()
        .any(|insn: &DisasmInsn| insn.operands.contains("[x29") && !is_frame_management(insn));
    if rbp_is_frame {
        FrameShape {
            base: Some(Reg::Rbp),
            rbp_is_frame: true,
        }
    } else if insns
        .iter()
        .any(|insn: &DisasmInsn| insn.operands.contains("[sp") || is_frame_management(insn))
    {
        FrameShape {
            base: Some(Reg::Rsp),
            rbp_is_frame: false,
        }
    } else {
        FrameShape {
            base: None,
            rbp_is_frame: false,
        }
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
        i64::try_from(magnitude).map_err(|_| reject("immediate exceeds signed ir range"))
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

fn parse_unsigned_literal(token: &str) -> Option<u64> {
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
        Flags::Cmp { lhs, rhs } => {
            lhs.reg == reg || matches!(rhs, Source::Reg(source) if source.reg == reg)
        }
        Flags::Test { operand } | Flags::TestImm { operand, .. } => operand.reg == reg,
        Flags::Sign { result } => result.reg == reg,
        Flags::CmpMem { .. } | Flags::FpCmp { .. } | Flags::Snapshot { .. } => true,
    }
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

fn is_vector_register_token(token: &str) -> bool {
    let mut chars = token.trim().chars();
    chars.next() == Some('v') && chars.next().is_some_and(|ch: char| ch.is_ascii_digit())
}

fn is_qreg_token(token: &str) -> bool {
    let mut chars = token.trim().chars();
    chars.next() == Some('q') && chars.next().is_some_and(|ch: char| ch.is_ascii_digit())
}

fn lower_vector(insn: &DisasmInsn) -> Result<Vec<Stmt>> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    match insn.mnemonic.as_str() {
        "add" | "sub" | "mul" => vector_bin(insn, &operands, false),
        "fadd" | "fsub" | "fmul" | "fdiv" => vector_bin(insn, &operands, true),
        "ldr" => vector_load_store(insn, &operands, true),
        "str" => vector_load_store(insn, &operands, false),
        "dup" => vector_dup(insn, &operands),
        _ => Err(reject_at(insn, "unsupported instruction")),
    }
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

fn vector_load_store(insn: &DisasmInsn, operands: &[&str], is_load: bool) -> Result<Vec<Stmt>> {
    if !(2..=3).contains(&operands.len()) {
        return Err(reject_at(insn, "malformed vector load or store"));
    }
    let reg: u8 = parse_qreg(operands[0])
        .ok_or_else(|| reject_at(insn, "vector load or store requires a q register"))?;
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
        stmts.push(base_update(mem.base, delta)?);
    }
    let access: MemRef = mem;
    let memory_stmt: Stmt = if is_load {
        Stmt::Vector(VecStmt::Load {
            dest: reg,
            arr: None,
            addr: access,
        })
    } else {
        Stmt::Vector(VecStmt::Store {
            src: reg,
            arr: None,
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

fn resolve_vector_types(items: &mut [Item]) -> Result<()> {
    let mut types: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    for item in items.iter() {
        let ItemKind::Stmt(Stmt::Vector(vec)) = &item.kind else {
            continue;
        };
        match vec {
            VecStmt::Bin {
                dest,
                lhs,
                rhs,
                arr,
                ..
            } => {
                note_vector_type(&mut types, *dest, *arr)?;
                note_vector_type(&mut types, *lhs, *arr)?;
                note_vector_type(&mut types, *rhs, *arr)?;
            }
            VecStmt::Dup { dest, arr, .. } => note_vector_type(&mut types, *dest, *arr)?,
            VecStmt::Load {
                dest,
                arr: Some(arr),
                ..
            } => note_vector_type(&mut types, *dest, *arr)?,
            VecStmt::Store {
                src,
                arr: Some(arr),
                ..
            } => note_vector_type(&mut types, *src, *arr)?,
            VecStmt::Load { arr: None, .. } | VecStmt::Store { arr: None, .. } => {}
        }
    }
    for item in items.iter_mut() {
        let ItemKind::Stmt(Stmt::Vector(vec)) = &mut item.kind else {
            continue;
        };
        match vec {
            VecStmt::Load { dest, arr, .. } => {
                *arr = Some(resolved_wide_arrangement(&types, *dest)?);
            }
            VecStmt::Store { src, arr, .. } => {
                *arr = Some(resolved_wide_arrangement(&types, *src)?);
            }
            VecStmt::Bin { .. } | VecStmt::Dup { .. } => {}
        }
    }
    Ok(())
}

fn note_vector_type(
    types: &mut BTreeMap<u8, VecArrangement>,
    reg: u8,
    arr: VecArrangement,
) -> Result<()> {
    match types.get(&reg) {
        Some(existing) if *existing != arr => Err(reject(
            "vector register is used with conflicting arrangements",
        )),
        _ => {
            types.insert(reg, arr);
            Ok(())
        }
    }
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
    for item in items {
        match &item.kind {
            ItemKind::Stmt(Stmt::Vector(vec)) => {
                has_vector = true;
                record_vector_types(&mut types, vec);
                for (reg, arr) in vector_reads(vec) {
                    if !written.contains(&reg) && !params.iter().any(|(r, _)| *r == reg) {
                        params.push((reg, arr));
                    }
                }
                if let Some(dest) = vector_write(vec) {
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
            }
            ItemKind::Stmt(stmt) => {
                if stmt_writes_rax_int(stmt) {
                    wrote_int_result = true;
                }
            }
            ItemKind::Branch { .. }
            | ItemKind::Jmp { .. }
            | ItemKind::Switch { .. }
            | ItemKind::Ret => {}
        }
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
        VecStmt::Dup { dest, arr, .. } => {
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
    }
}

fn vector_reads(vec: &VecStmt) -> Vec<(u8, VecArrangement)> {
    match vec {
        VecStmt::Bin { lhs, rhs, arr, .. } => vec![(*lhs, *arr), (*rhs, *arr)],
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
        VecStmt::Load { .. } | VecStmt::Dup { .. } => Vec::new(),
    }
}

fn vector_write(vec: &VecStmt) -> Option<u8> {
    match vec {
        VecStmt::Bin { dest, .. } | VecStmt::Dup { dest, .. } | VecStmt::Load { dest, .. } => {
            Some(*dest)
        }
        VecStmt::Store { .. } => None,
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
