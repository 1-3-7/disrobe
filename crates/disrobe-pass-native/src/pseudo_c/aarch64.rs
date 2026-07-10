use super::{
    Abi, AggregatePlan, BinOp, CondKind, Error, Flags, FnReturn, FnSignature, FrameShape, Item,
    ItemKind, LeafRecovery, MemRef, Reg, RegRef, ResolvedCall, Result, ScalarType, Source,
    SretPlan, SretReturn, Stmt, Structured, Width, annotate_calls_block_with_order,
    collect_call_targets, condition_is_sound, detect_sret, emit_c, emit_rust, infer_aggregate_plan,
    infer_params, plan_frame, structure_items,
};
use crate::arch::{Arch, DisasmInsn, disassemble};
use std::collections::{BTreeMap, BTreeSet};

const MAX_INSTRUCTIONS: usize = 4096;
const ITEM_STRIDE: u64 = 16;
const MAX_FRAME_BYTES: i64 = 1 << 20;

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

pub(super) fn recover(machine_code: &[u8], base: u64) -> Result<LeafRecovery> {
    recover_with_calls(machine_code, base, &[])
}

pub(super) fn recover_with_calls(
    machine_code: &[u8],
    base: u64,
    calls: &[ResolvedCall],
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
    let mut items: Vec<Item> = Vec::new();
    let mut return_width: Width = Width::W64;
    let mut flags: Option<TrackedFlags> = None;
    let frame: FrameAnalysis = frame_analysis(&insns)?;
    let outgoing: BTreeMap<usize, Vec<OutgoingSlot>> = outgoing_stores(&insns, calls)?;
    for (index, insn) in insns.iter().enumerate() {
        let address: u64 = item_address(base, index, 0)?;
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
        let sets_flags: bool = matches!(
            insn.mnemonic.as_str(),
            "adds" | "subs" | "cmp" | "cmn" | "tst"
        );
        let consumes_flags: bool = insn.mnemonic.starts_with("b.");
        if !sets_flags && !consumes_flags {
            flags = None;
        }
        match insn.mnemonic.as_str() {
            "add" | "adds" | "sub" | "subs" | "and" | "orr" | "eor" | "lsl" | "lsr" | "asr"
            | "mul" => {
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
                    flags = new_flags;
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
            "ldr" | "str" => {
                let (dest, stmts): (Option<RegRef>, Vec<Stmt>) =
                    lower_memory(insn, frame.info, outgoing_slots)?;
                push_stmts(&mut items, base, index, stmts)?;
                if let Some(dest) = dest
                    && dest.reg == Reg::Rax
                {
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
                flags = Some(new_flags);
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
            _ => return Err(reject_at(insn, "unsupported instruction")),
        }
    }
    finish(&insns, &items, return_width, calls)
}

fn finish(
    insns: &[DisasmInsn],
    items: &[Item],
    return_width: Width,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    let mut structured: Structured = structure_items(items)?;
    if !calls.is_empty() {
        let call_map = calls
            .iter()
            .map(|call: &ResolvedCall| (call.target, call))
            .collect();
        annotate_calls_block_with_order(&mut structured.body, &call_map, &CALL_ARG_ORDER);
    }
    let sret_plan: Option<SretPlan> = detect_sret(&structured.body, Abi::Aapcs64);
    let mut params: Vec<Reg> = infer_params(&structured.body, Abi::Aapcs64);
    if let Some(plan) = &sret_plan {
        params.retain(|reg: &Reg| *reg != plan.ptr);
    }
    let signature: FnSignature = FnSignature {
        fp: Vec::new(),
        int: params.clone(),
        ret: FnReturn::Int(return_width),
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
    Ok(LeafRecovery {
        source,
        rust_source,
        return_width_bits: return_width.bits(),
        params,
        fp_params: Vec::<ScalarType>::new(),
        returns_fp: None,
        lifted_split_return: structured.lifted_split_return,
        lifted_loop: structured.lifted_loop,
        lifted_switch: false,
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
    let op: BinOp = match insn.mnemonic.as_str() {
        "add" | "adds" => BinOp::Add,
        "sub" | "subs" => BinOp::Sub,
        "and" => BinOp::And,
        "orr" => BinOp::Or,
        "eor" => BinOp::Xor,
        "lsl" => BinOp::Shl,
        "lsr" => BinOp::Shr,
        "asr" => BinOp::Sar,
        "mul" => BinOp::Imul,
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
    let (value, source, width): (Option<RegRef>, Source, Width) = if insn.mnemonic == "ldr" {
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
    let memory_stmt: Stmt = if insn.mnemonic == "ldr" {
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
            matches!(prefix, 'v' | 'q' | 'd' | 's' | 'h' | 'b' | 'z' | 'p')
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

fn reject(message: &str) -> Error {
    Error::LlvmIr(format!("aarch64 reject: {message}"))
}

fn reject_at(insn: &DisasmInsn, message: &str) -> Error {
    reject(&format!(
        "{message} `{} {}` at {:#x}",
        insn.mnemonic, insn.operands, insn.address
    ))
}
