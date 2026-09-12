use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::SleighError;
use crate::compiler::{
    CompiledSpec, ConflictPolicy, ContextState, DecodeOutcome, compile_spec_with_policy,
};
use crate::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use crate::syntax::{SleighSpec, parse_spec};
use crate::vendor::preprocessed_arm32_source;

use super::{
    ArmMode, DecodedBlock, Lifted, UniqueAllocator, add_signed_offset, bits, constant,
    emit_condition, emit_flags, named_register, sign_extend_u64, unsupported_constructor,
};

static ARM32_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();

#[derive(Debug)]
struct ArmLifted {
    mnemonic: String,
    operands: String,
    ops: Vec<PcodeOp>,
}

pub(super) fn decode_block(bytes: &[u8], address: u64, mode: ArmMode) -> DecodedBlock {
    let compiled_result: &Result<CompiledSpec, SleighError> = ARM32_SPEC.get_or_init(compile_arm32);
    let compiled: &CompiledSpec = match compiled_result {
        Ok(value) => value,
        Err(error) => return spec_error(bytes, address, error),
    };
    let mut context: ContextState = BTreeMap::new();
    context.insert(
        "TMode".to_owned(),
        i64::from(u8::from(mode == ArmMode::Thumb)),
    );
    context.insert("ARMcondCk".to_owned(), 1);
    if mode == ArmMode::A32 {
        context.insert("ARMcond".to_owned(), 1);
    }
    let mut allocator: UniqueAllocator = UniqueAllocator::default();
    let mut instructions: Vec<PcodeInstr> = Vec::new();
    let mut ordered_ops: Vec<PcodeOp> = Vec::new();
    let mut cursor: usize = 0;
    let minimum: usize = if mode == ArmMode::Thumb { 2 } else { 4 };
    while cursor < bytes.len() {
        let remaining: usize = bytes.len().saturating_sub(cursor);
        let instruction_address: u64 =
            address.wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX));
        if remaining < minimum {
            let instruction: PcodeInstr = truncated(&bytes[cursor..], instruction_address);
            instructions.push(instruction);
            cursor = bytes.len();
            break;
        }
        let available: &[u8] = &bytes[cursor..];
        let outcome: DecodeOutcome =
            compiled.decode_complete(available, instruction_address, &context);
        let instruction: PcodeInstr = lift_outcome(
            compiled,
            outcome,
            available,
            instruction_address,
            mode,
            &mut allocator,
        );
        let length: usize = instruction.length.max(1).min(remaining);
        ordered_ops.extend(instruction.ops.iter().cloned());
        instructions.push(instruction);
        cursor = cursor.saturating_add(length);
    }
    DecodedBlock {
        consumed: cursor.min(bytes.len()),
        instructions,
        ordered_ops,
    }
}

fn compile_arm32() -> Result<CompiledSpec, SleighError> {
    let source: String = preprocessed_arm32_source()?;
    let spec: SleighSpec = parse_spec(&source)?;
    compile_spec_with_policy(spec, ConflictPolicy::FirstDefined)
}

fn lift_outcome(
    compiled: &CompiledSpec,
    outcome: DecodeOutcome,
    bytes: &[u8],
    address: u64,
    mode: ArmMode,
    allocator: &mut UniqueAllocator,
) -> PcodeInstr {
    match outcome {
        DecodeOutcome::Matched(matched) => {
            let length: usize = matched.length.min(bytes.len());
            let instruction_bytes: &[u8] = bytes.get(..length).unwrap_or(bytes);
            if matched.mnemonic == "blx" {
                let mnemonic: String = matched.mnemonic.clone();
                return unsupported_constructor(compiled, matched, instruction_bytes, mnemonic);
            }
            let lifted: Option<ArmLifted> = match mode {
                ArmMode::A32 => read_a32(instruction_bytes)
                    .and_then(|word: u32| lift_a32(compiled.source(), word, address, allocator)),
                ArmMode::Thumb => {
                    lift_thumb(compiled.source(), instruction_bytes, address, allocator)
                }
            };
            if let Some(value) = lifted {
                return PcodeInstr {
                    address,
                    bytes: instruction_bytes.to_vec(),
                    length,
                    mnemonic: value.mnemonic,
                    operands: value.operands,
                    ops: value.ops,
                    status: DecodeStatus::Supported,
                };
            }
            let mnemonic: String = matched.mnemonic.clone();
            unsupported_constructor(compiled, matched, instruction_bytes, mnemonic)
        }
        DecodeOutcome::NoMatch => PcodeInstr {
            address,
            bytes: bytes.get(..mode_width(mode)).unwrap_or(bytes).to_vec(),
            length: mode_width(mode).min(bytes.len()),
            mnemonic: ".inst".to_owned(),
            operands: hex_bytes(bytes.get(..mode_width(mode)).unwrap_or(bytes)),
            ops: vec![PcodeOp::CallOther {
                name: "arm_decode_unmatched".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::NoMatch,
        },
        DecodeOutcome::ResourceLimit { attempts } => PcodeInstr {
            address,
            bytes: bytes.get(..mode_width(mode)).unwrap_or(bytes).to_vec(),
            length: mode_width(mode).min(bytes.len()),
            mnemonic: ".resource_limit".to_owned(),
            operands: attempts.to_string(),
            ops: vec![PcodeOp::CallOther {
                name: "arm_decode_resource_limit".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::SpecError,
        },
        DecodeOutcome::Ambiguous { constructors } => PcodeInstr {
            address,
            bytes: bytes.get(..mode_width(mode)).unwrap_or(bytes).to_vec(),
            length: mode_width(mode).min(bytes.len()),
            mnemonic: ".ambiguous".to_owned(),
            operands: constructors
                .iter()
                .map(usize::to_string)
                .collect::<Vec<String>>()
                .join(","),
            ops: vec![PcodeOp::CallOther {
                name: "arm_decode_ambiguous".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::Ambiguous,
        },
        DecodeOutcome::Truncated { available, .. } => {
            truncated(bytes.get(..available).unwrap_or(bytes), address)
        }
    }
}

fn lift_a32(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    if word & 0x0fff_fff0 == 0x012f_ff10 {
        return lift_a32_bx(spec, word, allocator);
    }
    if word & 0x0e00_0000 == 0x0a00_0000 {
        return lift_a32_branch(spec, word, address, allocator);
    }
    if word & 0x0fb0_00f0 == 0x0100_0090 {
        return lift_a32_multiply(spec, word, allocator);
    }
    if word & 0x0fc0_00f0 == 0x0000_0090 {
        return lift_a32_multiply(spec, word, allocator);
    }
    if word & 0x0e00_0000 == 0x0800_0000 {
        return lift_a32_multiple(spec, word, allocator);
    }
    if word & 0x0c00_0000 == 0x0400_0000 {
        return lift_a32_memory(spec, word, allocator);
    }
    if word & 0x0ff0_0000 == 0x0300_0000 || word & 0x0ff0_0000 == 0x0340_0000 {
        return lift_a32_move_wide(spec, word, allocator);
    }
    if word & 0x0c00_0000 == 0 {
        return lift_a32_data(spec, word, address, allocator);
    }
    None
}

fn lift_a32_data(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    if bits(word, 28, 4) != 14 || word & 0x0fc0_00f0 == 0x0000_0090 {
        return None;
    }
    let opcode: u32 = bits(word, 21, 4);
    if !matches!(opcode, 0 | 1 | 2 | 3 | 4 | 10 | 12 | 13) {
        return None;
    }
    let rn_index: u32 = bits(word, 16, 4);
    let rd_index: u32 = bits(word, 12, 4);
    let left: Varnode = arm_input(spec, rn_index, address, ArmMode::A32)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let right: Varnode = a32_operand2(spec, word, address, allocator, &mut ops)?;
    let compare: bool = opcode == 10;
    let mnemonic: &str = match opcode {
        0 => "and",
        1 => "eor",
        2 => "sub",
        3 => "rsb",
        4 => "add",
        10 => "cmp",
        12 => "orr",
        13 => "mov",
        _ => return None,
    };
    let output: Varnode = if compare {
        allocator.allocate(4)?
    } else {
        arm_output(spec, rd_index)?
    };
    match opcode {
        0 => ops.push(PcodeOp::IntAnd {
            output,
            left,
            right,
        }),
        1 => ops.push(PcodeOp::IntXor {
            output,
            left,
            right,
        }),
        2 | 10 => ops.push(PcodeOp::IntSub {
            output,
            left,
            right,
        }),
        3 => ops.push(PcodeOp::IntSub {
            output,
            left: right,
            right: left,
        }),
        4 => ops.push(PcodeOp::IntAdd {
            output,
            left,
            right,
        }),
        12 => ops.push(PcodeOp::IntOr {
            output,
            left,
            right,
        }),
        13 => ops.push(PcodeOp::Copy {
            output,
            input: right,
        }),
        _ => return None,
    }
    let set_flags: bool = compare || bits(word, 20, 1) != 0;
    if set_flags {
        if matches!(opcode, 2 | 3 | 4 | 10) {
            let (flag_left, flag_right): (Varnode, Varnode) = if opcode == 3 {
                (right, left)
            } else {
                (left, right)
            };
            emit_flags(
                spec,
                output,
                flag_left,
                flag_right,
                opcode != 4,
                allocator,
                &mut ops,
            )?;
        } else {
            return None;
        }
    }
    Some(ArmLifted {
        mnemonic: mnemonic.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn a32_operand2(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    if bits(word, 25, 1) != 0 {
        let immediate: u32 = bits(word, 0, 8);
        let rotation: u32 = bits(word, 8, 4).saturating_mul(2);
        return Some(constant(u64::from(immediate.rotate_right(rotation)), 4));
    }
    if bits(word, 4, 1) != 0 {
        return None;
    }
    let rm: Varnode = arm_input(spec, bits(word, 0, 4), address, ArmMode::A32)?;
    let shift_type: u32 = bits(word, 5, 2);
    let encoded_amount: u32 = bits(word, 7, 5);
    if shift_type == 0 && encoded_amount == 0 {
        return Some(rm);
    }
    if shift_type == 3 {
        return None;
    }
    let amount: u32 = if encoded_amount == 0 {
        32
    } else {
        encoded_amount
    };
    let output: Varnode = allocator.allocate(4)?;
    match shift_type {
        0 => ops.push(PcodeOp::IntLeft {
            output,
            input: rm,
            amount: constant(u64::from(amount), 4),
        }),
        1 => ops.push(PcodeOp::IntRight {
            output,
            input: rm,
            amount: constant(u64::from(amount), 4),
        }),
        2 => ops.push(PcodeOp::IntSignedRight {
            output,
            input: rm,
            amount: constant(u64::from(amount), 4),
        }),
        _ => return None,
    }
    Some(output)
}

fn lift_a32_move_wide(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    if bits(word, 28, 4) != 14 {
        return None;
    }
    let destination: Varnode = arm_output(spec, bits(word, 12, 4))?;
    let immediate: u32 = bits(word, 0, 12) | bits(word, 16, 4).checked_shl(12)?;
    let top: bool = bits(word, 22, 1) != 0;
    let mut ops: Vec<PcodeOp> = Vec::new();
    if top {
        let low: Varnode = allocator.allocate(4)?;
        ops.push(PcodeOp::IntAnd {
            output: low,
            left: destination,
            right: constant(0xffff, 4),
        });
        ops.push(PcodeOp::IntOr {
            output: destination,
            left: low,
            right: constant(u64::from(immediate) << 16, 4),
        });
    } else {
        ops.push(PcodeOp::Copy {
            output: destination,
            input: constant(u64::from(immediate), 4),
        });
    }
    Some(ArmLifted {
        mnemonic: if top { "movt" } else { "movw" }.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_a32_multiply(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    if bits(word, 28, 4) != 14 {
        return None;
    }
    let accumulate: bool = bits(word, 21, 1) != 0;
    let destination: Varnode = arm_output(spec, bits(word, 16, 4))?;
    let left: Varnode = arm_input(spec, bits(word, 0, 4), 0, ArmMode::A32)?;
    let right: Varnode = arm_input(spec, bits(word, 8, 4), 0, ArmMode::A32)?;
    let product: Varnode = if accumulate {
        allocator.allocate(4)?
    } else {
        destination
    };
    let mut ops: Vec<PcodeOp> = vec![PcodeOp::IntMult {
        output: product,
        left,
        right,
    }];
    if accumulate {
        let addend: Varnode = arm_input(spec, bits(word, 12, 4), 0, ArmMode::A32)?;
        ops.push(PcodeOp::IntAdd {
            output: destination,
            left: product,
            right: addend,
        });
    }
    if bits(word, 20, 1) != 0 {
        emit_nz(spec, destination, &mut ops)?;
    }
    Some(ArmLifted {
        mnemonic: if accumulate { "mla" } else { "mul" }.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_a32_memory(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    if bits(word, 28, 4) != 14 || bits(word, 25, 1) != 0 || bits(word, 22, 1) != 0 {
        return None;
    }
    let load: bool = bits(word, 20, 1) != 0;
    let preindex: bool = bits(word, 24, 1) != 0;
    let increment: bool = bits(word, 23, 1) != 0;
    let writeback: bool = bits(word, 21, 1) != 0 || !preindex;
    let base: Varnode = arm_output(spec, bits(word, 16, 4))?;
    let data: Varnode = arm_output(spec, bits(word, 12, 4))?;
    let magnitude: i64 = i64::from(bits(word, 0, 12));
    let offset: i64 = if increment { magnitude } else { -magnitude };
    let mut ops: Vec<PcodeOp> = Vec::new();
    let adjusted: Varnode = add_signed_offset(base, offset, allocator, &mut ops)?;
    let pointer: Varnode = if preindex { adjusted } else { base };
    if load {
        ops.push(PcodeOp::Load {
            output: data,
            space: Space::Ram,
            pointer,
        });
    } else {
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value: data,
        });
    }
    if writeback {
        ops.push(PcodeOp::Copy {
            output: base,
            input: adjusted,
        });
    }
    Some(ArmLifted {
        mnemonic: if load { "ldr" } else { "str" }.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_a32_multiple(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    if bits(word, 28, 4) != 14 || bits(word, 22, 1) != 0 {
        return None;
    }
    let list: u32 = bits(word, 0, 16);
    let count: u32 = list.count_ones();
    if count == 0 {
        return None;
    }
    let load: bool = bits(word, 20, 1) != 0;
    let before: bool = bits(word, 24, 1) != 0;
    let increment: bool = bits(word, 23, 1) != 0;
    let writeback: bool = bits(word, 21, 1) != 0;
    let rn: u32 = bits(word, 16, 4);
    let base: Varnode = arm_output(spec, rn)?;
    let count_bytes: i64 = i64::from(count.saturating_mul(4));
    let start_offset: i64 = match (increment, before) {
        (true, false) => 0,
        (true, true) => 4,
        (false, false) => 4_i64.saturating_sub(count_bytes),
        (false, true) => -count_bytes,
    };
    let mut ops: Vec<PcodeOp> = Vec::new();
    let start: Varnode = add_signed_offset(base, start_offset, allocator, &mut ops)?;
    let mut position: u32 = 0;
    let mut return_target: Option<Varnode> = None;
    for register_index in 0_u32..16 {
        if list & (1_u32 << register_index) == 0 {
            continue;
        }
        let pointer: Varnode = add_signed_offset(
            start,
            i64::from(position.saturating_mul(4)),
            allocator,
            &mut ops,
        )?;
        if load && register_index == 15 {
            let target: Varnode = allocator.allocate(4)?;
            ops.push(PcodeOp::Load {
                output: target,
                space: Space::Ram,
                pointer,
            });
            return_target = Some(target);
        } else {
            let register: Varnode = arm_output(spec, register_index)?;
            if load {
                ops.push(PcodeOp::Load {
                    output: register,
                    space: Space::Ram,
                    pointer,
                });
            } else {
                ops.push(PcodeOp::Store {
                    space: Space::Ram,
                    pointer,
                    value: register,
                });
            }
        }
        position = position.saturating_add(1);
    }
    if writeback {
        let final_offset: i64 = if increment { count_bytes } else { -count_bytes };
        let updated: Varnode = add_signed_offset(base, final_offset, allocator, &mut ops)?;
        ops.push(PcodeOp::Copy {
            output: base,
            input: updated,
        });
    }
    if let Some(target) = return_target {
        let branch_target: Varnode = write_interworking_pc(spec, target, allocator, &mut ops)?;
        ops.push(PcodeOp::Return {
            target: Some(branch_target),
        });
    }
    let stack_alias: bool = rn == 13 && writeback;
    let mnemonic: &str = if stack_alias && !load && before && !increment {
        "push"
    } else if stack_alias && load && !before && increment {
        "pop"
    } else if load {
        "ldm"
    } else {
        "stm"
    };
    Some(ArmLifted {
        mnemonic: mnemonic.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_a32_branch(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let condition: u32 = bits(word, 28, 4);
    let link: bool = bits(word, 24, 1) != 0;
    if condition == 15 || link && condition != 14 {
        return None;
    }
    let displacement: i64 = sign_extend_u64(u64::from(bits(word, 0, 24)), 24).checked_mul(4)?;
    let target: u64 = address.wrapping_add(8).wrapping_add_signed(displacement);
    let mut ops: Vec<PcodeOp> = Vec::new();
    if link {
        let link_register: Varnode = named_register(spec, "lr")?;
        ops.push(PcodeOp::Copy {
            output: link_register,
            input: constant(address.wrapping_add(4), 4),
        });
        ops.push(PcodeOp::Call {
            target: code_address(target),
        });
    } else if condition == 14 {
        ops.push(PcodeOp::Branch {
            target: code_address(target),
        });
    } else {
        let predicate: Varnode = emit_condition(spec, condition, allocator, &mut ops)?;
        ops.push(PcodeOp::CBranch {
            target: code_address(target),
            condition: predicate,
        });
    }
    let mnemonic: String = if link {
        "bl".to_owned()
    } else if condition == 14 {
        "b".to_owned()
    } else {
        format!("b{}", condition_suffix(condition)?)
    };
    Some(ArmLifted {
        mnemonic,
        operands: String::new(),
        ops,
    })
}

fn lift_a32_bx(spec: &SleighSpec, word: u32, allocator: &mut UniqueAllocator) -> Option<ArmLifted> {
    if bits(word, 28, 4) != 14 {
        return None;
    }
    let register_index: u32 = bits(word, 0, 4);
    let input: Varnode = arm_input(spec, register_index, 0, ArmMode::A32)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let target: Varnode = write_interworking_pc(spec, input, allocator, &mut ops)?;
    let operation: PcodeOp = if register_index == 14 {
        PcodeOp::Return {
            target: Some(target),
        }
    } else {
        PcodeOp::BranchIndirect { target }
    };
    ops.push(operation);
    Some(ArmLifted {
        mnemonic: "bx".to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_thumb(
    spec: &SleighSpec,
    bytes: &[u8],
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let first: u16 = read_halfword(bytes)?;
    if bytes.len() >= 4 && is_thumb32(first) {
        let second: u16 = read_halfword(bytes.get(2..)?)?;
        return lift_thumb32(spec, first, second, address, allocator);
    }
    lift_thumb16(spec, first, address, allocator)
}

fn lift_thumb16(
    spec: &SleighSpec,
    halfword: u16,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let word: u32 = u32::from(halfword);
    if word == 0xbf00 {
        return Some(ArmLifted {
            mnemonic: "nop".to_owned(),
            operands: String::new(),
            ops: Vec::new(),
        });
    }
    if word & 0xf800 == 0x1800 {
        let immediate: bool = word & 0x0400 != 0;
        let subtract: bool = word & 0x0200 != 0;
        let destination: Varnode = arm_output(spec, bits(word, 0, 3))?;
        let left: Varnode = arm_input(spec, bits(word, 3, 3), address, ArmMode::Thumb)?;
        let right: Varnode = if immediate {
            constant(u64::from(bits(word, 6, 3)), 4)
        } else {
            arm_input(spec, bits(word, 6, 3), address, ArmMode::Thumb)?
        };
        let mut ops: Vec<PcodeOp> = Vec::new();
        if subtract {
            ops.push(PcodeOp::IntSub {
                output: destination,
                left,
                right,
            });
        } else {
            ops.push(PcodeOp::IntAdd {
                output: destination,
                left,
                right,
            });
        }
        emit_flags(
            spec,
            destination,
            left,
            right,
            subtract,
            allocator,
            &mut ops,
        )?;
        return Some(ArmLifted {
            mnemonic: if subtract { "subs" } else { "adds" }.to_owned(),
            operands: String::new(),
            ops,
        });
    }
    if word & 0xe000 == 0 && word & 0x1800 != 0x1800 {
        return lift_thumb_shift(spec, word, address, allocator);
    }
    if word & 0xe000 == 0x2000 {
        return lift_thumb_immediate(spec, word, address, allocator);
    }
    if word & 0xfc00 == 0x4000 {
        return lift_thumb_data(spec, word, address, allocator);
    }
    if word & 0xfc00 == 0x4400 {
        return lift_thumb_high_register(spec, word, address, allocator);
    }
    if word & 0xf000 == 0x6000 {
        return lift_thumb_memory(spec, word, allocator);
    }
    if word & 0xf000 == 0xc000 {
        return lift_thumb_multiple(spec, word, allocator);
    }
    if word & 0xf600 == 0xb400 {
        return lift_thumb_stack(spec, word, allocator);
    }
    if word & 0xf500 == 0xb100 {
        let not_zero: bool = bits(word, 11, 1) != 0;
        let input: Varnode = arm_input(spec, bits(word, 0, 3), address, ArmMode::Thumb)?;
        let condition: Varnode = allocator.allocate(1)?;
        let displacement: u32 =
            bits(word, 3, 5).checked_shl(1)? | bits(word, 9, 1).checked_shl(6)?;
        let target: u64 = address
            .wrapping_add(4)
            .wrapping_add(u64::from(displacement));
        let comparison: PcodeOp = if not_zero {
            PcodeOp::IntNotEqual {
                output: condition,
                left: input,
                right: constant(0, 4),
            }
        } else {
            PcodeOp::IntEqual {
                output: condition,
                left: input,
                right: constant(0, 4),
            }
        };
        return Some(ArmLifted {
            mnemonic: if not_zero { "cbnz" } else { "cbz" }.to_owned(),
            operands: String::new(),
            ops: vec![
                comparison,
                PcodeOp::CBranch {
                    target: code_address(target),
                    condition,
                },
            ],
        });
    }
    if word & 0xf000 == 0xd000 && bits(word, 8, 4) < 14 {
        let condition: u32 = bits(word, 8, 4);
        let displacement: i64 = sign_extend_u64(u64::from(bits(word, 0, 8)), 8).checked_mul(2)?;
        let target: u64 = address.wrapping_add(4).wrapping_add_signed(displacement);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let predicate: Varnode = emit_condition(spec, condition, allocator, &mut ops)?;
        ops.push(PcodeOp::CBranch {
            target: code_address(target),
            condition: predicate,
        });
        return Some(ArmLifted {
            mnemonic: format!("b{}", condition_suffix(condition)?),
            operands: String::new(),
            ops,
        });
    }
    if word & 0xf800 == 0xe000 {
        let displacement: i64 = sign_extend_u64(u64::from(bits(word, 0, 11)), 11).checked_mul(2)?;
        let target: u64 = address.wrapping_add(4).wrapping_add_signed(displacement);
        return Some(ArmLifted {
            mnemonic: "b".to_owned(),
            operands: String::new(),
            ops: vec![PcodeOp::Branch {
                target: code_address(target),
            }],
        });
    }
    None
}

fn lift_thumb_high_register(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let opcode: u32 = bits(word, 8, 2);
    let destination_index: u32 = bits(word, 0, 3) | bits(word, 7, 1).checked_shl(3)?;
    let source_index: u32 = bits(word, 3, 4);
    let source: Varnode = arm_input(spec, source_index, address, ArmMode::Thumb)?;
    if opcode == 3 {
        if bits(word, 7, 1) != 0 {
            return None;
        }
        let mut ops: Vec<PcodeOp> = Vec::new();
        let target: Varnode = write_interworking_pc(spec, source, allocator, &mut ops)?;
        let operation: PcodeOp = if source_index == 14 {
            PcodeOp::Return {
                target: Some(target),
            }
        } else {
            PcodeOp::BranchIndirect { target }
        };
        ops.push(operation);
        return Some(ArmLifted {
            mnemonic: "bx".to_owned(),
            operands: String::new(),
            ops,
        });
    }
    let left: Varnode = arm_input(spec, destination_index, address, ArmMode::Thumb)?;
    let compare: bool = opcode == 1;
    let writes_pc: bool = destination_index == 15 && !compare;
    let output: Varnode = if compare || writes_pc {
        allocator.allocate(4)?
    } else {
        arm_output(spec, destination_index)?
    };
    let mut ops: Vec<PcodeOp> = Vec::new();
    match opcode {
        0 => ops.push(PcodeOp::IntAdd {
            output,
            left,
            right: source,
        }),
        1 => {
            ops.push(PcodeOp::IntSub {
                output,
                left,
                right: source,
            });
            emit_flags(spec, output, left, source, true, allocator, &mut ops)?;
        }
        2 => ops.push(PcodeOp::Copy {
            output,
            input: source,
        }),
        _ => return None,
    }
    if writes_pc {
        let target: Varnode = write_interworking_pc(spec, output, allocator, &mut ops)?;
        if opcode == 2 && source_index == 14 {
            ops.push(PcodeOp::Return {
                target: Some(target),
            });
        } else {
            ops.push(PcodeOp::BranchIndirect { target });
        }
    }
    let mnemonic: &str = match opcode {
        0 => "add",
        1 => "cmp",
        2 => "mov",
        _ => return None,
    };
    Some(ArmLifted {
        mnemonic: mnemonic.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_thumb_shift(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let shift_type: u32 = bits(word, 11, 2);
    if shift_type > 2 {
        return None;
    }
    let destination: Varnode = arm_output(spec, bits(word, 0, 3))?;
    let input: Varnode = arm_input(spec, bits(word, 3, 3), address, ArmMode::Thumb)?;
    let encoded: u32 = bits(word, 6, 5);
    let amount: u32 = if encoded == 0 && shift_type != 0 {
        32
    } else {
        encoded
    };
    let mut ops: Vec<PcodeOp> = Vec::new();
    match shift_type {
        0 => ops.push(PcodeOp::IntLeft {
            output: destination,
            input,
            amount: constant(u64::from(amount), 4),
        }),
        1 => ops.push(PcodeOp::IntRight {
            output: destination,
            input,
            amount: constant(u64::from(amount), 4),
        }),
        2 => ops.push(PcodeOp::IntSignedRight {
            output: destination,
            input,
            amount: constant(u64::from(amount), 4),
        }),
        _ => return None,
    }
    emit_shift_flags(
        spec,
        destination,
        input,
        shift_type,
        amount,
        allocator,
        &mut ops,
    )?;
    let mnemonic: &str = match shift_type {
        0 => "lsls",
        1 => "lsrs",
        2 => "asrs",
        _ => return None,
    };
    Some(ArmLifted {
        mnemonic: mnemonic.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_thumb_immediate(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let opcode: u32 = bits(word, 11, 2);
    let destination: Varnode = arm_output(spec, bits(word, 8, 3))?;
    let immediate: Varnode = constant(u64::from(bits(word, 0, 8)), 4);
    let left: Varnode = arm_input(spec, bits(word, 8, 3), address, ArmMode::Thumb)?;
    let result: Varnode = if opcode == 1 {
        allocator.allocate(4)?
    } else {
        destination
    };
    let mut ops: Vec<PcodeOp> = Vec::new();
    match opcode {
        0 => ops.push(PcodeOp::Copy {
            output: result,
            input: immediate,
        }),
        1 | 3 => ops.push(PcodeOp::IntSub {
            output: result,
            left,
            right: immediate,
        }),
        2 => ops.push(PcodeOp::IntAdd {
            output: result,
            left,
            right: immediate,
        }),
        _ => return None,
    }
    if opcode == 0 {
        emit_nz(spec, result, &mut ops)?;
    } else {
        emit_flags(
            spec,
            result,
            left,
            immediate,
            opcode != 2,
            allocator,
            &mut ops,
        )?;
    }
    let mnemonic: &str = match opcode {
        0 => "movs",
        1 => "cmp",
        2 => "adds",
        3 => "subs",
        _ => return None,
    };
    Some(ArmLifted {
        mnemonic: mnemonic.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_thumb_data(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let opcode: u32 = bits(word, 6, 4);
    if !matches!(opcode, 0 | 1 | 10 | 12 | 13) {
        return None;
    }
    let left: Varnode = arm_input(spec, bits(word, 0, 3), address, ArmMode::Thumb)?;
    let right: Varnode = arm_input(spec, bits(word, 3, 3), address, ArmMode::Thumb)?;
    let compare: bool = opcode == 10;
    let output: Varnode = if compare {
        allocator.allocate(4)?
    } else {
        arm_output(spec, bits(word, 0, 3))?
    };
    let mut ops: Vec<PcodeOp> = Vec::new();
    match opcode {
        0 => ops.push(PcodeOp::IntAnd {
            output,
            left,
            right,
        }),
        1 => ops.push(PcodeOp::IntXor {
            output,
            left,
            right,
        }),
        10 => ops.push(PcodeOp::IntSub {
            output,
            left,
            right,
        }),
        12 => ops.push(PcodeOp::IntOr {
            output,
            left,
            right,
        }),
        13 => ops.push(PcodeOp::IntMult {
            output,
            left,
            right,
        }),
        _ => return None,
    }
    if compare {
        emit_flags(spec, output, left, right, true, allocator, &mut ops)?;
    } else {
        emit_nz(spec, output, &mut ops)?;
    }
    let mnemonic: &str = match opcode {
        0 => "ands",
        1 => "eors",
        10 => "cmp",
        12 => "orrs",
        13 => "muls",
        _ => return None,
    };
    Some(ArmLifted {
        mnemonic: mnemonic.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_thumb_memory(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let load: bool = bits(word, 11, 1) != 0;
    let data: Varnode = arm_output(spec, bits(word, 0, 3))?;
    let base: Varnode = arm_output(spec, bits(word, 3, 3))?;
    let offset: i64 = i64::from(bits(word, 6, 5).saturating_mul(4));
    let mut ops: Vec<PcodeOp> = Vec::new();
    let pointer: Varnode = add_signed_offset(base, offset, allocator, &mut ops)?;
    if load {
        ops.push(PcodeOp::Load {
            output: data,
            space: Space::Ram,
            pointer,
        });
    } else {
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value: data,
        });
    }
    Some(ArmLifted {
        mnemonic: if load { "ldr" } else { "str" }.to_owned(),
        operands: String::new(),
        ops,
    })
}

fn lift_thumb_multiple(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let load: bool = bits(word, 11, 1) != 0;
    let base_index: u32 = bits(word, 8, 3);
    let list: u32 = bits(word, 0, 8);
    lift_thumb_register_list(spec, base_index, list, load, true, allocator).map(|lifted: Lifted| {
        ArmLifted {
            mnemonic: if load { "ldmia" } else { "stmia" }.to_owned(),
            operands: lifted.operands,
            ops: lifted.ops,
        }
    })
}

fn lift_thumb_stack(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let load: bool = bits(word, 11, 1) != 0;
    let extra: u32 = bits(word, 8, 1);
    let mut list: u32 = bits(word, 0, 8);
    if extra != 0 {
        list |= 1_u32 << if load { 15 } else { 14 };
    }
    let lifted: Lifted = lift_thumb_register_list(spec, 13, list, load, true, allocator)?;
    Some(ArmLifted {
        mnemonic: if load { "pop" } else { "push" }.to_owned(),
        operands: lifted.operands,
        ops: lifted.ops,
    })
}

fn lift_thumb_register_list(
    spec: &SleighSpec,
    base_index: u32,
    list: u32,
    load: bool,
    writeback: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    let count: u32 = list.count_ones();
    if count == 0 {
        return None;
    }
    let base: Varnode = arm_output(spec, base_index)?;
    let decrement: bool = base_index == 13 && !load;
    let start_offset: i64 = if decrement {
        -i64::from(count.saturating_mul(4))
    } else {
        0
    };
    let mut ops: Vec<PcodeOp> = Vec::new();
    let start: Varnode = add_signed_offset(base, start_offset, allocator, &mut ops)?;
    let mut position: u32 = 0;
    let mut return_target: Option<Varnode> = None;
    for register_index in 0_u32..16 {
        if list & (1_u32 << register_index) == 0 {
            continue;
        }
        let pointer: Varnode = add_signed_offset(
            start,
            i64::from(position.saturating_mul(4)),
            allocator,
            &mut ops,
        )?;
        if load && register_index == 15 {
            let target: Varnode = allocator.allocate(4)?;
            ops.push(PcodeOp::Load {
                output: target,
                space: Space::Ram,
                pointer,
            });
            return_target = Some(target);
        } else {
            let register: Varnode = arm_output(spec, register_index)?;
            if load {
                ops.push(PcodeOp::Load {
                    output: register,
                    space: Space::Ram,
                    pointer,
                });
            } else {
                ops.push(PcodeOp::Store {
                    space: Space::Ram,
                    pointer,
                    value: register,
                });
            }
        }
        position = position.saturating_add(1);
    }
    if writeback {
        let delta: i64 = if decrement {
            -i64::from(count.saturating_mul(4))
        } else {
            i64::from(count.saturating_mul(4))
        };
        let updated: Varnode = add_signed_offset(base, delta, allocator, &mut ops)?;
        ops.push(PcodeOp::Copy {
            output: base,
            input: updated,
        });
    }
    if let Some(target) = return_target {
        let branch_target: Varnode = write_interworking_pc(spec, target, allocator, &mut ops)?;
        ops.push(PcodeOp::Return {
            target: Some(branch_target),
        });
    }
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_thumb32(
    spec: &SleighSpec,
    first: u16,
    second: u16,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<ArmLifted> {
    let upper: u32 = u32::from(first);
    let lower: u32 = u32::from(second);
    if upper & 0xfbf0 == 0xf240 || upper & 0xfbf0 == 0xf2c0 {
        let top: bool = upper & 0x0080 != 0;
        let immediate: u32 = bits(upper, 0, 4).checked_shl(12)?
            | bits(upper, 10, 1).checked_shl(11)?
            | bits(lower, 12, 3).checked_shl(8)?
            | bits(lower, 0, 8);
        let destination: Varnode = arm_output(spec, bits(lower, 8, 4))?;
        let mut ops: Vec<PcodeOp> = Vec::new();
        if top {
            let low: Varnode = allocator.allocate(4)?;
            ops.push(PcodeOp::IntAnd {
                output: low,
                left: destination,
                right: constant(0xffff, 4),
            });
            ops.push(PcodeOp::IntOr {
                output: destination,
                left: low,
                right: constant(u64::from(immediate) << 16, 4),
            });
        } else {
            ops.push(PcodeOp::Copy {
                output: destination,
                input: constant(u64::from(immediate), 4),
            });
        }
        return Some(ArmLifted {
            mnemonic: if top { "movt" } else { "movw" }.to_owned(),
            operands: String::new(),
            ops,
        });
    }
    if upper & 0xffe0 == 0xeb00 {
        let left: Varnode = arm_input(spec, bits(upper, 0, 4), address, ArmMode::Thumb)?;
        let raw_right: Varnode = arm_input(spec, bits(lower, 0, 4), address, ArmMode::Thumb)?;
        let shift_type: u32 = bits(lower, 4, 2);
        let shift_amount: u32 = bits(lower, 12, 3).checked_shl(2)? | bits(lower, 6, 2);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let right: Varnode = if shift_amount == 0 {
            raw_right
        } else {
            let shifted: Varnode = allocator.allocate(4)?;
            let operation: PcodeOp = match shift_type {
                0 => PcodeOp::IntLeft {
                    output: shifted,
                    input: raw_right,
                    amount: constant(u64::from(shift_amount), 4),
                },
                1 => PcodeOp::IntRight {
                    output: shifted,
                    input: raw_right,
                    amount: constant(u64::from(shift_amount), 4),
                },
                2 => PcodeOp::IntSignedRight {
                    output: shifted,
                    input: raw_right,
                    amount: constant(u64::from(shift_amount), 4),
                },
                _ => return None,
            };
            ops.push(operation);
            shifted
        };
        let output: Varnode = arm_output(spec, bits(lower, 8, 4))?;
        ops.push(PcodeOp::IntAdd {
            output,
            left,
            right,
        });
        return Some(ArmLifted {
            mnemonic: "add".to_owned(),
            operands: String::new(),
            ops,
        });
    }
    if matches!(upper & 0xfff0, 0xf840 | 0xf850) && bits(lower, 11, 1) != 0 {
        let load: bool = upper & 0x0010 != 0;
        let base: Varnode = arm_output(spec, bits(upper, 0, 4))?;
        let data: Varnode = arm_output(spec, bits(lower, 12, 4))?;
        let preindex: bool = bits(lower, 10, 1) != 0;
        let increment: bool = bits(lower, 9, 1) != 0;
        let writeback: bool = bits(lower, 8, 1) != 0;
        let magnitude: i64 = i64::from(bits(lower, 0, 8));
        let offset: i64 = if increment { magnitude } else { -magnitude };
        let mut ops: Vec<PcodeOp> = Vec::new();
        let adjusted: Varnode = add_signed_offset(base, offset, allocator, &mut ops)?;
        let pointer: Varnode = if preindex { adjusted } else { base };
        if load {
            ops.push(PcodeOp::Load {
                output: data,
                space: Space::Ram,
                pointer,
            });
        } else {
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer,
                value: data,
            });
        }
        if writeback {
            ops.push(PcodeOp::Copy {
                output: base,
                input: adjusted,
            });
        }
        return Some(ArmLifted {
            mnemonic: if load { "ldr" } else { "str" }.to_owned(),
            operands: String::new(),
            ops,
        });
    }
    if upper & 0xf800 == 0xf000 && lower & 0xd000 == 0xd000 {
        let sign: u32 = bits(upper, 10, 1);
        let first_complement: u32 = u32::from(bits(lower, 13, 1) == sign);
        let second_complement: u32 = u32::from(bits(lower, 11, 1) == sign);
        let encoded: u32 = sign.checked_shl(24)?
            | first_complement.checked_shl(23)?
            | second_complement.checked_shl(22)?
            | bits(upper, 0, 10).checked_shl(12)?
            | bits(lower, 0, 11).checked_shl(1)?;
        let displacement: i64 = sign_extend_u64(u64::from(encoded), 25);
        let target: u64 = address.wrapping_add(4).wrapping_add_signed(displacement);
        let link: Varnode = named_register(spec, "lr")?;
        return Some(ArmLifted {
            mnemonic: "bl".to_owned(),
            operands: String::new(),
            ops: vec![
                PcodeOp::Copy {
                    output: link,
                    input: constant(address.wrapping_add(4) | 1, 4),
                },
                PcodeOp::Call {
                    target: code_address(target),
                },
            ],
        });
    }
    None
}

fn arm_input(spec: &SleighSpec, index: u32, address: u64, mode: ArmMode) -> Option<Varnode> {
    if index == 15 {
        let pipeline_offset: u64 = match mode {
            ArmMode::A32 => 8,
            ArmMode::Thumb => 4,
        };
        return Some(constant(address.wrapping_add(pipeline_offset), 4));
    }
    arm_output(spec, index)
}

fn write_interworking_pc(
    spec: &SleighSpec,
    input: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let target: Varnode = allocator.allocate(4)?;
    ops.push(PcodeOp::IntAnd {
        output: target,
        left: input,
        right: constant(0xffff_fffe, 4),
    });
    let program_counter: Varnode = arm_output(spec, 15)?;
    ops.push(PcodeOp::Copy {
        output: program_counter,
        input: target,
    });
    Some(target)
}

fn emit_nz(spec: &SleighSpec, result: Varnode, ops: &mut Vec<PcodeOp>) -> Option<()> {
    let negative: Varnode = named_register(spec, "NG")?;
    let zero: Varnode = named_register(spec, "ZR")?;
    ops.push(PcodeOp::IntEqual {
        output: zero,
        left: result,
        right: constant(0, result.size_bytes),
    });
    ops.push(PcodeOp::IntSignedLess {
        output: negative,
        left: result,
        right: constant(0, result.size_bytes),
    });
    Some(())
}

fn emit_shift_flags(
    spec: &SleighSpec,
    result: Varnode,
    input: Varnode,
    shift_type: u32,
    amount: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    emit_nz(spec, result, ops)?;
    if amount == 0 {
        return Some(());
    }
    let carry: Varnode = named_register(spec, "CY")?;
    let shifted: Varnode = allocator.allocate(4)?;
    let extraction_shift: u32 = if shift_type == 0 {
        32_u32.checked_sub(amount)?
    } else {
        amount.checked_sub(1)?
    };
    ops.push(PcodeOp::IntRight {
        output: shifted,
        input,
        amount: constant(u64::from(extraction_shift), 4),
    });
    let masked: Varnode = allocator.allocate(4)?;
    ops.push(PcodeOp::IntAnd {
        output: masked,
        left: shifted,
        right: constant(1, 4),
    });
    ops.push(PcodeOp::IntNotEqual {
        output: carry,
        left: masked,
        right: constant(0, 4),
    });
    Some(())
}

const fn code_address(offset: u64) -> Varnode {
    Varnode {
        offset,
        size_bytes: 4,
        space: Space::Ram,
    }
}

fn arm_output(spec: &SleighSpec, index: u32) -> Option<Varnode> {
    let name: String = match index {
        0..=12 => format!("r{index}"),
        13 => "sp".to_owned(),
        14 => "lr".to_owned(),
        15 => "pc".to_owned(),
        _ => return None,
    };
    named_register(spec, &name)
}

const fn condition_suffix(condition: u32) -> Option<&'static str> {
    match condition {
        0 => Some("eq"),
        1 => Some("ne"),
        2 => Some("cs"),
        3 => Some("cc"),
        4 => Some("mi"),
        5 => Some("pl"),
        6 => Some("vs"),
        7 => Some("vc"),
        8 => Some("hi"),
        9 => Some("ls"),
        10 => Some("ge"),
        11 => Some("lt"),
        12 => Some("gt"),
        13 => Some("le"),
        14 => Some("al"),
        15 => Some("nv"),
        _ => None,
    }
}

fn read_a32(bytes: &[u8]) -> Option<u32> {
    let array: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn read_halfword(bytes: &[u8]) -> Option<u16> {
    let array: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

const fn is_thumb32(first: u16) -> bool {
    matches!(first >> 11, 0b11101..=0b11111)
}

const fn mode_width(mode: ArmMode) -> usize {
    match mode {
        ArmMode::A32 => 4,
        ArmMode::Thumb => 2,
    }
}

fn truncated(bytes: &[u8], address: u64) -> PcodeInstr {
    PcodeInstr {
        address,
        bytes: bytes.to_vec(),
        length: bytes.len(),
        mnemonic: ".byte".to_owned(),
        operands: hex_bytes(bytes),
        ops: Vec::new(),
        status: DecodeStatus::Truncated,
    }
}

fn spec_error(bytes: &[u8], address: u64, error: &SleighError) -> DecodedBlock {
    if bytes.is_empty() {
        return DecodedBlock {
            consumed: 0,
            instructions: Vec::new(),
            ordered_ops: Vec::new(),
        };
    }
    let operation: PcodeOp = PcodeOp::CallOther {
        name: "arm_sleigh_spec_error".to_owned(),
        output: None,
        inputs: Vec::new(),
    };
    DecodedBlock {
        consumed: bytes.len(),
        instructions: vec![PcodeInstr {
            address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: ".spec_error".to_owned(),
            operands: error.to_string(),
            ops: vec![operation.clone()],
            status: DecodeStatus::SpecError,
        }],
        ordered_ops: vec![operation],
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}
