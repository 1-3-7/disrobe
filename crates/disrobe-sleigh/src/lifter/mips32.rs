use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::SleighError;
use crate::compiler::{
    CompiledSpec, ConflictPolicy, ContextState, DecodeOutcome, compile_spec_with_policy,
};
use crate::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use crate::syntax::{Constructor, Endian, SleighSpec, parse_spec};
use crate::vendor::{preprocessed_mips32be_source, preprocessed_mips32le_source};

use super::{
    DecodedBlock, UniqueAllocator, add_signed_offset, bits, constant, named_register,
    sign_extend_u64, unsupported_constructor,
};

static MIPS32_BE_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();
static MIPS32_LE_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();

#[derive(Debug)]
struct DecodedMips {
    delay_slot: bool,
    instruction: PcodeInstr,
}

#[derive(Debug)]
struct MipsLifted {
    delay_slot: bool,
    mnemonic: String,
    ops: Vec<PcodeOp>,
    status: DecodeStatus,
}

pub(super) fn decode_block(bytes: &[u8], address: u64, endian: Endian) -> DecodedBlock {
    let compiled_result: &Result<CompiledSpec, SleighError> = match endian {
        Endian::Big => MIPS32_BE_SPEC.get_or_init(compile_mips32be),
        Endian::Little => MIPS32_LE_SPEC.get_or_init(compile_mips32le),
    };
    let compiled: &CompiledSpec = match compiled_result {
        Ok(value) => value,
        Err(error) => return spec_error(bytes, address, error),
    };
    let mut context: ContextState = BTreeMap::new();
    context.insert("ISA_MODE".to_owned(), 0);
    let mut allocator: UniqueAllocator = UniqueAllocator::default();
    let mut instructions: Vec<PcodeInstr> = Vec::new();
    let mut ordered_ops: Vec<PcodeOp> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let remaining: usize = bytes.len().saturating_sub(cursor);
        let instruction_address: u64 =
            address.wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX));
        if remaining < 4 {
            instructions.push(truncated(&bytes[cursor..], instruction_address));
            cursor = bytes.len();
            break;
        }
        let decoded: DecodedMips = decode_one(
            compiled,
            &bytes[cursor..],
            instruction_address,
            endian,
            &context,
            &mut allocator,
        );
        if !decoded.delay_slot {
            ordered_ops.extend(decoded.instruction.ops.iter().cloned());
            instructions.push(decoded.instruction);
            cursor = cursor.saturating_add(4);
            continue;
        }
        if remaining < 8 {
            let mut branch: PcodeInstr = decoded.instruction;
            branch.status = DecodeStatus::Unsupported;
            branch.ops = vec![PcodeOp::CallOther {
                name: "missing_delay_slot".to_owned(),
                output: None,
                inputs: Vec::new(),
            }];
            ordered_ops.extend(branch.ops.iter().cloned());
            instructions.push(branch);
            cursor = cursor.saturating_add(4);
            continue;
        }
        let slot_address: u64 = instruction_address.wrapping_add(4);
        let slot: DecodedMips = decode_one(
            compiled,
            &bytes[cursor.saturating_add(4)..],
            slot_address,
            endian,
            &context,
            &mut allocator,
        );
        if slot.delay_slot {
            let operation: PcodeOp = PcodeOp::CallOther {
                name: "nested_delay_transfer".to_owned(),
                output: None,
                inputs: Vec::new(),
            };
            let mut branch: PcodeInstr = decoded.instruction;
            branch.status = DecodeStatus::Unsupported;
            branch.ops = vec![operation.clone()];
            let mut nested: PcodeInstr = slot.instruction;
            nested.status = DecodeStatus::Unsupported;
            nested.ops = vec![operation.clone()];
            ordered_ops.push(operation);
            instructions.extend([branch, nested]);
            cursor = cursor.saturating_add(8);
            continue;
        }
        append_delayed_ops(
            &decoded.instruction.ops,
            &slot.instruction.ops,
            &mut ordered_ops,
        );
        instructions.extend([decoded.instruction, slot.instruction]);
        cursor = cursor.saturating_add(8);
    }
    DecodedBlock {
        consumed: cursor.min(bytes.len()),
        instructions,
        ordered_ops,
    }
}

fn compile_mips32be() -> Result<CompiledSpec, SleighError> {
    let source: String = preprocessed_mips32be_source()?;
    let spec: SleighSpec = parse_spec(&source)?;
    compile_spec_with_policy(spec, ConflictPolicy::FirstDefined)
}

fn compile_mips32le() -> Result<CompiledSpec, SleighError> {
    let source: String = preprocessed_mips32le_source()?;
    let spec: SleighSpec = parse_spec(&source)?;
    compile_spec_with_policy(spec, ConflictPolicy::FirstDefined)
}

fn decode_one(
    compiled: &CompiledSpec,
    bytes: &[u8],
    address: u64,
    endian: Endian,
    context: &ContextState,
    allocator: &mut UniqueAllocator,
) -> DecodedMips {
    let outcome: DecodeOutcome = compiled.decode(bytes, address, context);
    match outcome {
        DecodeOutcome::Matched(matched) => {
            let instruction_bytes: &[u8] = bytes.get(..4).unwrap_or(bytes);
            let lifted: Option<MipsLifted> = read_word(instruction_bytes, endian)
                .and_then(|word: u32| lift_word(compiled.source(), word, address, allocator));
            if let Some(value) = lifted {
                return DecodedMips {
                    delay_slot: value.delay_slot,
                    instruction: PcodeInstr {
                        address,
                        bytes: instruction_bytes.to_vec(),
                        length: 4,
                        mnemonic: value.mnemonic,
                        operands: String::new(),
                        ops: value.ops,
                        status: value.status,
                    },
                };
            }
            let delay_slot: bool = constructor_has_delay_slot(compiled, matched.constructor_id);
            let mnemonic: String = matched.mnemonic.clone();
            DecodedMips {
                delay_slot,
                instruction: unsupported_constructor(
                    compiled,
                    matched,
                    instruction_bytes,
                    mnemonic,
                ),
            }
        }
        DecodeOutcome::NoMatch => DecodedMips {
            delay_slot: false,
            instruction: PcodeInstr {
                address,
                bytes: bytes.get(..4).unwrap_or(bytes).to_vec(),
                length: 4.min(bytes.len()),
                mnemonic: ".word".to_owned(),
                operands: hex_bytes(bytes.get(..4).unwrap_or(bytes)),
                ops: vec![PcodeOp::CallOther {
                    name: "mips_decode_unmatched".to_owned(),
                    output: None,
                    inputs: Vec::new(),
                }],
                status: DecodeStatus::NoMatch,
            },
        },
        DecodeOutcome::ResourceLimit { attempts } => DecodedMips {
            delay_slot: false,
            instruction: PcodeInstr {
                address,
                bytes: bytes.get(..4).unwrap_or(bytes).to_vec(),
                length: 4.min(bytes.len()),
                mnemonic: ".resource_limit".to_owned(),
                operands: attempts.to_string(),
                ops: vec![PcodeOp::CallOther {
                    name: "mips_decode_resource_limit".to_owned(),
                    output: None,
                    inputs: Vec::new(),
                }],
                status: DecodeStatus::SpecError,
            },
        },
        DecodeOutcome::Ambiguous { constructors } => DecodedMips {
            delay_slot: false,
            instruction: PcodeInstr {
                address,
                bytes: bytes.get(..4).unwrap_or(bytes).to_vec(),
                length: 4.min(bytes.len()),
                mnemonic: ".ambiguous".to_owned(),
                operands: constructors
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<String>>()
                    .join(","),
                ops: vec![PcodeOp::CallOther {
                    name: "mips_decode_ambiguous".to_owned(),
                    output: None,
                    inputs: Vec::new(),
                }],
                status: DecodeStatus::Ambiguous,
            },
        },
        DecodeOutcome::Truncated { available, .. } => DecodedMips {
            delay_slot: false,
            instruction: truncated(bytes.get(..available).unwrap_or(bytes), address),
        },
    }
}

fn lift_word(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<MipsLifted> {
    if word == 0 {
        return Some(supported("nop", Vec::new(), false));
    }
    let opcode: u32 = bits(word, 26, 6);
    match opcode {
        0 => lift_special(spec, word, address, allocator),
        2 | 3 => lift_jump(spec, word, address, opcode == 3),
        4 | 5 => lift_branch(spec, word, address, opcode == 5, allocator),
        9..=15 => lift_immediate(spec, word, opcode, allocator),
        35 | 43 => lift_memory(spec, word, opcode == 35, allocator),
        _ => None,
    }
}

fn lift_special(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<MipsLifted> {
    let function: u32 = bits(word, 0, 6);
    if matches!(function, 8 | 9) {
        return lift_register_jump(spec, word, address, function == 9);
    }
    if matches!(function, 24..=27) {
        return lift_multiply_divide(spec, word, function, allocator);
    }
    if matches!(function, 0 | 2 | 3) {
        return lift_shift(spec, word, function);
    }
    if !matches!(function, 32..=38 | 42 | 43) {
        return None;
    }
    let left: Varnode = mips_input(spec, bits(word, 21, 5))?;
    let right: Varnode = mips_input(spec, bits(word, 16, 5))?;
    let destination_index: u32 = bits(word, 11, 5);
    let trapping: bool = matches!(function, 32 | 34);
    let output: Option<Varnode> = match mips_output(spec, destination_index) {
        Some(destination) => Some(destination),
        None if trapping => Some(allocator.allocate(4)?),
        None => None,
    };
    let mut ops: Vec<PcodeOp> = Vec::new();
    if let Some(destination) = output {
        match function {
            32 | 33 => ops.push(PcodeOp::IntAdd {
                output: destination,
                left,
                right,
            }),
            34 | 35 => ops.push(PcodeOp::IntSub {
                output: destination,
                left,
                right,
            }),
            36 => ops.push(PcodeOp::IntAnd {
                output: destination,
                left,
                right,
            }),
            37 => ops.push(PcodeOp::IntOr {
                output: destination,
                left,
                right,
            }),
            38 => ops.push(PcodeOp::IntXor {
                output: destination,
                left,
                right,
            }),
            42 | 43 => {
                let comparison: Varnode = allocator.allocate(1)?;
                let compare: PcodeOp = if function == 42 {
                    PcodeOp::IntSignedLess {
                        output: comparison,
                        left,
                        right,
                    }
                } else {
                    PcodeOp::IntLess {
                        output: comparison,
                        left,
                        right,
                    }
                };
                ops.extend([
                    compare,
                    PcodeOp::IntZext {
                        output: destination,
                        input: comparison,
                    },
                ]);
            }
            _ => return None,
        }
        if trapping {
            ops.push(PcodeOp::CallOther {
                name: "mips_overflow_trap".to_owned(),
                output: None,
                inputs: vec![left, right, destination],
            });
        }
    }
    let mnemonic: &str = match function {
        32 => "add",
        33 if bits(word, 16, 5) == 0 => "move",
        33 => "addu",
        34 => "sub",
        35 => "subu",
        36 => "and",
        37 => "or",
        38 => "xor",
        42 => "slt",
        43 => "sltu",
        _ => return None,
    };
    let status: DecodeStatus = if trapping {
        DecodeStatus::CallOther
    } else {
        DecodeStatus::Supported
    };
    Some(MipsLifted {
        delay_slot: false,
        mnemonic: mnemonic.to_owned(),
        ops,
        status,
    })
}

fn lift_shift(spec: &SleighSpec, word: u32, function: u32) -> Option<MipsLifted> {
    let input: Varnode = mips_input(spec, bits(word, 16, 5))?;
    let output: Option<Varnode> = mips_output(spec, bits(word, 11, 5));
    let mut ops: Vec<PcodeOp> = Vec::new();
    if let Some(destination) = output {
        let amount: Varnode = constant(u64::from(bits(word, 6, 5)), 4);
        let operation: PcodeOp = match function {
            0 => PcodeOp::IntLeft {
                output: destination,
                input,
                amount,
            },
            2 => PcodeOp::IntRight {
                output: destination,
                input,
                amount,
            },
            3 => PcodeOp::IntSignedRight {
                output: destination,
                input,
                amount,
            },
            _ => return None,
        };
        ops.push(operation);
    }
    let mnemonic: &str = match function {
        0 => "sll",
        2 => "srl",
        3 => "sra",
        _ => return None,
    };
    Some(supported(mnemonic, ops, false))
}

fn lift_immediate(
    spec: &SleighSpec,
    word: u32,
    opcode: u32,
    allocator: &mut UniqueAllocator,
) -> Option<MipsLifted> {
    let destination: Option<Varnode> = mips_output(spec, bits(word, 16, 5));
    let mut ops: Vec<PcodeOp> = Vec::new();
    if opcode == 15 {
        if let Some(output) = destination {
            ops.push(PcodeOp::IntLeft {
                output,
                input: constant(u64::from(bits(word, 0, 16)), 4),
                amount: constant(16, 4),
            });
        }
        return Some(supported("lui", ops, false));
    }
    let left: Varnode = mips_input(spec, bits(word, 21, 5))?;
    let signed: bool = matches!(opcode, 9..=11);
    let immediate_value: u64 = if signed {
        u64::from_ne_bytes(sign_extend_u64(u64::from(bits(word, 0, 16)), 16).to_ne_bytes())
    } else {
        u64::from(bits(word, 0, 16))
    };
    let right: Varnode = constant(immediate_value, 4);
    if let Some(output) = destination {
        match opcode {
            9 => ops.push(PcodeOp::IntAdd {
                output,
                left,
                right,
            }),
            10 | 11 => {
                let comparison: Varnode = allocator.allocate(1)?;
                let compare: PcodeOp = if opcode == 10 {
                    PcodeOp::IntSignedLess {
                        output: comparison,
                        left,
                        right,
                    }
                } else {
                    PcodeOp::IntLess {
                        output: comparison,
                        left,
                        right,
                    }
                };
                ops.extend([
                    compare,
                    PcodeOp::IntZext {
                        output,
                        input: comparison,
                    },
                ]);
            }
            12 => ops.push(PcodeOp::IntAnd {
                output,
                left,
                right,
            }),
            13 => ops.push(PcodeOp::IntOr {
                output,
                left,
                right,
            }),
            14 => ops.push(PcodeOp::IntXor {
                output,
                left,
                right,
            }),
            _ => return None,
        }
    }
    let mnemonic: &str = match opcode {
        9 if bits(word, 21, 5) == 0 => "li",
        9 => "addiu",
        10 => "slti",
        11 => "sltiu",
        12 => "andi",
        13 => "ori",
        14 => "xori",
        _ => return None,
    };
    Some(supported(mnemonic, ops, false))
}

fn lift_memory(
    spec: &SleighSpec,
    word: u32,
    load: bool,
    allocator: &mut UniqueAllocator,
) -> Option<MipsLifted> {
    let base: Varnode = mips_input(spec, bits(word, 21, 5))?;
    let offset: i64 = sign_extend_u64(u64::from(bits(word, 0, 16)), 16);
    let mut ops: Vec<PcodeOp> = Vec::new();
    let pointer: Varnode = add_signed_offset(base, offset, allocator, &mut ops)?;
    if load {
        if let Some(output) = mips_output(spec, bits(word, 16, 5)) {
            ops.push(PcodeOp::Load {
                output,
                space: Space::Ram,
                pointer,
            });
        }
    } else {
        let value: Varnode = mips_input(spec, bits(word, 16, 5))?;
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value,
        });
    }
    Some(supported(if load { "lw" } else { "sw" }, ops, false))
}

fn lift_branch(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    not_equal: bool,
    allocator: &mut UniqueAllocator,
) -> Option<MipsLifted> {
    let left: Varnode = mips_input(spec, bits(word, 21, 5))?;
    let right: Varnode = mips_input(spec, bits(word, 16, 5))?;
    let condition: Varnode = allocator.allocate(1)?;
    let displacement: i64 = sign_extend_u64(u64::from(bits(word, 0, 16)), 16).checked_mul(4)?;
    let target: u64 = address.wrapping_add(4).wrapping_add_signed(displacement);
    let compare: PcodeOp = if not_equal {
        PcodeOp::IntNotEqual {
            output: condition,
            left,
            right,
        }
    } else {
        PcodeOp::IntEqual {
            output: condition,
            left,
            right,
        }
    };
    let mnemonic: &str = if !not_equal && bits(word, 21, 10) == 0 {
        "b"
    } else if bits(word, 16, 5) == 0 {
        if not_equal { "bnez" } else { "beqz" }
    } else if not_equal {
        "bne"
    } else {
        "beq"
    };
    Some(supported(
        mnemonic,
        vec![
            compare,
            PcodeOp::CBranch {
                target: code_address(target),
                condition,
            },
        ],
        true,
    ))
}

fn lift_jump(spec: &SleighSpec, word: u32, address: u64, link: bool) -> Option<MipsLifted> {
    let target: u64 =
        address.wrapping_add(4) & 0xf000_0000 | u64::from(bits(word, 0, 26)).checked_shl(2)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    if link {
        let link_register: Varnode = named_register(spec, "ra")?;
        ops.push(PcodeOp::Copy {
            output: link_register,
            input: constant(address.wrapping_add(8), 4),
        });
        ops.push(PcodeOp::Call {
            target: code_address(target),
        });
    } else {
        ops.push(PcodeOp::Branch {
            target: code_address(target),
        });
    }
    Some(supported(if link { "jal" } else { "j" }, ops, true))
}

fn lift_register_jump(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    link: bool,
) -> Option<MipsLifted> {
    let source_index: u32 = bits(word, 21, 5);
    let target: Varnode = mips_input(spec, source_index)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    if link {
        let destination_index: u32 = bits(word, 11, 5);
        if let Some(destination) = mips_output(spec, destination_index) {
            ops.push(PcodeOp::Copy {
                output: destination,
                input: constant(address.wrapping_add(8), 4),
            });
        }
        ops.push(PcodeOp::CallIndirect { target });
    } else if source_index == 31 {
        ops.push(PcodeOp::Return {
            target: Some(target),
        });
    } else {
        ops.push(PcodeOp::BranchIndirect { target });
    }
    Some(supported(if link { "jalr" } else { "jr" }, ops, true))
}

fn lift_multiply_divide(
    spec: &SleighSpec,
    word: u32,
    function: u32,
    allocator: &mut UniqueAllocator,
) -> Option<MipsLifted> {
    let left: Varnode = mips_input(spec, bits(word, 21, 5))?;
    let right: Varnode = mips_input(spec, bits(word, 16, 5))?;
    let high: Varnode = named_register(spec, "hi")?;
    let low: Varnode = named_register(spec, "lo")?;
    let signed: bool = matches!(function, 24 | 26);
    if matches!(function, 24 | 25) {
        let wide_left: Varnode = allocator.allocate(8)?;
        let wide_right: Varnode = allocator.allocate(8)?;
        let product: Varnode = allocator.allocate(8)?;
        let mut ops: Vec<PcodeOp> = Vec::new();
        if signed {
            ops.extend([
                PcodeOp::IntSext {
                    output: wide_left,
                    input: left,
                },
                PcodeOp::IntSext {
                    output: wide_right,
                    input: right,
                },
            ]);
        } else {
            ops.extend([
                PcodeOp::IntZext {
                    output: wide_left,
                    input: left,
                },
                PcodeOp::IntZext {
                    output: wide_right,
                    input: right,
                },
            ]);
        }
        ops.push(PcodeOp::IntMult {
            output: product,
            left: wide_left,
            right: wide_right,
        });
        ops.push(PcodeOp::Subpiece {
            output: low,
            input: product,
            byte_offset: constant(0, 4),
        });
        ops.push(PcodeOp::Subpiece {
            output: high,
            input: product,
            byte_offset: constant(4, 4),
        });
        return Some(supported(if signed { "mult" } else { "multu" }, ops, false));
    }
    let quotient: PcodeOp = if signed {
        PcodeOp::IntSignedDiv {
            output: low,
            left,
            right,
        }
    } else {
        PcodeOp::IntDiv {
            output: low,
            left,
            right,
        }
    };
    let remainder: PcodeOp = if signed {
        PcodeOp::IntSignedRem {
            output: high,
            left,
            right,
        }
    } else {
        PcodeOp::IntRem {
            output: high,
            left,
            right,
        }
    };
    Some(MipsLifted {
        delay_slot: false,
        mnemonic: if signed { "div" } else { "divu" }.to_owned(),
        ops: vec![
            quotient,
            remainder,
            PcodeOp::CallOther {
                name: "mips_division_edge_cases".to_owned(),
                output: None,
                inputs: vec![left, right, high, low],
            },
        ],
        status: DecodeStatus::CallOther,
    })
}

fn supported(mnemonic: &str, ops: Vec<PcodeOp>, delay_slot: bool) -> MipsLifted {
    MipsLifted {
        delay_slot,
        mnemonic: mnemonic.to_owned(),
        ops,
        status: DecodeStatus::Supported,
    }
}

fn mips_input(spec: &SleighSpec, index: u32) -> Option<Varnode> {
    if index == 0 {
        return Some(constant(0, 4));
    }
    let name: &str = mips_register_name(index)?;
    named_register(spec, name)
}

const fn code_address(offset: u64) -> Varnode {
    Varnode {
        offset,
        size_bytes: 4,
        space: Space::Ram,
    }
}

fn mips_output(spec: &SleighSpec, index: u32) -> Option<Varnode> {
    if index == 0 {
        return None;
    }
    let name: &str = mips_register_name(index)?;
    named_register(spec, name)
}

fn mips_register_name(index: u32) -> Option<&'static str> {
    [
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
        "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp",
        "s8", "ra",
    ]
    .get(usize::try_from(index).ok()?)
    .copied()
}

fn append_delayed_ops(branch: &[PcodeOp], slot: &[PcodeOp], ordered: &mut Vec<PcodeOp>) {
    let transfer_index: Option<usize> = branch.iter().rposition(is_transfer);
    let Some(index) = transfer_index else {
        ordered.extend(branch.iter().cloned());
        ordered.extend(slot.iter().cloned());
        return;
    };
    ordered.extend(branch[..index].iter().cloned());
    ordered.extend(slot.iter().cloned());
    if let Some(transfer) = branch.get(index) {
        ordered.push(transfer.clone());
    }
    ordered.extend(branch[index.saturating_add(1)..].iter().cloned());
}

const fn is_transfer(operation: &PcodeOp) -> bool {
    matches!(
        operation,
        PcodeOp::Branch { .. }
            | PcodeOp::BranchIndirect { .. }
            | PcodeOp::CBranch { .. }
            | PcodeOp::Call { .. }
            | PcodeOp::CallIndirect { .. }
            | PcodeOp::Return { .. }
    )
}

fn constructor_has_delay_slot(compiled: &CompiledSpec, constructor_id: usize) -> bool {
    compiled
        .source()
        .constructors
        .get(constructor_id)
        .is_some_and(|constructor: &Constructor| {
            constructor
                .semantic_tokens
                .iter()
                .any(|token: &String| token == "delayslot")
        })
}

fn read_word(bytes: &[u8], endian: Endian) -> Option<u32> {
    let array: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(match endian {
        Endian::Big => u32::from_be_bytes(array),
        Endian::Little => u32::from_le_bytes(array),
    })
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
        name: "mips_sleigh_spec_error".to_owned(),
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
