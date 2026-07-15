use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::SleighError;
use crate::compiler::{
    CompiledSpec, ConflictPolicy, ContextState, DecodeMatch, DecodeOutcome,
    compile_spec_with_policy,
};
use crate::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use crate::syntax::{Constructor, SleighSpec, parse_spec};
use crate::vendor::preprocessed_powerpc32be_source;

use super::{
    DecodedBlock, UniqueAllocator, bits, constant, named_register, sign_extend_u64,
    unsupported_constructor,
};

static POWERPC32_BE_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();

pub(super) fn decode_block(bytes: &[u8], address: u64) -> DecodedBlock {
    let compiled_result: &Result<CompiledSpec, SleighError> =
        POWERPC32_BE_SPEC.get_or_init(compile_powerpc32be);
    let compiled: &CompiledSpec = match compiled_result {
        Ok(value) => value,
        Err(error) => return spec_error(bytes, address, error),
    };
    let mut context: ContextState = BTreeMap::new();
    context.insert("linkreg".to_owned(), 0);
    context.insert("vle".to_owned(), 0);
    let mut allocator: UniqueAllocator = UniqueAllocator::default();
    let mut instructions: Vec<PcodeInstr> = Vec::new();
    let mut ordered_ops: Vec<PcodeOp> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let remaining: usize = bytes.len().saturating_sub(cursor);
        let offset: u64 = u64::try_from(cursor).map_or(u64::MAX, |value: u64| value);
        let instruction_address: u64 = address.wrapping_add(offset);
        if remaining < 4 {
            let instruction: PcodeInstr = truncated(&bytes[cursor..], instruction_address);
            instructions.push(instruction);
            cursor = bytes.len();
            break;
        }
        let end: usize = cursor.saturating_add(4);
        let instruction_bytes: &[u8] = &bytes[cursor..end];
        let outcome: DecodeOutcome =
            compiled.decode(instruction_bytes, instruction_address, &context);
        let instruction: PcodeInstr = lift_outcome(
            compiled,
            outcome,
            instruction_bytes,
            instruction_address,
            &mut allocator,
        );
        ordered_ops.extend(instruction.ops.iter().cloned());
        instructions.push(instruction);
        cursor = end;
    }
    DecodedBlock {
        consumed: cursor.min(bytes.len()),
        instructions,
        ordered_ops,
    }
}

fn compile_powerpc32be() -> Result<CompiledSpec, SleighError> {
    let source: String = preprocessed_powerpc32be_source()?;
    let spec: SleighSpec = parse_spec(&source)?;
    compile_spec_with_policy(spec, ConflictPolicy::FirstDefined)
}

fn lift_outcome(
    compiled: &CompiledSpec,
    outcome: DecodeOutcome,
    bytes: &[u8],
    address: u64,
    allocator: &mut UniqueAllocator,
) -> PcodeInstr {
    match outcome {
        DecodeOutcome::Matched(matched) => lift_match(compiled, matched, bytes, allocator),
        DecodeOutcome::NoMatch => PcodeInstr {
            address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: ".word".to_owned(),
            operands: hex_bytes(bytes),
            ops: vec![PcodeOp::CallOther {
                name: "powerpc_decode_unmatched".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::NoMatch,
        },
        DecodeOutcome::ResourceLimit { attempts } => PcodeInstr {
            address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: ".resource_limit".to_owned(),
            operands: attempts.to_string(),
            ops: vec![PcodeOp::CallOther {
                name: "powerpc_decode_resource_limit".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::SpecError,
        },
        DecodeOutcome::Ambiguous { constructors } => PcodeInstr {
            address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: ".ambiguous".to_owned(),
            operands: constructors
                .iter()
                .map(usize::to_string)
                .collect::<Vec<String>>()
                .join(","),
            ops: vec![PcodeOp::CallOther {
                name: "powerpc_decode_ambiguous".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::Ambiguous,
        },
        DecodeOutcome::Truncated { available, .. } => {
            let fragment: &[u8] = bytes.get(..available).map_or(bytes, |value: &[u8]| value);
            truncated(fragment, address)
        }
    }
}

fn lift_match(
    compiled: &CompiledSpec,
    matched: DecodeMatch,
    bytes: &[u8],
    allocator: &mut UniqueAllocator,
) -> PcodeInstr {
    if matched.length != 4 || bytes.len() != 4 {
        let mnemonic: String = matched.mnemonic.clone();
        return unsupported_constructor(compiled, matched, bytes, mnemonic);
    }
    let word: Option<u32> = read_word(bytes);
    let constructor: Option<&Constructor> =
        compiled.source().constructors.get(matched.constructor_id);
    let lifted: Option<PowerPcLifted> = word.and_then(|value: u32| {
        constructor.and_then(|selected: &Constructor| {
            lift_constructor(
                compiled.source(),
                selected,
                value,
                matched.address,
                allocator,
            )
        })
    });
    if let Some(value) = lifted {
        return PcodeInstr {
            address: matched.address,
            bytes: bytes.to_vec(),
            length: 4,
            mnemonic: value.mnemonic,
            operands: String::new(),
            ops: value.ops,
            status: value.status,
        };
    }
    let mnemonic: String = canonical_mnemonic(&matched.mnemonic, read_word(bytes));
    unsupported_constructor(compiled, matched, bytes, mnemonic)
}

#[derive(Debug)]
struct PowerPcLifted {
    mnemonic: String,
    ops: Vec<PcodeOp>,
    status: DecodeStatus,
}

fn lift_constructor(
    spec: &SleighSpec,
    constructor: &Constructor,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<PowerPcLifted> {
    let mnemonic: &str = constructor.mnemonic.as_str();
    if mnemonic == "ori" && word == 0x6000_0000 {
        let register: Varnode = powerpc_register(spec, 0)?;
        return Some(supported(
            "nop",
            vec![PcodeOp::IntOr {
                output: register,
                left: register,
                right: constant(0, 4),
            }],
        ));
    }
    if matches!(
        mnemonic,
        "add" | "subf" | "and" | "or" | "xor" | "slw" | "srw" | "mullw" | "divw"
    ) {
        return lift_binary(spec, mnemonic, word, allocator);
    }
    if matches!(mnemonic, "addi" | "li" | "lis") {
        return lift_immediate(spec, mnemonic, word);
    }
    if matches!(mnemonic, "lwz" | "stw" | "lbz" | "stb") {
        return lift_memory(spec, mnemonic, word, allocator);
    }
    if mnemonic == "cmp" {
        return lift_compare(spec, word, allocator);
    }
    if matches!(mnemonic, "b" | "bl") && bits(word, 26, 6) == 18 {
        return lift_direct_branch(spec, mnemonic, word, address);
    }
    if matches!(mnemonic, "b" | "bd") && bits(word, 26, 6) == 16 {
        return lift_conditional_branch(spec, word, address, allocator);
    }
    if matches!(mnemonic, "blr" | "bctr") {
        return lift_indirect_branch(spec, mnemonic, word);
    }
    None
}

fn lift_binary(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<PowerPcLifted> {
    let logical: bool = matches!(mnemonic, "and" | "or" | "xor" | "slw" | "srw");
    let destination_index: u32 = if logical {
        bits(word, 16, 5)
    } else {
        bits(word, 21, 5)
    };
    let left_index: u32 = if logical {
        bits(word, 21, 5)
    } else {
        bits(word, 16, 5)
    };
    let destination: Varnode = powerpc_register(spec, destination_index)?;
    let left: Varnode = powerpc_register(spec, left_index)?;
    let right: Varnode = powerpc_register(spec, bits(word, 11, 5))?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    match mnemonic {
        "add" => ops.push(PcodeOp::IntAdd {
            output: destination,
            left,
            right,
        }),
        "subf" => ops.push(PcodeOp::IntSub {
            output: destination,
            left: right,
            right: left,
        }),
        "and" => ops.push(PcodeOp::IntAnd {
            output: destination,
            left,
            right,
        }),
        "or" => ops.push(PcodeOp::IntOr {
            output: destination,
            left,
            right,
        }),
        "xor" => ops.push(PcodeOp::IntXor {
            output: destination,
            left,
            right,
        }),
        "slw" | "srw" => {
            let amount: Varnode = allocator.allocate(4)?;
            ops.push(PcodeOp::IntAnd {
                output: amount,
                left: right,
                right: constant(0x3f, 4),
            });
            let shift: PcodeOp = if mnemonic == "slw" {
                PcodeOp::IntLeft {
                    output: destination,
                    input: left,
                    amount,
                }
            } else {
                PcodeOp::IntRight {
                    output: destination,
                    input: left,
                    amount,
                }
            };
            ops.push(shift);
        }
        "mullw" => ops.push(PcodeOp::IntMult {
            output: destination,
            left,
            right,
        }),
        "divw" => {
            let left_snapshot: Varnode = allocator.allocate(4)?;
            let right_snapshot: Varnode = allocator.allocate(4)?;
            ops.push(PcodeOp::Copy {
                output: left_snapshot,
                input: left,
            });
            ops.push(PcodeOp::Copy {
                output: right_snapshot,
                input: right,
            });
            ops.push(PcodeOp::IntSignedDiv {
                output: destination,
                left: left_snapshot,
                right: right_snapshot,
            });
            ops.push(PcodeOp::CallOther {
                name: "powerpc_division_edge_cases".to_owned(),
                output: None,
                inputs: vec![left_snapshot, right_snapshot, destination],
            });
            return Some(PowerPcLifted {
                mnemonic: mnemonic.to_owned(),
                ops,
                status: DecodeStatus::CallOther,
            });
        }
        _ => return None,
    }
    Some(supported(mnemonic, ops))
}

fn lift_immediate(spec: &SleighSpec, mnemonic: &str, word: u32) -> Option<PowerPcLifted> {
    let destination: Varnode = powerpc_register(spec, bits(word, 21, 5))?;
    let immediate: i64 = sign_extend_u64(u64::from(bits(word, 0, 16)), 16);
    let value: Varnode = signed_constant(immediate, 4);
    let operation: PcodeOp = match mnemonic {
        "li" => PcodeOp::Copy {
            output: destination,
            input: value,
        },
        "lis" => PcodeOp::IntLeft {
            output: destination,
            input: value,
            amount: constant(16, 4),
        },
        "addi" => PcodeOp::IntAdd {
            output: destination,
            left: powerpc_register(spec, bits(word, 16, 5))?,
            right: value,
        },
        _ => return None,
    };
    Some(supported(mnemonic, vec![operation]))
}

fn lift_memory(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<PowerPcLifted> {
    let base_index: u32 = bits(word, 16, 5);
    let base: Varnode = if base_index == 0 {
        constant(0, 4)
    } else {
        powerpc_register(spec, base_index)?
    };
    let displacement: i64 = sign_extend_u64(u64::from(bits(word, 0, 16)), 16);
    let pointer: Varnode = allocator.allocate(4)?;
    let mut ops: Vec<PcodeOp> = vec![PcodeOp::IntAdd {
        output: pointer,
        left: base,
        right: signed_constant(displacement, 4),
    }];
    let access_size: u32 = if matches!(mnemonic, "lbz" | "stb") {
        1
    } else {
        4
    };
    let register: Varnode = powerpc_register(spec, bits(word, 21, 5))?;
    if matches!(mnemonic, "stw" | "stb") {
        let value: Varnode = low_register_slice(register, access_size)?;
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value,
        });
        return Some(supported(mnemonic, ops));
    }
    if access_size == 4 {
        ops.push(PcodeOp::Load {
            output: register,
            space: Space::Ram,
            pointer,
        });
    } else {
        let loaded: Varnode = allocator.allocate(access_size)?;
        ops.push(PcodeOp::Load {
            output: loaded,
            space: Space::Ram,
            pointer,
        });
        ops.push(PcodeOp::IntZext {
            output: register,
            input: loaded,
        });
    }
    Some(supported(mnemonic, ops))
}

fn lift_compare(
    spec: &SleighSpec,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<PowerPcLifted> {
    let opcode: u32 = bits(word, 26, 6);
    let mnemonic: &str = if opcode == 11 { "cmpwi" } else { "cmpw" };
    let left: Varnode = powerpc_register(spec, bits(word, 16, 5))?;
    let right: Varnode = if opcode == 11 {
        signed_constant(sign_extend_u64(u64::from(bits(word, 0, 16)), 16), 4)
    } else if opcode == 31 {
        powerpc_register(spec, bits(word, 11, 5))?
    } else {
        return None;
    };
    let less: Varnode = allocator.allocate(1)?;
    let less_shifted: Varnode = allocator.allocate(1)?;
    let greater: Varnode = allocator.allocate(1)?;
    let greater_shifted: Varnode = allocator.allocate(1)?;
    let ordering: Varnode = allocator.allocate(1)?;
    let equal: Varnode = allocator.allocate(1)?;
    let equal_shifted: Varnode = allocator.allocate(1)?;
    let comparison: Varnode = allocator.allocate(1)?;
    let summary_overflow: Varnode = allocator.allocate(1)?;
    let xer_so: Varnode = named_register(spec, "xer_so")?;
    let condition_register: Varnode = condition_register(spec, bits(word, 23, 3))?;
    let ops: Vec<PcodeOp> = vec![
        PcodeOp::IntSignedLess {
            output: less,
            left,
            right,
        },
        PcodeOp::IntLeft {
            output: less_shifted,
            input: less,
            amount: constant(3, 4),
        },
        PcodeOp::IntSignedLess {
            output: greater,
            left: right,
            right: left,
        },
        PcodeOp::IntLeft {
            output: greater_shifted,
            input: greater,
            amount: constant(2, 4),
        },
        PcodeOp::IntOr {
            output: ordering,
            left: less_shifted,
            right: greater_shifted,
        },
        PcodeOp::IntEqual {
            output: equal,
            left,
            right,
        },
        PcodeOp::IntLeft {
            output: equal_shifted,
            input: equal,
            amount: constant(1, 4),
        },
        PcodeOp::IntOr {
            output: comparison,
            left: ordering,
            right: equal_shifted,
        },
        PcodeOp::IntAnd {
            output: summary_overflow,
            left: xer_so,
            right: constant(1, 1),
        },
        PcodeOp::IntOr {
            output: condition_register,
            left: comparison,
            right: summary_overflow,
        },
    ];
    Some(supported(mnemonic, ops))
}

fn lift_direct_branch(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
) -> Option<PowerPcLifted> {
    let target: Varnode = direct_branch_target(word, address);
    let lifted_mnemonic: String = direct_branch_mnemonic(mnemonic, word);
    let mut ops: Vec<PcodeOp> = Vec::new();
    if mnemonic == "bl" {
        let link_register: Varnode = named_register(spec, "LR")?;
        ops.push(PcodeOp::Copy {
            output: link_register,
            input: constant(address.wrapping_add(4) & u64::from(u32::MAX), 4),
        });
        if bits(word, 2, 24) == 1 && bits(word, 1, 1) == 0 {
            ops.push(PcodeOp::Branch { target });
        } else {
            ops.push(PcodeOp::Call { target });
        }
    } else {
        ops.push(PcodeOp::Branch { target });
    }
    Some(supported(&lifted_mnemonic, ops))
}

fn lift_conditional_branch(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<PowerPcLifted> {
    if bits(word, 0, 1) != 0 {
        return None;
    }
    let bo: u32 = bits(word, 21, 5);
    let bi: u32 = bits(word, 16, 5);
    let tests_condition: bool = bo & 0x10 == 0;
    let tests_counter: bool = bo & 0x04 == 0;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let condition: Option<Varnode> = if tests_condition {
        Some(branch_condition_bit(spec, bi, allocator, &mut ops)?)
    } else {
        None
    };
    let counter_condition: Option<Varnode> = if tests_counter {
        let counter: Varnode = named_register(spec, "CTR")?;
        ops.push(PcodeOp::IntSub {
            output: counter,
            left: counter,
            right: constant(1, 4),
        });
        let comparison: Varnode = allocator.allocate(1)?;
        let operation: PcodeOp = if bo & 0x02 == 0 {
            PcodeOp::IntNotEqual {
                output: comparison,
                left: counter,
                right: constant(0, 4),
            }
        } else {
            PcodeOp::IntEqual {
                output: comparison,
                left: counter,
                right: constant(0, 4),
            }
        };
        ops.push(operation);
        Some(comparison)
    } else {
        None
    };
    let branch_condition: Option<Varnode> = match (condition, counter_condition) {
        (Some(cr_bit), Some(counter_test)) => {
            let expected: Varnode = allocator.allocate(1)?;
            ops.push(PcodeOp::IntEqual {
                output: expected,
                left: cr_bit,
                right: constant(u64::from((bo & 0x08 != 0) as u8), 1),
            });
            let combined: Varnode = allocator.allocate(1)?;
            ops.push(PcodeOp::BoolAnd {
                output: combined,
                left: counter_test,
                right: expected,
            });
            Some(combined)
        }
        (Some(cr_bit), None) if bo & 0x08 == 0 => {
            let inverted: Varnode = allocator.allocate(1)?;
            ops.push(PcodeOp::BoolNegate {
                output: inverted,
                input: cr_bit,
            });
            Some(inverted)
        }
        (Some(cr_bit), None) => Some(cr_bit),
        (None, Some(counter_test)) => Some(counter_test),
        (None, None) => None,
    };
    let target: Varnode = conditional_branch_target(word, address);
    if let Some(value) = branch_condition {
        ops.push(PcodeOp::CBranch {
            target,
            condition: value,
        });
    } else {
        ops.push(PcodeOp::Branch { target });
    }
    Some(supported(&conditional_mnemonic(word), ops))
}

fn branch_condition_bit(
    spec: &SleighSpec,
    bi: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let field: Varnode = condition_register(spec, bi / 4)?;
    let shifted: Varnode = allocator.allocate(1)?;
    let condition: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntRight {
        output: shifted,
        input: field,
        amount: constant(u64::from(3_u32.saturating_sub(bi % 4)), 4),
    });
    ops.push(PcodeOp::IntAnd {
        output: condition,
        left: shifted,
        right: constant(1, 1),
    });
    Some(condition)
}

fn lift_indirect_branch(spec: &SleighSpec, mnemonic: &str, word: u32) -> Option<PowerPcLifted> {
    let target: Varnode = if mnemonic == "blr" {
        named_register(spec, "LR")?
    } else {
        named_register(spec, "CTR")?
    };
    let hint: u32 = bits(word, 11, 2);
    let operation: PcodeOp = if mnemonic == "blr" && hint == 0 {
        PcodeOp::Return {
            target: Some(target),
        }
    } else {
        PcodeOp::BranchIndirect { target }
    };
    let lifted_mnemonic: &str = match (mnemonic, hint) {
        ("blr", 1..=3) => "bclr",
        ("bctr", 1..=3) => "bcctr",
        _ => mnemonic,
    };
    Some(supported(lifted_mnemonic, vec![operation]))
}

fn canonical_mnemonic(mnemonic: &str, word: Option<u32>) -> String {
    let Some(value) = word else {
        return mnemonic.to_owned();
    };
    if mnemonic == "ori" && value == 0x6000_0000 {
        return "nop".to_owned();
    }
    if mnemonic == "cmp" {
        return if bits(value, 26, 6) == 11 {
            "cmpwi".to_owned()
        } else {
            "cmpw".to_owned()
        };
    }
    if matches!(mnemonic, "b" | "bd") && bits(value, 26, 6) == 16 {
        return conditional_mnemonic(value);
    }
    if matches!(mnemonic, "b" | "bl") && bits(value, 26, 6) == 18 {
        return direct_branch_mnemonic(mnemonic, value);
    }
    if matches!(mnemonic, "blr" | "bctr") && bits(value, 11, 2) != 0 {
        return if mnemonic == "blr" {
            "bclr".to_owned()
        } else {
            "bcctr".to_owned()
        };
    }
    mnemonic.to_owned()
}

fn direct_branch_mnemonic(mnemonic: &str, word: u32) -> String {
    if bits(word, 1, 1) != 0 {
        format!("{mnemonic}a")
    } else {
        mnemonic.to_owned()
    }
}

fn conditional_mnemonic(word: u32) -> String {
    let bo: u32 = bits(word, 21, 5);
    let bi: u32 = bits(word, 16, 5);
    let tests_condition: bool = bo & 0x10 == 0;
    let tests_counter: bool = bo & 0x04 == 0;
    let mut mnemonic: String = if tests_condition && !tests_counter {
        let index: usize = usize::try_from(bi % 4).map_or(0, |value: usize| value);
        let true_names: [&str; 4] = ["lt", "gt", "eq", "so"];
        let false_names: [&str; 4] = ["ge", "le", "ne", "ns"];
        let condition: &str = if bo & 0x08 != 0 {
            true_names[index]
        } else {
            false_names[index]
        };
        format!("b{condition}")
    } else if !tests_condition && tests_counter {
        if bo & 0x02 == 0 {
            "bdnz".to_owned()
        } else {
            "bdz".to_owned()
        }
    } else if tests_condition && tests_counter {
        let counter: &str = if bo & 0x02 == 0 { "dnz" } else { "dz" };
        let condition: &str = if bo & 0x08 != 0 { "t" } else { "f" };
        format!("b{counter}{condition}")
    } else {
        "b".to_owned()
    };
    if bits(word, 0, 1) != 0 {
        mnemonic.push('l');
    }
    if bits(word, 1, 1) != 0 {
        mnemonic.push('a');
    }
    mnemonic
}

fn direct_branch_target(word: u32, address: u64) -> Varnode {
    let encoded: u64 = u64::from(bits(word, 2, 24)) << 2;
    let displacement: i64 = sign_extend_u64(encoded, 26);
    branch_target(address, displacement, bits(word, 1, 1) != 0)
}

fn conditional_branch_target(word: u32, address: u64) -> Varnode {
    let encoded: u64 = u64::from(bits(word, 2, 14)) << 2;
    let displacement: i64 = sign_extend_u64(encoded, 16);
    branch_target(address, displacement, bits(word, 1, 1) != 0)
}

fn branch_target(address: u64, displacement: i64, absolute: bool) -> Varnode {
    let base: u64 = if absolute { 0 } else { address };
    let encoded: u64 = u64::from_ne_bytes(displacement.to_ne_bytes());
    Varnode {
        offset: base.wrapping_add(encoded) & u64::from(u32::MAX),
        size_bytes: 4,
        space: Space::Ram,
    }
}

fn condition_register(spec: &SleighSpec, index: u32) -> Option<Varnode> {
    let names: [&str; 8] = ["cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7"];
    let position: usize = usize::try_from(index).ok()?;
    let name: &&str = names.get(position)?;
    named_register(spec, name)
}

fn powerpc_register(spec: &SleighSpec, index: u32) -> Option<Varnode> {
    let names: [&str; 32] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13",
        "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26",
        "r27", "r28", "r29", "r30", "r31",
    ];
    let position: usize = usize::try_from(index).ok()?;
    let name: &&str = names.get(position)?;
    named_register(spec, name)
}

fn low_register_slice(register: Varnode, size_bytes: u32) -> Option<Varnode> {
    if size_bytes > register.size_bytes {
        return None;
    }
    let skipped: u32 = register.size_bytes.checked_sub(size_bytes)?;
    let offset: u64 = register.offset.checked_add(u64::from(skipped))?;
    Some(Varnode {
        offset,
        size_bytes,
        space: register.space,
    })
}

fn signed_constant(value: i64, size_bytes: u32) -> Varnode {
    constant(u64::from_ne_bytes(value.to_ne_bytes()), size_bytes)
}

fn supported(mnemonic: &str, ops: Vec<PcodeOp>) -> PowerPcLifted {
    PowerPcLifted {
        mnemonic: mnemonic.to_owned(),
        ops,
        status: DecodeStatus::Supported,
    }
}

fn read_word(bytes: &[u8]) -> Option<u32> {
    let array: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(array))
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
        name: "powerpc_spec_error".to_owned(),
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
