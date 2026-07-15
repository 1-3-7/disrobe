use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::SleighError;
use crate::compiler::{
    CompiledSpec, ConflictPolicy, ContextState, DecodeMatch, DecodeOutcome,
    compile_spec_with_policy,
};
use crate::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use crate::syntax::{Constructor, SleighSpec, parse_spec};
use crate::vendor::{
    preprocessed_riscv32_source, preprocessed_riscv32c_source, preprocessed_riscv64_source,
    preprocessed_riscv64c_source,
};

use super::{
    DecodedBlock, RiscVProfile, RiscVWidth, UniqueAllocator, bits, constant, mask_for_bytes,
    named_register, sign_extend_u64, unsupported_constructor,
};

static RISCV32_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();
static RISCV32C_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();
static RISCV64_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();
static RISCV64C_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();
const UNSUPPORTED_ENCODING_CAPTURE_LIMIT: usize = 24;

pub(super) fn decode_block(
    bytes: &[u8],
    address: u64,
    width: RiscVWidth,
    profile: RiscVProfile,
) -> DecodedBlock {
    let compiled_result: &Result<CompiledSpec, SleighError> = match (width, profile) {
        (RiscVWidth::Rv32, RiscVProfile::Base) => RISCV32_SPEC.get_or_init(compile_riscv32),
        (RiscVWidth::Rv32, RiscVProfile::Compressed) => RISCV32C_SPEC.get_or_init(compile_riscv32c),
        (RiscVWidth::Rv64, RiscVProfile::Base) => RISCV64_SPEC.get_or_init(compile_riscv64),
        (RiscVWidth::Rv64, RiscVProfile::Compressed) => RISCV64C_SPEC.get_or_init(compile_riscv64c),
    };
    let compiled: &CompiledSpec = match compiled_result {
        Ok(value) => value,
        Err(error) => return spec_error(bytes, address, error),
    };
    let context: ContextState = BTreeMap::new();
    let mut allocator: UniqueAllocator = UniqueAllocator::default();
    let mut instructions: Vec<PcodeInstr> = Vec::new();
    let mut ordered_ops: Vec<PcodeOp> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let remaining: usize = bytes.len().saturating_sub(cursor);
        let offset: u64 = u64::try_from(cursor).map_or(u64::MAX, |value: u64| value);
        let instruction_address: u64 = address.wrapping_add(offset);
        if remaining < 2 {
            let instruction: PcodeInstr = truncated(&bytes[cursor..], instruction_address);
            ordered_ops.extend(instruction.ops.iter().cloned());
            instructions.push(instruction);
            cursor = bytes.len();
            break;
        }
        let halfword_result: Option<u16> = read_halfword(&bytes[cursor..]);
        let halfword: u16 = if let Some(value) = halfword_result {
            value
        } else {
            let instruction: PcodeInstr = truncated(&bytes[cursor..], instruction_address);
            ordered_ops.extend(instruction.ops.iter().cloned());
            instructions.push(instruction);
            cursor = bytes.len();
            break;
        };
        let encoded_width: EncodedWidth = match profile {
            RiscVProfile::Base => EncodedWidth::Supported(4),
            RiscVProfile::Compressed => encoded_width(halfword),
        };
        let instruction_length: usize = match encoded_width {
            EncodedWidth::Supported(value) | EncodedWidth::Unsupported(value) => value,
            EncodedWidth::Unbounded if remaining < 24 => 24,
            EncodedWidth::Unbounded => remaining,
        };
        if remaining < instruction_length {
            let instruction: PcodeInstr = truncated(&bytes[cursor..], instruction_address);
            ordered_ops.extend(instruction.ops.iter().cloned());
            instructions.push(instruction);
            cursor = bytes.len();
            break;
        }
        let end: usize = cursor.saturating_add(instruction_length);
        let instruction_bytes: &[u8] = &bytes[cursor..end];
        if encoded_width != EncodedWidth::Supported(instruction_length) {
            let instruction: PcodeInstr =
                unsupported_length(instruction_bytes, instruction_address);
            ordered_ops.extend(instruction.ops.iter().cloned());
            instructions.push(instruction);
            cursor = end;
            continue;
        }
        let outcome: DecodeOutcome =
            compiled.decode_complete(instruction_bytes, instruction_address, &context);
        let instruction: PcodeInstr = lift_outcome(
            compiled,
            outcome,
            instruction_bytes,
            instruction_address,
            width,
            profile,
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

fn compile_riscv32() -> Result<CompiledSpec, SleighError> {
    compile_riscv(preprocessed_riscv32_source()?)
}

fn compile_riscv64() -> Result<CompiledSpec, SleighError> {
    compile_riscv(preprocessed_riscv64_source()?)
}

fn compile_riscv32c() -> Result<CompiledSpec, SleighError> {
    compile_riscv(preprocessed_riscv32c_source()?)
}

fn compile_riscv64c() -> Result<CompiledSpec, SleighError> {
    compile_riscv(preprocessed_riscv64c_source()?)
}

fn compile_riscv(source: String) -> Result<CompiledSpec, SleighError> {
    let spec: SleighSpec = parse_spec(&source)?;
    compile_spec_with_policy(spec, ConflictPolicy::FirstDefined)
}

fn lift_outcome(
    compiled: &CompiledSpec,
    outcome: DecodeOutcome,
    bytes: &[u8],
    address: u64,
    width: RiscVWidth,
    profile: RiscVProfile,
    allocator: &mut UniqueAllocator,
) -> PcodeInstr {
    match outcome {
        DecodeOutcome::Matched(matched) => {
            lift_match(compiled, matched, bytes, width, profile, allocator)
        }
        DecodeOutcome::NoMatch | DecodeOutcome::Truncated { .. } => no_match(bytes, address),
        DecodeOutcome::ResourceLimit { attempts } => PcodeInstr {
            address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: ".resource_limit".to_owned(),
            operands: attempts.to_string(),
            ops: vec![PcodeOp::CallOther {
                name: "riscv_decode_resource_limit".to_owned(),
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
                name: "riscv_decode_ambiguous".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::Ambiguous,
        },
    }
}

fn no_match(bytes: &[u8], address: u64) -> PcodeInstr {
    let mnemonic: &str = if bytes.len() == 2 { ".2byte" } else { ".word" };
    PcodeInstr {
        address,
        bytes: bytes.to_vec(),
        length: bytes.len(),
        mnemonic: mnemonic.to_owned(),
        operands: hex_bytes(bytes),
        ops: vec![PcodeOp::CallOther {
            name: "riscv_decode_unmatched".to_owned(),
            output: None,
            inputs: Vec::new(),
        }],
        status: DecodeStatus::NoMatch,
    }
}

#[derive(Debug)]
struct RiscVLifted {
    mnemonic: String,
    ops: Vec<PcodeOp>,
    status: DecodeStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncodedWidth {
    Supported(usize),
    Unsupported(usize),
    Unbounded,
}

fn lift_match(
    compiled: &CompiledSpec,
    matched: DecodeMatch,
    bytes: &[u8],
    width: RiscVWidth,
    profile: RiscVProfile,
    allocator: &mut UniqueAllocator,
) -> PcodeInstr {
    if matched.length != bytes.len() || !matches!(bytes.len(), 2 | 4) {
        return PcodeInstr {
            address: matched.address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: matched.mnemonic,
            operands: String::new(),
            ops: vec![PcodeOp::CallOther {
                name: "riscv_invalid_constructor_length".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::Unsupported,
        };
    }
    let constructor: Option<&Constructor> =
        compiled.source().constructors.get(matched.constructor_id);
    let lifted: Option<RiscVLifted> = constructor.and_then(|selected: &Constructor| {
        if bytes.len() == 2 {
            return read_halfword(bytes).and_then(|value: u16| {
                lift_compressed(
                    compiled.source(),
                    selected,
                    value,
                    matched.address,
                    width,
                    allocator,
                )
            });
        }
        read_word(bytes).and_then(|value: u32| {
            lift_constructor(
                compiled.source(),
                selected,
                value,
                matched.address,
                width,
                profile,
                allocator,
            )
        })
    });
    if let Some(value) = lifted {
        return PcodeInstr {
            address: matched.address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: value.mnemonic,
            operands: String::new(),
            ops: value.ops,
            status: value.status,
        };
    }
    let mnemonic: String = canonical_mnemonic(&matched.mnemonic, read_word(bytes));
    unsupported_constructor(compiled, matched, bytes, mnemonic)
}

fn canonical_mnemonic(mnemonic: &str, word: Option<u32>) -> String {
    let value: u32 = match word {
        Some(candidate) => candidate,
        None => return mnemonic.to_owned(),
    };
    if mnemonic == "sltiu" && bits(value, 20, 12) == 1 {
        return "seqz".to_owned();
    }
    mnemonic.to_owned()
}

fn lift_constructor(
    spec: &SleighSpec,
    constructor: &Constructor,
    word: u32,
    address: u64,
    width: RiscVWidth,
    profile: RiscVProfile,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let mnemonic: &str = constructor.mnemonic.as_str();
    if mnemonic == "nop" {
        return (word == 0x0000_0013).then(|| supported("nop", Vec::new()));
    }
    if matches!(mnemonic, "addi" | "li" | "mv") {
        return lift_immediate(spec, mnemonic, word, width);
    }
    if matches!(
        mnemonic,
        "add" | "sub" | "and" | "or" | "xor" | "sll" | "srl" | "sra" | "slt"
    ) {
        return lift_binary(spec, mnemonic, word, width, allocator);
    }
    if matches!(mnemonic, "lui" | "auipc") {
        return lift_upper(spec, mnemonic, word, address, width, allocator);
    }
    if matches!(mnemonic, "lw" | "sw" | "ld" | "sd") {
        return lift_memory(spec, mnemonic, word, width, allocator);
    }
    if matches!(
        mnemonic,
        "beq" | "bne" | "blt" | "bge" | "jal" | "j" | "jalr" | "jr" | "ret"
    ) {
        return lift_control(spec, mnemonic, word, address, width, profile, allocator);
    }
    if matches!(
        mnemonic,
        "mul" | "mulh" | "mulhsu" | "mulhu" | "div" | "divu" | "rem" | "remu"
    ) {
        return lift_multiply_divide(spec, mnemonic, word, width, allocator);
    }
    if atomic_operation(mnemonic).is_some() {
        return lift_atomic(spec, mnemonic, word, width);
    }
    None
}

fn lift_compressed(
    spec: &SleighSpec,
    constructor: &Constructor,
    halfword: u16,
    address: u64,
    width: RiscVWidth,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let mnemonic: &str = constructor.mnemonic.as_str();
    let encoded: u32 = u32::from(halfword);
    if mnemonic == "c.nop" {
        return Some(supported("nop", Vec::new()));
    }
    if matches!(mnemonic, "c.addi" | "c.li" | "c.addi4spn") {
        return lift_compressed_immediate(spec, mnemonic, encoded, width);
    }
    if matches!(
        mnemonic,
        "c.mv" | "c.add" | "c.sub" | "c.and" | "c.or" | "c.xor"
    ) {
        return lift_compressed_register(spec, mnemonic, encoded, width);
    }
    if matches!(
        mnemonic,
        "c.lw" | "c.sw" | "c.ld" | "c.sd" | "c.lwsp" | "c.swsp"
    ) {
        return lift_compressed_memory(spec, mnemonic, encoded, width, allocator);
    }
    if matches!(
        mnemonic,
        "c.j" | "c.jal" | "c.jr" | "c.jalr" | "c.beqz" | "c.bnez" | "ret"
    ) {
        return lift_compressed_control(spec, mnemonic, encoded, address, width, allocator);
    }
    None
}

fn lift_compressed_immediate(
    spec: &SleighSpec,
    mnemonic: &str,
    encoded: u32,
    width: RiscVWidth,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    if mnemonic == "c.addi4spn" {
        let immediate: u64 = u64::from(
            (bits(encoded, 7, 4) << 6)
                | (bits(encoded, 11, 2) << 4)
                | (bits(encoded, 5, 1) << 3)
                | (bits(encoded, 6, 1) << 2),
        );
        if immediate == 0 {
            return None;
        }
        let destination_index: u32 = bits(encoded, 2, 3).saturating_add(8);
        let destination: Varnode = riscv_output(spec, destination_index)?;
        let stack_pointer: Varnode = riscv_input(spec, 2, size_bytes)?;
        return Some(supported(
            "addi",
            vec![PcodeOp::IntAdd {
                output: destination,
                left: stack_pointer,
                right: constant(immediate, size_bytes),
            }],
        ));
    }
    let destination_index: u32 = bits(encoded, 7, 5);
    let output: Option<Varnode> = riscv_output(spec, destination_index);
    let destination: Varnode = match output {
        Some(value) => value,
        None => {
            return Some(supported(
                if mnemonic == "c.li" { "li" } else { "addi" },
                Vec::new(),
            ));
        }
    };
    let immediate_bits: u64 = u64::from((bits(encoded, 12, 1) << 5) | bits(encoded, 2, 5));
    let immediate: i64 = sign_extend_u64(immediate_bits, 6);
    let operation: PcodeOp = if mnemonic == "c.li" {
        PcodeOp::Copy {
            output: destination,
            input: signed_constant(immediate, size_bytes),
        }
    } else {
        PcodeOp::IntAdd {
            output: destination,
            left: destination,
            right: signed_constant(immediate, size_bytes),
        }
    };
    Some(supported(
        if mnemonic == "c.li" { "li" } else { "addi" },
        vec![operation],
    ))
}

fn lift_compressed_register(
    spec: &SleighSpec,
    mnemonic: &str,
    encoded: u32,
    width: RiscVWidth,
) -> Option<RiscVLifted> {
    let prime_registers: bool = matches!(mnemonic, "c.sub" | "c.and" | "c.or" | "c.xor");
    let destination_index: u32 = if prime_registers {
        bits(encoded, 7, 3).saturating_add(8)
    } else {
        bits(encoded, 7, 5)
    };
    let output: Option<Varnode> = riscv_output(spec, destination_index);
    let destination: Varnode = match output {
        Some(value) => value,
        None => {
            return Some(supported(
                if mnemonic == "c.mv" { "mv" } else { "add" },
                Vec::new(),
            ));
        }
    };
    let source_index: u32 = if prime_registers {
        bits(encoded, 2, 3).saturating_add(8)
    } else {
        bits(encoded, 2, 5)
    };
    let source: Varnode = riscv_input(spec, source_index, width.size_bytes())?;
    let operation: PcodeOp = match mnemonic {
        "c.mv" => PcodeOp::Copy {
            output: destination,
            input: source,
        },
        "c.add" => PcodeOp::IntAdd {
            output: destination,
            left: destination,
            right: source,
        },
        "c.sub" => PcodeOp::IntSub {
            output: destination,
            left: destination,
            right: source,
        },
        "c.and" => PcodeOp::IntAnd {
            output: destination,
            left: destination,
            right: source,
        },
        "c.or" => PcodeOp::IntOr {
            output: destination,
            left: destination,
            right: source,
        },
        "c.xor" => PcodeOp::IntXor {
            output: destination,
            left: destination,
            right: source,
        },
        _ => return None,
    };
    let stripped_mnemonic: Option<&str> = mnemonic.strip_prefix("c.");
    let lifted_mnemonic: &str = stripped_mnemonic.map_or(mnemonic, |value: &str| value);
    Some(supported(lifted_mnemonic, vec![operation]))
}

fn lift_compressed_memory(
    spec: &SleighSpec,
    mnemonic: &str,
    encoded: u32,
    width: RiscVWidth,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    let stack_form: bool = matches!(mnemonic, "c.lwsp" | "c.swsp");
    let store: bool = matches!(mnemonic, "c.sw" | "c.sd" | "c.swsp");
    let doubleword: bool = matches!(mnemonic, "c.ld" | "c.sd");
    if doubleword && width != RiscVWidth::Rv64 {
        return None;
    }
    let access_size: u32 = if doubleword { 8 } else { 4 };
    let base_index: u32 = if stack_form {
        2
    } else {
        bits(encoded, 7, 3).saturating_add(8)
    };
    let data_index: u32 = if stack_form {
        if store {
            bits(encoded, 2, 5)
        } else {
            bits(encoded, 7, 5)
        }
    } else {
        bits(encoded, 2, 3).saturating_add(8)
    };
    if !store && data_index == 0 {
        return None;
    }
    let immediate: u64 = if mnemonic == "c.lw" || mnemonic == "c.sw" {
        u64::from(
            (bits(encoded, 10, 3) << 3) | (bits(encoded, 6, 1) << 2) | (bits(encoded, 5, 1) << 6),
        )
    } else if doubleword {
        u64::from((bits(encoded, 10, 3) << 3) | (bits(encoded, 5, 2) << 6))
    } else if mnemonic == "c.lwsp" {
        u64::from(
            (bits(encoded, 12, 1) << 5) | (bits(encoded, 4, 3) << 2) | (bits(encoded, 2, 2) << 6),
        )
    } else {
        u64::from((bits(encoded, 7, 2) << 6) | (bits(encoded, 9, 4) << 2))
    };
    let base: Varnode = riscv_input(spec, base_index, size_bytes)?;
    let pointer: Varnode = allocator.allocate(size_bytes)?;
    let mut ops: Vec<PcodeOp> = vec![PcodeOp::IntAdd {
        output: pointer,
        left: base,
        right: constant(immediate, size_bytes),
    }];
    let lifted_mnemonic: &str = if doubleword {
        if store { "sd" } else { "ld" }
    } else if store {
        "sw"
    } else {
        "lw"
    };
    if store {
        let input: Varnode = riscv_input(spec, data_index, size_bytes)?;
        let value: Varnode = Varnode {
            offset: input.offset,
            size_bytes: access_size,
            space: input.space,
        };
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value,
        });
        return Some(supported(lifted_mnemonic, ops));
    }
    let output: Option<Varnode> = riscv_output(spec, data_index);
    let loaded: Varnode = match output {
        Some(destination) if access_size == size_bytes => destination,
        _ => allocator.allocate(access_size)?,
    };
    ops.push(PcodeOp::Load {
        output: loaded,
        space: Space::Ram,
        pointer,
    });
    if let Some(destination) = output
        && access_size < size_bytes
    {
        ops.push(PcodeOp::IntSext {
            output: destination,
            input: loaded,
        });
    }
    Some(supported(lifted_mnemonic, ops))
}

fn lift_compressed_control(
    spec: &SleighSpec,
    mnemonic: &str,
    encoded: u32,
    address: u64,
    width: RiscVWidth,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    if matches!(mnemonic, "c.beqz" | "c.bnez") {
        let source_index: u32 = bits(encoded, 7, 3).saturating_add(8);
        let source: Varnode = riscv_input(spec, source_index, size_bytes)?;
        let condition: Varnode = allocator.allocate(1)?;
        let comparison: PcodeOp = if mnemonic == "c.beqz" {
            PcodeOp::IntEqual {
                output: condition,
                left: source,
                right: constant(0, size_bytes),
            }
        } else {
            PcodeOp::IntNotEqual {
                output: condition,
                left: source,
                right: constant(0, size_bytes),
            }
        };
        let immediate_bits: u64 = u64::from(
            (bits(encoded, 12, 1) << 8)
                | (bits(encoded, 5, 2) << 6)
                | (bits(encoded, 2, 1) << 5)
                | (bits(encoded, 10, 2) << 3)
                | (bits(encoded, 3, 2) << 1),
        );
        let displacement: i64 = sign_extend_u64(immediate_bits, 9);
        let target: Varnode = code_address(add_signed_address(address, displacement, width), width);
        return Some(supported(
            if mnemonic == "c.beqz" { "beqz" } else { "bnez" },
            vec![comparison, PcodeOp::CBranch { target, condition }],
        ));
    }
    if matches!(mnemonic, "c.j" | "c.jal") {
        let immediate_bits: u64 = u64::from(
            (bits(encoded, 12, 1) << 11)
                | (bits(encoded, 11, 1) << 4)
                | (bits(encoded, 9, 2) << 8)
                | (bits(encoded, 8, 1) << 10)
                | (bits(encoded, 7, 1) << 6)
                | (bits(encoded, 6, 1) << 7)
                | (bits(encoded, 3, 3) << 1)
                | (bits(encoded, 2, 1) << 5),
        );
        let displacement: i64 = sign_extend_u64(immediate_bits, 12);
        let target: Varnode = code_address(add_signed_address(address, displacement, width), width);
        if mnemonic == "c.jal" {
            let link: Varnode = riscv_output(spec, 1)?;
            return Some(supported(
                "jal",
                vec![
                    PcodeOp::Copy {
                        output: link,
                        input: constant(mask_address(address.wrapping_add(2), width), size_bytes),
                    },
                    PcodeOp::Call { target },
                ],
            ));
        }
        return Some(supported("j", vec![PcodeOp::Branch { target }]));
    }
    let source_index: u32 = if mnemonic == "ret" {
        1
    } else {
        bits(encoded, 7, 5)
    };
    if source_index == 0 {
        return None;
    }
    let source: Varnode = riscv_input(spec, source_index, size_bytes)?;
    let target: Varnode = allocator.allocate(size_bytes)?;
    let mut ops: Vec<PcodeOp> = vec![PcodeOp::IntAnd {
        output: target,
        left: source,
        right: constant(mask_for_bytes(size_bytes) & !1_u64, size_bytes),
    }];
    if mnemonic == "ret" {
        ops.push(PcodeOp::Return {
            target: Some(target),
        });
        return Some(supported("ret", ops));
    }
    if mnemonic == "c.jalr" {
        let link: Varnode = riscv_output(spec, 1)?;
        ops.push(PcodeOp::Copy {
            output: link,
            input: constant(mask_address(address.wrapping_add(2), width), size_bytes),
        });
        ops.push(PcodeOp::CallIndirect { target });
        return Some(supported("jalr", ops));
    }
    ops.push(PcodeOp::BranchIndirect { target });
    Some(supported("jr", ops))
}

fn lift_atomic(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    width: RiscVWidth,
) -> Option<RiscVLifted> {
    let operation_code: u64 = atomic_operation(mnemonic)?;
    let doubleword: bool = mnemonic.as_bytes().last().copied() == Some(b'd');
    let access_size: u32 = if doubleword {
        if width != RiscVWidth::Rv64 {
            return None;
        }
        8
    } else {
        4
    };
    let address: Varnode = riscv_input(spec, bits(word, 15, 5), width.size_bytes())?;
    let operand: Varnode = if mnemonic.starts_with("lr.") {
        constant(0, access_size)
    } else {
        let register: Varnode = riscv_input(spec, bits(word, 20, 5), width.size_bytes())?;
        Varnode {
            offset: register.offset,
            size_bytes: access_size,
            space: register.space,
        }
    };
    let acquire: u64 = u64::from(bits(word, 26, 1));
    let release: u64 = u64::from(bits(word, 25, 1));
    let lifted_mnemonic: String = atomic_mnemonic(mnemonic, acquire != 0, release != 0);
    Some(RiscVLifted {
        mnemonic: lifted_mnemonic,
        ops: vec![PcodeOp::CallOther {
            name: "riscv_atomic_memory_v1".to_owned(),
            output: riscv_output(spec, bits(word, 7, 5)),
            inputs: vec![
                address,
                operand,
                constant(operation_code, 1),
                constant(u64::from(access_size), 1),
                constant(acquire, 1),
                constant(release, 1),
            ],
        }],
        status: DecodeStatus::CallOther,
    })
}

fn atomic_operation(mnemonic: &str) -> Option<u64> {
    match mnemonic {
        "lr.w" | "lr.d" => Some(0),
        "sc.w" | "sc.d" => Some(1),
        "amoswap.w" | "amoswap.d" => Some(2),
        "amoadd.w" | "amoadd.d" => Some(3),
        "amoand.w" | "amoand.d" => Some(4),
        "amoor.w" | "amoor.d" => Some(5),
        "amoxor.w" | "amoxor.d" => Some(6),
        "amomin.w" | "amomin.d" => Some(7),
        "amomax.w" | "amomax.d" => Some(8),
        _ => None,
    }
}

fn atomic_mnemonic(mnemonic: &str, acquire: bool, release: bool) -> String {
    let suffix: &str = match (acquire, release) {
        (false, false) => "",
        (false, true) => ".rl",
        (true, false) => ".aq",
        (true, true) => ".aqrl",
    };
    format!("{mnemonic}{suffix}")
}

fn lift_immediate(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    width: RiscVWidth,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    let destination_index: u32 = bits(word, 7, 5);
    let output: Option<Varnode> = riscv_output(spec, destination_index);
    let Some(destination) = output else {
        return Some(supported(mnemonic, Vec::new()));
    };
    let source_index: u32 = bits(word, 15, 5);
    let immediate: i64 = sign_extend_u64(u64::from(bits(word, 20, 12)), 12);
    let right: Varnode = signed_constant(immediate, size_bytes);
    let mut ops: Vec<PcodeOp> = Vec::new();
    if mnemonic == "li" {
        ops.push(PcodeOp::Copy {
            output: destination,
            input: right,
        });
    } else if mnemonic == "mv" {
        let input: Varnode = riscv_input(spec, source_index, size_bytes)?;
        ops.push(PcodeOp::Copy {
            output: destination,
            input,
        });
    } else {
        let left: Varnode = riscv_input(spec, source_index, size_bytes)?;
        ops.push(PcodeOp::IntAdd {
            output: destination,
            left,
            right,
        });
    }
    Some(supported(mnemonic, ops))
}

fn lift_binary(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    width: RiscVWidth,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    let destination_index: u32 = bits(word, 7, 5);
    let output: Option<Varnode> = riscv_output(spec, destination_index);
    let Some(destination) = output else {
        return Some(supported(mnemonic, Vec::new()));
    };
    let left: Varnode = riscv_input(spec, bits(word, 15, 5), size_bytes)?;
    let right: Varnode = riscv_input(spec, bits(word, 20, 5), size_bytes)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    match mnemonic {
        "add" => ops.push(PcodeOp::IntAdd {
            output: destination,
            left,
            right,
        }),
        "sub" => ops.push(PcodeOp::IntSub {
            output: destination,
            left,
            right,
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
        "sll" | "srl" | "sra" => {
            let amount: Varnode = allocator.allocate(size_bytes)?;
            let shift_mask: u64 = u64::from(width.bit_width().saturating_sub(1));
            ops.push(PcodeOp::IntAnd {
                output: amount,
                left: right,
                right: constant(shift_mask, size_bytes),
            });
            let operation: PcodeOp = match mnemonic {
                "sll" => PcodeOp::IntLeft {
                    output: destination,
                    input: left,
                    amount,
                },
                "srl" => PcodeOp::IntRight {
                    output: destination,
                    input: left,
                    amount,
                },
                "sra" => PcodeOp::IntSignedRight {
                    output: destination,
                    input: left,
                    amount,
                },
                _ => return None,
            };
            ops.push(operation);
        }
        "slt" => {
            let comparison: Varnode = allocator.allocate(1)?;
            ops.push(PcodeOp::IntSignedLess {
                output: comparison,
                left,
                right,
            });
            ops.push(PcodeOp::IntZext {
                output: destination,
                input: comparison,
            });
        }
        _ => return None,
    }
    Some(supported(mnemonic, ops))
}

fn lift_upper(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
    width: RiscVWidth,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let output: Option<Varnode> = riscv_output(spec, bits(word, 7, 5));
    let Some(destination) = output else {
        return Some(supported(mnemonic, Vec::new()));
    };
    let size_bytes: u32 = width.size_bytes();
    let immediate: i64 = sign_extend_u64(u64::from(bits(word, 12, 20)), 20);
    let value: Varnode = signed_constant(immediate, size_bytes);
    let amount: Varnode = constant(12, 4);
    let mut ops: Vec<PcodeOp> = Vec::new();
    if mnemonic == "lui" {
        ops.push(PcodeOp::IntLeft {
            output: destination,
            input: value,
            amount,
        });
    } else {
        let shifted: Varnode = allocator.allocate(size_bytes)?;
        ops.push(PcodeOp::IntLeft {
            output: shifted,
            input: value,
            amount,
        });
        ops.push(PcodeOp::IntAdd {
            output: destination,
            left: constant(mask_address(address, width), size_bytes),
            right: shifted,
        });
    }
    Some(supported(mnemonic, ops))
}

fn lift_memory(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    width: RiscVWidth,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    let base: Varnode = riscv_input(spec, bits(word, 15, 5), size_bytes)?;
    let store: bool = matches!(mnemonic, "sw" | "sd");
    let immediate: i64 = if store {
        let encoded: u64 = u64::from(bits(word, 7, 5) | (bits(word, 25, 7) << 5));
        sign_extend_u64(encoded, 12)
    } else {
        sign_extend_u64(u64::from(bits(word, 20, 12)), 12)
    };
    let pointer: Varnode = allocator.allocate(size_bytes)?;
    let mut ops: Vec<PcodeOp> = vec![PcodeOp::IntAdd {
        output: pointer,
        left: base,
        right: signed_constant(immediate, size_bytes),
    }];
    let access_size: u32 = match mnemonic {
        "lw" | "sw" => 4,
        "ld" | "sd" if width == RiscVWidth::Rv64 => 8,
        _ => return None,
    };
    if store {
        let input: Varnode = riscv_input(spec, bits(word, 20, 5), size_bytes)?;
        let value: Varnode = if access_size == size_bytes {
            input
        } else {
            Varnode {
                offset: input.offset,
                size_bytes: access_size,
                space: input.space,
            }
        };
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value,
        });
        return Some(supported(mnemonic, ops));
    }
    let destination: Option<Varnode> = riscv_output(spec, bits(word, 7, 5));
    let loaded: Varnode = match destination {
        Some(output) if access_size == size_bytes => output,
        _ => allocator.allocate(access_size)?,
    };
    ops.push(PcodeOp::Load {
        output: loaded,
        space: Space::Ram,
        pointer,
    });
    if let Some(output) = destination
        && access_size < size_bytes
    {
        ops.push(PcodeOp::IntSext {
            output,
            input: loaded,
        });
    }
    Some(supported(mnemonic, ops))
}

fn lift_control(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
    width: RiscVWidth,
    profile: RiscVProfile,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    if matches!(mnemonic, "beq" | "bne" | "blt" | "bge") {
        return lift_branch(spec, mnemonic, word, address, width, profile, allocator);
    }
    if matches!(mnemonic, "jal" | "j") {
        return Some(lift_jal(spec, mnemonic, word, address, width, profile));
    }
    if matches!(mnemonic, "jalr" | "jr" | "ret") {
        return lift_jalr(spec, mnemonic, word, address, width, profile, allocator);
    }
    None
}

fn lift_branch(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
    width: RiscVWidth,
    profile: RiscVProfile,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    let left: Varnode = riscv_input(spec, bits(word, 15, 5), size_bytes)?;
    let right: Varnode = riscv_input(spec, bits(word, 20, 5), size_bytes)?;
    let condition: Varnode = allocator.allocate(1)?;
    let comparison: PcodeOp = match mnemonic {
        "beq" => PcodeOp::IntEqual {
            output: condition,
            left,
            right,
        },
        "bne" => PcodeOp::IntNotEqual {
            output: condition,
            left,
            right,
        },
        "blt" => PcodeOp::IntSignedLess {
            output: condition,
            left,
            right,
        },
        "bge" => PcodeOp::IntSignedLessEqual {
            output: condition,
            left: right,
            right: left,
        },
        _ => return None,
    };
    let encoded: u64 = u64::from(
        (bits(word, 31, 1) << 12)
            | (bits(word, 7, 1) << 11)
            | (bits(word, 25, 6) << 5)
            | (bits(word, 8, 4) << 1),
    );
    let displacement: i64 = sign_extend_u64(encoded, 13);
    let target: Varnode = code_address(add_signed_address(address, displacement, width), width);
    if target.offset & instruction_alignment_mask(profile) != 0 {
        return Some(RiscVLifted {
            mnemonic: mnemonic.to_owned(),
            ops: vec![comparison, instruction_alignment(vec![condition, target])],
            status: DecodeStatus::CallOther,
        });
    }
    Some(supported(
        mnemonic,
        vec![comparison, PcodeOp::CBranch { target, condition }],
    ))
}

fn lift_jal(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
    width: RiscVWidth,
    profile: RiscVProfile,
) -> RiscVLifted {
    let destination_index: u32 = bits(word, 7, 5);
    let encoded: u64 = u64::from(
        (bits(word, 31, 1) << 20)
            | (bits(word, 12, 8) << 12)
            | (bits(word, 20, 1) << 11)
            | (bits(word, 21, 10) << 1),
    );
    let displacement: i64 = sign_extend_u64(encoded, 21);
    let target: Varnode = code_address(add_signed_address(address, displacement, width), width);
    if target.offset & instruction_alignment_mask(profile) != 0 {
        return RiscVLifted {
            mnemonic: mnemonic.to_owned(),
            ops: vec![instruction_alignment(vec![target])],
            status: DecodeStatus::CallOther,
        };
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    if let Some(output) = riscv_output(spec, destination_index) {
        ops.push(PcodeOp::Copy {
            output,
            input: constant(
                mask_address(address.wrapping_add(4), width),
                width.size_bytes(),
            ),
        });
    }
    if matches!(destination_index, 1 | 5) {
        ops.push(PcodeOp::Call { target });
    } else {
        ops.push(PcodeOp::Branch { target });
    }
    supported(mnemonic, ops)
}

fn lift_jalr(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
    width: RiscVWidth,
    profile: RiscVProfile,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    let source_index: u32 = bits(word, 15, 5);
    let source: Varnode = riscv_input(spec, source_index, size_bytes)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let target: Varnode;
    if mnemonic == "ret" {
        target = allocator.allocate(size_bytes)?;
        ops.push(PcodeOp::IntAnd {
            output: target,
            left: source,
            right: constant(mask_for_bytes(size_bytes) & !1_u64, size_bytes),
        });
        if profile == RiscVProfile::Base {
            ops.push(instruction_alignment(vec![target]));
        }
        ops.push(PcodeOp::Return {
            target: Some(target),
        });
        return Some(RiscVLifted {
            mnemonic: mnemonic.to_owned(),
            ops,
            status: if profile == RiscVProfile::Base {
                DecodeStatus::CallOther
            } else {
                DecodeStatus::Supported
            },
        });
    }
    let immediate: i64 = sign_extend_u64(u64::from(bits(word, 20, 12)), 12);
    let sum: Varnode = allocator.allocate(size_bytes)?;
    target = allocator.allocate(size_bytes)?;
    ops.push(PcodeOp::IntAdd {
        output: sum,
        left: source,
        right: signed_constant(immediate, size_bytes),
    });
    ops.push(PcodeOp::IntAnd {
        output: target,
        left: sum,
        right: constant(mask_for_bytes(size_bytes) & !1_u64, size_bytes),
    });
    let destination_index: u32 = bits(word, 7, 5);
    let static_target: Option<u64> = (source_index == 0)
        .then(|| mask_address(u64::from_ne_bytes(immediate.to_ne_bytes()), width) & !1_u64);
    if static_target.is_some_and(|value: u64| value & instruction_alignment_mask(profile) != 0) {
        ops.push(instruction_alignment(vec![target]));
        return Some(RiscVLifted {
            mnemonic: mnemonic.to_owned(),
            ops,
            status: DecodeStatus::CallOther,
        });
    }
    let dynamic_alignment: bool = profile == RiscVProfile::Base && static_target.is_none();
    if dynamic_alignment {
        ops.push(instruction_alignment(vec![target]));
    }
    if let Some(output) = riscv_output(spec, destination_index) {
        ops.push(PcodeOp::Copy {
            output,
            input: constant(mask_address(address.wrapping_add(4), width), size_bytes),
        });
    }
    if matches!(destination_index, 1 | 5) {
        ops.push(PcodeOp::CallIndirect { target });
    } else {
        ops.push(PcodeOp::BranchIndirect { target });
    }
    Some(RiscVLifted {
        mnemonic: mnemonic.to_owned(),
        ops,
        status: if dynamic_alignment {
            DecodeStatus::CallOther
        } else {
            DecodeStatus::Supported
        },
    })
}

fn lift_multiply_divide(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    width: RiscVWidth,
    allocator: &mut UniqueAllocator,
) -> Option<RiscVLifted> {
    let size_bytes: u32 = width.size_bytes();
    let output: Option<Varnode> = riscv_output(spec, bits(word, 7, 5));
    let Some(destination) = output else {
        return Some(supported(mnemonic, Vec::new()));
    };
    let left: Varnode = riscv_input(spec, bits(word, 15, 5), size_bytes)?;
    let right: Varnode = riscv_input(spec, bits(word, 20, 5), size_bytes)?;
    if mnemonic == "mul" {
        return Some(supported(
            mnemonic,
            vec![PcodeOp::IntMult {
                output: destination,
                left,
                right,
            }],
        ));
    }
    if matches!(mnemonic, "mulh" | "mulhsu" | "mulhu") {
        let extended_size: u32 = size_bytes.checked_mul(2)?;
        let extended_left: Varnode = allocator.allocate(extended_size)?;
        let extended_right: Varnode = allocator.allocate(extended_size)?;
        let product: Varnode = allocator.allocate(extended_size)?;
        let extend_left: PcodeOp = if mnemonic == "mulhu" {
            PcodeOp::IntZext {
                output: extended_left,
                input: left,
            }
        } else {
            PcodeOp::IntSext {
                output: extended_left,
                input: left,
            }
        };
        let extend_right: PcodeOp = if mnemonic == "mulh" {
            PcodeOp::IntSext {
                output: extended_right,
                input: right,
            }
        } else {
            PcodeOp::IntZext {
                output: extended_right,
                input: right,
            }
        };
        return Some(supported(
            mnemonic,
            vec![
                extend_left,
                extend_right,
                PcodeOp::IntMult {
                    output: product,
                    left: extended_left,
                    right: extended_right,
                },
                PcodeOp::Subpiece {
                    output: destination,
                    input: product,
                    byte_offset: constant(u64::from(size_bytes), 4),
                },
            ],
        ));
    }
    if !matches!(mnemonic, "div" | "divu" | "rem" | "remu") {
        return None;
    }
    let left_snapshot: Varnode = allocator.allocate(size_bytes)?;
    let right_snapshot: Varnode = allocator.allocate(size_bytes)?;
    let arithmetic: PcodeOp = match mnemonic {
        "div" => PcodeOp::IntSignedDiv {
            output: destination,
            left: left_snapshot,
            right: right_snapshot,
        },
        "divu" => PcodeOp::IntDiv {
            output: destination,
            left: left_snapshot,
            right: right_snapshot,
        },
        "rem" => PcodeOp::IntSignedRem {
            output: destination,
            left: left_snapshot,
            right: right_snapshot,
        },
        "remu" => PcodeOp::IntRem {
            output: destination,
            left: left_snapshot,
            right: right_snapshot,
        },
        _ => return None,
    };
    Some(RiscVLifted {
        mnemonic: mnemonic.to_owned(),
        ops: vec![
            PcodeOp::Copy {
                output: left_snapshot,
                input: left,
            },
            PcodeOp::Copy {
                output: right_snapshot,
                input: right,
            },
            arithmetic,
            PcodeOp::CallOther {
                name: "riscv_division_edge_cases".to_owned(),
                output: None,
                inputs: vec![left_snapshot, right_snapshot, destination],
            },
        ],
        status: DecodeStatus::CallOther,
    })
}

fn instruction_alignment(inputs: Vec<Varnode>) -> PcodeOp {
    PcodeOp::CallOther {
        name: "riscv_instruction_address_alignment".to_owned(),
        output: None,
        inputs,
    }
}

fn supported(mnemonic: &str, ops: Vec<PcodeOp>) -> RiscVLifted {
    RiscVLifted {
        mnemonic: mnemonic.to_owned(),
        ops,
        status: DecodeStatus::Supported,
    }
}

fn riscv_input(spec: &SleighSpec, index: u32, size_bytes: u32) -> Option<Varnode> {
    if index == 0 {
        return Some(constant(0, size_bytes));
    }
    riscv_register(spec, index)
}

fn riscv_output(spec: &SleighSpec, index: u32) -> Option<Varnode> {
    if index == 0 {
        return None;
    }
    riscv_register(spec, index)
}

fn riscv_register(spec: &SleighSpec, index: u32) -> Option<Varnode> {
    let names: [&str; 32] = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6",
    ];
    let position: usize = usize::try_from(index).ok()?;
    let name: &&str = names.get(position)?;
    named_register(spec, name)
}

const fn instruction_alignment_mask(profile: RiscVProfile) -> u64 {
    match profile {
        RiscVProfile::Base => 3,
        RiscVProfile::Compressed => 1,
    }
}

fn signed_constant(value: i64, size_bytes: u32) -> Varnode {
    constant(u64::from_ne_bytes(value.to_ne_bytes()), size_bytes)
}

fn add_signed_address(address: u64, displacement: i64, width: RiscVWidth) -> u64 {
    let encoded: u64 = u64::from_ne_bytes(displacement.to_ne_bytes());
    mask_address(address.wrapping_add(encoded), width)
}

fn mask_address(address: u64, width: RiscVWidth) -> u64 {
    address & mask_for_bytes(width.size_bytes())
}

const fn code_address(offset: u64, width: RiscVWidth) -> Varnode {
    Varnode {
        offset,
        size_bytes: width.size_bytes(),
        space: Space::Ram,
    }
}

fn read_word(bytes: &[u8]) -> Option<u32> {
    let array: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn read_halfword(bytes: &[u8]) -> Option<u16> {
    let array: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

fn encoded_width(halfword: u16) -> EncodedWidth {
    if halfword & 0x3 != 0x3 {
        return EncodedWidth::Supported(2);
    }
    if halfword & 0x1f != 0x1f {
        return EncodedWidth::Supported(4);
    }
    if halfword & 0x3f == 0x1f {
        return EncodedWidth::Unsupported(6);
    }
    if halfword & 0x7f == 0x3f {
        return EncodedWidth::Unsupported(8);
    }
    let length_code: u16 = (halfword >> 12) & 0x7;
    if length_code == 0x7 {
        EncodedWidth::Unbounded
    } else {
        EncodedWidth::Unsupported(10_usize.saturating_add(usize::from(length_code) * 2))
    }
}

impl RiscVWidth {
    const fn bit_width(self) -> u32 {
        self.size_bytes() * 8
    }

    const fn size_bytes(self) -> u32 {
        match self {
            Self::Rv32 => 4,
            Self::Rv64 => 8,
        }
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

fn unsupported_length(bytes: &[u8], address: u64) -> PcodeInstr {
    let capture_length: usize = bytes.len().min(UNSUPPORTED_ENCODING_CAPTURE_LIMIT);
    let captured: &[u8] = bytes
        .get(..capture_length)
        .map_or(&[], |value: &[u8]| value);
    PcodeInstr {
        address,
        bytes: captured.to_vec(),
        length: bytes.len(),
        mnemonic: ".insn".to_owned(),
        operands: hex_bytes(captured),
        ops: vec![PcodeOp::CallOther {
            name: "riscv_unsupported_instruction_length".to_owned(),
            output: None,
            inputs: vec![constant(
                u64::try_from(bytes.len()).map_or(u64::MAX, |value: u64| value),
                8,
            )],
        }],
        status: DecodeStatus::Unsupported,
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
        name: "riscv_spec_error".to_owned(),
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
