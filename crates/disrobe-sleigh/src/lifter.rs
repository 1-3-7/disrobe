use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::SleighError;
use crate::compiler::{
    CompiledSpec, ConflictPolicy, ContextState, DecodeMatch, DecodeOutcome,
    compile_spec_with_policy,
};
use crate::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use crate::syntax::{Constructor, SleighSpec, parse_spec};
use crate::vendor::preprocessed_aarch64_source;

mod arm32;
mod mips32;
mod powerpc;
mod riscv;

static AARCH64_SPEC: OnceLock<Result<CompiledSpec, SleighError>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmMode {
    A32,
    Thumb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiscVWidth {
    Rv32,
    Rv64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RiscVProfile {
    Base,
    Compressed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PowerPcWidth {
    Ppc32,
    Ppc64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Language {
    AArch64,
    Arm32(ArmMode),
    Mips32(crate::syntax::Endian),
    PowerPc32Be,
    PowerPc64Be,
    RiscV(RiscVWidth),
    RiscVCompressed(RiscVWidth),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedBlock {
    pub consumed: usize,
    pub instructions: Vec<PcodeInstr>,
    pub ordered_ops: Vec<PcodeOp>,
}

#[derive(Debug)]
struct Lifted {
    operands: String,
    ops: Vec<PcodeOp>,
}

#[derive(Clone, Copy, Debug)]
struct Destination {
    architectural: Option<Varnode>,
    result: Varnode,
}

#[derive(Clone, Copy, Debug, Default)]
struct UniqueAllocator {
    next: u64,
}

pub fn decode_block(bytes: &[u8], address: u64) -> Vec<PcodeInstr> {
    let compiled_result: &Result<CompiledSpec, SleighError> =
        AARCH64_SPEC.get_or_init(compile_aarch64);
    let compiled: &CompiledSpec = match compiled_result {
        Ok(value) => value,
        Err(error) => return spec_error_block(bytes, address, error),
    };
    let mut context: ContextState = BTreeMap::new();
    context.insert("ImmS_ImmR_TestSet".to_owned(), 1);
    let mut allocator: UniqueAllocator = UniqueAllocator::default();
    let mut instructions: Vec<PcodeInstr> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let remaining: usize = bytes.len().saturating_sub(cursor);
        let instruction_address: u64 = u64::try_from(cursor)
            .ok()
            .map_or(u64::MAX, |offset: u64| address.wrapping_add(offset));
        if remaining < 4 {
            instructions.push(PcodeInstr {
                address: instruction_address,
                bytes: bytes[cursor..].to_vec(),
                length: remaining,
                mnemonic: ".byte".to_owned(),
                operands: hex_bytes(&bytes[cursor..]),
                ops: Vec::new(),
                status: DecodeStatus::Truncated,
            });
            break;
        }
        let instruction_bytes: &[u8] = &bytes[cursor..cursor.saturating_add(4)];
        if let Some(word) = read_word(instruction_bytes) {
            seed_instruction_context(word, &mut context);
        }
        let outcome: DecodeOutcome =
            compiled.decode(instruction_bytes, instruction_address, &context);
        let instruction: PcodeInstr = lift_outcome(
            compiled,
            outcome,
            instruction_bytes,
            instruction_address,
            &mut allocator,
        );
        let length: usize = instruction.length.max(1).min(remaining);
        instructions.push(instruction);
        cursor = cursor.saturating_add(length);
    }
    instructions
}

pub fn decode_block_for_language(language: Language, bytes: &[u8], address: u64) -> DecodedBlock {
    match language {
        Language::AArch64 => {
            let instructions: Vec<PcodeInstr> = decode_block(bytes, address);
            let ordered_ops: Vec<PcodeOp> = instructions
                .iter()
                .flat_map(|instruction: &PcodeInstr| instruction.ops.iter().cloned())
                .collect();
            let consumed: usize = instructions
                .iter()
                .map(|instruction: &PcodeInstr| instruction.length)
                .sum::<usize>()
                .min(bytes.len());
            DecodedBlock {
                consumed,
                instructions,
                ordered_ops,
            }
        }
        Language::Arm32(mode) => arm32::decode_block(bytes, address, mode),
        Language::Mips32(endian) => mips32::decode_block(bytes, address, endian),
        Language::PowerPc32Be => powerpc::decode_block(bytes, address, PowerPcWidth::Ppc32),
        Language::PowerPc64Be => powerpc::decode_block(bytes, address, PowerPcWidth::Ppc64),
        Language::RiscV(width) => riscv::decode_block(bytes, address, width, RiscVProfile::Base),
        Language::RiscVCompressed(width) => {
            riscv::decode_block(bytes, address, width, RiscVProfile::Compressed)
        }
    }
}

fn compile_aarch64() -> Result<CompiledSpec, SleighError> {
    let source: String = preprocessed_aarch64_source()?;
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
        DecodeOutcome::NoMatch => {
            let word: u32 = read_word(bytes).unwrap_or(0);
            PcodeInstr {
                address,
                bytes: bytes.to_vec(),
                length: bytes.len(),
                mnemonic: ".inst".to_owned(),
                operands: format!("0x{word:08x}"),
                ops: vec![PcodeOp::CallOther {
                    name: format!("decode_unmatched_0x{word:08x}"),
                    output: None,
                    inputs: Vec::new(),
                }],
                status: DecodeStatus::NoMatch,
            }
        }
        DecodeOutcome::ResourceLimit { attempts } => PcodeInstr {
            address,
            bytes: bytes.to_vec(),
            length: bytes.len(),
            mnemonic: ".resource_limit".to_owned(),
            operands: attempts.to_string(),
            ops: vec![PcodeOp::CallOther {
                name: "decode_resource_limit".to_owned(),
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
                name: "decode_ambiguous".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::Ambiguous,
        },
        DecodeOutcome::Truncated { available, .. } => PcodeInstr {
            address,
            bytes: bytes.get(..available).unwrap_or(bytes).to_vec(),
            length: available,
            mnemonic: ".byte".to_owned(),
            operands: hex_bytes(bytes.get(..available).unwrap_or(bytes)),
            ops: Vec::new(),
            status: DecodeStatus::Truncated,
        },
    }
}

fn lift_match(
    compiled: &CompiledSpec,
    matched: DecodeMatch,
    bytes: &[u8],
    allocator: &mut UniqueAllocator,
) -> PcodeInstr {
    let word: u32 = read_word(bytes).unwrap_or(0);
    let constructor: Option<&Constructor> =
        compiled.source().constructors.get(matched.constructor_id);
    let mnemonic: String = matched.mnemonic.clone();
    let lifted: Option<Lifted> = constructor.and_then(|selected: &Constructor| {
        lift_supported(
            compiled.source(),
            selected,
            &mnemonic,
            word,
            matched.address,
            allocator,
        )
    });
    if let Some(value) = lifted {
        return PcodeInstr {
            address: matched.address,
            bytes: bytes.to_vec(),
            length: matched.length,
            mnemonic,
            operands: value.operands,
            ops: value.ops,
            status: DecodeStatus::Supported,
        };
    }
    unsupported_constructor(compiled, matched, bytes, mnemonic)
}

fn identifier_from_mnemonic(mnemonic: &str) -> String {
    mnemonic
        .chars()
        .map(|character: char| {
            if character == '_' || character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn unsupported_constructor(
    compiled: &CompiledSpec,
    matched: DecodeMatch,
    bytes: &[u8],
    mnemonic: String,
) -> PcodeInstr {
    let constructor: Option<&Constructor> =
        compiled.source().constructors.get(matched.constructor_id);
    let pcodeop: Option<String> = constructor.and_then(|selected: &Constructor| {
        selected
            .semantic_tokens
            .iter()
            .find(|token: &&String| compiled.source().pcodeops.contains(*token))
            .cloned()
    });
    let (name, status): (String, DecodeStatus) = pcodeop.map_or_else(
        || {
            (
                format!("unsupported_{}", identifier_from_mnemonic(&mnemonic)),
                DecodeStatus::Unsupported,
            )
        },
        |operation: String| (operation, DecodeStatus::CallOther),
    );
    PcodeInstr {
        address: matched.address,
        bytes: bytes.to_vec(),
        length: matched.length,
        mnemonic,
        operands: String::new(),
        ops: vec![PcodeOp::CallOther {
            name,
            output: None,
            inputs: Vec::new(),
        }],
        status,
    }
}

fn lift_supported(
    spec: &SleighSpec,
    _constructor: &Constructor,
    mnemonic: &str,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if matches!(
        mnemonic,
        "add" | "adds" | "sub" | "subs" | "cmp" | "cmn" | "mov"
    ) && let Some(value) = lift_add_sub(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "and" | "ands" | "eor" | "orr" | "mov" | "tst")
        && let Some(value) = lift_logical_register(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "mov" | "movk" | "movn" | "movz")
        && let Some(value) = lift_move_wide(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "asr" | "lsl" | "lsr")
        && let Some(value) = lift_bitfield_shift(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "ldr" | "str" | "ldur" | "stur")
        && let Some(value) = lift_load_store(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "ldr" | "str" | "ldur" | "stur")
        && let Some(value) = lift_scalar_fp_load_store(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if mnemonic == "ldr"
        && let Some(value) = lift_scalar_fp_literal(spec, word, address, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "ldp" | "stp")
        && let Some(value) = lift_pair(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "ldp" | "stp")
        && let Some(value) = lift_scalar_fp_pair(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "madd" | "msub" | "mul")
        && let Some(value) = lift_multiply(spec, mnemonic, word, allocator)
    {
        return Some(value);
    }
    if mnemonic == "csel"
        && let Some(value) = lift_csel(spec, word, allocator)
    {
        return Some(value);
    }
    if (mnemonic == "b"
        || mnemonic.starts_with("b.")
        || matches!(mnemonic, "bl" | "br" | "blr" | "cbnz" | "cbz" | "ret"))
        && let Some(value) = lift_control(spec, mnemonic, word, address, allocator)
    {
        return Some(value);
    }
    if matches!(mnemonic, "adr" | "adrp")
        && let Some(value) = lift_address(spec, mnemonic, word, address, allocator)
    {
        return Some(value);
    }
    (mnemonic == "nop" && word == 0xd503_201f).then_some(Lifted {
        operands: String::new(),
        ops: Vec::new(),
    })
}

fn lift_add_sub(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    let class: u32 = bits(word, 24, 5);
    let width: u32 = if bit(word, 31) { 8 } else { 4 };
    let is_sub: bool = bit(word, 30) || matches!(mnemonic, "sub" | "subs" | "cmp");
    let sets_flags: bool = bit(word, 29) || matches!(mnemonic, "cmp" | "cmn" | "adds" | "subs");
    let rn: u32 = bits(word, 5, 5);
    let rd: u32 = bits(word, 0, 5);
    let mut ops: Vec<PcodeOp> = Vec::new();
    let left: Varnode;
    let right: Varnode;
    let sp_allowed: bool;
    if class == 0x11 {
        sp_allowed = true;
        left = gpr_input(spec, rn, width, true)?;
        let shift: u32 = if bit(word, 22) { 12 } else { 0 };
        let immediate: u64 = u64::from(bits(word, 10, 12)).checked_shl(shift)?;
        right = constant(immediate, width);
    } else if class == 0x0b && !bit(word, 21) {
        sp_allowed = false;
        left = gpr_input(spec, rn, width, false)?;
        let rm: u32 = bits(word, 16, 5);
        let raw_right: Varnode = gpr_input(spec, rm, width, false)?;
        let shift_type: u32 = bits(word, 22, 2);
        let amount: u32 = bits(word, 10, 6);
        right = shift_operand(raw_right, shift_type, amount, allocator, &mut ops)?;
    } else {
        return None;
    }
    if mnemonic == "mov" && !is_sub && right.space == Space::Constant && right.offset == 0 {
        let destination: Destination = destination(spec, rd, width, sp_allowed, allocator)?;
        ops.push(PcodeOp::Copy {
            output: destination.result,
            input: left,
        });
        finish_destination(destination, &mut ops);
        return Some(Lifted {
            operands: String::new(),
            ops,
        });
    }
    let destination_sp_allowed: bool = sp_allowed && !sets_flags;
    let destination: Destination = destination(spec, rd, width, destination_sp_allowed, allocator)?;
    if is_sub {
        ops.push(PcodeOp::IntSub {
            output: destination.result,
            left,
            right,
        });
    } else {
        ops.push(PcodeOp::IntAdd {
            output: destination.result,
            left,
            right,
        });
    }
    if sets_flags {
        emit_flags(
            spec,
            destination.result,
            left,
            right,
            is_sub,
            allocator,
            &mut ops,
        )?;
    }
    finish_destination(destination, &mut ops);
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_logical_register(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if bits(word, 24, 5) != 0x0a {
        return None;
    }
    let width: u32 = if bit(word, 31) { 8 } else { 4 };
    let rn: u32 = bits(word, 5, 5);
    let rm: u32 = bits(word, 16, 5);
    let rd: u32 = bits(word, 0, 5);
    let mut ops: Vec<PcodeOp> = Vec::new();
    let left: Varnode = gpr_input(spec, rn, width, false)?;
    let raw_right: Varnode = gpr_input(spec, rm, width, false)?;
    let shift_type: u32 = bits(word, 22, 2);
    let amount: u32 = bits(word, 10, 6);
    let mut right: Varnode = shift_operand(raw_right, shift_type, amount, allocator, &mut ops)?;
    if bit(word, 21) {
        let inverted: Varnode = allocator.allocate(width)?;
        ops.push(PcodeOp::IntNegate {
            output: inverted,
            input: right,
        });
        right = inverted;
    }
    let destination: Destination = destination(spec, rd, width, false, allocator)?;
    let opcode: u32 = bits(word, 29, 2);
    if mnemonic == "mov" && opcode == 1 {
        ops.push(PcodeOp::Copy {
            output: destination.result,
            input: right,
        });
    } else {
        match opcode {
            0 | 3 => ops.push(PcodeOp::IntAnd {
                output: destination.result,
                left,
                right,
            }),
            1 => ops.push(PcodeOp::IntOr {
                output: destination.result,
                left,
                right,
            }),
            2 => ops.push(PcodeOp::IntXor {
                output: destination.result,
                left,
                right,
            }),
            _ => return None,
        }
    }
    if opcode == 3 {
        emit_logic_flags(spec, destination.result, allocator, &mut ops)?;
    }
    finish_destination(destination, &mut ops);
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_move_wide(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if word & 0x1f80_0000 != 0x1280_0000 {
        return None;
    }
    let width: u32 = if bit(word, 31) { 8 } else { 4 };
    let width_bits: u32 = width.checked_mul(8)?;
    let hw: u32 = bits(word, 21, 2);
    let shift: u32 = hw.checked_mul(16)?;
    if shift >= width_bits {
        return None;
    }
    let immediate: u64 = u64::from(bits(word, 5, 16)).checked_shl(shift)?;
    let rd: u32 = bits(word, 0, 5);
    let destination: Destination = destination(spec, rd, width, false, allocator)?;
    let opcode: u32 = bits(word, 29, 2);
    let mut ops: Vec<PcodeOp> = Vec::new();
    if opcode == 3 || mnemonic == "movk" {
        let old: Varnode = gpr_input(spec, rd, width, false)?;
        let field_mask: u64 = 0xffff_u64.checked_shl(shift)?;
        let width_mask: u64 = mask_for_bytes(width);
        let clear_mask: u64 = width_mask & !field_mask;
        let cleared: Varnode = allocator.allocate(width)?;
        ops.push(PcodeOp::IntAnd {
            output: cleared,
            left: old,
            right: constant(clear_mask, width),
        });
        ops.push(PcodeOp::IntOr {
            output: destination.result,
            left: cleared,
            right: constant(immediate, width),
        });
    } else {
        let value: u64 = if opcode == 0 || mnemonic == "movn" {
            !immediate & mask_for_bytes(width)
        } else if opcode == 2 {
            immediate
        } else {
            return None;
        };
        ops.push(PcodeOp::Copy {
            output: destination.result,
            input: constant(value, width),
        });
    }
    finish_destination(destination, &mut ops);
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_bitfield_shift(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if word & 0x1f80_0000 != 0x1300_0000 {
        return None;
    }
    let width: u32 = if bit(word, 31) { 8 } else { 4 };
    let width_bits: u32 = width.checked_mul(8)?;
    let immr: u32 = bits(word, 16, 6);
    let imms: u32 = bits(word, 10, 6);
    let rn: u32 = bits(word, 5, 5);
    let rd: u32 = bits(word, 0, 5);
    let input: Varnode = gpr_input(spec, rn, width, false)?;
    let amount: u32 = match mnemonic {
        "lsl" if imms.saturating_add(1) % width_bits == immr % width_bits => {
            width_bits.saturating_sub(immr) % width_bits
        }
        "lsr" | "asr" if imms == width_bits.saturating_sub(1) => immr,
        _ => return None,
    };
    let destination: Destination = destination(spec, rd, width, false, allocator)?;
    let operation: PcodeOp = match mnemonic {
        "lsl" => PcodeOp::IntLeft {
            output: destination.result,
            input,
            amount: constant(u64::from(amount), 4),
        },
        "lsr" => PcodeOp::IntRight {
            output: destination.result,
            input,
            amount: constant(u64::from(amount), 4),
        },
        "asr" => PcodeOp::IntSignedRight {
            output: destination.result,
            input,
            amount: constant(u64::from(amount), 4),
        },
        _ => return None,
    };
    let mut ops: Vec<PcodeOp> = vec![operation];
    finish_destination(destination, &mut ops);
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_load_store(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if word & 0x3a00_0000 != 0x3800_0000 || bit(word, 26) {
        return None;
    }
    let size_code: u32 = bits(word, 30, 2);
    let width: u32 = 1_u32.checked_shl(size_code)?;
    if !matches!(width, 4 | 8) {
        return None;
    }
    let unsigned_offset: bool = bit(word, 24);
    let index_mode: u32 = bits(word, 10, 2);
    let unscaled: bool = !unsigned_offset && index_mode == 0b00;
    if !unsigned_offset && (bit(word, 21) || matches!(index_mode, 0b10)) {
        return None;
    }
    let opcode: u32 = bits(word, 22, 2);
    let is_load: bool = mnemonic == if unscaled { "ldur" } else { "ldr" } && opcode == 1;
    let is_store: bool = mnemonic == if unscaled { "stur" } else { "str" } && opcode == 0;
    if !is_load && !is_store {
        return None;
    }
    let rn: u32 = bits(word, 5, 5);
    let rt: u32 = bits(word, 0, 5);
    let base: Varnode = gpr_input(spec, rn, 8, true)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let mut post_index_offset: Option<i64> = None;
    let pointer: Varnode = if unsigned_offset {
        let scaled: i64 = i64::from(bits(word, 10, 12)).checked_mul(i64::from(width))?;
        add_signed_offset(base, scaled, allocator, &mut ops)?
    } else {
        let displacement: i64 = signed_bits(word, 12, 9);
        match index_mode {
            0b00 => add_signed_offset(base, displacement, allocator, &mut ops)?,
            0b01 => {
                post_index_offset = Some(displacement);
                base
            }
            _ => {
                let updated: Varnode = add_signed_offset(base, displacement, allocator, &mut ops)?;
                let writeback: Varnode = register_output(spec, rn, 8, true)?;
                ops.push(PcodeOp::Copy {
                    output: writeback,
                    input: updated,
                });
                updated
            }
        }
    };
    if is_load {
        let destination: Destination = destination(spec, rt, width, false, allocator)?;
        ops.push(PcodeOp::Load {
            output: destination.result,
            space: Space::Ram,
            pointer,
        });
        finish_destination(destination, &mut ops);
    } else {
        let value: Varnode = gpr_input(spec, rt, width, false)?;
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value,
        });
    }
    if let Some(displacement) = post_index_offset {
        let updated: Varnode = add_signed_offset(base, displacement, allocator, &mut ops)?;
        let writeback: Varnode = register_output(spec, rn, 8, true)?;
        ops.push(PcodeOp::Copy {
            output: writeback,
            input: updated,
        });
    }
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

const fn scalar_fp_transfer(size_code: u32, opcode: u32) -> Option<(u32, bool)> {
    match (size_code, opcode) {
        (0, 0) => Some((1, false)),
        (0, 1) => Some((1, true)),
        (1, 0) => Some((2, false)),
        (1, 1) => Some((2, true)),
        (2, 0) => Some((4, false)),
        (2, 1) => Some((4, true)),
        (3, 0) => Some((8, false)),
        (3, 1) => Some((8, true)),
        (0, 2) => Some((16, false)),
        (0, 3) => Some((16, true)),
        _ => None,
    }
}

fn scalar_fp_register(spec: &SleighSpec, index: u32, width: u32) -> Option<Varnode> {
    let prefix: char = match width {
        1 => 'b',
        2 => 'h',
        4 => 's',
        8 => 'd',
        _ => return None,
    };
    named_register(spec, &format!("{prefix}{index}"))
}

fn vector_half(spec: &SleighSpec, index: u32, half: u64) -> Option<Varnode> {
    let vector: Varnode = named_register(spec, &format!("q{index}"))?;
    Some(Varnode {
        offset: vector.offset.checked_add(half.checked_mul(8)?)?,
        size_bytes: 8,
        space: Space::Register,
    })
}

fn lift_scalar_fp_load_store(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    let class: u32 = bits(word, 24, 6);
    if !matches!(class, 0b111_100 | 0b111_101) {
        return None;
    }
    let (width, is_load): (u32, bool) = scalar_fp_transfer(bits(word, 30, 2), bits(word, 22, 2))?;
    let index_mode: u32 = bits(word, 10, 2);
    let unscaled: bool = class == 0b111_100 && !bit(word, 21) && index_mode == 0b00;
    let expected: &str = match (is_load, unscaled) {
        (true, false) => "ldr",
        (true, true) => "ldur",
        (false, false) => "str",
        (false, true) => "stur",
    };
    if mnemonic != expected {
        return None;
    }
    let rn: u32 = bits(word, 5, 5);
    let rt: u32 = bits(word, 0, 5);
    let base: Varnode = gpr_input(spec, rn, 8, true)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let mut post_index_offset: Option<i64> = None;
    let pointer: Varnode = if class == 0b111_101 {
        let scaled: i64 = i64::from(bits(word, 10, 12)).checked_mul(i64::from(width))?;
        add_signed_offset(base, scaled, allocator, &mut ops)?
    } else if bit(word, 21) {
        if index_mode != 0b10 {
            return None;
        }
        let offset: Varnode = extended_register_offset(spec, word, width, allocator, &mut ops)?;
        let output: Varnode = allocator.allocate(8)?;
        ops.push(PcodeOp::IntAdd {
            output,
            left: base,
            right: offset,
        });
        output
    } else {
        let displacement: i64 = signed_bits(word, 12, 9);
        match index_mode {
            0b00 => add_signed_offset(base, displacement, allocator, &mut ops)?,
            0b01 => {
                post_index_offset = Some(displacement);
                base
            }
            0b11 => {
                let updated: Varnode = add_signed_offset(base, displacement, allocator, &mut ops)?;
                let writeback: Varnode = register_output(spec, rn, 8, true)?;
                ops.push(PcodeOp::Copy {
                    output: writeback,
                    input: updated,
                });
                updated
            }
            _ => return None,
        }
    };
    if is_load {
        lift_scalar_fp_load(spec, rt, width, pointer, allocator, &mut ops)?;
    } else {
        lift_scalar_fp_store(spec, rt, width, pointer, allocator, &mut ops)?;
    }
    if let Some(displacement) = post_index_offset {
        let updated: Varnode = add_signed_offset(base, displacement, allocator, &mut ops)?;
        let writeback: Varnode = register_output(spec, rn, 8, true)?;
        ops.push(PcodeOp::Copy {
            output: writeback,
            input: updated,
        });
    }
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_scalar_fp_load(
    spec: &SleighSpec,
    index: u32,
    width: u32,
    pointer: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    if width == 16 {
        let high_pointer: Varnode = add_signed_offset(pointer, 8, allocator, ops)?;
        ops.push(PcodeOp::Load {
            output: vector_half(spec, index, 0)?,
            space: Space::Ram,
            pointer,
        });
        ops.push(PcodeOp::Load {
            output: vector_half(spec, index, 1)?,
            space: Space::Ram,
            pointer: high_pointer,
        });
        return Some(());
    }
    let value: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Load {
        output: value,
        space: Space::Ram,
        pointer,
    });
    let scalar: Varnode = scalar_fp_register(spec, index, 8)?;
    ops.push(if width == 8 {
        PcodeOp::Copy {
            output: scalar,
            input: value,
        }
    } else {
        PcodeOp::IntZext {
            output: scalar,
            input: value,
        }
    });
    ops.push(PcodeOp::Copy {
        output: vector_half(spec, index, 1)?,
        input: constant(0, 8),
    });
    Some(())
}

fn lift_scalar_fp_store(
    spec: &SleighSpec,
    index: u32,
    width: u32,
    pointer: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    if width == 16 {
        let high_pointer: Varnode = add_signed_offset(pointer, 8, allocator, ops)?;
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value: vector_half(spec, index, 0)?,
        });
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer: high_pointer,
            value: vector_half(spec, index, 1)?,
        });
        return Some(());
    }
    ops.push(PcodeOp::Store {
        space: Space::Ram,
        pointer,
        value: scalar_fp_register(spec, index, width)?,
    });
    Some(())
}

fn extended_register_offset(
    spec: &SleighSpec,
    word: u32,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    if !bit(word, 14) {
        return None;
    }
    let option: u32 = bits(word, 13, 3);
    let rm: u32 = bits(word, 16, 5);
    let extended: Varnode = match option {
        0b011 | 0b111 => gpr_input(spec, rm, 8, false)?,
        0b010 | 0b110 => {
            let narrow: Varnode = gpr_input(spec, rm, 4, false)?;
            let output: Varnode = allocator.allocate(8)?;
            ops.push(if option == 0b010 {
                PcodeOp::IntZext {
                    output,
                    input: narrow,
                }
            } else {
                PcodeOp::IntSext {
                    output,
                    input: narrow,
                }
            });
            output
        }
        _ => return None,
    };
    let amount: u32 = if bit(word, 12) {
        width.trailing_zeros()
    } else {
        0
    };
    shift_operand(extended, 0, amount, allocator, ops)
}

fn lift_scalar_fp_literal(
    spec: &SleighSpec,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if bits(word, 24, 6) != 0b011_100 {
        return None;
    }
    let width: u32 = match bits(word, 30, 2) {
        0 => 4,
        1 => 8,
        2 => 16,
        _ => return None,
    };
    let rt: u32 = bits(word, 0, 5);
    let displacement: i64 = signed_bits(word, 5, 19).checked_mul(4)?;
    let target: u64 = address.wrapping_add(u64::from_ne_bytes(displacement.to_ne_bytes()));
    let mut ops: Vec<PcodeOp> = Vec::new();
    lift_scalar_fp_load(spec, rt, width, constant(target, 8), allocator, &mut ops)?;
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_scalar_fp_pair(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if bits(word, 27, 3) != 0b101 || !bit(word, 26) {
        return None;
    }
    let width: u32 = match bits(word, 30, 2) {
        0 => 4,
        1 => 8,
        2 => 16,
        _ => return None,
    };
    let is_load: bool = bit(word, 22);
    if mnemonic != if is_load { "ldp" } else { "stp" } {
        return None;
    }
    let rn: u32 = bits(word, 5, 5);
    let rt: u32 = bits(word, 0, 5);
    let rt2: u32 = bits(word, 10, 5);
    let displacement: i64 = signed_bits(word, 15, 7).checked_mul(i64::from(width))?;
    let base: Varnode = gpr_input(spec, rn, 8, true)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let mut post_index_offset: Option<i64> = None;
    let pointer: Varnode = match bits(word, 23, 2) {
        0b01 => {
            post_index_offset = Some(displacement);
            base
        }
        0b10 => add_signed_offset(base, displacement, allocator, &mut ops)?,
        0b11 => {
            let updated: Varnode = add_signed_offset(base, displacement, allocator, &mut ops)?;
            let writeback: Varnode = register_output(spec, rn, 8, true)?;
            ops.push(PcodeOp::Copy {
                output: writeback,
                input: updated,
            });
            updated
        }
        _ => return None,
    };
    let second: Varnode = add_signed_offset(pointer, i64::from(width), allocator, &mut ops)?;
    if is_load {
        lift_scalar_fp_load(spec, rt, width, pointer, allocator, &mut ops)?;
        lift_scalar_fp_load(spec, rt2, width, second, allocator, &mut ops)?;
    } else {
        lift_scalar_fp_store(spec, rt, width, pointer, allocator, &mut ops)?;
        lift_scalar_fp_store(spec, rt2, width, second, allocator, &mut ops)?;
    }
    if let Some(displacement) = post_index_offset {
        let updated: Varnode = add_signed_offset(base, displacement, allocator, &mut ops)?;
        let writeback: Varnode = register_output(spec, rn, 8, true)?;
        ops.push(PcodeOp::Copy {
            output: writeback,
            input: updated,
        });
    }
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_pair(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if word & 0x3a00_0000 != 0x2800_0000 || bit(word, 26) {
        return None;
    }
    let opc: u32 = bits(word, 30, 2);
    let width: u32 = match opc {
        0 => 4,
        2 => 8,
        _ => return None,
    };
    let is_load: bool = mnemonic == "ldp" && bit(word, 22);
    let is_store: bool = mnemonic == "stp" && !bit(word, 22);
    if !is_load && !is_store {
        return None;
    }
    let mode: u32 = bits(word, 23, 2);
    if mode == 0 {
        return None;
    }
    let rn: u32 = bits(word, 5, 5);
    let rt: u32 = bits(word, 0, 5);
    let rt2: u32 = bits(word, 10, 5);
    let raw_offset: i64 = signed_bits(word, 15, 7);
    let offset: i64 = raw_offset.checked_mul(i64::from(width))?;
    let base: Varnode = gpr_input(spec, rn, 8, true)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let pointer: Varnode = if mode == 1 {
        base
    } else {
        add_signed_offset(base, offset, allocator, &mut ops)?
    };
    let second_pointer: Varnode =
        add_signed_offset(pointer, i64::from(width), allocator, &mut ops)?;
    if is_load {
        let first: Destination = destination(spec, rt, width, false, allocator)?;
        let second: Destination = destination(spec, rt2, width, false, allocator)?;
        ops.push(PcodeOp::Load {
            output: first.result,
            space: Space::Ram,
            pointer,
        });
        ops.push(PcodeOp::Load {
            output: second.result,
            space: Space::Ram,
            pointer: second_pointer,
        });
        finish_destination(first, &mut ops);
        finish_destination(second, &mut ops);
    } else {
        let first: Varnode = gpr_input(spec, rt, width, false)?;
        let second: Varnode = gpr_input(spec, rt2, width, false)?;
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer,
            value: first,
        });
        ops.push(PcodeOp::Store {
            space: Space::Ram,
            pointer: second_pointer,
            value: second,
        });
    }
    if matches!(mode, 1 | 3) {
        let writeback: Varnode = register_output(spec, rn, 8, true)?;
        let updated: Varnode = if mode == 1 {
            add_signed_offset(base, offset, allocator, &mut ops)?
        } else {
            pointer
        };
        ops.push(PcodeOp::Copy {
            output: writeback,
            input: updated,
        });
    }
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_multiply(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if word & 0x7fe0_0000 != 0x1b00_0000 {
        return None;
    }
    let width: u32 = if bit(word, 31) { 8 } else { 4 };
    let rn: u32 = bits(word, 5, 5);
    let rm: u32 = bits(word, 16, 5);
    let ra: u32 = bits(word, 10, 5);
    let rd: u32 = bits(word, 0, 5);
    let left: Varnode = gpr_input(spec, rn, width, false)?;
    let right: Varnode = gpr_input(spec, rm, width, false)?;
    let destination: Destination = destination(spec, rd, width, false, allocator)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    if mnemonic == "mul" || ra == 31 {
        ops.push(PcodeOp::IntMult {
            output: destination.result,
            left,
            right,
        });
    } else {
        let product: Varnode = allocator.allocate(width)?;
        let accumulator: Varnode = gpr_input(spec, ra, width, false)?;
        ops.push(PcodeOp::IntMult {
            output: product,
            left,
            right,
        });
        if mnemonic == "msub" || bit(word, 15) {
            ops.push(PcodeOp::IntSub {
                output: destination.result,
                left: accumulator,
                right: product,
            });
        } else {
            ops.push(PcodeOp::IntAdd {
                output: destination.result,
                left: product,
                right: accumulator,
            });
        }
    }
    finish_destination(destination, &mut ops);
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_csel(spec: &SleighSpec, word: u32, allocator: &mut UniqueAllocator) -> Option<Lifted> {
    if word & 0x7fe0_0c00 != 0x1a80_0000 {
        return None;
    }
    let width: u32 = if bit(word, 31) { 8 } else { 4 };
    let rn: u32 = bits(word, 5, 5);
    let rm: u32 = bits(word, 16, 5);
    let rd: u32 = bits(word, 0, 5);
    let cond: u32 = bits(word, 12, 4);
    let when_true: Varnode = gpr_input(spec, rn, width, false)?;
    let when_false: Varnode = gpr_input(spec, rm, width, false)?;
    let destination: Destination = destination(spec, rd, width, false, allocator)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let condition: Varnode = emit_condition(spec, cond, allocator, &mut ops)?;
    let inverted: Varnode = allocator.allocate(1)?;
    let true_mask: Varnode = allocator.allocate(width)?;
    let false_mask: Varnode = allocator.allocate(width)?;
    let true_value: Varnode = allocator.allocate(width)?;
    let false_value: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::BoolNegate {
        output: inverted,
        input: condition,
    });
    ops.push(PcodeOp::IntZext {
        output: true_mask,
        input: condition,
    });
    ops.push(PcodeOp::IntZext {
        output: false_mask,
        input: inverted,
    });
    ops.push(PcodeOp::IntMult {
        output: true_value,
        left: true_mask,
        right: when_true,
    });
    ops.push(PcodeOp::IntMult {
        output: false_value,
        left: false_mask,
        right: when_false,
    });
    ops.push(PcodeOp::IntAdd {
        output: destination.result,
        left: true_value,
        right: false_value,
    });
    finish_destination(destination, &mut ops);
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_control(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    let mut ops: Vec<PcodeOp> = Vec::new();
    if mnemonic == "b" && word & 0x7c00_0000 == 0x1400_0000 {
        let offset: i64 = signed_bits(word, 0, 26).checked_mul(4)?;
        let target: u64 = address.wrapping_add_signed(offset);
        ops.push(PcodeOp::Branch {
            target: ram_address(target),
        });
    } else if mnemonic == "bl" && word & 0xfc00_0000 == 0x9400_0000 {
        let offset: i64 = signed_bits(word, 0, 26).checked_mul(4)?;
        let target: u64 = address.wrapping_add_signed(offset);
        let link: Varnode = named_register(spec, "x30")?;
        let return_address: u64 = address.wrapping_add(4);
        ops.push(PcodeOp::Copy {
            output: link,
            input: constant(return_address, 8),
        });
        ops.push(PcodeOp::Call {
            target: ram_address(target),
        });
    } else if mnemonic.starts_with("b.") && word & 0xff00_0010 == 0x5400_0000 {
        let offset: i64 = signed_bits(word, 5, 19).checked_mul(4)?;
        let target: u64 = address.wrapping_add_signed(offset);
        let condition: Varnode = emit_condition(spec, bits(word, 0, 4), allocator, &mut ops)?;
        ops.push(PcodeOp::CBranch {
            target: ram_address(target),
            condition,
        });
    } else if matches!(mnemonic, "cbz" | "cbnz") && word & 0x7e00_0000 == 0x3400_0000 {
        let width: u32 = if bit(word, 31) { 8 } else { 4 };
        let value: Varnode = gpr_input(spec, bits(word, 0, 5), width, false)?;
        let condition: Varnode = allocator.allocate(1)?;
        let offset: i64 = signed_bits(word, 5, 19).checked_mul(4)?;
        let target: u64 = address.wrapping_add_signed(offset);
        if mnemonic == "cbz" {
            ops.push(PcodeOp::IntEqual {
                output: condition,
                left: value,
                right: constant(0, width),
            });
        } else {
            ops.push(PcodeOp::IntNotEqual {
                output: condition,
                left: value,
                right: constant(0, width),
            });
        }
        ops.push(PcodeOp::CBranch {
            target: ram_address(target),
            condition,
        });
    } else if mnemonic == "br" && word & 0xffff_fc1f == 0xd61f_0000 {
        let target: Varnode = gpr_input(spec, bits(word, 5, 5), 8, false)?;
        ops.push(PcodeOp::BranchIndirect { target });
    } else if mnemonic == "blr" && word & 0xffff_fc1f == 0xd63f_0000 {
        let source_target: Varnode = gpr_input(spec, bits(word, 5, 5), 8, false)?;
        let target: Varnode = allocator.allocate(8)?;
        let link: Varnode = named_register(spec, "x30")?;
        let return_address: u64 = address.wrapping_add(4);
        ops.push(PcodeOp::Copy {
            output: target,
            input: source_target,
        });
        ops.push(PcodeOp::Copy {
            output: link,
            input: constant(return_address, 8),
        });
        ops.push(PcodeOp::CallIndirect { target });
    } else if mnemonic == "ret" && word & 0xffff_fc1f == 0xd65f_0000 {
        let target: Varnode = gpr_input(spec, bits(word, 5, 5), 8, false)?;
        ops.push(PcodeOp::Return {
            target: Some(target),
        });
    } else {
        return None;
    }
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn lift_address(
    spec: &SleighSpec,
    mnemonic: &str,
    word: u32,
    address: u64,
    allocator: &mut UniqueAllocator,
) -> Option<Lifted> {
    if word & 0x1f00_0000 != 0x1000_0000 {
        return None;
    }
    let immlo: u32 = bits(word, 29, 2);
    let immhi: u32 = bits(word, 5, 19);
    let combined: u32 = immhi.checked_shl(2)? | immlo;
    let offset: i64 = sign_extend_u64(u64::from(combined), 21);
    let target: u64 = if mnemonic == "adrp" {
        let page: u64 = address & !0xfff_u64;
        page.wrapping_add_signed(offset.checked_mul(4096)?)
    } else {
        address.wrapping_add_signed(offset)
    };
    let rd: u32 = bits(word, 0, 5);
    let destination: Destination = destination(spec, rd, 8, false, allocator)?;
    let mut ops: Vec<PcodeOp> = vec![PcodeOp::Copy {
        output: destination.result,
        input: constant(target, 8),
    }];
    finish_destination(destination, &mut ops);
    Some(Lifted {
        operands: String::new(),
        ops,
    })
}

fn emit_flags(
    spec: &SleighSpec,
    result: Varnode,
    left: Varnode,
    right: Varnode,
    is_sub: bool,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let zero: Varnode = flag(spec, "ZR")?;
    let negative: Varnode = flag(spec, "NG")?;
    let carry: Varnode = flag(spec, "CY")?;
    let overflow: Varnode = flag(spec, "OV")?;
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
    if is_sub {
        let borrow: Varnode = allocator.allocate(1)?;
        ops.push(PcodeOp::IntLess {
            output: borrow,
            left,
            right,
        });
        ops.push(PcodeOp::BoolNegate {
            output: carry,
            input: borrow,
        });
        ops.push(PcodeOp::IntSignedBorrow {
            output: overflow,
            left,
            right,
        });
    } else {
        ops.push(PcodeOp::IntCarry {
            output: carry,
            left,
            right,
        });
        ops.push(PcodeOp::IntSignedCarry {
            output: overflow,
            left,
            right,
        });
    }
    Some(())
}

fn emit_logic_flags(
    spec: &SleighSpec,
    result: Varnode,
    _allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let zero: Varnode = flag(spec, "ZR")?;
    let negative: Varnode = flag(spec, "NG")?;
    let carry: Varnode = flag(spec, "CY")?;
    let overflow: Varnode = flag(spec, "OV")?;
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
    ops.push(PcodeOp::Copy {
        output: carry,
        input: constant(0, 1),
    });
    ops.push(PcodeOp::Copy {
        output: overflow,
        input: constant(0, 1),
    });
    Some(())
}

fn emit_condition(
    spec: &SleighSpec,
    condition: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let negative: Varnode = flag(spec, "NG")?;
    let zero: Varnode = flag(spec, "ZR")?;
    let carry: Varnode = flag(spec, "CY")?;
    let overflow: Varnode = flag(spec, "OV")?;
    match condition {
        0 => Some(zero),
        1 => bool_not(zero, allocator, ops),
        2 => Some(carry),
        3 => bool_not(carry, allocator, ops),
        4 => Some(negative),
        5 => bool_not(negative, allocator, ops),
        6 => Some(overflow),
        7 => bool_not(overflow, allocator, ops),
        8 => {
            let not_zero: Varnode = bool_not(zero, allocator, ops)?;
            bool_and(carry, not_zero, allocator, ops)
        }
        9 => {
            let not_carry: Varnode = bool_not(carry, allocator, ops)?;
            bool_or(not_carry, zero, allocator, ops)
        }
        10 => bool_equal(negative, overflow, allocator, ops),
        11 => bool_xor(negative, overflow, allocator, ops),
        12 => {
            let not_zero: Varnode = bool_not(zero, allocator, ops)?;
            let equal: Varnode = bool_equal(negative, overflow, allocator, ops)?;
            bool_and(not_zero, equal, allocator, ops)
        }
        13 => {
            let different: Varnode = bool_xor(negative, overflow, allocator, ops)?;
            bool_or(zero, different, allocator, ops)
        }
        14 | 15 => Some(constant(1, 1)),
        _ => None,
    }
}

fn bool_not(
    input: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolNegate { output, input });
    Some(output)
}

fn bool_and(
    left: Varnode,
    right: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolAnd {
        output,
        left,
        right,
    });
    Some(output)
}

fn bool_or(
    left: Varnode,
    right: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolOr {
        output,
        left,
        right,
    });
    Some(output)
}

fn bool_xor(
    left: Varnode,
    right: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolXor {
        output,
        left,
        right,
    });
    Some(output)
}

fn bool_equal(
    left: Varnode,
    right: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntEqual {
        output,
        left,
        right,
    });
    Some(output)
}

fn shift_operand(
    input: Varnode,
    shift_type: u32,
    amount: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    if amount == 0 {
        return Some(input);
    }
    let output: Varnode = allocator.allocate(input.size_bytes)?;
    let amount_node: Varnode = constant(u64::from(amount), 4);
    let operation: PcodeOp = match shift_type {
        0 => PcodeOp::IntLeft {
            output,
            input,
            amount: amount_node,
        },
        1 => PcodeOp::IntRight {
            output,
            input,
            amount: amount_node,
        },
        2 => PcodeOp::IntSignedRight {
            output,
            input,
            amount: amount_node,
        },
        _ => return None,
    };
    ops.push(operation);
    Some(output)
}

fn add_signed_offset(
    base: Varnode,
    offset: i64,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    if offset == 0 {
        return Some(base);
    }
    let output: Varnode = allocator.allocate(base.size_bytes)?;
    let encoded: u64 = u64::from_ne_bytes(offset.to_ne_bytes());
    ops.push(PcodeOp::IntAdd {
        output,
        left: base,
        right: constant(encoded, base.size_bytes),
    });
    Some(output)
}

fn destination(
    spec: &SleighSpec,
    index: u32,
    width: u32,
    sp_allowed: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Destination> {
    if width == 8 {
        let architectural: Option<Varnode> = register_output(spec, index, width, sp_allowed);
        let result: Varnode = architectural.unwrap_or(allocator.allocate(width)?);
        return Some(Destination {
            architectural: None,
            result,
        });
    }
    let result: Varnode = allocator.allocate(width)?;
    let architectural: Option<Varnode> = if index == 31 && !sp_allowed {
        None
    } else {
        register_output(spec, index, 8, sp_allowed)
    };
    Some(Destination {
        architectural,
        result,
    })
}

fn finish_destination(destination: Destination, ops: &mut Vec<PcodeOp>) {
    if let Some(architectural) = destination.architectural {
        ops.push(PcodeOp::IntZext {
            output: architectural,
            input: destination.result,
        });
    }
}

fn gpr_input(spec: &SleighSpec, index: u32, width: u32, sp_allowed: bool) -> Option<Varnode> {
    if index == 31 && !sp_allowed {
        return Some(constant(0, width));
    }
    register_output(spec, index, width, sp_allowed)
}

fn register_output(spec: &SleighSpec, index: u32, width: u32, sp_allowed: bool) -> Option<Varnode> {
    let name: String = if index == 31 && sp_allowed {
        if width == 8 {
            "sp".to_owned()
        } else {
            "wsp".to_owned()
        }
    } else if index < 31 {
        if width == 8 {
            format!("x{index}")
        } else {
            format!("w{index}")
        }
    } else {
        return None;
    };
    named_register(spec, &name)
}

fn flag(spec: &SleighSpec, name: &str) -> Option<Varnode> {
    named_register(spec, name)
}

fn named_register(spec: &SleighSpec, name: &str) -> Option<Varnode> {
    spec.registers
        .iter()
        .find(|register| register.name == name)
        .map(|register| Varnode {
            offset: register.offset,
            size_bytes: register.size_bytes,
            space: Space::Register,
        })
}

impl UniqueAllocator {
    fn allocate(&mut self, size_bytes: u32) -> Option<Varnode> {
        if size_bytes == 0 {
            return None;
        }
        let offset: u64 = self.next;
        let stride: u64 = u64::from(size_bytes).max(8);
        self.next = self.next.checked_add(stride)?;
        Some(Varnode {
            offset,
            size_bytes,
            space: Space::Unique,
        })
    }
}

fn constant(offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset: offset & mask_for_bytes(size_bytes),
        size_bytes,
        space: Space::Constant,
    }
}

const fn ram_address(offset: u64) -> Varnode {
    Varnode {
        offset,
        size_bytes: 8,
        space: Space::Ram,
    }
}

fn mask_for_bytes(size_bytes: u32) -> u64 {
    let bits: u32 = size_bytes.saturating_mul(8);
    if bits >= 64 {
        u64::MAX
    } else {
        1_u64.checked_shl(bits).unwrap_or(0).saturating_sub(1)
    }
}

fn bit(word: u32, position: u32) -> bool {
    word.checked_shr(position).unwrap_or(0) & 1 != 0
}

fn bits(word: u32, low: u32, width: u32) -> u32 {
    let mask: u32 = if width >= 32 {
        u32::MAX
    } else {
        1_u32.checked_shl(width).unwrap_or(0).saturating_sub(1)
    };
    word.checked_shr(low).unwrap_or(0) & mask
}

fn signed_bits(word: u32, low: u32, width: u32) -> i64 {
    sign_extend_u64(u64::from(bits(word, low, width)), width)
}

fn sign_extend_u64(value: u64, width: u32) -> i64 {
    if width == 0 {
        return 0;
    }
    if width >= 64 {
        return i64::from_ne_bytes(value.to_ne_bytes());
    }
    let shift: u32 = 64_u32.saturating_sub(width);
    let shifted: u64 = value.checked_shl(shift).unwrap_or(0);
    i64::from_ne_bytes(shifted.to_ne_bytes()) >> shift
}

fn read_word(bytes: &[u8]) -> Option<u32> {
    let array: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn seed_instruction_context(word: u32, context: &mut ContextState) {
    let immr: u32 = bits(word, 16, 6);
    let imms: u32 = bits(word, 10, 6);
    context.insert("ImmS_LT_ImmR".to_owned(), i64::from(u8::from(imms < immr)));
    context.insert("ImmS_EQ_ImmR".to_owned(), i64::from(u8::from(imms == immr)));
    context.insert(
        "ImmS_LT_ImmR_minus_1".to_owned(),
        i64::from(u8::from(immr > 0 && imms < immr.saturating_sub(1))),
    );
    context.insert("ImmS_ne_1f".to_owned(), i64::from(u8::from(imms != 0x1f)));
    context.insert("ImmS_ne_3f".to_owned(), i64::from(u8::from(imms != 0x3f)));
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}

fn spec_error_block(bytes: &[u8], address: u64, error: &SleighError) -> Vec<PcodeInstr> {
    if bytes.is_empty() {
        return Vec::new();
    }
    vec![PcodeInstr {
        address,
        bytes: bytes.to_vec(),
        length: bytes.len(),
        mnemonic: ".spec_error".to_owned(),
        operands: error.to_string(),
        ops: vec![PcodeOp::CallOther {
            name: "sleigh_spec_error".to_owned(),
            output: None,
            inputs: Vec::new(),
        }],
        status: DecodeStatus::SpecError,
    }]
}
