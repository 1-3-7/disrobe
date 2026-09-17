#![forbid(unsafe_code)]

#[allow(clippy::redundant_pub_crate)]
mod registers;
#[allow(clippy::redundant_pub_crate)]
mod semantics;

use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use iced_x86::{
    Code, Decoder, DecoderError, DecoderOptions, FormatMnemonicOptions, Formatter, Instruction,
    InstructionInfoFactory, NasmFormatter,
};

use crate::registers::{UniqueAllocator, constant};
use crate::semantics::lift_instruction;

pub const MAX_X86_BLOCK_BYTES: usize = 1024 * 1024;
pub const MAX_X86_INSTRUCTIONS: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86PcodeLifter {
    bitness: u32,
    max_bytes: usize,
    max_instructions: usize,
}

impl X86PcodeLifter {
    #[must_use]
    pub const fn new(bitness: u32) -> Self {
        Self {
            bitness,
            max_bytes: MAX_X86_BLOCK_BYTES,
            max_instructions: MAX_X86_INSTRUCTIONS,
        }
    }

    #[must_use]
    pub const fn with_limits(mut self, max_bytes: usize, max_instructions: usize) -> Self {
        self.max_bytes = if max_bytes < MAX_X86_BLOCK_BYTES {
            max_bytes
        } else {
            MAX_X86_BLOCK_BYTES
        };
        self.max_instructions = if max_instructions < MAX_X86_INSTRUCTIONS {
            max_instructions
        } else {
            MAX_X86_INSTRUCTIONS
        };
        self
    }

    #[must_use]
    pub fn decode_block(self, bytes: &[u8], address: u64) -> DecodedBlock {
        if self.bitness != 64 {
            return invalid_bitness_block(bytes, address, self.bitness, self.max_bytes);
        }
        let bounded_length: usize = bytes.len().min(self.max_bytes);
        let bounded: &[u8] = bytes
            .get(..bounded_length)
            .map_or(bytes, |value: &[u8]| value);
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, bounded, address, DecoderOptions::NONE);
        let mut formatter: NasmFormatter = NasmFormatter::new();
        let mut allocator: UniqueAllocator = UniqueAllocator::default();
        let mut information: InstructionInfoFactory = InstructionInfoFactory::new();
        let mut instructions: Vec<PcodeInstr> = Vec::new();
        while decoder.can_decode() && instructions.len() < self.max_instructions {
            let start: usize = decoder.position();
            let mut decoded: Instruction = Instruction::default();
            decoder.decode_out(&mut decoded);
            let end: usize = decoder.position();
            let raw: Vec<u8> = bounded
                .get(start..end)
                .map_or_else(Vec::new, <[u8]>::to_vec);
            if decoded.code() == Code::INVALID {
                instructions.push(invalid_instruction(&decoded, raw, decoder.last_error()));
                continue;
            }
            let mut mnemonic: String = String::new();
            formatter.format_mnemonic_options(
                &decoded,
                &mut mnemonic,
                FormatMnemonicOptions::NO_PREFIXES,
            );
            let mut operands: String = String::new();
            formatter.format_all_operands(&decoded, &mut operands);
            let (status, ops): (DecodeStatus, Vec<PcodeOp>) =
                lift_instruction(&decoded, &mnemonic, &mut allocator, &mut information);
            instructions.push(PcodeInstr {
                address: decoded.ip(),
                bytes: raw,
                length: decoded.len(),
                mnemonic,
                ops,
                operands,
                status,
            });
        }
        let consumed: usize = decoder.position();
        if consumed < bytes.len() {
            instructions.push(limit_instruction(address, consumed, bytes.len()));
        }
        let ordered_ops: Vec<PcodeOp> = instructions
            .iter()
            .flat_map(|instruction: &PcodeInstr| instruction.ops.iter().cloned())
            .collect();
        DecodedBlock {
            consumed,
            instructions,
            ordered_ops,
        }
    }
}

#[must_use]
pub fn decode_block_x86(bytes: &[u8], address: u64, bitness: u32) -> DecodedBlock {
    X86PcodeLifter::new(bitness).decode_block(bytes, address)
}

fn invalid_instruction(decoded: &Instruction, raw: Vec<u8>, error: DecoderError) -> PcodeInstr {
    let truncated: bool = error == DecoderError::NoMoreBytes;
    let name: &str = if truncated {
        "x86_decode_truncated_side_effecting_v1"
    } else {
        "x86_decode_invalid_side_effecting_v1"
    };
    PcodeInstr {
        address: decoded.ip(),
        length: raw.len(),
        mnemonic: if truncated {
            ".byte".to_owned()
        } else {
            ".invalid".to_owned()
        },
        operands: hex_bytes(&raw),
        bytes: raw,
        ops: vec![PcodeOp::CallOther {
            name: name.to_owned(),
            output: None,
            inputs: Vec::new(),
        }],
        status: if truncated {
            DecodeStatus::Truncated
        } else {
            DecodeStatus::NoMatch
        },
    }
}

fn invalid_bitness_block(
    bytes: &[u8],
    address: u64,
    bitness: u32,
    max_bytes: usize,
) -> DecodedBlock {
    let consumed: usize = bytes.len().min(max_bytes);
    let captured: Vec<u8> = bytes.get(..consumed).map_or_else(Vec::new, <[u8]>::to_vec);
    let operation: PcodeOp = PcodeOp::CallOther {
        name: "x86_invalid_bitness_side_effecting_v1".to_owned(),
        output: None,
        inputs: vec![constant(u64::from(bitness), 4)],
    };
    let instruction: PcodeInstr = PcodeInstr {
        address,
        bytes: captured,
        length: consumed,
        mnemonic: ".invalid_bitness".to_owned(),
        operands: bitness.to_string(),
        ops: vec![operation.clone()],
        status: DecodeStatus::SpecError,
    };
    DecodedBlock {
        consumed,
        instructions: vec![instruction],
        ordered_ops: vec![operation],
    }
}

fn limit_instruction(address: u64, consumed: usize, supplied: usize) -> PcodeInstr {
    let instruction_address: u64 = u64::try_from(consumed)
        .ok()
        .map_or(u64::MAX, |offset: u64| address.wrapping_add(offset));
    let remaining: usize = supplied.saturating_sub(consumed);
    let remaining_u64: u64 = u64::try_from(remaining).map_or(u64::MAX, |value: u64| value);
    PcodeInstr {
        address: instruction_address,
        bytes: Vec::new(),
        length: 0,
        mnemonic: ".limit".to_owned(),
        operands: remaining.to_string(),
        ops: vec![PcodeOp::CallOther {
            name: "x86_decode_limit_side_effecting_v1".to_owned(),
            output: None,
            inputs: vec![
                Varnode {
                    offset: instruction_address,
                    size_bytes: 8,
                    space: Space::Ram,
                },
                constant(remaining_u64, 8),
            ],
        }],
        status: DecodeStatus::SpecError,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}
