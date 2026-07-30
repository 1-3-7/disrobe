use disrobe_ir::payload::InsnFlow;

use crate::flow_facts::ControlFlow;
use crate::pseudo_c::aarch64::{immediate_field, signed_immediate};

const OPCODE_BRANCH: u32 = 0b110_0011;
const OPCODE_JALR: u32 = 0b110_0111;
const OPCODE_JAL: u32 = 0b110_1111;
const OPCODE_SYSTEM: u32 = 0b111_0011;

const FUNCT12_ECALL: u32 = 0x000;
const FUNCT12_EBREAK: u32 = 0x001;
const FUNCT12_SRET: u32 = 0x102;
const FUNCT12_MRET: u32 = 0x302;

const LINK_REGISTER: u32 = 1;
const ALTERNATE_LINK_REGISTER: u32 = 5;

const COMPRESSED_QUADRANT_ONE: u32 = 0b01;
const COMPRESSED_QUADRANT_TWO: u32 = 0b10;

const fn is_link(register: u32) -> bool {
    register == LINK_REGISTER || register == ALTERNATE_LINK_REGISTER
}

fn jal_offset(word: u32) -> i64 {
    let raw: u32 = (immediate_field(word, 31, 1) << 20)
        | (immediate_field(word, 12, 8) << 12)
        | (immediate_field(word, 20, 1) << 11)
        | (immediate_field(word, 21, 10) << 1);
    signed_immediate(raw, 21)
}

fn branch_offset(word: u32) -> i64 {
    let raw: u32 = (immediate_field(word, 31, 1) << 12)
        | (immediate_field(word, 7, 1) << 11)
        | (immediate_field(word, 25, 6) << 5)
        | (immediate_field(word, 8, 4) << 1);
    signed_immediate(raw, 13)
}

fn compressed_jump_offset(half: u32) -> i64 {
    let raw: u32 = (immediate_field(half, 12, 1) << 11)
        | (immediate_field(half, 8, 1) << 10)
        | (immediate_field(half, 9, 2) << 8)
        | (immediate_field(half, 6, 1) << 7)
        | (immediate_field(half, 7, 1) << 6)
        | (immediate_field(half, 2, 1) << 5)
        | (immediate_field(half, 11, 1) << 4)
        | (immediate_field(half, 3, 3) << 1);
    signed_immediate(raw, 12)
}

fn compressed_branch_offset(half: u32) -> i64 {
    let raw: u32 = (immediate_field(half, 12, 1) << 8)
        | (immediate_field(half, 5, 2) << 6)
        | (immediate_field(half, 2, 1) << 5)
        | (immediate_field(half, 10, 2) << 3)
        | (immediate_field(half, 3, 2) << 1);
    signed_immediate(raw, 9)
}

fn relative(address: u64, offset: i64) -> Option<u64> {
    address.checked_add_signed(offset)
}

fn compressed_control_flow(address: u64, half: u32, rv64: bool) -> ControlFlow {
    let funct3: u32 = immediate_field(half, 13, 3);
    match half & 0b11 {
        COMPRESSED_QUADRANT_ONE => match funct3 {
            0b101 => ControlFlow::decoded(
                InsnFlow::UnconditionalBranch,
                relative(address, compressed_jump_offset(half)),
            ),
            0b001 if !rv64 => ControlFlow::decoded(
                InsnFlow::Call,
                relative(address, compressed_jump_offset(half)),
            ),
            0b110 | 0b111 => ControlFlow::decoded(
                InsnFlow::ConditionalBranch,
                relative(address, compressed_branch_offset(half)),
            ),
            _ => ControlFlow::decoded(InsnFlow::Sequential, None),
        },
        COMPRESSED_QUADRANT_TWO if funct3 == 0b100 => {
            let source: u32 = immediate_field(half, 7, 5);
            let second: u32 = immediate_field(half, 2, 5);
            let link_bit: u32 = immediate_field(half, 12, 1);
            match (link_bit, second, source) {
                (0, 0, register) if is_link(register) => {
                    ControlFlow::decoded(InsnFlow::Return, None)
                }
                (0, 0, register) if register != 0 => {
                    ControlFlow::decoded(InsnFlow::IndirectBranch, None)
                }
                (1, 0, register) if register != 0 => {
                    ControlFlow::decoded(InsnFlow::IndirectCall, None)
                }
                _ => ControlFlow::decoded(InsnFlow::Sequential, None),
            }
        }
        _ => ControlFlow::decoded(InsnFlow::Sequential, None),
    }
}

pub(super) fn control_flow(address: u64, raw: &[u8], rv64: bool) -> ControlFlow {
    let Some(low): Option<&[u8; 2]> = raw.first_chunk::<2>() else {
        return ControlFlow::undecodable();
    };
    let half: u32 = u32::from(u16::from_le_bytes(*low));
    if half & 0b11 != 0b11 {
        return compressed_control_flow(address, half, rv64);
    }
    let Some(bytes): Option<&[u8; 4]> = raw.first_chunk::<4>() else {
        return ControlFlow::undecodable();
    };
    let word: u32 = u32::from_le_bytes(*bytes);
    let destination: u32 = immediate_field(word, 7, 5);
    match word & 0x7f {
        OPCODE_JAL if destination == 0 => ControlFlow::decoded(
            InsnFlow::UnconditionalBranch,
            relative(address, jal_offset(word)),
        ),
        OPCODE_JAL => ControlFlow::decoded(InsnFlow::Call, relative(address, jal_offset(word))),
        OPCODE_JALR => {
            let source: u32 = immediate_field(word, 15, 5);
            if destination == 0 && is_link(source) {
                ControlFlow::decoded(InsnFlow::Return, None)
            } else if destination == 0 {
                ControlFlow::decoded(InsnFlow::IndirectBranch, None)
            } else {
                ControlFlow::decoded(InsnFlow::IndirectCall, None)
            }
        }
        OPCODE_BRANCH => ControlFlow::decoded(
            InsnFlow::ConditionalBranch,
            relative(address, branch_offset(word)),
        ),
        OPCODE_SYSTEM => match word >> 20 {
            FUNCT12_ECALL | FUNCT12_EBREAK => ControlFlow::decoded(InsnFlow::Interrupt, None),
            FUNCT12_SRET | FUNCT12_MRET => ControlFlow::decoded(InsnFlow::Return, None),
            _ => ControlFlow::decoded(InsnFlow::Sequential, None),
        },
        _ => ControlFlow::decoded(InsnFlow::Sequential, None),
    }
}
