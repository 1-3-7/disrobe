use disrobe_ir::payload::InsnFlow;

use crate::flow_facts::ControlFlow;
use crate::pseudo_c::aarch64::{immediate_field, signed_immediate};

const FORMAT_BRANCH: u32 = 0;
const FORMAT_CALL: u32 = 1;
const FORMAT_MEMORY_OR_ALU: u32 = 2;

const OP2_BPCC: u32 = 1;
const OP2_BICC: u32 = 2;
const OP2_BPR: u32 = 3;
const OP2_FBPFCC: u32 = 5;
const OP2_FBFCC: u32 = 6;
const OP2_CBCCC: u32 = 7;

const OP3_JMPL: u32 = 0x38;
const OP3_RETURN: u32 = 0x39;
const OP3_TRAP: u32 = 0x3a;

const COND_NEVER: u32 = 0;
const COND_ALWAYS: u32 = 8;

const RETURN_ADDRESS_REGISTER: u32 = 15;

fn relative(address: u64, raw: u32, width: u8) -> Option<u64> {
    let delta: i64 = signed_immediate(raw, width).checked_mul(4)?;
    address.checked_add_signed(delta)
}

fn conditional(address: u64, word: u32, raw: u32, width: u8) -> ControlFlow {
    let target: Option<u64> = relative(address, raw, width);
    match immediate_field(word, 25, 4) {
        COND_NEVER => ControlFlow::decoded(InsnFlow::Sequential, None),
        COND_ALWAYS => ControlFlow::decoded(InsnFlow::UnconditionalBranch, target),
        _ => ControlFlow::decoded(InsnFlow::ConditionalBranch, target),
    }
}

pub(super) fn control_flow(address: u64, word: u32) -> ControlFlow {
    match word >> 30 {
        FORMAT_CALL => ControlFlow::decoded(
            InsnFlow::Call,
            relative(address, immediate_field(word, 0, 30), 30),
        ),
        FORMAT_BRANCH => match immediate_field(word, 22, 3) {
            OP2_BICC | OP2_FBFCC | OP2_CBCCC => {
                conditional(address, word, immediate_field(word, 0, 22), 22)
            }
            OP2_BPCC | OP2_FBPFCC => conditional(address, word, immediate_field(word, 0, 19), 19),
            OP2_BPR => ControlFlow::decoded(
                InsnFlow::ConditionalBranch,
                relative(
                    address,
                    (immediate_field(word, 20, 2) << 14) | immediate_field(word, 0, 14),
                    16,
                ),
            ),
            _ => ControlFlow::decoded(InsnFlow::Sequential, None),
        },
        FORMAT_MEMORY_OR_ALU => match immediate_field(word, 19, 6) {
            OP3_JMPL => match immediate_field(word, 25, 5) {
                0 => ControlFlow::decoded(InsnFlow::Return, None),
                RETURN_ADDRESS_REGISTER => ControlFlow::decoded(InsnFlow::IndirectCall, None),
                _ => ControlFlow::decoded(InsnFlow::IndirectBranch, None),
            },
            OP3_RETURN => ControlFlow::decoded(InsnFlow::Return, None),
            OP3_TRAP => ControlFlow::decoded(InsnFlow::Interrupt, None),
            _ => ControlFlow::decoded(InsnFlow::Sequential, None),
        },
        _ => ControlFlow::decoded(InsnFlow::Sequential, None),
    }
}
