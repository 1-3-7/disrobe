use disrobe_ir::payload::InsnFlow;

use crate::flow_facts::ControlFlow;
use crate::pseudo_c::aarch64::{immediate_field, signed_immediate};

const BC: u32 = 16;
const SC: u32 = 17;
const B: u32 = 18;
const BRANCH_REGISTER: u32 = 19;

const XO_BCLR: u32 = 16;
const XO_BCCTR: u32 = 528;
const XO_BCTAR: u32 = 560;

const BO_ALWAYS_MASK: u32 = 0b1_0100;

const fn absolute(word: u32) -> bool {
    word & 0b10 != 0
}

const fn links(word: u32) -> bool {
    word & 0b1 != 0
}

fn branch_always(word: u32) -> bool {
    immediate_field(word, 21, 5) & BO_ALWAYS_MASK == BO_ALWAYS_MASK
}

fn relative_target(address: u64, word: u32, width: u8) -> Option<u64> {
    let delta: i64 = signed_immediate(immediate_field(word, 2, width), width).checked_mul(4)?;
    if absolute(word) {
        return Some(delta.cast_unsigned());
    }
    address.checked_add_signed(delta)
}

pub(super) fn control_flow(address: u64, word: u32) -> ControlFlow {
    match word >> 26 {
        B => {
            let target: Option<u64> = relative_target(address, word, 24);
            if links(word) {
                ControlFlow::decoded(InsnFlow::Call, target)
            } else {
                ControlFlow::decoded(InsnFlow::UnconditionalBranch, target)
            }
        }
        BC => {
            let target: Option<u64> = relative_target(address, word, 14);
            if links(word) {
                ControlFlow::decoded(InsnFlow::Call, target)
            } else if branch_always(word) {
                ControlFlow::decoded(InsnFlow::UnconditionalBranch, target)
            } else {
                ControlFlow::decoded(InsnFlow::ConditionalBranch, target)
            }
        }
        BRANCH_REGISTER => match immediate_field(word, 1, 10) {
            XO_BCLR if links(word) => ControlFlow::decoded(InsnFlow::IndirectCall, None),
            XO_BCLR => ControlFlow::decoded(InsnFlow::Return, None),
            XO_BCCTR | XO_BCTAR if links(word) => {
                ControlFlow::decoded(InsnFlow::IndirectCall, None)
            }
            XO_BCCTR | XO_BCTAR => ControlFlow::decoded(InsnFlow::IndirectBranch, None),
            _ => ControlFlow::decoded(InsnFlow::Sequential, None),
        },
        SC => ControlFlow::decoded(InsnFlow::Interrupt, None),
        _ => ControlFlow::decoded(InsnFlow::Sequential, None),
    }
}
