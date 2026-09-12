use disrobe_ir::payload::InsnFlow;

use crate::flow_facts::ControlFlow;
use crate::pseudo_c::aarch64::{immediate_field, signed_immediate};

const SPECIAL: u32 = 0x00;
const REGIMM: u32 = 0x01;
const J: u32 = 0x02;
const JAL: u32 = 0x03;
const BEQ: u32 = 0x04;
const BNE: u32 = 0x05;
const BLEZ: u32 = 0x06;
const BGTZ: u32 = 0x07;
const COP1: u32 = 0x11;
const BEQL: u32 = 0x14;
const BNEL: u32 = 0x15;
const BLEZL: u32 = 0x16;
const BGTZL: u32 = 0x17;

const SPECIAL_JR: u32 = 0x08;
const SPECIAL_JALR: u32 = 0x09;
const SPECIAL_SYSCALL: u32 = 0x0C;
const SPECIAL_BREAK: u32 = 0x0D;

const COP1_BC: u32 = 0x08;

const REGIMM_BLTZAL: u32 = 0x10;
const REGIMM_BGEZAL: u32 = 0x11;
const REGIMM_BLTZALL: u32 = 0x12;
const REGIMM_BGEZALL: u32 = 0x13;

const RETURN_ADDRESS_REGISTER: u32 = 31;

fn branch_target(address: u64, word: u32) -> Option<u64> {
    let delta: i64 = signed_immediate(immediate_field(word, 0, 16), 16).checked_mul(4)?;
    address.checked_add(4)?.checked_add_signed(delta)
}

fn jump_target(address: u64, word: u32) -> Option<u64> {
    let region: u64 = address.checked_add(4)? & 0xffff_ffff_f000_0000;
    Some(region | (u64::from(immediate_field(word, 0, 26)) << 2))
}

pub(super) fn control_flow(address: u64, word: u32) -> ControlFlow {
    let primary: u32 = word >> 26;
    match primary {
        SPECIAL => {
            let funct: u32 = word & 0x3f;
            let source: u32 = immediate_field(word, 21, 5);
            match funct {
                SPECIAL_JR if source == RETURN_ADDRESS_REGISTER => {
                    ControlFlow::decoded(InsnFlow::Return, None)
                }
                SPECIAL_JR => ControlFlow::decoded(InsnFlow::IndirectBranch, None),
                SPECIAL_JALR => ControlFlow::decoded(InsnFlow::IndirectCall, None),
                SPECIAL_SYSCALL | SPECIAL_BREAK => ControlFlow::decoded(InsnFlow::Interrupt, None),
                _ => ControlFlow::decoded(InsnFlow::Sequential, None),
            }
        }
        REGIMM => {
            let selector: u32 = immediate_field(word, 16, 5);
            let target: Option<u64> = branch_target(address, word);
            match selector {
                REGIMM_BLTZAL | REGIMM_BGEZAL | REGIMM_BLTZALL | REGIMM_BGEZALL => {
                    ControlFlow::decoded(InsnFlow::Call, target)
                }
                _ => ControlFlow::decoded(InsnFlow::ConditionalBranch, target),
            }
        }
        J => ControlFlow::decoded(InsnFlow::UnconditionalBranch, jump_target(address, word)),
        JAL => ControlFlow::decoded(InsnFlow::Call, jump_target(address, word)),
        BEQ | BNE | BLEZ | BGTZ | BEQL | BNEL | BLEZL | BGTZL => {
            ControlFlow::decoded(InsnFlow::ConditionalBranch, branch_target(address, word))
        }
        COP1 if immediate_field(word, 21, 5) == COP1_BC => {
            ControlFlow::decoded(InsnFlow::ConditionalBranch, branch_target(address, word))
        }
        _ => ControlFlow::decoded(InsnFlow::Sequential, None),
    }
}
