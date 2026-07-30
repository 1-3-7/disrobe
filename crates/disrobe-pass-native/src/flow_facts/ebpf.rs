use disrobe_ir::payload::InsnFlow;

use crate::flow_facts::ControlFlow;

const INSTRUCTION_BYTES: u64 = 8;

const CLASS_JMP: u8 = 0x05;
const CLASS_JMP32: u8 = 0x06;

const OP_JA: u8 = 0x00;
const OP_CALL: u8 = 0x80;
const OP_EXIT: u8 = 0x90;

const SOURCE_PSEUDO_CALL: u8 = 0x01;

fn relative(address: u64, steps: i64) -> Option<u64> {
    let delta: i64 = steps.checked_mul(i64::try_from(INSTRUCTION_BYTES).ok()?)?;
    address
        .checked_add(INSTRUCTION_BYTES)?
        .checked_add_signed(delta)
}

pub(super) fn control_flow(address: u64, raw: &[u8]) -> ControlFlow {
    let Some(header): Option<&[u8; 8]> = raw.first_chunk::<8>() else {
        return ControlFlow::undecodable();
    };
    let opcode: u8 = header[0];
    let class: u8 = opcode & 0x07;
    if class != CLASS_JMP && class != CLASS_JMP32 {
        return ControlFlow::decoded(InsnFlow::Sequential, None);
    }
    let offset: i64 = i64::from(i16::from_le_bytes([header[2], header[3]]));
    let immediate: i64 = i64::from(i32::from_le_bytes([
        header[4], header[5], header[6], header[7],
    ]));
    match (opcode & 0xf0, class) {
        (OP_JA, CLASS_JMP) => {
            ControlFlow::decoded(InsnFlow::UnconditionalBranch, relative(address, offset))
        }
        (OP_EXIT, CLASS_JMP) => ControlFlow::decoded(InsnFlow::Return, None),
        (OP_CALL, CLASS_JMP) => {
            if header[1] >> 4 == SOURCE_PSEUDO_CALL {
                ControlFlow::decoded(InsnFlow::Call, relative(address, immediate))
            } else {
                ControlFlow::decoded(InsnFlow::IndirectCall, None)
            }
        }
        _ => ControlFlow::decoded(InsnFlow::ConditionalBranch, relative(address, offset)),
    }
}
