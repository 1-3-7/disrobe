use std::collections::BTreeSet;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

use crate::arch::{DisasmInsn, decode_one_x86};

use super::{MemRef, Width, parse_addr_terms, parse_branch_target};

const SLOT_BYTES: i64 = 8;

fn vector_number(register: Register) -> Option<u32> {
    (register.is_xmm() || register.is_ymm())
        .then(|| u32::try_from(register.number()).ok())
        .flatten()
        .filter(|number: &u32| *number < 16)
}

fn zeroing_idiom(decoded: &Instruction) -> Option<u32> {
    let (dest, first, second): (Register, Register, Register) = match decoded.mnemonic() {
        Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor => (
            decoded.op0_register(),
            decoded.op0_register(),
            decoded.op1_register(),
        ),
        Mnemonic::Vxorps | Mnemonic::Vxorpd | Mnemonic::Vpxor => (
            decoded.op0_register(),
            decoded.op1_register(),
            decoded.op2_register(),
        ),
        _ => return None,
    };
    (first == second && first != Register::None)
        .then(|| vector_number(dest))
        .flatten()
}

pub(super) fn zeroed_vectors_before(insns: &[DisasmInsn]) -> Vec<u16> {
    let targets: BTreeSet<u64> = insns
        .iter()
        .filter_map(|insn: &DisasmInsn| parse_branch_target(&insn.operands))
        .collect();
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut zeroed: u16 = 0;
    let mut before: Vec<u16> = Vec::with_capacity(insns.len());
    for insn in insns {
        if targets.contains(&insn.address) {
            zeroed = 0;
        }
        before.push(zeroed);
        let Some(decoded): Option<Instruction> = decode_one_x86(64, insn.address, &insn.bytes)
        else {
            zeroed = 0;
            continue;
        };
        if !matches!(decoded.flow_control(), FlowControl::Next) {
            zeroed = 0;
            continue;
        }
        let idiom: Option<u32> = zeroing_idiom(&decoded);
        for used in factory.info(&decoded).used_registers() {
            if super::instruction_access_writes(used.access())
                && let Some(number) = vector_number(used.register().full_register())
                    .or_else(|| vector_number(used.register()))
            {
                zeroed &= !(1_u16 << number);
            }
        }
        if let Some(number) = idiom {
            zeroed |= 1_u16 << number;
        }
    }
    before
}

pub(super) fn zero_store_slots(insn: &DisasmInsn, zeroed: u16) -> Option<Vec<MemRef>> {
    let decoded: Instruction = decode_one_x86(64, insn.address, &insn.bytes)?;
    if !matches!(
        decoded.mnemonic(),
        Mnemonic::Movups
            | Mnemonic::Movaps
            | Mnemonic::Movdqu
            | Mnemonic::Movdqa
            | Mnemonic::Vmovups
            | Mnemonic::Vmovaps
            | Mnemonic::Vmovdqu
            | Mnemonic::Vmovdqa
    ) || decoded.op_count() != 2
        || decoded.op0_kind() != OpKind::Memory
        || decoded.op1_kind() != OpKind::Register
    {
        return None;
    }
    let source: Register = decoded.op1_register();
    let number: u32 = vector_number(source)?;
    if zeroed & (1_u16 << number) == 0 {
        return None;
    }
    let bytes: i64 = if source.is_ymm() { 32 } else { 16 };
    let (destination, _): (&str, &str) = insn.operands.split_once(',')?;
    let open: usize = destination.find('[')?;
    let close: usize = destination.rfind(']')?;
    let (base, index, disp): super::AddrTerms = parse_addr_terms(destination.get(open..=close)?)?;
    if base.is_none() && index.is_none() {
        return None;
    }
    (0..bytes / SLOT_BYTES)
        .map(|slot: i64| {
            Some(MemRef {
                base,
                index,
                disp: disp.checked_add(slot.checked_mul(SLOT_BYTES)?)?,
                width: Width::W64,
            })
        })
        .collect()
}
