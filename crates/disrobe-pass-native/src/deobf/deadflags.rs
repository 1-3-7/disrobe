use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, RflagsBits, UsedRegister,
};

const MAX_BLOCK_INSNS: usize = 4096;
const FLAG_BITS: u32 = RflagsBits::OF
    | RflagsBits::SF
    | RflagsBits::ZF
    | RflagsBits::AF
    | RflagsBits::CF
    | RflagsBits::PF;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeadFlagReport {
    pub block_address: u64,
    pub original_insns: u32,
    pub cleaned_insns: u32,
    pub eliminated_flag_writes: u32,
    pub eliminated_addresses: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct DeadFlagOutcome {
    pub report: DeadFlagReport,
    pub cleaned: Vec<Instruction>,
}

#[must_use]
pub fn clean_block(bitness: u32, base: u64, bytes: &[u8]) -> Option<DeadFlagOutcome> {
    clean_block_with_live_out(bitness, base, bytes, FLAG_BITS)
}

#[must_use]
pub fn clean_block_with_live_out(
    bitness: u32,
    base: u64,
    bytes: &[u8],
    flags_live_out: u32,
) -> Option<DeadFlagOutcome> {
    let insns: Vec<Instruction> = decode_all(bitness, base, bytes);
    if insns.is_empty() {
        return None;
    }
    let mut removable: Vec<bool> = vec![false; insns.len()];
    let mut live: u32 = flags_live_out & FLAG_BITS;
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();

    for i in (0..insns.len()).rev() {
        let insn: &Instruction = &insns[i];
        let read: u32 = insn.rflags_read() & FLAG_BITS;
        let modified: u32 = (insn.rflags_modified() | insn.rflags_undefined()) & FLAG_BITS;

        if is_pure_flag_definer(insn, &mut factory)
            && modified != 0
            && read == 0
            && modified & live == 0
        {
            removable[i] = true;
            continue;
        }

        if insn.flow_control() != FlowControl::Next {
            live = FLAG_BITS;
        }
        live &= !modified;
        live |= read;
    }

    let eliminated_addresses: Vec<u64> = insns
        .iter()
        .zip(removable.iter())
        .filter(|(_, drop): &(&Instruction, &bool)| **drop)
        .map(|(insn, _): (&Instruction, &bool)| insn.ip())
        .collect();
    let eliminated_flag_writes: u32 = u32::try_from(eliminated_addresses.len()).unwrap_or(u32::MAX);
    if eliminated_flag_writes == 0 {
        return None;
    }

    let cleaned: Vec<Instruction> = insns
        .iter()
        .zip(removable.iter())
        .filter_map(|(insn, drop): (&Instruction, &bool)| (!*drop).then_some(*insn))
        .collect();

    let report: DeadFlagReport = DeadFlagReport {
        block_address: base,
        original_insns: u32::try_from(insns.len()).unwrap_or(u32::MAX),
        cleaned_insns: u32::try_from(cleaned.len()).unwrap_or(u32::MAX),
        eliminated_flag_writes,
        eliminated_addresses,
    };
    Some(DeadFlagOutcome { report, cleaned })
}

fn is_pure_flag_definer(insn: &Instruction, factory: &mut InstructionInfoFactory) -> bool {
    if !matches!(insn.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
        return false;
    }
    if insn.has_lock_prefix() || insn.flow_control() != FlowControl::Next {
        return false;
    }
    if (0..insn.op_count()).any(|op: u32| insn.op_kind(op) == OpKind::Memory) {
        return false;
    }
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    info.used_memory().is_empty()
        && info.used_registers().iter().all(|r: &UsedRegister| {
            matches!(
                r.access(),
                OpAccess::Read | OpAccess::NoMemAccess | OpAccess::None
            )
        })
}

fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && out.len() < MAX_BLOCK_INSNS {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
