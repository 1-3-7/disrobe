use std::collections::BTreeMap;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register, UsedRegister,
};

const MAX_BLOCK_INSNS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CopyPropReport {
    pub original_insns: u32,
    pub cleaned_insns: u32,
    pub propagated_reads: u32,
    pub eliminated_copies: u32,
    pub eliminated_dead_stores: u32,
    pub changed: bool,
}

#[derive(Debug, Clone)]
pub struct CopyPropOutcome {
    pub report: CopyPropReport,
    pub cleaned: Vec<Instruction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopySource {
    Register { full: Register, generation: u64 },
    Immediate(u64),
}

#[derive(Debug, Default)]
struct CopyEnv {
    bindings: BTreeMap<Register, CopySource>,
    generation: BTreeMap<Register, u64>,
    clock: u64,
}

impl CopyEnv {
    fn current_generation(&self, full: Register) -> u64 {
        self.generation.get(&full).copied().unwrap_or(0)
    }

    fn bump(&mut self, full: Register) -> u64 {
        self.clock += 1;
        let next: u64 = self.clock;
        self.generation.insert(full, next);
        next
    }

    fn invalidate(&mut self, full: Register) {
        self.bindings.remove(&full);
        self.bindings.retain(|_, src: &mut CopySource| {
            !matches!(src, CopySource::Register { full: f, .. } if *f == full)
        });
    }

    fn record_register_copy(&mut self, dest_full: Register, src_full: Register) {
        let generation: u64 = self.current_generation(src_full);
        self.bindings.insert(
            dest_full,
            CopySource::Register {
                full: src_full,
                generation,
            },
        );
    }

    fn record_immediate(&mut self, dest_full: Register, value: u64) {
        self.bindings
            .insert(dest_full, CopySource::Immediate(value));
    }

    fn lookup_register(&self, full: Register) -> Option<Register> {
        match self.bindings.get(&full)? {
            CopySource::Register {
                full: src,
                generation,
            } if *generation == self.current_generation(*src) => Some(*src),
            _ => None,
        }
    }
}

#[must_use]
pub fn clean_block(bitness: u32, base: u64, bytes: &[u8]) -> Option<CopyPropOutcome> {
    clean_block_with_live_out(bitness, base, bytes, None)
}

#[must_use]
pub fn clean_block_with_live_out(
    bitness: u32,
    base: u64,
    bytes: &[u8],
    live_out: Option<&[Register]>,
) -> Option<CopyPropOutcome> {
    let insns: Vec<Instruction> = decode_all(bitness, base, bytes);
    if insns.is_empty() {
        return None;
    }
    let body_len: usize = trailing_terminator_index(&insns).unwrap_or(insns.len());
    let body: &[Instruction] = &insns[..body_len];
    let tail: &[Instruction] = &insns[body_len..];

    let live_set: Option<std::collections::BTreeSet<Register>> =
        live_out.map(|regs: &[Register]| {
            regs.iter()
                .copied()
                .filter(|r: &Register| is_general_purpose(*r))
                .map(full_register)
                .collect()
        });

    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut env: CopyEnv = CopyEnv::default();
    let mut rewritten: Vec<Instruction> = Vec::with_capacity(body.len());
    let mut propagated_reads: u32 = 0;

    for insn in body {
        if !is_block_local(insn) {
            return None;
        }
        let mut current: Instruction = *insn;
        propagated_reads += propagate_reads(&mut current, &env, &mut factory);
        update_env(&mut env, &current, &mut factory);
        rewritten.push(current);
    }

    let mut removed_copy: Vec<bool> = vec![false; rewritten.len()];
    let eliminated_copies: u32 = mark_redundant_copies(&rewritten, &mut removed_copy);
    let eliminated_dead_stores: u32 = mark_dead_stores(
        &rewritten,
        &mut removed_copy,
        live_set.as_ref(),
        &mut factory,
    );

    let mut cleaned: Vec<Instruction> = rewritten
        .iter()
        .zip(removed_copy.iter())
        .filter_map(|(insn, drop): (&Instruction, &bool)| (!*drop).then_some(*insn))
        .collect();
    cleaned.extend_from_slice(tail);

    let report: CopyPropReport = CopyPropReport {
        original_insns: u32::try_from(insns.len()).unwrap_or(u32::MAX),
        cleaned_insns: u32::try_from(cleaned.len()).unwrap_or(u32::MAX),
        propagated_reads,
        eliminated_copies,
        eliminated_dead_stores,
        changed: cleaned.len() != insns.len() || propagated_reads != 0,
    };
    Some(CopyPropOutcome { report, cleaned })
}

fn propagate_reads(
    insn: &mut Instruction,
    env: &CopyEnv,
    factory: &mut InstructionInfoFactory,
) -> u32 {
    if insn.flow_control() != FlowControl::Next {
        return 0;
    }
    let dest_written: Option<Register> = full_dest_write(insn, factory);
    let mut count: u32 = 0;
    for operand in 0..insn.op_count() {
        if insn.op_kind(operand) != OpKind::Register {
            continue;
        }
        let used: Register = insn.op_register(operand);
        if !is_general_purpose(used) {
            continue;
        }
        if !operand_is_pure_read(insn, operand, used, dest_written, factory) {
            continue;
        }
        let used_full: Register = full_register(used);
        let Some(src_full): Option<Register> = env.lookup_register(used_full) else {
            continue;
        };
        let Some(replacement): Option<Register> = sized_like(used, src_full) else {
            continue;
        };
        if replacement == used {
            continue;
        }
        insn.set_op_register(operand, replacement);
        count += 1;
    }
    count
}

fn operand_is_pure_read(
    insn: &Instruction,
    operand: u32,
    used: Register,
    dest_written: Option<Register>,
    factory: &mut InstructionInfoFactory,
) -> bool {
    if operand == 0 && dest_written.is_some() {
        return false;
    }
    let used_full: Register = full_register(used);
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    info.used_registers().iter().any(|r: &UsedRegister| {
        full_register(r.register()) == used_full && matches!(r.access(), OpAccess::Read)
    }) && info.used_registers().iter().all(|r: &UsedRegister| {
        full_register(r.register()) != used_full
            || matches!(r.access(), OpAccess::Read | OpAccess::NoMemAccess)
    })
}

fn full_dest_write(insn: &Instruction, factory: &mut InstructionInfoFactory) -> Option<Register> {
    if insn.op_count() == 0 || insn.op0_kind() != OpKind::Register {
        return None;
    }
    let dest: Register = insn.op0_register();
    if !is_general_purpose(dest) {
        return None;
    }
    let dest_full: Register = full_register(dest);
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    let writes: bool = info.used_registers().iter().any(|r: &UsedRegister| {
        full_register(r.register()) == dest_full
            && matches!(r.access(), OpAccess::Write | OpAccess::ReadWrite)
    });
    writes.then_some(dest_full)
}

fn update_env(env: &mut CopyEnv, insn: &Instruction, factory: &mut InstructionInfoFactory) {
    let written: Vec<Register> = {
        let info: &iced_x86::InstructionInfo = factory.info(insn);
        info.used_registers()
            .iter()
            .filter(|r: &&UsedRegister| {
                is_general_purpose(r.register())
                    && matches!(r.access(), OpAccess::Write | OpAccess::ReadWrite)
            })
            .map(|r: &UsedRegister| full_register(r.register()))
            .collect()
    };

    let copy: Option<(Register, CopyDef)> = exact_copy_definition(insn);
    for full in &written {
        env.invalidate(*full);
        env.bump(*full);
    }
    let Some((dest_full, def)): Option<(Register, CopyDef)> = copy else {
        return;
    };
    if written.len() != 1 || written[0] != dest_full {
        return;
    }
    match def {
        CopyDef::Register(src_full) if src_full != dest_full => {
            env.record_register_copy(dest_full, src_full);
        }
        CopyDef::Immediate(value) => env.record_immediate(dest_full, value),
        CopyDef::Register(_) => {}
    }
}

#[derive(Debug, Clone, Copy)]
enum CopyDef {
    Register(Register),
    Immediate(u64),
}

fn exact_copy_definition(insn: &Instruction) -> Option<(Register, CopyDef)> {
    if insn.mnemonic() != Mnemonic::Mov || insn.op0_kind() != OpKind::Register {
        return None;
    }
    let dest: Register = insn.op0_register();
    if !is_general_purpose(dest) || !is_full_width(dest) {
        return None;
    }
    let dest_full: Register = full_register(dest);
    match insn.op1_kind() {
        OpKind::Register => {
            let src: Register = insn.op1_register();
            if !is_general_purpose(src) || src.size() != dest.size() {
                return None;
            }
            Some((dest_full, CopyDef::Register(full_register(src))))
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some((dest_full, CopyDef::Immediate(read_immediate(insn)?))),
        _ => None,
    }
}

fn read_immediate(insn: &Instruction) -> Option<u64> {
    match insn.op1_kind() {
        OpKind::Immediate8 => Some(u64::from(insn.immediate8())),
        OpKind::Immediate16 => Some(u64::from(insn.immediate16())),
        OpKind::Immediate32 => Some(u64::from(insn.immediate32())),
        OpKind::Immediate64 => Some(insn.immediate64()),
        OpKind::Immediate8to16 => Some(insn.immediate8to16().cast_unsigned().into()),
        OpKind::Immediate8to32 => Some(insn.immediate8to32().cast_unsigned().into()),
        OpKind::Immediate8to64 => Some(insn.immediate8to64().cast_unsigned()),
        OpKind::Immediate32to64 => Some(insn.immediate32to64().cast_unsigned()),
        _ => None,
    }
}

fn mark_redundant_copies(insns: &[Instruction], removed: &mut [bool]) -> u32 {
    let mut count: u32 = 0;
    for (i, insn) in insns.iter().enumerate() {
        if removed[i] {
            continue;
        }
        if insn.mnemonic() == Mnemonic::Mov
            && insn.op0_kind() == OpKind::Register
            && insn.op1_kind() == OpKind::Register
            && insn.op0_register() == insn.op1_register()
            && is_general_purpose(insn.op0_register())
            && is_full_width(insn.op0_register())
        {
            removed[i] = true;
            count += 1;
        }
    }
    count
}

fn mark_dead_stores(
    insns: &[Instruction],
    removed: &mut [bool],
    live_set: Option<&std::collections::BTreeSet<Register>>,
    factory: &mut InstructionInfoFactory,
) -> u32 {
    let mut count: u32 = 0;
    for i in 0..insns.len() {
        if removed[i] {
            continue;
        }
        let insn: &Instruction = &insns[i];
        if !is_pure_full_register_def(insn, factory) {
            continue;
        }
        let dest_full: Register = full_register(insn.op0_register());
        if is_dead_after(insns, removed, i, dest_full, live_set, factory) {
            removed[i] = true;
            count += 1;
        }
    }
    count
}

fn is_dead_after(
    insns: &[Instruction],
    removed: &[bool],
    def_index: usize,
    dest_full: Register,
    live_set: Option<&std::collections::BTreeSet<Register>>,
    factory: &mut InstructionInfoFactory,
) -> bool {
    for (j, later) in insns.iter().enumerate().skip(def_index + 1) {
        if removed[j] {
            continue;
        }
        let info: &iced_x86::InstructionInfo = factory.info(later);
        let mut redefined: bool = false;
        for r in info.used_registers() {
            if full_register(r.register()) != dest_full {
                continue;
            }
            match r.access() {
                OpAccess::Read
                | OpAccess::ReadWrite
                | OpAccess::CondRead
                | OpAccess::ReadCondWrite => {
                    return false;
                }
                OpAccess::Write => {
                    if is_full_width(r.register()) {
                        redefined = true;
                    } else {
                        return false;
                    }
                }
                OpAccess::CondWrite => return false,
                OpAccess::None | OpAccess::NoMemAccess => {}
            }
        }
        if uses_register_in_memory(later, dest_full) {
            return false;
        }
        if redefined {
            return true;
        }
    }
    live_set.is_some_and(|set: &std::collections::BTreeSet<Register>| !set.contains(&dest_full))
}

fn uses_register_in_memory(insn: &Instruction, full: Register) -> bool {
    if insn.memory_base() != Register::None && full_register(insn.memory_base()) == full {
        return true;
    }
    insn.memory_index() != Register::None && full_register(insn.memory_index()) == full
}

fn is_pure_full_register_def(insn: &Instruction, factory: &mut InstructionInfoFactory) -> bool {
    if !matches!(
        insn.mnemonic(),
        Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Movzx | Mnemonic::Movsx
    ) {
        return false;
    }
    if insn.op0_kind() != OpKind::Register {
        return false;
    }
    let dest: Register = insn.op0_register();
    if !is_general_purpose(dest) || !is_full_width(dest) {
        return false;
    }
    if reads_memory(insn) {
        return false;
    }
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    if !info.used_memory().is_empty() {
        return false;
    }
    !info
        .used_registers()
        .iter()
        .any(|r: &UsedRegister| matches!(r.access(), OpAccess::CondWrite | OpAccess::ReadCondWrite))
}

fn reads_memory(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|op: u32| insn.op_kind(op) == OpKind::Memory)
}

fn is_block_local(insn: &Instruction) -> bool {
    matches!(insn.flow_control(), FlowControl::Next) && !insn.has_lock_prefix()
}

fn trailing_terminator_index(insns: &[Instruction]) -> Option<usize> {
    let last: usize = insns.len().checked_sub(1)?;
    (insns[last].flow_control() != FlowControl::Next).then_some(last)
}

fn is_general_purpose(reg: Register) -> bool {
    reg.is_gpr() && reg != Register::None
}

fn is_full_width(reg: Register) -> bool {
    reg.is_gpr32() || reg.is_gpr64()
}

fn full_register(reg: Register) -> Register {
    let full: Register = reg.full_register();
    if full == Register::None { reg } else { full }
}

fn sized_like(template: Register, full: Register) -> Option<Register> {
    let sized: Register = match template.size() {
        4 => full.full_register32(),
        8 => full.full_register(),
        _ => return None,
    };
    (sized != Register::None).then_some(sized)
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
