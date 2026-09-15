use std::collections::BTreeMap;

use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

const MAX_BLOCK_INSNS: usize = 4096;
const MAX_TABLE_ENTRIES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TableBaseForm {
    MemoryDisplacement,
    RipRelative,
    LeaRegister,
    MovImmRegister,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JumpTableCase {
    pub index: u64,
    pub target: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JumpTableResolution {
    pub branch_address: u64,
    pub table_base: u64,
    pub entry_scale: u32,
    pub base_form: TableBaseForm,
    pub index_register: String,
    pub cases: Vec<JumpTableCase>,
}

#[derive(Debug, Clone, Copy)]
struct IndirectBranch {
    index_reg: Register,
    scale: u32,
    static_disp: u64,
}

#[must_use]
pub fn resolve_block(
    bitness: u32,
    base: u64,
    bytes: &[u8],
    image_base: u64,
    image: &[u8],
) -> Option<JumpTableResolution> {
    let insns: Vec<Instruction> = decode_all(bitness, base, bytes);
    let branch: &Instruction = insns
        .last()
        .filter(|i: &&Instruction| i.flow_control() == FlowControl::IndirectBranch)?;
    let body: &[Instruction] = &insns[..insns.len().checked_sub(1)?];

    let Some(memory): Option<IndirectBranch> = classify_indirect(branch) else {
        return resolve_pic_rel32(branch, body, image_base, image);
    };

    let (table_base, base_form): (u64, TableBaseForm) = locate_table_base(branch, body, &memory)?;
    let index_bound: Option<u64> = index_upper_bound(body, full_register(memory.index_reg));
    let cases: Vec<JumpTableCase> = read_table(
        image_base,
        image,
        table_base,
        memory.scale,
        branch.ip(),
        index_bound,
    )?;
    if cases.len() < 2 {
        return None;
    }

    Some(JumpTableResolution {
        branch_address: branch.ip(),
        table_base,
        entry_scale: memory.scale,
        base_form,
        index_register: format!("{:?}", full_register(memory.index_reg)),
        cases,
    })
}

fn resolve_pic_rel32(
    branch: &Instruction,
    body: &[Instruction],
    image_base: u64,
    image: &[u8],
) -> Option<JumpTableResolution> {
    if branch.op0_kind() != OpKind::Register {
        return None;
    }
    let target_full: Register = full_register(branch.op0_register());

    let add: &Instruction = body.iter().rev().find(|insn: &&Instruction| {
        insn.mnemonic() == Mnemonic::Add
            && insn.op0_kind() == OpKind::Register
            && full_register(insn.op0_register()) == target_full
            && insn.op1_kind() == OpKind::Register
    })?;
    let table_reg_full: Register = full_register(add.op1_register());
    let add_position: usize = body
        .iter()
        .position(|insn: &Instruction| insn.ip() == add.ip())?;

    let load: &Instruction = body[..add_position]
        .iter()
        .rev()
        .find(|insn: &&Instruction| {
            matches!(insn.mnemonic(), Mnemonic::Movsxd | Mnemonic::Mov)
                && insn.op0_kind() == OpKind::Register
                && full_register(insn.op0_register()) == target_full
                && insn.op1_kind() == OpKind::Memory
        })?;
    if full_register(load.memory_base()) != table_reg_full {
        return None;
    }
    let index_reg: Register = load.memory_index();
    if index_reg == Register::None {
        return None;
    }
    let scale: u32 = load.memory_index_scale();
    if scale != 4 {
        return None;
    }
    let load_position: usize = body
        .iter()
        .position(|insn: &Instruction| insn.ip() == load.ip())?;

    let lea: &Instruction = body[..load_position]
        .iter()
        .rev()
        .find(|insn: &&Instruction| {
            insn.mnemonic() == Mnemonic::Lea
                && insn.op0_kind() == OpKind::Register
                && full_register(insn.op0_register()) == table_reg_full
                && insn.op1_kind() == OpKind::Memory
                && insn.memory_index() == Register::None
                && (insn.memory_base() == Register::None || insn.is_ip_rel_memory_operand())
        })?;
    let table_base: u64 = lea
        .memory_displacement64()
        .wrapping_add(load.memory_displacement64());

    let index_bound: Option<u64> = index_upper_bound(body, full_register(index_reg));
    let cases: Vec<JumpTableCase> =
        read_pic_table(image_base, image, table_base, branch.ip(), index_bound)?;
    if cases.len() < 2 {
        return None;
    }
    Some(JumpTableResolution {
        branch_address: branch.ip(),
        table_base,
        entry_scale: scale,
        base_form: TableBaseForm::LeaRegister,
        index_register: format!("{:?}", full_register(index_reg)),
        cases,
    })
}

fn read_pic_table(
    image_base: u64,
    image: &[u8],
    table_base: u64,
    branch_ip: u64,
    index_bound: Option<u64>,
) -> Option<Vec<JumpTableCase>> {
    let entry_cap: u64 = index_bound.map_or(MAX_TABLE_ENTRIES, |n: u64| n.min(MAX_TABLE_ENTRIES));
    let mut cases: Vec<JumpTableCase> = Vec::new();
    let mut index: u64 = 0;
    while index < entry_cap {
        let entry_addr: u64 = table_base.saturating_add(index.wrapping_mul(4));
        let Some(offset): Option<u64> = entry_addr.checked_sub(image_base) else {
            break;
        };
        let offset: usize = usize::try_from(offset).ok()?;
        let Some(raw): Option<[u8; 4]> = image
            .get(offset..offset + 4)
            .and_then(|slice: &[u8]| slice.try_into().ok())
        else {
            break;
        };
        let delta: i64 = i64::from(i32::from_le_bytes(raw));
        let target: u64 = table_base.wrapping_add(delta.cast_unsigned());
        if !plausible_target(target, image_base, image.len(), branch_ip) {
            break;
        }
        cases.push(JumpTableCase { index, target });
        index += 1;
    }
    (!cases.is_empty()).then_some(cases)
}

fn classify_indirect(branch: &Instruction) -> Option<IndirectBranch> {
    if branch.op0_kind() != OpKind::Memory {
        return None;
    }
    let index_reg: Register = branch.memory_index();
    if index_reg == Register::None {
        return None;
    }
    let scale: u32 = branch.memory_index_scale();
    if scale != 4 && scale != 8 {
        return None;
    }
    Some(IndirectBranch {
        index_reg,
        scale,
        static_disp: branch.memory_displacement64(),
    })
}

fn locate_table_base(
    branch: &Instruction,
    body: &[Instruction],
    memory: &IndirectBranch,
) -> Option<(u64, TableBaseForm)> {
    let base_reg: Register = branch.memory_base();
    if base_reg == Register::None {
        return Some((memory.static_disp, TableBaseForm::MemoryDisplacement));
    }
    if branch.is_ip_rel_memory_operand() {
        return Some((memory.static_disp, TableBaseForm::RipRelative));
    }
    let base_full: Register = full_register(base_reg);
    let definition: &Instruction = last_full_definition(body, base_full)?;
    match definition.mnemonic() {
        Mnemonic::Lea if definition.op1_kind() == OpKind::Memory => {
            if definition.memory_index() != Register::None {
                return None;
            }
            let base_is_static: bool =
                definition.memory_base() == Register::None || definition.is_ip_rel_memory_operand();
            if !base_is_static {
                return None;
            }
            Some((
                definition
                    .memory_displacement64()
                    .wrapping_add(memory.static_disp),
                TableBaseForm::LeaRegister,
            ))
        }
        Mnemonic::Mov => {
            let immediate: u64 = mov_immediate(definition)?;
            Some((
                immediate.wrapping_add(memory.static_disp),
                TableBaseForm::MovImmRegister,
            ))
        }
        _ => None,
    }
}

fn last_full_definition(body: &[Instruction], target_full: Register) -> Option<&Instruction> {
    let mut found: Option<&Instruction> = None;
    for insn in body {
        if writes_other_full(insn, target_full) {
            return None;
        }
        if defines_full(insn, target_full) {
            found = Some(insn);
        }
    }
    found
}

fn defines_full(insn: &Instruction, target_full: Register) -> bool {
    insn.op0_kind() == OpKind::Register
        && is_general_purpose(insn.op0_register())
        && is_full_width(insn.op0_register())
        && full_register(insn.op0_register()) == target_full
}

fn writes_other_full(insn: &Instruction, target_full: Register) -> bool {
    insn.memory_base() != Register::None
        && full_register(insn.memory_base()) == target_full
        && insn.op0_kind() == OpKind::Memory
        && writes_memory_via_base(insn)
}

fn writes_memory_via_base(insn: &Instruction) -> bool {
    matches!(
        insn.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::Or
            | Mnemonic::And
    ) && insn.op0_kind() == OpKind::Memory
}

fn mov_immediate(insn: &Instruction) -> Option<u64> {
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

fn index_upper_bound(body: &[Instruction], index_full: Register) -> Option<u64> {
    let mut bound: Option<u64> = None;
    for (position, insn) in body.iter().enumerate() {
        if insn.mnemonic() != Mnemonic::Cmp {
            continue;
        }
        if insn.op0_kind() != OpKind::Register {
            continue;
        }
        if full_register(insn.op0_register()) != index_full {
            continue;
        }
        let Some(limit): Option<u64> = compare_immediate(insn) else {
            continue;
        };
        let Some(next): Option<&Instruction> = body.get(position + 1) else {
            continue;
        };
        if next.flow_control() != FlowControl::ConditionalBranch {
            continue;
        }
        let count: Option<u64> = match next.condition_code() {
            ConditionCode::a | ConditionCode::g => Some(limit.saturating_add(1)),
            ConditionCode::ae | ConditionCode::ge => Some(limit),
            _ => None,
        };
        if count.is_some() {
            bound = count;
        }
    }
    bound
}

fn compare_immediate(insn: &Instruction) -> Option<u64> {
    match insn.op1_kind() {
        OpKind::Immediate8 => Some(u64::from(insn.immediate8())),
        OpKind::Immediate16 => Some(u64::from(insn.immediate16())),
        OpKind::Immediate32 => Some(u64::from(insn.immediate32())),
        OpKind::Immediate8to16 => Some(u64::from(insn.immediate8to16().cast_unsigned())),
        OpKind::Immediate8to32 => Some(u64::from(insn.immediate8to32().cast_unsigned())),
        OpKind::Immediate8to64 => Some(insn.immediate8to64().cast_unsigned()),
        OpKind::Immediate32to64 => Some(insn.immediate32to64().cast_unsigned()),
        _ => None,
    }
}

fn read_table(
    image_base: u64,
    image: &[u8],
    table_base: u64,
    scale: u32,
    branch_ip: u64,
    index_bound: Option<u64>,
) -> Option<Vec<JumpTableCase>> {
    let entry_cap: u64 = index_bound.map_or(MAX_TABLE_ENTRIES, |n: u64| n.min(MAX_TABLE_ENTRIES));
    let mut seen: BTreeMap<u64, u64> = BTreeMap::new();
    let mut index: u64 = 0;
    while index < entry_cap {
        let entry_addr: u64 = table_base.saturating_add(index.wrapping_mul(u64::from(scale)));
        let Some(offset): Option<u64> = entry_addr.checked_sub(image_base) else {
            break;
        };
        let offset: usize = usize::try_from(offset).ok()?;
        let target: Option<u64> = match scale {
            8 => image
                .get(offset..offset + 8)
                .and_then(|raw: &[u8]| raw.try_into().ok())
                .map(u64::from_le_bytes),
            _ => image
                .get(offset..offset + 4)
                .and_then(|raw: &[u8]| raw.try_into().ok())
                .map(|b: [u8; 4]| u64::from(u32::from_le_bytes(b))),
        };
        let Some(target): Option<u64> = target else {
            break;
        };
        if !plausible_target(target, image_base, image.len(), branch_ip) {
            break;
        }
        seen.insert(index, target);
        index += 1;
    }
    (!seen.is_empty()).then(|| {
        seen.into_iter()
            .map(|(index, target): (u64, u64)| JumpTableCase { index, target })
            .collect()
    })
}

fn plausible_target(target: u64, image_base: u64, image_len: usize, branch_ip: u64) -> bool {
    let end: u64 = image_base.saturating_add(image_len as u64);
    if target < image_base || target >= end {
        return false;
    }
    let distance: u64 = target.abs_diff(branch_ip);
    distance <= 0x10_0000
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
