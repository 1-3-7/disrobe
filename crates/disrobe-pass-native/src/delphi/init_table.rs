use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};
use serde::{Deserialize, Serialize};

use super::image::PeView;

const MAX_STUB_INSTRUCTIONS: usize = 48;
const MAX_STUB_BYTES: usize = 256;
const MAX_UNITS: i32 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiUnitEntry {
    pub init: u64,
    pub finalize: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiInitTable {
    pub va: u64,
    pub unit_table_va: u64,
    pub unit_count: usize,
    pub initialized_units: usize,
    pub finalized_units: usize,
    pub units: Vec<DelphiUnitEntry>,
}

fn entry_stub_addresses(view: &PeView<'_>) -> Vec<u64> {
    let entry_rva: u32 = view.image.entry_point_rva;
    if entry_rva == 0 {
        return Vec::new();
    }
    let Some(off): Option<usize> = view.rva_to_off(entry_rva) else {
        return Vec::new();
    };
    let Some(code): Option<&[u8]> = view
        .bytes
        .get(off..view.bytes.len().min(off + MAX_STUB_BYTES))
    else {
        return Vec::new();
    };
    let bitness: u32 = if view.is_64() { 64 } else { 32 };
    let base: u64 = view.image_base().wrapping_add(u64::from(entry_rva));
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, code, base, DecoderOptions::NONE);

    let mut out: Vec<u64> = Vec::new();
    let mut instruction: Instruction = Instruction::default();
    let mut seen: usize = 0;
    while decoder.can_decode() && seen < MAX_STUB_INSTRUCTIONS {
        decoder.decode_out(&mut instruction);
        seen += 1;
        if instruction.is_invalid() {
            break;
        }
        if instruction.is_ip_rel_memory_operand() {
            out.push(instruction.ip_rel_memory_address());
        }
        for index in 0..instruction.op_count() {
            match instruction.op_kind(index) {
                OpKind::Immediate32 => out.push(u64::from(instruction.immediate32())),
                OpKind::Immediate64 => out.push(instruction.immediate64()),
                OpKind::Memory => {
                    let displacement: u64 = instruction.memory_displacement64();
                    if displacement != 0 {
                        out.push(displacement);
                    }
                }
                _ => {}
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn reads_as_code(view: &PeView<'_>, address: u64) -> bool {
    address == 0 || view.is_executable_va(address)
}

fn parse_at(view: &PeView<'_>, table_va: u64, pointer_offset: usize) -> Option<DelphiInitTable> {
    let ptr: usize = view.ptr_size();
    let header_off: usize = view.va_to_off(table_va)?;
    let unit_count: i32 = view.read_i32(header_off)?;
    if unit_count <= 0 || unit_count > MAX_UNITS {
        return None;
    }
    let unit_table_va: u64 = view.read_ptr(header_off.checked_add(pointer_offset)?)?;
    if unit_table_va == 0 {
        return None;
    }
    let mut entry_off: usize = view.va_to_off(unit_table_va)?;

    let mut units: Vec<DelphiUnitEntry> = Vec::with_capacity(unit_count as usize);
    let mut initialized_units: usize = 0;
    let mut finalized_units: usize = 0;
    for _ in 0..unit_count {
        let init: u64 = view.read_ptr(entry_off)?;
        let finalize: u64 = view.read_ptr(entry_off.checked_add(ptr)?)?;
        if !reads_as_code(view, init) || !reads_as_code(view, finalize) {
            return None;
        }
        if init != 0 {
            initialized_units += 1;
        }
        if finalize != 0 {
            finalized_units += 1;
        }
        units.push(DelphiUnitEntry { init, finalize });
        entry_off = entry_off.checked_add(ptr.checked_mul(2)?)?;
    }
    if initialized_units == 0 && finalized_units == 0 {
        return None;
    }

    Some(DelphiInitTable {
        va: table_va,
        unit_table_va,
        unit_count: unit_count as usize,
        initialized_units,
        finalized_units,
        units,
    })
}

fn parse(view: &PeView<'_>, table_va: u64) -> Option<DelphiInitTable> {
    let packed: usize = 4;
    let aligned: usize = view.ptr_size();
    let mut candidate: Option<DelphiInitTable> = parse_at(view, table_va, packed);
    if candidate.is_none() && aligned != packed {
        candidate = parse_at(view, table_va, aligned);
    }
    candidate
}

pub(super) fn recover(view: &PeView<'_>) -> Option<DelphiInitTable> {
    entry_stub_addresses(view)
        .into_iter()
        .find_map(|address: u64| parse(view, address))
}
