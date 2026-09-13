use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::read::SymbolIndex;
use object::read::macho::Nlist as _;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};

use crate::elf::{RelocSource, analyze as analyze_elf_dynamic};

const MAX_MACHO_IMPORT_STUBS: usize = 65_536;
const MAX_MACHO_IMPORT_NAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_MACHO_SCANNED_NAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_MACHO_SYMBOL_NAME_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportStub {
    pub stub_address: u64,
    pub slot_address: u64,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TailCallKind {
    ImportThunk,
    FunctionStart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailCall {
    pub site: u64,
    pub target: u64,
    pub kind: TailCallKind,
    pub name: Option<String>,
}

#[must_use]
pub fn resolve_elf_plt_imports(bytes: &[u8]) -> Vec<ImportStub> {
    let Some(report) = analyze_elf_dynamic(bytes) else {
        return Vec::new();
    };
    let mut slot_to_name: BTreeMap<u64, String> = BTreeMap::new();
    for reloc in &report.relocations {
        if reloc.source != RelocSource::JmpRel {
            continue;
        }
        let Some(name): Option<&String> = reloc.symbol_name.as_ref() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        slot_to_name.insert(reloc.offset, name.clone());
    }
    if slot_to_name.is_empty() {
        return Vec::new();
    }

    let Ok(file): Result<object::File<'_>, object::Error> = object::File::parse(bytes) else {
        return Vec::new();
    };
    let bits: u32 = if file.is_64() { 64 } else { 32 };

    let mut out: Vec<ImportStub> = Vec::new();
    for section in file.sections() {
        let is_plt: bool = section
            .name()
            .is_ok_and(|n: &str| n == ".plt" || n.starts_with(".plt"));
        if !is_plt {
            continue;
        }
        let Ok(data): Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        decode_plt_section(bits, section.address(), data, &slot_to_name, &mut out);
    }

    out.sort_by_key(|a: &ImportStub| a.stub_address);
    out.dedup();
    out
}

fn decode_plt_section(
    bits: u32,
    section_addr: u64,
    data: &[u8],
    slot_to_name: &BTreeMap<u64, String>,
    out: &mut Vec<ImportStub>,
) {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, data, section_addr, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut pending_stub: Option<u64> = None;
    while decoder.can_decode() {
        let stub_start: u64 = decoder.ip();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() || insn.mnemonic() == Mnemonic::Nop {
            pending_stub = None;
            continue;
        }
        if pending_stub.is_none() {
            pending_stub = Some(stub_start);
        }
        if let Some(slot) = indirect_jmp_slot(&insn) {
            let stub_address: u64 = pending_stub.take().unwrap_or(stub_start);
            if let Some(name) = slot_to_name.get(&slot) {
                out.push(ImportStub {
                    stub_address,
                    slot_address: slot,
                    name: name.clone(),
                });
            }
            continue;
        }
        if insn.flow_control() == FlowControl::UnconditionalBranch {
            pending_stub = None;
        }
    }
}

pub(crate) fn indirect_jmp_slot(insn: &Instruction) -> Option<u64> {
    if insn.mnemonic() != Mnemonic::Jmp {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if insn.is_ip_rel_memory_operand() {
        return Some(insn.ip_rel_memory_address());
    }
    if insn.memory_base() == Register::None && insn.memory_index() == Register::None {
        return Some(insn.memory_displacement64());
    }
    None
}

#[must_use]
pub fn resolve_pe_iat_imports(bytes: &[u8]) -> Vec<ImportStub> {
    let Ok(pe): Result<goblin::pe::PE<'_>, goblin::error::Error> = goblin::pe::PE::parse(bytes)
    else {
        return Vec::new();
    };
    let image_base: u64 = pe.image_base;
    let mut out: Vec<ImportStub> = Vec::new();
    for import in &pe.imports {
        if import.name.is_empty() {
            continue;
        }
        let slot_address: u64 = image_base.wrapping_add(import.offset as u64);
        out.push(ImportStub {
            stub_address: slot_address,
            slot_address,
            name: import.name.to_string(),
        });
    }
    out.sort_by_key(|a: &ImportStub| a.slot_address);
    out.dedup();
    out
}

#[must_use]
pub fn resolve_macho_stub_imports(bytes: &[u8]) -> Vec<ImportStub> {
    let Ok(file): object::read::Result<object::read::macho::MachOFile64<'_>> =
        object::read::macho::MachOFile64::parse(bytes)
    else {
        return Vec::new();
    };
    let mut indirect_table: Option<(usize, usize)> = None;
    let mut has_symbol_table: bool = false;
    let mut string_table: Option<(usize, usize)> = None;
    let Ok(mut commands) = file.macho_load_commands() else {
        return Vec::new();
    };
    loop {
        let command = match commands.next() {
            Ok(Some(command)) => command,
            Ok(None) => break,
            Err(_) => return Vec::new(),
        };
        let Ok(symtab) = command.symtab() else {
            return Vec::new();
        };
        if let Some(symtab) = symtab {
            if has_symbol_table {
                return Vec::new();
            }
            has_symbol_table = true;
            let Some(string_offset): Option<usize> =
                usize::try_from(symtab.stroff.get(file.endian())).ok()
            else {
                return Vec::new();
            };
            let Some(string_size): Option<usize> =
                usize::try_from(symtab.strsize.get(file.endian())).ok()
            else {
                return Vec::new();
            };
            let Some(string_end): Option<usize> = string_offset.checked_add(string_size) else {
                return Vec::new();
            };
            if string_end > bytes.len() {
                return Vec::new();
            }
            string_table = Some((string_offset, string_end));
        }
        let Ok(dysymtab) = command.dysymtab() else {
            return Vec::new();
        };
        if let Some(dysymtab) = dysymtab {
            if indirect_table.is_some() {
                return Vec::new();
            }
            indirect_table = Some((
                dysymtab.indirectsymoff.get(file.endian()) as usize,
                dysymtab.nindirectsyms.get(file.endian()) as usize,
            ));
        }
    }
    let Some((indirect_offset, indirect_count)) = indirect_table else {
        return Vec::new();
    };
    let Some((string_offset, string_end)) = string_table else {
        return Vec::new();
    };
    let Some(indirect_bytes): Option<usize> = indirect_count.checked_mul(4) else {
        return Vec::new();
    };
    let Some(indirect_end): Option<usize> = indirect_offset.checked_add(indirect_bytes) else {
        return Vec::new();
    };
    let Some(indirect_data): Option<&[u8]> = bytes.get(indirect_offset..indirect_end) else {
        return Vec::new();
    };
    let symbols = file.macho_symbol_table();
    let mut out: Vec<ImportStub> = Vec::new();
    let mut cached_names: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let mut stub_entries: usize = 0;
    let mut name_bytes: usize = 0;
    let mut scanned_name_bytes: usize = 0;
    for section in file.sections() {
        let raw = section.macho_section();
        if raw.flags.get(file.endian()) & object::macho::SECTION_TYPE
            != object::macho::S_SYMBOL_STUBS
        {
            continue;
        }
        let stub_size: usize = raw.reserved2.get(file.endian()) as usize;
        let Ok(stub_data) = section.data() else {
            continue;
        };
        if stub_size == 0 || stub_data.len() % stub_size != 0 {
            continue;
        }
        let indirect_start: usize = raw.reserved1.get(file.endian()) as usize;
        for (position, _) in stub_data.chunks_exact(stub_size).enumerate() {
            let Some(next_entries): Option<usize> = stub_entries.checked_add(1) else {
                return Vec::new();
            };
            if next_entries > MAX_MACHO_IMPORT_STUBS {
                return Vec::new();
            }
            stub_entries = next_entries;
            let Some(indirect_index): Option<usize> = indirect_start.checked_add(position) else {
                break;
            };
            let Some(entry_offset): Option<usize> = indirect_index.checked_mul(4) else {
                break;
            };
            let Some(entry_end): Option<usize> = entry_offset.checked_add(4) else {
                break;
            };
            let Some(entry): Option<&[u8]> = indirect_data.get(entry_offset..entry_end) else {
                break;
            };
            let Ok(entry): Result<[u8; 4], _> = entry.try_into() else {
                break;
            };
            let symbol_index: usize = if file.is_little_endian() {
                u32::from_le_bytes(entry) as usize
            } else {
                u32::from_be_bytes(entry) as usize
            };
            if symbol_index
                & ((object::macho::INDIRECT_SYMBOL_LOCAL | object::macho::INDIRECT_SYMBOL_ABS)
                    as usize)
                != 0
            {
                continue;
            }
            let Some(symbol) = symbols.symbol(SymbolIndex(symbol_index)).ok() else {
                continue;
            };
            if symbol.n_type() & object::macho::N_TYPE != object::macho::N_UNDF
                || symbol.n_type() & object::macho::N_EXT == 0
            {
                continue;
            }
            let name_index: u32 = symbol.n_strx(file.endian());
            if let std::collections::btree_map::Entry::Vacant(entry) =
                cached_names.entry(name_index)
            {
                let name_start: Option<usize> = usize::try_from(name_index)
                    .ok()
                    .and_then(|index: usize| string_offset.checked_add(index));
                let raw_name: Option<&[u8]> = name_start.and_then(|start: usize| {
                    let end: usize = start
                        .checked_add(MAX_MACHO_SYMBOL_NAME_BYTES)
                        .map_or(string_end, |end: usize| end.min(string_end));
                    bytes.get(start..end)
                });
                let resolved: Option<String> = if let Some(raw_name) = raw_name {
                    let remaining: usize = MAX_MACHO_SCANNED_NAME_BYTES - scanned_name_bytes;
                    if remaining == 0 {
                        return Vec::new();
                    }
                    let bounded_name: &[u8] = &raw_name[..raw_name.len().min(remaining)];
                    let nul: Option<usize> = bounded_name.iter().position(|byte: &u8| *byte == 0);
                    scanned_name_bytes += nul.map_or(bounded_name.len(), |index: usize| index + 1);
                    nul.and_then(|nul: usize| core::str::from_utf8(&raw_name[..nul]).ok())
                        .and_then(|name: &str| {
                            let name: &str = name.strip_prefix('_').unwrap_or(name);
                            (!name.is_empty()).then(|| name.to_owned())
                        })
                } else {
                    None
                };
                entry.insert(resolved);
            }
            let Some(name): Option<&String> =
                cached_names.get(&name_index).and_then(Option::as_ref)
            else {
                continue;
            };
            let Some(next_name_bytes): Option<usize> = name_bytes.checked_add(name.len()) else {
                return Vec::new();
            };
            if next_name_bytes > MAX_MACHO_IMPORT_NAME_BYTES {
                return Vec::new();
            }
            let Some(offset): Option<u64> = u64::try_from(position)
                .ok()
                .and_then(|position: u64| u64::try_from(stub_size).ok()?.checked_mul(position))
            else {
                continue;
            };
            let Some(stub_address): Option<u64> = section.address().checked_add(offset) else {
                continue;
            };
            out.push(ImportStub {
                stub_address,
                slot_address: stub_address,
                name: name.to_owned(),
            });
            name_bytes = next_name_bytes;
        }
    }
    let mut unique: BTreeMap<u64, Option<String>> = BTreeMap::new();
    for stub in out {
        match unique.entry(stub.stub_address) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(stub.name));
            }
            std::collections::btree_map::Entry::Occupied(mut entry)
                if entry.get().as_deref() != Some(stub.name.as_str()) =>
            {
                entry.insert(None);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }
    unique
        .into_iter()
        .filter_map(|(stub_address, name): (u64, Option<String>)| {
            name.map(|name: String| ImportStub {
                stub_address,
                slot_address: stub_address,
                name,
            })
        })
        .collect()
}

#[must_use]
pub fn classify_tail_calls(
    bits: u32,
    section_addr: u64,
    code: &[u8],
    function_starts: &BTreeSet<u64>,
    import_stubs: &[ImportStub],
) -> Vec<TailCall> {
    let stub_names: BTreeMap<u64, String> = import_stubs
        .iter()
        .map(|s: &ImportStub| (s.stub_address, s.name.clone()))
        .collect();
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, code, section_addr, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut out: Vec<TailCall> = Vec::new();
    while decoder.can_decode() {
        let site: u64 = decoder.ip();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        if insn.flow_control() != FlowControl::UnconditionalBranch {
            continue;
        }
        if !matches!(
            insn.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            continue;
        }
        let target: u64 = insn.near_branch_target();
        if let Some(name) = stub_names.get(&target) {
            out.push(TailCall {
                site,
                target,
                kind: TailCallKind::ImportThunk,
                name: Some(name.clone()),
            });
            continue;
        }
        if !function_starts.contains(&target) {
            continue;
        }
        if containing_function(function_starts, site) == Some(target) {
            continue;
        }
        out.push(TailCall {
            site,
            target,
            kind: TailCallKind::FunctionStart,
            name: None,
        });
    }
    out
}

fn containing_function(function_starts: &BTreeSet<u64>, site: u64) -> Option<u64> {
    function_starts.range(..=site).next_back().copied()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
