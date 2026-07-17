use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};

use crate::elf::{RelocSource, analyze as analyze_elf_dynamic};

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
        if insn.is_invalid() {
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

fn indirect_jmp_slot(insn: &Instruction) -> Option<u64> {
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
