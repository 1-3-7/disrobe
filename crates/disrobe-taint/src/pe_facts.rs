use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use goblin::pe::PE;
use goblin::pe::relocation::IMAGE_REL_BASED_DIR64;
use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};

use crate::callgraph::{CallEdge, CallEdgeEvidence};
use crate::pointers::ConstantPointers;

pub const MAX_CONSTANT_POINTER_SLOTS: usize = 1 << 22;
const MAX_RELOCATION_WORDS: usize = 1 << 22;
const MAX_PE_SECTIONS: usize = 96;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeFacts {
    pub import_call_edges: Vec<CallEdge>,
    pub constant_pointers: ConstantPointers,
}

#[derive(Debug, thiserror::Error)]
pub enum PeFactsError {
    #[error("cannot parse the PE image: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("the PE32+ image has no optional header, so its mapped size is unknown")]
    MissingOptionalHeader,
    #[error("the PE image relocates more than {limit} read-only pointer slots")]
    TooManyConstantPointers { limit: usize },
    #[error("the PE relocation scan exceeds its {limit}-word bound")]
    TooManyRelocationWords { limit: usize },
    #[error("the PE image has more than {limit} sections")]
    TooManySections { limit: usize },
    #[error("PE sections overlap at RVAs {left_rva:#x} and {right_rva:#x}")]
    OverlappingSections { left_rva: u32, right_rva: u32 },
    #[error("the PE section beginning at RVA {rva:#x} has an invalid mapped range")]
    InvalidSectionRange { rva: u32 },
    #[error("the relocated pointer slot at RVA {rva:#x} lies outside the mapped PE image")]
    InvalidPointerSlot { rva: u32 },
}

pub fn pe_facts(bytes: &[u8], module: &NirModule) -> Result<PeFacts, PeFactsError> {
    if !bytes.starts_with(b"MZ") {
        return Ok(PeFacts::default());
    }
    let pe: PE<'_> = PE::parse(bytes)?;
    let imports: BTreeMap<u64, String> = pe
        .imports
        .iter()
        .filter_map(|import| {
            let offset: u64 = u64::try_from(import.offset).ok()?;
            pe.image_base
                .checked_add(offset)
                .map(|address: u64| (address, import.name.to_string()))
        })
        .collect();
    Ok(PeFacts {
        import_call_edges: import_call_edges(module, &imports),
        constant_pointers: constant_pointers(&pe, bytes)?,
    })
}

fn constant_pointers(pe: &PE<'_>, bytes: &[u8]) -> Result<ConstantPointers, PeFactsError> {
    constant_pointers_with_limits(pe, bytes, MAX_RELOCATION_WORDS, MAX_PE_SECTIONS)
}

fn constant_pointers_with_limits(
    pe: &PE<'_>,
    bytes: &[u8],
    relocation_word_limit: usize,
    section_limit: usize,
) -> Result<ConstantPointers, PeFactsError> {
    let mut pointers: ConstantPointers = ConstantPointers::new();
    if !pe.is_64 {
        return Ok(pointers);
    }
    let Some(relocations) = pe.relocation_data.as_ref() else {
        return Ok(pointers);
    };
    let image_end: u64 = pe
        .header
        .optional_header
        .as_ref()
        .map(|header| u64::from(header.windows_fields.size_of_image))
        .and_then(|size: u64| pe.image_base.checked_add(size))
        .ok_or(PeFactsError::MissingOptionalHeader)?;
    let sections: SectionIndex = SectionIndex::new(pe, section_limit)?;
    let mut scanned_words: usize = 0;
    for block in relocations.blocks() {
        let block = block?;
        for word in block.words() {
            scanned_words = scanned_words
                .checked_add(1)
                .filter(|count: &usize| *count <= relocation_word_limit)
                .ok_or(PeFactsError::TooManyRelocationWords {
                    limit: relocation_word_limit,
                })?;
            let word = word?;
            if u16::from(word.reloc_type()) != IMAGE_REL_BASED_DIR64 {
                continue;
            }
            let rva: u32 = block
                .rva
                .checked_add(u32::from(word.offset()))
                .ok_or(PeFactsError::InvalidPointerSlot { rva: block.rva })?;
            let slot: u64 = pe
                .image_base
                .checked_add(u64::from(rva))
                .filter(|slot: &u64| slot.checked_add(8).is_some_and(|end| end <= image_end))
                .ok_or(PeFactsError::InvalidPointerSlot { rva })?;
            let Some(target): Option<u64> = sections.read_only_qword(bytes, rva) else {
                continue;
            };
            if !(pe.image_base..image_end).contains(&target) {
                continue;
            }
            if pointers.len() >= MAX_CONSTANT_POINTER_SLOTS {
                return Err(PeFactsError::TooManyConstantPointers {
                    limit: MAX_CONSTANT_POINTER_SLOTS,
                });
            }
            pointers.insert(slot, target);
        }
    }
    Ok(pointers)
}

#[derive(Debug, Clone, Copy)]
struct IndexedSection {
    rva: u32,
    end: u32,
    raw: u32,
    read_only: bool,
}

#[derive(Debug, Default)]
struct SectionIndex {
    sections: Vec<IndexedSection>,
}

impl SectionIndex {
    fn new(pe: &PE<'_>, section_limit: usize) -> Result<Self, PeFactsError> {
        if pe.sections.len() > section_limit {
            return Err(PeFactsError::TooManySections {
                limit: section_limit,
            });
        }
        let mut sections: Vec<IndexedSection> = Vec::with_capacity(pe.sections.len());
        for section in &pe.sections {
            let size: u32 = section.size_of_raw_data.min(section.virtual_size);
            if size == 0 {
                continue;
            }
            let end: u32 = section.virtual_address.checked_add(size).ok_or(
                PeFactsError::InvalidSectionRange {
                    rva: section.virtual_address,
                },
            )?;
            sections.push(IndexedSection {
                rva: section.virtual_address,
                end,
                raw: section.pointer_to_raw_data,
                read_only: section.characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
                    == 0,
            });
        }
        sections.sort_by_key(|section: &IndexedSection| section.rva);
        for pair in sections.windows(2) {
            let [left, right] = pair else {
                continue;
            };
            if left.end > right.rva {
                return Err(PeFactsError::OverlappingSections {
                    left_rva: left.rva,
                    right_rva: right.rva,
                });
            }
        }
        Ok(Self { sections })
    }

    fn read_only_qword(&self, bytes: &[u8], rva: u32) -> Option<u64> {
        let position: usize = self
            .sections
            .partition_point(|section: &IndexedSection| section.rva <= rva);
        let section: &IndexedSection = self.sections.get(position.checked_sub(1)?)?;
        if !section.read_only {
            return None;
        }
        let within: u32 = rva.checked_sub(section.rva)?;
        if rva.checked_add(8)? > section.end {
            return None;
        }
        let start: usize = usize::try_from(section.raw.checked_add(within)?).ok()?;
        let raw: [u8; 8] = bytes.get(start..start.checked_add(8)?)?.try_into().ok()?;
        Some(u64::from_le_bytes(raw))
    }
}

fn import_call_edges(module: &NirModule, imports: &BTreeMap<u64, String>) -> Vec<CallEdge> {
    let mut edges: Vec<CallEdge> = Vec::new();
    for function in &module.functions {
        let branch_targets: BTreeSet<u64> = function
            .instructions
            .iter()
            .filter_map(|instruction: &NirInstr| instruction.op.direct_target())
            .collect();
        for (index, instruction) in function.instructions.iter().enumerate() {
            if !matches!(instruction.op, NirOp::IndirectCall) {
                continue;
            }
            let Some(slot): Option<u64> = instruction
                .operands
                .iter()
                .find_map(|operand: &String| {
                    operand
                        .trim()
                        .strip_prefix("qword ")
                        .and_then(relative_slot)
                })
                .or_else(|| register_loaded_slot(function, index, &branch_targets))
            else {
                continue;
            };
            let Some(symbol): Option<&String> = imports.get(&slot) else {
                continue;
            };
            edges.push(CallEdge::definite(
                instruction.address,
                slot,
                CallEdgeEvidence::NamedExternal {
                    symbol: symbol.clone(),
                },
            ));
        }
    }
    edges
}

fn register_loaded_slot(
    function: &NirFunction,
    index: usize,
    branch_targets: &BTreeSet<u64>,
) -> Option<u64> {
    let call: &NirInstr = function.instructions.get(index)?;
    let [register]: &[String] = call.operands.as_slice() else {
        return None;
    };
    let loaded: &NirInstr = function.instructions.get(index.checked_sub(1)?)?;
    if branch_targets.contains(&call.address) || !loaded.mnemonic.eq_ignore_ascii_case("mov") {
        return None;
    }
    let [destination, source]: &[String] = loaded.operands.as_slice() else {
        return None;
    };
    if !destination.trim().eq_ignore_ascii_case(register.trim()) {
        return None;
    }
    let source: &str = source.trim();
    relative_slot(source.strip_prefix("qword ").unwrap_or(source))
}

fn relative_slot(operand: &str) -> Option<u64> {
    let inner: &str = operand
        .trim()
        .strip_prefix('[')?
        .strip_suffix(']')?
        .trim()
        .strip_prefix("rel ")?;
    let hex: &str = inner.strip_suffix('h').unwrap_or(inner);
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use disrobe_nir::{NirSymbol, SourceLang, SourceRef, SymbolKind};

    use super::*;

    fn instruction(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands: operands
                .iter()
                .map(|value: &&str| (*value).to_owned())
                .collect(),
            source: SourceRef::new(SourceLang::NativeX86, address),
            ..NirInstr::default()
        }
    }

    fn single_function(instructions: Vec<NirInstr>) -> NirModule {
        NirModule {
            source_hash: [0; 32],
            lang: SourceLang::NativeX86,
            functions: vec![NirFunction {
                name: "entry".to_owned(),
                address: 0x1000,
                end: 0x1010,
                is_export: true,
                instructions,
                source: SourceRef::new(SourceLang::NativeX86, 0x1000),
            }],
            symbols: vec![NirSymbol {
                address: 0x2000,
                name: "system".to_owned(),
                kind: SymbolKind::Import,
            }],
        }
    }

    fn names(edges: &[CallEdge]) -> Vec<(u64, String)> {
        edges
            .iter()
            .flat_map(|edge: &CallEdge| {
                edge.evidence()
                    .iter()
                    .filter_map(move |evidence| match evidence {
                        CallEdgeEvidence::NamedExternal { symbol } => {
                            Some((edge.site, symbol.clone()))
                        }
                        _ => None,
                    })
            })
            .collect()
    }

    #[test]
    fn a_call_through_an_iat_operand_names_the_import() {
        let module: NirModule = single_function(vec![instruction(
            0x1000,
            NirOp::IndirectCall,
            "call",
            &["qword [rel 2000h]"],
        )]);
        let imports: BTreeMap<u64, String> = BTreeMap::from([(0x2000, "system".to_owned())]);
        assert_eq!(
            names(&import_call_edges(&module, &imports)),
            vec![(0x1000, "system".to_owned())]
        );
        let elsewhere: BTreeMap<u64, String> = BTreeMap::from([(0x2008, "system".to_owned())]);
        assert!(import_call_edges(&module, &elsewhere).is_empty());
    }

    fn register_call_module(loaded: &str, entered_by_branch: bool) -> NirModule {
        let mut instructions: Vec<NirInstr> = vec![
            instruction(0x1000, NirOp::Load, "mov", &[loaded, "[rel 2000h]"]),
            instruction(0x1007, NirOp::IndirectCall, "call", &["rax"]),
            instruction(0x1009, NirOp::Return, "ret", &[]),
        ];
        if entered_by_branch {
            instructions.push(instruction(
                0x100a,
                NirOp::Branch {
                    target: Some(0x1007),
                },
                "jmp",
                &["0000000000001007h"],
            ));
        }
        single_function(instructions)
    }

    #[test]
    fn a_register_call_right_after_its_iat_load_names_the_import() {
        let imports: BTreeMap<u64, String> = BTreeMap::from([(0x2000, "recv".to_owned())]);
        assert_eq!(
            names(&import_call_edges(
                &register_call_module("rax", false),
                &imports
            )),
            vec![(0x1007, "recv".to_owned())]
        );
        assert!(
            import_call_edges(&register_call_module("rdx", false), &imports).is_empty(),
            "a load into a different register says nothing about the called register"
        );
        assert!(
            import_call_edges(&register_call_module("rax", true), &imports).is_empty(),
            "a call that another path branches to may see a different register value"
        );
    }

    #[test]
    fn bytes_that_are_not_a_pe_image_carry_no_facts() -> Result<(), PeFactsError> {
        let module: NirModule = single_function(Vec::new());
        assert_eq!(
            pe_facts(b"\xca\xfe\xba\xbe class bytes", &module)?,
            PeFacts::default()
        );
        Ok(())
    }

    #[test]
    fn a_truncated_pe_image_is_a_typed_error() {
        let module: NirModule = single_function(Vec::new());
        assert!(matches!(
            pe_facts(b"MZ\x00\x00", &module),
            Err(PeFactsError::Parse(_))
        ));
    }

    #[test]
    fn relocated_slots_outside_the_declared_image_are_a_typed_error() -> Result<(), PeFactsError> {
        let bytes: &[u8] = include_bytes!("../../../corpus/dotnet/HelloAppAot.exe");
        let mut pe: PE<'_> = PE::parse(bytes)?;
        let _reference: ConstantPointers = constant_pointers(&pe, bytes)?;
        pe.header
            .optional_header
            .as_mut()
            .ok_or(PeFactsError::MissingOptionalHeader)?
            .windows_fields
            .size_of_image = 1;
        assert!(matches!(
            constant_pointers(&pe, bytes),
            Err(PeFactsError::InvalidPointerSlot { .. })
        ));
        Ok(())
    }

    #[test]
    fn relocation_word_limit_refuses_before_scanning_fixture_words() -> Result<(), PeFactsError> {
        let bytes: &[u8] = include_bytes!("../../../corpus/dotnet/HelloAppAot.exe");
        let pe: PE<'_> = PE::parse(bytes)?;
        let reference: ConstantPointers = constant_pointers(&pe, bytes)?;
        assert!(
            !reference.is_empty(),
            "fixture has relocated constant pointers"
        );
        assert!(matches!(
            constant_pointers_with_limits(&pe, bytes, 0, MAX_PE_SECTIONS),
            Err(PeFactsError::TooManyRelocationWords { limit: 0 })
        ));
        Ok(())
    }

    #[test]
    fn section_limit_refuses_before_relocation_scanning() -> Result<(), PeFactsError> {
        let bytes: &[u8] = include_bytes!("../../../corpus/dotnet/HelloAppAot.exe");
        let pe: PE<'_> = PE::parse(bytes)?;
        assert!(matches!(
            constant_pointers_with_limits(&pe, bytes, MAX_RELOCATION_WORDS, 0),
            Err(PeFactsError::TooManySections { limit: 0 })
        ));
        Ok(())
    }

    #[test]
    fn overlapping_sections_are_a_typed_refusal() -> Result<(), PeFactsError> {
        let bytes: &[u8] = include_bytes!("../../../corpus/dotnet/HelloAppAot.exe");
        let mut pe: PE<'_> = PE::parse(bytes)?;
        let first: usize = pe
            .sections
            .iter()
            .position(|section| section.size_of_raw_data.min(section.virtual_size) > 0)
            .ok_or(PeFactsError::InvalidSectionRange { rva: 0 })?;
        let second: usize = pe
            .sections
            .iter()
            .enumerate()
            .skip(first + 1)
            .find_map(|(index, section)| {
                (section.size_of_raw_data.min(section.virtual_size) > 0).then_some(index)
            })
            .ok_or(PeFactsError::InvalidSectionRange { rva: 0 })?;
        let first_rva: u32 = pe.sections[first].virtual_address;
        pe.sections[second].virtual_address = first_rva;
        assert!(matches!(
            SectionIndex::new(&pe, MAX_PE_SECTIONS),
            Err(PeFactsError::OverlappingSections { .. })
        ));
        Ok(())
    }
}
