use disrobe_bytes::ByteReader;
use disrobe_pass_native::{Arch, DisasmInsn, PseudoAbi, disassemble, recover_leaf_function_abi};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::metadata::{metadata_slice, parse_metadata_root, read_strings_heap};
use crate::pe::{ClrHeader, DataDirectory, PeImage};
use crate::tables::{Tables, parse_tables};

pub const R2R_MAGIC: u32 = 0x0052_5452;
const R2R_HEADER_LEN: usize = 16;
const R2R_SECTION_LEN: usize = 12;
const MAX_R2R_SECTIONS: u32 = 1024;
const MAX_R2R_RUNTIME_FUNCTIONS: usize = 1_048_576;
const MACHINE_I386: u16 = 0x014C;
const MACHINE_ARM: u16 = 0x01C0;
const MACHINE_ARMNT: u16 = 0x01C4;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARM64: u16 = 0xAA64;
const MAX_SUPPORTED_R2R_MAJOR_VERSION: u16 = 27;
const MAX_R2R_METHOD_BODY_INPUT_BYTES: usize = 1024 * 1024;
const MAX_R2R_METHOD_BODY_TOTAL_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_R2R_METHOD_BODY_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_R2R_METHOD_BODY_TOTAL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub flags: u32,
    pub number_of_sections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rReport {
    pub present: bool,
    pub header: Option<R2rHeader>,
    pub sections: Vec<R2rSection>,
    pub runtime_functions: R2rRuntimeFunctions,
    pub crossgen2_native_aot: bool,
    pub composite_image: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rSection {
    #[serde(rename = "type")]
    pub section_type: u32,
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rAmd64RuntimeFunction {
    #[serde(rename = "unwind_info_start_rva")]
    pub unwind_info_start: R2rRva,
    #[serde(rename = "unwind_info_end_rva")]
    pub unwind_info_end: R2rRva,
    #[serde(rename = "gc_info_start_rva")]
    pub gc_info_start: R2rRva,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_def: Option<R2rMethodDefIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_def_abstention: Option<R2rMethodDefAbstention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_body: Option<R2rMethodBody>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rUnwindGcRuntimeFunction {
    pub unwind_info_start_rva: R2rRva,
    pub gc_info_start_rva: R2rRva,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_def: Option<R2rMethodDefIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_def_abstention: Option<R2rMethodDefAbstention>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rMethodDefIdentity {
    pub token: u32,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rMethodCodeRange {
    pub start_rva: R2rRva,
    pub end_rva: R2rRva,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum R2rMethodBody {
    Recovered {
        range: R2rMethodCodeRange,
        pseudo_c: String,
        signature: R2rMethodBodySignature,
    },
    Refused {
        range: Option<R2rMethodCodeRange>,
        reason: R2rMethodBodyRefusal,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R2rMethodBodySignature {
    Registers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R2rMethodBodyRefusal {
    BoundaryUnavailable,
    BoundaryAmbiguous,
    RangeMalformed,
    RangeNotExecutable,
    RangeOverlaps,
    InputBudgetExhausted,
    OutputBudgetExhausted,
    AddressOverflow,
    NativeLifterRefused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rMethodDefAbstention {
    pub token: u32,
    pub name: String,
    pub reason: R2rMethodDefAbstentionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R2rMethodDefAbstentionReason {
    FixupUnsupported,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum R2rMethodDefIdentityJoin {
    #[default]
    NotAttempted,
    Recovered {
        attached: usize,
        abstained: usize,
    },
    UnsupportedLayout,
}

impl R2rMethodDefIdentityJoin {
    const fn is_not_attempted(&self) -> bool {
        matches!(self, Self::NotAttempted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R2rUnwindGcMachine {
    X86,
    Arm,
    ArmNt,
    Arm64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "layout", rename_all = "snake_case")]
pub enum R2rRuntimeFunctions {
    #[default]
    Absent,
    Amd64 {
        entries: Vec<R2rAmd64RuntimeFunction>,
        #[serde(
            default,
            skip_serializing_if = "R2rMethodDefIdentityJoin::is_not_attempted"
        )]
        method_def_identity: R2rMethodDefIdentityJoin,
    },
    UnwindGcInfo {
        machine: R2rUnwindGcMachine,
        entries: Vec<R2rUnwindGcRuntimeFunction>,
        #[serde(
            default,
            skip_serializing_if = "R2rMethodDefIdentityJoin::is_not_attempted"
        )]
        method_def_identity: R2rMethodDefIdentityJoin,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct R2rRva(pub u32);

pub fn detect(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> Result<R2rReport> {
    if clr.managed_native_header.rva == 0 || clr.managed_native_header.size == 0 {
        return Ok(absent_report());
    }
    let (header, sections, runtime_functions): (R2rHeader, Vec<R2rSection>, R2rRuntimeFunctions) =
        parse(image, pe, clr)?;
    let composite_image: bool = (header.flags & 0x0000_0001) != 0;
    let crossgen2_native_aot: bool = (header.flags & 0x0000_0080) != 0;
    Ok(R2rReport {
        present: true,
        header: Some(header),
        sections,
        runtime_functions,
        crossgen2_native_aot,
        composite_image,
    })
}

const fn absent_report() -> R2rReport {
    R2rReport {
        present: false,
        header: None,
        sections: Vec::new(),
        runtime_functions: R2rRuntimeFunctions::Absent,
        crossgen2_native_aot: false,
        composite_image: false,
    }
}

pub fn parse_header(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> Result<R2rHeader> {
    parse(image, pe, clr)
        .map(|(header, _, _): (R2rHeader, Vec<R2rSection>, R2rRuntimeFunctions)| header)
}

fn parse(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
) -> Result<(R2rHeader, Vec<R2rSection>, R2rRuntimeFunctions)> {
    let dir: DataDirectory = clr.managed_native_header;
    if dir.size < R2R_HEADER_LEN as u32 {
        return Err(Error::Truncated {
            offset: dir.rva as usize,
            needed: R2R_HEADER_LEN,
            had: dir.size as usize,
        });
    }
    let directory_size: usize = dir.size as usize;
    let slice: &[u8] = pe
        .slice_exact_file_backed_rva(image, dir.rva, directory_size)
        .ok_or(Error::Truncated {
            offset: dir.rva as usize,
            needed: directory_size,
            had: 0,
        })?;
    let mut reader: ByteReader<'_> = ByteReader::new(slice);
    let magic: u32 = reader.read_u32_le()?;
    if magic != R2R_MAGIC {
        return Err(Error::BadR2rMagic(magic));
    }
    let major_version: u16 = reader.read_u16_le()?;
    let minor_version: u16 = reader.read_u16_le()?;
    if !(1..=MAX_SUPPORTED_R2R_MAJOR_VERSION).contains(&major_version) {
        return Err(Error::UnsupportedR2rVersion(u32::from(major_version)));
    }
    let flags: u32 = reader.read_u32_le()?;
    let number_of_sections: u32 = reader.read_u32_le()?;
    if number_of_sections > MAX_R2R_SECTIONS {
        return Err(Error::TooManyR2rSections {
            count: number_of_sections,
            cap: MAX_R2R_SECTIONS,
        });
    }
    let section_count: usize = number_of_sections as usize;
    let sections_size: usize =
        section_count
            .checked_mul(R2R_SECTION_LEN)
            .ok_or(Error::TooManyR2rSections {
                count: number_of_sections,
                cap: MAX_R2R_SECTIONS,
            })?;
    let required_size: usize =
        R2R_HEADER_LEN
            .checked_add(sections_size)
            .ok_or(Error::TooManyR2rSections {
                count: number_of_sections,
                cap: MAX_R2R_SECTIONS,
            })?;
    if required_size > directory_size {
        return Err(Error::Truncated {
            offset: dir.rva as usize,
            needed: required_size,
            had: directory_size,
        });
    }
    let header: R2rHeader = R2rHeader {
        magic,
        major_version,
        minor_version,
        flags,
        number_of_sections,
    };
    let mut sections: Vec<R2rSection> = Vec::with_capacity(section_count);
    let mut previous_type: Option<u32> = None;
    for index in 0..section_count {
        let section_type: u32 = reader.read_u32_le()?;
        let rva: u32 = reader.read_u32_le()?;
        let size: u32 = reader.read_u32_le()?;
        if previous_type.is_some_and(|previous: u32| section_type <= previous) {
            return Err(Error::InvalidR2rSectionTable {
                index,
                reason: "section types are not strictly increasing",
            });
        }
        if size != 0 {
            let section_size: usize = size as usize;
            if pe
                .slice_exact_file_backed_rva(image, rva, section_size)
                .is_none()
            {
                return Err(Error::InvalidR2rSectionTable {
                    index,
                    reason: "section range is not wholly file backed",
                });
            }
        }
        sections.push(R2rSection {
            section_type,
            name: section_name(section_type),
            rva,
            size,
        });
        previous_type = Some(section_type);
    }
    let mut runtime_functions: R2rRuntimeFunctions = sections
        .iter()
        .find(|section: &&R2rSection| section.section_type == 102)
        .map_or_else(
            || Ok(R2rRuntimeFunctions::Absent),
            |section: &R2rSection| parse_runtime_functions(image, pe, section),
        )?;
    let method_def_section: Option<&R2rSection> = sections
        .iter()
        .find(|section: &&R2rSection| section.section_type == 103);
    if let Some(section) = method_def_section {
        if major_version == 10 && minor_version == 1 && flags & 0x0000_0001 == 0 {
            let parsed: ParsedMethodDefJoin =
                parse_method_def_entry_points(image, pe, clr, section, &runtime_functions)?;
            attach_method_def_join(&mut runtime_functions, parsed)?;
        } else {
            attach_method_def_join(
                &mut runtime_functions,
                ParsedMethodDefJoin::UnsupportedLayout,
            )?;
        }
    }
    attach_method_bodies(image, pe, &mut runtime_functions);
    validate_unclaimed_runtime_ranges(image, pe, &runtime_functions)?;
    Ok((header, sections, runtime_functions))
}

fn parse_runtime_functions(
    image: &[u8],
    pe: &PeImage,
    section: &R2rSection,
) -> Result<R2rRuntimeFunctions> {
    let unwind_gc_machine: Option<R2rUnwindGcMachine> = match pe.machine {
        MACHINE_AMD64 => None,
        MACHINE_I386 => Some(R2rUnwindGcMachine::X86),
        MACHINE_ARM => Some(R2rUnwindGcMachine::Arm),
        MACHINE_ARMNT => Some(R2rUnwindGcMachine::ArmNt),
        MACHINE_ARM64 => Some(R2rUnwindGcMachine::Arm64),
        _ => {
            return Err(Error::InvalidR2rRuntimeFunctions {
                index: 0,
                reason: "PE machine has no supported ReadyToRun runtime-function layout",
            });
        }
    };
    let entry_size: usize = if unwind_gc_machine.is_some() { 8 } else { 12 };
    let section_size: usize = section.size as usize;
    if !section_size.is_multiple_of(entry_size) {
        return Err(Error::InvalidR2rRuntimeFunctions {
            index: section_size / entry_size,
            reason: "section size is not divisible by the machine entry width",
        });
    }
    let entry_count: usize = section_size / entry_size;
    if entry_count > MAX_R2R_RUNTIME_FUNCTIONS {
        return Err(Error::InvalidR2rRuntimeFunctions {
            index: entry_count,
            reason: "runtime-function count exceeds parser limit",
        });
    }
    if section_size == 0 {
        return Ok(unwind_gc_machine.map_or_else(
            || R2rRuntimeFunctions::Amd64 {
                entries: Vec::new(),
                method_def_identity: R2rMethodDefIdentityJoin::NotAttempted,
            },
            |machine: R2rUnwindGcMachine| R2rRuntimeFunctions::UnwindGcInfo {
                machine,
                entries: Vec::new(),
                method_def_identity: R2rMethodDefIdentityJoin::NotAttempted,
            },
        ));
    }
    let bytes: &[u8] = pe
        .slice_exact_file_backed_rva(image, section.rva, section_size)
        .ok_or(Error::InvalidR2rRuntimeFunctions {
            index: 0,
            reason: "runtime-function table is not wholly file backed",
        })?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if let Some(machine) = unwind_gc_machine {
        let mut entries: Vec<R2rUnwindGcRuntimeFunction> = Vec::with_capacity(entry_count);
        for index in 0..entry_count {
            let unwind_info_start_rva: u32 = reader.read_u32_le()?;
            let gc_info_start_rva: u32 = reader.read_u32_le()?;
            if pe
                .slice_exact_file_backed_rva(image, unwind_info_start_rva, 1)
                .is_none()
            {
                return Err(Error::InvalidR2rRuntimeFunctions {
                    index,
                    reason: "runtime-function unwind-info RVA is not file backed",
                });
            }
            if pe
                .slice_exact_file_backed_rva(image, gc_info_start_rva, 1)
                .is_none()
            {
                return Err(Error::InvalidR2rRuntimeFunctions {
                    index,
                    reason: "runtime-function GC-info RVA is not file backed",
                });
            }
            entries.push(R2rUnwindGcRuntimeFunction {
                unwind_info_start_rva: R2rRva(unwind_info_start_rva),
                gc_info_start_rva: R2rRva(gc_info_start_rva),
                method_def: None,
                method_def_abstention: None,
            });
        }
        return Ok(R2rRuntimeFunctions::UnwindGcInfo {
            machine,
            entries,
            method_def_identity: R2rMethodDefIdentityJoin::NotAttempted,
        });
    }
    let mut entries: Vec<R2rAmd64RuntimeFunction> = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let unwind_info_start_rva: u32 = reader.read_u32_le()?;
        let unwind_info_end_rva: u32 = reader.read_u32_le()?;
        let gc_info_start_rva: u32 = reader.read_u32_le()?;
        if pe
            .slice_exact_file_backed_rva(image, gc_info_start_rva, 1)
            .is_none()
        {
            return Err(Error::InvalidR2rRuntimeFunctions {
                index,
                reason: "GC-info start RVA is not file backed",
            });
        }
        entries.push(R2rAmd64RuntimeFunction {
            unwind_info_start: R2rRva(unwind_info_start_rva),
            unwind_info_end: R2rRva(unwind_info_end_rva),
            gc_info_start: R2rRva(gc_info_start_rva),
            method_def: None,
            method_def_abstention: None,
            method_body: None,
        });
    }
    Ok(R2rRuntimeFunctions::Amd64 {
        entries,
        method_def_identity: R2rMethodDefIdentityJoin::NotAttempted,
    })
}

const fn invalid_method_def(index: usize, reason: &'static str) -> Error {
    Error::InvalidR2rRuntimeFunctions { index, reason }
}

const fn native_unsigned_width(first: u8) -> Option<usize> {
    if first & 1 == 0 {
        Some(1)
    } else if first & 2 == 0 {
        Some(2)
    } else if first & 4 == 0 {
        Some(3)
    } else if first & 8 == 0 {
        Some(4)
    } else if first & 16 == 0 {
        Some(5)
    } else {
        None
    }
}

fn native_unsigned_at(bytes: &[u8], at: usize, index: usize) -> Result<Option<(u32, usize)>> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(at)
        .map_err(|_| invalid_method_def(index, "native unsigned offset is outside the section"))?;
    let first: u8 = reader
        .read_u8()
        .map_err(|_| invalid_method_def(index, "native unsigned value is truncated"))?;
    let width: usize = native_unsigned_width(first)
        .ok_or_else(|| invalid_method_def(index, "native unsigned encoding is malformed"))?;
    if width != 1 {
        reader
            .read_bytes(width - 1)
            .map_err(|_| invalid_method_def(index, "native unsigned value is truncated"))?;
        return Ok(None);
    }
    Ok(Some((u32::from(first >> 1), 1)))
}

enum SparseArrayElement {
    Absent,
    Payload(usize),
    UnsupportedLayout,
}

fn sparse_array_element(bytes: &[u8], base: usize, index: usize) -> Result<SparseArrayElement> {
    let block_index: usize = index / 16;
    if block_index != 0 {
        return Err(invalid_method_def(
            index,
            "multiple NativeArray blocks are not supported for this layout",
        ));
    }
    let mut index_reader: ByteReader<'_> = ByteReader::new(bytes);
    index_reader
        .seek(base)
        .map_err(|_| invalid_method_def(index, "NativeArray block index is truncated"))?;
    let block_offset: usize = usize::from(
        index_reader
            .read_u8()
            .map_err(|_| invalid_method_def(index, "NativeArray block index is truncated"))?,
    );
    let mut node_at: usize = base
        .checked_add(block_offset)
        .ok_or_else(|| invalid_method_def(index, "NativeArray block offset overflowed"))?;
    for bit in [8usize, 4, 2, 1] {
        let Some((node, width)): Option<(u32, usize)> = native_unsigned_at(bytes, node_at, index)?
        else {
            return Ok(SparseArrayElement::UnsupportedLayout);
        };
        let take_high: bool = index & bit != 0;
        if take_high {
            if node & 2 == 0 {
                if node.trailing_zeros() >= 2 && usize::try_from(node >> 2).ok() == Some(index & 15)
                {
                    return Ok(SparseArrayElement::UnsupportedLayout);
                }
                return Ok(SparseArrayElement::Absent);
            }
            let high_offset: usize = usize::try_from(node >> 2).map_err(|_| {
                invalid_method_def(index, "NativeArray high-child offset does not fit usize")
            })?;
            node_at = node_at.checked_add(high_offset).ok_or_else(|| {
                invalid_method_def(index, "NativeArray high-child offset overflowed")
            })?;
        } else {
            if node & 1 == 0 {
                if node.trailing_zeros() >= 2 && usize::try_from(node >> 2).ok() == Some(index & 15)
                {
                    return Ok(SparseArrayElement::UnsupportedLayout);
                }
                return Ok(SparseArrayElement::Absent);
            }
            node_at = node_at.checked_add(width).ok_or_else(|| {
                invalid_method_def(index, "NativeArray low-child offset overflowed")
            })?;
        }
        if node_at >= bytes.len() {
            return Err(invalid_method_def(
                index,
                "NativeArray child offset is outside the section",
            ));
        }
    }
    Ok(SparseArrayElement::Payload(node_at))
}

const fn runtime_function_count(runtime_functions: &R2rRuntimeFunctions) -> usize {
    match runtime_functions {
        R2rRuntimeFunctions::Absent => 0,
        R2rRuntimeFunctions::Amd64 { entries, .. } => entries.len(),
        R2rRuntimeFunctions::UnwindGcInfo { entries, .. } => entries.len(),
    }
}

fn method_def_names(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> Result<Vec<String>> {
    let root: crate::metadata::MetadataRoot = parse_metadata_root(image, pe, clr)
        .map_err(|_| invalid_method_def(0, "CLI metadata root is unavailable"))?;
    let bytes: &[u8] = metadata_slice(image, pe, clr, &root)
        .map_err(|_| invalid_method_def(0, "CLI metadata range is unavailable"))?;
    let table_header: crate::metadata::StreamHeader = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
        .ok_or_else(|| invalid_method_def(0, "CLI metadata table stream is absent"))?;
    let tables: Tables = parse_tables(bytes, table_header)
        .map_err(|_| invalid_method_def(0, "CLI metadata tables are malformed"))?;
    let strings_header: crate::metadata::StreamHeader = root
        .streams
        .get("#Strings")
        .copied()
        .ok_or_else(|| invalid_method_def(0, "CLI metadata strings heap is absent"))?;
    let strings: std::collections::BTreeMap<u32, String> = read_strings_heap(bytes, strings_header);
    let mut names: Vec<String> = Vec::with_capacity(tables.methods.len());
    for (index, method) in tables.methods.iter().enumerate() {
        let name: String = strings
            .get(&method.name)
            .filter(|name: &&String| !name.is_empty())
            .cloned()
            .ok_or_else(|| invalid_method_def(index, "MethodDef name is absent"))?;
        names.push(name);
    }
    Ok(names)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedMethodDefAssociation {
    Identity {
        runtime_index: usize,
        identity: R2rMethodDefIdentity,
    },
    Abstention {
        runtime_index: usize,
        abstention: R2rMethodDefAbstention,
    },
}

impl ParsedMethodDefAssociation {
    const fn runtime_index(&self) -> usize {
        match self {
            Self::Identity { runtime_index, .. } | Self::Abstention { runtime_index, .. } => {
                *runtime_index
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedMethodDefJoin {
    Recovered(Vec<ParsedMethodDefAssociation>),
    UnsupportedLayout,
}

struct NibbleCursor<'a> {
    reader: ByteReader<'a>,
    end: usize,
    high: Option<u8>,
}

impl<'a> NibbleCursor<'a> {
    fn new(bytes: &'a [u8], start: usize, end: usize, index: usize) -> Result<Self> {
        if end > bytes.len() || start > end {
            return Err(invalid_method_def(index, "fixup list range is malformed"));
        }
        let mut reader: ByteReader<'a> = ByteReader::new(bytes);
        reader
            .seek(start)
            .map_err(|_| invalid_method_def(index, "fixup list offset is outside the section"))?;
        Ok(Self {
            reader,
            end,
            high: None,
        })
    }

    fn read(&mut self, index: usize) -> Result<u8> {
        if let Some(high) = self.high.take() {
            return Ok(high);
        }
        if self.reader.position() >= self.end {
            return Err(invalid_method_def(index, "fixup list is truncated"));
        }
        let byte: u8 = self
            .reader
            .read_u8()
            .map_err(|_| invalid_method_def(index, "fixup list is truncated"))?;
        self.high = Some(byte >> 4);
        Ok(byte & 0x0f)
    }
}

fn read_fixup_uint(cursor: &mut NibbleCursor<'_>, index: usize) -> Result<u32> {
    let mut value: u32 = 0;
    loop {
        let nibble: u8 = cursor.read(index)?;
        value = value
            .checked_mul(8)
            .and_then(|shifted: u32| shifted.checked_add(u32::from(nibble & 7)))
            .ok_or_else(|| invalid_method_def(index, "fixup integer overflowed u32"))?;
        if nibble & 8 == 0 {
            return Ok(value);
        }
    }
}

fn validate_fixup_list(bytes: &[u8], start: usize, end: usize, index: usize) -> Result<()> {
    let mut cursor: NibbleCursor<'_> = NibbleCursor::new(bytes, start, end, index)?;
    let _table_index: u32 = read_fixup_uint(&mut cursor, index)?;
    loop {
        let _fixup_index: u32 = read_fixup_uint(&mut cursor, index)?;
        loop {
            let delta: u32 = read_fixup_uint(&mut cursor, index)?;
            if delta == 0 {
                break;
            }
        }
        let table_index: u32 = read_fixup_uint(&mut cursor, index)?;
        if table_index == 0 {
            return Ok(());
        }
    }
}

fn parse_method_def_entry_points(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    section: &R2rSection,
    runtime_functions: &R2rRuntimeFunctions,
) -> Result<ParsedMethodDefJoin> {
    if pe.machine != MACHINE_AMD64 {
        return Ok(ParsedMethodDefJoin::UnsupportedLayout);
    }
    let section_size: usize = section.size as usize;
    let bytes: &[u8] = pe
        .slice_exact_file_backed_rva(image, section.rva, section_size)
        .ok_or_else(|| invalid_method_def(0, "MethodDef entry-point section is not file backed"))?;
    let Some((header, header_width)): Option<(u32, usize)> = native_unsigned_at(bytes, 0, 0)?
    else {
        return Ok(ParsedMethodDefJoin::UnsupportedLayout);
    };
    if header & 3 != 0 {
        return Ok(ParsedMethodDefJoin::UnsupportedLayout);
    }
    let element_count: usize = usize::try_from(header >> 2)
        .map_err(|_| invalid_method_def(0, "MethodDef NativeArray count does not fit usize"))?;
    if element_count > MAX_R2R_RUNTIME_FUNCTIONS {
        return Err(invalid_method_def(
            element_count,
            "MethodDef NativeArray count exceeds parser limit",
        ));
    }
    if element_count > 16 {
        return Ok(ParsedMethodDefJoin::UnsupportedLayout);
    }
    let names: Vec<String> = method_def_names(image, pe, clr)?;
    if element_count > names.len() {
        return Err(invalid_method_def(
            element_count,
            "MethodDef NativeArray names a RID outside CLI metadata",
        ));
    }
    let runtime_count: usize = runtime_function_count(runtime_functions);
    let mut payloads: Vec<(usize, String, usize)> = Vec::new();
    let mut claimed_payload_offsets: std::collections::BTreeSet<usize> =
        std::collections::BTreeSet::new();
    for (method_index, name) in names.into_iter().take(element_count).enumerate() {
        let payload_at: usize = match sparse_array_element(bytes, header_width, method_index)? {
            SparseArrayElement::Absent => continue,
            SparseArrayElement::Payload(payload_at) => payload_at,
            SparseArrayElement::UnsupportedLayout => {
                return Ok(ParsedMethodDefJoin::UnsupportedLayout);
            }
        };
        if !claimed_payload_offsets.insert(payload_at) {
            return Err(invalid_method_def(
                method_index,
                "multiple MethodDefs share one NativeArray payload",
            ));
        }
        payloads.push((method_index, name, payload_at));
    }
    let mut associations: Vec<ParsedMethodDefAssociation> = Vec::new();
    let mut claimed_runtime_indices: std::collections::BTreeSet<usize> =
        std::collections::BTreeSet::new();
    for (method_index, name, payload_at) in payloads {
        let Some((encoded_entrypoint, encoded_width)): Option<(u32, usize)> =
            native_unsigned_at(bytes, payload_at, method_index)?
        else {
            return Ok(ParsedMethodDefJoin::UnsupportedLayout);
        };
        let has_fixups: bool = encoded_entrypoint & 1 != 0;
        if has_fixups && encoded_entrypoint & 2 != 0 {
            return Ok(ParsedMethodDefJoin::UnsupportedLayout);
        }
        if has_fixups {
            let fixup_at: usize = payload_at
                .checked_add(encoded_width)
                .ok_or_else(|| invalid_method_def(method_index, "fixup list offset overflowed"))?;
            let fixup_end: usize = claimed_payload_offsets
                .range((
                    std::ops::Bound::Included(fixup_at),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .copied()
                .unwrap_or(bytes.len());
            validate_fixup_list(bytes, fixup_at, fixup_end, method_index)?;
        }
        let runtime_index_value: u32 = if has_fixups {
            encoded_entrypoint >> 2
        } else {
            encoded_entrypoint >> 1
        };
        let runtime_index: usize = usize::try_from(runtime_index_value).map_err(|_| {
            invalid_method_def(method_index, "runtime-function index does not fit usize")
        })?;
        if runtime_index >= runtime_count {
            return Err(invalid_method_def(
                method_index,
                "MethodDef entry point names a runtime function outside the table",
            ));
        }
        if !claimed_runtime_indices.insert(runtime_index) {
            return Err(invalid_method_def(
                method_index,
                "multiple MethodDefs name the same runtime function",
            ));
        }
        let rid: u32 = u32::try_from(method_index + 1)
            .map_err(|_| invalid_method_def(method_index, "MethodDef RID does not fit u32"))?;
        let token: u32 = 0x0600_0000 | rid;
        if has_fixups {
            associations.push(ParsedMethodDefAssociation::Abstention {
                runtime_index,
                abstention: R2rMethodDefAbstention {
                    token,
                    name,
                    reason: R2rMethodDefAbstentionReason::FixupUnsupported,
                },
            });
        } else {
            associations.push(ParsedMethodDefAssociation::Identity {
                runtime_index,
                identity: R2rMethodDefIdentity { token, name },
            });
        }
    }
    Ok(ParsedMethodDefJoin::Recovered(associations))
}

fn attach_method_def_join(
    runtime_functions: &mut R2rRuntimeFunctions,
    parsed: ParsedMethodDefJoin,
) -> Result<()> {
    let mut updated: R2rRuntimeFunctions = runtime_functions.clone();
    let associations: Vec<ParsedMethodDefAssociation> = match parsed {
        ParsedMethodDefJoin::UnsupportedLayout => {
            match &mut updated {
                R2rRuntimeFunctions::Absent => {}
                R2rRuntimeFunctions::Amd64 {
                    method_def_identity,
                    ..
                }
                | R2rRuntimeFunctions::UnwindGcInfo {
                    method_def_identity,
                    ..
                } => {
                    *method_def_identity = R2rMethodDefIdentityJoin::UnsupportedLayout;
                }
            }
            *runtime_functions = updated;
            return Ok(());
        }
        ParsedMethodDefJoin::Recovered(associations) => associations,
    };
    let attached: usize = associations
        .iter()
        .filter(|association: &&ParsedMethodDefAssociation| {
            matches!(association, ParsedMethodDefAssociation::Identity { .. })
        })
        .count();
    let abstained: usize = associations.len().saturating_sub(attached);
    match &mut updated {
        R2rRuntimeFunctions::Absent => {
            if !associations.is_empty() {
                return Err(invalid_method_def(
                    0,
                    "MethodDef entry points exist without runtime functions",
                ));
            }
        }
        R2rRuntimeFunctions::Amd64 {
            entries,
            method_def_identity,
        } => {
            for association in associations {
                let index: usize = association.runtime_index();
                let entry: &mut R2rAmd64RuntimeFunction =
                    entries.get_mut(index).ok_or_else(|| {
                        invalid_method_def(index, "runtime-function identity index is out of range")
                    })?;
                match association {
                    ParsedMethodDefAssociation::Identity { identity, .. } => {
                        entry.method_def = Some(identity);
                    }
                    ParsedMethodDefAssociation::Abstention { abstention, .. } => {
                        entry.method_def_abstention = Some(abstention);
                    }
                }
            }
            *method_def_identity = R2rMethodDefIdentityJoin::Recovered {
                attached,
                abstained,
            };
        }
        R2rRuntimeFunctions::UnwindGcInfo {
            entries,
            method_def_identity,
            ..
        } => {
            for association in associations {
                let index: usize = association.runtime_index();
                let entry: &mut R2rUnwindGcRuntimeFunction =
                    entries.get_mut(index).ok_or_else(|| {
                        invalid_method_def(index, "runtime-function identity index is out of range")
                    })?;
                match association {
                    ParsedMethodDefAssociation::Identity { identity, .. } => {
                        entry.method_def = Some(identity);
                    }
                    ParsedMethodDefAssociation::Abstention { abstention, .. } => {
                        entry.method_def_abstention = Some(abstention);
                    }
                }
            }
            *method_def_identity = R2rMethodDefIdentityJoin::Recovered {
                attached,
                abstained,
            };
        }
    }
    *runtime_functions = updated;
    Ok(())
}

const fn method_body_refusal(
    range: Option<R2rMethodCodeRange>,
    reason: R2rMethodBodyRefusal,
) -> R2rMethodBody {
    R2rMethodBody::Refused { range, reason }
}

fn range_is_file_backed(image: &[u8], pe: &PeImage, range: R2rMethodCodeRange) -> bool {
    let Some(length): Option<u32> = range.end_rva.0.checked_sub(range.start_rva.0) else {
        return false;
    };
    length != 0
        && usize::try_from(length)
            .ok()
            .and_then(|length| pe.slice_exact_file_backed_rva(image, range.start_rva.0, length))
            .is_some()
}

fn validate_unclaimed_runtime_ranges(
    image: &[u8],
    pe: &PeImage,
    runtime_functions: &R2rRuntimeFunctions,
) -> Result<()> {
    let R2rRuntimeFunctions::Amd64 { entries, .. } = runtime_functions else {
        return Ok(());
    };
    for (index, entry) in entries.iter().enumerate() {
        let range: R2rMethodCodeRange = R2rMethodCodeRange {
            start_rva: entry.unwind_info_start,
            end_rva: entry.unwind_info_end,
        };
        if entry.method_def.is_none() && !range_is_file_backed(image, pe, range) {
            return Err(Error::InvalidR2rRuntimeFunctions {
                index,
                reason: "runtime-function range is not wholly file backed",
            });
        }
    }
    Ok(())
}

#[derive(Default)]
struct R2rMethodBodyBudget {
    input: usize,
    output: usize,
}

fn body_from_range(
    image: &[u8],
    pe: &PeImage,
    range: R2rMethodCodeRange,
    overlaps: bool,
    budget: &mut R2rMethodBodyBudget,
) -> R2rMethodBody {
    let length_u32: u32 = match range.end_rva.0.checked_sub(range.start_rva.0) {
        Some(length) if length != 0 => length,
        _ => return method_body_refusal(Some(range), R2rMethodBodyRefusal::RangeMalformed),
    };
    if overlaps {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::RangeOverlaps);
    }
    let length: usize = match usize::try_from(length_u32) {
        Ok(length) if length <= MAX_R2R_METHOD_BODY_INPUT_BYTES => length,
        _ => {
            return method_body_refusal(Some(range), R2rMethodBodyRefusal::InputBudgetExhausted);
        }
    };
    let Some(total_input): Option<usize> = budget.input.checked_add(length) else {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::InputBudgetExhausted);
    };
    if total_input > MAX_R2R_METHOD_BODY_TOTAL_INPUT_BYTES {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::InputBudgetExhausted);
    }
    budget.input = total_input;
    let executable: bool = pe.sections.iter().any(|section| {
        let Some(raw_end): Option<u32> = section.virtual_address.checked_add(section.raw_size)
        else {
            return false;
        };
        range.start_rva.0 >= section.virtual_address
            && range.end_rva.0 <= raw_end
            && section.characteristics & 0x2000_0000 != 0
    });
    if !executable {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::RangeNotExecutable);
    }
    let Some(bytes): Option<&[u8]> =
        pe.slice_exact_file_backed_rva(image, range.start_rva.0, length)
    else {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::RangeMalformed);
    };
    let Some(base): Option<u64> = pe.image_base.checked_add(u64::from(range.start_rva.0)) else {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::AddressOverflow);
    };
    let instructions: Vec<DisasmInsn> = match disassemble(Arch::X86_64, base, bytes) {
        Ok(instructions) => instructions,
        Err(_) => {
            return method_body_refusal(Some(range), R2rMethodBodyRefusal::BoundaryAmbiguous);
        }
    };
    let Some(expected_end): Option<u64> = base.checked_add(length as u64) else {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::AddressOverflow);
    };
    let mut next_address: u64 = base;
    for (index, instruction) in instructions.iter().enumerate() {
        if instruction.address != next_address
            || instruction.bytes.is_empty()
            || instruction.mnemonic == "(bad)"
        {
            return method_body_refusal(Some(range), R2rMethodBodyRefusal::BoundaryAmbiguous);
        }
        let Some(instruction_end): Option<u64> = instruction
            .address
            .checked_add(instruction.bytes.len() as u64)
        else {
            return method_body_refusal(Some(range), R2rMethodBodyRefusal::AddressOverflow);
        };
        if instruction_end > expected_end
            || (index + 1 < instructions.len()
                && matches!(instruction.mnemonic.as_str(), "ret" | "retf"))
        {
            return method_body_refusal(Some(range), R2rMethodBodyRefusal::BoundaryAmbiguous);
        }
        next_address = instruction_end;
    }
    if instructions.is_empty() || next_address != expected_end {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::BoundaryAmbiguous);
    }
    let Some(reserved_output): Option<usize> =
        budget.output.checked_add(MAX_R2R_METHOD_BODY_OUTPUT_BYTES)
    else {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::OutputBudgetExhausted);
    };
    if reserved_output > MAX_R2R_METHOD_BODY_TOTAL_OUTPUT_BYTES {
        return method_body_refusal(Some(range), R2rMethodBodyRefusal::OutputBudgetExhausted);
    }
    match recover_leaf_function_abi(bytes, base, PseudoAbi::MsX64) {
        Ok(recovery) => {
            let Some(total_output): Option<usize> =
                budget.output.checked_add(recovery.source.len())
            else {
                return method_body_refusal(
                    Some(range),
                    R2rMethodBodyRefusal::OutputBudgetExhausted,
                );
            };
            if recovery.source.len() > MAX_R2R_METHOD_BODY_OUTPUT_BYTES {
                return method_body_refusal(
                    Some(range),
                    R2rMethodBodyRefusal::OutputBudgetExhausted,
                );
            }
            if total_output > MAX_R2R_METHOD_BODY_TOTAL_OUTPUT_BYTES {
                return method_body_refusal(
                    Some(range),
                    R2rMethodBodyRefusal::OutputBudgetExhausted,
                );
            }
            budget.output = total_output;
            R2rMethodBody::Recovered {
                range,
                pseudo_c: recovery.source,
                signature: R2rMethodBodySignature::Registers,
            }
        }
        Err(_) => method_body_refusal(Some(range), R2rMethodBodyRefusal::NativeLifterRefused),
    }
}

fn attach_method_bodies(image: &[u8], pe: &PeImage, runtime_functions: &mut R2rRuntimeFunctions) {
    let R2rRuntimeFunctions::Amd64 { entries, .. } = runtime_functions else {
        return;
    };
    let mut ranges: Vec<(usize, R2rMethodCodeRange)> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            (
                index,
                R2rMethodCodeRange {
                    start_rva: entry.unwind_info_start,
                    end_rva: entry.unwind_info_end,
                },
            )
        })
        .collect();
    ranges.sort_unstable_by_key(|(_, range)| (range.start_rva, range.end_rva));
    let mut overlaps: Vec<bool> = vec![false; entries.len()];
    let mut greatest_end: Option<(usize, u32)> = None;
    for (index, range) in &ranges {
        if let Some((prior_index, prior_end)) = greatest_end
            && range.start_rva.0 < prior_end
        {
            if let Some(value) = overlaps.get_mut(prior_index) {
                *value = true;
            }
            if let Some(value) = overlaps.get_mut(*index) {
                *value = true;
            }
        }
        if greatest_end.is_none_or(|(_, end)| range.end_rva.0 > end) {
            greatest_end = Some((*index, range.end_rva.0));
        }
    }
    let by_index: Vec<R2rMethodCodeRange> = entries
        .iter()
        .map(|entry| R2rMethodCodeRange {
            start_rva: entry.unwind_info_start,
            end_rva: entry.unwind_info_end,
        })
        .collect();
    let mut budget: R2rMethodBodyBudget = R2rMethodBodyBudget::default();
    for (index, entry) in entries.iter_mut().enumerate() {
        if entry.method_def.is_none() {
            continue;
        }
        let Some(range): Option<R2rMethodCodeRange> = by_index.get(index).copied() else {
            entry.method_body = Some(method_body_refusal(
                None,
                R2rMethodBodyRefusal::BoundaryUnavailable,
            ));
            continue;
        };
        let overlap: bool = overlaps.get(index).is_none_or(|overlap| *overlap);
        entry.method_body = Some(body_from_range(image, pe, range, overlap, &mut budget));
    }
}

fn section_name(section_type: u32) -> String {
    let known: Option<&'static str> = match section_type {
        100 => Some("compiler_identifier"),
        101 => Some("import_sections"),
        102 => Some("runtime_functions"),
        103 => Some("method_def_entry_points"),
        104 => Some("exception_info"),
        105 => Some("debug_info"),
        106 => Some("delay_load_method_call_thunks"),
        108 => Some("available_types"),
        109 => Some("instance_method_entry_points"),
        110 => Some("inlining_info"),
        111 => Some("profile_data_info"),
        112 => Some("manifest_metadata"),
        113 => Some("attribute_presence"),
        114 => Some("inlining_info_2"),
        115 => Some("component_assemblies"),
        116 => Some("owner_composite_executable"),
        117 => Some("pgo_instrumentation_data"),
        118 => Some("manifest_assembly_mvids"),
        119 => Some("cross_module_inline_info"),
        120 => Some("hot_cold_map"),
        121 => Some("method_is_generic_map"),
        122 => Some("enclosing_type_map"),
        123 => Some("type_generic_info_map"),
        124 => Some("external_type_maps"),
        125 => Some("proxy_type_maps"),
        126 => Some("type_map_assembly_targets"),
        _ => None,
    };
    known.map_or_else(|| format!("unknown_{section_type}"), str::to_owned)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pe::{PeBitness, SectionHeader};

    #[test]
    fn r2r_magic_matches_rtr_ascii() {
        assert_eq!(R2R_MAGIC.to_le_bytes(), [b'R', b'T', b'R', 0]);
    }

    #[test]
    fn arm64_runtime_functions_preserve_unwind_and_gc_fields() {
        let mut image: Vec<u8> = vec![0; 0x80];
        image[0x20..0x24].copy_from_slice(&0x1040u32.to_le_bytes());
        image[0x24..0x28].copy_from_slice(&0x1050u32.to_le_bytes());
        let pe: PeImage = PeImage {
            bitness: PeBitness::Pe32Plus,
            machine: MACHINE_ARM64,
            number_of_sections: 1,
            timestamp: 0,
            characteristics: 0,
            entry_point_rva: 0,
            image_base: 0,
            data_directories: Vec::new(),
            sections: vec![SectionHeader {
                name: ".data".to_owned(),
                virtual_size: 0x80,
                virtual_address: 0x1000,
                raw_size: 0x80,
                raw_pointer: 0,
                characteristics: 0,
            }],
        };
        let section: R2rSection = R2rSection {
            section_type: 102,
            name: "runtime_functions".to_owned(),
            rva: 0x1020,
            size: 8,
        };
        let decoded: R2rRuntimeFunctions =
            parse_runtime_functions(&image, &pe, &section).expect("arm64 runtime functions");

        assert_eq!(
            serde_json::to_value(decoded).expect("serialize arm64 runtime functions"),
            serde_json::json!({
                "layout": "unwind_gc_info",
                "machine": "arm64",
                "entries": [{"unwind_info_start_rva": 4160, "gc_info_start_rva": 4176}]
            })
        );
    }

    #[test]
    fn output_budget_overflow_has_a_distinct_refusal() {
        let image: [u8; 1] = [0xcc];
        let pe: PeImage = PeImage {
            bitness: PeBitness::Pe32Plus,
            machine: MACHINE_AMD64,
            number_of_sections: 1,
            timestamp: 0,
            characteristics: 0,
            entry_point_rva: 0,
            image_base: 0,
            data_directories: Vec::new(),
            sections: vec![SectionHeader {
                name: ".text".to_owned(),
                virtual_size: 1,
                virtual_address: 0x1000,
                raw_size: 1,
                raw_pointer: 0,
                characteristics: 0x2000_0000,
            }],
        };
        let range: R2rMethodCodeRange = R2rMethodCodeRange {
            start_rva: R2rRva(0x1000),
            end_rva: R2rRva(0x1001),
        };
        let mut budget: R2rMethodBodyBudget = R2rMethodBodyBudget {
            input: 0,
            output: usize::MAX,
        };

        assert!(matches!(
            body_from_range(&image, &pe, range, false, &mut budget),
            R2rMethodBody::Refused {
                reason: R2rMethodBodyRefusal::OutputBudgetExhausted,
                ..
            }
        ));
    }
}
