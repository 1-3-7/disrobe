use std::collections::{BTreeMap, BTreeSet};

use disrobe_binfmt::native::{Arch as BinArch, Endian, NativeFile, NativeFormat};
use disrobe_bytes::ByteReader;
use gimli::{
    BaseAddresses, CieOrFde, CommonInformationEntry, EhFrame, EhFrameOffset, EndianSlice,
    FrameDescriptionEntry, LittleEndian, UnwindSection as _,
};
use object::{
    Object as _, ObjectSection as _, ObjectSegment as _, ObjectSymbol as _,
    SymbolKind as ObjSymbolKind,
    endian::LittleEndian as ObjectLittleEndian,
    read::pe::{ImageNtHeaders as _, ImageOptionalHeader as _},
};

use crate::debug::{dbg_kv, dbg_section};
use crate::elf::{ElfDynamicReport, RelocSource, SegmentMapping, SymbolType, analyze};

type EhSlice<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SeedOrigin {
    Entry,
    Export,
    SymbolTable,
    DynamicSymbol,
    UnwindEntry,
    ElfEhFrameHeader,
    InitArray,
    ThreadInit,
    FiniArray,
    DynamicInit,
    RelocationPointer,
    ElfPlt,
    DataPointer,
    MachFunctionStarts,
    MachCompactUnwind,
    PePdata,
    PeTlsCallback,
}

impl SeedOrigin {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Export => "export",
            Self::SymbolTable => "symtab",
            Self::DynamicSymbol => "dynsym",
            Self::UnwindEntry => "eh-frame",
            Self::ElfEhFrameHeader => "eh-frame-hdr",
            Self::InitArray => "init-array",
            Self::ThreadInit => "thread-init",
            Self::FiniArray => "fini-array",
            Self::DynamicInit => "dt-init",
            Self::RelocationPointer => "relocation",
            Self::ElfPlt => "elf-plt",
            Self::DataPointer => "data-pointer",
            Self::MachFunctionStarts => "macho-function-starts",
            Self::MachCompactUnwind => "macho-compact-unwind",
            Self::PePdata => "pe-pdata",
            Self::PeTlsCallback => "pe-tls-callback",
        }
    }
}

const AARCH64_INSTRUCTION_ALIGNMENT: u64 = 4;

const POINTER_BYTES: usize = 8;

pub(super) const MAX_SEEDS: usize = 1 << 17;

const MAX_UNWIND_ENTRIES: usize = 1 << 17;

const PE_ARM64_PDATA_RECORD_BYTES: usize = 8;

const MAX_POINTER_SLOTS: usize = 1 << 21;

const MAX_PE_TLS_CALLBACKS: usize = 1 << 12;

const PE64_TLS_DIRECTORY_BYTES: usize = 40;

const PE64_POINTER_BYTES: u64 = 8;

const MAX_EXECUTABLE_RANGES: usize = 1 << 12;

const MACH_COMPACT_UNWIND_VERSION: u32 = 1;

const MACH_COMPACT_UNWIND_REGULAR_PAGE: u32 = 2;

const MACH_COMPACT_UNWIND_COMPRESSED_PAGE: u32 = 3;

const MACH_COMPACT_UNWIND_PAGE_BYTES: usize = 4096;

const MACH_COMPACT_UNWIND_HEADER_BYTES: usize = 28;

const MACH_COMPACT_UNWIND_INDEX_BYTES: usize = 12;

const MACH_COMPACT_UNWIND_NOT_FUNCTION_START: u32 = 0x8000_0000;

const MIN_POINTER_RUN: usize = 2;

const R_AARCH64_RELATIVE: u32 = 1027;

const R_AARCH64_IRELATIVE: u32 = 1032;

const R_AARCH64_JUMP_SLOT: u32 = 1026;

const AARCH64_PLT_ENTRY_BYTES: u64 = 16;

const MAX_AARCH64_PLT_ENTRIES: usize = 1 << 16;

const _: () = assert!(MAX_AARCH64_PLT_ENTRIES < MAX_SEEDS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactUnwindError {
    Header,
    Version,
    Index,
    Page,
    Entry,
    Address,
    Limit,
}

impl CompactUnwindError {
    const fn label(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Version => "version",
            Self::Index => "index",
            Self::Page => "page",
            Self::Entry => "entry",
            Self::Address => "address",
            Self::Limit => "limit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompactUnwindOutcome {
    accepted: usize,
    error: Option<CompactUnwindError>,
}

impl CompactUnwindOutcome {
    const fn success(accepted: usize) -> Self {
        Self {
            accepted,
            error: None,
        }
    }

    const fn failure(accepted: usize, error: CompactUnwindError) -> Self {
        Self {
            accepted,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompactUnwindIndex {
    function: u32,
    page: u32,
    lsda: u32,
}

#[derive(Debug, Default)]
struct CompactUnwindState {
    previous: Option<u32>,
    processed: usize,
    accepted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutableRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Default)]
pub(super) struct SeedSet {
    seeds: BTreeMap<u64, BTreeSet<SeedOrigin>>,
}

impl SeedSet {
    fn admit(&mut self, address: u64, origin: SeedOrigin) {
        if self.seeds.len() >= MAX_SEEDS && !self.seeds.contains_key(&address) {
            return;
        }
        self.seeds.entry(address).or_default().insert(origin);
    }

    pub(super) fn addresses(&self) -> Vec<u64> {
        self.seeds.keys().copied().collect()
    }

    pub(super) fn counts(&self) -> BTreeMap<SeedOrigin, usize> {
        let mut counts: BTreeMap<SeedOrigin, usize> = BTreeMap::new();
        for origins in self.seeds.values() {
            for origin in origins {
                *counts.entry(*origin).or_insert(0) += 1;
            }
        }
        counts
    }
}

#[cfg(test)]
impl SeedSet {
    fn origins_of(&self, address: u64) -> BTreeSet<SeedOrigin> {
        self.seeds.get(&address).cloned().unwrap_or_default()
    }
}

struct ImageView<'a> {
    file: Option<object::File<'a>>,
    bytes: &'a [u8],
    executable: Vec<ExecutableRange>,
    segments: Vec<SegmentMapping>,
    file_section_reads: FileSectionReads,
}

#[derive(Clone, Copy)]
enum FileSectionReads {
    Allow,
    Deny,
}

impl<'a> ImageView<'a> {
    fn new(bytes: &'a [u8], report: Option<&ElfDynamicReport>) -> Self {
        let file: Option<object::File<'a>> = object::File::parse(bytes).ok();
        let mut executable: Vec<ExecutableRange> = Vec::new();
        if let Some(parsed) = file.as_ref() {
            for section in parsed.sections() {
                if executable.len() >= MAX_EXECUTABLE_RANGES {
                    break;
                }
                if !matches!(section.kind(), object::SectionKind::Text) {
                    continue;
                }
                let start: u64 = section.address();
                let Some(end): Option<u64> = start.checked_add(section.size()) else {
                    continue;
                };
                if end > start {
                    executable.push(ExecutableRange { start, end });
                }
            }
        }
        let segments: Vec<SegmentMapping> = report
            .map_or_else(Vec::new, |parsed: &ElfDynamicReport| {
                parsed.segments.clone()
            });
        if executable.is_empty() {
            for segment in &segments {
                if executable.len() >= MAX_EXECUTABLE_RANGES {
                    break;
                }
                if !segment.executable {
                    continue;
                }
                let Some(end): Option<u64> = segment.virtual_addr.checked_add(segment.mem_size)
                else {
                    continue;
                };
                if end > segment.virtual_addr {
                    executable.push(ExecutableRange {
                        start: segment.virtual_addr,
                        end,
                    });
                }
            }
        }
        executable.sort_by_key(|range: &ExecutableRange| range.start);
        Self {
            file,
            bytes,
            executable,
            segments,
            file_section_reads: FileSectionReads::Allow,
        }
    }

    fn new_pe64(bytes: &'a [u8]) -> Option<Self> {
        let file: object::File<'a> = object::File::parse(bytes).ok()?;
        let pe: object::read::pe::PeFile64<'a> = object::read::pe::PeFile64::parse(bytes).ok()?;
        let section_table: object::read::coff::SectionTable<'a> = pe.section_table();
        if section_table.len() > MAX_EXECUTABLE_RANGES {
            return None;
        }
        let image_base: u64 = pe.nt_headers().optional_header().image_base();
        let section_alignment: u64 =
            u64::from(pe.nt_headers().optional_header().section_alignment());
        let mut executable: Vec<ExecutableRange> = Vec::new();
        let mut segments: Vec<SegmentMapping> = Vec::with_capacity(section_table.len());
        for section in section_table.iter() {
            let virtual_size: u64 = u64::from(section.virtual_size.get(ObjectLittleEndian));
            let virtual_addr: u64 = image_base
                .checked_add(u64::from(section.virtual_address.get(ObjectLittleEndian)))?;
            let virtual_end: u64 = virtual_addr.checked_add(virtual_size)?;
            let characteristics: u32 = section.characteristics.get(ObjectLittleEndian);
            let is_executable: bool = characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0;
            if is_executable && virtual_end > virtual_addr {
                executable.push(ExecutableRange {
                    start: virtual_addr,
                    end: virtual_end,
                });
            }
            let (file_offset, file_size): (u32, u32) = section.pe_file_range();
            segments.push(SegmentMapping {
                kind: "pe-section".to_owned(),
                file_offset: u64::from(file_offset),
                file_size: u64::from(file_size),
                virtual_addr,
                mem_size: virtual_size,
                readable: characteristics & object::pe::IMAGE_SCN_MEM_READ != 0,
                writable: characteristics & object::pe::IMAGE_SCN_MEM_WRITE != 0,
                executable: is_executable,
                align: section_alignment,
            });
        }
        executable.sort_by_key(|range: &ExecutableRange| range.start);
        Some(Self {
            file: Some(file),
            bytes,
            executable,
            segments,
            file_section_reads: FileSectionReads::Deny,
        })
    }

    fn is_executable(&self, address: u64) -> bool {
        self.executable
            .iter()
            .any(|range: &ExecutableRange| address >= range.start && address < range.end)
    }

    fn has_linked_addresses(&self) -> bool {
        self.file.as_ref().is_some_and(|file: &object::File<'_>| {
            matches!(
                file.kind(),
                object::ObjectKind::Executable | object::ObjectKind::Dynamic
            )
        })
    }

    fn starts_a_range(&self, address: u64) -> bool {
        self.executable
            .iter()
            .any(|range: &ExecutableRange| range.start == address)
    }

    fn is_candidate(&self, address: u64) -> bool {
        address != 0 && address % AARCH64_INSTRUCTION_ALIGNMENT == 0 && self.is_executable(address)
    }

    fn contains_executable_extent(&self, address: u64, byte_len: u64) -> bool {
        let Some(end): Option<u64> = address.checked_add(byte_len) else {
            return false;
        };
        byte_len != 0
            && self
                .executable
                .iter()
                .any(|range: &ExecutableRange| address >= range.start && end <= range.end)
    }

    fn word_at(&self, address: u64) -> Option<u32> {
        for segment in &self.segments {
            let Some(offset): Option<u64> = address.checked_sub(segment.virtual_addr) else {
                continue;
            };
            if offset >= segment.file_size {
                continue;
            }
            let Some(file_offset): Option<u64> = segment.file_offset.checked_add(offset) else {
                continue;
            };
            if let Some(word) = read_word(self.bytes, file_offset) {
                return Some(word);
            }
        }
        if matches!(self.file_section_reads, FileSectionReads::Deny) {
            return None;
        }
        let parsed: &object::File<'a> = self.file.as_ref()?;
        for section in parsed.sections() {
            let Some(offset): Option<u64> = address.checked_sub(section.address()) else {
                continue;
            };
            if offset >= section.size() {
                continue;
            }
            let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
                continue;
            };
            if let Some(word) = read_word(data, offset) {
                return Some(word);
            }
        }
        None
    }

    fn qword_at(&self, address: u64) -> Option<u64> {
        for segment in &self.segments {
            let Some(offset): Option<u64> = address.checked_sub(segment.virtual_addr) else {
                continue;
            };
            if offset >= segment.file_size {
                continue;
            }
            let Some(file_offset): Option<u64> = segment.file_offset.checked_add(offset) else {
                continue;
            };
            if let Some(qword) = read_qword(self.bytes, file_offset) {
                return Some(qword);
            }
        }
        if matches!(self.file_section_reads, FileSectionReads::Deny) {
            return None;
        }
        let parsed: &object::File<'a> = self.file.as_ref()?;
        for section in parsed.sections() {
            let Some(offset): Option<u64> = address.checked_sub(section.address()) else {
                continue;
            };
            if offset >= section.size() {
                continue;
            }
            let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
                continue;
            };
            if let Some(qword) = read_qword(data, offset) {
                return Some(qword);
            }
        }
        None
    }
}

fn read_word(bytes: &[u8], offset: u64) -> Option<u32> {
    let start: usize = usize::try_from(offset).ok()?;
    let end: usize = start.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(start..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_qword(bytes: &[u8], offset: u64) -> Option<u64> {
    let start: usize = usize::try_from(offset).ok()?;
    let end: usize = start.checked_add(8)?;
    let raw: [u8; 8] = bytes.get(start..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

const fn is_prologue_word(word: u32) -> bool {
    const STP_MASK: u32 = 0xFFC0_03E0;
    const STP_PRE_INDEX_SP: u32 = 0xA980_03E0;
    const STP_OFFSET_SP: u32 = 0xA900_03E0;
    const SUB_SP_MASK: u32 = 0xFF80_03FF;
    const SUB_SP_IMM: u32 = 0xD100_03FF;
    const PACIASP: u32 = 0xD503_233F;
    const PACIBSP: u32 = 0xD503_237F;
    const BTI_C: u32 = 0xD503_245F;
    const BTI_J: u32 = 0xD503_249F;
    const BTI_JC: u32 = 0xD503_24DF;
    word & STP_MASK == STP_PRE_INDEX_SP
        || word & STP_MASK == STP_OFFSET_SP
        || word & SUB_SP_MASK == SUB_SP_IMM
        || word == PACIASP
        || word == PACIBSP
        || word == BTI_C
        || word == BTI_J
        || word == BTI_JC
}

const fn is_boundary_word(word: u32) -> bool {
    const RET_MASK: u32 = 0xFFFF_FC1F;
    const RET: u32 = 0xD65F_0000;
    const BRANCH_MASK: u32 = 0xFC00_0000;
    const BRANCH: u32 = 0x1400_0000;
    const INDIRECT_MASK: u32 = 0xFFFF_FC1F;
    const BR: u32 = 0xD61F_0000;
    const BRK_MASK: u32 = 0xFFE0_001F;
    const BRK: u32 = 0xD420_0000;
    const NOP: u32 = 0xD503_201F;
    word == 0
        || word == NOP
        || word & RET_MASK == RET
        || word & BRANCH_MASK == BRANCH
        || word & INDIRECT_MASK == BR
        || word & BRK_MASK == BRK
}

fn follows_a_boundary(view: &ImageView<'_>, address: u64) -> bool {
    if view.starts_a_range(address) {
        return true;
    }
    let Some(previous): Option<u64> = address.checked_sub(AARCH64_INSTRUCTION_ALIGNMENT) else {
        return false;
    };
    view.word_at(previous).is_some_and(is_boundary_word)
}

fn opens_a_function(view: &ImageView<'_>, address: u64) -> bool {
    view.word_at(address).is_some_and(is_prologue_word)
}

fn collect_object_symbols(view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    let entry: u64 = parsed.entry();
    if view.is_candidate(entry) {
        seeds.admit(entry, SeedOrigin::Entry);
    }
    for symbol in parsed.symbols() {
        if !matches!(symbol.kind(), ObjSymbolKind::Text) || symbol.is_undefined() {
            continue;
        }
        let address: u64 = symbol.address();
        if view.is_candidate(address) {
            seeds.admit(address, SeedOrigin::SymbolTable);
        }
    }
    for symbol in parsed.dynamic_symbols() {
        if !matches!(symbol.kind(), ObjSymbolKind::Text) || symbol.is_undefined() {
            continue;
        }
        let address: u64 = symbol.address();
        if view.is_candidate(address) {
            seeds.admit(address, SeedOrigin::DynamicSymbol);
        }
    }
}

fn collect_exports(native: &NativeFile, view: &ImageView<'_>, seeds: &mut SeedSet) {
    for export in &native.exports {
        if view.is_candidate(export.address) {
            seeds.admit(export.address, SeedOrigin::Export);
        }
    }
}

fn collect_dynamic(report: &ElfDynamicReport, view: &ImageView<'_>, seeds: &mut SeedSet) {
    for entry in [report.init, report.fini].into_iter().flatten() {
        if view.is_candidate(entry) {
            seeds.admit(entry, SeedOrigin::DynamicInit);
        }
    }
    for address in &report.init_array {
        if view.is_candidate(*address) {
            seeds.admit(*address, SeedOrigin::InitArray);
        }
    }
    for address in &report.fini_array {
        if view.is_candidate(*address) {
            seeds.admit(*address, SeedOrigin::FiniArray);
        }
    }
    for symbol in &report.symbols {
        if !symbol.defined || !matches!(symbol.sym_type, SymbolType::Func) {
            continue;
        }
        if view.is_candidate(symbol.value) {
            seeds.admit(symbol.value, SeedOrigin::DynamicSymbol);
        }
    }
    for relocation in &report.relocations {
        if !matches!(relocation.r_type, R_AARCH64_RELATIVE | R_AARCH64_IRELATIVE) {
            continue;
        }
        let Ok(addend): core::result::Result<u64, core::num::TryFromIntError> =
            u64::try_from(relocation.addend)
        else {
            continue;
        };
        if view.is_candidate(addend)
            && (opens_a_function(view, addend) || follows_a_boundary(view, addend))
        {
            seeds.admit(addend, SeedOrigin::RelocationPointer);
        }
    }
}

fn collect_elf_plt_entries(report: &ElfDynamicReport, view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    let Some(plt): Option<object::Section<'_, '_>> =
        parsed.sections().find(|section: &object::Section<'_, '_>| {
            section.name().is_ok_and(|name: &str| name == ".plt")
        })
    else {
        return;
    };
    let Ok(data): core::result::Result<&[u8], object::Error> = plt.data() else {
        return;
    };
    if !canonical_plt0(data) {
        return;
    }
    let mut relocations: BTreeMap<u64, &crate::elf::Relocation> = BTreeMap::new();
    for relocation in report
        .relocations
        .iter()
        .filter(|relocation: &&crate::elf::Relocation| relocation.source == RelocSource::JmpRel)
    {
        if relocation.r_type != R_AARCH64_JUMP_SLOT || !valid_dynamic_symbol(report, relocation) {
            continue;
        }
        relocations.entry(relocation.offset).or_insert(relocation);
    }
    for entry_index in 0..MAX_AARCH64_PLT_ENTRIES {
        let Some(offset): Option<usize> = entry_index
            .checked_mul(16)
            .and_then(|relative: usize| 32_usize.checked_add(relative))
        else {
            break;
        };
        let Some(end): Option<usize> = offset.checked_add(16) else {
            break;
        };
        let Some(stub): Option<&[u8]> = data.get(offset..end) else {
            break;
        };
        let Ok(offset_u64): core::result::Result<u64, core::num::TryFromIntError> =
            u64::try_from(offset)
        else {
            break;
        };
        let Some(address): Option<u64> = plt.address().checked_add(offset_u64) else {
            break;
        };
        let Some(slot): Option<u64> = canonical_plt_stub_slot(address, stub) else {
            break;
        };
        if relocations.contains_key(&slot)
            && view.is_candidate(address)
            && view.contains_executable_extent(address, AARCH64_PLT_ENTRY_BYTES)
        {
            seeds.admit(address, SeedOrigin::ElfPlt);
        }
    }
}

fn valid_dynamic_symbol(report: &ElfDynamicReport, relocation: &crate::elf::Relocation) -> bool {
    let Ok(index): core::result::Result<usize, core::num::TryFromIntError> =
        usize::try_from(relocation.symbol_index)
    else {
        return false;
    };
    report
        .symbols
        .get(index)
        .is_some_and(|symbol: &crate::elf::DynamicSymbol| !symbol.name.is_empty())
}

fn canonical_plt0(data: &[u8]) -> bool {
    let Some(first): Option<u32> = read_word(data, 0) else {
        return false;
    };
    let Some(adrp): Option<u32> = read_word(data, 4) else {
        return false;
    };
    let Some(ldr): Option<u32> = read_word(data, 8) else {
        return false;
    };
    let Some(add): Option<u32> = read_word(data, 12) else {
        return false;
    };
    let Some(branch): Option<u32> = read_word(data, 16) else {
        return false;
    };
    first & 0xFFC0_7FFF == 0xA980_7BF0 && canonical_plt_stub_words(adrp, ldr, add, branch)
}

fn canonical_plt_stub_slot(address: u64, bytes: &[u8]) -> Option<u64> {
    let words: [u32; 4] = [
        read_word(bytes, 0)?,
        read_word(bytes, 4)?,
        read_word(bytes, 8)?,
        read_word(bytes, 12)?,
    ];
    if !canonical_plt_stub_words(words[0], words[1], words[2], words[3]) {
        return None;
    }
    let immediate: u64 =
        u64::from((words[0] >> 29) & 3) | (u64::from((words[0] >> 5) & 0x7FFFF) << 2);
    let pages: i64 = (i64::try_from(immediate).ok()? << 43) >> 43;
    let page: u64 = (address & !0xFFF).checked_add_signed(pages.checked_mul(4096)?)?;
    page.checked_add(u64::from((words[1] >> 10) & 0xFFF).checked_mul(8)?)
}

const fn canonical_plt_stub_words(adrp: u32, ldr: u32, add: u32, branch: u32) -> bool {
    adrp & 0x9F00_001F == 0x9000_0010
        && ldr & 0xFFC0_03FF == 0xF940_0211
        && add & 0xFF00_03FF == 0x9100_0210
        && branch == 0xD61F_0220
}

fn collect_initializer_tables(
    view: &ImageView<'_>,
    seeds: &mut SeedSet,
    slot_limit: usize,
    image_base: Option<u64>,
) {
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    let mut scanned: usize = 0;
    for section in parsed.sections() {
        let (origin, slot_bytes, relative_base): (SeedOrigin, usize, Option<u64>) = match section
            .flags()
        {
            object::SectionFlags::MachO { flags }
                if flags & object::macho::SECTION_TYPE
                    == object::macho::S_MOD_INIT_FUNC_POINTERS =>
            {
                (SeedOrigin::InitArray, POINTER_BYTES, None)
            }
            object::SectionFlags::MachO { flags }
                if flags & object::macho::SECTION_TYPE
                    == object::macho::S_MOD_TERM_FUNC_POINTERS =>
            {
                (SeedOrigin::FiniArray, POINTER_BYTES, None)
            }
            object::SectionFlags::MachO { flags }
                if flags & object::macho::SECTION_TYPE
                    == object::macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS =>
            {
                (SeedOrigin::ThreadInit, POINTER_BYTES, None)
            }
            object::SectionFlags::MachO { flags }
                if flags & object::macho::SECTION_TYPE == object::macho::S_INIT_FUNC_OFFSETS =>
            {
                let Some(base): Option<u64> = image_base else {
                    continue;
                };
                (
                    SeedOrigin::InitArray,
                    core::mem::size_of::<u32>(),
                    Some(base),
                )
            }
            _ => {
                let Ok(name): core::result::Result<&str, object::Error> = section.name() else {
                    continue;
                };
                match name {
                    ".init_array" | ".preinit_array" => {
                        (SeedOrigin::InitArray, POINTER_BYTES, None)
                    }
                    ".fini_array" => (SeedOrigin::FiniArray, POINTER_BYTES, None),
                    _ => continue,
                }
            }
        };
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        if data.len() % slot_bytes != 0 {
            continue;
        }
        for slot in data.chunks_exact(slot_bytes) {
            if scanned >= slot_limit {
                return;
            }
            scanned = scanned.saturating_add(1);
            let address: u64 = if let Some(base) = relative_base {
                let Ok(raw): core::result::Result<[u8; 4], core::array::TryFromSliceError> =
                    slot.try_into()
                else {
                    continue;
                };
                let Some(address): Option<u64> =
                    base.checked_add(u64::from(u32::from_le_bytes(raw)))
                else {
                    continue;
                };
                address
            } else {
                let Ok(raw): core::result::Result<
                    [u8; POINTER_BYTES],
                    core::array::TryFromSliceError,
                > = slot.try_into() else {
                    continue;
                };
                u64::from_le_bytes(raw)
            };
            if view.is_candidate(address) {
                seeds.admit(address, origin);
            }
        }
    }
}

fn parse_cie<'a>(
    section: &EhFrame<EhSlice<'a>>,
    bases: &BaseAddresses,
    offset: EhFrameOffset<usize>,
) -> gimli::Result<CommonInformationEntry<EhSlice<'a>>> {
    section.cie_from_offset(bases, offset)
}

fn collect_unwind_entries(view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    let Some(section): Option<object::Section<'_, '_>> =
        parsed.sections().find(|section: &object::Section<'_, '_>| {
            section.name().is_ok_and(|name: &str| name == ".eh_frame")
        })
    else {
        return;
    };
    let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
        return;
    };
    if data.is_empty() {
        return;
    }
    let text_base: u64 = view
        .executable
        .first()
        .map_or(0, |range: &ExecutableRange| range.start);
    let bases: BaseAddresses = BaseAddresses::default()
        .set_eh_frame(section.address())
        .set_text(text_base);
    let eh_frame: EhFrame<EhSlice<'_>> = EhFrame::new(data, LittleEndian);
    let mut entries: gimli::CfiEntriesIter<'_, EhFrame<EhSlice<'_>>, EhSlice<'_>> =
        eh_frame.entries(&bases);
    let mut seen: usize = 0;
    while seen < MAX_UNWIND_ENTRIES {
        let Ok(Some(entry)): gimli::Result<
            Option<CieOrFde<'_, EhFrame<EhSlice<'_>>, EhSlice<'_>>>,
        > = entries.next() else {
            return;
        };
        seen = seen.saturating_add(1);
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde): gimli::Result<FrameDescriptionEntry<EhSlice<'_>>> = partial.parse(parse_cie)
        else {
            continue;
        };
        let address: u64 = fde.initial_address();
        if view.is_candidate(address) {
            seeds.admit(address, SeedOrigin::UnwindEntry);
        }
    }
}

fn decode_elf_eh_frame_hdr(
    data: &[u8],
    header_address: u64,
    eh_frame_start: u64,
    eh_frame_end: u64,
    view: &ImageView<'_>,
    seeds: &mut SeedSet,
) {
    const VERSION: u8 = 1;
    const EH_FRAME_POINTER_ENCODING: u8 = 0x1b;
    const FDE_COUNT_ENCODING: u8 = 0x03;
    const TABLE_ENCODING: u8 = 0x3b;
    const EH_FRAME_POINTER_OFFSET: u64 = 4;

    if eh_frame_end <= eh_frame_start {
        return;
    }
    let mut reader: ByteReader<'_> = ByteReader::new(data);
    let Ok(version): core::result::Result<u8, disrobe_bytes::ByteReadError> = reader.read_u8()
    else {
        return;
    };
    let Ok(eh_frame_encoding): core::result::Result<u8, disrobe_bytes::ByteReadError> =
        reader.read_u8()
    else {
        return;
    };
    let Ok(count_encoding): core::result::Result<u8, disrobe_bytes::ByteReadError> =
        reader.read_u8()
    else {
        return;
    };
    let Ok(table_encoding): core::result::Result<u8, disrobe_bytes::ByteReadError> =
        reader.read_u8()
    else {
        return;
    };
    if version != VERSION
        || eh_frame_encoding != EH_FRAME_POINTER_ENCODING
        || count_encoding != FDE_COUNT_ENCODING
        || table_encoding != TABLE_ENCODING
    {
        return;
    }
    let Ok(eh_frame_delta): core::result::Result<i32, disrobe_bytes::ByteReadError> =
        reader.read_i32_le()
    else {
        return;
    };
    let Some(eh_frame_pointer_base): Option<u64> =
        header_address.checked_add(EH_FRAME_POINTER_OFFSET)
    else {
        return;
    };
    if eh_frame_pointer_base.checked_add_signed(i64::from(eh_frame_delta)) != Some(eh_frame_start) {
        return;
    }
    let Ok(declared_count): core::result::Result<u32, disrobe_bytes::ByteReadError> =
        reader.read_u32_le()
    else {
        return;
    };
    let Ok(declared_count): core::result::Result<usize, core::num::TryFromIntError> =
        usize::try_from(declared_count)
    else {
        return;
    };
    let row_limit: usize = declared_count.min(MAX_UNWIND_ENTRIES);
    let mut previous_start: Option<u64> = None;
    for _ in 0..row_limit {
        let Ok(start_delta): core::result::Result<i32, disrobe_bytes::ByteReadError> =
            reader.read_i32_le()
        else {
            return;
        };
        let Ok(fde_delta): core::result::Result<i32, disrobe_bytes::ByteReadError> =
            reader.read_i32_le()
        else {
            return;
        };
        let (Some(start), Some(fde)): (Option<u64>, Option<u64>) = (
            header_address.checked_add_signed(i64::from(start_delta)),
            header_address.checked_add_signed(i64::from(fde_delta)),
        ) else {
            return;
        };
        if !view.is_candidate(start)
            || previous_start.is_some_and(|previous: u64| start <= previous)
            || fde < eh_frame_start
            || fde >= eh_frame_end
        {
            return;
        }
        seeds.admit(start, SeedOrigin::ElfEhFrameHeader);
        previous_start = Some(start);
    }
}

fn collect_elf_eh_frame_hdr(view: &ImageView<'_>, seeds: &mut SeedSet) {
    if !view.has_linked_addresses() {
        return;
    }
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    let Some(header): Option<object::Section<'_, '_>> = parsed.section_by_name(".eh_frame_hdr")
    else {
        return;
    };
    let Some(eh_frame): Option<object::Section<'_, '_>> = parsed.section_by_name(".eh_frame")
    else {
        return;
    };
    let Ok(data): core::result::Result<&[u8], object::Error> = header.data() else {
        return;
    };
    let Some(eh_frame_end): Option<u64> = eh_frame.address().checked_add(eh_frame.size()) else {
        return;
    };
    decode_elf_eh_frame_hdr(
        data,
        header.address(),
        eh_frame.address(),
        eh_frame_end,
        view,
        seeds,
    );
}

fn collect_data_pointers(view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    let mut scanned: usize = 0;
    for section in parsed.sections() {
        if !matches!(
            section.kind(),
            object::SectionKind::ReadOnlyData
                | object::SectionKind::ReadOnlyDataWithRel
                | object::SectionKind::Data
        ) {
            continue;
        }
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        let mut run: Vec<u64> = Vec::new();
        for slot in data.chunks_exact(POINTER_BYTES) {
            if scanned >= MAX_POINTER_SLOTS {
                break;
            }
            scanned = scanned.saturating_add(1);
            let Ok(raw): core::result::Result<[u8; POINTER_BYTES], core::array::TryFromSliceError> =
                slot.try_into()
            else {
                continue;
            };
            let value: u64 = u64::from_le_bytes(raw);
            if view.is_candidate(value) {
                run.push(value);
                continue;
            }
            admit_pointer_run(&mut run, view, seeds);
        }
        admit_pointer_run(&mut run, view, seeds);
    }
}

fn read_compact_u16(data: &[u8], offset: usize) -> Option<u16> {
    let mut reader: ByteReader<'_> = ByteReader::new(data);
    reader.seek(offset).ok()?;
    reader.read_u16_le().ok()
}

fn read_compact_u32(data: &[u8], offset: usize) -> Option<u32> {
    let mut reader: ByteReader<'_> = ByteReader::new(data);
    reader.seek(offset).ok()?;
    reader.read_u32_le().ok()
}

fn compact_table_span(
    offset: u32,
    count: u32,
    width: usize,
    limit: usize,
) -> Option<(usize, usize)> {
    let start: usize = usize::try_from(offset).ok()?;
    let entries: usize = usize::try_from(count).ok()?;
    let size: usize = entries.checked_mul(width)?;
    let end: usize = start.checked_add(size)?;
    (end <= limit).then_some((start, end))
}

fn read_compact_index(data: &[u8], index_start: usize, index: usize) -> Option<CompactUnwindIndex> {
    let offset: usize =
        index_start.checked_add(index.checked_mul(MACH_COMPACT_UNWIND_INDEX_BYTES)?)?;
    Some(CompactUnwindIndex {
        function: read_compact_u32(data, offset)?,
        page: read_compact_u32(data, offset.checked_add(4)?)?,
        lsda: read_compact_u32(data, offset.checked_add(8)?)?,
    })
}

fn admit_compact_offset(
    function_offset: u32,
    encoding: u32,
    current_offset: u32,
    next_offset: u32,
    image_base: u64,
    view: &ImageView<'_>,
    seeds: &mut SeedSet,
    state: &mut CompactUnwindState,
) -> core::result::Result<(), CompactUnwindError> {
    if state.previous.is_none() && function_offset != current_offset {
        return Err(CompactUnwindError::Entry);
    }
    if function_offset < current_offset || function_offset >= next_offset {
        return Err(CompactUnwindError::Entry);
    }
    if state
        .previous
        .is_some_and(|previous: u32| function_offset <= previous)
    {
        return Err(CompactUnwindError::Entry);
    }
    if state.processed >= MAX_UNWIND_ENTRIES {
        return Err(CompactUnwindError::Limit);
    }
    state.previous = Some(function_offset);
    state.processed = state.processed.saturating_add(1);
    if encoding & MACH_COMPACT_UNWIND_NOT_FUNCTION_START != 0 {
        return Ok(());
    }
    let address: u64 = image_base
        .checked_add(u64::from(function_offset))
        .ok_or(CompactUnwindError::Address)?;
    if !view.is_candidate(address) {
        return Err(CompactUnwindError::Address);
    }
    seeds.admit(address, SeedOrigin::MachCompactUnwind);
    state.accepted = state.accepted.saturating_add(1);
    Ok(())
}

fn decode_macho_compact_unwind(
    data: &[u8],
    image_base: u64,
    view: &ImageView<'_>,
    seeds: &mut SeedSet,
) -> CompactUnwindOutcome {
    if data.len() < MACH_COMPACT_UNWIND_HEADER_BYTES {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    }
    let mut header: ByteReader<'_> = ByteReader::new(data);
    let Ok(version): core::result::Result<u32, disrobe_bytes::ByteReadError> = header.read_u32_le()
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    if version != MACH_COMPACT_UNWIND_VERSION {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Version);
    }
    let Ok(common_offset): core::result::Result<u32, disrobe_bytes::ByteReadError> =
        header.read_u32_le()
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    let Ok(common_count): core::result::Result<u32, disrobe_bytes::ByteReadError> =
        header.read_u32_le()
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    let Ok(personality_offset): core::result::Result<u32, disrobe_bytes::ByteReadError> =
        header.read_u32_le()
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    let Ok(personality_count): core::result::Result<u32, disrobe_bytes::ByteReadError> =
        header.read_u32_le()
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    let Ok(index_offset): core::result::Result<u32, disrobe_bytes::ByteReadError> =
        header.read_u32_le()
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    let Ok(index_count): core::result::Result<u32, disrobe_bytes::ByteReadError> =
        header.read_u32_le()
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    let Some((common_start, _)): Option<(usize, usize)> =
        compact_table_span(common_offset, common_count, 4, data.len())
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    };
    if compact_table_span(personality_offset, personality_count, 4, data.len()).is_none() {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Header);
    }
    let Ok(index_entries): core::result::Result<usize, core::num::TryFromIntError> =
        usize::try_from(index_count)
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
    };
    if !(2..=MAX_UNWIND_ENTRIES.saturating_add(1)).contains(&index_entries) {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
    }
    let Some((index_start, _)): Option<(usize, usize)> = compact_table_span(
        index_offset,
        index_count,
        MACH_COMPACT_UNWIND_INDEX_BYTES,
        data.len(),
    ) else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
    };
    for index in 0..index_entries.saturating_sub(1) {
        let (Some(current), Some(next)): (Option<CompactUnwindIndex>, Option<CompactUnwindIndex>) = (
            read_compact_index(data, index_start, index),
            read_compact_index(data, index_start, index.saturating_add(1)),
        ) else {
            return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
        };
        if current.function >= next.function || current.page == 0 {
            return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
        }
        let Ok(current_page): core::result::Result<usize, core::num::TryFromIntError> =
            usize::try_from(current.page)
        else {
            return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
        };
        if current_page >= data.len()
            || (next.page != 0 && next.page <= current.page)
            || usize::try_from(current.lsda).map_or(true, |offset: usize| offset > data.len())
            || next.lsda < current.lsda
            || (next.lsda - current.lsda) % 8 != 0
        {
            return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
        }
    }
    let Some(sentinel): Option<CompactUnwindIndex> =
        read_compact_index(data, index_start, index_entries.saturating_sub(1))
    else {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
    };
    if sentinel.page != 0
        || usize::try_from(sentinel.lsda).map_or(true, |offset: usize| offset > data.len())
    {
        return CompactUnwindOutcome::failure(0, CompactUnwindError::Index);
    }

    let mut state: CompactUnwindState = CompactUnwindState::default();
    for index in 0..index_entries.saturating_sub(1) {
        let (Some(current), Some(next)): (Option<CompactUnwindIndex>, Option<CompactUnwindIndex>) = (
            read_compact_index(data, index_start, index),
            read_compact_index(data, index_start, index.saturating_add(1)),
        ) else {
            return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Index);
        };
        let Ok(page_start): core::result::Result<usize, core::num::TryFromIntError> =
            usize::try_from(current.page)
        else {
            return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
        };
        let Some(page_capacity_end): Option<usize> = page_start
            .checked_add(MACH_COMPACT_UNWIND_PAGE_BYTES)
            .map(|end: usize| end.min(data.len()))
        else {
            return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
        };
        let page_end: usize = if next.page == 0 {
            page_capacity_end
        } else {
            let Ok(next_page): core::result::Result<usize, core::num::TryFromIntError> =
                usize::try_from(next.page)
            else {
                return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
            };
            page_capacity_end.min(next_page)
        };
        let Some(kind): Option<u32> = read_compact_u32(data, page_start) else {
            return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
        };
        state.previous = None;
        match kind {
            MACH_COMPACT_UNWIND_REGULAR_PAGE => {
                let (Some(entries_relative), Some(entry_count)): (Option<u16>, Option<u16>) = (
                    read_compact_u16(data, page_start.saturating_add(4)),
                    read_compact_u16(data, page_start.saturating_add(6)),
                ) else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                let Some(entries_start): Option<usize> =
                    page_start.checked_add(usize::from(entries_relative))
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                let Some(entries_end): Option<usize> = usize::from(entry_count)
                    .checked_mul(8)
                    .and_then(|size: usize| entries_start.checked_add(size))
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                if entry_count == 0 || usize::from(entries_relative) < 8 || entries_end > page_end {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                }
                for entry in 0..usize::from(entry_count) {
                    let Some(entry_offset): Option<usize> = entry
                        .checked_mul(8)
                        .and_then(|relative: usize| entries_start.checked_add(relative))
                    else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let Some(function_offset): Option<u32> = read_compact_u32(data, entry_offset)
                    else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let Some(encoding_offset): Option<usize> = entry_offset.checked_add(4) else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let Some(encoding): Option<u32> = read_compact_u32(data, encoding_offset)
                    else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    if let Err(error) = admit_compact_offset(
                        function_offset,
                        encoding,
                        current.function,
                        next.function,
                        image_base,
                        view,
                        seeds,
                        &mut state,
                    ) {
                        return CompactUnwindOutcome::failure(state.accepted, error);
                    }
                }
            }
            MACH_COMPACT_UNWIND_COMPRESSED_PAGE => {
                let (
                    Some(entries_relative),
                    Some(entry_count),
                    Some(encodings_relative),
                    Some(encodings_count),
                ): (Option<u16>, Option<u16>, Option<u16>, Option<u16>) = (
                    read_compact_u16(data, page_start.saturating_add(4)),
                    read_compact_u16(data, page_start.saturating_add(6)),
                    read_compact_u16(data, page_start.saturating_add(8)),
                    read_compact_u16(data, page_start.saturating_add(10)),
                )
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                let Some(entries_start): Option<usize> =
                    page_start.checked_add(usize::from(entries_relative))
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                let Some(encodings_start): Option<usize> =
                    page_start.checked_add(usize::from(encodings_relative))
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                let Some(entries_end): Option<usize> = usize::from(entry_count)
                    .checked_mul(4)
                    .and_then(|size: usize| entries_start.checked_add(size))
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                let Some(encodings_end): Option<usize> = usize::from(encodings_count)
                    .checked_mul(4)
                    .and_then(|size: usize| encodings_start.checked_add(size))
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                let Some(total_encodings): Option<u32> =
                    common_count.checked_add(u32::from(encodings_count))
                else {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                };
                if entry_count == 0
                    || usize::from(entries_relative) < 12
                    || usize::from(encodings_relative) < 12
                    || entries_end > page_end
                    || encodings_end > page_end
                    || total_encodings > 256
                {
                    return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
                }
                for entry in 0..usize::from(entry_count) {
                    let Some(entry_offset): Option<usize> = entry
                        .checked_mul(4)
                        .and_then(|relative: usize| entries_start.checked_add(relative))
                    else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let Some(packed): Option<u32> = read_compact_u32(data, entry_offset) else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let encoding_index: u32 = packed >> 24;
                    if encoding_index >= total_encodings {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    }
                    let raw_encoding_index: u32 = if encoding_index < common_count {
                        encoding_index
                    } else {
                        encoding_index - common_count
                    };
                    let Ok(resolved_encoding_index): core::result::Result<
                        usize,
                        core::num::TryFromIntError,
                    > = usize::try_from(raw_encoding_index) else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let encoding_base: usize = if encoding_index < common_count {
                        common_start
                    } else {
                        encodings_start
                    };
                    let Some(encoding_offset): Option<usize> = resolved_encoding_index
                        .checked_mul(4)
                        .and_then(|relative: usize| encoding_base.checked_add(relative))
                    else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let Some(encoding): Option<u32> = read_compact_u32(data, encoding_offset)
                    else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    let Some(function_offset): Option<u32> =
                        current.function.checked_add(packed & 0x00ff_ffff)
                    else {
                        return CompactUnwindOutcome::failure(
                            state.accepted,
                            CompactUnwindError::Entry,
                        );
                    };
                    if let Err(error) = admit_compact_offset(
                        function_offset,
                        encoding,
                        current.function,
                        next.function,
                        image_base,
                        view,
                        seeds,
                        &mut state,
                    ) {
                        return CompactUnwindOutcome::failure(state.accepted, error);
                    }
                }
            }
            _ => {
                return CompactUnwindOutcome::failure(state.accepted, CompactUnwindError::Page);
            }
        }
    }
    CompactUnwindOutcome::success(state.accepted)
}

fn macho_text_base(view: &ImageView<'_>) -> Option<u64> {
    let parsed: &object::File<'_> = view.file.as_ref()?;
    let mut base: Option<u64> = None;
    for segment in parsed.segments() {
        if segment.name().ok().flatten() != Some("__TEXT") {
            continue;
        }
        if base.replace(segment.address()).is_some() {
            return None;
        }
    }
    base
}

fn collect_macho_compact_unwind(view: &ImageView<'_>, image_base: u64, seeds: &mut SeedSet) {
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    let mut data: Option<&[u8]> = None;
    for section in parsed.sections() {
        if section.name().ok() != Some("__unwind_info")
            || section.segment_name().ok().flatten() != Some("__TEXT")
        {
            continue;
        }
        let Ok(section_data): core::result::Result<&[u8], object::Error> = section.data() else {
            return;
        };
        if data.replace(section_data).is_some() {
            return;
        }
    }
    let Some(data): Option<&[u8]> = data else {
        return;
    };
    let outcome: CompactUnwindOutcome = decode_macho_compact_unwind(data, image_base, view, seeds);
    dbg_kv("macho_compact_unwind_entries", || {
        outcome.accepted.to_string()
    });
    if let Some(error) = outcome.error {
        dbg_kv("macho_compact_unwind_error", || error.label().to_owned());
    }
}

fn decode_macho_function_starts(
    data: &[u8],
    image_base: u64,
    view: &ImageView<'_>,
    seeds: &mut SeedSet,
) {
    let mut address: u64 = image_base;
    let mut cursor: usize = 0;
    let mut count: usize = 0;
    while cursor < data.len() && count < MAX_SEEDS {
        let Ok((delta, consumed)): core::result::Result<(u64, usize), disrobe_bytes::LebError> =
            disrobe_bytes::read_uleb128_at(data, cursor)
        else {
            return;
        };
        if delta == 0 || consumed == 0 {
            return;
        }
        let Some(next_cursor): Option<usize> = cursor.checked_add(consumed) else {
            return;
        };
        let Some(next_address): Option<u64> = address.checked_add(delta) else {
            return;
        };
        if !view.is_candidate(next_address) {
            return;
        }
        seeds.admit(next_address, SeedOrigin::MachFunctionStarts);
        cursor = next_cursor;
        address = next_address;
        count = count.saturating_add(1);
    }
}

fn collect_macho_function_starts(
    bytes: &[u8],
    image_base: u64,
    view: &ImageView<'_>,
    seeds: &mut SeedSet,
) {
    let Ok(file): core::result::Result<
        object::read::macho::MachOFile64<'_, object::Endianness, &[u8]>,
        object::Error,
    > = object::read::macho::MachOFile64::parse(bytes) else {
        return;
    };
    let endian: object::Endianness = file.endian();
    let Ok(mut commands): core::result::Result<
        object::read::macho::LoadCommandIterator<'_, object::Endianness>,
        object::Error,
    > = file.macho_load_commands() else {
        return;
    };
    let mut function_starts: Option<(usize, usize)> = None;
    while let Ok(Some(command)) = commands.next() {
        let Ok(variant): core::result::Result<
            object::read::macho::LoadCommandVariant<'_, object::Endianness>,
            object::Error,
        > = command.variant() else {
            return;
        };
        match variant {
            object::read::macho::LoadCommandVariant::LinkeditData(linkedit)
                if command.cmd() == object::macho::LC_FUNCTION_STARTS =>
            {
                let Ok(start): core::result::Result<usize, core::num::TryFromIntError> =
                    usize::try_from(linkedit.dataoff.get(endian))
                else {
                    return;
                };
                let Ok(size): core::result::Result<usize, core::num::TryFromIntError> =
                    usize::try_from(linkedit.datasize.get(endian))
                else {
                    return;
                };
                function_starts = Some((start, size));
            }
            _ => {}
        }
    }
    let Some((start, size)): Option<(usize, usize)> = function_starts else {
        return;
    };
    let Some(end): Option<usize> = start.checked_add(size) else {
        return;
    };
    let Some(data): Option<&[u8]> = bytes.get(start..end) else {
        return;
    };
    decode_macho_function_starts(data, image_base, view, seeds);
}

fn decode_pe_arm64_pdata(data: &[u8], image_base: u64, view: &ImageView<'_>, seeds: &mut SeedSet) {
    let entry_count: usize = (data.len() / PE_ARM64_PDATA_RECORD_BYTES).min(MAX_UNWIND_ENTRIES);
    let Some(byte_len): Option<usize> = entry_count.checked_mul(PE_ARM64_PDATA_RECORD_BYTES) else {
        return;
    };
    let Some(table): Option<&[u8]> = data.get(..byte_len) else {
        return;
    };
    let mut reader: ByteReader<'_> = ByteReader::new(table);
    let mut previous_begin_rva: Option<u32> = None;
    for _ in 0..entry_count {
        let Ok(begin_rva): core::result::Result<u32, disrobe_bytes::ByteReadError> =
            reader.read_u32_le()
        else {
            return;
        };
        let Ok(unwind_data): core::result::Result<u32, disrobe_bytes::ByteReadError> =
            reader.read_u32_le()
        else {
            return;
        };
        if begin_rva == 0 || previous_begin_rva.is_some_and(|previous: u32| begin_rva <= previous) {
            return;
        }
        previous_begin_rva = Some(begin_rva);
        let Some(address): Option<u64> = image_base.checked_add(u64::from(begin_rva)) else {
            return;
        };
        let Some(entry): Option<PeArm64RuntimeEntry> =
            pe_arm64_runtime_entry(unwind_data, image_base, view)
        else {
            return;
        };
        let byte_len: u64 = match entry {
            PeArm64RuntimeEntry::Function { byte_len }
            | PeArm64RuntimeEntry::Fragment { byte_len } => byte_len,
        };
        if !view.is_candidate(address) || !view.contains_executable_extent(address, byte_len) {
            return;
        }
        if matches!(entry, PeArm64RuntimeEntry::Function { .. }) {
            seeds.admit(address, SeedOrigin::PePdata);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeArm64RuntimeEntry {
    Function { byte_len: u64 },
    Fragment { byte_len: u64 },
}

fn pe_arm64_runtime_entry(
    unwind_data: u32,
    image_base: u64,
    view: &ImageView<'_>,
) -> Option<PeArm64RuntimeEntry> {
    match unwind_data & 0x3 {
        0 => Some(PeArm64RuntimeEntry::Function {
            byte_len: pe_arm64_xdata_function_len(unwind_data, image_base, view)?,
        }),
        1 => Some(PeArm64RuntimeEntry::Function {
            byte_len: pe_arm64_packed_function_len(unwind_data)?,
        }),
        2 => Some(PeArm64RuntimeEntry::Fragment {
            byte_len: pe_arm64_packed_function_len(unwind_data)?,
        }),
        3 => None,
        _ => None,
    }
}

fn pe_arm64_packed_function_len(unwind_data: u32) -> Option<u64> {
    let byte_len: u64 = u64::from(unwind_data & 0x0000_1ffc);
    (byte_len != 0).then_some(byte_len)
}

fn pe_arm64_xdata_function_len(
    unwind_data: u32,
    image_base: u64,
    view: &ImageView<'_>,
) -> Option<u64> {
    let xdata_rva: u32 = unwind_data & !0x3;
    if xdata_rva == 0 {
        return None;
    }
    let xdata_address: u64 = image_base.checked_add(u64::from(xdata_rva))?;
    let header: u32 = view.word_at(xdata_address)?;
    let function_words: u32 = header & 0x0003_ffff;
    let version: u32 = (header >> 18) & 0x3;
    if function_words == 0 || version != 0 {
        return None;
    }
    let has_exception_handler: bool = header & 0x0010_0000 != 0;
    let epilogue_is_packed: bool = header & 0x0020_0000 != 0;
    let compact_counts: bool = header & 0xffc0_0000 != 0;
    let (header_words, epilogue_count, code_words): (usize, usize, usize) = if compact_counts {
        (
            1,
            usize::try_from((header >> 22) & 0x1f).ok()?,
            usize::try_from((header >> 27) & 0x1f).ok()?,
        )
    } else {
        let extension_address: u64 = xdata_address.checked_add(4)?;
        let extension: u32 = view.word_at(extension_address)?;
        if extension & 0xff00_0000 != 0 {
            return None;
        }
        (
            2,
            usize::try_from(extension & 0x0000_ffff).ok()?,
            usize::try_from((extension >> 16) & 0xff).ok()?,
        )
    };
    let scope_words: usize = if epilogue_is_packed {
        0
    } else {
        epilogue_count
    };
    let total_words: usize = header_words
        .checked_add(scope_words)?
        .checked_add(code_words)?
        .checked_add(usize::from(has_exception_handler))?;
    let last_word_index: usize = total_words.checked_sub(1)?;
    let last_word_offset: u64 = u64::try_from(last_word_index).ok()?.checked_mul(4)?;
    let last_word_address: u64 = xdata_address.checked_add(last_word_offset)?;
    view.word_at(last_word_address)?;
    u64::from(function_words).checked_mul(AARCH64_INSTRUCTION_ALIGNMENT)
}

fn collect_pe_arm64_pdata(bytes: &[u8], view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Ok(file): core::result::Result<object::read::pe::PeFile64<'_>, object::Error> =
        object::read::pe::PeFile64::parse(bytes)
    else {
        return;
    };
    let Some(directory): Option<&object::pe::ImageDataDirectory> =
        file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    else {
        return;
    };
    let Ok(data): core::result::Result<&[u8], object::Error> =
        directory.data(bytes, &file.section_table())
    else {
        return;
    };
    decode_pe_arm64_pdata(data, file.relative_address_base(), view, seeds);
}

fn decode_pe_arm64_tls_callbacks(data: &[u8], view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Some(directory): Option<&[u8]> = data.get(..PE64_TLS_DIRECTORY_BYTES) else {
        return;
    };
    let mut reader: ByteReader<'_> = ByteReader::new(directory);
    if reader.seek(24).is_err() {
        return;
    }
    let Ok(callback_array): core::result::Result<u64, disrobe_bytes::ByteReadError> =
        reader.read_u64_le()
    else {
        return;
    };
    if callback_array == 0 || callback_array % PE64_POINTER_BYTES != 0 {
        return;
    }
    for index in 0..MAX_PE_TLS_CALLBACKS {
        let Some(slot_offset): Option<u64> = u64::try_from(index)
            .ok()
            .and_then(|value: u64| value.checked_mul(PE64_POINTER_BYTES))
        else {
            return;
        };
        let Some(slot_address): Option<u64> = callback_array.checked_add(slot_offset) else {
            return;
        };
        let Some(callback): Option<u64> = view.qword_at(slot_address) else {
            return;
        };
        if callback == 0 {
            return;
        }
        if !view.is_candidate(callback) {
            return;
        }
        seeds.admit(callback, SeedOrigin::PeTlsCallback);
    }
}

fn collect_pe_arm64_tls_callbacks(bytes: &[u8], view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Ok(file): core::result::Result<object::read::pe::PeFile64<'_>, object::Error> =
        object::read::pe::PeFile64::parse(bytes)
    else {
        return;
    };
    let Some(directory): Option<&object::pe::ImageDataDirectory> =
        file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_TLS)
    else {
        return;
    };
    let Ok(data): core::result::Result<&[u8], object::Error> =
        directory.data(bytes, &file.section_table())
    else {
        return;
    };
    decode_pe_arm64_tls_callbacks(data, view, seeds);
}

pub(super) fn is_supported_pe_arm64(bytes: &[u8]) -> bool {
    let Ok(file): core::result::Result<object::read::pe::PeFile64<'_>, object::Error> =
        object::read::pe::PeFile64::parse(bytes)
    else {
        return false;
    };
    matches!(file.architecture(), object::Architecture::Aarch64)
        && file.sub_architecture().is_none()
        && file.is_little_endian()
        && ImageView::new_pe64(bytes).is_some()
}

fn admit_pointer_run(run: &mut Vec<u64>, view: &ImageView<'_>, seeds: &mut SeedSet) {
    let shaped_like_a_table: bool = run.len() >= MIN_POINTER_RUN;
    for address in &*run {
        let accepted: bool = if shaped_like_a_table {
            opens_a_function(view, *address) || follows_a_boundary(view, *address)
        } else {
            opens_a_function(view, *address) && follows_a_boundary(view, *address)
        };
        if accepted {
            seeds.admit(*address, SeedOrigin::DataPointer);
        }
    }
    run.clear();
}

pub(super) fn collect(native: &NativeFile, bytes: &[u8]) -> SeedSet {
    let mut seeds: SeedSet = SeedSet::default();
    if !matches!(native.arch, BinArch::Aarch64) || !matches!(native.endian, Endian::Little) {
        return seeds;
    }
    if matches!(native.format, NativeFormat::MachO64) {
        let view: ImageView<'_> = ImageView::new(bytes, None);
        if view.executable.is_empty() {
            return seeds;
        }
        collect_object_symbols(&view, &mut seeds);
        collect_exports(native, &view, &mut seeds);
        let image_base: Option<u64> = macho_text_base(&view);
        if view.has_linked_addresses() {
            collect_initializer_tables(&view, &mut seeds, MAX_POINTER_SLOTS, image_base);
        }
        if let Some(image_base) = image_base {
            collect_macho_function_starts(bytes, image_base, &view, &mut seeds);
            collect_macho_compact_unwind(&view, image_base, &mut seeds);
        }
        report_seeds(&seeds);
        return seeds;
    }
    if matches!(native.format, NativeFormat::Pe64) {
        if !is_supported_pe_arm64(bytes) {
            return seeds;
        }
        let Some(view): Option<ImageView<'_>> = ImageView::new_pe64(bytes) else {
            return seeds;
        };
        if view.executable.is_empty() {
            return seeds;
        }
        collect_object_symbols(&view, &mut seeds);
        collect_exports(native, &view, &mut seeds);
        collect_pe_arm64_pdata(bytes, &view, &mut seeds);
        collect_pe_arm64_tls_callbacks(bytes, &view, &mut seeds);
        report_seeds(&seeds);
        return seeds;
    }
    if !matches!(native.format, NativeFormat::Elf64) {
        return seeds;
    }
    let report: Option<ElfDynamicReport> = analyze(bytes);
    let view: ImageView<'_> = ImageView::new(bytes, report.as_ref());
    if view.executable.is_empty() {
        return seeds;
    }
    collect_object_symbols(&view, &mut seeds);
    collect_exports(native, &view, &mut seeds);
    if let Some(parsed) = report.as_ref() {
        collect_dynamic(parsed, &view, &mut seeds);
        collect_elf_plt_entries(parsed, &view, &mut seeds);
    }
    if view.has_linked_addresses() {
        collect_initializer_tables(&view, &mut seeds, MAX_POINTER_SLOTS, None);
    }
    collect_elf_eh_frame_hdr(&view, &mut seeds);
    collect_unwind_entries(&view, &mut seeds);
    collect_data_pointers(&view, &mut seeds);
    report_seeds(&seeds);
    seeds
}

fn report_seeds(seeds: &SeedSet) {
    dbg_section("aarch64-function-seeds");
    let counts: BTreeMap<SeedOrigin, usize> = seeds.counts();
    for (origin, count) in &counts {
        dbg_kv(origin.label(), || count.to_string());
    }
    dbg_kv("seed_total", || seeds.addresses().len().to_string());
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        CompactUnwindError, CompactUnwindOutcome, ExecutableRange, FileSectionReads, ImageView,
        MAX_AARCH64_PLT_ENTRIES, MAX_PE_TLS_CALLBACKS, MAX_SEEDS, MAX_UNWIND_ENTRIES,
        PE_ARM64_PDATA_RECORD_BYTES, PE64_TLS_DIRECTORY_BYTES, POINTER_BYTES, R_AARCH64_JUMP_SLOT,
        SeedOrigin, SeedSet, canonical_plt_stub_slot, canonical_plt0, collect,
        collect_elf_plt_entries, collect_initializer_tables, decode_elf_eh_frame_hdr,
        decode_macho_compact_unwind, decode_macho_function_starts, decode_pe_arm64_pdata,
        decode_pe_arm64_tls_callbacks, is_boundary_word, is_prologue_word,
    };

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use disrobe_binfmt::native::{NativeFile, parse_native};
    use object::{
        Architecture, BinaryFormat, Endianness, Object as _, ObjectSection as _, ObjectSymbol as _,
        SectionFlags, SectionKind, SymbolKind as ObjSymbolKind, write::Object as WriteObject,
    };

    use crate::elf::{
        DynamicSymbol, ElfClass, ElfData, ElfDynamicReport, RelocSource, Relocation, SymbolBind,
        SymbolType,
    };

    #[derive(Debug, Clone, Copy)]
    struct Fixture {
        stripped: &'static str,
        reference: &'static str,
        expected_starts: usize,
    }

    const UNWOUND_STATIC: Fixture = Fixture {
        stripped: "native/discovery/disc_aarch64.stripped.elf",
        reference: "native/discovery/disc_aarch64.unstripped.elf",
        expected_starts: 27,
    };

    const UNWOUND_SHARED: Fixture = Fixture {
        stripped: "native/discovery/disc_aarch64_shared.stripped.elf",
        reference: "native/discovery/disc_aarch64_shared.unstripped.elf",
        expected_starts: 25,
    };

    const PLAIN_STATIC: Fixture = Fixture {
        stripped: "native/discovery/disc_aarch64_nounwind.stripped.elf",
        reference: "native/discovery/disc_aarch64_nounwind.unstripped.elf",
        expected_starts: 27,
    };

    const ALL_FIXTURES: [Fixture; 3] = [UNWOUND_STATIC, UNWOUND_SHARED, PLAIN_STATIC];

    fn corpus_bytes(relative: &str) -> Vec<u8> {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(relative);
        std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "the graded fixture {} must be readable: {error}",
                path.display()
            )
        })
    }

    fn seeds_for(relative: &str) -> SeedSet {
        let bytes: Vec<u8> = corpus_bytes(relative);
        let native: NativeFile =
            parse_native(&bytes).expect("the graded fixture parses as a native image");
        collect(&native, &bytes)
    }

    fn reference_starts(unstripped: &[u8]) -> BTreeMap<u64, String> {
        let file: object::File<'_> =
            object::File::parse(unstripped).expect("the reference twin must parse");
        let text: BTreeSet<usize> = file
            .sections()
            .filter(|section: &object::Section<'_, '_>| {
                matches!(section.kind(), object::SectionKind::Text)
            })
            .map(|section: object::Section<'_, '_>| section.index().0)
            .collect();
        let mut starts: BTreeMap<u64, String> = BTreeMap::new();
        for symbol in file.symbols() {
            if !matches!(symbol.kind(), ObjSymbolKind::Text) {
                continue;
            }
            let object::SymbolSection::Section(index) = symbol.section() else {
                continue;
            };
            if !text.contains(&index.0) {
                continue;
            }
            let name: String = symbol.name().unwrap_or("<unnamed>").to_owned();
            starts.entry(symbol.address()).or_insert(name);
        }
        starts
    }

    fn per_source_recall(fixture: Fixture) -> BTreeMap<SeedOrigin, usize> {
        let truth: BTreeMap<u64, String> = reference_starts(&corpus_bytes(fixture.reference));
        assert_eq!(
            truth.len(),
            fixture.expected_starts,
            "{}: the committed reference twin changed shape",
            fixture.reference
        );
        let seeds: SeedSet = seeds_for(fixture.stripped);
        let mut per_source: BTreeMap<SeedOrigin, usize> = BTreeMap::new();
        for address in truth.keys() {
            for origin in seeds.origins_of(*address) {
                *per_source.entry(origin).or_insert(0) += 1;
            }
        }
        per_source
    }

    fn seeded_reference_starts(fixture: Fixture) -> BTreeSet<String> {
        let truth: BTreeMap<u64, String> = reference_starts(&corpus_bytes(fixture.reference));
        let seeds: SeedSet = seeds_for(fixture.stripped);
        truth
            .into_iter()
            .filter(|(address, _): &(u64, String)| !seeds.origins_of(*address).is_empty())
            .map(|(_, name): (u64, String)| name)
            .collect()
    }

    #[test]
    fn unwind_tables_seed_every_reference_start() {
        for fixture in [UNWOUND_STATIC, UNWOUND_SHARED] {
            let per_source: BTreeMap<SeedOrigin, usize> = per_source_recall(fixture);
            let unwind: usize = per_source
                .get(&SeedOrigin::UnwindEntry)
                .copied()
                .unwrap_or(0);
            let seeded: usize = seeded_reference_starts(fixture).len();
            println!(
                "{}: seeded {seeded}/{} with {per_source:?}",
                fixture.stripped, fixture.expected_starts
            );
            assert_eq!(
                seeded, fixture.expected_starts,
                "{}: every reference start must be seeded, got {per_source:?}",
                fixture.stripped
            );
            assert!(
                unwind + 1 >= fixture.expected_starts,
                "{}: the unwind table must name all but the entry point, got {per_source:?}",
                fixture.stripped
            );
        }
    }

    #[test]
    fn pointer_tables_seed_the_starts_an_image_without_unwind_data_would_lose() {
        let per_source: BTreeMap<SeedOrigin, usize> = per_source_recall(PLAIN_STATIC);
        println!("{}: {per_source:?}", PLAIN_STATIC.stripped);
        assert!(
            !per_source.contains_key(&SeedOrigin::UnwindEntry),
            "this fixture is built without unwind tables: {per_source:?}"
        );
        assert!(
            per_source.get(&SeedOrigin::InitArray).copied().unwrap_or(0) >= 1,
            "the init_array slot names a constructor: {per_source:?}"
        );
        assert!(
            per_source.get(&SeedOrigin::FiniArray).copied().unwrap_or(0) >= 1,
            "the fini_array slot names a destructor: {per_source:?}"
        );
        assert!(
            per_source
                .get(&SeedOrigin::DataPointer)
                .copied()
                .unwrap_or(0)
                >= 12,
            "the read-only dispatch tables name their targets: {per_source:?}"
        );
        let seeded: BTreeSet<String> = seeded_reference_starts(PLAIN_STATIC);
        for required in [
            "only_from_data",
            "also_only_from_data",
            "discovery_ctor",
            "discovery_dtor",
        ] {
            assert!(
                seeded.contains(required),
                "{required} has no incoming call and must come from a table: {seeded:?}"
            );
        }
    }

    #[test]
    fn a_shared_object_keeps_its_exported_starts_after_stripping() {
        let per_source: BTreeMap<SeedOrigin, usize> = per_source_recall(UNWOUND_SHARED);
        let exported: usize = per_source.get(&SeedOrigin::Export).copied().unwrap_or(0);
        let dynamic: usize = per_source
            .get(&SeedOrigin::DynamicSymbol)
            .copied()
            .unwrap_or(0);
        assert!(
            exported >= 3 && dynamic >= 3,
            "the three exported functions survive in .dynsym: {per_source:?}"
        );
    }

    #[test]
    fn every_seed_is_aligned_executable_and_tagged() {
        for fixture in ALL_FIXTURES {
            let seeds: SeedSet = seeds_for(fixture.stripped);
            let addresses: Vec<u64> = seeds.addresses();
            assert!(!addresses.is_empty(), "{}: no seeds", fixture.stripped);
            for address in &addresses {
                assert_eq!(
                    address % 4,
                    0,
                    "{}: {address:#x} is not aligned",
                    fixture.stripped
                );
                assert!(
                    !seeds.origins_of(*address).is_empty(),
                    "{}: {address:#x} carries no origin",
                    fixture.stripped
                );
            }
        }
    }

    fn canonical_eh_frame_header(count: u32, entries: &[(i32, i32)]) -> Vec<u8> {
        let mut data: Vec<u8> = vec![1, 0x1b, 0x03, 0x3b];
        data.extend_from_slice(&0xfc_i32.to_le_bytes());
        data.extend_from_slice(&count.to_le_bytes());
        for (start, fde) in entries {
            data.extend_from_slice(&start.to_le_bytes());
            data.extend_from_slice(&fde.to_le_bytes());
        }
        data
    }

    fn eh_frame_header_view() -> ImageView<'static> {
        ImageView {
            file: None,
            bytes: &[],
            executable: vec![ExecutableRange {
                start: 0x1000,
                end: 0x1100,
            }],
            segments: Vec::new(),
            file_section_reads: FileSectionReads::Allow,
        }
    }

    #[test]
    fn elf_eh_frame_header_retains_the_valid_prefix_of_a_truncated_table() {
        let mut data: Vec<u8> = canonical_eh_frame_header(3, &[(-0x1000, 0x100), (-0xffc, 0x110)]);
        data.extend_from_slice(&(-0xff8_i32).to_le_bytes());
        let view: ImageView<'_> = eh_frame_header_view();
        let mut seeds: SeedSet = SeedSet::default();

        decode_elf_eh_frame_hdr(&data, 0x2000, 0x2100, 0x2200, &view, &mut seeds);

        assert_eq!(seeds.addresses(), vec![0x1000, 0x1004]);
        assert_eq!(
            seeds.origins_of(0x1000),
            BTreeSet::from([SeedOrigin::ElfEhFrameHeader])
        );
    }

    #[test]
    fn elf_eh_frame_header_bounds_an_oversized_declared_count() {
        let data: Vec<u8> = canonical_eh_frame_header(u32::MAX, &[(-0x1000, 0x100)]);
        let view: ImageView<'_> = eh_frame_header_view();
        let mut seeds: SeedSet = SeedSet::default();

        decode_elf_eh_frame_hdr(&data, 0x2000, 0x2100, 0x2200, &view, &mut seeds);

        assert_eq!(seeds.addresses(), vec![0x1000]);
    }

    #[test]
    fn elf_eh_frame_header_stops_after_the_first_invalid_row() {
        let data: Vec<u8> =
            canonical_eh_frame_header(3, &[(-0x1000, 0x100), (-0xffd, 0x110), (-0xff8, 0x120)]);
        let view: ImageView<'_> = eh_frame_header_view();
        let mut seeds: SeedSet = SeedSet::default();

        decode_elf_eh_frame_hdr(&data, 0x2000, 0x2100, 0x2200, &view, &mut seeds);

        assert_eq!(seeds.addresses(), vec![0x1000]);
    }

    #[test]
    fn elf_eh_frame_header_rejects_unsupported_pointer_encodings() {
        for index in 0..3 {
            let mut data: Vec<u8> = canonical_eh_frame_header(1, &[(-0x1000, 0x100)]);
            data[index + 1] = 0xff;
            let view: ImageView<'_> = eh_frame_header_view();
            let mut seeds: SeedSet = SeedSet::default();

            decode_elf_eh_frame_hdr(&data, 0x2000, 0x2100, 0x2200, &view, &mut seeds);

            assert!(seeds.addresses().is_empty(), "encoding index {index}");
        }
    }

    #[test]
    fn elf_eh_frame_header_abstains_from_relocatable_objects() {
        let mut bytes: Vec<u8> = corpus_bytes(UNWOUND_STATIC.stripped);
        let linked_native: NativeFile =
            parse_native(&bytes).expect("the linked AArch64 ELF must parse");
        let linked: SeedSet = collect(&linked_native, &bytes);
        assert!(
            linked
                .counts()
                .get(&SeedOrigin::ElfEhFrameHeader)
                .is_some_and(|count: &usize| *count > 0),
            "the control image must carry a populated .eh_frame_hdr"
        );
        bytes[16..18].copy_from_slice(&object::elf::ET_REL.to_le_bytes());
        let parsed: object::File<'_> =
            object::File::parse(bytes.as_slice()).expect("the ET_REL view must parse");
        assert_eq!(parsed.kind(), object::ObjectKind::Relocatable);
        let native: NativeFile =
            parse_native(&bytes).expect("the ET_REL view must reach discovery");

        let seeds: SeedSet = collect(&native, &bytes);

        assert_eq!(seeds.counts().get(&SeedOrigin::ElfEhFrameHeader), None);
    }

    #[test]
    fn no_seed_lands_outside_the_reference_function_set() {
        for fixture in ALL_FIXTURES {
            let truth: BTreeMap<u64, String> = reference_starts(&corpus_bytes(fixture.reference));
            let seeds: SeedSet = seeds_for(fixture.stripped);
            let strays: Vec<u64> = seeds
                .addresses()
                .into_iter()
                .filter(|address: &u64| !truth.contains_key(address))
                .collect();
            assert!(
                strays.is_empty(),
                "{}: seeds outside the reference twin: {strays:#x?}",
                fixture.stripped
            );
        }
    }

    #[test]
    fn seed_collection_is_deterministic() {
        for fixture in ALL_FIXTURES {
            let first: Vec<u64> = seeds_for(fixture.stripped).addresses();
            let second: Vec<u64> = seeds_for(fixture.stripped).addresses();
            assert_eq!(
                first, second,
                "{}: seed collection must repeat byte for byte",
                fixture.stripped
            );
        }
    }

    const ELF_PLT0_WORDS: [u32; 8] = [
        0xA9BF_7BF0,
        0x9000_0010,
        0xF940_0E11,
        0x9100_6210,
        0xD61F_0220,
        0xD503_201F,
        0xD503_201F,
        0xD503_201F,
    ];

    const ELF_PLT_STUB_18: [u32; 4] = [0x9000_0010, 0xF940_0E11, 0x9100_6210, 0xD61F_0220];

    const ELF_PLT_STUB_20: [u32; 4] = [0x9000_0010, 0xF940_1211, 0x9100_8210, 0xD61F_0220];

    const ELF_PLT_STUB_28: [u32; 4] = [0x9000_0010, 0xF940_1611, 0x9100_A210, 0xD61F_0220];

    fn words_bytes(words: &[u32]) -> Vec<u8> {
        words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect()
    }

    fn elf_plt_section(stubs: &[[u32; 4]]) -> Vec<u8> {
        let mut data: Vec<u8> = words_bytes(&ELF_PLT0_WORDS);
        for stub in stubs {
            data.extend_from_slice(&words_bytes(stub));
        }
        data
    }

    fn elf_plt_object(data: &[u8]) -> Vec<u8> {
        let mut object: WriteObject<'_> =
            WriteObject::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
        let plt: object::write::SectionId =
            object.add_section(Vec::new(), b".plt".to_vec(), SectionKind::Text);
        let _: u64 = object.append_section_data(plt, data, 16);
        object.write().expect("the ELF PLT fixture must serialize")
    }

    fn elf_plt_symbol(name: &str) -> DynamicSymbol {
        DynamicSymbol {
            name: name.to_owned(),
            value: 0,
            size: 0,
            bind: SymbolBind::Global,
            sym_type: SymbolType::Func,
            defined: false,
        }
    }

    fn elf_plt_relocation(
        offset: u64,
        r_type: u32,
        symbol_index: u32,
        source: RelocSource,
    ) -> Relocation {
        Relocation {
            offset,
            r_type,
            symbol_index,
            addend: 0,
            symbol_name: None,
            source,
        }
    }

    fn elf_plt_report(
        symbols: Vec<DynamicSymbol>,
        relocations: Vec<Relocation>,
    ) -> ElfDynamicReport {
        ElfDynamicReport {
            class: ElfClass::Elf64,
            data: ElfData::Little,
            entry: 0,
            segments: Vec::new(),
            interpreter: None,
            needed: Vec::new(),
            soname: None,
            rpath: None,
            runpath: None,
            init: None,
            fini: None,
            init_array: Vec::new(),
            fini_array: Vec::new(),
            dynamic_entry_count: 0,
            symbol_count_source: None,
            symbols,
            relocations,
            notes: Vec::new(),
        }
    }

    fn collect_elf_plt_fixture(
        bytes: &[u8],
        report: &ElfDynamicReport,
        executable_end: Option<u64>,
    ) -> SeedSet {
        let mut view: ImageView<'_> = ImageView::new(bytes, Some(report));
        if let Some(end) = executable_end {
            view.executable = vec![ExecutableRange { start: 0, end }];
        }
        let mut seeds: SeedSet = SeedSet::default();
        collect_elf_plt_entries(report, &view, &mut seeds);
        seeds
    }

    #[test]
    fn elf_plt_structural_decoders_reject_corruption_truncation_and_overflow() {
        let plt0: Vec<u8> = words_bytes(&ELF_PLT0_WORDS);
        assert!(canonical_plt0(&plt0));
        for length in [0_usize, 4, 8, 12, 16] {
            assert!(!canonical_plt0(&plt0[..length]), "length {length}");
        }
        let mut corrupted_plt0: Vec<u8> = plt0;
        corrupted_plt0[16..20].copy_from_slice(&0xD503_201F_u32.to_le_bytes());
        assert!(!canonical_plt0(&corrupted_plt0));

        let stub: Vec<u8> = words_bytes(&ELF_PLT_STUB_18);
        assert_eq!(canonical_plt_stub_slot(0x20, &stub), Some(0x18));
        for length in [0_usize, 4, 8, 12] {
            assert_eq!(
                canonical_plt_stub_slot(0x20, &stub[..length]),
                None,
                "length {length}"
            );
        }
        let mut corrupted_stub: Vec<u8> = stub;
        corrupted_stub[12..16].copy_from_slice(&0xD503_201F_u32.to_le_bytes());
        assert_eq!(canonical_plt_stub_slot(0x20, &corrupted_stub), None);

        let overflowing_stub: Vec<u8> =
            words_bytes(&[0xB000_0010, 0xF940_0E11, 0x9100_6210, 0xD61F_0220]);
        assert_eq!(canonical_plt_stub_slot(u64::MAX, &overflowing_stub), None);
    }

    #[test]
    fn elf_plt_collection_tags_origins_and_preserves_only_valid_stub_prefixes() {
        let report: ElfDynamicReport = elf_plt_report(
            vec![elf_plt_symbol("alpha"), elf_plt_symbol("beta")],
            vec![
                elf_plt_relocation(0x18, R_AARCH64_JUMP_SLOT, 0, RelocSource::JmpRel),
                elf_plt_relocation(0x20, R_AARCH64_JUMP_SLOT, 1, RelocSource::JmpRel),
            ],
        );
        let complete: Vec<u8> =
            elf_plt_object(&elf_plt_section(&[ELF_PLT_STUB_18, ELF_PLT_STUB_20]));
        let seeds: SeedSet = collect_elf_plt_fixture(&complete, &report, None);
        assert_eq!(seeds.addresses(), vec![0x20, 0x30]);
        for address in [0x20_u64, 0x30] {
            assert_eq!(
                seeds.origins_of(address),
                BTreeSet::from([SeedOrigin::ElfPlt]),
                "address {address:#x}"
            );
        }

        let mut corrupt_data: Vec<u8> = elf_plt_section(&[ELF_PLT_STUB_18, ELF_PLT_STUB_20]);
        corrupt_data[60..64].copy_from_slice(&0xD503_201F_u32.to_le_bytes());
        let corrupt: Vec<u8> = elf_plt_object(&corrupt_data);
        assert_eq!(
            collect_elf_plt_fixture(&corrupt, &report, None).addresses(),
            vec![0x20]
        );

        let mut truncated_data: Vec<u8> = elf_plt_section(&[ELF_PLT_STUB_18, ELF_PLT_STUB_20]);
        truncated_data.truncate(56);
        let truncated: Vec<u8> = elf_plt_object(&truncated_data);
        assert_eq!(
            collect_elf_plt_fixture(&truncated, &report, None).addresses(),
            vec![0x20]
        );

        assert_eq!(
            collect_elf_plt_fixture(&complete, &report, Some(0x38)).addresses(),
            vec![0x20]
        );
    }

    #[test]
    fn elf_plt_collection_rejects_invalid_symbols_and_non_jump_slots() {
        let one_stub: Vec<u8> = elf_plt_object(&elf_plt_section(&[ELF_PLT_STUB_18]));
        for report in [
            elf_plt_report(
                vec![elf_plt_symbol("alpha")],
                vec![elf_plt_relocation(
                    0x18,
                    R_AARCH64_JUMP_SLOT,
                    1,
                    RelocSource::JmpRel,
                )],
            ),
            elf_plt_report(
                vec![elf_plt_symbol("")],
                vec![elf_plt_relocation(
                    0x18,
                    R_AARCH64_JUMP_SLOT,
                    0,
                    RelocSource::JmpRel,
                )],
            ),
        ] {
            assert!(
                collect_elf_plt_fixture(&one_stub, &report, None)
                    .addresses()
                    .is_empty()
            );
        }

        let mixed: Vec<u8> = elf_plt_object(&elf_plt_section(&[
            ELF_PLT_STUB_18,
            ELF_PLT_STUB_20,
            ELF_PLT_STUB_28,
        ]));
        let report: ElfDynamicReport = elf_plt_report(
            vec![elf_plt_symbol("alpha")],
            vec![
                elf_plt_relocation(0x18, R_AARCH64_JUMP_SLOT, 0, RelocSource::JmpRel),
                elf_plt_relocation(0x20, 1027, 0, RelocSource::JmpRel),
                elf_plt_relocation(0x28, R_AARCH64_JUMP_SLOT, 0, RelocSource::Rela),
            ],
        );
        let seeds: SeedSet = collect_elf_plt_fixture(&mixed, &report, None);
        assert_eq!(seeds.addresses(), vec![0x20]);
        assert_eq!(seeds.origins_of(0x20), BTreeSet::from([SeedOrigin::ElfPlt]));
    }

    #[test]
    fn elf_plt_scan_stops_at_its_entry_limit() {
        for (stub_count, expected_count) in [
            (MAX_AARCH64_PLT_ENTRIES, MAX_AARCH64_PLT_ENTRIES),
            (MAX_AARCH64_PLT_ENTRIES + 1, MAX_AARCH64_PLT_ENTRIES),
        ] {
            let stubs: Vec<[u32; 4]> = vec![ELF_PLT_STUB_18; stub_count];
            let bytes: Vec<u8> = elf_plt_object(&elf_plt_section(&stubs));
            let section_bytes: usize = 32 + stub_count * 16;
            let page_count: usize = section_bytes.div_ceil(4096);
            let relocations: Vec<Relocation> = (0..page_count)
                .map(|page: usize| {
                    let page_address: u64 =
                        u64::try_from(page).expect("the test page index fits u64") * 4096;
                    elf_plt_relocation(
                        page_address + 0x18,
                        R_AARCH64_JUMP_SLOT,
                        0,
                        RelocSource::JmpRel,
                    )
                })
                .collect();
            let report: ElfDynamicReport =
                elf_plt_report(vec![elf_plt_symbol("alpha")], relocations);

            let seeds: SeedSet = collect_elf_plt_fixture(&bytes, &report, None);

            assert_eq!(seeds.addresses().len(), expected_count, "{stub_count}");
            assert_eq!(
                seeds.addresses().last().copied(),
                Some(
                    0x20 + (u64::try_from(expected_count).expect("the test count fits u64") - 1)
                        * 16
                ),
                "{stub_count}"
            );
        }
    }

    fn decode_function_starts(data: &[u8]) -> SeedSet {
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &[],
            executable: vec![ExecutableRange {
                start: 0x1000,
                end: 0x1100,
            }],
            segments: Vec::new(),
            file_section_reads: FileSectionReads::Allow,
        };
        let mut seeds: SeedSet = SeedSet::default();
        decode_macho_function_starts(data, 0x1000, &view, &mut seeds);
        seeds
    }

    fn push_u16(data: &mut Vec<u8>, value: u16) {
        data.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(data: &mut Vec<u8>, value: u32) {
        data.extend_from_slice(&value.to_le_bytes());
    }

    fn compact_unwind_page(kind: u32, entries: &[u32], common_count: u32) -> Vec<u8> {
        let page_offset: u32 = 56;
        let mut data: Vec<u8> = Vec::new();
        push_u32(&mut data, 1);
        push_u32(&mut data, 28);
        push_u32(&mut data, common_count);
        push_u32(&mut data, 32);
        push_u32(&mut data, 0);
        push_u32(&mut data, 32);
        push_u32(&mut data, 2);
        for _ in 0..common_count {
            push_u32(&mut data, 0x0300_0000);
        }
        data.resize(32, 0);
        push_u32(&mut data, 0);
        push_u32(&mut data, page_offset);
        push_u32(&mut data, 0);
        push_u32(&mut data, 0x40);
        push_u32(&mut data, 0);
        push_u32(&mut data, 0);
        data.resize(page_offset as usize, 0);
        push_u32(&mut data, kind);
        match kind {
            2 => {
                push_u16(&mut data, 8);
                push_u16(&mut data, entries.len() as u16);
                for function_offset in entries {
                    push_u32(&mut data, *function_offset);
                    push_u32(&mut data, 0x0300_0000);
                }
            }
            3 => {
                push_u16(&mut data, 12);
                push_u16(&mut data, entries.len() as u16);
                push_u16(&mut data, 12_u16.saturating_add((entries.len() as u16) * 4));
                push_u16(&mut data, 0);
                for packed in entries {
                    push_u32(&mut data, *packed);
                }
            }
            _ => {}
        }
        data
    }

    fn decode_compact_unwind(data: &[u8]) -> (SeedSet, CompactUnwindOutcome) {
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &[],
            executable: vec![ExecutableRange {
                start: 0x1000,
                end: 0x1100,
            }],
            segments: Vec::new(),
            file_section_reads: FileSectionReads::Allow,
        };
        let mut seeds: SeedSet = SeedSet::default();
        let outcome: CompactUnwindOutcome =
            decode_macho_compact_unwind(data, 0x1000, &view, &mut seeds);
        (seeds, outcome)
    }

    fn clear_macho_symbols(bytes: &mut [u8]) {
        let ncmds: usize =
            u32::from_le_bytes(bytes[16..20].try_into().expect("Mach header ncmds")) as usize;
        let mut cursor: usize = 32;
        let mut cleared: bool = false;
        for _ in 0..ncmds {
            let header_end: usize = cursor.checked_add(8).expect("bounded load header");
            let header: &[u8] = bytes
                .get(cursor..header_end)
                .expect("load command header must be in the fixture");
            let cmd: u32 = u32::from_le_bytes(header[..4].try_into().expect("load command id"));
            let cmdsize: usize =
                u32::from_le_bytes(header[4..8].try_into().expect("load command size")) as usize;
            assert!(cmdsize >= 8, "load command must include its header");
            let command_end: usize = cursor
                .checked_add(cmdsize)
                .expect("bounded load command size");
            assert!(
                command_end <= bytes.len(),
                "load command must stay in the fixture"
            );
            if cmd == object::macho::LC_SYMTAB {
                assert!(cmdsize >= 16, "LC_SYMTAB must contain its symbol count");
                bytes[cursor + 12..cursor + 16].copy_from_slice(&0_u32.to_le_bytes());
                cleared = true;
            } else if cmd == object::macho::LC_DYSYMTAB {
                bytes[header_end..command_end].fill(0);
            }
            cursor = command_end;
        }
        assert!(cleared, "the real fixture must carry LC_SYMTAB");
    }

    fn assert_no_macho_start_metadata(bytes: &[u8], reference: &object::File<'_>) {
        assert!(
            reference
                .sections()
                .all(|section: object::Section<'_, '_>| {
                    !matches!(section.name().ok(), Some("__unwind_info" | "__eh_frame"))
                }),
            "the initializer fixture must not carry unwind function starts"
        );
        let macho: object::read::macho::MachOFile64<'_, object::Endianness, &[u8]> =
            object::read::macho::MachOFile64::parse(bytes)
                .expect("the linked Mach-O header must parse");
        let mut commands: object::read::macho::LoadCommandIterator<'_, object::Endianness> = macho
            .macho_load_commands()
            .expect("the linked Mach-O load commands must parse");
        while let Some(command) = commands
            .next()
            .expect("the linked Mach-O load command must parse")
        {
            assert_ne!(
                command.cmd(),
                object::macho::LC_FUNCTION_STARTS,
                "the initializer fixture must not carry LC_FUNCTION_STARTS"
            );
        }
    }

    fn macho_pointer_sections(section_type: u32, sections: &[&[u8]]) -> Vec<u8> {
        let mut object: WriteObject<'_> = WriteObject::new(
            BinaryFormat::MachO,
            Architecture::Aarch64,
            Endianness::Little,
        );
        for (index, data) in sections.iter().enumerate() {
            let section: object::write::SectionId = object.add_section(
                b"custom".to_vec(),
                format!("renamed{index}").into_bytes(),
                SectionKind::Data,
            );
            object.section_mut(section).flags = SectionFlags::MachO {
                flags: section_type,
            };
            let _: u64 = object.append_section_data(section, data, 8);
        }
        object.write().expect("the Mach-O table must serialize")
    }

    fn relocatable_macho_initializer() -> Vec<u8> {
        let mut object: WriteObject<'_> = WriteObject::new(
            BinaryFormat::MachO,
            Architecture::Aarch64,
            Endianness::Little,
        );
        let text: object::write::SectionId =
            object.section_id(object::write::StandardSection::Text);
        let _: u64 =
            object.append_section_data(text, &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6], 4);
        let initializer: object::write::SectionId = object.add_section(
            b"__DATA".to_vec(),
            b"__mod_init_func".to_vec(),
            SectionKind::Data,
        );
        object.section_mut(initializer).flags = SectionFlags::MachO {
            flags: object::macho::S_MOD_INIT_FUNC_POINTERS,
        };
        let _: u64 = object.append_section_data(initializer, &4_u64.to_le_bytes(), 8);
        object
            .write()
            .expect("the relocatable Mach-O initializer must serialize")
    }

    #[test]
    fn compact_unwind_regular_and_compressed_pages_recover_exact_starts() {
        for (kind, entries) in [(2, vec![0, 4]), (3, vec![0, 4])] {
            let data: Vec<u8> = compact_unwind_page(kind, &entries, 1);
            let (seeds, outcome): (SeedSet, CompactUnwindOutcome) = decode_compact_unwind(&data);
            assert_eq!(outcome, CompactUnwindOutcome::success(2), "kind {kind}");
            assert_eq!(seeds.addresses(), vec![0x1000, 0x1004], "kind {kind}");
        }
    }

    #[test]
    fn compact_unwind_excludes_ranges_that_are_not_function_starts() {
        let mut regular: Vec<u8> = compact_unwind_page(2, &[0, 4], 1);
        regular[76..80].copy_from_slice(&0x8000_0000_u32.to_le_bytes());

        let mut compressed_common: Vec<u8> = compact_unwind_page(3, &[0, 0x0100_0004], 1);
        compressed_common[28..32].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
        compressed_common[66..68].copy_from_slice(&1_u16.to_le_bytes());
        push_u32(&mut compressed_common, 0x0300_0000);

        let mut compressed_local: Vec<u8> = compact_unwind_page(3, &[0, 0x0100_0004], 1);
        compressed_local[66..68].copy_from_slice(&1_u16.to_le_bytes());
        push_u32(&mut compressed_local, 0x8000_0000);

        for (name, data, expected) in [
            ("regular", regular, vec![0x1000]),
            ("compressed common", compressed_common, vec![0x1004]),
            ("compressed local", compressed_local, vec![0x1000]),
        ] {
            let (seeds, outcome): (SeedSet, CompactUnwindOutcome) = decode_compact_unwind(&data);
            assert_eq!(outcome, CompactUnwindOutcome::success(1), "{name}");
            assert_eq!(seeds.addresses(), expected, "{name}");
        }
    }

    #[test]
    fn compact_unwind_refuses_invalid_headers_before_admission() {
        let mut unsupported: Vec<u8> = compact_unwind_page(3, &[0], 1);
        unsupported[..4].copy_from_slice(&2_u32.to_le_bytes());
        let mut excessive_indices: Vec<u8> = compact_unwind_page(3, &[0], 1);
        excessive_indices[24..28].copy_from_slice(
            &(u32::try_from(MAX_UNWIND_ENTRIES).expect("the seed cap fits u32") + 2).to_le_bytes(),
        );
        for (name, data, error) in [
            (
                "truncated",
                unsupported[..20].to_vec(),
                CompactUnwindError::Header,
            ),
            ("version", unsupported, CompactUnwindError::Version),
            ("index cap", excessive_indices, CompactUnwindError::Index),
        ] {
            let (seeds, outcome): (SeedSet, CompactUnwindOutcome) = decode_compact_unwind(&data);
            assert!(seeds.addresses().is_empty(), "{name}");
            assert_eq!(outcome.error, Some(error), "{name}");
            assert_eq!(outcome.accepted, 0, "{name}");
        }
    }

    #[test]
    fn compact_unwind_refuses_malformed_indices_and_pages() {
        let mut missing_sentinel: Vec<u8> = compact_unwind_page(3, &[0], 1);
        missing_sentinel[48..52].copy_from_slice(&60_u32.to_le_bytes());
        let mut outside_page: Vec<u8> = compact_unwind_page(3, &[0], 1);
        let outside_offset: u32 =
            u32::try_from(outside_page.len()).expect("the test page fits u32") + 4;
        outside_page[36..40].copy_from_slice(&outside_offset.to_le_bytes());
        let mut one_index: Vec<u8> = compact_unwind_page(3, &[0], 1);
        one_index[24..28].copy_from_slice(&1_u32.to_le_bytes());
        let mut truncated_regular: Vec<u8> = compact_unwind_page(2, &[0, 4], 1);
        truncated_regular.truncate(truncated_regular.len() - 4);
        let mut invalid_local_encodings: Vec<u8> = compact_unwind_page(3, &[0, 4], 1);
        invalid_local_encodings[66..68].copy_from_slice(&1_u16.to_le_bytes());
        let unknown_page: Vec<u8> = compact_unwind_page(9, &[], 1);
        let empty_page: Vec<u8> = compact_unwind_page(3, &[], 1);
        for (name, data, error) in [
            ("sentinel", missing_sentinel, CompactUnwindError::Index),
            ("page extent", outside_page, CompactUnwindError::Index),
            ("missing index", one_index, CompactUnwindError::Index),
            (
                "regular extent",
                truncated_regular,
                CompactUnwindError::Page,
            ),
            (
                "local encodings",
                invalid_local_encodings,
                CompactUnwindError::Page,
            ),
            ("page kind", unknown_page, CompactUnwindError::Page),
            ("empty page", empty_page, CompactUnwindError::Page),
        ] {
            let (seeds, outcome): (SeedSet, CompactUnwindOutcome) = decode_compact_unwind(&data);
            assert!(seeds.addresses().is_empty(), "{name}");
            assert_eq!(outcome, CompactUnwindOutcome::failure(0, error), "{name}");
        }
    }

    #[test]
    fn compact_unwind_preserves_a_valid_prefix_on_entry_corruption() {
        let mut outside: Vec<u8> = compact_unwind_page(3, &[0, 0x104], 1);
        outside[44..48].copy_from_slice(&0x200_u32.to_le_bytes());
        let cases: [(&str, Vec<u8>, CompactUnwindError); 3] = [
            (
                "encoding",
                compact_unwind_page(3, &[0, 0x0200_0004], 1),
                CompactUnwindError::Entry,
            ),
            (
                "unaligned",
                compact_unwind_page(3, &[0, 2], 1),
                CompactUnwindError::Address,
            ),
            ("outside", outside, CompactUnwindError::Address),
        ];
        for (name, data, error) in cases {
            let (seeds, outcome): (SeedSet, CompactUnwindOutcome) = decode_compact_unwind(&data);
            assert_eq!(seeds.addresses(), vec![0x1000], "{name}");
            assert_eq!(outcome, CompactUnwindOutcome::failure(1, error), "{name}");
        }
    }

    #[test]
    fn compact_unwind_refuses_image_base_overflow() {
        let mut data: Vec<u8> = compact_unwind_page(3, &[0], 1);
        data[32..36].copy_from_slice(&4_u32.to_le_bytes());
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &[],
            executable: vec![ExecutableRange {
                start: 0,
                end: u64::MAX,
            }],
            segments: Vec::new(),
            file_section_reads: FileSectionReads::Allow,
        };
        let mut seeds: SeedSet = SeedSet::default();
        let outcome: CompactUnwindOutcome =
            decode_macho_compact_unwind(&data, u64::MAX, &view, &mut seeds);
        assert!(seeds.addresses().is_empty());
        assert_eq!(
            outcome,
            CompactUnwindOutcome::failure(0, CompactUnwindError::Address)
        );
    }

    #[test]
    fn malformed_macho_function_starts_preserve_only_the_valid_prefix() {
        let cases: [(&str, Vec<u8>); 4] = [
            ("truncated", vec![4, 4, 0x80]),
            ("overflow", [vec![4, 4], vec![0xff; 10], vec![2]].concat()),
            ("unaligned", vec![4, 4, 2]),
            ("outside text", vec![4, 4, 0x80, 0x02]),
        ];
        for (name, data) in cases {
            let seeds: SeedSet = decode_function_starts(&data);
            assert_eq!(seeds.addresses(), vec![0x1004, 0x1008], "{name}");
            for address in seeds.addresses() {
                assert_eq!(
                    seeds.origins_of(address),
                    BTreeSet::from([SeedOrigin::MachFunctionStarts]),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn macho_function_start_terminator_ignores_padding() {
        let seeds: SeedSet = decode_function_starts(&[4, 0, 4, 4]);
        assert_eq!(seeds.addresses(), vec![0x1004]);
    }

    #[test]
    fn macho_function_starts_match_the_independent_text_symbol_table() {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus/mobile/macho-mac/SwiftHello.original");
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        let native: NativeFile =
            parse_native(&bytes).expect("the tracked arm64 Mach-O fixture must parse");
        let file: object::File<'_> =
            object::File::parse(bytes.as_slice()).expect("the symbol reference must parse");
        let expected: BTreeSet<u64> = file
            .symbols()
            .filter(|symbol: &object::Symbol<'_, '_>| {
                matches!(symbol.kind(), ObjSymbolKind::Text)
                    && !symbol.is_undefined()
                    && symbol
                        .name()
                        .is_ok_and(|name: &str| name != "__mh_execute_header")
            })
            .map(|symbol: object::Symbol<'_, '_>| symbol.address())
            .collect();
        assert_eq!(expected.len(), 46, "the tracked symbol reference changed");
        let seeds: SeedSet = collect(&native, &bytes);
        let recovered: BTreeSet<u64> = seeds
            .addresses()
            .into_iter()
            .filter(|address: &u64| {
                seeds
                    .origins_of(*address)
                    .contains(&SeedOrigin::MachFunctionStarts)
            })
            .collect();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn macho_compact_unwind_matches_the_llvm_function_index() {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus/mobile/macho-mac/SwiftHello.original");
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        let native: NativeFile = parse_native(&bytes).expect("the arm64 Mach-O fixture must parse");
        let expected_offsets: [u64; 24] = [
            0x0f68, 0x1154, 0x123c, 0x1244, 0x1354, 0x1374, 0x15d4, 0x1654, 0x1724, 0x1744, 0x1854,
            0x188c, 0x1980, 0x19a0, 0x1a90, 0x1acc, 0x1af4, 0x1be4, 0x1c14, 0x1c50, 0x200c, 0x204c,
            0x209c, 0x20a0,
        ];
        let expected: BTreeSet<u64> = expected_offsets
            .into_iter()
            .map(|offset: u64| 0x1_0000_0000_u64 + offset)
            .collect();
        let seeds: SeedSet = collect(&native, &bytes);
        let recovered: BTreeSet<u64> = seeds
            .addresses()
            .into_iter()
            .filter(|address: &u64| {
                seeds
                    .origins_of(*address)
                    .contains(&SeedOrigin::MachCompactUnwind)
            })
            .collect();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn macho_module_initializer_arrays_match_the_llvm_linked_symbols() {
        let bytes: &[u8] = include_bytes!("../../tests/fixtures/macho_aarch64_initializers.macho");
        let native: NativeFile = parse_native(bytes).expect("the arm64 Mach-O fixture must parse");
        let expected: [(u64, SeedOrigin); 2] = [
            (0x1_0000_0410, SeedOrigin::InitArray),
            (0x1_0000_0420, SeedOrigin::FiniArray),
        ];
        let reference: object::File<'_> =
            object::File::parse(bytes).expect("the linked symbol reference must parse");
        assert_no_macho_start_metadata(bytes, &reference);
        let symbols: BTreeMap<String, u64> = reference
            .symbols()
            .filter_map(|symbol: object::Symbol<'_, '_>| {
                let name: &str = symbol.name().ok()?;
                matches!(name, "_initialize_probe" | "_terminate_probe")
                    .then(|| (name.to_owned(), symbol.address()))
            })
            .collect();
        assert_eq!(symbols.get("_initialize_probe"), Some(&expected[0].0));
        assert_eq!(symbols.get("_terminate_probe"), Some(&expected[1].0));
        let linked_slots: BTreeMap<SeedOrigin, u64> = reference
            .sections()
            .filter_map(|section: object::Section<'_, '_>| {
                let object::SectionFlags::MachO { flags } = section.flags() else {
                    return None;
                };
                let origin: SeedOrigin = match flags & object::macho::SECTION_TYPE {
                    object::macho::S_MOD_INIT_FUNC_POINTERS => SeedOrigin::InitArray,
                    object::macho::S_MOD_TERM_FUNC_POINTERS => SeedOrigin::FiniArray,
                    _ => return None,
                };
                let data: &[u8] = section.data().ok()?;
                let raw: [u8; POINTER_BYTES] = data.try_into().ok()?;
                Some((origin, u64::from_le_bytes(raw)))
            })
            .collect();
        assert_eq!(
            linked_slots.get(&SeedOrigin::InitArray),
            Some(&expected[0].0)
        );
        assert_eq!(
            linked_slots.get(&SeedOrigin::FiniArray),
            Some(&expected[1].0)
        );

        let seeds: SeedSet = collect(&native, bytes);
        for (address, origin) in expected {
            assert!(
                seeds.origins_of(address).contains(&origin),
                "{origin:?} must seed {address:#x}"
            );
        }
        assert_eq!(seeds.counts().get(&SeedOrigin::InitArray), Some(&1));
        assert_eq!(seeds.counts().get(&SeedOrigin::FiniArray), Some(&1));
    }

    #[test]
    fn macho_initializer_offsets_match_llvm_and_reach_the_stripped_payload() {
        let mut bytes: Vec<u8> =
            include_bytes!("../../tests/fixtures/macho_aarch64_init_offsets.macho").to_vec();
        let reference: object::File<'_> =
            object::File::parse(bytes.as_slice()).expect("the linked offset fixture must parse");
        assert_no_macho_start_metadata(bytes.as_slice(), &reference);
        let symbols: BTreeMap<String, u64> = reference
            .symbols()
            .filter_map(|symbol: object::Symbol<'_, '_>| {
                let name: &str = symbol.name().ok()?;
                matches!(name, "_initialize_probe" | "_terminate_probe")
                    .then(|| (name.to_owned(), symbol.address()))
            })
            .collect();
        assert_eq!(symbols.get("_initialize_probe"), Some(&0x1_0000_0400));
        assert_eq!(symbols.get("_terminate_probe"), Some(&0x1_0000_0410));
        let view: ImageView<'_> = ImageView::new(bytes.as_slice(), None);
        let image_base: u64 = super::macho_text_base(&view).expect("the fixture must carry __TEXT");
        let offset: u32 = reference
            .sections()
            .find_map(|section: object::Section<'_, '_>| {
                let object::SectionFlags::MachO { flags } = section.flags() else {
                    return None;
                };
                if flags & object::macho::SECTION_TYPE != object::macho::S_INIT_FUNC_OFFSETS {
                    return None;
                }
                let raw: [u8; 4] = section.data().ok()?.try_into().ok()?;
                Some(u32::from_le_bytes(raw))
            })
            .expect("the fixture must carry one initializer offset");
        assert_eq!(
            image_base.checked_add(u64::from(offset)),
            symbols.get("_initialize_probe").copied()
        );

        clear_macho_symbols(&mut bytes);
        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(&bytes)
                .expect("the stripped offset fixture must reach disassembly discovery");
        let recovered: BTreeSet<u64> = payload
            .symbol_table
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    disrobe_ir::payload::DisasmSymbolKind::Function
                        | disrobe_ir::payload::DisasmSymbolKind::Export
                )
            })
            .map(|symbol| symbol.address)
            .collect();
        assert!(recovered.contains(&0x1_0000_0400));
        assert!(recovered.contains(&0x1_0000_0410));
    }

    #[test]
    fn macho_thread_initializer_matches_llvm_and_reaches_the_stripped_payload() {
        let mut bytes: Vec<u8> =
            include_bytes!("../../tests/fixtures/macho_aarch64_thread_initializer.macho").to_vec();
        let reference: object::File<'_> = object::File::parse(bytes.as_slice())
            .expect("the linked thread-initializer fixture must parse");
        assert_no_macho_start_metadata(bytes.as_slice(), &reference);
        let initializer: u64 = reference
            .symbols()
            .find_map(|symbol: object::Symbol<'_, '_>| {
                (symbol.name().ok()? == "_initialize_thread").then(|| symbol.address())
            })
            .expect("the LLVM symbol table must identify the thread initializer");
        assert_eq!(initializer, 0x1_0000_0300);
        assert!(
            reference
                .exports()
                .expect("the LLVM export trie must parse")
                .iter()
                .all(|export: &object::Export<'_>| {
                    export.name() != b"_initialize_thread" && export.address() != initializer
                }),
            "the thread initializer must not be reachable through the export trie"
        );
        let slot: u64 = reference
            .sections()
            .find_map(|section: object::Section<'_, '_>| {
                let object::SectionFlags::MachO { flags } = section.flags() else {
                    return None;
                };
                if flags & object::macho::SECTION_TYPE
                    != object::macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
                {
                    return None;
                }
                let raw: [u8; POINTER_BYTES] = section.data().ok()?.try_into().ok()?;
                Some(u64::from_le_bytes(raw))
            })
            .expect("the fixture must carry one thread-initializer pointer");
        assert_eq!(slot, initializer);

        clear_macho_symbols(&mut bytes);
        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(&bytes)
                .expect("the stripped thread-initializer fixture must reach discovery");
        let recovered: BTreeSet<u64> = payload
            .symbol_table
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    disrobe_ir::payload::DisasmSymbolKind::Function
                        | disrobe_ir::payload::DisasmSymbolKind::Export
                )
            })
            .map(|symbol| symbol.address)
            .collect();
        assert!(
            recovered.contains(&initializer),
            "the typed thread-initializer table must seed the local function"
        );
        let native: NativeFile =
            parse_native(bytes.as_slice()).expect("the stripped thread fixture must parse");
        let seeds: SeedSet = collect(&native, bytes.as_slice());
        assert_eq!(
            seeds.origins_of(initializer),
            BTreeSet::from([SeedOrigin::ThreadInit])
        );
        assert_eq!(seeds.counts().get(&SeedOrigin::ThreadInit), Some(&1));
    }

    #[test]
    fn macho_initializer_arrays_reject_partial_sections_and_invalid_slots() {
        let complete: Vec<u8> = [0_u64, 2, 0x1000, 0x2000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let encoded: Vec<u8> =
            macho_pointer_sections(object::macho::S_MOD_INIT_FUNC_POINTERS, &[&complete]);
        let mut view: ImageView<'_> = ImageView::new(&encoded, None);
        view.executable = vec![ExecutableRange {
            start: 0x1000,
            end: 0x1100,
        }];
        let mut seeds: SeedSet = SeedSet::default();
        collect_initializer_tables(&view, &mut seeds, super::MAX_POINTER_SLOTS, None);
        assert_eq!(seeds.addresses(), vec![0x1000]);
        assert_eq!(
            seeds.origins_of(0x1000),
            BTreeSet::from([SeedOrigin::InitArray])
        );

        let mut partial: Vec<u8> = 0x1000_u64.to_le_bytes().to_vec();
        partial.push(0xaa);
        let encoded: Vec<u8> =
            macho_pointer_sections(object::macho::S_MOD_INIT_FUNC_POINTERS, &[&partial]);
        let mut view: ImageView<'_> = ImageView::new(&encoded, None);
        view.executable = vec![ExecutableRange {
            start: 0x1000,
            end: 0x1100,
        }];
        let mut seeds: SeedSet = SeedSet::default();
        collect_initializer_tables(&view, &mut seeds, super::MAX_POINTER_SLOTS, None);
        assert!(seeds.addresses().is_empty());

        let encoded: Vec<u8> = macho_pointer_sections(
            object::macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
            &[&partial],
        );
        let mut view: ImageView<'_> = ImageView::new(&encoded, None);
        view.executable = vec![ExecutableRange {
            start: 0x1000,
            end: 0x1100,
        }];
        let mut seeds: SeedSet = SeedSet::default();
        collect_initializer_tables(&view, &mut seeds, super::MAX_POINTER_SLOTS, None);
        assert!(seeds.addresses().is_empty());
    }

    #[test]
    fn relocatable_initializer_tables_abstain_before_reading_raw_slots() {
        let bytes: Vec<u8> = relocatable_macho_initializer();
        let parsed: object::File<'_> =
            object::File::parse(bytes.as_slice()).expect("the relocatable Mach-O must parse");
        assert_eq!(parsed.kind(), object::ObjectKind::Relocatable);
        let native: NativeFile =
            parse_native(bytes.as_slice()).expect("the relocatable Mach-O must reach discovery");
        let seeds: SeedSet = collect(&native, bytes.as_slice());
        assert!(
            seeds.origins_of(4).is_empty(),
            "an unresolved relocatable slot must not become a linked function address"
        );
    }

    #[test]
    fn macho_initializer_slot_limit_is_global_across_sections() {
        let first: Vec<u8> = [0x1000_u64, 0x1004]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let second: Vec<u8> = [0x1008_u64, 0x100c]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let encoded: Vec<u8> =
            macho_pointer_sections(object::macho::S_MOD_INIT_FUNC_POINTERS, &[&first, &second]);
        let mut view: ImageView<'_> = ImageView::new(&encoded, None);
        view.executable = vec![ExecutableRange {
            start: 0x1000,
            end: 0x1100,
        }];
        let mut seeds: SeedSet = SeedSet::default();
        collect_initializer_tables(&view, &mut seeds, 3, None);
        assert_eq!(seeds.addresses(), vec![0x1000, 0x1004, 0x1008]);
    }

    #[test]
    fn macho_initializer_offsets_are_relative_to_the_text_base() {
        let offsets: Vec<u8> = [0x100_u32, 0x104, 0x300]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let encoded: Vec<u8> =
            macho_pointer_sections(object::macho::S_INIT_FUNC_OFFSETS, &[&offsets]);
        let mut view: ImageView<'_> = ImageView::new(&encoded, None);
        view.executable = vec![ExecutableRange {
            start: 0x1100,
            end: 0x1200,
        }];
        let mut seeds: SeedSet = SeedSet::default();
        collect_initializer_tables(&view, &mut seeds, super::MAX_POINTER_SLOTS, Some(0x1000));
        assert_eq!(seeds.addresses(), vec![0x1100, 0x1104]);
        assert_eq!(
            seeds.origins_of(0x1100),
            BTreeSet::from([SeedOrigin::InitArray])
        );

        let partial: Vec<u8> = [0x100_u32.to_le_bytes().as_slice(), &[0xaa]].concat();
        let encoded: Vec<u8> =
            macho_pointer_sections(object::macho::S_INIT_FUNC_OFFSETS, &[&partial]);
        let mut view: ImageView<'_> = ImageView::new(&encoded, None);
        view.executable = vec![ExecutableRange {
            start: 0x1100,
            end: 0x1200,
        }];
        let mut seeds: SeedSet = SeedSet::default();
        collect_initializer_tables(&view, &mut seeds, super::MAX_POINTER_SLOTS, Some(0x1000));
        assert!(seeds.addresses().is_empty());

        let overflow: Vec<u8> = u32::MAX.to_le_bytes().to_vec();
        let encoded: Vec<u8> =
            macho_pointer_sections(object::macho::S_INIT_FUNC_OFFSETS, &[&overflow]);
        let mut view: ImageView<'_> = ImageView::new(&encoded, None);
        view.executable = vec![ExecutableRange {
            start: 0,
            end: u64::MAX,
        }];
        let mut seeds: SeedSet = SeedSet::default();
        collect_initializer_tables(
            &view,
            &mut seeds,
            super::MAX_POINTER_SLOTS,
            Some(u64::MAX - 1),
        );
        assert!(seeds.addresses().is_empty());
    }

    #[test]
    fn stripped_macho_initializer_arrays_reach_the_disassembly_payload() {
        let mut bytes: Vec<u8> =
            include_bytes!("../../tests/fixtures/macho_aarch64_initializers.macho").to_vec();
        clear_macho_symbols(&mut bytes);
        let stripped: object::File<'_> =
            object::File::parse(bytes.as_slice()).expect("the stripped view must parse");
        assert_eq!(
            stripped
                .symbols()
                .filter(|symbol: &object::Symbol<'_, '_>| {
                    matches!(symbol.kind(), ObjSymbolKind::Text)
                })
                .count(),
            0,
            "the caller case must not retain text symbols"
        );
        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(&bytes)
                .expect("the stripped Mach-O must reach disassembly discovery");
        let recovered: BTreeSet<u64> = payload
            .symbol_table
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    disrobe_ir::payload::DisasmSymbolKind::Function
                        | disrobe_ir::payload::DisasmSymbolKind::Export
                )
            })
            .map(|symbol| symbol.address)
            .collect();
        assert!(recovered.contains(&0x1_0000_0410));
        assert!(recovered.contains(&0x1_0000_0420));
    }

    #[test]
    fn stripped_macho_function_starts_reach_the_disassembly_payload() {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus/mobile/macho-mac/SwiftHello.original");
        let mut bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        let reference: object::File<'_> =
            object::File::parse(bytes.as_slice()).expect("the symbol reference must parse");
        let expected: BTreeSet<u64> = reference
            .symbols()
            .filter(|symbol: &object::Symbol<'_, '_>| {
                matches!(symbol.kind(), ObjSymbolKind::Text)
                    && !symbol.is_undefined()
                    && symbol
                        .name()
                        .is_ok_and(|name: &str| name != "__mh_execute_header")
            })
            .map(|symbol: object::Symbol<'_, '_>| symbol.address())
            .collect();
        clear_macho_symbols(&mut bytes);
        let stripped: object::File<'_> =
            object::File::parse(bytes.as_slice()).expect("the stripped view must parse");
        assert_eq!(
            stripped
                .symbols()
                .filter(|symbol: &object::Symbol<'_, '_>| {
                    matches!(symbol.kind(), ObjSymbolKind::Text)
                })
                .count(),
            0,
            "the caller case must not retain text symbols"
        );
        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(&bytes)
                .expect("the stripped Mach-O must reach disassembly discovery");
        let recovered: BTreeSet<u64> = payload
            .symbol_table
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    disrobe_ir::payload::DisasmSymbolKind::Function
                        | disrobe_ir::payload::DisasmSymbolKind::Export
                )
            })
            .map(|symbol| symbol.address)
            .collect();
        let missing: Vec<u64> = expected.difference(&recovered).copied().collect();
        assert!(missing.is_empty(), "missing stripped starts: {missing:#x?}");
    }

    #[test]
    fn macho_function_starts_use_text_instead_of_the_lowest_segment() {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus/mobile/macho-mac/SwiftHello.original");
        let mut bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        let ncmds: usize =
            u32::from_le_bytes(bytes[16..20].try_into().expect("Mach header ncmds")) as usize;
        let mut cursor: usize = 32;
        let mut changed: bool = false;
        for _ in 0..ncmds {
            let header_end: usize = cursor.checked_add(8).expect("bounded load header");
            let header: &[u8] = bytes
                .get(cursor..header_end)
                .expect("load command header must be in the fixture");
            let cmd: u32 = u32::from_le_bytes(header[..4].try_into().expect("load command id"));
            let cmdsize: usize =
                u32::from_le_bytes(header[4..8].try_into().expect("load command size")) as usize;
            assert!(cmdsize >= 8, "load command must include its header");
            let command_end: usize = cursor
                .checked_add(cmdsize)
                .expect("bounded load command size");
            assert!(command_end <= bytes.len(), "load command must be bounded");
            if cmd == object::macho::LC_SEGMENT_64 && cmdsize >= 72 {
                let name: &[u8] = &bytes[cursor + 8..cursor + 24];
                if !name.starts_with(b"__TEXT") && !name.starts_with(b"__PAGEZERO") {
                    bytes[cursor + 24..cursor + 32].copy_from_slice(&0x1000_u64.to_le_bytes());
                    changed = true;
                    break;
                }
            }
            cursor = command_end;
        }
        assert!(changed, "the fixture must contain a non-text segment");
        let native: NativeFile = parse_native(&bytes).expect("the unusual Mach-O must parse");
        let seeds: SeedSet = collect(&native, &bytes);
        assert_eq!(
            seeds.counts().get(&SeedOrigin::MachFunctionStarts).copied(),
            Some(46)
        );
    }

    #[test]
    fn stripped_pe_arm64_pdata_reaches_the_disassembly_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes: Vec<u8> = include_bytes!("../../tests/fixtures/pe_arm64_pdata.exe").to_vec();
        let section_name: usize = bytes
            .windows(8)
            .position(|window: &[u8]| window == b".pdata\0\0")
            .ok_or_else(|| {
                std::io::Error::other("the fixture must carry the exception section name")
            })?;
        bytes[section_name..section_name + 8].copy_from_slice(b".armunw\0");
        let reference: object::File<'_> = object::File::parse(bytes.as_slice())?;
        assert_eq!(reference.architecture(), Architecture::Aarch64);
        assert_eq!(reference.relative_address_base(), 0x1_4000_0000);
        assert_eq!(reference.entry(), 0x1_4000_1048);
        assert_eq!(
            reference.symbols().count(),
            0,
            "the PE fixture must be stripped"
        );
        let expected: BTreeSet<u64> =
            BTreeSet::from([0x1_4000_1000, 0x1_4000_1018, 0x1_4000_1030, 0x1_4000_1048]);

        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(bytes.as_slice())?;
        let recovered: BTreeSet<u64> = payload
            .symbol_table
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    disrobe_ir::payload::DisasmSymbolKind::Function
                        | disrobe_ir::payload::DisasmSymbolKind::Export
                )
            })
            .map(|symbol| symbol.address)
            .collect();
        assert_eq!(
            expected.difference(&recovered).count(),
            0,
            "{recovered:#x?}"
        );
        Ok(())
    }

    #[test]
    fn pe_arm64_pdata_keeps_a_valid_prefix_and_rejects_invalid_starts() {
        type InvalidCase<'data> = (Option<(u32, u32)>, &'data [u8]);

        let image_base: u64 = 0x1_4000_0000;
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &[],
            executable: vec![ExecutableRange {
                start: image_base + 0x1000,
                end: image_base + 0x2000,
            }],
            segments: Vec::new(),
            file_section_reads: FileSectionReads::Allow,
        };
        let invalid_cases: [InvalidCase<'_>; 4] = [
            (Some((0x1002, 5)), &[]),
            (Some((0x3000, 5)), &[]),
            (Some((0x1ffc, 0x19)), &[]),
            (None, &[0xaa, 0xbb, 0xcc]),
        ];
        for (invalid_record, tail) in invalid_cases {
            let mut data: Vec<u8> = Vec::new();
            data.extend_from_slice(&0x1000_u32.to_le_bytes());
            data.extend_from_slice(&5_u32.to_le_bytes());
            if let Some(record) = invalid_record {
                let (invalid_begin_rva, invalid_unwind_data): (u32, u32) = record;
                data.extend_from_slice(&invalid_begin_rva.to_le_bytes());
                data.extend_from_slice(&invalid_unwind_data.to_le_bytes());
            }
            data.extend_from_slice(tail);
            let mut seeds: SeedSet = SeedSet::default();

            decode_pe_arm64_pdata(&data, image_base, &view, &mut seeds);

            assert_eq!(seeds.addresses(), vec![image_base + 0x1000]);
            assert_eq!(
                seeds.origins_of(image_base + 0x1000),
                BTreeSet::from([SeedOrigin::PePdata])
            );
        }
    }

    #[test]
    fn pe_arm64_pdata_bounds_entries_and_checked_address_addition()
    -> Result<(), Box<dyn std::error::Error>> {
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &[],
            executable: vec![ExecutableRange {
                start: 0,
                end: u64::MAX,
            }],
            segments: Vec::new(),
            file_section_reads: FileSectionReads::Allow,
        };
        let mut data: Vec<u8> = Vec::with_capacity((MAX_UNWIND_ENTRIES + 1) * 8);
        for index in 0..=MAX_UNWIND_ENTRIES {
            let begin_rva: u32 = u32::try_from(index.saturating_add(1) * 4)?;
            data.extend_from_slice(&begin_rva.to_le_bytes());
            data.extend_from_slice(&5_u32.to_le_bytes());
        }
        let mut bounded: SeedSet = SeedSet::default();
        decode_pe_arm64_pdata(&data, 0, &view, &mut bounded);
        let expected_last: u64 = u64::try_from(MAX_UNWIND_ENTRIES)?.saturating_mul(4);
        assert_eq!(bounded.addresses().len(), MAX_UNWIND_ENTRIES);
        assert_eq!(bounded.addresses().last().copied(), Some(expected_last));

        let mut overflowed: SeedSet = SeedSet::default();
        decode_pe_arm64_pdata(
            &[0x00, 0x20, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00],
            u64::MAX - 0x1000,
            &view,
            &mut overflowed,
        );
        assert!(overflowed.addresses().is_empty());
        Ok(())
    }

    #[test]
    fn pe_arm64_pdata_validates_unwind_forms_and_sorted_function_starts()
    -> Result<(), Box<dyn std::error::Error>> {
        let image_base: u64 = 0x1_4000_0000;
        let mut image: Vec<u8> = vec![0; 0x200c];
        image[0x2000..0x2004].copy_from_slice(&0x1020_000b_u32.to_le_bytes());
        image[0x2004..0x2008].copy_from_slice(&0x01d4_c1d2_u32.to_le_bytes());
        image[0x2008..0x200c].copy_from_slice(&0xe3e3_e3e4_u32.to_le_bytes());
        let image_len: u64 = u64::try_from(image.len())?;
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &image,
            executable: vec![ExecutableRange {
                start: image_base + 0x1000,
                end: image_base + 0x1100,
            }],
            segments: vec![crate::elf::SegmentMapping {
                kind: "test".to_owned(),
                file_offset: 0,
                file_size: image_len,
                virtual_addr: image_base,
                mem_size: image_len,
                readable: true,
                writable: false,
                executable: false,
                align: 4,
            }],
            file_section_reads: FileSectionReads::Allow,
        };
        let mut valid_data: Vec<u8> = Vec::new();
        valid_data.extend_from_slice(&0x1000_u32.to_le_bytes());
        valid_data.extend_from_slice(&0x2000_u32.to_le_bytes());
        valid_data.extend_from_slice(&0x1030_u32.to_le_bytes());
        valid_data.extend_from_slice(&0x19_u32.to_le_bytes());
        let mut valid: SeedSet = SeedSet::default();
        decode_pe_arm64_pdata(&valid_data, image_base, &view, &mut valid);
        assert_eq!(
            valid.addresses(),
            vec![image_base + 0x1000, image_base + 0x1030]
        );

        for unwind_data in [1_u32, 0x1a, 0x1b] {
            let mut record: Vec<u8> = Vec::new();
            record.extend_from_slice(&0x1000_u32.to_le_bytes());
            record.extend_from_slice(&unwind_data.to_le_bytes());
            let mut rejected: SeedSet = SeedSet::default();
            decode_pe_arm64_pdata(&record, image_base, &view, &mut rejected);
            assert!(rejected.addresses().is_empty(), "{unwind_data:#x}");
        }

        let mut descending_data: Vec<u8> = Vec::new();
        for begin_rva in [0x1010_u32, 0x1000] {
            descending_data.extend_from_slice(&begin_rva.to_le_bytes());
            descending_data.extend_from_slice(&5_u32.to_le_bytes());
        }
        let mut descending: SeedSet = SeedSet::default();
        decode_pe_arm64_pdata(&descending_data, image_base, &view, &mut descending);
        assert_eq!(descending.addresses(), vec![image_base + 0x1010]);

        let mut invalid_image: Vec<u8> = image.clone();
        invalid_image[0x2000..0x2004].copy_from_slice(&0x1024_000b_u32.to_le_bytes());
        let invalid_version_view: ImageView<'_> = ImageView {
            file: None,
            bytes: &invalid_image,
            executable: view.executable.clone(),
            segments: view.segments.clone(),
            file_section_reads: FileSectionReads::Allow,
        };
        let mut invalid_version: SeedSet = SeedSet::default();
        decode_pe_arm64_pdata(
            &valid_data[..PE_ARM64_PDATA_RECORD_BYTES],
            image_base,
            &invalid_version_view,
            &mut invalid_version,
        );
        assert!(invalid_version.addresses().is_empty());
        Ok(())
    }

    #[test]
    fn pe_arm64_pdata_rejects_a_directory_larger_than_its_section()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes: Vec<u8> = include_bytes!("../../tests/fixtures/pe_arm64_pdata.exe").to_vec();
        let pe_offset_bytes: [u8; 4] = bytes[0x3c..0x40].try_into()?;
        let pe_offset: usize = usize::try_from(u32::from_le_bytes(pe_offset_bytes))?;
        let optional_header: usize = pe_offset.checked_add(4 + 20).ok_or_else(|| {
            std::io::Error::other("the optional header offset must remain bounded")
        })?;
        let exception_size: usize = optional_header
            .checked_add(112 + object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8 + 4)
            .ok_or_else(|| {
                std::io::Error::other("the exception directory offset must remain bounded")
            })?;
        bytes[exception_size..exception_size + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        let native: NativeFile = parse_native(&bytes)?;

        let seeds: SeedSet = collect(&native, &bytes);

        assert_eq!(seeds.counts().get(&SeedOrigin::PePdata), None);
        assert_eq!(seeds.addresses(), vec![0x1_4000_1048]);
        Ok(())
    }

    #[test]
    fn pe_arm64_pdata_does_not_parse_the_arm64ec_runtime_function_layout()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes: Vec<u8> = include_bytes!("../../tests/fixtures/pe_arm64_pdata.exe").to_vec();
        let pe_offset_bytes: [u8; 4] = bytes[0x3c..0x40].try_into()?;
        let pe_offset: usize = usize::try_from(u32::from_le_bytes(pe_offset_bytes))?;
        let machine: usize = pe_offset
            .checked_add(4)
            .ok_or_else(|| std::io::Error::other("the machine offset must remain bounded"))?;
        bytes[machine..machine + 2]
            .copy_from_slice(&object::pe::IMAGE_FILE_MACHINE_ARM64EC.to_le_bytes());
        let native: NativeFile = parse_native(&bytes)?;

        let seeds: SeedSet = collect(&native, &bytes);

        assert_eq!(seeds.counts().get(&SeedOrigin::PePdata), None);
        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(bytes.as_slice())?;
        assert_eq!(
            payload
                .symbol_table
                .iter()
                .filter(|symbol| {
                    matches!(
                        symbol.kind,
                        disrobe_ir::payload::DisasmSymbolKind::Function
                            | disrobe_ir::payload::DisasmSymbolKind::Export
                    )
                })
                .count(),
            0
        );
        Ok(())
    }

    #[test]
    fn stripped_pe_arm64_tls_callback_reaches_the_disassembly_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes: Vec<u8> = include_bytes!("../../tests/fixtures/pe_arm64_tls.exe").to_vec();
        let section_name: usize = bytes
            .windows(8)
            .position(|window: &[u8]| window == b".rdata\0\0")
            .ok_or_else(|| std::io::Error::other("the fixture must contain its TLS directory"))?;
        bytes[section_name..section_name + 8].copy_from_slice(b".tlsdir\0");
        let reference: object::File<'_> = object::File::parse(bytes.as_slice())?;
        assert_eq!(reference.architecture(), Architecture::Aarch64);
        assert_eq!(reference.entry(), 0x1_4000_1014);
        assert_eq!(reference.symbols().count(), 0);
        assert!(
            reference
                .sections()
                .all(|section: object::Section<'_, '_>| {
                    section.name().is_ok_and(|name: &str| name != ".pdata")
                })
        );

        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(bytes.as_slice())?;
        let recovered: BTreeSet<u64> = payload
            .symbol_table
            .iter()
            .filter(|symbol| {
                matches!(
                    symbol.kind,
                    disrobe_ir::payload::DisasmSymbolKind::Function
                        | disrobe_ir::payload::DisasmSymbolKind::Export
                )
            })
            .map(|symbol| symbol.address)
            .collect();
        assert!(recovered.contains(&0x1_4000_1000), "{recovered:#x?}");
        Ok(())
    }

    #[test]
    fn pe_arm64_tls_callback_requires_an_executable_section_characteristic()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes: Vec<u8> = include_bytes!("../../tests/fixtures/pe_arm64_tls.exe").to_vec();
        let pe_offset_bytes: [u8; 4] = bytes[0x3c..0x40].try_into()?;
        let pe_offset: usize = usize::try_from(u32::from_le_bytes(pe_offset_bytes))?;
        let optional_header_size_bytes: [u8; 2] =
            bytes[pe_offset + 20..pe_offset + 22].try_into()?;
        let optional_header_size: usize =
            usize::from(u16::from_le_bytes(optional_header_size_bytes));
        let text_characteristics: usize = pe_offset
            .checked_add(4 + 20)
            .and_then(|offset: usize| offset.checked_add(optional_header_size))
            .and_then(|offset: usize| offset.checked_add(36))
            .ok_or_else(|| {
                std::io::Error::other("the text characteristics offset must be bounded")
            })?;
        let characteristics_bytes: [u8; 4] =
            bytes[text_characteristics..text_characteristics + 4].try_into()?;
        let characteristics: u32 =
            u32::from_le_bytes(characteristics_bytes) & !object::pe::IMAGE_SCN_MEM_EXECUTE;
        bytes[text_characteristics..text_characteristics + 4]
            .copy_from_slice(&characteristics.to_le_bytes());
        let native: NativeFile = parse_native(bytes.as_slice())?;

        let seeds: SeedSet = collect(&native, bytes.as_slice());

        assert!(
            !seeds
                .origins_of(0x1_4000_1000)
                .contains(&SeedOrigin::PeTlsCallback)
        );
        Ok(())
    }

    #[test]
    fn pe_arm64_tls_callback_rejects_wrapped_image_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes: Vec<u8> = include_bytes!("../../tests/fixtures/pe_arm64_tls.exe").to_vec();
        let pe_offset_bytes: [u8; 4] = bytes[0x3c..0x40].try_into()?;
        let pe_offset: usize = usize::try_from(u32::from_le_bytes(pe_offset_bytes))?;
        let optional_header: usize = pe_offset
            .checked_add(4 + 20)
            .ok_or_else(|| std::io::Error::other("the optional header offset must be bounded"))?;
        let optional_header_size_bytes: [u8; 2] =
            bytes[pe_offset + 20..pe_offset + 22].try_into()?;
        let optional_header_size: usize =
            usize::from(u16::from_le_bytes(optional_header_size_bytes));
        let section_table: usize = optional_header
            .checked_add(optional_header_size)
            .ok_or_else(|| std::io::Error::other("the section table offset must be bounded"))?;
        for section_index in 0..6_usize {
            let virtual_address: usize = section_table
                .checked_add(section_index.saturating_mul(40))
                .and_then(|offset: usize| offset.checked_add(12))
                .ok_or_else(|| {
                    std::io::Error::other("the section address offset must be bounded")
                })?;
            let original_bytes: [u8; 4] = bytes[virtual_address..virtual_address + 4].try_into()?;
            let shifted: u32 = u32::from_le_bytes(original_bytes)
                .checked_add(0xf000)
                .ok_or_else(|| std::io::Error::other("the section address must be bounded"))?;
            bytes[virtual_address..virtual_address + 4].copy_from_slice(&shifted.to_le_bytes());
        }
        let image_base: usize = optional_header
            .checked_add(24)
            .ok_or_else(|| std::io::Error::other("the image base offset must be bounded"))?;
        bytes[image_base..image_base + 8].copy_from_slice(&0xffff_ffff_ffff_0000_u64.to_le_bytes());
        let entry_point: usize = optional_header
            .checked_add(16)
            .ok_or_else(|| std::io::Error::other("the entry point offset must be bounded"))?;
        bytes[entry_point..entry_point + 4].copy_from_slice(&0x1_0014_u32.to_le_bytes());
        let size_of_image: usize = optional_header
            .checked_add(56)
            .ok_or_else(|| std::io::Error::other("the image size offset must be bounded"))?;
        bytes[size_of_image..size_of_image + 4].copy_from_slice(&0x1_6000_u32.to_le_bytes());
        let tls_directory_rva: usize = optional_header
            .checked_add(112 + object::pe::IMAGE_DIRECTORY_ENTRY_TLS * 8)
            .ok_or_else(|| std::io::Error::other("the TLS directory offset must be bounded"))?;
        bytes[tls_directory_rva..tls_directory_rva + 4]
            .copy_from_slice(&0x1_1000_u32.to_le_bytes());
        let tls_callbacks: usize = 0x600_usize
            .checked_add(24)
            .ok_or_else(|| std::io::Error::other("the TLS callback offset must be bounded"))?;
        bytes[0x600..0x608].copy_from_slice(&0x4000_u64.to_le_bytes());
        bytes[0x608..0x610].copy_from_slice(&0x4002_u64.to_le_bytes());
        bytes[0x610..0x618].copy_from_slice(&0x2000_u64.to_le_bytes());
        bytes[tls_callbacks..tls_callbacks + 8].copy_from_slice(&0x3000_u64.to_le_bytes());
        bytes[0x800..0x808].copy_from_slice(&4_u64.to_le_bytes());
        let native: NativeFile = parse_native(bytes.as_slice())?;

        let seeds: SeedSet = collect(&native, bytes.as_slice());
        let payload: disrobe_ir::payload::DisasmPayload =
            super::super::build_disasm_payload(bytes.as_slice())?;

        assert!(!seeds.origins_of(4).contains(&SeedOrigin::PeTlsCallback));
        assert!(
            payload.symbol_table.iter().all(|symbol| {
                !matches!(
                    symbol.kind,
                    disrobe_ir::payload::DisasmSymbolKind::Function
                        | disrobe_ir::payload::DisasmSymbolKind::Export
                ) || symbol.address != 0x14
            }),
            "{:x?}",
            payload.symbol_table
        );
        Ok(())
    }

    #[test]
    fn pe_arm64_tls_callbacks_preserve_only_a_valid_bounded_prefix() {
        let mut image: Vec<u8> = Vec::new();
        for callback in [0x1000_u64, 0x1002, 0] {
            image.extend_from_slice(&callback.to_le_bytes());
        }
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &image,
            executable: vec![ExecutableRange {
                start: 0x1000,
                end: 0x1100,
            }],
            segments: vec![crate::elf::SegmentMapping {
                kind: "test".to_owned(),
                file_offset: 0,
                file_size: 24,
                virtual_addr: 0x2000,
                mem_size: 24,
                readable: true,
                writable: false,
                executable: false,
                align: 8,
            }],
            file_section_reads: FileSectionReads::Allow,
        };
        let mut directory: [u8; PE64_TLS_DIRECTORY_BYTES] = [0; PE64_TLS_DIRECTORY_BYTES];
        directory[24..32].copy_from_slice(&0x2000_u64.to_le_bytes());
        let mut seeds: SeedSet = SeedSet::default();

        decode_pe_arm64_tls_callbacks(&directory, &view, &mut seeds);

        assert_eq!(seeds.addresses(), vec![0x1000]);
        assert_eq!(
            seeds.origins_of(0x1000),
            BTreeSet::from([SeedOrigin::PeTlsCallback])
        );

        let partial_view: ImageView<'_> = ImageView {
            file: None,
            bytes: &image[..12],
            executable: view.executable,
            segments: vec![crate::elf::SegmentMapping {
                kind: "test".to_owned(),
                file_offset: 0,
                file_size: 12,
                virtual_addr: 0x2000,
                mem_size: 12,
                readable: true,
                writable: false,
                executable: false,
                align: 8,
            }],
            file_section_reads: FileSectionReads::Allow,
        };
        let mut partial: SeedSet = SeedSet::default();
        decode_pe_arm64_tls_callbacks(&directory, &partial_view, &mut partial);
        assert_eq!(partial.addresses(), vec![0x1000]);
    }

    #[test]
    fn pe_arm64_tls_callbacks_reject_invalid_directories_and_arrays() {
        let image: [u8; 8] = 0x1000_u64.to_le_bytes();
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &image,
            executable: vec![ExecutableRange {
                start: 0x1000,
                end: 0x1100,
            }],
            segments: vec![crate::elf::SegmentMapping {
                kind: "test".to_owned(),
                file_offset: 0,
                file_size: 8,
                virtual_addr: 0x2000,
                mem_size: 8,
                readable: true,
                writable: false,
                executable: false,
                align: 8,
            }],
            file_section_reads: FileSectionReads::Allow,
        };
        let mut valid_directory: [u8; PE64_TLS_DIRECTORY_BYTES] = [0; PE64_TLS_DIRECTORY_BYTES];
        valid_directory[24..32].copy_from_slice(&0x2000_u64.to_le_bytes());
        let mut misaligned_directory: [u8; PE64_TLS_DIRECTORY_BYTES] = valid_directory;
        misaligned_directory[24..32].copy_from_slice(&0x2001_u64.to_le_bytes());
        let mut unmapped_directory: [u8; PE64_TLS_DIRECTORY_BYTES] = valid_directory;
        unmapped_directory[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        let zero_directory: [u8; PE64_TLS_DIRECTORY_BYTES] = [0; PE64_TLS_DIRECTORY_BYTES];
        for directory in [
            &valid_directory[..PE64_TLS_DIRECTORY_BYTES - 1],
            misaligned_directory.as_slice(),
            unmapped_directory.as_slice(),
            zero_directory.as_slice(),
        ] {
            let mut seeds: SeedSet = SeedSet::default();
            decode_pe_arm64_tls_callbacks(directory, &view, &mut seeds);
            assert!(seeds.addresses().is_empty());
        }

        let mut outside_image: Vec<u8> = Vec::new();
        outside_image.extend_from_slice(&0x3000_u64.to_le_bytes());
        outside_image.extend_from_slice(&0_u64.to_le_bytes());
        let outside_view: ImageView<'_> = ImageView {
            file: None,
            bytes: &outside_image,
            executable: view.executable,
            segments: vec![crate::elf::SegmentMapping {
                kind: "test".to_owned(),
                file_offset: 0,
                file_size: 16,
                virtual_addr: 0x2000,
                mem_size: 16,
                readable: true,
                writable: false,
                executable: false,
                align: 8,
            }],
            file_section_reads: FileSectionReads::Allow,
        };
        let mut outside: SeedSet = SeedSet::default();
        decode_pe_arm64_tls_callbacks(&valid_directory, &outside_view, &mut outside);
        assert!(outside.addresses().is_empty());
    }

    #[test]
    fn pe_arm64_tls_callback_walk_stops_at_the_hard_cap() -> Result<(), Box<dyn std::error::Error>>
    {
        let slot_count: usize = MAX_PE_TLS_CALLBACKS.saturating_add(1);
        let mut image: Vec<u8> = Vec::with_capacity(slot_count.saturating_mul(POINTER_BYTES));
        for _ in 0..MAX_PE_TLS_CALLBACKS.saturating_sub(1) {
            image.extend_from_slice(&0x1000_u64.to_le_bytes());
        }
        image.extend_from_slice(&0x1004_u64.to_le_bytes());
        image.extend_from_slice(&0x1008_u64.to_le_bytes());
        let image_size: u64 = u64::try_from(image.len())?;
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &image,
            executable: vec![ExecutableRange {
                start: 0x1000,
                end: 0x1100,
            }],
            segments: vec![crate::elf::SegmentMapping {
                kind: "test".to_owned(),
                file_offset: 0,
                file_size: image_size,
                virtual_addr: 0x2000,
                mem_size: image_size,
                readable: true,
                writable: false,
                executable: false,
                align: 8,
            }],
            file_section_reads: FileSectionReads::Allow,
        };
        let mut directory: [u8; PE64_TLS_DIRECTORY_BYTES] = [0; PE64_TLS_DIRECTORY_BYTES];
        directory[24..32].copy_from_slice(&0x2000_u64.to_le_bytes());
        let mut seeds: SeedSet = SeedSet::default();

        decode_pe_arm64_tls_callbacks(&directory, &view, &mut seeds);

        assert_eq!(seeds.addresses(), vec![0x1000, 0x1004]);
        Ok(())
    }

    #[test]
    fn pe_arm64_tls_directory_is_bounded_and_rejects_arm64ec()
    -> Result<(), Box<dyn std::error::Error>> {
        let original: &[u8] = include_bytes!("../../tests/fixtures/pe_arm64_tls.exe");
        let pe_offset_bytes: [u8; 4] = original[0x3c..0x40].try_into()?;
        let pe_offset: usize = usize::try_from(u32::from_le_bytes(pe_offset_bytes))?;
        let optional_header: usize = pe_offset
            .checked_add(4 + 20)
            .ok_or_else(|| std::io::Error::other("the optional header offset must be bounded"))?;
        let tls_size: usize = optional_header
            .checked_add(112 + object::pe::IMAGE_DIRECTORY_ENTRY_TLS * 8 + 4)
            .ok_or_else(|| std::io::Error::other("the TLS directory offset must be bounded"))?;
        let machine: usize = pe_offset
            .checked_add(4)
            .ok_or_else(|| std::io::Error::other("the machine offset must be bounded"))?;

        let mut oversized: Vec<u8> = original.to_vec();
        oversized[tls_size..tls_size + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        let oversized_native: NativeFile = parse_native(&oversized)?;
        let oversized_seeds: SeedSet = collect(&oversized_native, &oversized);
        assert_eq!(
            oversized_seeds.counts().get(&SeedOrigin::PeTlsCallback),
            None
        );

        let mut arm64ec: Vec<u8> = original.to_vec();
        arm64ec[machine..machine + 2]
            .copy_from_slice(&object::pe::IMAGE_FILE_MACHINE_ARM64EC.to_le_bytes());
        let arm64ec_native: NativeFile = parse_native(&arm64ec)?;
        let arm64ec_seeds: SeedSet = collect(&arm64ec_native, &arm64ec);
        assert_eq!(arm64ec_seeds.counts().get(&SeedOrigin::PeTlsCallback), None);
        Ok(())
    }

    #[test]
    fn pe_arm64_tls_callback_collection_is_deterministic() -> Result<(), Box<dyn std::error::Error>>
    {
        let bytes: &[u8] = include_bytes!("../../tests/fixtures/pe_arm64_tls.exe");
        let native: NativeFile = parse_native(bytes)?;
        let first: SeedSet = collect(&native, bytes);
        let second: SeedSet = collect(&native, bytes);
        assert_eq!(first.addresses(), second.addresses());
        assert_eq!(first.counts(), second.counts());
        Ok(())
    }

    #[test]
    fn prologue_and_boundary_words_are_told_apart() {
        assert!(is_prologue_word(0xA9BF_7BFD), "stp x29, x30, [sp, #-16]!");
        assert!(is_prologue_word(0xD100_43FF), "sub sp, sp, #16");
        assert!(is_prologue_word(0xD503_233F), "paciasp");
        assert!(is_prologue_word(0xD503_245F), "bti c");
        assert!(!is_prologue_word(0xD65F_03C0), "ret opens nothing");
        assert!(
            !is_prologue_word(0x8B00_0020),
            "add x0, x1, x0 opens nothing"
        );
        assert!(is_boundary_word(0xD65F_03C0), "ret closes a function");
        assert!(is_boundary_word(0x1400_0004), "b closes a function");
        assert!(is_boundary_word(0xD503_201F), "nop pads between functions");
        assert!(!is_boundary_word(0x8B00_0020), "add closes nothing");
    }

    #[test]
    fn truncated_and_corrupted_images_stay_bounded() {
        for fixture in ALL_FIXTURES {
            let full: Vec<u8> = corpus_bytes(fixture.stripped);
            let cuts: [usize; 6] = [1, 64, 256, 1024, 2048, full.len() / 2];
            for cut in cuts {
                let slice: &[u8] = &full[..cut.min(full.len())];
                if let Ok(native) = parse_native(slice) {
                    let seeds: SeedSet = collect(&native, slice);
                    assert!(seeds.addresses().len() <= MAX_SEEDS);
                }
            }
            let mut corrupted: Vec<u8> = full;
            for byte in corrupted.iter_mut().skip(0x400).take(0x400) {
                *byte = 0xFF;
            }
            if let Ok(native) = parse_native(&corrupted) {
                let seeds: SeedSet = collect(&native, &corrupted);
                assert!(seeds.addresses().len() <= MAX_SEEDS);
            }
        }
    }
}
