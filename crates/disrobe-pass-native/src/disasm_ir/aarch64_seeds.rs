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
};

use crate::debug::{dbg_kv, dbg_section};
use crate::elf::{ElfDynamicReport, SegmentMapping, SymbolType, analyze};

type EhSlice<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SeedOrigin {
    Entry,
    Export,
    SymbolTable,
    DynamicSymbol,
    UnwindEntry,
    InitArray,
    FiniArray,
    DynamicInit,
    RelocationPointer,
    DataPointer,
    MachFunctionStarts,
    MachCompactUnwind,
}

impl SeedOrigin {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Export => "export",
            Self::SymbolTable => "symtab",
            Self::DynamicSymbol => "dynsym",
            Self::UnwindEntry => "eh-frame",
            Self::InitArray => "init-array",
            Self::FiniArray => "fini-array",
            Self::DynamicInit => "dt-init",
            Self::RelocationPointer => "relocation",
            Self::DataPointer => "data-pointer",
            Self::MachFunctionStarts => "macho-function-starts",
            Self::MachCompactUnwind => "macho-compact-unwind",
        }
    }
}

const AARCH64_INSTRUCTION_ALIGNMENT: u64 = 4;

const POINTER_BYTES: usize = 8;

pub(super) const MAX_SEEDS: usize = 1 << 17;

const MAX_UNWIND_ENTRIES: usize = 1 << 17;

const MAX_POINTER_SLOTS: usize = 1 << 21;

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
        }
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
}

fn read_word(bytes: &[u8], offset: u64) -> Option<u32> {
    let start: usize = usize::try_from(offset).ok()?;
    let end: usize = start.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(start..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
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
    }
    if view.has_linked_addresses() {
        collect_initializer_tables(&view, &mut seeds, MAX_POINTER_SLOTS, None);
    }
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
        CompactUnwindError, CompactUnwindOutcome, ExecutableRange, ImageView, MAX_SEEDS,
        MAX_UNWIND_ENTRIES, POINTER_BYTES, SeedOrigin, SeedSet, collect,
        collect_initializer_tables, decode_macho_compact_unwind, decode_macho_function_starts,
        is_boundary_word, is_prologue_word,
    };

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use disrobe_binfmt::native::{NativeFile, parse_native};
    use object::{
        Architecture, BinaryFormat, Endianness, Object as _, ObjectSection as _, ObjectSymbol as _,
        SectionFlags, SectionKind, SymbolKind as ObjSymbolKind, write::Object as WriteObject,
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

    fn decode_function_starts(data: &[u8]) -> SeedSet {
        let view: ImageView<'_> = ImageView {
            file: None,
            bytes: &[],
            executable: vec![ExecutableRange {
                start: 0x1000,
                end: 0x1100,
            }],
            segments: Vec::new(),
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
            reference.sections().all(
                |section: object::Section<'_, '_>| section.name().ok() != Some("__unwind_info")
            ),
            "the initializer fixture must not carry compact-unwind function starts"
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
