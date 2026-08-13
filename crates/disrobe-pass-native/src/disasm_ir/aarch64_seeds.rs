use std::collections::{BTreeMap, BTreeSet};

use disrobe_binfmt::native::{Arch as BinArch, Endian, NativeFile, NativeFormat};
use gimli::{
    BaseAddresses, CieOrFde, CommonInformationEntry, EhFrame, EhFrameOffset, EndianSlice,
    FrameDescriptionEntry, LittleEndian, UnwindSection as _,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind as ObjSymbolKind};

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
        }
    }
}

const AARCH64_INSTRUCTION_ALIGNMENT: u64 = 4;

const POINTER_BYTES: usize = 8;

pub(super) const MAX_SEEDS: usize = 1 << 17;

const MAX_UNWIND_ENTRIES: usize = 1 << 17;

const MAX_POINTER_SLOTS: usize = 1 << 21;

const MAX_EXECUTABLE_RANGES: usize = 1 << 12;

const MIN_POINTER_RUN: usize = 2;

const R_AARCH64_RELATIVE: u32 = 1027;

const R_AARCH64_IRELATIVE: u32 = 1032;

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

fn collect_pointer_arrays(view: &ImageView<'_>, seeds: &mut SeedSet) {
    let Some(parsed): Option<&object::File<'_>> = view.file.as_ref() else {
        return;
    };
    for section in parsed.sections() {
        let Ok(name): core::result::Result<&str, object::Error> = section.name() else {
            continue;
        };
        let origin: SeedOrigin = match name {
            ".init_array" | ".preinit_array" => SeedOrigin::InitArray,
            ".fini_array" => SeedOrigin::FiniArray,
            _ => continue,
        };
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        for slot in data.chunks_exact(POINTER_BYTES).take(MAX_POINTER_SLOTS) {
            let Ok(raw): core::result::Result<[u8; POINTER_BYTES], core::array::TryFromSliceError> =
                slot.try_into()
            else {
                continue;
            };
            let address: u64 = u64::from_le_bytes(raw);
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
    if !matches!(native.arch, BinArch::Aarch64)
        || !matches!(native.format, NativeFormat::Elf64)
        || !matches!(native.endian, Endian::Little)
    {
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
    collect_pointer_arrays(&view, &mut seeds);
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
    use super::{MAX_SEEDS, SeedOrigin, SeedSet, collect, is_boundary_word, is_prologue_word};

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use disrobe_binfmt::native::{NativeFile, parse_native};
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind as ObjSymbolKind};

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
