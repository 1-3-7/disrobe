use std::cmp::Ordering;
use std::collections::BTreeMap;

use disrobe_binfmt::{Arch, Endian, NativeFile, ParsedNativeFormat, SectionInfo, parse_native};
use disrobe_bytes::{
    bounded_element_capacity, read_i32_le_at, read_u16_le_at, read_u32_le_at, read_u64_le_at,
};
use disrobe_core::byte_search;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSegment as _;
use object::read::{DynamicRelocationIterator, File as ObjFile};
use object::{RelocationFlags, RelocationTarget};

use serde::{Deserialize, Serialize};

mod invoke_map;
mod metadata_records;

pub use metadata_records::{
    AotMetadataAttribution, AotMetadataStatus, AotMethod, AotMethodSignature, AotType,
    AotTypeSignature, AotTypeSignatureKind, recover_metadata_attribution,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotReport {
    pub is_native_aot: bool,
    pub recovered_symbols: BTreeMap<String, u32>,
    pub modules_table_offset: Option<u32>,
    pub eager_class_constructors: u32,
    pub runtime_label: AotRuntime,
    pub ready_to_run: Option<ReadyToRunHeader>,
    pub recovered_names: Vec<String>,
    #[serde(default)]
    pub metadata_attribution: AotMetadataAttribution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AotRuntime {
    Net7,
    Net8,
    Net9,
    Net10,
    Unknown,
}

pub const READY_TO_RUN_SIGNATURE: u32 = 0x0052_5452;

const READY_TO_RUN_ENTRY_TYPE: u8 = 1;
const MAX_READY_TO_RUN_SECTIONS: u16 = 1024;
const MAX_PROFILE_MAJOR: u16 = 64;
const MAX_DYNAMIC_RELOCATIONS: usize = 1_048_576;
const ELF_RELATIVE_RELOCATION_TYPES: [(Arch, u32); 12] = [
    (Arch::X86, object::elf::R_386_RELATIVE),
    (Arch::X86_64, object::elf::R_X86_64_RELATIVE),
    (Arch::Arm, object::elf::R_ARM_RELATIVE),
    (Arch::Aarch64, object::elf::R_AARCH64_RELATIVE),
    (Arch::RiscV32, object::elf::R_RISCV_RELATIVE),
    (Arch::RiscV64, object::elf::R_RISCV_RELATIVE),
    (Arch::PowerPc, object::elf::R_PPC_RELATIVE),
    (Arch::PowerPc64, object::elf::R_PPC64_RELATIVE),
    (Arch::Sparc, object::elf::R_SPARC_RELATIVE),
    (Arch::Sparc64, object::elf::R_SPARC_RELATIVE),
    (Arch::LoongArch64, object::elf::R_LARCH_RELATIVE),
    (Arch::S390x, object::elf::R_390_RELATIVE),
];

#[derive(Debug, Clone, Copy)]
struct PointerRelocation {
    addend: i64,
    implicit_addend: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum AotLayoutProfile {
    #[default]
    PointerPair,
    LengthAndPointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AotProfileSelection {
    pub selected: AotLayoutProfile,
    pub declared: Option<AotLayoutProfile>,
    pub disagreement: bool,
    pub self_consistent_rows: u16,
    pub mapped_rows: u16,
}

#[derive(Debug, Clone, Copy)]
enum SectionExtent {
    EndPointer {
        flags_offset: usize,
        allowed_flags: u32,
        has_end_flag: u32,
        end_pointer_index: usize,
    },
    Length {
        length_offset: usize,
    },
}

#[derive(Debug, Clone, Copy)]
struct LayoutProfile {
    id: AotLayoutProfile,
    min_major: u16,
    max_major: u16,
    fixed_row_bytes: usize,
    pointer_count: usize,
    id_offset: usize,
    start_offset: usize,
    min_section_id: i32,
    max_section_id: i32,
    extent: SectionExtent,
}

impl LayoutProfile {
    fn row_size(self, pointer_size: usize) -> Option<usize> {
        self.pointer_count
            .checked_mul(pointer_size)?
            .checked_add(self.fixed_row_bytes)
    }

    const fn hints_at(self, major_version: u16) -> bool {
        major_version >= self.min_major && major_version <= self.max_major
    }
}

const AOT_LAYOUT_PROFILES: [LayoutProfile; 2] = [
    LayoutProfile {
        id: AotLayoutProfile::PointerPair,
        min_major: 8,
        max_major: 18,
        fixed_row_bytes: 8,
        pointer_count: 2,
        id_offset: 0,
        start_offset: 8,
        min_section_id: 100,
        max_section_id: 399,
        extent: SectionExtent::EndPointer {
            flags_offset: 4,
            allowed_flags: 1,
            has_end_flag: 1,
            end_pointer_index: 1,
        },
    },
    LayoutProfile {
        id: AotLayoutProfile::LengthAndPointer,
        min_major: 18,
        max_major: MAX_PROFILE_MAJOR,
        fixed_row_bytes: 8,
        pointer_count: 1,
        id_offset: 0,
        start_offset: 8,
        min_section_id: 100,
        max_section_id: 399,
        extent: SectionExtent::Length { length_offset: 4 },
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotSection {
    pub id: i32,
    pub flags: i32,
    pub start_rva: u32,
    pub end_rva: u32,
}

impl AotSection {
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.end_rva.saturating_sub(self.start_rva)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyToRunHeader {
    pub file_offset: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub flags: u32,
    pub sections: Vec<AotSection>,
}

impl ReadyToRunHeader {
    #[must_use]
    pub fn section(&self, id: i32) -> Option<&AotSection> {
        self.sections.iter().find(|s: &&AotSection| s.id == id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyToRunInspection {
    pub header: ReadyToRunHeader,
    pub profile_selection: AotProfileSelection,
}

#[must_use]
pub fn locate_ready_to_run_header(image: &[u8]) -> Option<ReadyToRunHeader> {
    inspect_ready_to_run_header(image)
        .ok()
        .flatten()
        .map(|inspection: ReadyToRunInspection| inspection.header)
}

pub fn inspect_ready_to_run_header(
    image: &[u8],
) -> crate::error::Result<Option<ReadyToRunInspection>> {
    let native: NativeFile = parse_native(image).map_err(|error: disrobe_binfmt::Error| {
        crate::error::Error::AotContainerRead(error.to_string())
    })?;
    if !supported_native_format(native.format) {
        return Err(crate::error::Error::UnsupportedAotContainer(
            native.format.label(),
        ));
    }
    if !matches!(native.endian, Endian::Little) {
        return Err(crate::error::Error::UnsupportedAotContainer(
            "big-endian image",
        ));
    }
    let file: ObjFile<'_, &[u8]> = ObjFile::parse(image)
        .map_err(|error: object::Error| crate::error::Error::AotContainerRead(error.to_string()))?;
    if !section_views_agree(&native, &file) {
        return Err(crate::error::Error::AotContainerRead(
            "container section views disagree".to_owned(),
        ));
    }
    let needle: [u8; 4] = READY_TO_RUN_SIGNATURE.to_le_bytes();
    if byte_search::find(image, &needle).is_none() {
        return Ok(None);
    }
    let pointer_relocations: BTreeMap<u64, PointerRelocation> =
        pointer_relocations(&native, &file)?;
    let Some(pointer_bits): Option<u32> = native.bits.checked_div(8) else {
        return Err(crate::error::Error::UnsupportedAotContainer(
            "invalid pointer width",
        ));
    };
    let pointer_size: usize =
        usize::try_from(pointer_bits).map_err(|_: std::num::TryFromIntError| {
            crate::error::Error::UnsupportedAotContainer("invalid pointer width")
        })?;
    if !matches!(pointer_size, 4 | 8) {
        return Err(crate::error::Error::UnsupportedAotContainer(
            "invalid pointer width",
        ));
    }
    let Some(address_base): Option<u64> = container_address_base(&file) else {
        return Err(crate::error::Error::AotContainerRead(
            "container has no file-backed section".to_owned(),
        ));
    };
    let mut cursor: usize = 0;
    let mut best: Option<ScoredHeader> = None;
    let mut ambiguous: bool = false;
    while cursor < image.len() {
        let Some(remaining): Option<&[u8]> = image.get(cursor..) else {
            break;
        };
        let Some(found): Option<usize> = byte_search::find(remaining, &needle) else {
            break;
        };
        let candidate: usize = cursor.saturating_add(found);
        let evaluation: CandidateEvaluation = read_ready_to_run_header(
            image,
            &file,
            &pointer_relocations,
            pointer_size,
            address_base,
            candidate,
        );
        let scored: Option<ScoredHeader> = evaluation.best;
        if let Some(scored) = scored {
            match best.as_ref() {
                None => {
                    best = Some(scored);
                    ambiguous = evaluation.ambiguous;
                }
                Some(current) => match scored.score.cmp(&current.score) {
                    Ordering::Greater => {
                        best = Some(scored);
                        ambiguous = evaluation.ambiguous;
                    }
                    Ordering::Equal
                        if evaluation.ambiguous
                            || scored.header != current.header
                            || scored.profile_selection != current.profile_selection =>
                    {
                        ambiguous = true;
                    }
                    Ordering::Equal | Ordering::Less => {}
                },
            }
        }
        let Some(next): Option<usize> = candidate.checked_add(1) else {
            break;
        };
        cursor = next;
    }
    if ambiguous {
        Err(crate::error::Error::AmbiguousAotLayout)
    } else {
        Ok(best.map(|scored: ScoredHeader| ReadyToRunInspection {
            header: scored.header,
            profile_selection: scored.profile_selection,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StructuralScore {
    self_consistent_rows: u16,
    mapped_rows: u16,
    ordered_rows: u16,
    entry_size_match: bool,
    has_spanned_row: bool,
    file_backed_rows: u16,
}

#[derive(Debug, Clone)]
struct ScoredHeader {
    header: ReadyToRunHeader,
    profile_selection: AotProfileSelection,
    score: StructuralScore,
}

#[derive(Debug, Clone)]
struct CandidateEvaluation {
    best: Option<ScoredHeader>,
    ambiguous: bool,
}

impl CandidateEvaluation {
    const fn none() -> Self {
        Self {
            best: None,
            ambiguous: false,
        }
    }
}

fn read_ready_to_run_header<'a>(
    image: &'a [u8],
    file: &ObjFile<'a, &'a [u8]>,
    pointer_relocations: &BTreeMap<u64, PointerRelocation>,
    pointer_size: usize,
    address_base: u64,
    at: usize,
) -> CandidateEvaluation {
    let Some(major_at): Option<usize> = at.checked_add(4) else {
        return CandidateEvaluation::none();
    };
    let Some(minor_at): Option<usize> = at.checked_add(6) else {
        return CandidateEvaluation::none();
    };
    let Some(flags_at): Option<usize> = at.checked_add(8) else {
        return CandidateEvaluation::none();
    };
    let Some(count_at): Option<usize> = at.checked_add(12) else {
        return CandidateEvaluation::none();
    };
    let Some(entry_size_at): Option<usize> = at.checked_add(14) else {
        return CandidateEvaluation::none();
    };
    let Some(entry_type_at): Option<usize> = at.checked_add(15) else {
        return CandidateEvaluation::none();
    };
    let Ok(major_version): Result<u16, disrobe_bytes::ByteReadError> =
        read_u16_le_at(image, major_at)
    else {
        return CandidateEvaluation::none();
    };
    let Ok(minor_version): Result<u16, disrobe_bytes::ByteReadError> =
        read_u16_le_at(image, minor_at)
    else {
        return CandidateEvaluation::none();
    };
    let Ok(flags): Result<u32, disrobe_bytes::ByteReadError> = read_u32_le_at(image, flags_at)
    else {
        return CandidateEvaluation::none();
    };
    let Ok(count): Result<u16, disrobe_bytes::ByteReadError> = read_u16_le_at(image, count_at)
    else {
        return CandidateEvaluation::none();
    };
    let Some(entry_size): Option<u8> = image.get(entry_size_at).copied() else {
        return CandidateEvaluation::none();
    };
    let Some(entry_type): Option<u8> = image.get(entry_type_at).copied() else {
        return CandidateEvaluation::none();
    };
    if entry_type != READY_TO_RUN_ENTRY_TYPE {
        return CandidateEvaluation::none();
    }
    if count == 0 || count > MAX_READY_TO_RUN_SECTIONS {
        return CandidateEvaluation::none();
    }
    let declared: Option<AotLayoutProfile> = declared_profile(major_version);
    let mut best: Option<ScoredHeader> = None;
    let mut ambiguous: bool = false;
    let mut maximal_hint: bool = false;
    for hinted_phase in [true, false] {
        for profile in AOT_LAYOUT_PROFILES {
            let is_hint: bool = declared == Some(profile.id);
            if is_hint != hinted_phase {
                continue;
            }
            let profile_cannot_tie_maximal_hint: bool = !hinted_phase
                && maximal_hint
                && profile.row_size(pointer_size) != Some(usize::from(entry_size));
            if profile_cannot_tie_maximal_hint {
                continue;
            }
            let Some(scored): Option<ScoredHeader> = score_profile(
                image,
                file,
                pointer_relocations,
                pointer_size,
                address_base,
                at,
                major_version,
                minor_version,
                flags,
                count,
                entry_size,
                profile,
            ) else {
                continue;
            };
            match best.as_ref() {
                None => {
                    best = Some(scored);
                    ambiguous = false;
                }
                Some(current) => match scored.score.cmp(&current.score) {
                    Ordering::Greater => {
                        best = Some(scored);
                        ambiguous = false;
                    }
                    Ordering::Equal
                        if scored.header.sections != current.header.sections
                            || scored.profile_selection != current.profile_selection =>
                    {
                        ambiguous = true;
                    }
                    Ordering::Equal | Ordering::Less => {}
                },
            }
        }
        if hinted_phase {
            maximal_hint = best.as_ref().is_some_and(|scored: &ScoredHeader| {
                scored.score == maximal_structural_score(count)
            });
        }
    }
    let best: Option<ScoredHeader> =
        best.filter(|scored: &ScoredHeader| profile_is_acceptable(scored, count));
    CandidateEvaluation {
        ambiguous: ambiguous && best.is_some(),
        best,
    }
}

#[allow(clippy::too_many_arguments)]
fn score_profile<'a>(
    image: &'a [u8],
    file: &ObjFile<'a, &'a [u8]>,
    pointer_relocations: &BTreeMap<u64, PointerRelocation>,
    pointer_size: usize,
    address_base: u64,
    at: usize,
    major_version: u16,
    minor_version: u16,
    flags: u32,
    count: u16,
    entry_size: u8,
    profile: LayoutProfile,
) -> Option<ScoredHeader> {
    let row_size: usize = profile.row_size(pointer_size)?;
    let table: usize = at.checked_add(16)?;
    let table_bytes: usize = usize::from(count).checked_mul(row_size)?;
    let candidate_bytes: usize = 16usize.checked_add(table_bytes)?;
    if !file_range_is_backed(file, at, candidate_bytes) {
        return None;
    }
    let remaining: usize = image.len().checked_sub(table)?;
    let capacity: usize =
        bounded_element_capacity(u64::from(count), row_size, remaining).min(usize::from(count));
    let mut sections: Vec<AotSection> = Vec::with_capacity(capacity);
    let mut self_consistent_rows: u16 = 0;
    let mut mapped_rows: u16 = 0;
    let mut file_backed_rows: u16 = 0;
    let mut ordered_rows: u16 = 0;
    let mut spanned_rows: u16 = 0;
    let mut previous_id: Option<i32> = None;
    for index in 0..usize::from(count) {
        let row_delta: usize = index.checked_mul(row_size)?;
        let row: usize = table.checked_add(row_delta)?;
        let row_end: usize = row.checked_add(row_size)?;
        let row_bytes: &[u8] = image.get(row..row_end)?;
        let id: i32 = read_i32_le_at(row_bytes, profile.id_offset).ok()?;
        let id_is_plausible: bool = id >= profile.min_section_id && id <= profile.max_section_id;
        let ordered: bool = previous_id.is_none_or(|previous: i32| id > previous);
        previous_id = Some(id);
        let Some((row_flags, start, end)): Option<(i32, u64, u64)> = decode_section_extent(
            row_bytes,
            file,
            pointer_relocations,
            row,
            pointer_size,
            profile,
        ) else {
            continue;
        };
        let extent_is_consistent: bool = end >= start;
        if !id_is_plausible || !extent_is_consistent {
            continue;
        }
        self_consistent_rows = self_consistent_rows.saturating_add(1);
        if ordered {
            ordered_rows = ordered_rows.saturating_add(1);
        }
        if end > start {
            spanned_rows = spanned_rows.saturating_add(1);
        }
        if address_range_is_mapped(file, start, end) {
            mapped_rows = mapped_rows.saturating_add(1);
        }
        if address_range_is_file_backed(file, start, end) {
            file_backed_rows = file_backed_rows.saturating_add(1);
        }
        let start_rva: u32 = u32::try_from(start.checked_sub(address_base)?).ok()?;
        let end_rva: u32 = u32::try_from(end.checked_sub(address_base)?).ok()?;
        sections.push(AotSection {
            id,
            flags: row_flags,
            start_rva,
            end_rva,
        });
    }
    let declared: Option<AotLayoutProfile> = declared_profile(major_version);
    let selection: AotProfileSelection = AotProfileSelection {
        selected: profile.id,
        declared,
        disagreement: declared.is_some_and(|value: AotLayoutProfile| value != profile.id),
        self_consistent_rows,
        mapped_rows,
    };
    let header: ReadyToRunHeader = ReadyToRunHeader {
        file_offset: u32::try_from(at).ok()?,
        major_version,
        minor_version,
        flags,
        sections,
    };
    let score: StructuralScore = StructuralScore {
        self_consistent_rows,
        mapped_rows,
        ordered_rows,
        entry_size_match: usize::from(entry_size) == row_size,
        has_spanned_row: spanned_rows > 0,
        file_backed_rows,
    };
    Some(ScoredHeader {
        header,
        profile_selection: selection,
        score,
    })
}

const fn maximal_structural_score(count: u16) -> StructuralScore {
    StructuralScore {
        self_consistent_rows: count,
        mapped_rows: count,
        ordered_rows: count,
        entry_size_match: true,
        has_spanned_row: true,
        file_backed_rows: count,
    }
}

fn decode_section_extent<'a>(
    row: &[u8],
    file: &ObjFile<'a, &'a [u8]>,
    pointer_relocations: &BTreeMap<u64, PointerRelocation>,
    row_file_offset: usize,
    pointer_size: usize,
    profile: LayoutProfile,
) -> Option<(i32, u64, u64)> {
    let start: u64 = read_pointer(
        row,
        file,
        pointer_relocations,
        row_file_offset,
        profile.start_offset,
        pointer_size,
    )?;
    match profile.extent {
        SectionExtent::EndPointer {
            flags_offset,
            allowed_flags,
            has_end_flag,
            end_pointer_index,
        } => {
            let row_flags: i32 = read_i32_le_at(row, flags_offset).ok()?;
            let raw_flags: u32 = row_flags as u32;
            if raw_flags & !allowed_flags != 0 {
                return None;
            }
            let end: u64 = if raw_flags & has_end_flag == 0 {
                start
            } else {
                let pointer_delta: usize = end_pointer_index.checked_mul(pointer_size)?;
                let end_offset: usize = profile.start_offset.checked_add(pointer_delta)?;
                read_pointer(
                    row,
                    file,
                    pointer_relocations,
                    row_file_offset,
                    end_offset,
                    pointer_size,
                )?
            };
            Some((row_flags, start, end))
        }
        SectionExtent::Length { length_offset } => {
            let length: i32 = read_i32_le_at(row, length_offset).ok()?;
            let length: u64 = u64::try_from(length).ok()?;
            let end: u64 = start.checked_add(length)?;
            Some((0, start, end))
        }
    }
}

fn read_pointer<'a>(
    bytes: &[u8],
    file: &ObjFile<'a, &'a [u8]>,
    pointer_relocations: &BTreeMap<u64, PointerRelocation>,
    row_file_offset: usize,
    at: usize,
    pointer_size: usize,
) -> Option<u64> {
    let raw: u64 = match pointer_size {
        4 => read_u32_le_at(bytes, at).ok().map(u64::from),
        8 => read_u64_le_at(bytes, at).ok(),
        _ => None,
    }?;
    if pointer_relocations.is_empty() {
        return Some(raw);
    }
    let pointer_file_offset: usize = row_file_offset.checked_add(at)?;
    let pointer_address: u64 = file_offset_to_address(file, pointer_file_offset, pointer_size)?;
    let Some(relocation): Option<&PointerRelocation> = pointer_relocations.get(&pointer_address)
    else {
        return Some(raw);
    };
    apply_pointer_relocation(raw, *relocation)
}

fn apply_pointer_relocation(raw: u64, relocation: PointerRelocation) -> Option<u64> {
    if !relocation.implicit_addend {
        return u64::try_from(relocation.addend).ok();
    }
    if relocation.addend >= 0 {
        let addend: u64 = u64::try_from(relocation.addend).ok()?;
        raw.checked_add(addend)
    } else {
        raw.checked_sub(relocation.addend.unsigned_abs())
    }
}

fn profile_is_acceptable(scored: &ScoredHeader, count: u16) -> bool {
    scored.score.self_consistent_rows == count
        && scored.score.mapped_rows == count
        && scored.score.ordered_rows == count
        && scored.score.has_spanned_row
        && scored.score.entry_size_match
        && scored.header.sections.len() == usize::from(count)
}

fn declared_profile(major_version: u16) -> Option<AotLayoutProfile> {
    let mut declared: Option<AotLayoutProfile> = None;
    for profile in AOT_LAYOUT_PROFILES {
        if !profile.hints_at(major_version) {
            continue;
        }
        if declared.is_some() {
            return None;
        }
        declared = Some(profile.id);
    }
    declared
}

const fn supported_native_format(format: ParsedNativeFormat) -> bool {
    matches!(
        format,
        ParsedNativeFormat::Pe32
            | ParsedNativeFormat::Pe64
            | ParsedNativeFormat::Elf32
            | ParsedNativeFormat::Elf64
            | ParsedNativeFormat::MachO32
            | ParsedNativeFormat::MachO64
    )
}

fn pointer_relocations<'a>(
    native: &NativeFile,
    file: &ObjFile<'a, &'a [u8]>,
) -> crate::error::Result<BTreeMap<u64, PointerRelocation>> {
    let mut values: BTreeMap<u64, PointerRelocation> = BTreeMap::new();
    if !matches!(
        native.format,
        ParsedNativeFormat::Elf32 | ParsedNativeFormat::Elf64
    ) {
        return Ok(values);
    }
    let Some(relocations): Option<DynamicRelocationIterator<'a, '_, &'a [u8]>> =
        file.dynamic_relocations()
    else {
        return Ok(values);
    };
    let mut relocation_count: usize = 0;
    for (address, relocation) in relocations {
        relocation_count = relocation_count.checked_add(1).ok_or_else(|| {
            crate::error::Error::AotContainerRead("dynamic relocation count overflowed".to_owned())
        })?;
        if relocation_count > MAX_DYNAMIC_RELOCATIONS {
            return Err(crate::error::Error::AotContainerRead(
                "dynamic relocation count exceeds parser limit".to_owned(),
            ));
        }
        let r_type: u32 = match relocation.flags() {
            RelocationFlags::Elf { r_type } => r_type,
            _ => continue,
        };
        let is_relative: bool = ELF_RELATIVE_RELOCATION_TYPES.iter().any(
            |(candidate_arch, candidate_type): &(Arch, u32)| {
                *candidate_arch == native.arch && *candidate_type == r_type
            },
        );
        if !is_relative {
            continue;
        }
        if !matches!(relocation.target(), RelocationTarget::Absolute) {
            return Err(crate::error::Error::AotContainerRead(
                "relative relocation has a non-absolute target".to_owned(),
            ));
        }
        let value: PointerRelocation = PointerRelocation {
            addend: relocation.addend(),
            implicit_addend: relocation.has_implicit_addend(),
        };
        if values.insert(address, value).is_some() {
            return Err(crate::error::Error::AotContainerRead(
                "duplicate relative relocation address".to_owned(),
            ));
        }
    }
    Ok(values)
}

fn section_views_agree<'a>(native: &NativeFile, file: &ObjFile<'a, &'a [u8]>) -> bool {
    let mut native_sections: std::slice::Iter<'_, SectionInfo> = native.sections.iter();
    for object_section in file.sections() {
        let Some(native_section): Option<&SectionInfo> = native_sections.next() else {
            return false;
        };
        if native_section.address != object_section.address()
            || native_section.size != object_section.size()
        {
            return false;
        }
    }
    native_sections.next().is_none()
}

fn container_address_base<'a>(file: &ObjFile<'a, &'a [u8]>) -> Option<u64> {
    let relative_base: u64 = file.relative_address_base();
    if relative_base != 0 {
        return Some(relative_base);
    }
    let segment_base: Option<u64> = file
        .segments()
        .filter_map(|segment| {
            let address: u64 = segment.address();
            let (_, file_size): (u64, u64) = segment.file_range();
            (file_size != 0).then_some(address)
        })
        .min();
    if segment_base.is_some() {
        return segment_base;
    }
    file.sections()
        .filter_map(|section| {
            let address: u64 = section.address();
            let (_, size): (u64, u64) = section.file_range()?;
            (size != 0).then_some(address)
        })
        .min()
}

fn file_offset_to_address<'a>(file: &ObjFile<'a, &'a [u8]>, at: usize, size: usize) -> Option<u64> {
    let at: u64 = u64::try_from(at).ok()?;
    let size: u64 = u64::try_from(size).ok()?;
    let end: u64 = at.checked_add(size)?;
    for section in file.sections() {
        let section_address: u64 = section.address();
        let Some((file_start, file_size)): Option<(u64, u64)> = section.file_range() else {
            continue;
        };
        let file_end: u64 = file_start.checked_add(file_size)?;
        if at < file_start || end > file_end {
            continue;
        }
        let delta: u64 = at.checked_sub(file_start)?;
        return section_address.checked_add(delta);
    }
    None
}

fn file_range_is_backed<'a>(file: &ObjFile<'a, &'a [u8]>, at: usize, size: usize) -> bool {
    let Ok(start): Result<u64, std::num::TryFromIntError> = u64::try_from(at) else {
        return false;
    };
    let Ok(size): Result<u64, std::num::TryFromIntError> = u64::try_from(size) else {
        return false;
    };
    let Some(end): Option<u64> = start.checked_add(size) else {
        return false;
    };
    file.sections().any(|section| {
        let Some((file_start, file_size)): Option<(u64, u64)> = section.file_range() else {
            return false;
        };
        let Some(file_end): Option<u64> = file_start.checked_add(file_size) else {
            return false;
        };
        start >= file_start && end <= file_end
    })
}

fn address_range_is_mapped<'a>(file: &ObjFile<'a, &'a [u8]>, start: u64, end: u64) -> bool {
    if end < start {
        return false;
    }
    file.sections().any(|section| {
        let section_address: u64 = section.address();
        let section_size: u64 = section.size();
        let Some(section_end): Option<u64> = section_address.checked_add(section_size) else {
            return false;
        };
        address_range_is_inside(start, end, section_address, section_end)
    })
}

fn address_range_is_file_backed<'a>(file: &ObjFile<'a, &'a [u8]>, start: u64, end: u64) -> bool {
    if end < start {
        return false;
    }
    file.sections().any(|section| {
        let section_address: u64 = section.address();
        let Some((_, file_size)): Option<(u64, u64)> = section.file_range() else {
            return false;
        };
        let Some(section_end): Option<u64> = section_address.checked_add(file_size) else {
            return false;
        };
        address_range_is_inside(start, end, section_address, section_end)
    })
}

const fn address_range_is_inside(
    start: u64,
    end: u64,
    section_start: u64,
    section_end: u64,
) -> bool {
    if start == end {
        start >= section_start && start < section_end
    } else {
        start >= section_start && end <= section_end
    }
}

fn section_bytes_for_address<'a>(
    image: &'a [u8],
    file: &ObjFile<'a, &'a [u8]>,
    start: u64,
    end: u64,
) -> Option<&'a [u8]> {
    if end < start {
        return None;
    }
    for section in file.sections() {
        let section_address: u64 = section.address();
        let Some((file_start, file_size)): Option<(u64, u64)> = section.file_range() else {
            continue;
        };
        if file_size == 0 {
            continue;
        }
        let Some(section_end): Option<u64> = section_address.checked_add(file_size) else {
            continue;
        };
        if !address_range_is_inside(start, end, section_address, section_end) {
            continue;
        }
        let delta: u64 = start.checked_sub(section_address)?;
        let span: u64 = end.checked_sub(start)?;
        let slice_start: u64 = file_start.checked_add(delta)?;
        let slice_end: u64 = slice_start.checked_add(span)?;
        let slice_start: usize = usize::try_from(slice_start).ok()?;
        let slice_end: usize = usize::try_from(slice_end).ok()?;
        return image.get(slice_start..slice_end);
    }
    None
}

const MIN_NAME_LEN: usize = 2;
const MAX_NAME_LEN: usize = 256;
const NAME_RUN_THRESHOLDS: [usize; 4] = [1, 2, 3, 4];
const MAX_RECOVERED_NAMES: usize = 65536;

#[must_use]
pub fn is_metadata_identifier(text: &str) -> bool {
    let mut chars: std::str::Chars<'_> = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '<') {
        return false;
    }
    text.chars().all(|c: char| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '<' | '>' | '.' | '`' | '+' | '/')
    })
}

#[must_use]
pub fn decode_metadata_unsigned(bytes: &[u8], at: usize) -> Option<(u32, usize)> {
    let first: u8 = *bytes.get(at)?;
    if first & 1 == 0 {
        return Some((u32::from(first >> 1), 1));
    }
    if first & 3 == 1 {
        let second: u8 = *bytes.get(at.checked_add(1)?)?;
        return Some((u32::from(first >> 2) | (u32::from(second) << 6), 2));
    }
    if first & 7 == 3 {
        let second: u8 = *bytes.get(at.checked_add(1)?)?;
        let third: u8 = *bytes.get(at.checked_add(2)?)?;
        let value: u32 =
            u32::from(first >> 3) | (u32::from(second) << 5) | (u32::from(third) << 13);
        return Some((value, 3));
    }
    if first & 15 == 7 {
        let second: u8 = *bytes.get(at.checked_add(1)?)?;
        let third: u8 = *bytes.get(at.checked_add(2)?)?;
        let fourth: u8 = *bytes.get(at.checked_add(3)?)?;
        let value: u32 = u32::from(first >> 4)
            | (u32::from(second) << 4)
            | (u32::from(third) << 12)
            | (u32::from(fourth) << 20);
        return Some((value, 4));
    }
    if first & 31 == 15 {
        let value_at: usize = at.checked_add(1)?;
        let value: u32 = read_u32_le_at(bytes, value_at).ok()?;
        return Some((value, 5));
    }
    None
}

fn read_metadata_name(bytes: &[u8], at: usize) -> Option<(&str, usize)> {
    let (length, width): (u32, usize) = decode_metadata_unsigned(bytes, at)?;
    let length: usize = length as usize;
    if !(MIN_NAME_LEN..=MAX_NAME_LEN).contains(&length) {
        return None;
    }
    let begin: usize = at.checked_add(width)?;
    let end: usize = begin.checked_add(length)?;
    let slice: &[u8] = bytes.get(begin..end)?;
    let text: &str = std::str::from_utf8(slice).ok()?;
    if text
        .chars()
        .any(|c: char| c.is_control() || c == char::REPLACEMENT_CHARACTER)
    {
        return None;
    }
    Some((text, end))
}

fn recover_names_at_threshold(bytes: &[u8], min_run: usize, out: &mut Vec<String>) {
    let mut at: usize = 0;
    while at < bytes.len() && out.len() < MAX_RECOVERED_NAMES {
        let mut cursor: usize = at;
        let mut run: Vec<&str> = Vec::new();
        while let Some((text, next)) = read_metadata_name(bytes, cursor) {
            run.push(text);
            cursor = next;
            if run.len() >= MAX_RECOVERED_NAMES {
                break;
            }
        }
        if run.len() >= min_run {
            for text in run {
                if out.len() >= MAX_RECOVERED_NAMES {
                    break;
                }
                if is_metadata_identifier(text) {
                    out.push(text.to_owned());
                }
            }
            at = cursor;
        } else {
            at = at.saturating_add(1);
        }
    }
}

fn recover_names_in(bytes: &[u8], out: &mut Vec<String>) {
    for min_run in NAME_RUN_THRESHOLDS {
        recover_names_at_threshold(bytes, min_run, out);
    }
}

#[must_use]
pub fn recover_metadata_names(image: &[u8], header: &ReadyToRunHeader) -> Vec<String> {
    let Ok(native): disrobe_binfmt::Result<NativeFile> = parse_native(image) else {
        return Vec::new();
    };
    if !supported_native_format(native.format) || !matches!(native.endian, Endian::Little) {
        return Vec::new();
    }
    let Ok(file): Result<ObjFile<'_, &[u8]>, object::Error> = ObjFile::parse(image) else {
        return Vec::new();
    };
    if !section_views_agree(&native, &file) {
        return Vec::new();
    }
    let Some(address_base): Option<u64> = container_address_base(&file) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for section in &header.sections {
        if section.is_empty() {
            continue;
        }
        let Some(start): Option<u64> = address_base.checked_add(u64::from(section.start_rva))
        else {
            continue;
        };
        let Some(end): Option<u64> = address_base.checked_add(u64::from(section.end_rva)) else {
            continue;
        };
        let Some(region): Option<&[u8]> = section_bytes_for_address(image, &file, start, end)
        else {
            continue;
        };
        recover_names_in(region, &mut out);
    }
    out.sort_unstable();
    out.dedup();
    out
}

const AOT_NEEDLES: &[(&[u8], &str)] = &[
    (b"__modules_a", "modules_table"),
    (b"NativeAOT", "aot_marker"),
    (b"RhpNewFast", "rhp_alloc"),
    (b"S_P_CoreLib", "corelib_module"),
    (b"S_P_TypeLoader", "typeloader_module"),
    (b"RhFindBlob", "rh_blob_locator"),
    (b"RhpThrowEx", "rh_throw"),
    (b"RhpReversePInvoke", "reverse_pinvoke"),
];

const EAGER_CCTOR_SCAN_CAP: u32 = 512;

#[must_use]
pub fn detect(image: &[u8]) -> AotReport {
    let mut symbols: BTreeMap<String, u32> = BTreeMap::new();
    let mut modules_table_offset: Option<u32> = None;
    let mut eager: u32 = 0;
    for (needle, label) in AOT_NEEDLES {
        let Some(found): Option<usize> = byte_search::find(image, needle) else {
            continue;
        };
        let absolute: u32 = u32::try_from(found).map_or(u32::MAX, |value: u32| value);
        symbols.insert((*label).to_owned(), absolute);
        if *label == "modules_table" {
            modules_table_offset = Some(absolute);
        }
    }
    let eager_marker: &[u8] = b"EagerCctor";
    let mut cursor: usize = 0;
    while eager < EAGER_CCTOR_SCAN_CAP {
        let Some(remaining): Option<&[u8]> = image.get(cursor..) else {
            break;
        };
        let Some(pos): Option<usize> = byte_search::find(remaining, eager_marker) else {
            break;
        };
        eager = eager.saturating_add(1);
        let Some(found): Option<usize> = cursor.checked_add(pos) else {
            break;
        };
        let Some(next): Option<usize> = found.checked_add(eager_marker.len()) else {
            break;
        };
        cursor = next;
    }
    let ready_to_run: Option<ReadyToRunHeader> = locate_ready_to_run_header(image);
    let recovered_names: Vec<String> = ready_to_run
        .as_ref()
        .map_or_else(Vec::new, |header: &ReadyToRunHeader| {
            recover_metadata_names(image, header)
        });
    let metadata_attribution: AotMetadataAttribution = ready_to_run.as_ref().map_or_else(
        AotMetadataAttribution::default,
        |header: &ReadyToRunHeader| match recover_metadata_attribution(image, header) {
            Ok(attribution) => attribution,
            Err(error) => AotMetadataAttribution::rejected(error),
        },
    );
    let is_native_aot: bool = ready_to_run.is_some()
        || symbols.contains_key("aot_marker")
        || symbols.contains_key("modules_table")
        || symbols.contains_key("rhp_alloc")
        || symbols.contains_key("corelib_module");
    let runtime: AotRuntime = classify_runtime(image);
    AotReport {
        is_native_aot,
        recovered_symbols: symbols,
        modules_table_offset,
        eager_class_constructors: eager,
        runtime_label: runtime,
        ready_to_run,
        recovered_names,
        metadata_attribution,
    }
}

fn classify_runtime(image: &[u8]) -> AotRuntime {
    if byte_search::contains(image, b"net10.0") {
        AotRuntime::Net10
    } else if byte_search::contains(image, b"net9.0") {
        AotRuntime::Net9
    } else if byte_search::contains(image, b"net8.0") {
        AotRuntime::Net8
    } else if byte_search::contains(image, b"net7.0") {
        AotRuntime::Net7
    } else {
        AotRuntime::Unknown
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_native_aot_when_marker_present() {
        let mut img: Vec<u8> = vec![0u8; 1024];
        img[100..109].copy_from_slice(b"NativeAOT");
        let report: AotReport = detect(&img);
        assert!(report.is_native_aot);
    }

    #[test]
    fn detect_reports_runtime_label_net8() {
        let mut img: Vec<u8> = b"...net8.0...".to_vec();
        img.extend_from_slice(b"NativeAOT");
        let report: AotReport = detect(&img);
        assert_eq!(report.runtime_label, AotRuntime::Net8);
    }

    #[test]
    fn repeated_marker_reports_one_consistent_position() {
        let mut img: Vec<u8> = vec![0u8; 1024];
        img[100..111].copy_from_slice(b"__modules_a");
        img[500..511].copy_from_slice(b"__modules_a");
        let report: AotReport = detect(&img);
        assert_eq!(
            report.recovered_symbols.get("modules_table").copied(),
            report.modules_table_offset,
            "the two fields describe the same marker and must not disagree about where it is"
        );
        assert_eq!(
            report.modules_table_offset,
            Some(100),
            "a repeated marker is reported at its first position"
        );
    }

    #[test]
    fn detect_empty_image_is_not_aot() {
        let report: AotReport = detect(&[]);
        assert!(!report.is_native_aot);
    }

    #[test]
    fn legacy_serialized_reports_default_metadata_attribution() {
        let report: AotReport = detect(&[]);
        let mut value: serde_json::Value =
            serde_json::to_value(report).expect("AotReport must serialize");
        let object: &mut serde_json::Map<String, serde_json::Value> = value
            .as_object_mut()
            .expect("AotReport must serialize as an object");
        let removed: Option<serde_json::Value> = object.remove("metadata_attribution");
        assert!(removed.is_some());
        let restored: AotReport =
            serde_json::from_value(value).expect("legacy AotReport must deserialize");
        assert_eq!(
            restored.metadata_attribution,
            AotMetadataAttribution::default()
        );
    }

    #[test]
    fn eager_class_constructor_scan_is_capped() {
        let mut img: Vec<u8> = Vec::new();
        for _ in 0..600 {
            img.extend_from_slice(b"EagerCctor");
            img.push(0);
        }
        let report: AotReport = detect(&img);
        assert_eq!(report.eager_class_constructors, 512);
    }
}
