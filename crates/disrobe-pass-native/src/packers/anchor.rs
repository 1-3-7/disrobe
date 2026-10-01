use std::ops::Range;

use crate::packers::overlay::compute_image_end;
use crate::packers::pe_sections::{PeImage, PeSection};

const ENTRY_REGION_BYTES: usize = 0x200;
const OVERLAY_START_BYTES: usize = 0x40;
const FIXED_HEADER_BYTES: usize = 0x40;
const HEADER_TAIL_BYTES: usize = 0x40;
const PE_SIGNATURE_AND_COFF_BYTES: usize = 24;
const PE_SECTION_HEADER_BYTES: usize = 40;
const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
const ELF_PT_LOAD: u64 = 1;
const ELF_PT_NOTE: u64 = 4;
const ELF_NOTE_PAD_BYTES: usize = 8;
const MACHO_THIN_MAGICS: [(u32, usize); 2] = [(0xFEED_FACE, 28), (0xFEED_FACF, 32)];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AnchorRegions {
    spans: Vec<Range<usize>>,
}

impl AnchorRegions {
    #[must_use]
    pub(super) fn of(bytes: &[u8], pe: Option<&PeImage>) -> Self {
        let fixed_header =
            || -> Vec<Range<usize>> { std::iter::once(0..fixed_header_end(bytes)).collect() };
        let raw: Vec<Range<usize>> = match pe {
            Some(image) => pe_regions(bytes.len(), image),
            None if bytes.starts_with(ELF_MAGIC) => elf_regions(bytes).unwrap_or_else(fixed_header),
            None => fixed_header(),
        };
        let spans: Vec<Range<usize>> = raw
            .into_iter()
            .filter_map(|span: Range<usize>| {
                let end: usize = span.end.min(bytes.len());
                (span.start < end).then_some(span.start..end)
            })
            .collect();
        Self { spans }
    }

    #[must_use]
    pub(super) fn contains(&self, offset: usize) -> bool {
        self.spans
            .iter()
            .any(|span: &Range<usize>| span.contains(&offset))
    }

    #[must_use]
    pub(super) fn find(&self, bytes: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return None;
        }
        self.spans
            .iter()
            .filter_map(|span: &Range<usize>| {
                let window_end: usize = span.end.saturating_add(needle.len() - 1).min(bytes.len());
                let window: &[u8] = bytes.get(span.start..window_end)?;
                window
                    .windows(needle.len())
                    .position(|candidate: &[u8]| candidate == needle)
                    .map(|relative: usize| span.start + relative)
            })
            .min()
    }
}

fn fixed_header_end(bytes: &[u8]) -> usize {
    let Some(magic): Option<[u8; 4]> = bytes.get(..4).and_then(|b: &[u8]| b.try_into().ok()) else {
        return FIXED_HEADER_BYTES;
    };
    for (expected, header_len) in MACHO_THIN_MAGICS {
        let big_endian: bool = u32::from_be_bytes(magic) == expected;
        if !big_endian && u32::from_le_bytes(magic) != expected {
            continue;
        }
        let Some(command_bytes): Option<u64> = read_field(bytes, 20, 4, big_endian) else {
            return FIXED_HEADER_BYTES;
        };
        return usize::try_from(command_bytes)
            .ok()
            .and_then(|commands: usize| commands.checked_add(header_len + HEADER_TAIL_BYTES))
            .unwrap_or(FIXED_HEADER_BYTES);
    }
    FIXED_HEADER_BYTES
}

fn pe_regions(file_len: usize, image: &PeImage) -> Vec<Range<usize>> {
    let section_table_end: usize = (image.pe_header_offset as usize)
        .saturating_add(PE_SIGNATURE_AND_COFF_BYTES)
        .saturating_add(usize::from(image.size_of_optional_header))
        .saturating_add(image.sections.len().saturating_mul(PE_SECTION_HEADER_BYTES));
    let first_section_data: Option<usize> = image
        .sections
        .iter()
        .filter(|section: &&PeSection| section.raw_size > 0 && section.raw_pointer > 0)
        .map(|section: &PeSection| section.raw_pointer as usize)
        .min();
    let declared_headers: usize = image.size_of_headers as usize;
    let header_end: usize = section_table_end.max(
        first_section_data.map_or(declared_headers, |first: usize| declared_headers.min(first)),
    );
    let mut regions: Vec<Range<usize>> = Vec::with_capacity(3);
    regions.push(0..header_end.saturating_add(HEADER_TAIL_BYTES));
    if let Ok(entry) = image.file_offset_for_rva(image.entry_point_rva, file_len)
        && image.entry_point_rva != 0
    {
        regions.push(entry..entry.saturating_add(ENTRY_REGION_BYTES));
    }
    let image_end: usize = usize::try_from(compute_image_end(image, file_len)).unwrap_or(file_len);
    let overlay_start: usize = image_end.max(header_end);
    regions.push(overlay_start..overlay_start.saturating_add(OVERLAY_START_BYTES));
    regions
}

struct ElfLayout {
    wide: bool,
    big_endian: bool,
}

impl ElfLayout {
    const fn word(&self) -> usize {
        if self.wide { 8 } else { 4 }
    }
}

fn read_field(bytes: &[u8], offset: usize, width: usize, big_endian: bool) -> Option<u64> {
    let raw: &[u8] = bytes.get(offset..offset.checked_add(width)?)?;
    let fold = |value: u64, byte: &u8| (value << 8) | u64::from(*byte);
    Some(if big_endian {
        raw.iter().fold(0, fold)
    } else {
        raw.iter().rev().fold(0, fold)
    })
}

fn to_offset(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}

fn saturating_offset(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn elf_regions(bytes: &[u8]) -> Option<Vec<Range<usize>>> {
    let layout: ElfLayout = ElfLayout {
        wide: *bytes.get(4)? == 2,
        big_endian: *bytes.get(5)? == 2,
    };
    let field = |offset: usize, width: usize| read_field(bytes, offset, width, layout.big_endian);
    let word: usize = layout.word();
    let (entry_at, phoff_at, shoff_at, sizes_at): (usize, usize, usize, usize) = if layout.wide {
        (24, 32, 40, 52)
    } else {
        (24, 28, 32, 40)
    };
    let entry: u64 = field(entry_at, word)?;
    let phoff: usize = to_offset(field(phoff_at, word)?)?;
    let shoff: usize = to_offset(field(shoff_at, word)?)?;
    let ehsize: usize = to_offset(field(sizes_at, 2)?)?;
    let phentsize: usize = to_offset(field(sizes_at + 2, 2)?)?;
    let phnum: usize = to_offset(field(sizes_at + 4, 2)?)?;
    let shentsize: usize = to_offset(field(sizes_at + 6, 2)?)?;
    let shnum: usize = to_offset(field(sizes_at + 8, 2)?)?;

    let mut regions: Vec<Range<usize>> = Vec::with_capacity(5);
    regions.push(0..ehsize.max(FIXED_HEADER_BYTES.min(bytes.len())));
    let mut content_end: usize = ehsize;
    let mut entry_offset: Option<usize> = None;
    if phnum > 0 && phentsize > 0 {
        let table_end: usize = phoff.checked_add(phnum.checked_mul(phentsize)?)?;
        content_end = content_end.max(table_end);
        let mut notes: Vec<Range<usize>> = Vec::new();
        let (offset_at, vaddr_at, filesz_at): (usize, usize, usize) =
            if layout.wide { (8, 16, 32) } else { (4, 8, 16) };
        for index in 0..phnum {
            let header: usize = phoff.saturating_add(index.saturating_mul(phentsize));
            let (Some(p_type), Some(p_offset), Some(p_vaddr), Some(p_filesz)): (
                Option<u64>,
                Option<u64>,
                Option<u64>,
                Option<u64>,
            ) = (
                field(header, 4),
                field(header.saturating_add(offset_at), word),
                field(header.saturating_add(vaddr_at), word),
                field(header.saturating_add(filesz_at), word),
            ) else {
                break;
            };
            if p_type == ELF_PT_NOTE
                && let (Some(start), Some(len)) = (to_offset(p_offset), to_offset(p_filesz))
                && len > 0
            {
                notes.push(start..start.saturating_add(len));
            }
            if p_type != ELF_PT_LOAD {
                continue;
            }
            content_end = content_end.max(saturating_offset(p_offset.saturating_add(p_filesz)));
            if entry_offset.is_none() && entry >= p_vaddr && entry - p_vaddr < p_filesz {
                entry_offset = p_offset.checked_add(entry - p_vaddr).and_then(to_offset);
            }
        }
        notes.sort_by_key(|note: &Range<usize>| note.start);
        let headers_end: usize = notes
            .iter()
            .fold(table_end, |end: usize, note: &Range<usize>| {
                if note.start >= end && note.start - end < ELF_NOTE_PAD_BYTES {
                    note.end
                } else {
                    end
                }
            });
        regions.push(phoff..headers_end.saturating_add(HEADER_TAIL_BYTES));
    }
    if shnum > 0 && shentsize > 0 {
        let table_end: usize = shoff.checked_add(shnum.checked_mul(shentsize)?)?;
        regions.push(shoff..table_end);
        content_end = content_end.max(table_end);
    }
    if let Some(offset) = entry_offset {
        regions.push(offset..offset.saturating_add(ENTRY_REGION_BYTES));
    }
    regions.push(content_end..content_end.saturating_add(OVERLAY_START_BYTES));
    Some(regions)
}
