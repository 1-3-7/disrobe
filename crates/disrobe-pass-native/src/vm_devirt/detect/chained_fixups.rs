use disrobe_bytes::{read_u16_le_at, read_u32_le_at, read_u64_le_at};
use object::{Object, ObjectSection, ObjectSegment, macho};

use super::Segment;

const MAX_SEGMENTS: usize = 256;
const MAX_SECTIONS: usize = 4096;
const MAX_FIXUP_BYTES: usize = 1 << 20;
const MAX_CHAIN_STEPS: usize = 65_536;
const MAX_CHAIN_PAGES: usize = 65_536;

struct ImageSegment {
    va: u64,
    end: u64,
    file_offset: usize,
    file_end: usize,
}

struct LoadedSection {
    index: usize,
    va: u64,
    end: u64,
}

pub(super) fn apply(obj: &object::File<'_>, bytes: &[u8], loaded: &mut [Segment]) -> Option<()> {
    let object::File::MachO64(file) = obj else {
        return Some(());
    };
    if !obj.is_little_endian() || obj.architecture() != object::Architecture::X86_64 {
        return Some(());
    }
    let mut commands: object::read::macho::LoadCommandIterator<'_, object::Endianness> =
        file.macho_load_commands().ok()?;
    let mut fixups: Option<&[u8]> = None;
    let mut command_count: usize = 0;
    while let Some(command) = commands.next().ok()? {
        command_count = command_count.checked_add(1)?;
        if command_count > 4096 {
            return None;
        }
        if command.cmd() != macho::LC_DYLD_CHAINED_FIXUPS {
            continue;
        }
        let data: &macho::LinkeditDataCommand<object::Endianness> = command.data().ok()?;
        let offset: usize = usize::try_from(data.dataoff.get(file.endian())).ok()?;
        let size: usize = usize::try_from(data.datasize.get(file.endian())).ok()?;
        if size > MAX_FIXUP_BYTES || fixups.is_some() {
            return None;
        }
        fixups = Some(bytes.get(offset..offset.checked_add(size)?)?);
    }
    let Some(fixups) = fixups else {
        return Some(());
    };
    let mut segments: Vec<ImageSegment> = Vec::new();
    let mut image_base: Option<u64> = None;
    for segment in obj.segments() {
        if segments.len() == MAX_SEGMENTS {
            return None;
        }
        let (offset, size): (u64, u64) = segment.file_range();
        let file_offset: usize = usize::try_from(offset).ok()?;
        let file_size: usize = usize::try_from(size).ok()?;
        let file_end: usize = file_offset.checked_add(file_size)?;
        let end: u64 = segment.address().checked_add(segment.size())?;
        if size > segment.size()
            || file_end > bytes.len()
            || segments.iter().any(|previous: &ImageSegment| {
                (segment.size() != 0
                    && previous.va != previous.end
                    && segment.address() < previous.end
                    && previous.va < end)
                    || (file_size != 0
                        && previous.file_offset != previous.file_end
                        && file_offset < previous.file_end
                        && previous.file_offset < file_end)
            })
        {
            return None;
        }
        segments.push(ImageSegment {
            va: segment.address(),
            end,
            file_offset,
            file_end,
        });
        if file_offset == 0 && file_size >= 32 && image_base.replace(segment.address()).is_some() {
            return None;
        }
    }
    let sections: Vec<LoadedSection> = validate_loaded_sections(obj, &segments, loaded)?;
    apply_chains(fixups, bytes, &segments, image_base?, loaded, &sections)
}

fn validate_loaded_sections(
    obj: &object::File<'_>,
    segments: &[ImageSegment],
    loaded: &[Segment],
) -> Option<Vec<LoadedSection>> {
    let sections: Vec<LoadedSection> = loaded_section_ranges(loaded)?;
    let mut loaded_index: usize = 0;
    for (section_index, section) in obj.sections().enumerate() {
        if section_index >= MAX_SECTIONS {
            return None;
        }
        let data: &[u8] = section.data().ok()?;
        if data.is_empty() {
            continue;
        }
        let copied: &Segment = loaded.get(loaded_index)?;
        let (offset, size): (u64, u64) = section.file_range()?;
        let va: u64 = section.address();
        let end: u64 = va.checked_add(size)?;
        if copied.va != va || u64::try_from(copied.bytes.len()).ok()? != size {
            return None;
        }
        let owner: &ImageSegment = segments
            .iter()
            .find(|segment: &&ImageSegment| segment.va <= va && end <= segment.end)?;
        let file_offset: usize = usize::try_from(offset).ok()?;
        let file_end: usize = file_offset.checked_add(usize::try_from(size).ok()?)?;
        if file_offset
            != owner
                .file_offset
                .checked_add(usize::try_from(va - owner.va).ok()?)?
            || file_end > owner.file_end
        {
            return None;
        }
        loaded_index = loaded_index.checked_add(1)?;
    }
    if loaded_index != loaded.len() {
        return None;
    }
    Some(sections)
}

fn loaded_section_ranges(loaded: &[Segment]) -> Option<Vec<LoadedSection>> {
    if loaded.len() > MAX_SECTIONS {
        return None;
    }
    let mut sections: Vec<LoadedSection> = Vec::with_capacity(loaded.len());
    for (index, section) in loaded.iter().enumerate() {
        if section.bytes.is_empty() {
            return None;
        }
        sections.push(LoadedSection {
            index,
            va: section.va,
            end: section
                .va
                .checked_add(u64::try_from(section.bytes.len()).ok()?)?,
        });
    }
    sections.sort_unstable_by_key(|section: &LoadedSection| section.va);
    if sections
        .windows(2)
        .any(|pair: &[LoadedSection]| pair[0].end > pair[1].va)
    {
        return None;
    }
    Some(sections)
}

fn apply_chains(
    fixups: &[u8],
    bytes: &[u8],
    segments: &[ImageSegment],
    image_base: u64,
    loaded: &mut [Segment],
    sections: &[LoadedSection],
) -> Option<()> {
    if fixups.len() < 28 || read_u32_le_at(fixups, 0).ok()? != 0 {
        return None;
    }
    let starts_offset: usize = usize::try_from(read_u32_le_at(fixups, 4).ok()?).ok()?;
    if starts_offset < 28 {
        return None;
    }
    let starts: &[u8] = fixups.get(starts_offset..)?;
    let count: usize = usize::try_from(read_u32_le_at(starts, 0).ok()?).ok()?;
    if count > segments.len() || count > MAX_SEGMENTS {
        return None;
    }
    let table_end: usize = 4usize.checked_add(count.checked_mul(4)?)?;
    let _: &[u8] = starts.get(..table_end)?;
    let mut steps_left: usize = MAX_CHAIN_STEPS;
    let mut pages_left: usize = MAX_CHAIN_PAGES;
    for (index, segment) in segments.iter().take(count).enumerate() {
        let offset: usize = usize::try_from(read_u32_le_at(starts, 4 + index * 4).ok()?).ok()?;
        if offset == 0 {
            continue;
        }
        if offset < table_end {
            return None;
        }
        let size: usize = usize::try_from(read_u32_le_at(starts, offset).ok()?).ok()?;
        let info: &[u8] = starts.get(offset..offset.checked_add(size)?)?;
        let page_size: u64 = u64::from(read_u16_le_at(info, 4).ok()?);
        let format: u16 = read_u16_le_at(info, 6).ok()?;
        let segment_offset: u64 = read_u64_le_at(info, 8).ok()?;
        let page_count: usize = usize::from(read_u16_le_at(info, 20).ok()?);
        if !matches!(page_size, 0x1000 | 0x4000)
            || !matches!(format, 2 | 6)
            || image_base.checked_add(segment_offset)? != segment.va
            || read_u32_le_at(info, 16).ok()? != 0
        {
            return None;
        }
        let _: &[u8] = info.get(..22usize.checked_add(page_count.checked_mul(2)?)?)?;
        pages_left = pages_left.checked_sub(page_count)?;
        for page in 0..page_count {
            let start: u16 = read_u16_le_at(info, 22 + page * 2).ok()?;
            if start == 0xffff {
                continue;
            }
            if start & 0x8000 != 0 {
                return None;
            }
            let page_offset: u64 = u64::try_from(page).ok()?.checked_mul(page_size)?;
            let mut within_page: u64 = u64::from(start);
            loop {
                steps_left = steps_left.checked_sub(1)?;
                if within_page.checked_add(8)? > page_size {
                    return None;
                }
                let offset: u64 = page_offset.checked_add(within_page)?;
                let file_delta: usize = usize::try_from(offset).ok()?;
                let file_at: usize = segment.file_offset.checked_add(file_delta)?;
                if file_at.checked_add(8)? > segment.file_end {
                    return None;
                }
                let word: u64 = read_u64_le_at(bytes, file_at).ok()?;
                let next: u64 = ((word >> 51) & 0xfff) * 4;
                if word >> 63 == 0 {
                    let target: u64 = rebase_target(word, format, image_base)?;
                    patch_word(loaded, sections, segment.va.checked_add(offset)?, target)?;
                }
                if next == 0 {
                    break;
                }
                if next < 8 {
                    return None;
                }
                within_page = within_page.checked_add(next)?;
            }
        }
    }
    Some(())
}

fn rebase_target(word: u64, format: u16, image_base: u64) -> Option<u64> {
    if word >> 63 != 0 || ((word >> 44) & 0x7f) != 0 {
        return None;
    }
    let low: u64 = word & 0x0000_000f_ffff_ffff;
    let high: u64 = ((word >> 36) & 0xff) << 56;
    match format {
        2 => Some(high | low),
        6 => image_base.checked_add(high | low),
        _ => None,
    }
}

fn patch_word(
    loaded: &mut [Segment],
    sections: &[LoadedSection],
    va: u64,
    target: u64,
) -> Option<()> {
    let end: u64 = va.checked_add(8)?;
    let position: usize = sections.partition_point(|section: &LoadedSection| section.end <= va);
    let Some(section) = sections.get(position) else {
        return Some(());
    };
    if section.va >= end {
        return Some(());
    }
    if va < section.va || end > section.end {
        return None;
    }
    let offset: usize = usize::try_from(va - section.va).ok()?;
    loaded
        .get_mut(section.index)?
        .bytes
        .get_mut(offset..offset.checked_add(8)?)?
        .copy_from_slice(&target.to_le_bytes());
    Some(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn copied_sections(file: &object::File<'_>) -> Vec<Segment> {
        file.sections()
            .filter_map(|section: object::Section<'_, '_>| {
                let data: &[u8] = section.data().expect("valid section data");
                if data.is_empty() {
                    None
                } else {
                    Some(Segment {
                        va: section.address(),
                        bytes: data.to_vec(),
                        executable: super::super::section_is_executable(&section),
                    })
                }
            })
            .collect()
    }

    #[test]
    fn a_chained_section_must_match_the_segments_file_mapping() {
        const IMAGE: &[u8] =
            include_bytes!("../../../tests/fixtures/vm_oracle_x86_64_chained.macho");
        const DATA_OFFSET_FIELD: usize = 0x350;
        assert_eq!(
            read_u32_le_at(IMAGE, DATA_OFFSET_FIELD).expect("section offset"),
            0x3000
        );
        let valid: object::File<'_> = object::File::parse(IMAGE).expect("compiled Mach-O fixture");
        assert!(apply(&valid, IMAGE, &mut copied_sections(&valid)).is_some());

        let mut corrupt: Vec<u8> = IMAGE.to_vec();
        corrupt[DATA_OFFSET_FIELD..DATA_OFFSET_FIELD + 4].copy_from_slice(&0x3100u32.to_le_bytes());
        let file: object::File<'_> = object::File::parse(corrupt.as_slice())
            .expect("the in-file section offset remains structurally parseable");
        let mut loaded: Vec<Segment> = copied_sections(&file);
        let before: Vec<Segment> = loaded.clone();
        assert!(apply(&file, &corrupt, &mut loaded).is_none());
        assert_eq!(
            loaded, before,
            "reject inconsistent mappings before any rebase is written"
        );
    }

    #[test]
    fn loaded_sections_have_a_separate_bounded_index() {
        let mut loaded: Vec<Segment> = (0..MAX_SECTIONS)
            .map(|index: usize| Segment {
                va: 0x1000 + u64::try_from(index).expect("bounded section index") * 16,
                bytes: vec![0; 8],
                executable: false,
            })
            .collect();
        loaded.reverse();
        let sections: Vec<LoadedSection> =
            loaded_section_ranges(&loaded).expect("section cap fits");
        assert!(patch_word(&mut loaded, &sections, 0x1000, 0x2340).is_some());
        assert_eq!(
            loaded.last().expect("first section by VA").bytes,
            0x2340u64.to_le_bytes()
        );
        loaded.push(Segment {
            va: 0x1000_0000,
            bytes: vec![0; 8],
            executable: false,
        });
        assert!(loaded_section_ranges(&loaded).is_none());
    }

    fn chain_metadata(format: u16, page_starts: &[u16]) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0; 36];
        bytes[4..8].copy_from_slice(&28u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&8u32.to_le_bytes());
        let size: u32 = 22 + u32::try_from(page_starts.len()).expect("small page list") * 2;
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&0x1000u16.to_le_bytes());
        bytes.extend_from_slice(&format.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(page_starts.len())
                .expect("page count")
                .to_le_bytes(),
        );
        for start in page_starts {
            bytes.extend_from_slice(&start.to_le_bytes());
        }
        bytes
    }

    fn apply_test_chain(metadata: &[u8], bytes: &[u8]) -> Option<Vec<u8>> {
        let len: u64 = u64::try_from(bytes.len()).expect("small test segment");
        let segments: [ImageSegment; 1] = [ImageSegment {
            va: 0x1000,
            end: 0x1000 + len,
            file_offset: 0,
            file_end: bytes.len(),
        }];
        let mut loaded: [Segment; 1] = [Segment {
            va: 0x1000,
            bytes: bytes.to_vec(),
            executable: false,
        }];
        let sections: Vec<LoadedSection> = loaded_section_ranges(&loaded)?;
        apply_chains(metadata, bytes, &segments, 0x1000, &mut loaded, &sections)?;
        Some(std::mem::take(&mut loaded[0].bytes))
    }

    #[test]
    fn both_pointer_formats_rebase_only_slots_reached_from_page_starts() {
        for (format, target) in [(2u16, 0x2340u64), (6, 0x3340)] {
            let first: u64 = (2u64 << 51) | 0x2340;
            let unvisited: u64 = (3u64 << 51) | 0x3450;
            let bytes: Vec<u8> = [first, 0x4560, unvisited]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect();
            let recovered: Vec<u8> = apply_test_chain(&chain_metadata(format, &[0]), &bytes)
                .expect("valid local rebases");
            assert_eq!(
                read_u64_le_at(&recovered, 0).expect("first pointer"),
                target
            );
            assert_eq!(
                read_u64_le_at(&recovered, 8).expect("last pointer"),
                if format == 2 { 0x4560 } else { 0x5560 }
            );
            assert_eq!(
                read_u64_le_at(&recovered, 16).expect("unvisited word"),
                unvisited
            );
        }
    }

    #[test]
    fn bound_imports_are_left_unresolved_while_the_chain_continues() {
        let bind: u64 = (1u64 << 63) | (2u64 << 51) | 7;
        let bytes: Vec<u8> = [bind, 0x2340]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let recovered: Vec<u8> =
            apply_test_chain(&chain_metadata(6, &[0]), &bytes).expect("walk past imported pointer");
        assert_eq!(read_u64_le_at(&recovered, 0).expect("bind slot"), bind);
        assert_eq!(read_u64_le_at(&recovered, 8).expect("rebase slot"), 0x3340);
    }

    #[test]
    fn truncated_and_inconsistent_chain_metadata_is_rejected() {
        let metadata: Vec<u8> = chain_metadata(2, &[0]);
        let bytes: [u8; 8] = 0x2340u64.to_le_bytes();
        for length in 0..metadata.len() {
            assert!(
                apply_test_chain(&metadata[..length], &bytes).is_none(),
                "length {length}"
            );
        }
        for (offset, replacement) in [
            (0usize, 1u32.to_le_bytes()),
            (4, 0u32.to_le_bytes()),
            (28, 2u32.to_le_bytes()),
            (32, 4u32.to_le_bytes()),
            (36, 23u32.to_le_bytes()),
            (40, 0u32.to_le_bytes()),
            (44, 1u32.to_le_bytes()),
            (52, 1u32.to_le_bytes()),
        ] {
            let mut corrupt: Vec<u8> = metadata.clone();
            corrupt[offset..offset + 4].copy_from_slice(&replacement);
            assert!(
                apply_test_chain(&corrupt, &bytes).is_none(),
                "offset {offset}"
            );
        }
        assert!(apply_test_chain(&chain_metadata(7, &[0]), &bytes).is_none());
        assert!(apply_test_chain(&chain_metadata(2, &[0x8000]), &bytes).is_none());
        assert!(apply_test_chain(&chain_metadata(2, &[0xfff]), &bytes).is_none());
    }

    #[test]
    fn chains_cannot_cross_file_or_page_boundaries_or_overlap_slots() {
        let metadata: Vec<u8> = chain_metadata(2, &[0]);
        for word in [(1u64 << 51) | 0x2340, (0x400u64 << 51) | 0x2340] {
            let mut bytes: Vec<u8> = vec![0; 0x2000];
            bytes[..8].copy_from_slice(&word.to_le_bytes());
            assert!(apply_test_chain(&metadata, &bytes).is_none());
        }
        let bytes: [u8; 8] = ((2u64 << 51) | 0x2340).to_le_bytes();
        assert!(apply_test_chain(&metadata, &bytes).is_none());
    }

    #[test]
    fn reserved_rebase_bits_and_address_overflow_are_rejected() {
        assert_eq!(
            rebase_target(0xabu64 << 36 | 0x1234, 2, 0),
            Some(0xab00_0000_0000_1234)
        );
        assert_eq!(rebase_target(1u64 << 44, 2, 0), None);
        assert_eq!(rebase_target(1u64 << 63, 2, 0), None);
        assert_eq!(rebase_target(1, 6, u64::MAX), None);
        assert_eq!(rebase_target(1, 7, 0), None);
    }

    #[test]
    fn overlapping_or_partial_loaded_sections_cannot_receive_a_rebase() {
        let segment: Segment = Segment {
            va: 0x1000,
            bytes: vec![0; 8],
            executable: false,
        };
        assert!(loaded_section_ranges(&[segment.clone(), segment.clone()]).is_none());
        let mut loaded: [Segment; 1] = [segment];
        let sections: Vec<LoadedSection> = loaded_section_ranges(&loaded).expect("one section");
        assert!(patch_word(&mut loaded, &sections, 0x1004, 0x2340).is_none());
        assert!(patch_word(&mut loaded, &sections, 0xffc, 0x2340).is_none());
    }

    #[test]
    fn chain_steps_are_bounded_across_pages() {
        let pages: usize = MAX_CHAIN_STEPS / (0x1000 / 8) + 1;
        let metadata: Vec<u8> = chain_metadata(2, &vec![0; pages]);
        let mut bytes: Vec<u8> = vec![0; pages * 0x1000];
        for page in bytes.chunks_exact_mut(0x1000) {
            for word in page.chunks_exact_mut(8) {
                word.copy_from_slice(&((2u64 << 51) | 0x2340).to_le_bytes());
            }
            page[0xff8..].copy_from_slice(&0x2340u64.to_le_bytes());
        }
        assert!(apply_test_chain(&metadata, &bytes).is_none());
    }
}
