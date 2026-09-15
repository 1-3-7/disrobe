use object::endian::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, PeFile, SectionTable};
use object::read::{File as ObjFile, ObjectKind};
use object::{
    Architecture as ObjArchitecture, Object as _, ObjectSection as _, ObjectSegment as _,
    SectionFlags, SegmentFlags,
};

use crate::error::{Error, Result};
use crate::native::{Arch, Endian, NativeFormat, detect_native_format, map_arch};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeImageSection {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub executable: bool,
    file_offset: Option<u64>,
    file_size: u64,
    end_address: u64,
}

#[derive(Debug)]
pub struct NativeImage<'data> {
    bytes: &'data [u8],
    format: NativeFormat,
    architecture: Arch,
    bits: u32,
    endian: Endian,
    pointer_size: u8,
    relative_address_base: u64,
    sections: Vec<NativeImageSection>,
    load_regions: Vec<NativeLoadRegion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeLoadRegion {
    address: u64,
    end_address: u64,
    file_offset: u64,
    file_size: u64,
    executable: bool,
}

impl<'data> NativeImage<'data> {
    #[must_use]
    pub const fn format(&self) -> NativeFormat {
        self.format
    }

    #[must_use]
    pub const fn architecture(&self) -> Arch {
        self.architecture
    }

    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    #[must_use]
    pub const fn pointer_size(&self) -> u8 {
        self.pointer_size
    }

    #[must_use]
    pub fn sections(&self) -> &[NativeImageSection] {
        &self.sections
    }

    #[must_use]
    pub fn section_at(&self, address: u64) -> Option<&NativeImageSection> {
        let insertion_index: usize = self
            .sections
            .partition_point(|section: &NativeImageSection| section.address <= address);
        let section_index: usize = insertion_index.checked_sub(1)?;
        let section: &NativeImageSection = self.sections.get(section_index)?;

        (address < section.end_address).then_some(section)
    }

    #[must_use]
    pub fn file_offset(&self, address: u64) -> Option<u64> {
        let section: &NativeImageSection = self.section_at(address)?;
        let section_file_offset: u64 = section.file_offset?;
        let delta: u64 = address.checked_sub(section.address)?;

        if delta >= section.file_size {
            return None;
        }

        section_file_offset.checked_add(delta)
    }

    #[must_use]
    pub fn bytes_at(&self, address: u64) -> Option<&'data [u8]> {
        let section: &NativeImageSection = self.section_at(address)?;
        let section_file_offset: u64 = section.file_offset?;
        let delta: u64 = address.checked_sub(section.address)?;

        if delta >= section.file_size {
            return None;
        }

        let file_offset: u64 = section_file_offset.checked_add(delta)?;
        let file_remaining: u64 = section.file_size.checked_sub(delta)?;
        let virtual_remaining: u64 = section.size.checked_sub(delta)?;
        let length: u64 = file_remaining.min(virtual_remaining);
        let start: usize = usize::try_from(file_offset).ok()?;
        let length_usize: usize = usize::try_from(length).ok()?;
        let end: usize = start.checked_add(length_usize)?;

        self.bytes.get(start..end)
    }

    pub(crate) fn virtual_address_from_relative(&self, address: u32) -> Option<u64> {
        self.relative_address_base.checked_add(u64::from(address))
    }

    pub(crate) fn loader_bytes_at(&self, address: u64) -> Option<&'data [u8]> {
        let mut resolved: Option<(u64, u64)> = None;
        let mut unbacked_overlap: bool = false;

        for region in &self.load_regions {
            if address < region.address || address >= region.end_address {
                continue;
            }

            let delta: u64 = address.checked_sub(region.address)?;
            if delta >= region.file_size {
                unbacked_overlap = true;
                continue;
            }

            let file_offset: u64 = region.file_offset.checked_add(delta)?;
            let length: u64 = region.file_size.checked_sub(delta)?;
            resolved = match resolved {
                None => Some((file_offset, length)),
                Some((prior_offset, prior_length)) if prior_offset == file_offset => {
                    Some((file_offset, prior_length.min(length)))
                }
                Some(_) => return None,
            };
        }

        if unbacked_overlap && resolved.is_some() {
            return None;
        }

        let (file_offset, length): (u64, u64) = resolved?;
        let start: usize = usize::try_from(file_offset).ok()?;
        let length_usize: usize = usize::try_from(length).ok()?;
        let end: usize = start.checked_add(length_usize)?;
        self.bytes.get(start..end)
    }
}

pub fn parse_native_image(bytes: &[u8]) -> Result<NativeImage<'_>> {
    let format: NativeFormat = detect_native_format(bytes)?;

    if !matches!(
        format,
        NativeFormat::Pe32
            | NativeFormat::Pe64
            | NativeFormat::Elf32
            | NativeFormat::Elf64
            | NativeFormat::MachO32
            | NativeFormat::MachO64
    ) {
        return Err(native_error(format!(
            "{} cannot provide a virtual-address image",
            format.label()
        )));
    }

    let file: ObjFile<'_, &[u8]> =
        ObjFile::parse(bytes).map_err(|error: object::Error| native_error(error.to_string()))?;

    if !matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic) {
        return Err(native_error(format!(
            "{} is not a loadable image",
            format.label()
        )));
    }

    let object_architecture: ObjArchitecture = file.architecture();
    let architecture: Arch = map_arch(object_architecture);
    let pointer_size: u8 = object_architecture
        .address_size()
        .ok_or_else(|| native_error("native image has an unknown pointer size"))?
        .bytes();
    let bits: u32 = if file.is_64() { 64 } else { 32 };
    let endian: Endian = match file.endianness() {
        object::Endianness::Little => Endian::Little,
        object::Endianness::Big => Endian::Big,
    };
    let relative_address_base: u64 = file.relative_address_base();
    let load_regions: Vec<NativeLoadRegion> = match format {
        NativeFormat::Elf32 | NativeFormat::Elf64 => {
            object_load_regions(&file, bytes, NativeFormatFamily::Elf)?
        }
        NativeFormat::MachO32 | NativeFormat::MachO64 => {
            object_load_regions(&file, bytes, NativeFormatFamily::MachO)?
        }
        _ => Vec::new(),
    };
    let sections: Vec<NativeImageSection> = match format {
        NativeFormat::Pe32 => pe_sections::<object::pe::ImageNtHeaders32>(bytes)?,
        NativeFormat::Pe64 => pe_sections::<object::pe::ImageNtHeaders64>(bytes)?,
        NativeFormat::Elf32 | NativeFormat::Elf64 => {
            object_sections(&file, bytes, NativeFormatFamily::Elf, &load_regions)?
        }
        NativeFormat::MachO32 | NativeFormat::MachO64 => {
            object_sections(&file, bytes, NativeFormatFamily::MachO, &load_regions)?
        }
        _ => return Err(native_error("native image format changed during parsing")),
    };
    let sections: Vec<NativeImageSection> = validate_sections(sections)?;

    if sections.is_empty()
        && (!matches!(format, NativeFormat::Elf32 | NativeFormat::Elf64) || load_regions.is_empty())
    {
        return Err(native_error("native image has no mapped sections"));
    }

    Ok(NativeImage {
        bytes,
        format,
        architecture,
        bits,
        endian,
        pointer_size,
        relative_address_base,
        sections,
        load_regions,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeFormatFamily {
    Elf,
    MachO,
}

fn object_sections<'data>(
    file: &ObjFile<'data, &'data [u8]>,
    bytes: &[u8],
    family: NativeFormatFamily,
    load_regions: &[NativeLoadRegion],
) -> Result<Vec<NativeImageSection>> {
    let mut sections: Vec<NativeImageSection> = Vec::with_capacity(file.sections().count());
    let mut copied_name_bytes: usize = 0;

    for section in file.sections() {
        let size: u64 = section.size();
        let flags: SectionFlags = section.flags();
        let mapped: bool = match (family, flags) {
            (NativeFormatFamily::Elf, SectionFlags::Elf { sh_flags }) => {
                sh_flags & u64::from(object::elf::SHF_ALLOC) != 0
                    && sh_flags & u64::from(object::elf::SHF_TLS) == 0
            }
            (NativeFormatFamily::MachO, SectionFlags::MachO { .. }) => true,
            _ => {
                return Err(native_error(
                    "native section has flags for a different format",
                ));
            }
        };

        if !mapped || size == 0 {
            continue;
        }

        let name_ref: &str = section
            .name()
            .map_err(|error: object::Error| native_error(error.to_string()))?;
        let next_name_bytes: usize =
            next_section_name_total(copied_name_bytes, name_ref.len(), bytes.len())?;
        copied_name_bytes = next_name_bytes;
        let name: String = name_ref.to_owned();
        let address: u64 = section.address();
        let end_address: u64 = address
            .checked_add(size)
            .ok_or_else(|| native_error(format!("section {name:?} virtual range overflows")))?;
        let file_range: Option<(u64, u64)> = section.file_range();

        if let Some((file_offset, file_size)) = file_range {
            if file_size > 0 {
                let subject: String = format!("section {name:?}");
                validate_file_range(bytes, file_offset, file_size, &subject)?;
            }
            if file_size > size {
                return Err(native_error(format!(
                    "section {name:?} file-backed range exceeds its virtual address range"
                )));
            }
        }

        let load_region: &NativeLoadRegion =
            load_region_for_section(load_regions, address, end_address, &name)?;
        validate_section_backing(load_region, address, file_range, &name)?;
        let executable: bool = load_region.executable;
        let (file_offset, file_size): (Option<u64>, u64) = match file_range {
            Some((offset, length)) if length > 0 => (Some(offset), length),
            _ => (None, 0),
        };

        sections.push(NativeImageSection {
            name,
            address,
            size,
            executable,
            file_offset,
            file_size,
            end_address,
        });
    }

    Ok(sections)
}

fn next_section_name_total(
    copied: usize,
    name_length: usize,
    input_length: usize,
) -> Result<usize> {
    let next: usize = copied
        .checked_add(name_length)
        .ok_or_else(|| native_error("native section names exceed the input size"))?;
    if next > input_length {
        return Err(native_error("native section names exceed the input size"));
    }
    Ok(next)
}

fn object_load_regions<'data>(
    file: &ObjFile<'data, &'data [u8]>,
    bytes: &[u8],
    family: NativeFormatFamily,
) -> Result<Vec<NativeLoadRegion>> {
    let mut regions: Vec<NativeLoadRegion> = Vec::with_capacity(file.segments().count());
    let format_label: &str = match family {
        NativeFormatFamily::Elf => "ELF",
        NativeFormatFamily::MachO => "Mach-O",
    };
    let range_name: String = format!("{format_label} load segment");

    for segment in file.segments() {
        let address: u64 = segment.address();
        let memory_size: u64 = segment.size();
        let end_address: u64 = address.checked_add(memory_size).ok_or_else(|| {
            native_error(format!(
                "{format_label} load segment virtual range overflows"
            ))
        })?;
        let (file_offset, file_size): (u64, u64) = segment.file_range();

        if file_size > memory_size {
            return Err(native_error(format!(
                "{format_label} load segment file-backed range exceeds its virtual address range"
            )));
        }

        if file_size > 0 {
            validate_file_range(bytes, file_offset, file_size, &range_name)?;
        }

        if memory_size == 0 {
            continue;
        }

        let flags: SegmentFlags = segment.flags();
        let executable: bool = match (family, flags) {
            (NativeFormatFamily::Elf, SegmentFlags::Elf { p_flags }) => {
                p_flags & object::elf::PF_X != 0
            }
            (
                NativeFormatFamily::MachO,
                SegmentFlags::MachO {
                    maxprot, initprot, ..
                },
            ) => macho_segment_executable(initprot, maxprot)?,
            _ => {
                return Err(native_error(format!(
                    "{format_label} load segment has flags for a different format"
                )));
            }
        };
        regions.push(NativeLoadRegion {
            address,
            end_address,
            file_offset,
            file_size,
            executable,
        });
    }

    normalize_load_regions(regions, format_label)
}

fn macho_segment_executable(initprot: u32, maxprot: u32) -> Result<bool> {
    if initprot & !maxprot != 0 {
        return Err(native_error(
            "Mach-O load segment initial protections exceed maximum protections",
        ));
    }
    Ok(initprot & object::macho::VM_PROT_EXECUTE != 0)
}

fn normalize_load_regions(
    mut regions: Vec<NativeLoadRegion>,
    format_label: &str,
) -> Result<Vec<NativeLoadRegion>> {
    regions.sort_unstable_by_key(|region: &NativeLoadRegion| region.address);
    let mut normalized: Vec<NativeLoadRegion> = Vec::with_capacity(regions.len());
    for region in regions {
        let Some(previous): Option<&mut NativeLoadRegion> = normalized.last_mut() else {
            normalized.push(region);
            continue;
        };
        if previous.end_address <= region.address {
            normalized.push(region);
            continue;
        }
        merge_load_regions(previous, region, format_label)?;
    }

    Ok(normalized)
}

fn merge_load_regions(
    previous: &mut NativeLoadRegion,
    current: NativeLoadRegion,
    format_label: &str,
) -> Result<()> {
    let overlap_start: u64 = current.address;
    let overlap_end: u64 = previous.end_address.min(current.end_address);
    let previous_backed_length: u64 =
        load_region_backed_length(previous, overlap_start, overlap_end)?;
    let current_backed_length: u64 =
        load_region_backed_length(&current, overlap_start, overlap_end)?;

    if previous.executable != current.executable || previous_backed_length != current_backed_length
    {
        return Err(native_error(format!(
            "{format_label} load segments have conflicting overlap"
        )));
    }

    if previous_backed_length > 0 {
        let previous_offset: u64 = load_region_file_offset(previous, overlap_start)?;
        let current_offset: u64 = load_region_file_offset(&current, overlap_start)?;
        if previous_offset != current_offset {
            return Err(native_error(format!(
                "{format_label} load segments map overlapping addresses to different file offsets"
            )));
        }
    }

    let previous_backed_end: Option<u64> = load_region_backed_end(previous)?;
    let current_backed_end: Option<u64> = load_region_backed_end(&current)?;
    let merged_backed_end: Option<u64> = match (previous_backed_end, current_backed_end) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    };
    previous.file_size = match merged_backed_end {
        Some(end) => end
            .checked_sub(previous.address)
            .ok_or_else(|| native_error("merged load segment file range is invalid"))?,
        None => 0,
    };
    previous.end_address = previous.end_address.max(current.end_address);

    Ok(())
}

fn load_region_backed_end(region: &NativeLoadRegion) -> Result<Option<u64>> {
    if region.file_size == 0 {
        return Ok(None);
    }

    let end: u64 = region
        .address
        .checked_add(region.file_size)
        .ok_or_else(|| native_error("load segment file-backed range overflows"))?;
    Ok(Some(end))
}

fn load_region_backed_length(
    region: &NativeLoadRegion,
    overlap_start: u64,
    overlap_end: u64,
) -> Result<u64> {
    let Some(backed_end): Option<u64> = load_region_backed_end(region)? else {
        return Ok(0);
    };
    Ok(backed_end.min(overlap_end).saturating_sub(overlap_start))
}

fn load_region_file_offset(region: &NativeLoadRegion, address: u64) -> Result<u64> {
    let delta: u64 = address
        .checked_sub(region.address)
        .ok_or_else(|| native_error("load segment address precedes its start"))?;
    region
        .file_offset
        .checked_add(delta)
        .ok_or_else(|| native_error("load segment file offset overflows"))
}

fn load_region_for_section<'region>(
    regions: &'region [NativeLoadRegion],
    address: u64,
    end_address: u64,
    section_name: &str,
) -> Result<&'region NativeLoadRegion> {
    let insertion_index: usize =
        regions.partition_point(|region: &NativeLoadRegion| region.address <= address);
    let region_index: usize = insertion_index.checked_sub(1).ok_or_else(|| {
        native_error(format!(
            "section {section_name:?} is not contained in a load segment"
        ))
    })?;
    let region: &NativeLoadRegion = regions.get(region_index).ok_or_else(|| {
        native_error(format!(
            "section {section_name:?} is not contained in a load segment"
        ))
    })?;

    if end_address > region.end_address {
        return Err(native_error(format!(
            "section {section_name:?} crosses a load segment boundary"
        )));
    }

    Ok(region)
}

fn validate_section_backing(
    region: &NativeLoadRegion,
    section_address: u64,
    file_range: Option<(u64, u64)>,
    section_name: &str,
) -> Result<()> {
    let delta: u64 = section_address
        .checked_sub(region.address)
        .ok_or_else(|| native_error("section address precedes its load segment"))?;
    let region_file_remaining: Option<u64> = if delta < region.file_size {
        Some(
            region
                .file_size
                .checked_sub(delta)
                .ok_or_else(|| native_error("load segment file-backed range is invalid"))?,
        )
    } else {
        None
    };

    match file_range {
        Some((section_file_offset, section_file_size)) if section_file_size > 0 => {
            let available: u64 = region_file_remaining.ok_or_else(|| {
                native_error(format!(
                    "section {section_name:?} has file backing outside its load segment"
                ))
            })?;
            if section_file_size > available {
                return Err(native_error(format!(
                    "section {section_name:?} file-backed range exceeds its load segment"
                )));
            }
            let expected_file_offset: u64 = region
                .file_offset
                .checked_add(delta)
                .ok_or_else(|| native_error("section file offset overflows"))?;
            if section_file_offset != expected_file_offset {
                return Err(native_error(format!(
                    "section {section_name:?} conflicts with its load segment file mapping"
                )));
            }
        }
        _ => {}
    }

    Ok(())
}

fn pe_sections<Pe>(bytes: &[u8]) -> Result<Vec<NativeImageSection>>
where
    Pe: ImageNtHeaders,
{
    let file: PeFile<'_, Pe, &[u8]> =
        PeFile::parse(bytes).map_err(|error: object::Error| native_error(error.to_string()))?;
    let sections_table: SectionTable<'_> = file.section_table();
    let image_base: u64 = file.relative_address_base();
    let mut sections: Vec<NativeImageSection> = Vec::with_capacity(sections_table.len());

    for section in sections_table.iter() {
        let name_length: usize = section
            .name
            .iter()
            .position(|value: &u8| *value == 0)
            .unwrap_or(section.name.len());
        let name_bytes: &[u8] = section
            .name
            .get(..name_length)
            .ok_or_else(|| native_error("PE section name range is invalid"))?;
        let name: String = std::str::from_utf8(name_bytes)
            .map_err(|error: std::str::Utf8Error| native_error(error.to_string()))?
            .to_owned();
        let virtual_size: u64 = u64::from(section.virtual_size.get(LE));
        let virtual_address: u64 = u64::from(section.virtual_address.get(LE));
        let raw_size: u64 = u64::from(section.size_of_raw_data.get(LE));
        let raw_offset: u64 = u64::from(section.pointer_to_raw_data.get(LE));

        if raw_size > 0 {
            if raw_offset == 0 {
                return Err(native_error(format!(
                    "section {name:?} has file bytes at offset zero"
                )));
            }
            let subject: String = format!("section {name:?}");
            validate_file_range(bytes, raw_offset, raw_size, &subject)?;
        }

        if virtual_size == 0 && raw_size > 0 {
            return Err(native_error(format!(
                "section {name:?} has a file-backed range but no virtual address range"
            )));
        }

        if virtual_size == 0 {
            continue;
        }

        let address: u64 = image_base
            .checked_add(virtual_address)
            .ok_or_else(|| native_error(format!("section {name:?} virtual address overflows")))?;
        let end_address: u64 = address
            .checked_add(virtual_size)
            .ok_or_else(|| native_error(format!("section {name:?} virtual range overflows")))?;
        let file_size: u64 = virtual_size.min(raw_size);
        let file_offset: Option<u64> = (file_size > 0).then_some(raw_offset);
        let characteristics: u32 = section.characteristics.get(LE);
        let executable: bool = characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0;

        sections.push(NativeImageSection {
            name,
            address,
            size: virtual_size,
            executable,
            file_offset,
            file_size,
            end_address,
        });
    }

    if sections.is_empty() {
        return Err(native_error("PE image has no mapped sections"));
    }

    Ok(sections)
}

fn validate_file_range(bytes: &[u8], offset: u64, size: u64, subject: &str) -> Result<()> {
    let end: u64 = offset
        .checked_add(size)
        .ok_or_else(|| native_error(format!("{subject} file-backed range overflows")))?;
    let start_usize: usize = usize::try_from(offset)
        .map_err(|error: std::num::TryFromIntError| native_error(error.to_string()))?;
    let end_usize: usize = usize::try_from(end)
        .map_err(|error: std::num::TryFromIntError| native_error(error.to_string()))?;

    bytes
        .get(start_usize..end_usize)
        .ok_or_else(|| native_error(format!("{subject} file-backed range is truncated")))?;

    Ok(())
}

fn validate_sections(mut sections: Vec<NativeImageSection>) -> Result<Vec<NativeImageSection>> {
    sections.sort_unstable_by_key(|section: &NativeImageSection| section.address);

    for pair in sections.windows(2) {
        let previous: &NativeImageSection = pair
            .first()
            .ok_or_else(|| native_error("section overlap window is incomplete"))?;
        let current: &NativeImageSection = pair
            .get(1)
            .ok_or_else(|| native_error("section overlap window is incomplete"))?;

        if previous.end_address > current.address {
            return Err(native_error(format!(
                "sections {:?} and {:?} overlap",
                previous.name, current.name
            )));
        }
    }

    Ok(sections)
}

fn native_error(message: impl Into<String>) -> Error {
    Error::NativeParse(message.into())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn region(
        address: u64,
        end_address: u64,
        file_offset: u64,
        file_size: u64,
        executable: bool,
    ) -> NativeLoadRegion {
        NativeLoadRegion {
            address,
            end_address,
            file_offset,
            file_size,
            executable,
        }
    }

    #[test]
    fn compatible_load_region_overlaps_merge() {
        let regions: Vec<NativeLoadRegion> = vec![
            region(0x1000, 0x1200, 0, 0x200, true),
            region(0x1100, 0x1300, 0x100, 0x200, true),
        ];
        let normalized: Vec<NativeLoadRegion> =
            normalize_load_regions(regions, "ELF").expect("compatible overlap should merge");
        let merged: &NativeLoadRegion =
            normalized.first().expect("merged region should be present");

        assert_eq!(normalized.len(), 1);
        assert_eq!(merged.address, 0x1000);
        assert_eq!(merged.end_address, 0x1300);
        assert_eq!(merged.file_offset, 0);
        assert_eq!(merged.file_size, 0x300);
        assert!(merged.executable);
    }

    #[test]
    fn conflicting_load_region_file_offsets_reject() {
        let regions: Vec<NativeLoadRegion> = vec![
            region(0x1000, 0x1200, 0, 0x200, true),
            region(0x1100, 0x1300, 0x200, 0x200, true),
        ];

        assert!(normalize_load_regions(regions, "ELF").is_err());
    }

    #[test]
    fn conflicting_load_region_permissions_reject() {
        let regions: Vec<NativeLoadRegion> = vec![
            region(0x1000, 0x1200, 0, 0x200, true),
            region(0x1100, 0x1300, 0x100, 0x200, false),
        ];

        assert!(normalize_load_regions(regions, "ELF").is_err());
    }

    #[test]
    fn backed_and_unbacked_load_region_overlap_rejects() {
        let regions: Vec<NativeLoadRegion> = vec![
            region(0x1000, 0x1200, 0, 0x80, false),
            region(0x1100, 0x1300, 0x100, 0x100, false),
        ];

        assert!(normalize_load_regions(regions, "ELF").is_err());
    }

    #[test]
    fn compatible_three_region_overlap_chain_merges() {
        let regions: Vec<NativeLoadRegion> = vec![
            region(0x1200, 0x1400, 0x200, 0x200, true),
            region(0x1000, 0x1200, 0, 0x200, true),
            region(0x1100, 0x1300, 0x100, 0x200, true),
        ];
        let normalized: Vec<NativeLoadRegion> =
            normalize_load_regions(regions, "ELF").expect("compatible chain should merge");
        let merged: &NativeLoadRegion =
            normalized.first().expect("merged region should be present");

        assert_eq!(normalized.len(), 1);
        assert_eq!(merged.address, 0x1000);
        assert_eq!(merged.end_address, 0x1400);
        assert_eq!(merged.file_size, 0x400);
    }

    #[test]
    fn section_name_budget_rejects_input_sized_overrun() {
        let error: Error = next_section_name_total(8, 5, 12)
            .expect_err("section name budget should reject excess allocation");

        assert!(matches!(error, Error::NativeParse(_)));
    }

    #[test]
    fn macho_initial_protections_must_fit_maximum() {
        let read: u32 = object::macho::VM_PROT_READ;
        let execute: u32 = object::macho::VM_PROT_EXECUTE;
        let executable: bool = macho_segment_executable(read | execute, read | execute)
            .expect("valid execute protections should parse");

        assert!(macho_segment_executable(read | execute, read).is_err());
        assert!(executable);
    }

    #[test]
    fn section_file_mapping_conflict_rejects() {
        let load_region: NativeLoadRegion = region(0x1000, 0x1200, 0, 0x200, true);

        assert!(
            validate_section_backing(&load_region, 0x1100, Some((0x180, 0x40)), ".text").is_err()
        );
    }

    #[test]
    fn explicit_zero_fill_section_remains_unbacked() {
        let load_region: NativeLoadRegion = region(0x1000, 0x1200, 0, 0x200, false);

        assert!(validate_section_backing(&load_region, 0x1100, None, "__bss").is_ok());
    }
}
