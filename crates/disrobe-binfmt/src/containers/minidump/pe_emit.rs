use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use object::Object as _;
use object::ObjectSection as _;

use super::{u16_le, u32_le};

const SECTION_ENTRY_SIZE: usize = 40;
const OPT_MAGIC_PE32_PLUS: u16 = 0x020B;
const PE32_IMAGE_BASE_OFFSET: usize = 28;
const PE32_PLUS_IMAGE_BASE_OFFSET: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeEmitReport {
    pub pe_offset: u64,
    pub is_pe32_plus: bool,
    pub image_base_written: u64,
    pub sections_rewritten: usize,
    pub structurally_valid: bool,
    pub validated_section_count: usize,
    pub import_dll_count: Option<usize>,
    pub notes: Vec<String>,
}

struct Rewrite {
    pe_offset: usize,
    is_pe32_plus: bool,
    image_base_written: u64,
    sections_rewritten: usize,
}

pub(super) fn emit(image: &mut [u8], base_of_image: u64) -> PeEmitReport {
    let mut notes: Vec<String> = Vec::new();
    let rewrite: Option<Rewrite> = rewrite_section_table(image, base_of_image, &mut notes);
    let (structurally_valid, validated_section_count, import_dll_count): (
        bool,
        usize,
        Option<usize>,
    ) = validate(image);

    if let Some(count) = import_dll_count
        && count > 0
    {
        notes.push(
            "minidump: the import address table in a memory-mapped image holds resolved runtime pointers, not the original unresolved thunks; this is a characteristic of a loaded image, not corruption".to_owned(),
        );
    }
    if !structurally_valid {
        notes.push(
            "minidump: emitted image did not fully validate as a PE via the object parser; sections or directories may be partial in the dump".to_owned(),
        );
    }

    let (pe_offset, is_pe32_plus, image_base_written, sections_rewritten): (u64, bool, u64, usize) =
        rewrite.map_or_else(
            || {
                notes.push(
                    "minidump: could not locate a PE header in the carved image; section table left unmodified".to_owned(),
                );
                (0u64, false, base_of_image, 0usize)
            },
            |r: Rewrite| {
                (
                    r.pe_offset as u64,
                    r.is_pe32_plus,
                    r.image_base_written,
                    r.sections_rewritten,
                )
            },
        );

    PeEmitReport {
        pe_offset,
        is_pe32_plus,
        image_base_written,
        sections_rewritten,
        structurally_valid,
        validated_section_count,
        import_dll_count,
        notes,
    }
}

fn rewrite_section_table(
    image: &mut [u8],
    base_of_image: u64,
    notes: &mut Vec<String>,
) -> Option<Rewrite> {
    let pe_offset: usize = crate::structural::locate_pe_header(image)?;
    let coff_off: usize = pe_offset.checked_add(4)?;
    let number_of_sections: u16 = u16_le(image, coff_off.checked_add(2)?)?;
    let optional_header_size: u16 = u16_le(image, coff_off.checked_add(16)?)?;
    let optional_header_off: usize = coff_off.checked_add(20)?;
    let optional_magic: u16 = u16_le(image, optional_header_off)?;
    let is_pe32_plus: bool = optional_magic == OPT_MAGIC_PE32_PLUS;

    let image_base_off: usize = optional_header_off.checked_add(if is_pe32_plus {
        PE32_PLUS_IMAGE_BASE_OFFSET
    } else {
        PE32_IMAGE_BASE_OFFSET
    })?;
    if is_pe32_plus {
        write_u64_le(image, image_base_off, base_of_image);
    } else {
        write_u32_le(image, image_base_off, base_of_image as u32);
    }

    let section_table_off: usize =
        optional_header_off.checked_add(optional_header_size as usize)?;
    let image_len: u64 = image.len() as u64;
    let mut sections_rewritten: usize = 0;
    for index in 0..number_of_sections as usize {
        let header_off: usize =
            section_table_off.checked_add(index.checked_mul(SECTION_ENTRY_SIZE)?)?;
        let virtual_size: u32 = match u32_le(image, header_off.checked_add(8)?) {
            Some(value) => value,
            None => break,
        };
        let virtual_address: u32 = match u32_le(image, header_off.checked_add(12)?) {
            Some(value) => value,
            None => break,
        };
        let raw_size: u32 = if u64::from(virtual_address) >= image_len {
            0
        } else {
            let remaining: u64 = image_len - u64::from(virtual_address);
            u64::from(virtual_size).min(remaining) as u32
        };
        if !write_u32_le(image, header_off.checked_add(16)?, raw_size)
            || !write_u32_le(image, header_off.checked_add(20)?, virtual_address)
        {
            notes.push(format!(
                "minidump: section header {index} runs past the carved image; not rewritten"
            ));
            break;
        }
        sections_rewritten += 1;
    }

    Some(Rewrite {
        pe_offset,
        is_pe32_plus,
        image_base_written: base_of_image,
        sections_rewritten,
    })
}

fn validate(image: &[u8]) -> (bool, usize, Option<usize>) {
    let file: object::read::File<'_> = match object::read::File::parse(image) {
        Ok(parsed) => parsed,
        Err(_) => return (false, 0, None),
    };
    if !matches!(file.format(), object::BinaryFormat::Pe) {
        return (false, 0, None);
    }
    let mut section_count: usize = 0;
    let mut all_sections_ok: bool = true;
    for section in file.sections() {
        section_count += 1;
        if section.data().is_err() {
            all_sections_ok = false;
        }
    }
    let import_dll_count: Option<usize> = file.imports().ok().map(|imports| {
        let mut libraries: BTreeSet<Vec<u8>> = BTreeSet::new();
        for import in &imports {
            libraries.insert(import.library().to_vec());
        }
        libraries.len()
    });
    (all_sections_ok, section_count, import_dll_count)
}

fn write_u32_le(buf: &mut [u8], at: usize, value: u32) -> bool {
    buf.get_mut(at..at + 4)
        .map(|slot: &mut [u8]| slot.copy_from_slice(&value.to_le_bytes()))
        .is_some()
}

fn write_u64_le(buf: &mut [u8], at: usize, value: u64) -> bool {
    buf.get_mut(at..at + 8)
        .map(|slot: &mut [u8]| slot.copy_from_slice(&value.to_le_bytes()))
        .is_some()
}
