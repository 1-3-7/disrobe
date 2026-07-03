use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, parse_pe_image};

const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_BASERELOC: usize = 5;

const REL_ABSOLUTE: u16 = 0;
const REL_HIGHLOW: u16 = 3;
const REL_DIR64: u16 = 10;

const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const RESOURCE_DIR_HEADER_SIZE: usize = 16;
const RESOURCE_ENTRY_SIZE: usize = 8;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;
const RESOURCE_SUBDIR_FLAG: u32 = 0x8000_0000;
const ORDINAL_FLAG_PE32: u32 = 0x8000_0000;
const ORDINAL_FLAG_PE32_PLUS: u64 = 0x8000_0000_0000_0000;
const MAX_RESOURCE_DEPTH: u32 = 8;

/// One restoration step the unbind pass performed, tallied per directory so the residual is
/// attributable to a concrete loader action rather than a single opaque percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UnbindReport {
    pub relocations_walked: usize,

    pub relocations_unapplied: usize,

    pub iat_descriptors_walked: usize,

    pub iat_thunks_restored: usize,

    pub resource_data_entries_walked: usize,

    pub resource_offsets_restored: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reloc {
    rva: u32,
    kind: u16,
}

fn read_u16(image: &[u8], off: usize) -> Option<u16> {
    let end: usize = off.checked_add(2)?;
    if end > image.len() {
        return None;
    }
    Some(u16::from_le_bytes([image[off], image[off + 1]]))
}

fn read_u32(image: &[u8], off: usize) -> Option<u32> {
    let end: usize = off.checked_add(4)?;
    if end > image.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        image[off],
        image[off + 1],
        image[off + 2],
        image[off + 3],
    ]))
}

fn read_u64(image: &[u8], off: usize) -> Option<u64> {
    let end: usize = off.checked_add(8)?;
    if end > image.len() {
        return None;
    }
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(&image[off..end]);
    Some(u64::from_le_bytes(arr))
}

fn walk_base_relocations(mapped: &[u8], dir_rva: u32, dir_size: u32) -> Vec<Reloc> {
    let mut out: Vec<Reloc> = Vec::new();
    if dir_rva == 0 || dir_size == 0 {
        return out;
    }
    let end: usize = (dir_rva as usize).saturating_add(dir_size as usize);
    let mut cursor: usize = dir_rva as usize;
    while cursor + 8 <= end {
        let Some(page_rva): Option<u32> = read_u32(mapped, cursor) else {
            break;
        };
        let Some(block_size): Option<u32> = read_u32(mapped, cursor + 4) else {
            break;
        };
        if block_size < 8 {
            break;
        }
        let block_end: usize = cursor.saturating_add(block_size as usize).min(end);
        let mut entry: usize = cursor + 8;
        while entry + 2 <= block_end {
            let Some(packed): Option<u16> = read_u16(mapped, entry) else {
                break;
            };
            let kind: u16 = packed >> 12;
            let offset: u16 = packed & 0x0FFF;
            if kind != REL_ABSOLUTE {
                out.push(Reloc {
                    rva: page_rva.wrapping_add(u32::from(offset)),
                    kind,
                });
            }
            entry += 2;
        }
        cursor = cursor.saturating_add(block_size as usize);
    }
    out
}

fn apply_delta(mapped: &mut [u8], relocs: &[Reloc], delta: u64) -> usize {
    let mut applied: usize = 0;
    for reloc in relocs {
        let off: usize = reloc.rva as usize;
        match reloc.kind {
            REL_HIGHLOW => {
                let Some(value): Option<u32> = read_u32(mapped, off) else {
                    continue;
                };
                let updated: u32 = value.wrapping_add(delta as u32);
                mapped[off..off + 4].copy_from_slice(&updated.to_le_bytes());
                applied += 1;
            }
            REL_DIR64 => {
                let Some(value): Option<u64> = read_u64(mapped, off) else {
                    continue;
                };
                let updated: u64 = value.wrapping_add(delta);
                mapped[off..off + 8].copy_from_slice(&updated.to_le_bytes());
                applied += 1;
            }
            _ => {}
        }
    }
    applied
}

fn restore_iat_from_ilt(
    mapped: &mut [u8],
    import_dir_rva: u32,
    is_pe32_plus: bool,
    report: &mut UnbindReport,
) {
    if import_dir_rva == 0 {
        return;
    }
    let ptr_size: usize = if is_pe32_plus { 8 } else { 4 };
    let mut descriptor: usize = import_dir_rva as usize;
    while descriptor + IMPORT_DESCRIPTOR_SIZE <= mapped.len() {
        let Some(original_first_thunk): Option<u32> = read_u32(mapped, descriptor) else {
            break;
        };
        let Some(first_thunk): Option<u32> = read_u32(mapped, descriptor + 16) else {
            break;
        };
        let Some(name_rva): Option<u32> = read_u32(mapped, descriptor + 12) else {
            break;
        };
        if original_first_thunk == 0 && first_thunk == 0 && name_rva == 0 {
            break;
        }
        report.iat_descriptors_walked += 1;
        if original_first_thunk != 0 && first_thunk != 0 && original_first_thunk != first_thunk {
            restore_one_descriptor(
                mapped,
                original_first_thunk,
                first_thunk,
                ptr_size,
                is_pe32_plus,
                report,
            );
        }
        descriptor += IMPORT_DESCRIPTOR_SIZE;
    }
}

fn restore_one_descriptor(
    mapped: &mut [u8],
    ilt_rva: u32,
    iat_rva: u32,
    ptr_size: usize,
    is_pe32_plus: bool,
    report: &mut UnbindReport,
) {
    let mut slot: usize = 0;
    loop {
        let ilt_off: usize = ilt_rva as usize + slot * ptr_size;
        let iat_off: usize = iat_rva as usize + slot * ptr_size;
        let restored: Option<u64> = if is_pe32_plus {
            read_u64(mapped, ilt_off)
        } else {
            read_u32(mapped, ilt_off).map(u64::from)
        };
        let Some(restored): Option<u64> = restored else {
            break;
        };
        if restored == 0 {
            break;
        }
        if !ilt_entry_is_plausible(restored, is_pe32_plus) {
            break;
        }
        if iat_off + ptr_size > mapped.len() {
            break;
        }
        if is_pe32_plus {
            mapped[iat_off..iat_off + 8].copy_from_slice(&restored.to_le_bytes());
        } else {
            mapped[iat_off..iat_off + 4].copy_from_slice(&(restored as u32).to_le_bytes());
        }
        report.iat_thunks_restored += 1;
        slot += 1;
        if slot > 0x10000 {
            break;
        }
    }
}

fn ilt_entry_is_plausible(entry: u64, is_pe32_plus: bool) -> bool {
    let ordinal: bool = if is_pe32_plus {
        entry & ORDINAL_FLAG_PE32_PLUS != 0
    } else {
        (entry as u32) & ORDINAL_FLAG_PE32 != 0
    };
    ordinal || u32::try_from(entry).is_ok()
}

fn restore_resource_offsets(
    mapped: &mut [u8],
    resource_dir_rva: u32,
    image_base: u64,
    report: &mut UnbindReport,
) {
    if resource_dir_rva == 0 {
        return;
    }
    let base: usize = resource_dir_rva as usize;
    walk_resource_dir(mapped, base, base, image_base, 0, report);
}

fn walk_resource_dir(
    mapped: &mut [u8],
    table_off: usize,
    section_base: usize,
    image_base: u64,
    depth: u32,
    report: &mut UnbindReport,
) {
    if depth > MAX_RESOURCE_DEPTH {
        return;
    }
    let Some(named): Option<u16> = read_u16(mapped, table_off + 12) else {
        return;
    };
    let Some(id): Option<u16> = read_u16(mapped, table_off + 14) else {
        return;
    };
    let total: usize = named as usize + id as usize;
    for i in 0..total {
        let entry_off: usize = table_off + RESOURCE_DIR_HEADER_SIZE + i * RESOURCE_ENTRY_SIZE;
        let Some(offset_to_data): Option<u32> = read_u32(mapped, entry_off + 4) else {
            return;
        };
        if offset_to_data & RESOURCE_SUBDIR_FLAG != 0 {
            let child: usize = section_base + (offset_to_data & !RESOURCE_SUBDIR_FLAG) as usize;
            walk_resource_dir(mapped, child, section_base, image_base, depth + 1, report);
        } else {
            let data_entry: usize = section_base + offset_to_data as usize;
            restore_resource_data_entry(mapped, data_entry, image_base, report);
        }
    }
}

fn restore_resource_data_entry(
    mapped: &mut [u8],
    data_entry: usize,
    image_base: u64,
    report: &mut UnbindReport,
) {
    if data_entry + RESOURCE_DATA_ENTRY_SIZE > mapped.len() {
        return;
    }
    let Some(offset): Option<u32> = read_u32(mapped, data_entry) else {
        return;
    };
    report.resource_data_entries_walked += 1;
    if image_base == 0 || image_base > u64::from(u32::MAX) {
        return;
    }
    let base32: u32 = image_base as u32;
    if offset >= base32 {
        let rva: u32 = offset - base32;
        if (rva as usize) < mapped.len() {
            mapped[data_entry..data_entry + 4].copy_from_slice(&rva.to_le_bytes());
            report.resource_offsets_restored += 1;
        }
    }
}

/// Roll a loaded-and-bound PE image back to its on-disk RVA-mapped form.
///
/// `mapped` is the image as the loader laid it out in memory (sections at their RVAs). `load_base`
/// is the base the loader actually mapped it at, recovered from a dump header or the relocation
/// fixups themselves. The pass un-applies base relocations back to the preferred `image_base`,
/// rewrites the loader-bound IAT thunks from the untouched import lookup table, and restores any
/// resource `OffsetToData` field a dumper turned into an absolute VA.
pub fn unbind_pe(mapped: &mut [u8], load_base: u64) -> Result<UnbindReport> {
    let img: PeImage = parse_pe_image(mapped)?;
    let mut report: UnbindReport = UnbindReport::default();

    let (reloc_rva, reloc_size): (u32, u32) = img
        .data_directories
        .get(DIR_BASERELOC)
        .map_or((0, 0), |d| (d.virtual_address, d.size));
    let relocs: Vec<Reloc> = walk_base_relocations(mapped, reloc_rva, reloc_size);
    report.relocations_walked = relocs.len();
    let delta: u64 = img.image_base.wrapping_sub(load_base);
    if delta != 0 {
        report.relocations_unapplied = apply_delta(mapped, &relocs, delta);
    } else {
        report.relocations_unapplied = relocs.len();
    }

    let import_rva: u32 = img
        .data_directories
        .get(DIR_IMPORT)
        .map_or(0, |d| d.virtual_address);
    restore_iat_from_ilt(mapped, import_rva, img.is_pe32_plus, &mut report);

    let resource_rva: u32 = img
        .data_directories
        .get(DIR_RESOURCE)
        .map_or(0, |d| d.virtual_address);
    restore_resource_offsets(mapped, resource_rva, img.image_base, &mut report);

    if mapped.len() < 2 {
        return Err(Error::Truncated {
            needed: 2,
            had: mapped.len(),
        });
    }
    Ok(report)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn pe32_plus_with_reloc() -> Vec<u8> {
        let opt_size: usize = 0xF0;
        let sec_off: usize = 0x80 + 4 + 20 + opt_size;
        let total: usize = 0x4000;
        let mut buf: Vec<u8> = vec![0u8; total];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe: usize = 0x80;
        buf[pe..pe + 4].copy_from_slice(b"PE\x00\x00");
        let coff: usize = pe + 4;
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt + 24..opt + 32].copy_from_slice(&0x0001_4000_0000u64.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir_base: usize = opt + 112;
        buf[dir_base + DIR_BASERELOC * 8..dir_base + DIR_BASERELOC * 8 + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes());
        buf[dir_base + DIR_BASERELOC * 8 + 4..dir_base + DIR_BASERELOC * 8 + 8]
            .copy_from_slice(&0x10u32.to_le_bytes());
        let text: usize = sec_off;
        buf[text..text + 5].copy_from_slice(b".text");
        buf[text + 8..text + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[text + 12..text + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[text + 16..text + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[text + 20..text + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        let reloc: usize = sec_off + 40;
        buf[reloc..reloc + 6].copy_from_slice(b".reloc");
        buf[reloc + 8..reloc + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[reloc + 12..reloc + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[reloc + 16..reloc + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[reloc + 20..reloc + 24].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[0x1000..0x1008].copy_from_slice(&0x0001_4000_1000u64.to_le_bytes());
        buf[0x2000..0x2004].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[0x2004..0x2008].copy_from_slice(&0x10u32.to_le_bytes());
        let packed: u16 = REL_DIR64 << 12;
        buf[0x2008..0x200A].copy_from_slice(&packed.to_le_bytes());
        buf
    }

    #[test]
    fn unbind_un_applies_dir64_relocation_to_preferred_base() {
        let original: Vec<u8> = pe32_plus_with_reloc();
        let mut loaded: Vec<u8> = original.clone();
        let load_base: u64 = 0x0007_0000_0000;
        let img: PeImage = parse_pe_image(&original).expect("parse");
        let delta: u64 = load_base.wrapping_sub(img.image_base);
        let relocs: Vec<Reloc> = walk_base_relocations(&loaded, 0x2000, 0x10);
        assert_eq!(relocs.len(), 1);
        apply_delta(&mut loaded, &relocs, delta);
        assert_ne!(
            loaded[0x1000..0x1008],
            original[0x1000..0x1008],
            "loader rebase must have moved the fixup target"
        );
        let report: UnbindReport = unbind_pe(&mut loaded, load_base).expect("unbind");
        assert_eq!(report.relocations_walked, 1);
        assert_eq!(report.relocations_unapplied, 1);
        assert_eq!(
            loaded[0x1000..0x1008],
            original[0x1000..0x1008],
            "unbind must restore the preferred-base fixup target byte-for-byte"
        );
    }

    #[test]
    fn unbind_with_matching_base_is_a_noop_on_bytes() {
        let original: Vec<u8> = pe32_plus_with_reloc();
        let mut loaded: Vec<u8> = original.clone();
        let img: PeImage = parse_pe_image(&original).expect("parse");
        let report: UnbindReport = unbind_pe(&mut loaded, img.image_base).expect("unbind");
        assert_eq!(report.relocations_unapplied, report.relocations_walked);
        assert_eq!(
            loaded, original,
            "zero-delta unbind must not change any byte"
        );
    }

    #[test]
    fn restore_iat_copies_lookup_table_over_bound_thunks() {
        let mut mapped: Vec<u8> = vec![0u8; 0x400];
        let import_rva: u32 = 0x100;
        let ilt_rva: u32 = 0x140;
        let iat_rva: u32 = 0x180;
        let name_rva: u32 = 0x1C0;
        let d: usize = import_rva as usize;
        mapped[d..d + 4].copy_from_slice(&ilt_rva.to_le_bytes());
        mapped[d + 12..d + 16].copy_from_slice(&name_rva.to_le_bytes());
        mapped[d + 16..d + 20].copy_from_slice(&iat_rva.to_le_bytes());
        let lookup0: u64 = u64::from(name_rva);
        let lookup1: u64 = ORDINAL_FLAG_PE32_PLUS | 7;
        mapped[ilt_rva as usize..ilt_rva as usize + 8].copy_from_slice(&lookup0.to_le_bytes());
        mapped[ilt_rva as usize + 8..ilt_rva as usize + 16].copy_from_slice(&lookup1.to_le_bytes());
        let bound0: u64 = 0x7FFE_1234_5678;
        let bound1: u64 = 0x7FFE_1234_56B0;
        mapped[iat_rva as usize..iat_rva as usize + 8].copy_from_slice(&bound0.to_le_bytes());
        mapped[iat_rva as usize + 8..iat_rva as usize + 16].copy_from_slice(&bound1.to_le_bytes());
        let mut report: UnbindReport = UnbindReport::default();
        restore_iat_from_ilt(&mut mapped, import_rva, true, &mut report);
        assert_eq!(report.iat_thunks_restored, 2);
        assert_eq!(
            read_u64(&mapped, iat_rva as usize),
            Some(lookup0),
            "name-RVA thunk must be restored from the import lookup table"
        );
        assert_eq!(
            read_u64(&mapped, iat_rva as usize + 8),
            Some(lookup1),
            "by-ordinal thunk must be restored from the import lookup table"
        );
    }

    #[test]
    fn restore_resource_offset_converts_absolute_va_back_to_rva() {
        let mut mapped: Vec<u8> = vec![0u8; 0x1000];
        let image_base: u64 = 0x0040_0000;
        let original_rva: u32 = 0x800;
        let dumped_va: u32 = image_base as u32 + original_rva;
        let data_entry: usize = 0x200;
        mapped[data_entry..data_entry + 4].copy_from_slice(&dumped_va.to_le_bytes());
        let mut report: UnbindReport = UnbindReport::default();
        restore_resource_data_entry(&mut mapped, data_entry, image_base, &mut report);
        assert_eq!(report.resource_offsets_restored, 1);
        assert_eq!(
            read_u32(&mapped, data_entry),
            Some(original_rva),
            "a dumper-VA OffsetToData must be folded back to an RVA"
        );
    }

    #[test]
    fn restore_resource_offset_leaves_a_genuine_rva_untouched() {
        let mut mapped: Vec<u8> = vec![0u8; 0x1000];
        let image_base: u64 = 0x0040_0000;
        let genuine_rva: u32 = 0x800;
        let data_entry: usize = 0x200;
        mapped[data_entry..data_entry + 4].copy_from_slice(&genuine_rva.to_le_bytes());
        let mut report: UnbindReport = UnbindReport::default();
        restore_resource_data_entry(&mut mapped, data_entry, image_base, &mut report);
        assert_eq!(
            report.resource_offsets_restored, 0,
            "a value already below the image base is an RVA and must not be touched"
        );
        assert_eq!(read_u32(&mapped, data_entry), Some(genuine_rva));
    }
}
