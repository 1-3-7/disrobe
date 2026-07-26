use std::collections::BTreeMap;

use disrobe_core::byte_search;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotReport {
    pub is_native_aot: bool,
    pub recovered_symbols: BTreeMap<String, u32>,
    pub modules_table_offset: Option<u32>,
    pub eager_class_constructors: u32,
    pub runtime_label: AotRuntime,
    pub ready_to_run: Option<ReadyToRunHeader>,
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

const MODULE_INFO_ROW_LEN: usize = 24;
const READY_TO_RUN_ENTRY_TYPE: u8 = 1;
const MAX_READY_TO_RUN_SECTIONS: u16 = 1024;
const MAX_READY_TO_RUN_MAJOR: u16 = 64;

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

#[must_use]
pub fn locate_ready_to_run_header(image: &[u8]) -> Option<ReadyToRunHeader> {
    let pe: crate::pe::PeImage = crate::pe::parse(image).ok()?;
    let needle: [u8; 4] = READY_TO_RUN_SIGNATURE.to_le_bytes();
    let mut cursor: usize = 0;
    while let Some(found) = byte_search::find(image.get(cursor..)?, &needle) {
        let candidate: usize = cursor.saturating_add(found);
        if let Some(header) = read_ready_to_run_header(image, &pe, candidate) {
            return Some(header);
        }
        cursor = candidate.checked_add(1)?;
    }
    None
}

fn read_ready_to_run_header(
    image: &[u8],
    pe: &crate::pe::PeImage,
    at: usize,
) -> Option<ReadyToRunHeader> {
    let major_version: u16 = read_u16(image, at.checked_add(4)?)?;
    let minor_version: u16 = read_u16(image, at.checked_add(6)?)?;
    let flags: u32 = read_u32(image, at.checked_add(8)?)?;
    let count: u16 = read_u16(image, at.checked_add(12)?)?;
    let entry_size: u8 = *image.get(at.checked_add(14)?)?;
    let entry_type: u8 = *image.get(at.checked_add(15)?)?;
    if major_version == 0 || major_version > MAX_READY_TO_RUN_MAJOR {
        return None;
    }
    if entry_type != READY_TO_RUN_ENTRY_TYPE || usize::from(entry_size) != MODULE_INFO_ROW_LEN {
        return None;
    }
    if count == 0 || count > MAX_READY_TO_RUN_SECTIONS {
        return None;
    }
    let table: usize = at.checked_add(16)?;
    let mut sections: Vec<AotSection> = Vec::with_capacity(usize::from(count));
    let mut spanned: bool = false;
    for index in 0..usize::from(count) {
        let row: usize = table.checked_add(index.checked_mul(MODULE_INFO_ROW_LEN)?)?;
        let id: i32 = read_u32(image, row)? as i32;
        let row_flags: i32 = read_u32(image, row.checked_add(4)?)? as i32;
        let start: u64 = read_u64(image, row.checked_add(8)?)?;
        let end: u64 = read_u64(image, row.checked_add(16)?)?;
        let start_rva: u32 = virtual_address_to_rva(pe, start)?;
        let end_rva: u32 = if end == 0 {
            start_rva
        } else {
            virtual_address_to_rva(pe, end)?
        };
        if end_rva < start_rva {
            return None;
        }
        if end_rva > start_rva {
            spanned = true;
        }
        sections.push(AotSection {
            id,
            flags: row_flags,
            start_rva,
            end_rva,
        });
    }
    if !spanned {
        return None;
    }
    Some(ReadyToRunHeader {
        file_offset: u32::try_from(at).ok()?,
        major_version,
        minor_version,
        flags,
        sections,
    })
}

fn virtual_address_to_rva(pe: &crate::pe::PeImage, address: u64) -> Option<u32> {
    let rva: u64 = address.checked_sub(pe.image_base)?;
    let rva: u32 = u32::try_from(rva).ok()?;
    let mapped: bool = pe
        .sections
        .iter()
        .any(|section: &crate::pe::SectionHeader| {
            let start: u32 = section.virtual_address;
            let end: u32 = start.saturating_add(section.virtual_size.max(section.raw_size));
            rva >= start && rva <= end
        });
    mapped.then_some(rva)
}

fn read_u16(image: &[u8], at: usize) -> Option<u16> {
    let end: usize = at.checked_add(2)?;
    let slice: &[u8] = image.get(at..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(image: &[u8], at: usize) -> Option<u32> {
    let end: usize = at.checked_add(4)?;
    let slice: &[u8] = image.get(at..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(image: &[u8], at: usize) -> Option<u64> {
    let end: usize = at.checked_add(8)?;
    let slice: &[u8] = image.get(at..end)?;
    let mut bytes: [u8; 8] = [0u8; 8];
    bytes.copy_from_slice(slice);
    Some(u64::from_le_bytes(bytes))
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
        let absolute: u32 = u32::try_from(found).unwrap_or(u32::MAX);
        symbols.insert((*label).to_owned(), absolute);
        if *label == "modules_table" {
            modules_table_offset = Some(absolute);
        }
    }
    let eager_marker: &[u8] = b"EagerCctor";
    let mut cursor: usize = 0;
    while eager < EAGER_CCTOR_SCAN_CAP {
        let Some(pos): Option<usize> = byte_search::find(&image[cursor..], eager_marker) else {
            break;
        };
        eager = eager.saturating_add(1);
        cursor += pos + eager_marker.len();
    }
    let ready_to_run: Option<ReadyToRunHeader> = locate_ready_to_run_header(image);
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
