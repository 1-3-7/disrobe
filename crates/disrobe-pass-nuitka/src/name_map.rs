use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::debug::DebugLog;
use disrobe_pass_native::{RipRef, scan_rip_relative_refs, text_section_window};
use serde::{Deserialize, Serialize};

const MIN_NAME_LEN: usize = 3;
const MAX_NAME_LEN: usize = 200;
const MAX_NAMES: usize = 50_000;
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRef {
    pub instruction_offset: u64,
    pub function_address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameMapEntry {
    pub name: String,
    pub string_address: u64,
    pub references: Vec<NameRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeNameMap {
    pub module_name: String,
    pub mapped_functions: usize,
    pub entries: Vec<NameMapEntry>,
}

impl NativeNameMap {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

struct PeSection {
    virtual_address: u64,
    virtual_size: usize,
    raw_ptr: usize,
    raw_size: usize,
}

fn pe_image_base_and_sections(image: &[u8]) -> Option<(u64, Vec<PeSection>)> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew: usize = u32::from_le_bytes(image.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if image.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = e_lfanew + 4;
    let num_sections: usize =
        u16::from_le_bytes(image.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt_size: usize =
        u16::from_le_bytes(image.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let opt: usize = coff + 20;
    let magic: u16 = u16::from_le_bytes(image.get(opt..opt + 2)?.try_into().ok()?);
    let image_base: u64 = match magic {
        0x20b => u64::from_le_bytes(image.get(opt + 24..opt + 32)?.try_into().ok()?),
        0x10b => u64::from(u32::from_le_bytes(
            image.get(opt + 28..opt + 32)?.try_into().ok()?,
        )),
        _ => return None,
    };
    let section_table: usize = opt + opt_size;
    let mut sections: Vec<PeSection> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let sh: usize = section_table + i * 40;
        let virtual_size: usize =
            u32::from_le_bytes(image.get(sh + 8..sh + 12)?.try_into().ok()?) as usize;
        let virtual_address: u64 = u64::from(u32::from_le_bytes(
            image.get(sh + 12..sh + 16)?.try_into().ok()?,
        ));
        let raw_size: usize =
            u32::from_le_bytes(image.get(sh + 16..sh + 20)?.try_into().ok()?) as usize;
        let raw_ptr: usize =
            u32::from_le_bytes(image.get(sh + 20..sh + 24)?.try_into().ok()?) as usize;
        sections.push(PeSection {
            virtual_address,
            virtual_size,
            raw_ptr,
            raw_size,
        });
    }
    Some((image_base, sections))
}

fn va_to_file_offset(va: u64, image_base: u64, sections: &[PeSection]) -> Option<usize> {
    let rva: u64 = va.checked_sub(image_base)?;
    for s in sections {
        let span: u64 = s.virtual_size.max(s.raw_size) as u64;
        if rva >= s.virtual_address && rva < s.virtual_address + span {
            let delta: usize = usize::try_from(rva - s.virtual_address).ok()?;
            if delta >= s.raw_size {
                return None;
            }
            return Some(s.raw_ptr + delta);
        }
    }
    None
}

fn read_c_string(image: &[u8], offset: usize) -> Option<&str> {
    let slice: &[u8] = image.get(offset..offset + MAX_NAME_LEN + 1)?;
    let end: usize = slice.iter().position(|&b: &u8| b == 0)?;
    if end < MIN_NAME_LEN {
        return None;
    }
    std::str::from_utf8(&slice[..end]).ok()
}

const MAX_NAME_MAP_TEXT_BYTES: usize = 96 * 1024 * 1024;

#[must_use]
pub fn map_names(module_name: &str, image: &[u8], names: &[String]) -> Option<NativeNameMap> {
    let dbg: DebugLog = DebugLog::for_scope("nuitka");
    dbg.section("native-name-map");
    let (image_base, sections): (u64, Vec<PeSection>) = pe_image_base_and_sections(image)?;
    let (text_va, bits, text): (u64, u32, &[u8]) = text_section_window(image)?;
    if bits != 64 || text.is_empty() {
        return None;
    }

    let wanted: BTreeSet<&str> = names
        .iter()
        .filter(|n: &&String| {
            (MIN_NAME_LEN..=MAX_NAME_LEN).contains(&n.len())
                && n.bytes()
                    .all(|b: u8| b == b'_' || b == b'.' || b.is_ascii_alphanumeric())
        })
        .take(MAX_NAMES)
        .map(|n: &String| n.as_str())
        .collect();
    if wanted.is_empty() {
        return None;
    }

    let refs: Vec<RipRef> = scan_rip_relative_refs(text, text_va, MAX_NAME_MAP_TEXT_BYTES);
    let mut by_addr: BTreeMap<u64, NameMapEntry> = BTreeMap::new();
    for r in &refs {
        if let Some(existing) = by_addr.get_mut(&r.target_va) {
            existing.references.push(NameRef {
                instruction_offset: r.instruction_offset,
                function_address: Some(r.function_offset),
            });
            continue;
        }
        let Some(file_off): Option<usize> = va_to_file_offset(r.target_va, image_base, &sections)
        else {
            continue;
        };
        let Some(text_str): Option<&str> = read_c_string(image, file_off) else {
            continue;
        };
        if !wanted.contains(text_str) {
            continue;
        }
        by_addr.insert(
            r.target_va,
            NameMapEntry {
                name: text_str.to_owned(),
                string_address: r.target_va,
                references: vec![NameRef {
                    instruction_offset: r.instruction_offset,
                    function_address: Some(r.function_offset),
                }],
            },
        );
        if by_addr.len() >= MAX_ENTRIES {
            break;
        }
    }

    if by_addr.is_empty() {
        return None;
    }
    let entries: Vec<NameMapEntry> = by_addr.into_values().collect();
    let mut mapped: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for e in &entries {
        for r in &e.references {
            if let Some(addr) = r.function_address {
                mapped.insert(addr);
            }
        }
    }
    dbg.kv("name-map entries", || entries.len().to_string());
    dbg.kv("mapped functions", || mapped.len().to_string());
    Some(NativeNameMap {
        module_name: module_name.to_owned(),
        mapped_functions: mapped.len(),
        entries,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn corpus_standalone() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real/sample_app-standalone.exe")
    }

    #[test]
    fn maps_recovered_names_to_text_references_on_real_binary() {
        let path: std::path::PathBuf = corpus_standalone();
        if !path.is_file() {
            eprintln!("skipping: real nuitka corpus exe absent");
            return;
        }
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let constants: crate::const_blob::NuitkaConstants =
            crate::const_blob::parse_constants(&image);
        let mut names: Vec<String> = Vec::new();
        for m in &constants.modules {
            names.extend(m.strings.iter().cloned());
        }
        names.sort_unstable();
        names.dedup();
        let map: NativeNameMap =
            map_names("sample_app", &image, &names).expect("name map produced from real binary");
        assert!(
            !map.entries.is_empty(),
            "expected at least one recovered name referenced from .text"
        );
        let entry: &NameMapEntry = &map.entries[0];
        assert!(
            names.contains(&entry.name),
            "mapped name {} must be one of the recovered constants",
            entry.name
        );
        assert!(
            map.entries.iter().any(|e: &NameMapEntry| e
                .references
                .iter()
                .any(|r: &NameRef| r.function_address.is_some())),
            "at least one recovered name must be attributable to an enclosing .text function"
        );
    }
}
