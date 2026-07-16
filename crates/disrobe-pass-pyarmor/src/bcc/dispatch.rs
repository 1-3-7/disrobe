use object::{Object as _, ObjectSection as _};

use crate::v8v9::BccArch;

const RECORD_STRIDE: usize = 32;
const MAX_RECORDS: usize = 65_536;
const MAX_NAME_LEN: usize = 128;
const MAX_SECTIONS: usize = 4096;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const SHF_EXECINSTR: u64 = 0x4;
const SHT_NOBITS: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchEntry {
    pub(crate) name: String,
    pub(crate) dispatch_line: Option<i32>,
    pub(crate) code_offset: u64,
    pub(crate) size: u64,
    pub(crate) arch: BccArch,
    pub(crate) container_index: usize,
}

struct SectionView {
    addr: u64,
    data: Vec<u8>,
    is_text: bool,
}

pub(crate) fn parse_dispatch(
    blob: &[u8],
    arch: BccArch,
    container_index: usize,
) -> Vec<DispatchEntry> {
    let views: Vec<SectionView> = enumerate_sections(blob);
    let mut text_ranges: Vec<(u64, u64)> = Vec::new();
    let mut text_end: u64 = 0;
    for view in &views {
        if !view.is_text {
            continue;
        }
        let len: u64 = u64::try_from(view.data.len()).unwrap_or(0);
        if let Some(end) = view.addr.checked_add(len) {
            text_ranges.push((view.addr, end));
            text_end = text_end.max(end);
        }
    }
    if text_ranges.is_empty() {
        return Vec::new();
    }

    let mut best: Vec<RawEntry> = Vec::new();
    for view in &views {
        if view.is_text {
            continue;
        }
        let entries: Vec<RawEntry> = parse_records(&view.data, &text_ranges, &views);
        if entries.len() > best.len() {
            best = entries;
        }
    }
    finalize_entries(best, text_end, arch, container_index)
}

fn enumerate_sections(blob: &[u8]) -> Vec<SectionView> {
    if blob.len() >= 4 && blob[..4] == ELF_MAGIC {
        return enumerate_elf_sections(blob);
    }
    enumerate_object_sections(blob)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn code_at(blob: &[u8], va: u64, size: u64) -> Option<Vec<u8>> {
    for view in &enumerate_sections(blob) {
        if !view.is_text {
            continue;
        }
        let len: u64 = u64::try_from(view.data.len()).ok()?;
        let end: u64 = view.addr.checked_add(len)?;
        if va < view.addr || va >= end {
            continue;
        }
        let start: usize = usize::try_from(va - view.addr).ok()?;
        let want: usize = usize::try_from(size).unwrap_or(0);
        let available: usize = view.data.len().saturating_sub(start);
        let take: usize = want.min(available);
        if take == 0 {
            return None;
        }
        return view.data.get(start..start + take).map(<[u8]>::to_vec);
    }
    None
}

fn enumerate_elf_sections(blob: &[u8]) -> Vec<SectionView> {
    if blob.len() < 64 || blob[4] != 2 || blob[5] != 1 {
        return Vec::new();
    }
    let Some(shoff): Option<usize> = read_u64(blob, 0x28).try_into().ok() else {
        return Vec::new();
    };
    let shentsize: usize = usize::from(read_u16(blob, 0x3a));
    let shnum: usize = usize::from(read_u16(blob, 0x3c)).min(MAX_SECTIONS);
    if shentsize < 64 {
        return Vec::new();
    }
    let mut views: Vec<SectionView> = Vec::new();
    for i in 0..shnum {
        let Some(base): Option<usize> = i
            .checked_mul(shentsize)
            .and_then(|delta: usize| shoff.checked_add(delta))
        else {
            break;
        };
        if base
            .checked_add(64)
            .is_none_or(|end: usize| end > blob.len())
        {
            break;
        }
        let sh_type: u32 = read_u32(blob, base + 4);
        let sh_flags: u64 = read_u64(blob, base + 8);
        let sh_addr: u64 = read_u64(blob, base + 16);
        let Some(sh_offset): Option<usize> = read_u64(blob, base + 24).try_into().ok() else {
            continue;
        };
        let Some(sh_size): Option<usize> = read_u64(blob, base + 32).try_into().ok() else {
            continue;
        };
        if sh_type == SHT_NOBITS || sh_size == 0 || sh_addr == 0 {
            continue;
        }
        let Some(data): Option<&[u8]> = sh_offset
            .checked_add(sh_size)
            .and_then(|end: usize| blob.get(sh_offset..end))
        else {
            continue;
        };
        views.push(SectionView {
            addr: sh_addr,
            data: data.to_vec(),
            is_text: sh_flags & SHF_EXECINSTR != 0,
        });
    }
    views
}

fn enumerate_object_sections(blob: &[u8]) -> Vec<SectionView> {
    let Ok(file): Result<object::File<'_>, object::Error> = object::File::parse(blob) else {
        return Vec::new();
    };
    let mut views: Vec<SectionView> = Vec::new();
    for section in file.sections() {
        let Ok(data): Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        let addr: u64 = section.address();
        if addr == 0 || data.is_empty() {
            continue;
        }
        views.push(SectionView {
            addr,
            data: data.to_vec(),
            is_text: section.kind() == object::SectionKind::Text,
        });
    }
    views
}

struct RawEntry {
    name: String,
    code_offset: u64,
}

fn parse_records(
    section: &[u8],
    text_ranges: &[(u64, u64)],
    views: &[SectionView],
) -> Vec<RawEntry> {
    let mut out: Vec<RawEntry> = Vec::new();
    let mut offset: usize = 0;
    while offset + RECORD_STRIDE <= section.len() && out.len() < MAX_RECORDS {
        let name_ptr: u64 = read_u64(section, offset);
        let code_offset: u64 = read_u64(section, offset + 8);
        if name_ptr == 0 && code_offset == 0 {
            break;
        }
        let in_text: bool = text_ranges
            .iter()
            .any(|(start, end): &(u64, u64)| code_offset >= *start && code_offset < *end);
        if !in_text {
            break;
        }
        let Some(name): Option<String> = resolve_name(name_ptr, views) else {
            break;
        };
        out.push(RawEntry { name, code_offset });
        offset += RECORD_STRIDE;
    }
    out
}

fn resolve_name(va: u64, views: &[SectionView]) -> Option<String> {
    for view in views {
        let end: u64 = view
            .addr
            .checked_add(u64::try_from(view.data.len()).ok()?)?;
        if va < view.addr || va >= end {
            continue;
        }
        let start: usize = usize::try_from(va - view.addr).ok()?;
        let rest: &[u8] = view.data.get(start..)?;
        let terminator: usize = rest.iter().position(|b: &u8| *b == 0).unwrap_or(rest.len());
        let bytes: &[u8] = rest.get(..terminator)?;
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return None;
        }
        if !is_c_identifier(bytes) {
            return None;
        }
        return Some(String::from_utf8_lossy(bytes).into_owned());
    }
    None
}

fn is_c_identifier(bytes: &[u8]) -> bool {
    let Some(first): Option<&u8> = bytes.first() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || *first == b'_') {
        return false;
    }
    bytes
        .iter()
        .all(|b: &u8| b.is_ascii_alphanumeric() || *b == b'_')
}

fn finalize_entries(
    raw: Vec<RawEntry>,
    text_end: u64,
    arch: BccArch,
    container_index: usize,
) -> Vec<DispatchEntry> {
    let mut sorted: Vec<RawEntry> = raw;
    sorted.sort_by_key(|entry: &RawEntry| entry.code_offset);
    let count: usize = sorted.len();
    let mut out: Vec<DispatchEntry> = Vec::with_capacity(count);
    for (i, entry) in sorted.iter().enumerate() {
        let next_bound: u64 = sorted
            .get(i + 1)
            .map_or(text_end, |next: &RawEntry| next.code_offset);
        let size: u64 = next_bound.saturating_sub(entry.code_offset);
        out.push(DispatchEntry {
            name: entry.name.clone(),
            dispatch_line: parse_bcc_line(&entry.name),
            code_offset: entry.code_offset,
            size,
            arch,
            container_index,
        });
    }
    out
}

fn parse_bcc_line(name: &str) -> Option<i32> {
    let digits: &str = name.strip_prefix("bcc_")?;
    digits.parse::<i32>().ok()
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    buf.get(offset..offset + 8)
        .and_then(|slice: &[u8]| slice.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    buf.get(offset..offset + 4)
        .and_then(|slice: &[u8]| slice.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    buf.get(offset..offset + 2)
        .and_then(|slice: &[u8]| slice.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_garbage_blobs_yield_no_entries() {
        assert!(parse_dispatch(&[], BccArch::WinX64, 0).is_empty());
        assert!(parse_dispatch(&[0u8; 3], BccArch::WinX64, 0).is_empty());
        assert!(parse_dispatch(&[0xffu8; 512], BccArch::LinuxX64, 0).is_empty());
    }

    #[test]
    fn truncated_elf_header_does_not_panic() {
        let mut blob: Vec<u8> = ELF_MAGIC.to_vec();
        blob.extend_from_slice(&[2u8, 1u8]);
        blob.resize(40, 0);
        assert!(parse_dispatch(&blob, BccArch::WinX64, 0).is_empty());
    }

    #[test]
    fn hostile_section_offsets_are_bounded() {
        let mut blob: Vec<u8> = vec![0u8; 200];
        blob[..4].copy_from_slice(&ELF_MAGIC);
        blob[4] = 2;
        blob[5] = 1;
        blob[0x28..0x30].copy_from_slice(&64u64.to_le_bytes());
        blob[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        blob[0x3c..0x3e].copy_from_slice(&9000u16.to_le_bytes());
        let entries: Vec<DispatchEntry> = parse_dispatch(&blob, BccArch::WinX64, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn parses_hand_built_descriptor_table() {
        let blob: Vec<u8> = build_descriptor_elf();
        let entries: Vec<DispatchEntry> = parse_dispatch(&blob, BccArch::LinuxX64, 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].code_offset, 0x1000);
        assert_eq!(entries[0].name, "bcc_4");
        assert_eq!(entries[0].dispatch_line, Some(4));
        assert_eq!(entries[0].size, 0x40);
        assert_eq!(entries[0].arch, BccArch::LinuxX64);
        assert_eq!(entries[0].container_index, 2);
        assert_eq!(entries[1].code_offset, 0x1040);
        assert_eq!(entries[1].name, "bcc_9");
    }

    fn build_descriptor_elf() -> Vec<u8> {
        let text_addr: u64 = 0x1000;
        let text_size: u64 = 0x80;
        let names_addr: u64 = 0x2000;
        let names: &[u8] = b"bcc_4\0bcc_9\0";
        let table_addr: u64 = 0x3000;
        let mut table: Vec<u8> = Vec::new();
        table.extend_from_slice(&names_addr.to_le_bytes());
        table.extend_from_slice(&text_addr.to_le_bytes());
        table.extend_from_slice(&1u64.to_le_bytes());
        table.extend_from_slice(&0u64.to_le_bytes());
        table.extend_from_slice(&(names_addr + 6).to_le_bytes());
        table.extend_from_slice(&(text_addr + 0x40).to_le_bytes());
        table.extend_from_slice(&1u64.to_le_bytes());
        table.extend_from_slice(&0u64.to_le_bytes());
        table.resize(RECORD_STRIDE * 3, 0);

        let header_len: usize = 64;
        let shentsize: usize = 64;
        let sections: [(u64, u64, u32, u64, &[u8]); 3] = [
            (
                text_addr,
                text_size,
                1,
                SHF_EXECINSTR,
                &vec![0x90u8; text_size as usize],
            ),
            (names_addr, names.len() as u64, 1, 0, names),
            (table_addr, table.len() as u64, 1, 0, &table),
        ];

        let mut body: Vec<u8> = Vec::new();
        let mut placed: Vec<(u64, u32, u64, usize, usize)> = Vec::new();
        for (addr, size, sh_type, flags, data) in &sections {
            let offset: usize = header_len + body.len();
            body.extend_from_slice(data);
            placed.push((*addr, *sh_type, *flags, offset, *size as usize));
        }
        let shoff: usize = header_len + body.len();

        let mut blob: Vec<u8> = vec![0u8; header_len];
        blob[..4].copy_from_slice(&ELF_MAGIC);
        blob[4] = 2;
        blob[5] = 1;
        blob[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        blob[0x3a..0x3c].copy_from_slice(&(shentsize as u16).to_le_bytes());
        blob[0x3c..0x3e].copy_from_slice(&(placed.len() as u16).to_le_bytes());
        blob[0x3e..0x40].copy_from_slice(&259u16.to_le_bytes());
        blob.extend_from_slice(&body);
        for (addr, sh_type, flags, offset, size) in placed {
            let mut hdr: Vec<u8> = vec![0u8; shentsize];
            hdr[4..8].copy_from_slice(&sh_type.to_le_bytes());
            hdr[8..16].copy_from_slice(&flags.to_le_bytes());
            hdr[16..24].copy_from_slice(&addr.to_le_bytes());
            hdr[24..32].copy_from_slice(&(offset as u64).to_le_bytes());
            hdr[32..40].copy_from_slice(&(size as u64).to_le_bytes());
            blob.extend_from_slice(&hdr);
        }
        blob
    }
}
