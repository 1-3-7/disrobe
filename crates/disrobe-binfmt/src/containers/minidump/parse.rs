use crate::error::Result;

use super::{
    CV_SIGNATURE_NB10, CV_SIGNATURE_RSDS, CvKind, CvRecord, DIRECTORY_ENTRY_LEN, HEADER_LEN,
    MAX_MEMORY_REGIONS, MAX_MODULE_NAME_BYTES, MAX_MODULES, MAX_PDB_PATH_BYTES,
    MEMORY_DESCRIPTOR_LEN, MEMORY_DESCRIPTOR64_LEN, MEMORY64_LIST_HEADER_LEN, MINIDUMP_SIGNATURE,
    MINIDUMP_VERSION, MODULE_ENTRY_LEN, MemorySource, MinidumpHeader, MinidumpMemoryRegion,
    MinidumpModule, ProcessorArch, StreamDirEntry, err, u16_le, u32_le, u64_le,
};

pub(super) fn parse_header(bytes: &[u8]) -> Result<MinidumpHeader> {
    if bytes.len() < HEADER_LEN {
        return Err(err("minidump: file shorter than the 32-byte header"));
    }
    let signature: u32 = u32_le(bytes, 0).ok_or_else(|| err("minidump: truncated signature"))?;
    if signature != MINIDUMP_SIGNATURE {
        return Err(err(format!(
            "minidump: signature 0x{signature:08x} is not MDMP (0x{MINIDUMP_SIGNATURE:08x})"
        )));
    }
    let version: u32 = u32_le(bytes, 4).ok_or_else(|| err("minidump: truncated version"))?;
    if (version & 0xFFFF) as u16 != MINIDUMP_VERSION {
        return Err(err(format!(
            "minidump: version low word {} is not MINIDUMP_VERSION ({MINIDUMP_VERSION})",
            version & 0xFFFF
        )));
    }
    let number_of_streams: u32 =
        u32_le(bytes, 8).ok_or_else(|| err("minidump: truncated stream count"))?;
    let stream_directory_rva: u32 =
        u32_le(bytes, 12).ok_or_else(|| err("minidump: truncated directory rva"))?;
    if number_of_streams > super::MAX_STREAMS {
        return Err(err(format!(
            "minidump: stream count {number_of_streams} exceeds cap {}",
            super::MAX_STREAMS
        )));
    }
    Ok(MinidumpHeader {
        version,
        number_of_streams,
        stream_directory_rva,
    })
}

pub(super) fn read_directory(bytes: &[u8], header: &MinidumpHeader) -> Result<Vec<StreamDirEntry>> {
    let count: usize = header.number_of_streams as usize;
    let dir_rva: usize = header.stream_directory_rva as usize;
    let table_bytes: usize = count
        .checked_mul(DIRECTORY_ENTRY_LEN)
        .ok_or_else(|| err("minidump: stream directory size overflow"))?;
    let dir_end: usize = dir_rva
        .checked_add(table_bytes)
        .ok_or_else(|| err("minidump: stream directory extends past usize"))?;
    if dir_end > bytes.len() {
        return Err(err(format!(
            "minidump: stream directory [{dir_rva}, {dir_end}) runs past end of file ({})",
            bytes.len()
        )));
    }
    let mut streams: Vec<StreamDirEntry> = Vec::with_capacity(count.min(4096));
    for index in 0..count {
        let at: usize = dir_rva + index * DIRECTORY_ENTRY_LEN;
        let stream_type: u32 =
            u32_le(bytes, at).ok_or_else(|| err("minidump: truncated directory entry type"))?;
        let data_size: u32 =
            u32_le(bytes, at + 4).ok_or_else(|| err("minidump: truncated directory entry size"))?;
        let rva: u32 =
            u32_le(bytes, at + 8).ok_or_else(|| err("minidump: truncated directory entry rva"))?;
        let end: u64 = u64::from(rva)
            .checked_add(u64::from(data_size))
            .ok_or_else(|| err("minidump: directory entry range overflow"))?;
        if end > bytes.len() as u64 {
            continue;
        }
        streams.push(StreamDirEntry {
            stream_type,
            data_size,
            rva,
        });
    }
    Ok(streams)
}

pub(super) fn parse_system_info(bytes: &[u8], stream: &StreamDirEntry) -> Option<ProcessorArch> {
    if stream.data_size < 2 {
        return None;
    }
    let arch_raw: u16 = u16_le(bytes, stream.rva as usize)?;
    Some(ProcessorArch::from_raw(arch_raw))
}

pub(super) fn parse_module_list(
    bytes: &[u8],
    stream: &StreamDirEntry,
    notes: &mut Vec<String>,
) -> Result<Vec<MinidumpModule>> {
    let base: usize = stream.rva as usize;
    let count: u32 = u32_le(bytes, base).ok_or_else(|| err("minidump: truncated module count"))?;
    if count > MAX_MODULES {
        return Err(err(format!(
            "minidump: module count {count} exceeds cap {MAX_MODULES}"
        )));
    }
    let array_base: usize = base
        .checked_add(4)
        .ok_or_else(|| err("minidump: module array base overflow"))?;
    let mut modules: Vec<MinidumpModule> = Vec::with_capacity((count as usize).min(4096));
    for index in 0..count as usize {
        let entry: usize = array_base
            .checked_add(
                index
                    .checked_mul(MODULE_ENTRY_LEN)
                    .ok_or_else(|| err("minidump: module array index overflow"))?,
            )
            .ok_or_else(|| err("minidump: module array offset overflow"))?;
        if bytes.get(entry..entry + MODULE_ENTRY_LEN).is_none() {
            notes.push(format!(
                "minidump: module {index} of {count} runs past end of file; truncated module list"
            ));
            break;
        }
        let base_of_image: u64 =
            u64_le(bytes, entry).ok_or_else(|| err("minidump: truncated module base"))?;
        let size_of_image: u32 =
            u32_le(bytes, entry + 8).ok_or_else(|| err("minidump: truncated module size"))?;
        let checksum: u32 =
            u32_le(bytes, entry + 12).ok_or_else(|| err("minidump: truncated module checksum"))?;
        let timestamp: u32 =
            u32_le(bytes, entry + 16).ok_or_else(|| err("minidump: truncated module timestamp"))?;
        let name_rva: u32 =
            u32_le(bytes, entry + 20).ok_or_else(|| err("minidump: truncated module name rva"))?;
        let cv_size: u32 =
            u32_le(bytes, entry + 76).ok_or_else(|| err("minidump: truncated cv size"))?;
        let cv_rva: u32 =
            u32_le(bytes, entry + 80).ok_or_else(|| err("minidump: truncated cv rva"))?;

        let name: String = read_minidump_string(bytes, name_rva).unwrap_or_else(|| {
            notes.push(format!(
                "minidump: module at base 0x{base_of_image:016x} has an unreadable name string"
            ));
            format!("module_{base_of_image:016x}.bin")
        });
        let cv_record: Option<CvRecord> = parse_cv_record(bytes, cv_rva, cv_size);

        modules.push(MinidumpModule {
            base_of_image,
            size_of_image,
            checksum,
            timestamp,
            name,
            cv_record,
        });
    }
    Ok(modules)
}

pub(super) fn parse_memory_list(
    bytes: &[u8],
    stream: &StreamDirEntry,
    regions: &mut Vec<MinidumpMemoryRegion>,
    notes: &mut Vec<String>,
) {
    let base: usize = stream.rva as usize;
    let Some(count): Option<u32> = u32_le(bytes, base) else {
        notes.push("minidump: truncated MemoryListStream count".to_owned());
        return;
    };
    if u64::from(count) > MAX_MEMORY_REGIONS {
        notes.push(format!(
            "minidump: MemoryList range count {count} exceeds cap {MAX_MEMORY_REGIONS}; skipped"
        ));
        return;
    }
    let file_len: u64 = bytes.len() as u64;
    for index in 0..count as usize {
        let Some(entry): Option<usize> = base
            .checked_add(4)
            .zip(index.checked_mul(MEMORY_DESCRIPTOR_LEN))
            .and_then(|(b, o): (usize, usize)| b.checked_add(o))
        else {
            break;
        };
        let (Some(start_va), Some(data_size), Some(rva)): (Option<u64>, Option<u32>, Option<u32>) = (
            u64_le(bytes, entry),
            u32_le(bytes, entry + 8),
            u32_le(bytes, entry + 12),
        ) else {
            notes.push(format!(
                "minidump: MemoryList descriptor {index} runs past end of file"
            ));
            break;
        };
        let file_offset: u64 = u64::from(rva);
        let claimed: u64 = u64::from(data_size);
        let file_available: u64 = clamp_available(file_offset, claimed, file_len);
        if file_available < claimed {
            notes.push(format!(
                "minidump: MemoryList range at va 0x{start_va:016x} declares {claimed} bytes but only {file_available} are present in the file"
            ));
        }
        regions.push(MinidumpMemoryRegion {
            start_va,
            data_size: claimed,
            file_offset,
            file_available,
            source: MemorySource::MemoryList,
        });
    }
}

pub(super) fn parse_memory64_list(
    bytes: &[u8],
    stream: &StreamDirEntry,
    regions: &mut Vec<MinidumpMemoryRegion>,
    notes: &mut Vec<String>,
) -> Result<()> {
    let base: usize = stream.rva as usize;
    let number_of_ranges: u64 =
        u64_le(bytes, base).ok_or_else(|| err("minidump: truncated Memory64List count"))?;
    if number_of_ranges > MAX_MEMORY_REGIONS {
        return Err(err(format!(
            "minidump: Memory64List range count {number_of_ranges} exceeds cap {MAX_MEMORY_REGIONS}"
        )));
    }
    let base_rva: u64 =
        u64_le(bytes, base + 8).ok_or_else(|| err("minidump: truncated Memory64List base rva"))?;
    let file_len: u64 = bytes.len() as u64;
    let count: usize = usize::try_from(number_of_ranges)
        .map_err(|_e: std::num::TryFromIntError| err("minidump: Memory64List count overflow"))?;
    let mut running: u64 = base_rva;
    for index in 0..count {
        let entry: usize = base
            .checked_add(MEMORY64_LIST_HEADER_LEN)
            .zip(index.checked_mul(MEMORY_DESCRIPTOR64_LEN))
            .and_then(|(b, o): (usize, usize)| b.checked_add(o))
            .ok_or_else(|| err("minidump: Memory64List descriptor offset overflow"))?;
        let start_va: u64 = u64_le(bytes, entry)
            .ok_or_else(|| err("minidump: truncated Memory64List descriptor va"))?;
        let data_size: u64 = u64_le(bytes, entry + 8)
            .ok_or_else(|| err("minidump: truncated Memory64List descriptor size"))?;
        let file_offset: u64 = running;
        let file_available: u64 = clamp_available(file_offset, data_size, file_len);
        if file_available < data_size {
            notes.push(format!(
                "minidump: Memory64List range at va 0x{start_va:016x} declares {data_size} bytes but only {file_available} are present in the file"
            ));
        }
        regions.push(MinidumpMemoryRegion {
            start_va,
            data_size,
            file_offset,
            file_available,
            source: MemorySource::Memory64List,
        });
        running = running
            .checked_add(data_size)
            .ok_or_else(|| err("minidump: Memory64List running file offset overflow"))?;
        if running > file_len && index + 1 < count {
            notes.push(format!(
                "minidump: Memory64List data runs past end of file after range {index}; remaining ranges truncated"
            ));
            break;
        }
    }
    Ok(())
}

fn clamp_available(file_offset: u64, claimed: u64, file_len: u64) -> u64 {
    if file_offset >= file_len {
        return 0;
    }
    claimed.min(file_len - file_offset)
}

pub(super) fn read_minidump_string(bytes: &[u8], rva: u32) -> Option<String> {
    let off: usize = rva as usize;
    let length_bytes: u32 = u32_le(bytes, off)?;
    if length_bytes > MAX_MODULE_NAME_BYTES {
        return None;
    }
    let length: usize = length_bytes as usize;
    let buffer_start: usize = off.checked_add(4)?;
    let buffer_end: usize = buffer_start.checked_add(length)?;
    let buffer: &[u8] = bytes.get(buffer_start..buffer_end)?;
    let units: Vec<u16> = buffer
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let decoded: String = char::decode_utf16(units)
        .map(|r: core::result::Result<char, core::char::DecodeUtf16Error>| r.unwrap_or('\u{FFFD}'))
        .collect();
    Some(decoded.trim_end_matches('\u{0}').to_owned())
}

fn parse_cv_record(bytes: &[u8], rva: u32, size: u32) -> Option<CvRecord> {
    if size < 4 || rva == 0 {
        return None;
    }
    let off: usize = rva as usize;
    let end: usize = off.checked_add(size as usize)?;
    let record: &[u8] = bytes.get(off..end)?;
    let cv_signature: u32 = u32_le(record, 0)?;
    match cv_signature {
        CV_SIGNATURE_RSDS => {
            let guid_slice: &[u8] = record.get(4..20)?;
            let mut guid: [u8; 16] = [0u8; 16];
            guid.copy_from_slice(guid_slice);
            let age: u32 = u32_le(record, 20)?;
            let pdb_path: String = read_c_string(record, 24);
            Some(CvRecord {
                kind: CvKind::Pdb70,
                guid,
                age,
                pdb_path,
            })
        }
        CV_SIGNATURE_NB10 => {
            let signature: u32 = u32_le(record, 8)?;
            let age: u32 = u32_le(record, 12)?;
            let mut guid: [u8; 16] = [0u8; 16];
            guid[0..4].copy_from_slice(&signature.to_le_bytes());
            let pdb_path: String = read_c_string(record, 16);
            Some(CvRecord {
                kind: CvKind::Pdb20,
                guid,
                age,
                pdb_path,
            })
        }
        _ => None,
    }
}

fn read_c_string(record: &[u8], start: usize) -> String {
    let Some(tail): Option<&[u8]> = record.get(start..) else {
        return String::new();
    };
    let capped: &[u8] = if tail.len() > MAX_PDB_PATH_BYTES {
        &tail[..MAX_PDB_PATH_BYTES]
    } else {
        tail
    };
    let end: usize = capped
        .iter()
        .position(|&b: &u8| b == 0)
        .unwrap_or(capped.len());
    String::from_utf8_lossy(&capped[..end]).into_owned()
}
