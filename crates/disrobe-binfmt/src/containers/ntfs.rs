use std::io::Cursor;

use ntfs::structured_values::NtfsFileNamespace;
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";
const MAX_FILES: usize = 500_000;
const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtfsVolume {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub cluster_size: u32,
}

#[derive(Debug, Clone)]
pub struct NtfsFileEntry {
    pub path: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NtfsWalk {
    pub volume: NtfsVolume,
    pub files: Vec<NtfsFileEntry>,
    pub notes: Vec<String>,
}

#[must_use]
pub fn detect_ntfs(bytes: &[u8]) -> Option<NtfsVolume> {
    if bytes.len() < 512 {
        return None;
    }
    if &bytes[3..11] != NTFS_OEM_ID {
        return None;
    }
    let bytes_per_sector: u16 = u16::from_le_bytes([bytes[11], bytes[12]]);
    let sectors_per_cluster: u8 = bytes[13];
    if bytes_per_sector == 0 || !bytes_per_sector.is_power_of_two() {
        return None;
    }
    Some(NtfsVolume {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size: u32::from(bytes_per_sector) * u32::from(sectors_per_cluster.max(1)),
    })
}

pub fn walk_ntfs(bytes: &[u8], max_total: u64) -> Result<NtfsWalk> {
    let volume: NtfsVolume = detect_ntfs(bytes)
        .ok_or_else(|| Error::Ntfs("NTFS OEM id not found at offset 3".to_owned()))?;
    let mut cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut ntfs: Ntfs =
        Ntfs::new(&mut cursor).map_err(|e| Error::Ntfs(format!("open volume: {e}")))?;
    ntfs.read_upcase_table(&mut cursor)
        .map_err(|e| Error::Ntfs(format!("read $UpCase: {e}")))?;
    let root: NtfsFile = ntfs
        .root_directory(&mut cursor)
        .map_err(|e| Error::Ntfs(format!("root directory: {e}")))?;

    let mut files: Vec<NtfsFileEntry> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    let root_record: u64 = root.file_record_number();
    let mut stack: Vec<(NtfsFile, String, usize)> = vec![(root, String::new(), 0)];
    let mut visited: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    while let Some((dir, prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH || files.len() > MAX_FILES {
            break;
        }
        if !visited.insert(dir.file_record_number()) {
            continue;
        }
        let index = match dir.directory_index(&mut cursor) {
            Ok(i) => i,
            Err(e) => {
                notes.push(format!("ntfs `{prefix}` directory index: {e}"));
                continue;
            }
        };
        let mut entries = index.entries();
        while let Some(entry) = entries.next(&mut cursor) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    notes.push(format!("ntfs entry in `{prefix}`: {e}"));
                    continue;
                }
            };
            let Some(key) = entry.key() else {
                continue;
            };
            let Ok(file_name) = key else {
                continue;
            };
            if file_name.namespace() == NtfsFileNamespace::Dos {
                continue;
            }
            let name: String = file_name.name().to_string_lossy();
            if name == "." || name.starts_with('$') {
                continue;
            }
            let child_record: u64 = entry.file_reference().file_record_number();
            if child_record == root_record {
                continue;
            }
            let child: NtfsFile = match entry.to_file(&ntfs, &mut cursor) {
                Ok(f) => f,
                Err(e) => {
                    notes.push(format!("ntfs to_file `{name}`: {e}"));
                    continue;
                }
            };
            let child_path: String = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if file_name.is_directory() {
                stack.push((child, child_path, depth + 1));
            } else {
                match read_default_data(&mut cursor, &child, max_total) {
                    Ok(Some(data)) => {
                        total = total.saturating_add(data.len() as u64);
                        if total > max_total {
                            return Err(Error::Ntfs(format!("walk exceeds total cap {max_total}")));
                        }
                        files.push(NtfsFileEntry {
                            path: child_path,
                            data,
                        });
                    }
                    Ok(None) => {}
                    Err(e) => notes.push(format!("ntfs read `{child_path}`: {e}")),
                }
            }
        }
    }

    Ok(NtfsWalk {
        volume,
        files,
        notes,
    })
}

fn read_default_data(
    cursor: &mut Cursor<&[u8]>,
    file: &NtfsFile,
    max_total: u64,
) -> std::result::Result<Option<Vec<u8>>, String> {
    let Some(data_item) = file.data(cursor, "") else {
        return Ok(None);
    };
    let data_item = data_item.map_err(|e| format!("data item: {e}"))?;
    let data_attribute = data_item
        .to_attribute()
        .map_err(|e| format!("to_attribute: {e}"))?;
    let mut value = data_attribute
        .value(cursor)
        .map_err(|e| format!("attribute value: {e}"))?;
    let len: u64 = value.len();
    if len > max_total {
        return Err(format!("file size {len} exceeds total cap {max_total}"));
    }
    let mut buf: Vec<u8> = vec![0u8; len as usize];
    value
        .read_exact(cursor, &mut buf)
        .map_err(|e| format!("read_exact: {e}"))?;
    Ok(Some(buf))
}

#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn hostile_named_image(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    Some(tests::build_single_file_ntfs(name, body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const fn align8(value: usize) -> usize {
        value.wrapping_add(7) & !7
    }

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(|unit: u16| unit.to_le_bytes())
            .collect()
    }

    fn unsigned_varint_bytes(value: u64) -> Vec<u8> {
        if value == 0 {
            return Vec::new();
        }
        let mut bytes: Vec<u8> = value.to_le_bytes().to_vec();
        while bytes.len() > 1 && *bytes.last().expect("nonempty") == 0 {
            bytes.pop();
        }
        bytes
    }

    fn signed_varint_bytes(value: i64) -> Vec<u8> {
        let mut bytes: Vec<u8> = value.to_le_bytes().to_vec();
        while bytes.len() > 1 {
            let last: u8 = bytes[bytes.len() - 1];
            let second_last: u8 = bytes[bytes.len() - 2];
            let redundant: bool = (last == 0x00 && second_last & 0x80 == 0)
                || (last == 0xff && second_last & 0x80 != 0);
            if redundant {
                bytes.pop();
            } else {
                break;
            }
        }
        bytes
    }

    fn encode_single_data_run(lcn: u64, cluster_count: u64) -> Vec<u8> {
        let cluster_count_bytes: Vec<u8> = unsigned_varint_bytes(cluster_count);
        let lcn_delta_bytes: Vec<u8> =
            signed_varint_bytes(i64::try_from(lcn).expect("lcn fits in an i64"));
        let header: u8 = ((lcn_delta_bytes.len() as u8) << 4) | cluster_count_bytes.len() as u8;
        let mut out: Vec<u8> = vec![header];
        out.extend_from_slice(&cluster_count_bytes);
        out.extend_from_slice(&lcn_delta_bytes);
        out.push(0);
        out
    }

    fn build_resident_attribute(
        ty: u32,
        name: Option<&str>,
        value: &[u8],
        instance: u16,
    ) -> Vec<u8> {
        const RESIDENT_HEADER_LEN: u16 = 23;
        let name_bytes: Vec<u8> = name.map(utf16le_bytes).unwrap_or_default();
        let name_offset: u16 = if name_bytes.is_empty() {
            0
        } else {
            RESIDENT_HEADER_LEN
        };
        let value_offset: u16 = RESIDENT_HEADER_LEN + name_bytes.len() as u16;
        let raw_len: usize = value_offset as usize + value.len();
        let attribute_length: usize = align8(raw_len);
        let mut out: Vec<u8> = vec![0u8; attribute_length];
        out[0..4].copy_from_slice(&ty.to_le_bytes());
        out[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());
        out[8] = 0;
        out[9] = (name_bytes.len() / 2) as u8;
        out[10..12].copy_from_slice(&name_offset.to_le_bytes());
        out[12..14].copy_from_slice(&0u16.to_le_bytes());
        out[14..16].copy_from_slice(&instance.to_le_bytes());
        out[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        out[20..22].copy_from_slice(&value_offset.to_le_bytes());
        out[22] = 0;
        if !name_bytes.is_empty() {
            let start: usize = name_offset as usize;
            out[start..start + name_bytes.len()].copy_from_slice(&name_bytes);
        }
        let start: usize = value_offset as usize;
        out[start..start + value.len()].copy_from_slice(value);
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn build_nonresident_attribute(
        ty: u32,
        data_runs: &[u8],
        allocated_size: u64,
        data_size: u64,
        initialized_size: u64,
        highest_vcn: i64,
        instance: u16,
    ) -> Vec<u8> {
        const NON_RESIDENT_HEADER_LEN: u16 = 64;
        let raw_len: usize = NON_RESIDENT_HEADER_LEN as usize + data_runs.len();
        let attribute_length: usize = align8(raw_len);
        let mut out: Vec<u8> = vec![0u8; attribute_length];
        out[0..4].copy_from_slice(&ty.to_le_bytes());
        out[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());
        out[8] = 1;
        out[9] = 0;
        out[10..12].copy_from_slice(&0u16.to_le_bytes());
        out[12..14].copy_from_slice(&0u16.to_le_bytes());
        out[14..16].copy_from_slice(&instance.to_le_bytes());
        out[16..24].copy_from_slice(&0i64.to_le_bytes());
        out[24..32].copy_from_slice(&highest_vcn.to_le_bytes());
        out[32..34].copy_from_slice(&NON_RESIDENT_HEADER_LEN.to_le_bytes());
        out[34] = 0;
        out[40..48].copy_from_slice(&allocated_size.to_le_bytes());
        out[48..56].copy_from_slice(&data_size.to_le_bytes());
        out[56..64].copy_from_slice(&initialized_size.to_le_bytes());
        let start: usize = NON_RESIDENT_HEADER_LEN as usize;
        out[start..start + data_runs.len()].copy_from_slice(data_runs);
        out
    }

    fn build_file_name_value(parent_record: u64, name: &str, data_size: u64) -> Vec<u8> {
        const FILE_NAME_HEADER_LEN: usize = 66;
        let name_bytes: Vec<u8> = utf16le_bytes(name);
        let mut out: Vec<u8> = vec![0u8; FILE_NAME_HEADER_LEN + name_bytes.len()];
        out[0..8].copy_from_slice(&parent_record.to_le_bytes());
        out[40..48].copy_from_slice(&data_size.to_le_bytes());
        out[48..56].copy_from_slice(&data_size.to_le_bytes());
        out[56..60].copy_from_slice(&0u32.to_le_bytes());
        out[60..64].copy_from_slice(&0u32.to_le_bytes());
        out[64] = (name_bytes.len() / 2) as u8;
        out[65] = 0;
        out[FILE_NAME_HEADER_LEN..FILE_NAME_HEADER_LEN + name_bytes.len()]
            .copy_from_slice(&name_bytes);
        out
    }

    fn build_index_entry_for_file(
        child_record: u64,
        parent_record: u64,
        name: &str,
        data_size: u64,
    ) -> Vec<u8> {
        const INDEX_ENTRY_HEADER_LEN: usize = 16;
        let file_name_value: Vec<u8> = build_file_name_value(parent_record, name, data_size);
        let key_length: u16 = file_name_value.len() as u16;
        let raw_len: usize = INDEX_ENTRY_HEADER_LEN + file_name_value.len();
        let padded_len: usize = align8(raw_len);
        let mut out: Vec<u8> = vec![0u8; padded_len];
        out[0..8].copy_from_slice(&child_record.to_le_bytes());
        out[8..10].copy_from_slice(&(padded_len as u16).to_le_bytes());
        out[10..12].copy_from_slice(&key_length.to_le_bytes());
        out[12] = 0;
        out[INDEX_ENTRY_HEADER_LEN..INDEX_ENTRY_HEADER_LEN + file_name_value.len()]
            .copy_from_slice(&file_name_value);
        out
    }

    fn build_terminator_index_entry() -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 16];
        out[8..10].copy_from_slice(&16u16.to_le_bytes());
        out[12] = 0x02;
        out
    }

    fn build_index_root_value(entries: &[u8]) -> Vec<u8> {
        const INDEX_ROOT_AND_NODE_HEADER_LEN: usize = 32;
        let mut out: Vec<u8> = vec![0u8; INDEX_ROOT_AND_NODE_HEADER_LEN + entries.len()];
        out[0..4].copy_from_slice(&0x30u32.to_le_bytes());
        out[4..8].copy_from_slice(&1u32.to_le_bytes());
        out[8..12].copy_from_slice(&4096u32.to_le_bytes());
        out[12] = 1;
        out[16..20].copy_from_slice(&16u32.to_le_bytes());
        out[20..24].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        out[24..28].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        out[28] = 0;
        out[INDEX_ROOT_AND_NODE_HEADER_LEN..INDEX_ROOT_AND_NODE_HEADER_LEN + entries.len()]
            .copy_from_slice(entries);
        out
    }

    fn build_file_record(record_size: usize, flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
        const FIRST_ATTRIBUTE_OFFSET: u16 = 48;
        const UPDATE_SEQUENCE_OFFSET: usize = 42;
        let mut body: Vec<u8> = Vec::new();
        for attribute in attributes {
            body.extend_from_slice(attribute);
        }
        body.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        let data_size: u32 = u32::from(FIRST_ATTRIBUTE_OFFSET) + body.len() as u32;
        assert!(
            (data_size as usize) <= record_size,
            "synthetic file record body {data_size} exceeds the {record_size}-byte record"
        );
        let sector_count: usize = record_size / 512;
        let update_sequence_count: u16 = sector_count as u16 + 1;

        let mut record: Vec<u8> = vec![0u8; record_size];
        record[0..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&(UPDATE_SEQUENCE_OFFSET as u16).to_le_bytes());
        record[6..8].copy_from_slice(&update_sequence_count.to_le_bytes());
        record[8..16].copy_from_slice(&0u64.to_le_bytes());
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18..20].copy_from_slice(&1u16.to_le_bytes());
        record[20..22].copy_from_slice(&FIRST_ATTRIBUTE_OFFSET.to_le_bytes());
        record[22..24].copy_from_slice(&flags.to_le_bytes());
        record[24..28].copy_from_slice(&data_size.to_le_bytes());
        record[28..32].copy_from_slice(&(record_size as u32).to_le_bytes());
        record[32..40].copy_from_slice(&0u64.to_le_bytes());
        record[40..42].copy_from_slice(&(attributes.len() as u16).to_le_bytes());
        record[FIRST_ATTRIBUTE_OFFSET as usize..FIRST_ATTRIBUTE_OFFSET as usize + body.len()]
            .copy_from_slice(&body);

        let usn: [u8; 2] = [0x01, 0x00];
        record[UPDATE_SEQUENCE_OFFSET..UPDATE_SEQUENCE_OFFSET + 2].copy_from_slice(&usn);
        for sector in 0..sector_count {
            let tail: usize = sector * 512 + 510;
            let original: [u8; 2] = [record[tail], record[tail + 1]];
            let array_pos: usize = UPDATE_SEQUENCE_OFFSET + 2 + sector * 2;
            record[array_pos..array_pos + 2].copy_from_slice(&original);
            record[tail] = usn[0];
            record[tail + 1] = usn[1];
        }
        record
    }

    fn place_record(
        image: &mut [u8],
        mft_lcn: u64,
        record_size: usize,
        record_number: u64,
        record: &[u8],
    ) {
        let offset: usize = mft_lcn as usize * 512 + record_number as usize * record_size;
        image[offset..offset + record.len()].copy_from_slice(record);
    }

    fn write_boot_sector(image: &mut [u8], total_sectors: u64, mft_lcn: u64) {
        let boot: &mut [u8] = &mut image[0..512];
        boot[3..11].copy_from_slice(NTFS_OEM_ID);
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 1;
        boot[21] = 0xf8;
        boot[40..48].copy_from_slice(&total_sectors.to_le_bytes());
        boot[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
        boot[56..64].copy_from_slice(&mft_lcn.to_le_bytes());
        boot[64] = (-10i8) as u8;
        boot[68] = (-12i8) as u8;
        boot[510] = 0x55;
        boot[511] = 0xaa;
    }

    pub(super) fn build_single_file_ntfs(name: &str, body: &[u8]) -> Vec<u8> {
        const FILE_RECORD_SIZE: usize = 1024;
        const MFT_LCN: u64 = 1;
        const MFT_RECORD_COUNT: u64 = 16;
        const MFT_CLUSTERS: u64 = MFT_RECORD_COUNT * FILE_RECORD_SIZE as u64 / 512;
        const UPCASE_LCN: u64 = MFT_LCN + MFT_CLUSTERS;
        const UPCASE_BYTES: usize = 65536 * 2;
        const UPCASE_CLUSTERS: u64 = UPCASE_BYTES as u64 / 512;
        const ROOT_RECORD: u64 = 5;
        const UPCASE_RECORD: u64 = 10;
        const TARGET_RECORD: u64 = 12;
        const TOTAL_CLUSTERS: u64 = 1 + MFT_CLUSTERS + UPCASE_CLUSTERS;

        let mut image: Vec<u8> = vec![0u8; TOTAL_CLUSTERS as usize * 512];
        write_boot_sector(&mut image, TOTAL_CLUSTERS, MFT_LCN);

        let mft_data_runs: Vec<u8> = encode_single_data_run(MFT_LCN, MFT_CLUSTERS);
        let mft_bytes: u64 = MFT_CLUSTERS * 512;
        let mft_data_attribute: Vec<u8> = build_nonresident_attribute(
            0x80,
            &mft_data_runs,
            mft_bytes,
            mft_bytes,
            mft_bytes,
            MFT_CLUSTERS as i64 - 1,
            0,
        );
        let mft_record: Vec<u8> =
            build_file_record(FILE_RECORD_SIZE, 0x0001, &[mft_data_attribute]);
        place_record(&mut image, MFT_LCN, FILE_RECORD_SIZE, 0, &mft_record);

        let file_entry: Vec<u8> =
            build_index_entry_for_file(TARGET_RECORD, ROOT_RECORD, name, body.len() as u64);
        let terminator_entry: Vec<u8> = build_terminator_index_entry();
        let mut entries: Vec<u8> = Vec::new();
        entries.extend_from_slice(&file_entry);
        entries.extend_from_slice(&terminator_entry);
        let index_root_value: Vec<u8> = build_index_root_value(&entries);
        let index_root_attribute: Vec<u8> =
            build_resident_attribute(0x90, Some("$I30"), &index_root_value, 0);
        let root_record: Vec<u8> =
            build_file_record(FILE_RECORD_SIZE, 0x0003, &[index_root_attribute]);
        place_record(
            &mut image,
            MFT_LCN,
            FILE_RECORD_SIZE,
            ROOT_RECORD,
            &root_record,
        );

        let upcase_data: Vec<u8> = (0u32..65536)
            .flat_map(|code_point: u32| (code_point as u16).to_le_bytes())
            .collect();
        let upcase_data_runs: Vec<u8> = encode_single_data_run(UPCASE_LCN, UPCASE_CLUSTERS);
        let upcase_attribute: Vec<u8> = build_nonresident_attribute(
            0x80,
            &upcase_data_runs,
            UPCASE_BYTES as u64,
            UPCASE_BYTES as u64,
            UPCASE_BYTES as u64,
            UPCASE_CLUSTERS as i64 - 1,
            0,
        );
        let upcase_record: Vec<u8> =
            build_file_record(FILE_RECORD_SIZE, 0x0001, &[upcase_attribute]);
        place_record(
            &mut image,
            MFT_LCN,
            FILE_RECORD_SIZE,
            UPCASE_RECORD,
            &upcase_record,
        );

        let data_attribute: Vec<u8> = build_resident_attribute(0x80, None, body, 0);
        let target_record: Vec<u8> = build_file_record(FILE_RECORD_SIZE, 0x0001, &[data_attribute]);
        place_record(
            &mut image,
            MFT_LCN,
            FILE_RECORD_SIZE,
            TARGET_RECORD,
            &target_record,
        );

        let upcase_offset: usize = UPCASE_LCN as usize * 512;
        image[upcase_offset..upcase_offset + UPCASE_BYTES].copy_from_slice(&upcase_data);

        image
    }

    #[test]
    fn hostile_named_image_places_the_raw_name_in_the_root_directory() {
        for name in ["evil.", "..\\escape.txt", "a\u{2215}b.txt", "CONSOLE.txt"] {
            let bytes: Vec<u8> = hostile_named_image(name, b"payload").expect("ntfs image builds");
            let walk: NtfsWalk = walk_ntfs(&bytes, 64 * 1024 * 1024).expect("walk succeeds");
            assert_eq!(walk.files.len(), 1, "name {name:?}");
            assert_eq!(walk.files[0].path, name);
            assert_eq!(walk.files[0].data, b"payload");
        }
    }

    fn corpus_fixture() -> Option<Vec<u8>> {
        let mut p: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.push("corpus");
        p.push("binfmt");
        p.push("ntfs");
        p.push("hello.ntfs");
        std::fs::read(&p).ok()
    }

    #[test]
    fn detect_rejects_non_ntfs() {
        assert!(detect_ntfs(&[0u8; 1024]).is_none());
        let mut fake: Vec<u8> = vec![0u8; 512];
        fake[3..11].copy_from_slice(b"MSDOS5.0");
        assert!(detect_ntfs(&fake).is_none());
    }

    #[test]
    fn detect_accepts_ntfs_oem() {
        let mut boot: Vec<u8> = vec![0u8; 512];
        boot[3..11].copy_from_slice(NTFS_OEM_ID);
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 8;
        let vol: NtfsVolume = detect_ntfs(&boot).expect("ntfs");
        assert_eq!(vol.bytes_per_sector, 512);
        assert_eq!(vol.sectors_per_cluster, 8);
        assert_eq!(vol.cluster_size, 4096);
    }

    #[test]
    #[ignore = "needs gitignored real fixture corpus/binfmt/ntfs/hello.ntfs (~5MB); run with --ignored"]
    fn walks_real_ntfs_volume_byte_exact() {
        let Some(bytes): Option<Vec<u8>> = corpus_fixture() else {
            panic!("missing fixture corpus/binfmt/ntfs/hello.ntfs");
        };
        let walk: NtfsWalk = walk_ntfs(&bytes, 256 * 1024 * 1024).expect("walk ntfs");
        assert!(
            !walk.files.is_empty(),
            "expected at least one file in volume"
        );
        for f in &walk.files {
            assert!(!f.path.is_empty());
        }
    }
}
