use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const SECTOR_SIZE: usize = 2048;
const VOLUME_DESCRIPTOR_LBA: usize = 16;
const VD_PRIMARY: u8 = 1;
const VD_SUPPLEMENTARY: u8 = 2;
const VD_TERMINATOR: u8 = 255;
const STANDARD_ID: &[u8; 5] = b"CD001";
const DIR_FLAG_DIRECTORY: u8 = 0x02;
const MAX_DIR_DEPTH: usize = 64;
const MAX_RECORDS: usize = 5_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoEntry {
    pub path: String,
    pub extent_lba: u32,
    pub data_len: u32,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoImage {
    pub volume_id: String,
    pub joliet: bool,
    pub files: Vec<IsoEntry>,
}

#[inline]
fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at).ok()
}

fn sector(bytes: &[u8], lba: usize) -> Option<&[u8]> {
    let start: usize = lba.checked_mul(SECTOR_SIZE)?;
    let end: usize = start.checked_add(SECTOR_SIZE)?;
    bytes.get(start..end)
}

pub fn detect_iso(bytes: &[u8]) -> bool {
    sector(bytes, VOLUME_DESCRIPTOR_LBA)
        .and_then(|s: &[u8]| s.get(1..6))
        .is_some_and(|id: &[u8]| id == STANDARD_ID)
}

pub fn parse_iso(bytes: &[u8]) -> Result<IsoImage> {
    if !detect_iso(bytes) {
        return Err(Error::Decompression(
            "iso 9660 primary volume descriptor not found at sector 16".to_owned(),
        ));
    }
    let mut primary: Option<usize> = None;
    let mut supplementary: Option<usize> = None;
    for i in 0..32 {
        let lba: usize = VOLUME_DESCRIPTOR_LBA + i;
        let Some(vd): Option<&[u8]> = sector(bytes, lba) else {
            break;
        };
        if vd.get(1..6) != Some(STANDARD_ID.as_slice()) {
            break;
        }
        match vd[0] {
            VD_PRIMARY => primary = Some(lba),
            VD_SUPPLEMENTARY if is_joliet(vd) => supplementary = Some(lba),
            VD_TERMINATOR => break,
            _ => {}
        }
    }

    let (vd_lba, joliet): (usize, bool) = match supplementary {
        Some(lba) => (lba, true),
        None => (
            primary.ok_or_else(|| {
                Error::Decompression("iso primary volume descriptor missing".to_owned())
            })?,
            false,
        ),
    };
    let vd: &[u8] = sector(bytes, vd_lba)
        .ok_or_else(|| Error::Decompression("iso volume descriptor out of bounds".to_owned()))?;

    let volume_id: String = decode_volume_id(&vd[40..72], joliet);
    let root_record: &[u8] = vd
        .get(156..156 + 34)
        .ok_or_else(|| Error::Decompression("iso root directory record truncated".to_owned()))?;
    let root_lba: u32 = read_u32_le(root_record, 2)
        .ok_or_else(|| Error::Decompression("iso root extent truncated".to_owned()))?;
    let root_len: u32 = read_u32_le(root_record, 10)
        .ok_or_else(|| Error::Decompression("iso root length truncated".to_owned()))?;

    let mut files: Vec<IsoEntry> = Vec::new();
    walk_directory(
        bytes,
        root_lba,
        root_len,
        String::new(),
        joliet,
        0,
        &mut files,
    )?;
    Ok(IsoImage {
        volume_id,
        joliet,
        files,
    })
}

fn is_joliet(vd: &[u8]) -> bool {
    matches!(vd.get(88..91), Some([0x25, 0x2f, 0x40 | 0x43 | 0x45]))
}

fn decode_volume_id(raw: &[u8], joliet: bool) -> String {
    if joliet {
        decode_ucs2_be(raw).trim().to_owned()
    } else {
        String::from_utf8_lossy(raw).trim().to_owned()
    }
}

fn decode_ucs2_be(raw: &[u8]) -> String {
    let mut out: String = String::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let code: u16 = u16::from_be_bytes([pair[0], pair[1]]);
        if code == 0 {
            continue;
        }
        out.push(char::from_u32(u32::from(code)).map_or('\u{fffd}', |value: char| value));
    }
    out
}

fn walk_directory(
    bytes: &[u8],
    lba: u32,
    len: u32,
    prefix: String,
    joliet: bool,
    depth: usize,
    out: &mut Vec<IsoEntry>,
) -> Result<()> {
    if depth > MAX_DIR_DEPTH || out.len() > MAX_RECORDS {
        return Ok(());
    }
    let start: usize = (lba as usize)
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| Error::Decompression("iso directory extent overflow".to_owned()))?;
    let end: usize = start
        .checked_add(len as usize)
        .map_or(bytes.len(), |e: usize| e.min(bytes.len()));
    let region: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Decompression("iso directory extent out of bounds".to_owned()))?;

    let mut pos: usize = 0;
    let mut subdirs: Vec<(String, u32, u32)> = Vec::new();
    while pos < region.len() {
        let record_len: usize = region[pos] as usize;
        if record_len == 0 {
            let next_sector: usize = (pos / SECTOR_SIZE + 1) * SECTOR_SIZE;
            if next_sector <= pos || next_sector >= region.len() {
                break;
            }
            pos = next_sector;
            continue;
        }
        if record_len < 33 || pos + record_len > region.len() {
            break;
        }
        let record: &[u8] = &region[pos..pos + record_len];
        let extent_lba: u32 = read_u32_le(record, 2).map_or(0, |value: u32| value);
        let data_len: u32 = read_u32_le(record, 10).map_or(0, |value: u32| value);
        let flags: u8 = record[25];
        let name_len: usize = record[32] as usize;
        let name_bytes: &[u8] = record
            .get(33..33 + name_len)
            .map_or(&[] as &[u8], |value: &[u8]| value);
        pos += record_len;

        if name_len == 1 && (name_bytes == [0x00] || name_bytes == [0x01]) {
            continue;
        }
        let name: String = decode_record_name(name_bytes, joliet);
        if name.is_empty() {
            continue;
        }
        let is_dir: bool = flags & DIR_FLAG_DIRECTORY != 0;
        let full: String = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        out.push(IsoEntry {
            path: full.clone(),
            extent_lba,
            data_len,
            is_dir,
        });
        if is_dir {
            subdirs.push((full, extent_lba, data_len));
        }
    }

    for (sub_prefix, sub_lba, sub_len) in subdirs {
        walk_directory(bytes, sub_lba, sub_len, sub_prefix, joliet, depth + 1, out)?;
    }
    Ok(())
}

fn decode_record_name(name_bytes: &[u8], joliet: bool) -> String {
    let decoded: String = if joliet {
        decode_ucs2_be(name_bytes)
    } else {
        String::from_utf8_lossy(name_bytes).into_owned()
    };
    strip_version_suffix(&decoded)
}

fn strip_version_suffix(name: &str) -> String {
    match name.rsplit_once(';') {
        Some((base, ver)) if ver.bytes().all(|b: u8| b.is_ascii_digit()) => base.to_owned(),
        _ => name.to_owned(),
    }
}

pub fn file_data<'a>(bytes: &'a [u8], entry: &IsoEntry) -> Option<&'a [u8]> {
    if entry.is_dir {
        return None;
    }
    let start: usize = (entry.extent_lba as usize).checked_mul(SECTOR_SIZE)?;
    let end: usize = start.checked_add(entry.data_len as usize)?;
    bytes.get(start..end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn put_record(buf: &mut Vec<u8>, name: &[u8], lba: u32, len: u32, is_dir: bool) {
        let record_len: usize = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
        let start: usize = buf.len();
        buf.push(record_len as u8);
        buf.push(0);
        buf.extend_from_slice(&lba.to_le_bytes());
        buf.extend_from_slice(&lba.to_be_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&[0u8; 7]);
        buf.push(if is_dir { DIR_FLAG_DIRECTORY } else { 0 });
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(name.len() as u8);
        buf.extend_from_slice(name);
        while buf.len() - start < record_len {
            buf.push(0);
        }
    }

    fn build_iso(file_name: &[u8], file_body: &[u8]) -> Vec<u8> {
        let total_sectors: usize = 24;
        let mut image: Vec<u8> = vec![0u8; total_sectors * SECTOR_SIZE];

        let root_lba: u32 = 20;
        let file_lba: u32 = 21;

        let pvd_off: usize = VOLUME_DESCRIPTOR_LBA * SECTOR_SIZE;
        image[pvd_off] = VD_PRIMARY;
        image[pvd_off + 1..pvd_off + 6].copy_from_slice(STANDARD_ID);
        let vol_id: &[u8] = b"DISROBE_TEST                    ";
        image[pvd_off + 40..pvd_off + 40 + vol_id.len()].copy_from_slice(vol_id);
        let mut root_record: Vec<u8> = Vec::new();
        put_record(
            &mut root_record,
            &[0x00],
            root_lba,
            SECTOR_SIZE as u32,
            true,
        );
        image[pvd_off + 156..pvd_off + 156 + root_record.len()].copy_from_slice(&root_record);

        let term_off: usize = (VOLUME_DESCRIPTOR_LBA + 1) * SECTOR_SIZE;
        image[term_off] = VD_TERMINATOR;
        image[term_off + 1..term_off + 6].copy_from_slice(STANDARD_ID);

        let mut dir: Vec<u8> = Vec::new();
        put_record(&mut dir, &[0x00], root_lba, SECTOR_SIZE as u32, true);
        put_record(&mut dir, &[0x01], root_lba, SECTOR_SIZE as u32, true);
        put_record(&mut dir, file_name, file_lba, file_body.len() as u32, false);
        let root_off: usize = root_lba as usize * SECTOR_SIZE;
        image[root_off..root_off + dir.len()].copy_from_slice(&dir);

        let file_off: usize = file_lba as usize * SECTOR_SIZE;
        image[file_off..file_off + file_body.len()].copy_from_slice(file_body);
        image
    }

    #[test]
    fn detects_and_extracts_iso_file() {
        let body: &[u8] = b"iso 9660 recovered file contents";
        let image: Vec<u8> = build_iso(b"HELLO.TXT;1", body);
        assert!(detect_iso(&image));
        let iso: IsoImage = parse_iso(&image).expect("parse iso");
        assert_eq!(iso.volume_id, "DISROBE_TEST");
        let file: &IsoEntry = iso
            .files
            .iter()
            .find(|e: &&IsoEntry| !e.is_dir)
            .expect("file entry");
        assert_eq!(file.path, "HELLO.TXT");
        let data: &[u8] = file_data(&image, file).expect("file data");
        assert_eq!(data, body);
    }

    #[test]
    fn rejects_non_iso() {
        assert!(!detect_iso(&vec![0u8; 4096]));
        assert!(parse_iso(&vec![0u8; 4096]).is_err());
    }

    #[test]
    fn truncated_iso_does_not_panic() {
        let body: &[u8] = b"payload";
        let full: Vec<u8> = build_iso(b"A.TXT;1", body);
        for cut in (SECTOR_SIZE..full.len()).step_by(1024) {
            let _ = parse_iso(&full[..cut]);
        }
    }
}
