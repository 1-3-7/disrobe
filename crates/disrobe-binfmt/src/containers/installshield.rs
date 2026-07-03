use std::io::Read as _;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallshieldExternalHint {
    pub tool_binary: &'static str,
    pub install_hint: &'static str,
}

#[must_use]
pub const fn installshield_external_hint() -> InstallshieldExternalHint {
    InstallshieldExternalHint {
        tool_binary: "i6comp",
        install_hint: "InstallShield CAB archives require `i6comp` / `isinfo` / `unshield`; install one (e.g. `apt install unshield` or build i6comp from source) - no Elastic-2.0-compatible pure-Rust decoder exists for InstallShield's proprietary container",
    }
}

const ISC_SIGNATURE: u32 = 0x2863_5349;
const COMMON_HEADER_LEN: usize = 20;
const FILE_DESCRIPTOR_LEN: usize = 0x57;
const FILE_COMPRESSED: u16 = 0x0004;
const FILE_INVALID: u16 = 0x0008;
const FILE_SPLIT: u16 = 0x0001;
const MAX_IS_FILES: usize = 200_000;
const MAX_IS_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallShieldHeader {
    pub version: u32,
    pub cab_descriptor_offset: u32,
    pub cab_descriptor_size: u32,
    pub file_count: u32,
    pub file_table_offset: u32,
}

#[derive(Debug, Clone)]
pub struct InstallShieldFile {
    pub name: String,
    pub data: Vec<u8>,
    pub compressed: bool,
}

pub fn detect_installshield(bytes: &[u8]) -> Option<InstallShieldHeader> {
    if bytes.len() < COMMON_HEADER_LEN {
        return None;
    }
    if read_u32(bytes, 0)? != ISC_SIGNATURE {
        return None;
    }
    let version: u32 = read_u32(bytes, 4)?;
    let cab_descriptor_offset: u32 = read_u32(bytes, 0x0C)?;
    let cab_descriptor_size: u32 = read_u32(bytes, 0x10)?;
    let desc_base: usize = cab_descriptor_offset as usize;
    let file_count: u32 = read_u32(bytes, desc_base + 0x28).map_or(0, |value: u32| value);
    let file_table_offset: u32 = read_u32(bytes, desc_base + 0x0C).map_or(0, |value: u32| value);
    Some(InstallShieldHeader {
        version,
        cab_descriptor_offset,
        cab_descriptor_size,
        file_count,
        file_table_offset,
    })
}

pub fn walk_installshield(bytes: &[u8], max_total: u64) -> Result<Vec<InstallShieldFile>> {
    let header: InstallShieldHeader = detect_installshield(bytes)
        .ok_or_else(|| is_err("input is not an InstallShield `ISc(` cabinet"))?;
    if (header.version >> 24) < 6 && header.version > 0 && header.version < 0x0100_0000 {
        return Err(Error::InstallShield(format!(
            "InstallShield version {} (<6) uses the legacy file-descriptor layout not decoded in-tree; only the v6+ 0x57-byte descriptor is walked",
            header.version
        )));
    }
    let desc_base: usize = header.cab_descriptor_offset as usize;
    let file_table_base: usize = desc_base
        .checked_add(header.file_table_offset as usize)
        .ok_or_else(|| is_err("file table offset overflow"))?;
    let count: usize = (header.file_count as usize).min(MAX_IS_FILES);
    let mut files: Vec<InstallShieldFile> = Vec::with_capacity(count);
    let mut total: u64 = 0;
    let offsets_len: usize = count
        .checked_mul(4)
        .ok_or_else(|| is_err("file offset table length overflow"))?;
    let offsets_end: usize = file_table_base
        .checked_add(offsets_len)
        .ok_or_else(|| is_err("file offset table end overflow"))?;
    let offsets: &[u8] = bytes
        .get(file_table_base..offsets_end)
        .ok_or_else(|| is_err("file offset table out of bounds"))?;
    for i in 0..count {
        let entry_rel: u32 = read_u32(offsets, i * 4).map_or(0, |value: u32| value);
        let entry_rel_usize: usize = match usize::try_from(entry_rel) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let desc_at: usize = match file_table_base.checked_add(entry_rel_usize) {
            Some(v) => v,
            None => continue,
        };
        let Some(desc_end): Option<usize> = desc_at.checked_add(FILE_DESCRIPTOR_LEN) else {
            continue;
        };
        let Some(descriptor): Option<&[u8]> = bytes.get(desc_at..desc_end) else {
            continue;
        };
        let flags: u16 = read_u16(descriptor, 0x00).map_or(0, |value: u16| value);
        if flags & FILE_INVALID != 0 || flags & FILE_SPLIT != 0 {
            continue;
        }
        let expanded_size: u64 = read_u64(descriptor, 0x02).map_or(0, |value: u64| value);
        let compressed_size: u64 = read_u64(descriptor, 0x0A).map_or(0, |value: u64| value);
        let data_offset: u64 = read_u64(descriptor, 0x12).map_or(0, |value: u64| value);
        let name_offset: u32 = read_u32(descriptor, 0x3A).map_or(0, |value: u32| value);
        let compressed: bool = flags & FILE_COMPRESSED != 0;
        if expanded_size > MAX_IS_FILE_BYTES || compressed_size > MAX_IS_FILE_BYTES {
            continue;
        }
        let name_offset_usize: usize = match usize::try_from(name_offset) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(name_at): Option<usize> = file_table_base.checked_add(name_offset_usize) else {
            continue;
        };
        let data_offset_usize: usize = match usize::try_from(data_offset) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let compressed_size_usize: usize = match usize::try_from(compressed_size) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let expanded_size_usize: usize = match usize::try_from(expanded_size) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name: String = read_cstring(bytes, name_at);
        let data: Vec<u8> = read_file_bytes(
            bytes,
            data_offset_usize,
            compressed_size_usize,
            expanded_size_usize,
            compressed,
        )?;
        let data_len: u64 =
            u64::try_from(data.len()).map_err(|_| is_err("file data length exceeds u64"))?;
        total = total.saturating_add(data_len);
        if total > max_total {
            return Err(Error::InstallShield(format!(
                "installshield walk exceeds total cap {max_total}"
            )));
        }
        files.push(InstallShieldFile {
            name,
            data,
            compressed,
        });
    }
    Ok(files)
}

fn read_file_bytes(
    bytes: &[u8],
    data_offset: usize,
    compressed_size: usize,
    expanded_size: usize,
    compressed: bool,
) -> Result<Vec<u8>> {
    let data_end: usize = data_offset
        .checked_add(compressed_size)
        .ok_or_else(|| is_err("file data region offset overflow"))?;
    let region: &[u8] = bytes
        .get(data_offset..data_end)
        .ok_or_else(|| is_err("file data region out of bounds"))?;
    if !compressed {
        return Ok(region.to_vec());
    }
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(region);
    let mut out: Vec<u8> = Vec::with_capacity(expanded_size.min(64 * 1024 * 1024));
    decoder
        .by_ref()
        .take(MAX_IS_FILE_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::InstallShield(format!("installshield zlib: {e}")))?;
    let out_len: u64 =
        u64::try_from(out.len()).map_err(|_| is_err("installshield file length exceeds u64"))?;
    if out_len > MAX_IS_FILE_BYTES {
        return Err(Error::InstallShield(format!(
            "installshield file exceeds per-file cap {MAX_IS_FILE_BYTES}"
        )));
    }
    if out.len() > expanded_size {
        return Err(is_err(
            "installshield zlib output exceeds declared file size",
        ));
    }
    Ok(out)
}

fn read_cstring(bytes: &[u8], at: usize) -> String {
    let slice: &[u8] = bytes.get(at..).map_or(&[] as &[u8], |value: &[u8]| value);
    let end: usize = slice
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(slice.len(), |value: usize| value);
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

#[inline]
fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let s: &[u8] = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let s: &[u8] = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let s: &[u8] = bytes.get(at..at + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[inline]
fn is_err(msg: &'static str) -> Error {
    Error::InstallShield(msg.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hint_points_to_external_tool() {
        let hint: InstallshieldExternalHint = installshield_external_hint();
        assert!(matches!(hint.tool_binary, "i6comp"));
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn build_test_installshield(file_name: &str, file_body: &[u8]) -> Vec<u8> {
        let compressed: Vec<u8> = zlib_compress(file_body);
        let cab_descriptor_offset: u32 = 0x100;
        let file_table_offset: u32 = 0x40;
        let file_table_base: usize = cab_descriptor_offset as usize + file_table_offset as usize;

        let offset_table_len: u32 = 4;
        let name_rel: u32 = offset_table_len;
        let descriptor_rel: u32 = name_rel + file_name.len() as u32 + 1;
        let descriptor_at: usize = file_table_base + descriptor_rel as usize;

        let data_offset: usize = descriptor_at + FILE_DESCRIPTOR_LEN + 16;

        let mut image: Vec<u8> = vec![0u8; data_offset + compressed.len()];
        image[0..4].copy_from_slice(&ISC_SIGNATURE.to_le_bytes());
        image[4..8].copy_from_slice(&0x0600_0000u32.to_le_bytes());
        image[0x0C..0x10].copy_from_slice(&cab_descriptor_offset.to_le_bytes());
        image[0x10..0x14].copy_from_slice(&64u32.to_le_bytes());

        let desc_base: usize = cab_descriptor_offset as usize;
        image[desc_base + 0x0C..desc_base + 0x10].copy_from_slice(&file_table_offset.to_le_bytes());
        image[desc_base + 0x28..desc_base + 0x2C].copy_from_slice(&1u32.to_le_bytes());

        image[file_table_base..file_table_base + 4].copy_from_slice(&descriptor_rel.to_le_bytes());

        let name_at: usize = file_table_base + name_rel as usize;
        image[name_at..name_at + file_name.len()].copy_from_slice(file_name.as_bytes());

        image[descriptor_at..descriptor_at + 2].copy_from_slice(&FILE_COMPRESSED.to_le_bytes());
        image[descriptor_at + 0x02..descriptor_at + 0x0A]
            .copy_from_slice(&(file_body.len() as u64).to_le_bytes());
        image[descriptor_at + 0x0A..descriptor_at + 0x12]
            .copy_from_slice(&(compressed.len() as u64).to_le_bytes());
        image[descriptor_at + 0x12..descriptor_at + 0x1A]
            .copy_from_slice(&(data_offset as u64).to_le_bytes());
        image[descriptor_at + 0x3A..descriptor_at + 0x3E].copy_from_slice(&name_rel.to_le_bytes());

        image[data_offset..data_offset + compressed.len()].copy_from_slice(&compressed);
        image
    }

    #[test]
    fn walks_real_format_installshield_v6() {
        let body: &[u8] = &b"installshield isc cabinet zlib file body recovery ".repeat(20);
        let image: Vec<u8> = build_test_installshield("setup/app.exe", body);
        let header: InstallShieldHeader = detect_installshield(&image).expect("detect");
        assert_eq!(header.file_count, 1);
        let files: Vec<InstallShieldFile> =
            walk_installshield(&image, 64 * 1024 * 1024).expect("walk");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "setup/app.exe");
        assert_eq!(files[0].data, body);
        assert!(files[0].compressed);
    }

    #[test]
    fn rejects_inflated_size_past_descriptor() {
        let compressed: Vec<u8> = zlib_compress(b"tool");
        let err: Error =
            read_file_bytes(&compressed, 0, compressed.len(), 3, true).expect_err("size cap");
        assert!(matches!(err, Error::InstallShield(_)));
    }

    #[test]
    fn rejects_data_region_offset_overflow() {
        let err: Error = read_file_bytes(&[], usize::MAX, 1, 0, false).expect_err("range");
        assert!(matches!(err, Error::InstallShield(_)));
    }

    #[test]
    fn rejects_non_installshield() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(detect_installshield(&bytes).is_none());
    }

    #[test]
    fn extract_to_writes_installshield_file() {
        let body: &[u8] = b"installshield end to end payload 0xFEEDFACE";
        let image: Vec<u8> = build_test_installshield("bin/tool.dll", body);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-is-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::InstallShield,
            &image,
            &dir,
        )
        .expect("installshield extract");
        assert_eq!(result.kind, crate::container::ContainerKind::InstallShield);
        assert_eq!(std::fs::read(dir.join("bin/tool.dll")).expect("file"), body);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
