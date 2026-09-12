use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const SEA_MAGIC: u32 = 0x0143_DA20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SeaFlags {
    pub disable_experimental_warning: bool,
    pub use_snapshot: bool,
    pub use_code_cache: bool,
    pub include_assets: bool,
    pub include_exec_argv: bool,
    pub raw: u32,
}

impl SeaFlags {
    const FLAG_DISABLE_WARNING: u32 = 1u32 << 0u32;
    const FLAG_USE_SNAPSHOT: u32 = 1u32 << 1u32;
    const FLAG_USE_CODE_CACHE: u32 = 1u32 << 2u32;
    const FLAG_INCLUDE_ASSETS: u32 = 1u32 << 3u32;
    const FLAG_INCLUDE_EXEC_ARGV: u32 = 1u32 << 4u32;

    #[must_use]
    pub const fn from_bits(raw: u32) -> Self {
        Self {
            disable_experimental_warning: (raw & Self::FLAG_DISABLE_WARNING) != 0u32,
            use_snapshot: (raw & Self::FLAG_USE_SNAPSHOT) != 0u32,
            use_code_cache: (raw & Self::FLAG_USE_CODE_CACHE) != 0u32,
            include_assets: (raw & Self::FLAG_INCLUDE_ASSETS) != 0u32,
            include_exec_argv: (raw & Self::FLAG_INCLUDE_EXEC_ARGV) != 0u32,
            raw,
        }
    }
}

pub const SEA_MAX_STRING_BYTES: usize = 256usize * 1024usize * 1024usize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeaBlob {
    pub magic_offset: u64,
    pub magic: u32,
    pub flags: SeaFlags,
    pub exec_argv_extension: u8,
    pub code_path: String,
    pub main_code_len: u64,

    pub main_code_offset: u64,
    pub end_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeaBlobLocation {
    pub blob_offset: u64,
    pub flags: u32,
}

#[must_use]
pub fn find_sea_magic_offsets(bytes: &[u8]) -> Vec<u64> {
    let needle: [u8; 4] = SEA_MAGIC.to_le_bytes();
    let mut hits: Vec<u64> = Vec::new();
    if bytes.len() < needle.len() {
        return hits;
    }
    let limit: usize = bytes
        .len()
        .saturating_sub(needle.len())
        .saturating_add(1usize);
    for off in 0usize..limit {
        if bytes[off..off + needle.len()] == needle {
            hits.push(off as u64);
        }
    }
    hits
}

#[must_use]
pub fn detect_node_sea_blob(bytes: &[u8]) -> Option<SeaBlobLocation> {
    let hits: Vec<u64> = find_sea_magic_offsets(bytes);
    for off in hits {
        let off_usize: usize = usize::try_from(off).ok()?;
        let flags_end: usize = off_usize.checked_add(8usize)?;
        if flags_end > bytes.len() {
            continue;
        }
        let flags_raw: u32 = u32::from_le_bytes([
            bytes[off_usize + 4usize],
            bytes[off_usize + 5usize],
            bytes[off_usize + 6usize],
            bytes[off_usize + 7usize],
        ]);
        if (flags_raw & !valid_flag_mask()) != 0u32 {
            continue;
        }
        return Some(SeaBlobLocation {
            blob_offset: off,
            flags: flags_raw,
        });
    }
    None
}

const fn valid_flag_mask() -> u32 {
    (1u32 << 0u32) | (1u32 << 1u32) | (1u32 << 2u32) | (1u32 << 3u32) | (1u32 << 4u32)
}

pub fn parse_sea_blob_at(bytes: &[u8], start: u64) -> Result<SeaBlob> {
    let start_usize: usize = usize::try_from(start).map_err(|_: std::num::TryFromIntError| {
        Error::OxcParse("sea start overflows usize".to_owned())
    })?;
    if bytes.len() < start_usize.saturating_add(9usize) {
        return Err(Error::OxcParse(format!(
            "sea blob too short at offset {start}: need at least 9 header bytes, \
             got {}",
            bytes.len().saturating_sub(start_usize)
        )));
    }
    let mut cursor: usize = start_usize;
    let magic: u32 = read_u32_le(bytes, cursor)?;
    if magic != SEA_MAGIC {
        return Err(Error::OxcParse(format!(
            "sea magic mismatch at offset {start}: got 0x{magic:08X}, expected 0x{SEA_MAGIC:08X}"
        )));
    }
    cursor = cursor.saturating_add(4usize);
    let flags_raw: u32 = read_u32_le(bytes, cursor)?;
    if (flags_raw & !valid_flag_mask()) != 0u32 {
        return Err(Error::OxcParse(format!(
            "sea flags 0x{flags_raw:08X} have bits outside the SeaFlags mask (0x{:08X})",
            valid_flag_mask()
        )));
    }
    cursor = cursor.saturating_add(4usize);
    let exec_argv_extension: u8 = read_u8(bytes, cursor)?;
    cursor = cursor.saturating_add(1usize);
    let (code_path, next): (String, usize) = read_length_prefixed_string(bytes, cursor)?;
    cursor = next;
    let main_code_len: u64 = read_u64_le(bytes, cursor)?;
    cursor = cursor.saturating_add(8usize);
    let main_code_len_usize: usize =
        usize::try_from(main_code_len).map_err(|_: std::num::TryFromIntError| {
            Error::OxcParse(format!("sea main_code_len {main_code_len} overflows usize"))
        })?;
    if main_code_len_usize > SEA_MAX_STRING_BYTES {
        return Err(Error::OxcParse(format!(
            "sea main_code_len {main_code_len_usize} exceeds SEA_MAX_STRING_BYTES"
        )));
    }
    let main_code_offset: usize = cursor;
    let main_code_end: usize = cursor
        .checked_add(main_code_len_usize)
        .ok_or_else(|| Error::OxcParse("sea main_code end overflows usize".to_owned()))?;
    if main_code_end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "sea main_code extends past input: end={main_code_end}, len={}",
            bytes.len()
        )));
    }
    cursor = main_code_end;
    Ok(SeaBlob {
        magic_offset: start,
        magic,
        flags: SeaFlags::from_bits(flags_raw),
        exec_argv_extension,
        code_path,
        main_code_len,
        main_code_offset: main_code_offset as u64,
        end_offset: cursor as u64,
    })
}

pub fn parse_sea_blob(bytes: &[u8]) -> Result<SeaBlob> {
    let loc: SeaBlobLocation = detect_node_sea_blob(bytes).ok_or_else(|| {
        let len: usize = bytes.len();
        Error::OxcParse(format!(
            "sea magic 0x{SEA_MAGIC:08X} not found anywhere in {len} input bytes"
        ))
    })?;
    parse_sea_blob_at(bytes, loc.blob_offset)
}

pub fn carve_sea_main_code(bytes: &[u8], blob: &SeaBlob) -> Result<Vec<u8>> {
    let start: usize =
        usize::try_from(blob.main_code_offset).map_err(|_: std::num::TryFromIntError| {
            Error::OxcParse("sea main_code_offset overflows usize".to_owned())
        })?;
    let end: usize = usize::try_from(blob.main_code_offset.saturating_add(blob.main_code_len))
        .map_err(|_: std::num::TryFromIntError| {
            Error::OxcParse("sea main_code end overflows usize".to_owned())
        })?;
    if end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "sea main_code carve out of bounds: end={end}, len={}",
            bytes.len()
        )));
    }
    Ok(bytes[start..end].to_vec())
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8> {
    if offset >= bytes.len() {
        return Err(Error::OxcParse(format!(
            "u8 read out of bounds: offset={offset}, len={}",
            bytes.len()
        )));
    }
    Ok(bytes[offset])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let end: usize = offset
        .checked_add(4usize)
        .ok_or_else(|| Error::OxcParse("u32 read offset overflows usize".to_owned()))?;
    if end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "u32 read out of bounds: offset={offset}, end={end}, len={}",
            bytes.len()
        )));
    }
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1usize],
        bytes[offset + 2usize],
        bytes[offset + 3usize],
    ]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
    let end: usize = offset
        .checked_add(8usize)
        .ok_or_else(|| Error::OxcParse("u64 read offset overflows usize".to_owned()))?;
    if end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "u64 read out of bounds: offset={offset}, end={end}, len={}",
            bytes.len()
        )));
    }
    Ok(u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1usize],
        bytes[offset + 2usize],
        bytes[offset + 3usize],
        bytes[offset + 4usize],
        bytes[offset + 5usize],
        bytes[offset + 6usize],
        bytes[offset + 7usize],
    ]))
}

fn read_length_prefixed_string(bytes: &[u8], offset: usize) -> Result<(String, usize)> {
    let len: u64 = read_u64_le(bytes, offset)?;
    let len_usize: usize = usize::try_from(len).map_err(|_: std::num::TryFromIntError| {
        Error::OxcParse(format!("sea string length {len} overflows usize"))
    })?;
    if len_usize > SEA_MAX_STRING_BYTES {
        return Err(Error::OxcParse(format!(
            "sea string length {len_usize} exceeds SEA_MAX_STRING_BYTES"
        )));
    }
    let start: usize = offset.saturating_add(8usize);
    let end: usize = start
        .checked_add(len_usize)
        .ok_or_else(|| Error::OxcParse("sea string end overflows usize".to_owned()))?;
    if end > bytes.len() {
        return Err(Error::OxcParse(format!(
            "sea string extends past input: end={end}, len={}",
            bytes.len()
        )));
    }
    let s: String = String::from_utf8_lossy(&bytes[start..end]).into_owned();
    Ok((s, end))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_real_sea(code_path: &str, main_code: &[u8], flags: u32) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&SEA_MAGIC.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.push(0u8);
        out.extend_from_slice(&(code_path.len() as u64).to_le_bytes());
        out.extend_from_slice(code_path.as_bytes());
        out.extend_from_slice(&(main_code.len() as u64).to_le_bytes());
        out.extend_from_slice(main_code);
        out
    }

    #[test]
    fn non_utf8_code_path_preserves_the_main_code_payload() {
        let path_bytes: [u8; 5] = [b'a', 0xff, b'.', b'j', b's'];
        let main: &[u8] = b"console.log(1);\n";
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&SEA_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0u8);
        bytes.extend_from_slice(&(path_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&path_bytes);
        bytes.extend_from_slice(&(main.len() as u64).to_le_bytes());
        bytes.extend_from_slice(main);

        let blob: SeaBlob =
            parse_sea_blob(&bytes).expect("a bad code-path byte must not abort the blob");
        assert!(blob.code_path.contains('\u{fffd}'));
        assert_eq!(blob.main_code_len, main.len() as u64);
        let carved: Vec<u8> = carve_sea_main_code(&bytes, &blob).expect("carve");
        assert_eq!(carved, main);
    }

    #[test]
    fn sea_magic_constant_matches_real_node_value() {
        assert_eq!(SEA_MAGIC, 0x0143_DA20);
        assert_eq!(SEA_MAGIC.to_le_bytes(), [0x20u8, 0xDAu8, 0x43u8, 0x01u8]);
    }

    #[test]
    fn parses_synthetic_real_format_sea_blob() {
        let bytes: Vec<u8> = synth_real_sea("script.js", b"console.log('hi sea');\n", 0u32);
        let blob: SeaBlob = parse_sea_blob(&bytes).expect("parse sea");
        assert_eq!(blob.magic, SEA_MAGIC);
        assert_eq!(blob.code_path, "script.js");
        assert_eq!(blob.main_code_len, 23u64);
        assert!(!blob.flags.use_snapshot);
        let main: Vec<u8> = carve_sea_main_code(&bytes, &blob).expect("carve");
        assert_eq!(main, b"console.log('hi sea');\n");
    }

    #[test]
    fn detects_real_sea_magic_offset_in_haystack() {
        let mut haystack: Vec<u8> = vec![0xCCu8; 64];
        haystack.extend_from_slice(&synth_real_sea("a.js", b"x", 0u32));
        let loc: SeaBlobLocation = detect_node_sea_blob(&haystack).expect("detect");
        assert_eq!(loc.blob_offset, 64u64);
        assert_eq!(loc.flags, 0u32);
    }

    #[test]
    fn returns_none_on_binary_without_sea_magic() {
        assert!(detect_node_sea_blob(&[0u8; 256]).is_none());
    }

    #[test]
    fn rejects_bogus_magic() {
        let mut bytes: Vec<u8> = synth_real_sea("a.js", b"x", 0u32);
        bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err: Error = parse_sea_blob(&bytes).unwrap_err();
        assert!(matches!(err, Error::OxcParse(_)));
    }

    #[test]
    fn rejects_flags_with_unknown_bits() {
        let bytes: Vec<u8> = synth_real_sea("a.js", b"x", 0xFFFF_FFFFu32);
        let err: Error = parse_sea_blob(&bytes).unwrap_err();
        match err {
            Error::OxcParse(msg) => assert!(
                msg.contains("not found") || msg.contains("outside the SeaFlags mask"),
                "msg={msg}"
            ),
            other => panic!("expected OxcParse, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_main_code_length_dos_guard() {
        let mut bytes: Vec<u8> = synth_real_sea("a.js", b"x", 0u32);
        let main_len_offset: usize = bytes.len() - 1usize - b"x".len() - 8usize;
        let huge: u64 = 0x4000_0000u64;
        bytes[main_len_offset..main_len_offset + 8usize].copy_from_slice(&huge.to_le_bytes());
        let err: Error = parse_sea_blob(&bytes).unwrap_err();
        match err {
            Error::OxcParse(msg) => assert!(
                msg.contains("exceeds") || msg.contains("extends past"),
                "msg={msg}"
            ),
            other => panic!("expected OxcParse, got {other:?}"),
        }
    }

    #[test]
    fn flags_decode_each_bit() {
        let f: SeaFlags = SeaFlags::from_bits(0b1_1111u32);
        assert!(f.disable_experimental_warning);
        assert!(f.use_snapshot);
        assert!(f.use_code_cache);
        assert!(f.include_assets);
        assert!(f.include_exec_argv);
    }
}
