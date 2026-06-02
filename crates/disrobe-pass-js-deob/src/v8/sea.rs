use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Real Node.js Single Executable Application `kMagic` constant.
///
/// Source: `src/node_sea.h` in nodejs/node - `const uint32_t kMagic = 0x143da20;`.
/// Stored little-endian at offset 0 of every `sea-prep.blob` produced by
/// `node --experimental-sea-config`. Empirically verified against a real
/// `sea-prep.blob` generated on Node 24.16 (bytes: `20 da 43 01 ...`).
pub const SEA_MAGIC: u32 = 0x0143_DA20;

/// Legacy byte-string sentinel kept only so external callers that imported the
/// old (fabricated) `NODE_SEA` symbol get a compile-time deprecation, not a
/// silent semantic change.
#[deprecated(
    since = "0.3.0",
    note = "fake constant; Node SEA blobs have NO `NODE_SEA` literal - detect via SEA_MAGIC (0x0143DA20) at offset 0"
)]
pub const SEA_MAGIC_LEGACY_LABEL: &[u8; 8] = b"NODE_SEA";

/// Legacy alias for the fake resource-tag constant. The real format has no such tag.
#[deprecated(
    since = "0.3.0",
    note = "fake constant; use SEA_MAGIC (0x0143DA20) which is the actual first u32 of every sea-prep.blob"
)]
pub const SEA_RESOURCE_TAG_V1: u32 = SEA_MAGIC;

/// Bit flags written into the `flags` `u32` immediately after the magic.
///
/// Source: `enum class SeaFlags : uint32_t` in `src/node_sea.h`.
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

/// Hard cap to bound any single string-view read from a SEA blob (prevents the
/// 1.6-GiB-class garbage that fabricated parsers produce on malformed input).
pub const SEA_MAX_STRING_BYTES: usize = 256usize * 1024usize * 1024usize;

/// Parsed contents of a Node SEA blob (or a SEA-embedded segment carved out of a host binary).
///
/// Field order matches `SeaSerializer::Write` in upstream Node.js
/// (`src/node_sea.cc`): magic, flags, `exec_argv_extension`, then two
/// size_t-length-prefixed strings (`code_path`, `main_code_or_snapshot`).
/// The optional `code_cache` / `assets` / `exec_argv` tails are not parsed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeaBlob {
    pub magic_offset: u64,
    pub magic: u32,
    pub flags: SeaFlags,
    pub exec_argv_extension: u8,
    pub code_path: String,
    pub main_code_len: u64,
    /// Offset of the main-code bytes inside the input buffer (absolute, not relative
    /// to `magic_offset`).
    pub main_code_offset: u64,
    pub end_offset: u64,
}

/// Location of a SEA blob inside a larger binary (e.g. a postject-injected Node exe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeaBlobLocation {
    pub blob_offset: u64,
    pub flags: u32,
}

/// Locate every `SEA_MAGIC` occurrence in `bytes`. A standalone `sea-prep.blob`
/// has the magic at offset 0; a postject-injected binary may have it embedded.
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

/// Detect whether `bytes` contains a Node SEA blob (standalone or embedded).
/// Returns the first plausible location.
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

/// Parse a Node SEA blob starting at offset `start` of `bytes`.
///
/// Layout (see `SeaSerializer::Write` in `src/node_sea.cc` and
/// `WriteStringView` / `ReadStringView` in `src/blob_serializer_deserializer-inl.h`):
/// 1. `magic: u32` = `SEA_MAGIC`
/// 2. `flags: u32` (see [`SeaFlags`])
/// 3. `exec_argv_extension: u8`
/// 4. `code_path: length_prefixed_string` (`size_t` u64 length, then UTF-8 bytes)
/// 5. `main_code_or_snapshot: length_prefixed_string` (`size_t` u64 length, then bytes)
/// 6. (optional, flags-gated) `code_cache`, `assets`, `exec_argv`
///
/// Only fields 1-5 are required to identify a valid SEA blob; we stop after them
/// and report `end_offset`. Empirically verified against a 57-byte real
/// `sea-prep.blob` produced by Node 24.16.
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

/// Convenience: parse the first SEA blob found anywhere in `bytes`.
pub fn parse_sea_blob(bytes: &[u8]) -> Result<SeaBlob> {
    let loc: SeaBlobLocation = detect_node_sea_blob(bytes).ok_or_else(|| {
        let len: usize = bytes.len();
        Error::OxcParse(format!(
            "sea magic 0x{SEA_MAGIC:08X} not found anywhere in {len} input bytes"
        ))
    })?;
    parse_sea_blob_at(bytes, loc.blob_offset)
}

/// Carve the main-code bytes (as recorded by the SEA writer) out of `bytes`.
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
    let s: String = String::from_utf8(bytes[start..end].to_vec()).map_err(
        |e: std::string::FromUtf8Error| Error::OxcParse(format!("sea string not utf-8: {e}")),
    )?;
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
