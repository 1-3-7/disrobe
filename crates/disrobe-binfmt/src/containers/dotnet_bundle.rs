use std::borrow::Cow;
use std::io::Read;

use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::quota::{ExtractionQuota, QuotaGuard, sanitize_entry_path};

const MARKER_SIGNATURE: [u8; 32] = [
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
];
const HEADER_OFFSET_FIELD_LEN: usize = 8;
const COMPRESSION_MAJOR_VERSION: u32 = 6;
const V2_HEADER_MAJOR_VERSION: u32 = 2;
const MAX_MAJOR_VERSION: u32 = 64;
const MAX_EMBEDDED_FILES: usize = 1_000_000;
const MAX_PATH_LEN: usize = 64 * 1024;
const MAX_VARINT_SHIFT: u32 = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleFileType {
    Unknown,
    Assembly,
    NativeBinary,
    DepsJson,
    RuntimeConfigJson,
    Symbols,
}

impl BundleFileType {
    #[must_use]
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Assembly),
            2 => Some(Self::NativeBinary),
            3 => Some(Self::DepsJson),
            4 => Some(Self::RuntimeConfigJson),
            5 => Some(Self::Symbols),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleLocation {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotnetBundleFile {
    pub relative_path: String,
    pub file_type: BundleFileType,
    pub offset: u64,
    pub size: u64,
    pub compressed_size: u64,
}

impl DotnetBundleFile {
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.compressed_size > 0
    }

    #[must_use]
    const fn stored_len(&self) -> u64 {
        if self.compressed_size > 0 {
            self.compressed_size
        } else {
            self.size
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotnetBundle {
    pub major_version: u32,
    pub minor_version: u32,
    pub bundle_id: String,
    pub header_offset: u64,
    pub deps_json: Option<BundleLocation>,
    pub runtimeconfig_json: Option<BundleLocation>,
    pub flags: u64,
    pub files: Vec<DotnetBundleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotnetBundleEntry {
    pub relative_path: String,
    pub file_type: BundleFileType,
    pub data: Vec<u8>,
}

fn bundle_err(message: &str) -> Error {
    Error::DotnetBundle(message.to_owned())
}

fn read_u32(reader: &mut ByteReader<'_>, field: &str) -> Result<u32> {
    reader
        .read_u32_le()
        .map_err(|_| bundle_err(&format!("truncated reading {field}")))
}

fn read_i32(reader: &mut ByteReader<'_>, field: &str) -> Result<i32> {
    reader
        .read_i32_le()
        .map_err(|_| bundle_err(&format!("truncated reading {field}")))
}

fn read_i64(reader: &mut ByteReader<'_>, field: &str) -> Result<i64> {
    reader
        .read_i64_le()
        .map_err(|_| bundle_err(&format!("truncated reading {field}")))
}

fn read_u64(reader: &mut ByteReader<'_>, field: &str) -> Result<u64> {
    reader
        .read_u64_le()
        .map_err(|_| bundle_err(&format!("truncated reading {field}")))
}

fn read_u8(reader: &mut ByteReader<'_>, field: &str) -> Result<u8> {
    reader
        .read_u8()
        .map_err(|_| bundle_err(&format!("truncated reading {field}")))
}

fn read_7bit_prefixed_string(reader: &mut ByteReader<'_>, field: &str) -> Result<String> {
    let mut length: usize = 0;
    let mut shift: u32 = 0;
    loop {
        let byte: u8 = read_u8(reader, field)?;
        length |= usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| bundle_err(&format!("{field} length prefix overflow")))?;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > MAX_VARINT_SHIFT {
            return Err(bundle_err(&format!("{field} length prefix too long")));
        }
    }
    if length == 0 || length > MAX_PATH_LEN {
        return Err(bundle_err(&format!("{field} length {length} out of range")));
    }
    let raw: &[u8] = reader
        .read_bytes(length)
        .map_err(|_| bundle_err(&format!("truncated reading {field} body")))?;
    String::from_utf8(raw.to_vec()).map_err(|_| bundle_err(&format!("{field} is not valid utf-8")))
}

const fn version_supported(major: u32, minor: u32) -> bool {
    minor == 0
        && major <= MAX_MAJOR_VERSION
        && (major == 1 || major == V2_HEADER_MAJOR_VERSION || major >= COMPRESSION_MAJOR_VERSION)
}

fn read_header_offset(bytes: &[u8], signature_start: usize) -> Option<u64> {
    let field_start: usize = signature_start.checked_sub(HEADER_OFFSET_FIELD_LEN)?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(field_start).ok()?;
    reader.read_u64_le().ok()
}

fn header_is_plausible(bytes: &[u8], header_offset: u64) -> bool {
    let Ok(offset): std::result::Result<usize, _> = usize::try_from(header_offset) else {
        return false;
    };
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if reader.seek(offset).is_err() {
        return false;
    }
    let (Ok(major), Ok(minor)): (std::result::Result<u32, _>, std::result::Result<u32, _>) =
        (reader.read_u32_le(), reader.read_u32_le())
    else {
        return false;
    };
    if !version_supported(major, minor) {
        return false;
    }
    matches!(reader.read_i32_le(), Ok(count) if count > 0)
}

fn locate_header_offset(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < MARKER_SIGNATURE.len() + HEADER_OFFSET_FIELD_LEN {
        return None;
    }
    let last_start: usize = bytes.len() - MARKER_SIGNATURE.len();
    let mut index: usize = HEADER_OFFSET_FIELD_LEN;
    while index <= last_start {
        if bytes
            .get(index..)
            .is_some_and(|window: &[u8]| window.starts_with(&MARKER_SIGNATURE))
            && let Some(offset) = read_header_offset(bytes, index)
            && header_is_plausible(bytes, offset)
        {
            return Some(offset);
        }
        index += 1;
    }
    None
}

fn has_native_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0x7f, b'E', b'L', b'F'])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

#[must_use]
pub fn detect_dotnet_bundle(bytes: &[u8]) -> Option<u64> {
    if !has_native_magic(bytes) {
        return None;
    }
    locate_header_offset(bytes)
}

fn parse_location(reader: &mut ByteReader<'_>, field: &str) -> Result<Option<BundleLocation>> {
    let offset: i64 = read_i64(reader, field)?;
    let size: i64 = read_i64(reader, field)?;
    if offset < 0 || size < 0 {
        return Err(bundle_err(&format!("{field} has a negative location")));
    }
    if offset == 0 {
        return Ok(None);
    }
    Ok(Some(BundleLocation {
        offset: offset as u64,
        size: size as u64,
    }))
}

fn parse_file_entry(reader: &mut ByteReader<'_>, major_version: u32) -> Result<DotnetBundleFile> {
    let offset: i64 = read_i64(reader, "file entry offset")?;
    let size: i64 = read_i64(reader, "file entry size")?;
    let compressed_size: i64 = if major_version >= COMPRESSION_MAJOR_VERSION {
        read_i64(reader, "file entry compressed size")?
    } else {
        0
    };
    let type_byte: u8 = read_u8(reader, "file entry type")?;
    if offset <= 0 || size < 0 || compressed_size < 0 {
        return Err(bundle_err("file entry has an out-of-range offset or size"));
    }
    let file_type: BundleFileType = BundleFileType::from_u8(type_byte)
        .ok_or_else(|| bundle_err("file entry has an unknown type"))?;
    let relative_path: String = read_7bit_prefixed_string(reader, "file entry relative path")?;
    Ok(DotnetBundleFile {
        relative_path,
        file_type,
        offset: offset as u64,
        size: size as u64,
        compressed_size: compressed_size as u64,
    })
}

pub fn parse_dotnet_bundle(bytes: &[u8]) -> Result<DotnetBundle> {
    let header_offset: u64 = locate_header_offset(bytes)
        .ok_or_else(|| bundle_err("bundle marker or header not found"))?;
    let offset: usize = usize::try_from(header_offset)
        .map_err(|_| bundle_err("bundle header offset out of range"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(offset)
        .map_err(|_| bundle_err("bundle header offset past end of file"))?;

    let major_version: u32 = read_u32(&mut reader, "major version")?;
    let minor_version: u32 = read_u32(&mut reader, "minor version")?;
    if !version_supported(major_version, minor_version) {
        return Err(bundle_err("unsupported bundle version"));
    }
    let file_count_signed: i32 = read_i32(&mut reader, "embedded file count")?;
    if file_count_signed <= 0 {
        return Err(bundle_err("bundle declares a non-positive file count"));
    }
    let file_count: usize = file_count_signed as usize;
    if file_count > MAX_EMBEDDED_FILES {
        return Err(bundle_err("bundle file count exceeds sanity bound"));
    }
    let bundle_id: String = read_7bit_prefixed_string(&mut reader, "bundle id")?;

    let (deps_json, runtimeconfig_json, flags): (
        Option<BundleLocation>,
        Option<BundleLocation>,
        u64,
    ) = if major_version >= V2_HEADER_MAJOR_VERSION {
        let deps: Option<BundleLocation> = parse_location(&mut reader, "deps.json location")?;
        let runtimeconfig: Option<BundleLocation> =
            parse_location(&mut reader, "runtimeconfig.json location")?;
        let flags: u64 = read_u64(&mut reader, "header flags")?;
        (deps, runtimeconfig, flags)
    } else {
        (None, None, 0)
    };

    let mut files: Vec<DotnetBundleFile> = Vec::with_capacity(file_count.min(4096));
    for _ in 0..file_count {
        files.push(parse_file_entry(&mut reader, major_version)?);
    }

    Ok(DotnetBundle {
        major_version,
        minor_version,
        bundle_id,
        header_offset,
        deps_json,
        runtimeconfig_json,
        flags,
        files,
    })
}

fn inflate_deflate(compressed: &[u8], cap: u64, entry: &str) -> Result<Vec<u8>> {
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let mut decoder: flate2::read::DeflateDecoder<&[u8]> =
        flate2::read::DeflateDecoder::new(compressed);
    let read: u64 = std::io::copy(&mut (&mut decoder).take(limit), &mut out)
        .map_err(|e: std::io::Error| bundle_err(&format!("deflate decode failed: {e}")))?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: entry.to_owned(),
            reason: format!("inflated stream exceeds declared size {cap}"),
        });
    }
    Ok(out)
}

pub fn bundle_file_bytes<'a>(
    bytes: &'a [u8],
    file: &DotnetBundleFile,
    max_uncompressed: u64,
) -> Result<Cow<'a, [u8]>> {
    if file.size > max_uncompressed {
        return Err(Error::QuotaExceeded {
            entry: file.relative_path.clone(),
            reason: format!("declared size {} exceeds cap {max_uncompressed}", file.size),
        });
    }
    let offset: usize =
        usize::try_from(file.offset).map_err(|_| bundle_err("file entry offset out of range"))?;
    let stored_len: usize = usize::try_from(file.stored_len())
        .map_err(|_| bundle_err("file entry stored length out of range"))?;
    let end: usize = offset
        .checked_add(stored_len)
        .ok_or_else(|| bundle_err("file entry extent overflow"))?;
    let stored: &[u8] = bytes
        .get(offset..end)
        .ok_or_else(|| bundle_err("file entry extent past end of file"))?;

    if file.is_compressed() {
        let decoded: Vec<u8> = inflate_deflate(stored, file.size, &file.relative_path)?;
        if decoded.len() as u64 != file.size {
            return Err(bundle_err(
                "inflated output length does not match declared size",
            ));
        }
        Ok(Cow::Owned(decoded))
    } else {
        if stored.len() as u64 != file.size {
            return Err(bundle_err(
                "stored file extent does not match declared size",
            ));
        }
        Ok(Cow::Borrowed(stored))
    }
}

pub fn extract_dotnet_bundle(
    bytes: &[u8],
    quota: ExtractionQuota,
) -> Result<Vec<DotnetBundleEntry>> {
    let bundle: DotnetBundle = parse_dotnet_bundle(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let cap: u64 = guard.max_per_entry_uncompressed();
    let mut out: Vec<DotnetBundleEntry> = Vec::with_capacity(bundle.files.len().min(4096));
    for file in &bundle.files {
        let relative_path: String = sanitize_entry_path(&file.relative_path)?;
        guard.admit_entry(&relative_path, file.size, file.stored_len())?;
        let data: Cow<'_, [u8]> = bundle_file_bytes(bytes, file, cap)?;
        out.push(DotnetBundleEntry {
            relative_path,
            file_type: file.file_type,
            data: data.into_owned(),
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn put_7bit_string(buf: &mut Vec<u8>, text: &str) {
        let mut length: usize = text.len();
        loop {
            let mut byte: u8 = (length & 0x7f) as u8;
            length >>= 7;
            if length != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if length == 0 {
                break;
            }
        }
        buf.extend_from_slice(text.as_bytes());
    }

    struct FileSpec {
        path: &'static str,
        file_type: BundleFileType,
        content: Vec<u8>,
        compressed: Option<Vec<u8>>,
    }

    fn deflate_compress(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(3));
        encoder.write_all(data).expect("deflate write");
        encoder.finish().expect("deflate finish")
    }

    fn build_bundle(major_version: u32, files: &[FileSpec]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        out.extend(std::iter::repeat_n(0u8, 60));

        let mut placements: Vec<(u64, u64, u64)> = Vec::new();
        for spec in files {
            let stored: &[u8] = spec.compressed.as_deref().unwrap_or(&spec.content);
            let offset: u64 = out.len() as u64;
            out.extend_from_slice(stored);
            let compressed_size: u64 = spec
                .compressed
                .as_ref()
                .map_or(0, |c: &Vec<u8>| c.len() as u64);
            placements.push((offset, spec.content.len() as u64, compressed_size));
        }

        let header_offset: u64 = out.len() as u64;
        out.extend_from_slice(&major_version.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(files.len() as i32).to_le_bytes());
        put_7bit_string(&mut out, "TESTBUNDLEID");
        if major_version >= V2_HEADER_MAJOR_VERSION {
            out.extend_from_slice(&0i64.to_le_bytes());
            out.extend_from_slice(&0i64.to_le_bytes());
            out.extend_from_slice(&0i64.to_le_bytes());
            out.extend_from_slice(&0i64.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        for (spec, &(offset, size, compressed_size)) in files.iter().zip(placements.iter()) {
            out.extend_from_slice(&(offset as i64).to_le_bytes());
            out.extend_from_slice(&(size as i64).to_le_bytes());
            if major_version >= COMPRESSION_MAJOR_VERSION {
                out.extend_from_slice(&(compressed_size as i64).to_le_bytes());
            }
            out.push(spec.file_type as u8);
            put_7bit_string(&mut out, spec.path);
        }

        let marker_at: u64 = out.len() as u64;
        out.extend_from_slice(&header_offset.to_le_bytes());
        out.extend_from_slice(&MARKER_SIGNATURE);
        let _ = marker_at;
        out
    }

    fn sample_files(compressed: bool) -> Vec<FileSpec> {
        let assembly: Vec<u8> = b"MZ\x90\x00this-is-a-managed-assembly-body".to_vec();
        let deps: Vec<u8> = br#"{"runtimeTarget":{"name":".NETCoreApp,Version=v9.0"}}"#.to_vec();
        let runtimeconfig: Vec<u8> = br#"{"runtimeOptions":{"tfm":"net9.0"}}"#.to_vec();
        vec![
            FileSpec {
                path: "app.dll",
                file_type: BundleFileType::Assembly,
                compressed: compressed.then(|| deflate_compress(&assembly)),
                content: assembly,
            },
            FileSpec {
                path: "app.deps.json",
                file_type: BundleFileType::DepsJson,
                compressed: None,
                content: deps,
            },
            FileSpec {
                path: "app.runtimeconfig.json",
                file_type: BundleFileType::RuntimeConfigJson,
                compressed: None,
                content: runtimeconfig,
            },
        ]
    }

    #[test]
    fn detects_and_parses_v6_uncompressed_bundle() {
        let files: Vec<FileSpec> = sample_files(false);
        let bytes: Vec<u8> = build_bundle(6, &files);
        assert!(detect_dotnet_bundle(&bytes).is_some());
        let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
        assert_eq!(bundle.major_version, 6);
        assert_eq!(bundle.files.len(), 3);
        assert_eq!(bundle.bundle_id, "TESTBUNDLEID");
        for (file, spec) in bundle.files.iter().zip(files.iter()) {
            let data: Cow<'_, [u8]> = bundle_file_bytes(&bytes, file, 1 << 30).expect("extract");
            assert_eq!(data.as_ref(), spec.content.as_slice());
        }
    }

    #[test]
    fn extracts_v6_compressed_assembly_byte_identical() {
        let files: Vec<FileSpec> = sample_files(true);
        let bytes: Vec<u8> = build_bundle(6, &files);
        let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse");
        assert!(bundle.files[0].is_compressed());
        let entries: Vec<DotnetBundleEntry> =
            extract_dotnet_bundle(&bytes, ExtractionQuota::default_safe()).expect("extract");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data, files[0].content);
        assert_eq!(entries[1].data, files[1].content);
    }

    #[test]
    fn parses_v1_legacy_bundle_without_v2_header() {
        let files: Vec<FileSpec> = sample_files(false);
        let bytes: Vec<u8> = build_bundle(1, &files);
        let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse v1");
        assert_eq!(bundle.major_version, 1);
        assert!(bundle.deps_json.is_none());
        let data: Cow<'_, [u8]> =
            bundle_file_bytes(&bytes, &bundle.files[0], 1 << 30).expect("extract");
        assert_eq!(data.as_ref(), files[0].content.as_slice());
    }

    #[test]
    fn rejects_non_bundle_binary() {
        let mut bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F'];
        bytes.extend(std::iter::repeat_n(0u8, 4096));
        assert!(detect_dotnet_bundle(&bytes).is_none());
        assert!(parse_dotnet_bundle(&bytes).is_err());
    }

    #[test]
    fn rejects_size_lie_beyond_buffer() {
        let files: Vec<FileSpec> = sample_files(false);
        let mut bytes: Vec<u8> = build_bundle(6, &files);
        let header_offset: usize =
            usize::try_from(detect_dotnet_bundle(&bytes).expect("offset")).expect("fits");
        let entry_size_at: usize = header_offset + 4 + 4 + 4 + 13 + 40 + 8;
        bytes[entry_size_at..entry_size_at + 8].copy_from_slice(&(1u64 << 20).to_le_bytes());
        let bundle: DotnetBundle = parse_dotnet_bundle(&bytes).expect("parse metadata");
        assert!(bundle_file_bytes(&bytes, &bundle.files[0], 1 << 30).is_err());
    }

    #[test]
    fn truncated_bundle_does_not_panic() {
        let full: Vec<u8> = build_bundle(6, &sample_files(true));
        for cut in (0..full.len()).step_by(3) {
            let _ = detect_dotnet_bundle(&full[..cut]);
            let _ = parse_dotnet_bundle(&full[..cut]);
            let _ = extract_dotnet_bundle(&full[..cut], ExtractionQuota::default_safe());
        }
    }
}
