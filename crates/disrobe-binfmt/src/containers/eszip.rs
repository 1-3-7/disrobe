use disrobe_bytes::ByteReader;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::quota::{ABSOLUTE_MAX_ENTRIES, ExtractionQuota, QuotaGuard, sanitize_entry_path};

const MAGIC_V2: &[u8; 8] = b"ESZIP_V2";
const MAGIC_V2_1: &[u8; 8] = b"ESZIP2.1";
const MAGIC_V2_2: &[u8; 8] = b"ESZIP2.2";
const MAGIC_V2_3: &[u8; 8] = b"ESZIP2.3";
const MAGIC_PREFIX: &[u8; 5] = b"ESZIP";

const MAX_CANDIDATE_OFFSETS: usize = 4096;
const SHA256_DIGEST_LEN: usize = 32;
const XXHASH3_DIGEST_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EszipVersion {
    V2,
    V2_1,
    V2_2,
    V2_3,
}

impl EszipVersion {
    fn from_magic(magic: &[u8]) -> Option<Self> {
        match magic {
            m if m == MAGIC_V2 => Some(Self::V2),
            m if m == MAGIC_V2_1 => Some(Self::V2_1),
            m if m == MAGIC_V2_2 => Some(Self::V2_2),
            m if m == MAGIC_V2_3 => Some(Self::V2_3),
            _ => None,
        }
    }

    const fn supports_options(self) -> bool {
        matches!(self, Self::V2_2 | Self::V2_3)
    }

    const fn supports_npm(self) -> bool {
        !matches!(self, Self::V2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EszipChecksum {
    None,
    Sha256,
    XxHash3,
    Unknown(u8),
}

impl EszipChecksum {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Sha256,
            2 => Self::XxHash3,
            other => Self::Unknown(other),
        }
    }

    const fn default_digest_len(self) -> Option<usize> {
        match self {
            Self::None => Some(0),
            Self::Sha256 => Some(SHA256_DIGEST_LEN),
            Self::XxHash3 => Some(XXHASH3_DIGEST_LEN),
            Self::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EszipModuleKind {
    JavaScript,
    Json,
    Jsonc,
    OpaqueData,
    Wasm,
    Unknown(u8),
}

impl EszipModuleKind {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::JavaScript,
            1 => Self::Json,
            2 => Self::Jsonc,
            3 => Self::OpaqueData,
            4 => Self::Wasm,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EszipModuleEntry {
    pub specifier: String,
    pub kind: EszipModuleKind,
    pub source_offset: usize,
    pub source_len: usize,
    pub source_map_offset: usize,
    pub source_map_len: usize,
    pub source_hash_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EszipRedirect {
    pub specifier: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EszipNpmSpecifier {
    pub specifier: String,
    pub package_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EszipArchive {
    pub version: EszipVersion,
    pub checksum: EszipChecksum,
    pub checksum_size: usize,
    pub base_offset: usize,
    pub modules: Vec<EszipModuleEntry>,
    pub redirects: Vec<EszipRedirect>,
    pub npm_specifiers: Vec<EszipNpmSpecifier>,
}

impl EszipArchive {
    #[must_use]
    const fn has_entries(&self) -> bool {
        !self.modules.is_empty() || !self.redirects.is_empty() || !self.npm_specifiers.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EszipExtractedModule {
    pub specifier: String,
    pub path: String,
    pub kind: EszipModuleKind,
    pub source: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct RawModule {
    kind: EszipModuleKind,
    source_offset: u32,
    source_len: u32,
    source_map_offset: u32,
    source_map_len: u32,
}

#[derive(Debug)]
enum RawEntry {
    Module {
        specifier: String,
        raw: RawModule,
    },
    Redirect {
        specifier: String,
        target: String,
    },
    Npm {
        specifier: String,
        package_index: u32,
    },
}

fn map_read_err(context: &'static str) -> impl Fn(disrobe_bytes::ByteReadError) -> Error {
    move |_e: disrobe_bytes::ByteReadError| Error::Eszip(context.to_owned())
}

fn scan_magic_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets: Vec<usize> = Vec::new();
    if bytes.len() < 8 {
        return offsets;
    }
    let last: usize = bytes.len() - 8;
    let mut i: usize = 0;
    while i <= last {
        if bytes[i] == b'E' && &bytes[i..i + 5] == MAGIC_PREFIX {
            let window: &[u8] = &bytes[i..i + 8];
            if EszipVersion::from_magic(window).is_some() {
                offsets.push(i);
                if offsets.len() >= MAX_CANDIDATE_OFFSETS {
                    break;
                }
            }
        }
        i += 1;
    }
    offsets
}

fn candidate_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut candidates: Vec<usize> = Vec::new();
    if let Ok(file) = object::File::parse(bytes) {
        for section in file.sections() {
            let Some((offset, size)): Option<(u64, u64)> = section.file_range() else {
                continue;
            };
            let (Ok(start), Ok(len)): (
                core::result::Result<usize, _>,
                core::result::Result<usize, _>,
            ) = (usize::try_from(offset), usize::try_from(size)) else {
                continue;
            };
            let Some(end): Option<usize> = start.checked_add(len) else {
                continue;
            };
            let Some(region): Option<&[u8]> = bytes.get(start..end.min(bytes.len())) else {
                continue;
            };
            for local in scan_magic_offsets(region) {
                if let Some(abs) = start.checked_add(local) {
                    candidates.push(abs);
                }
            }
        }
    }
    for abs in scan_magic_offsets(bytes) {
        candidates.push(abs);
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates.truncate(MAX_CANDIDATE_OFFSETS);
    candidates
}

pub fn detect_eszip(bytes: &[u8]) -> Option<usize> {
    for base in candidate_offsets(bytes) {
        if let Ok(archive) = parse_eszip_at(bytes, base)
            && archive.has_entries()
        {
            return Some(base);
        }
    }
    None
}

pub fn parse_eszip(bytes: &[u8]) -> Result<EszipArchive> {
    for base in candidate_offsets(bytes) {
        if let Ok(archive) = parse_eszip_at(bytes, base)
            && archive.has_entries()
        {
            return Ok(archive);
        }
    }
    Err(Error::Eszip(
        "no parseable eszip v2 archive found in input".to_owned(),
    ))
}

pub fn parse_eszip_at(bytes: &[u8], base: usize) -> Result<EszipArchive> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(base)
        .map_err(|_e: disrobe_bytes::ByteReadError| {
            Error::Eszip("base offset out of range".to_owned())
        })?;

    let magic: &[u8] = reader
        .read_bytes(8)
        .map_err(map_read_err("magic truncated"))?;
    let version: EszipVersion = EszipVersion::from_magic(magic)
        .ok_or_else(|| Error::Eszip("bad eszip magic".to_owned()))?;

    let (checksum, checksum_size): (EszipChecksum, usize) =
        read_checksum_options(&mut reader, version)?;

    let header_len: usize = read_u32_usize(&mut reader, "modules header length")?;
    let header_body: &[u8] = reader
        .read_bytes(header_len)
        .map_err(map_read_err("modules header truncated"))?;
    reader
        .skip(checksum_size)
        .map_err(map_read_err("modules header checksum truncated"))?;

    let entries: Vec<RawEntry> = parse_header_entries(header_body, version)?;

    if version.supports_npm() {
        skip_section(&mut reader, checksum_size, "npm section")?;
    }

    let sources_body_base: usize = read_section_body_base(&mut reader, "sources section")?;
    let sources_len: usize = section_len_at(&reader, sources_body_base)?;

    let source_maps_body_base: usize = read_section_body_base(&mut reader, "source maps section")?;
    let source_maps_len: usize = section_len_at(&reader, source_maps_body_base)?;

    let mut modules: Vec<EszipModuleEntry> = Vec::new();
    let mut redirects: Vec<EszipRedirect> = Vec::new();
    let mut npm_specifiers: Vec<EszipNpmSpecifier> = Vec::new();

    for entry in entries {
        match entry {
            RawEntry::Module { specifier, raw } => {
                let source: Option<ResolvedRange> = resolve_range(
                    bytes,
                    sources_body_base,
                    sources_len,
                    raw.source_offset,
                    raw.source_len,
                    checksum,
                    checksum_size,
                );
                let source_map: Option<ResolvedRange> = resolve_range(
                    bytes,
                    source_maps_body_base,
                    source_maps_len,
                    raw.source_map_offset,
                    raw.source_map_len,
                    checksum,
                    checksum_size,
                );
                if raw.source_len != 0 {
                    let Some(resolved) = source else {
                        continue;
                    };
                    if resolved.rejected {
                        continue;
                    }
                    let (sm_offset, sm_len): (usize, usize) = match source_map {
                        Some(sm) if !sm.rejected => (sm.offset, sm.len),
                        _ => (0, 0),
                    };
                    modules.push(EszipModuleEntry {
                        specifier,
                        kind: raw.kind,
                        source_offset: resolved.offset,
                        source_len: resolved.len,
                        source_map_offset: sm_offset,
                        source_map_len: sm_len,
                        source_hash_verified: resolved.hash_verified,
                    });
                } else {
                    let (sm_offset, sm_len): (usize, usize) = match source_map {
                        Some(sm) if !sm.rejected => (sm.offset, sm.len),
                        _ => (0, 0),
                    };
                    modules.push(EszipModuleEntry {
                        specifier,
                        kind: raw.kind,
                        source_offset: 0,
                        source_len: 0,
                        source_map_offset: sm_offset,
                        source_map_len: sm_len,
                        source_hash_verified: true,
                    });
                }
            }
            RawEntry::Redirect { specifier, target } => {
                redirects.push(EszipRedirect { specifier, target });
            }
            RawEntry::Npm {
                specifier,
                package_index,
            } => {
                npm_specifiers.push(EszipNpmSpecifier {
                    specifier,
                    package_index,
                });
            }
        }
    }

    Ok(EszipArchive {
        version,
        checksum,
        checksum_size,
        base_offset: base,
        modules,
        redirects,
        npm_specifiers,
    })
}

#[derive(Debug, Clone, Copy)]
struct ResolvedRange {
    offset: usize,
    len: usize,
    hash_verified: bool,
    rejected: bool,
}

#[allow(clippy::too_many_arguments)]
fn resolve_range(
    bytes: &[u8],
    body_base: usize,
    section_len: usize,
    rel_offset: u32,
    rel_len: u32,
    checksum: EszipChecksum,
    checksum_size: usize,
) -> Option<ResolvedRange> {
    if rel_offset == 0 && rel_len == 0 {
        return None;
    }
    let rel_offset: usize = usize::try_from(rel_offset).ok()?;
    let rel_len: usize = usize::try_from(rel_len).ok()?;
    let body_end: usize = rel_offset.checked_add(rel_len)?;
    let with_hash: usize = body_end.checked_add(checksum_size)?;
    if with_hash > section_len {
        return Some(ResolvedRange {
            offset: 0,
            len: 0,
            hash_verified: false,
            rejected: true,
        });
    }
    let abs_offset: usize = body_base.checked_add(rel_offset)?;
    let abs_end: usize = abs_offset.checked_add(rel_len)?;
    let data: &[u8] = bytes.get(abs_offset..abs_end)?;

    let hash_verified: bool = match checksum {
        EszipChecksum::Sha256 => {
            let hash_start: usize = abs_end;
            let hash_end: usize = hash_start.checked_add(SHA256_DIGEST_LEN)?;
            let stored: &[u8] = bytes.get(hash_start..hash_end)?;
            let mut hasher: Sha256 = Sha256::new();
            hasher.update(data);
            let computed: [u8; SHA256_DIGEST_LEN] = hasher.finalize().into();
            if computed.as_slice() != stored {
                return Some(ResolvedRange {
                    offset: 0,
                    len: 0,
                    hash_verified: false,
                    rejected: true,
                });
            }
            true
        }
        _ => false,
    };

    Some(ResolvedRange {
        offset: abs_offset,
        len: rel_len,
        hash_verified,
        rejected: false,
    })
}

fn read_checksum_options(
    reader: &mut ByteReader<'_>,
    version: EszipVersion,
) -> Result<(EszipChecksum, usize)> {
    if !version.supports_options() {
        return Ok((EszipChecksum::Sha256, SHA256_DIGEST_LEN));
    }

    let options_len: usize = read_u32_usize(reader, "options header length")?;
    let options_body: &[u8] = reader
        .read_bytes(options_len)
        .map_err(map_read_err("options header truncated"))?;
    if !options_len.is_multiple_of(2) {
        return Err(Error::Eszip(
            "eszip options header is not a sequence of byte pairs".to_owned(),
        ));
    }

    let mut checksum: EszipChecksum = EszipChecksum::None;
    let mut explicit_size: Option<usize> = None;
    for pair in options_body.chunks_exact(2) {
        match pair[0] {
            0 => checksum = EszipChecksum::from_u8(pair[1]),
            1 => explicit_size = Some(usize::from(pair[1])),
            _ => {}
        }
    }

    let checksum_size: usize = match explicit_size {
        Some(size) => size,
        None => checksum
            .default_digest_len()
            .ok_or_else(|| Error::Eszip("eszip checksum size is unknown".to_owned()))?,
    };

    reader
        .skip(checksum_size)
        .map_err(map_read_err("options header checksum truncated"))?;

    Ok((checksum, checksum_size))
}

fn parse_header_entries(header_body: &[u8], version: EszipVersion) -> Result<Vec<RawEntry>> {
    let mut reader: ByteReader<'_> = ByteReader::new(header_body);
    let mut entries: Vec<RawEntry> = Vec::new();

    while !reader.is_empty() {
        if entries.len() >= ABSOLUTE_MAX_ENTRIES {
            return Err(Error::Eszip(
                "eszip module count exceeds sanity bound".to_owned(),
            ));
        }
        let Ok(specifier_len): core::result::Result<usize, _> = read_u32_usize_body(&mut reader)
        else {
            break;
        };
        let Ok(specifier_bytes): core::result::Result<&[u8], _> = reader.read_bytes(specifier_len)
        else {
            break;
        };
        let specifier: String = String::from_utf8_lossy(specifier_bytes).into_owned();

        let Ok(kind): core::result::Result<u8, _> = reader.read_u8() else {
            break;
        };
        match kind {
            0 => {
                let Ok(source_offset): core::result::Result<u32, _> = reader.read_u32_be() else {
                    break;
                };
                let Ok(source_len): core::result::Result<u32, _> = reader.read_u32_be() else {
                    break;
                };
                let Ok(source_map_offset): core::result::Result<u32, _> = reader.read_u32_be()
                else {
                    break;
                };
                let Ok(source_map_len): core::result::Result<u32, _> = reader.read_u32_be() else {
                    break;
                };
                let Ok(module_kind): core::result::Result<u8, _> = reader.read_u8() else {
                    break;
                };
                entries.push(RawEntry::Module {
                    specifier,
                    raw: RawModule {
                        kind: EszipModuleKind::from_u8(module_kind),
                        source_offset,
                        source_len,
                        source_map_offset,
                        source_map_len,
                    },
                });
            }
            1 => {
                let Ok(target_len): core::result::Result<usize, _> =
                    read_u32_usize_body(&mut reader)
                else {
                    break;
                };
                let Ok(target_bytes): core::result::Result<&[u8], _> =
                    reader.read_bytes(target_len)
                else {
                    break;
                };
                entries.push(RawEntry::Redirect {
                    specifier,
                    target: String::from_utf8_lossy(target_bytes).into_owned(),
                });
            }
            2 if version.supports_npm() => {
                let Ok(package_index): core::result::Result<u32, _> = reader.read_u32_be() else {
                    break;
                };
                entries.push(RawEntry::Npm {
                    specifier,
                    package_index,
                });
            }
            _ => break,
        }
    }

    Ok(entries)
}

fn skip_section(
    reader: &mut ByteReader<'_>,
    checksum_size: usize,
    context: &'static str,
) -> Result<()> {
    let len: usize = read_u32_usize(reader, context)?;
    reader.skip(len).map_err(map_read_err(context))?;
    reader.skip(checksum_size).map_err(map_read_err(context))?;
    Ok(())
}

fn read_section_body_base(reader: &mut ByteReader<'_>, context: &'static str) -> Result<usize> {
    let len: usize = read_u32_usize(reader, context)?;
    let body_base: usize = reader.position();
    reader.skip(len).map_err(map_read_err(context))?;
    Ok(body_base)
}

fn section_len_at(reader: &ByteReader<'_>, body_base: usize) -> Result<usize> {
    reader
        .position()
        .checked_sub(body_base)
        .ok_or_else(|| Error::Eszip("section length underflow".to_owned()))
}

fn read_u32_usize(reader: &mut ByteReader<'_>, context: &'static str) -> Result<usize> {
    let value: u32 = reader.read_u32_be().map_err(map_read_err(context))?;
    usize::try_from(value)
        .map_err(|_e: core::num::TryFromIntError| Error::Eszip(context.to_owned()))
}

fn read_u32_usize_body(
    reader: &mut ByteReader<'_>,
) -> core::result::Result<usize, disrobe_bytes::ByteReadError> {
    let value: u32 = reader.read_u32_be()?;
    Ok(value as usize)
}

pub fn module_source<'a>(bytes: &'a [u8], module: &EszipModuleEntry) -> Option<&'a [u8]> {
    if module.source_len == 0 {
        return Some(&[]);
    }
    let end: usize = module.source_offset.checked_add(module.source_len)?;
    bytes.get(module.source_offset..end)
}

pub fn module_source_map<'a>(bytes: &'a [u8], module: &EszipModuleEntry) -> Option<&'a [u8]> {
    if module.source_map_len == 0 {
        return Some(&[]);
    }
    let end: usize = module
        .source_map_offset
        .checked_add(module.source_map_len)?;
    bytes.get(module.source_map_offset..end)
}

pub fn sanitize_eszip_specifier(specifier: &str) -> Option<String> {
    let without_scheme: &str = match specifier.split_once("://") {
        Some((_scheme, rest)) => match rest.split_once('/') {
            Some((_authority, path)) => path,
            None => rest,
        },
        None => match specifier.split_once(':') {
            Some((scheme, rest))
                if !scheme.is_empty()
                    && scheme.chars().all(|c: char| c.is_ascii_alphanumeric())
                    && !rest.is_empty() =>
            {
                rest
            }
            _ => specifier,
        },
    };
    let trimmed: &str = without_scheme.trim_start_matches(['/', '\\']);
    let drive_stripped: &str = strip_drive_prefix(trimmed);
    sanitize_entry_path(drive_stripped).ok()
}

fn strip_drive_prefix(path: &str) -> &str {
    let bytes: &[u8] = path.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
    {
        return path[3..].trim_start_matches(['/', '\\']);
    }
    path
}

pub fn extract_eszip(bytes: &[u8], quota: &ExtractionQuota) -> Result<Vec<EszipExtractedModule>> {
    let archive: EszipArchive = parse_eszip(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(*quota);
    let mut out: Vec<EszipExtractedModule> = Vec::new();

    for (index, module) in archive.modules.iter().enumerate() {
        let Some(source): Option<&[u8]> = module_source(bytes, module) else {
            continue;
        };
        if module.source_len == 0 {
            continue;
        }
        let source_len: u64 = source.len() as u64;
        guard.admit_entry(&module.specifier, source_len, source_len)?;
        let path: String = sanitize_eszip_specifier(&module.specifier)
            .unwrap_or_else(|| format!("module_{index}"));
        out.push(EszipExtractedModule {
            specifier: module.specifier.clone(),
            path,
            kind: module.kind,
            source: source.to_vec(),
        });
    }

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct SourceItem {
        specifier: &'static str,
        kind: u8,
        source: &'static [u8],
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn build_eszip(
        magic: [u8; 8],
        checksum: EszipChecksum,
        items: &[SourceItem],
        redirects: &[(&str, &str)],
    ) -> Vec<u8> {
        let checksum_size: usize = match checksum {
            EszipChecksum::None | EszipChecksum::Unknown(_) => 0,
            EszipChecksum::Sha256 => 32,
            EszipChecksum::XxHash3 => 8,
        };
        let hash = |data: &[u8]| -> Vec<u8> {
            match checksum {
                EszipChecksum::Sha256 => sha256(data).to_vec(),
                _ => Vec::new(),
            }
        };

        let mut sources: Vec<u8> = Vec::new();
        let mut source_offsets: Vec<(u32, u32)> = Vec::new();
        for item in items {
            if item.source.is_empty() {
                source_offsets.push((0, 0));
                continue;
            }
            let offset: u32 = sources.len() as u32;
            sources.extend_from_slice(item.source);
            sources.extend_from_slice(&hash(item.source));
            source_offsets.push((offset, item.source.len() as u32));
        }

        let mut header: Vec<u8> = Vec::new();
        for (item, (offset, len)) in items.iter().zip(source_offsets.iter()) {
            header.extend_from_slice(&(item.specifier.len() as u32).to_be_bytes());
            header.extend_from_slice(item.specifier.as_bytes());
            header.push(0);
            header.extend_from_slice(&offset.to_be_bytes());
            header.extend_from_slice(&len.to_be_bytes());
            header.extend_from_slice(&0u32.to_be_bytes());
            header.extend_from_slice(&0u32.to_be_bytes());
            header.push(item.kind);
        }
        for (specifier, target) in redirects {
            header.extend_from_slice(&(specifier.len() as u32).to_be_bytes());
            header.extend_from_slice(specifier.as_bytes());
            header.push(1);
            header.extend_from_slice(&(target.len() as u32).to_be_bytes());
            header.extend_from_slice(target.as_bytes());
        }

        let version: EszipVersion = EszipVersion::from_magic(&magic).unwrap();

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&magic);

        if version.supports_options() {
            let checksum_byte: u8 = match checksum {
                EszipChecksum::None => 0,
                EszipChecksum::Sha256 => 1,
                EszipChecksum::XxHash3 => 2,
                EszipChecksum::Unknown(v) => v,
            };
            let options_body: [u8; 4] = [0, checksum_byte, 1, checksum_size as u8];
            out.extend_from_slice(&(options_body.len() as u32).to_be_bytes());
            out.extend_from_slice(&options_body);
            out.extend_from_slice(&hash(&options_body));
        }

        out.extend_from_slice(&(header.len() as u32).to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&hash(&header));

        if version.supports_npm() {
            let npm_body: [u8; 0] = [];
            out.extend_from_slice(&(npm_body.len() as u32).to_be_bytes());
            out.extend_from_slice(&npm_body);
            out.extend_from_slice(&hash(&npm_body));
        }

        out.extend_from_slice(&(sources.len() as u32).to_be_bytes());
        out.extend_from_slice(&sources);

        let source_maps: [u8; 0] = [];
        out.extend_from_slice(&(source_maps.len() as u32).to_be_bytes());
        out.extend_from_slice(&source_maps);

        out
    }

    fn sample_items() -> Vec<SourceItem> {
        vec![
            SourceItem {
                specifier: "file:///main.ts",
                kind: 0,
                source: b"import { x } from './util.ts';\nconsole.log(x);\n",
            },
            SourceItem {
                specifier: "file:///util.ts",
                kind: 0,
                source: b"export const x = 42;\n",
            },
            SourceItem {
                specifier: "file:///config.json",
                kind: 1,
                source: b"{\"name\":\"demo\"}",
            },
        ]
    }

    #[test]
    fn parses_v23_no_checksum() {
        let items: Vec<SourceItem> = sample_items();
        let bytes: Vec<u8> = build_eszip(*MAGIC_V2_3, EszipChecksum::None, &items, &[]);
        let archive: EszipArchive = parse_eszip(&bytes).expect("parse");
        assert_eq!(archive.version, EszipVersion::V2_3);
        assert_eq!(archive.checksum, EszipChecksum::None);
        assert_eq!(archive.modules.len(), 3);
        let extracted: Vec<EszipExtractedModule> =
            extract_eszip(&bytes, &ExtractionQuota::default_safe()).expect("extract");
        assert_eq!(extracted.len(), 3);
        assert_eq!(extracted[0].specifier, "file:///main.ts");
        assert_eq!(extracted[0].path, "main.ts");
        assert_eq!(
            extracted[0].source,
            b"import { x } from './util.ts';\nconsole.log(x);\n"
        );
        assert_eq!(extracted[2].source, b"{\"name\":\"demo\"}");
        assert_eq!(extracted[2].kind, EszipModuleKind::Json);
    }

    #[test]
    fn parses_v21_sha256_and_verifies_hash() {
        let items: Vec<SourceItem> = sample_items();
        let bytes: Vec<u8> = build_eszip(*MAGIC_V2_1, EszipChecksum::Sha256, &items, &[]);
        let archive: EszipArchive = parse_eszip(&bytes).expect("parse");
        assert_eq!(archive.version, EszipVersion::V2_1);
        assert_eq!(archive.checksum, EszipChecksum::Sha256);
        assert_eq!(archive.checksum_size, 32);
        assert_eq!(archive.modules.len(), 3);
        assert!(archive.modules.iter().all(|m| m.source_hash_verified));
        let body: &[u8] = module_source(&bytes, &archive.modules[1]).expect("source");
        assert_eq!(body, b"export const x = 42;\n");
    }

    #[test]
    fn parses_v2_sha256() {
        let items: Vec<SourceItem> = sample_items();
        let bytes: Vec<u8> = build_eszip(*MAGIC_V2, EszipChecksum::Sha256, &items, &[]);
        let archive: EszipArchive = parse_eszip(&bytes).expect("parse");
        assert_eq!(archive.version, EszipVersion::V2);
        assert_eq!(archive.modules.len(), 3);
    }

    #[test]
    fn parses_redirects() {
        let items: Vec<SourceItem> = sample_items();
        let bytes: Vec<u8> = build_eszip(
            *MAGIC_V2_3,
            EszipChecksum::None,
            &items,
            &[("file:///a.ts", "file:///main.ts")],
        );
        let archive: EszipArchive = parse_eszip(&bytes).expect("parse");
        assert_eq!(archive.redirects.len(), 1);
        assert_eq!(archive.redirects[0].specifier, "file:///a.ts");
        assert_eq!(archive.redirects[0].target, "file:///main.ts");
    }

    #[test]
    fn rejects_module_with_corrupt_source_hash() {
        let items: Vec<SourceItem> = sample_items();
        let mut bytes: Vec<u8> = build_eszip(*MAGIC_V2_1, EszipChecksum::Sha256, &items, &[]);
        let magic_pos: usize = bytes
            .windows(8)
            .position(|w: &[u8]| w == MAGIC_V2_1)
            .expect("magic");
        let sources_marker: &[u8] = b"export const x = 42;\n";
        let src_pos: usize = bytes
            .windows(sources_marker.len())
            .position(|w: &[u8]| w == sources_marker)
            .expect("source bytes present");
        assert!(src_pos > magic_pos);
        bytes[src_pos] ^= 0xff;
        let archive: EszipArchive = parse_eszip(&bytes).expect("parse still succeeds");
        assert!(
            archive
                .modules
                .iter()
                .all(|m| m.specifier != "file:///util.ts"),
            "corrupt-hash module must be dropped"
        );
        assert_eq!(archive.modules.len(), 2);
    }

    #[test]
    fn detects_eszip_embedded_in_host_binary() {
        let items: Vec<SourceItem> = sample_items();
        let eszip: Vec<u8> = build_eszip(*MAGIC_V2_3, EszipChecksum::None, &items, &[]);
        let mut host: Vec<u8> = Vec::new();
        host.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        host.extend(std::iter::repeat_n(0u8, 4096));
        let base: usize = host.len();
        host.extend_from_slice(&eszip);
        host.extend(std::iter::repeat_n(0u8, 128));
        assert_eq!(detect_eszip(&host), Some(base));
        let archive: EszipArchive = parse_eszip(&host).expect("parse embedded");
        assert_eq!(archive.base_offset, base);
        assert_eq!(archive.modules.len(), 3);
    }

    #[test]
    fn rejects_non_eszip_binary() {
        let mut bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F'];
        bytes.extend(std::iter::repeat_n(0u8, 2048));
        assert!(detect_eszip(&bytes).is_none());
        assert!(parse_eszip(&bytes).is_err());
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let items: Vec<SourceItem> = sample_items();
        for magic in [*MAGIC_V2, *MAGIC_V2_1, *MAGIC_V2_2, *MAGIC_V2_3] {
            let checksum: EszipChecksum = if magic == *MAGIC_V2 || magic == *MAGIC_V2_1 {
                EszipChecksum::Sha256
            } else {
                EszipChecksum::None
            };
            let full: Vec<u8> = build_eszip(magic, checksum, &items, &[]);
            for cut in 0..full.len() {
                let _ = parse_eszip(&full[..cut]);
                let _ = detect_eszip(&full[..cut]);
            }
        }
    }

    #[test]
    fn sanitize_specifier_strips_scheme_and_authority() {
        assert_eq!(
            sanitize_eszip_specifier("file:///home/user/main.ts").as_deref(),
            Some("home/user/main.ts")
        );
        assert_eq!(
            sanitize_eszip_specifier("https://deno.land/x/mod/a.ts").as_deref(),
            Some("x/mod/a.ts")
        );
        assert_eq!(
            sanitize_eszip_specifier("npm:chalk@5.0.0").as_deref(),
            Some("chalk@5.0.0")
        );
        assert_eq!(
            sanitize_eszip_specifier("file:///C:/Users/x/app.ts").as_deref(),
            Some("Users/x/app.ts")
        );
        assert!(sanitize_eszip_specifier("file:///../../etc/passwd").is_none());
    }
}
