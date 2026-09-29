use std::collections::{BTreeMap, BTreeSet};

use disrobe_bytes::{ByteReadError, ByteReader};
use serde::{Deserialize, Serialize};

use crate::containers::eszip::{EszipArchive, EszipModuleEntry, parse_eszip_at};
use crate::error::{Error, Result};
use crate::quota::{
    ABSOLUTE_MAX_ENTRIES, ExtractionQuota, MAX_ENTRY_PATH_BYTES, QuotaGuard, sanitize_entry_path,
};

pub const DENO_COMPILE_MAGIC: &[u8; 8] = b"d3n0l4nd";

const ESZIP_TRAILER_HEADER_LEN: usize = 40;
const MAX_MAGIC_CANDIDATES: usize = 4096;
const MAX_MEDIA_TYPE: u8 = 20;
const SPECIFIER_RECORD_MIN_BYTES: usize = 8;
const REDIRECT_RECORD_BYTES: usize = 8;
const REMOTE_MODULE_RECORD_MIN_BYTES: usize = 10;
const HAS_TRANSPILED_FLAG: u8 = 1 << 0;
const HAS_SOURCE_MAP_FLAG: u8 = 1 << 1;
const HAS_CJS_EXPORT_ANALYSIS_FLAG: u8 = 1 << 2;
const EMPTY_NPM_VFS: &[u8] = b"null";
const ESZIP_PREFIX: &[u8; 5] = b"ESZIP";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenoCompileLayout {
    EszipTrailer,
    ModuleStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenoModuleOrigin {
    EmbeddedFile,
    RemoteModule,
    EszipModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub offset: usize,
    pub len: usize,
}

impl ByteSpan {
    #[must_use]
    pub fn slice(self, bytes: &[u8]) -> Option<&[u8]> {
        let end: usize = self.offset.checked_add(self.len)?;
        bytes.get(self.offset..end)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenoCompileModule {
    pub specifier: String,
    pub path: String,
    pub origin: DenoModuleOrigin,
    pub source: ByteSpan,
    pub transpiled: Option<ByteSpan>,
    pub source_map: Option<ByteSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenoCompileSymlink {
    pub path: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenoCompileRedirect {
    pub specifier: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenoCompilePayload {
    pub layout: DenoCompileLayout,
    pub base_offset: usize,
    pub len: usize,
    pub entrypoint: String,
    pub modules: Vec<DenoCompileModule>,
    pub symlinks: Vec<DenoCompileSymlink>,
    pub redirects: Vec<DenoCompileRedirect>,
    pub unread_npm_files: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenoExtractedRole {
    Source,
    SourceMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenoCompileExtractedFile {
    pub path: String,
    pub specifier: String,
    pub role: DenoExtractedRole,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct MetadataHeader {
    entrypoint_key: String,
}

#[derive(Debug, Deserialize)]
enum VfsEntry {
    Dir(VfsDir),
    File(VfsFile),
    Symlink(VfsSymlink),
}

#[derive(Debug, Deserialize)]
struct VfsDir {
    #[serde(rename = "n")]
    name: String,
    #[serde(rename = "e")]
    entries: Vec<VfsEntry>,
}

#[derive(Debug, Deserialize)]
struct VfsFile {
    #[serde(rename = "n")]
    name: String,
    #[serde(rename = "o")]
    offset: [u64; 2],
    #[serde(rename = "m", default)]
    transpiled: Option<[u64; 2]>,
    #[serde(rename = "s", default)]
    source_map: Option<[u64; 2]>,
}

#[derive(Debug, Deserialize)]
struct VfsSymlink {
    #[serde(rename = "n")]
    name: String,
    #[serde(rename = "p")]
    parts: Vec<String>,
}

#[derive(Debug)]
struct RemoteModuleRecord {
    specifier: String,
    source: ByteSpan,
    transpiled: Option<ByteSpan>,
    source_map: Option<ByteSpan>,
}

fn malformed(context: &str) -> Error {
    Error::Eszip(format!("deno compile payload: {context}"))
}

fn read_err(context: &'static str) -> impl Fn(ByteReadError) -> Error {
    move |_error: ByteReadError| malformed(context)
}

fn magic_offsets(bytes: &[u8]) -> Vec<usize> {
    memchr::memmem::find_iter(bytes, DENO_COMPILE_MAGIC)
        .take(MAX_MAGIC_CANDIDATES)
        .collect()
}

#[must_use]
pub fn detect_deno_compile(bytes: &[u8]) -> Option<usize> {
    parse_deno_compile(bytes)
        .ok()
        .map(|payload: DenoCompilePayload| payload.base_offset)
}

pub fn parse_deno_compile(bytes: &[u8]) -> Result<DenoCompilePayload> {
    for base in magic_offsets(bytes).into_iter().rev() {
        if let Ok(payload) = parse_deno_compile_at(bytes, base)
            && !payload.modules.is_empty()
        {
            return Ok(payload);
        }
    }
    Err(malformed("no d3n0l4nd payload with embedded modules found"))
}

pub fn parse_deno_compile_at(bytes: &[u8], base: usize) -> Result<DenoCompilePayload> {
    if has_eszip_trailer_shape(bytes, base) {
        parse_eszip_trailer_at(bytes, base)
    } else {
        parse_module_store_at(bytes, base)
    }
}

fn has_eszip_trailer_shape(bytes: &[u8], base: usize) -> bool {
    let eszip_pos: Option<&[u8]> = base
        .checked_add(8)
        .and_then(|start: usize| bytes.get(start..start.checked_add(8)?));
    let body: Option<&[u8]> = base
        .checked_add(ESZIP_TRAILER_HEADER_LEN)
        .and_then(|start: usize| bytes.get(start..start.checked_add(ESZIP_PREFIX.len())?));
    eszip_pos == Some(&[0u8; 8][..]) && body == Some(&ESZIP_PREFIX[..])
}

fn expect_magic(reader: &mut ByteReader<'_>, context: &'static str) -> Result<()> {
    let magic: &[u8] = reader.read_bytes(8).map_err(read_err(context))?;
    if magic != DENO_COMPILE_MAGIC {
        return Err(malformed(context));
    }
    Ok(())
}

fn u64_to_usize(value: u64, context: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_error: core::num::TryFromIntError| malformed(context))
}

fn read_u64_block<'a>(reader: &mut ByteReader<'a>, context: &'static str) -> Result<&'a [u8]> {
    let len: usize = u64_to_usize(reader.read_u64_le().map_err(read_err(context))?, context)?;
    reader.read_bytes(len).map_err(read_err(context))
}

fn read_u32_block<'a>(reader: &mut ByteReader<'a>, context: &'static str) -> Result<&'a [u8]> {
    let len: u32 = reader.read_u32_le().map_err(read_err(context))?;
    let len: usize =
        usize::try_from(len).map_err(|_error: core::num::TryFromIntError| malformed(context))?;
    reader.read_bytes(len).map_err(read_err(context))
}

fn read_record_count(
    reader: &mut ByteReader<'_>,
    min_record_bytes: usize,
    context: &'static str,
) -> Result<usize> {
    let count: u32 = reader.read_u32_le().map_err(read_err(context))?;
    let count: usize =
        usize::try_from(count).map_err(|_error: core::num::TryFromIntError| malformed(context))?;
    let fits: bool = count
        .checked_mul(min_record_bytes)
        .is_some_and(|needed: usize| needed <= reader.remaining());
    if !fits || count > ABSOLUTE_MAX_ENTRIES {
        return Err(malformed(context));
    }
    Ok(count)
}

fn read_u32_span(reader: &mut ByteReader<'_>, context: &'static str) -> Result<ByteSpan> {
    let len: usize = read_u32_block(reader, context)?.len();
    Ok(ByteSpan {
        offset: reader.position() - len,
        len,
    })
}

fn read_specifiers(reader: &mut ByteReader<'_>) -> Result<BTreeMap<u32, String>> {
    let count: usize = read_record_count(reader, SPECIFIER_RECORD_MIN_BYTES, "specifier count")?;
    let mut specifiers: BTreeMap<u32, String> = BTreeMap::new();
    for _ in 0..count {
        let text: &[u8] = read_u32_block(reader, "specifier text")?;
        let id: u32 = reader.read_u32_le().map_err(read_err("specifier id"))?;
        let specifier: String = String::from_utf8(text.to_vec())
            .map_err(|_error: std::string::FromUtf8Error| malformed("specifier is not UTF-8"))?;
        if specifiers.insert(id, specifier).is_some() {
            return Err(malformed("duplicate specifier id"));
        }
    }
    Ok(specifiers)
}

fn specifier_for(specifiers: &BTreeMap<u32, String>, id: u32) -> Result<String> {
    specifiers
        .get(&id)
        .cloned()
        .ok_or_else(|| malformed("record names an unknown specifier id"))
}

fn read_redirects(
    reader: &mut ByteReader<'_>,
    specifiers: &BTreeMap<u32, String>,
) -> Result<Vec<DenoCompileRedirect>> {
    let count: usize = read_record_count(reader, REDIRECT_RECORD_BYTES, "redirect count")?;
    let mut redirects: Vec<DenoCompileRedirect> = Vec::new();
    for _ in 0..count {
        let from: u32 = reader.read_u32_le().map_err(read_err("redirect source"))?;
        let to: u32 = reader.read_u32_le().map_err(read_err("redirect target"))?;
        redirects.push(DenoCompileRedirect {
            specifier: specifier_for(specifiers, from)?,
            target: specifier_for(specifiers, to)?,
        });
    }
    Ok(redirects)
}

fn read_optional_span(
    reader: &mut ByteReader<'_>,
    flags: u8,
    flag: u8,
    context: &'static str,
) -> Result<Option<ByteSpan>> {
    if flags & flag == 0 {
        return Ok(None);
    }
    read_u32_span(reader, context).map(Some)
}

fn read_remote_modules(
    reader: &mut ByteReader<'_>,
    specifiers: &BTreeMap<u32, String>,
) -> Result<Vec<RemoteModuleRecord>> {
    let count: usize = read_record_count(
        reader,
        REMOTE_MODULE_RECORD_MIN_BYTES,
        "remote module count",
    )?;
    let mut modules: Vec<RemoteModuleRecord> = Vec::new();
    for _ in 0..count {
        let id: u32 = reader.read_u32_le().map_err(read_err("remote module id"))?;
        let media_type: u8 = reader
            .read_u8()
            .map_err(read_err("remote module media type"))?;
        if media_type > MAX_MEDIA_TYPE {
            return Err(malformed("remote module media type is unknown"));
        }
        let source: ByteSpan = read_u32_span(reader, "remote module source")?;
        let flags: u8 = reader.read_u8().map_err(read_err("remote module flags"))?;
        let transpiled: Option<ByteSpan> = read_optional_span(
            reader,
            flags,
            HAS_TRANSPILED_FLAG,
            "remote module transpiled source",
        )?;
        let source_map: Option<ByteSpan> = read_optional_span(
            reader,
            flags,
            HAS_SOURCE_MAP_FLAG,
            "remote module source map",
        )?;
        read_optional_span(
            reader,
            flags,
            HAS_CJS_EXPORT_ANALYSIS_FLAG,
            "remote module export analysis",
        )?;
        modules.push(RemoteModuleRecord {
            specifier: specifier_for(specifiers, id)?,
            source,
            transpiled,
            source_map,
        });
    }
    Ok(modules)
}

fn parse_module_store_at(bytes: &[u8], base: usize) -> Result<DenoCompilePayload> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(base)
        .map_err(read_err("payload offset out of range"))?;
    expect_magic(&mut reader, "opening magic")?;
    let metadata: &[u8] = read_u64_block(&mut reader, "metadata")?;
    read_u64_block(&mut reader, "npm snapshot")?;
    let specifiers: BTreeMap<u32, String> = read_specifiers(&mut reader)?;
    let redirects: Vec<DenoCompileRedirect> = read_redirects(&mut reader, &specifiers)?;
    let remote: Vec<RemoteModuleRecord> = read_remote_modules(&mut reader, &specifiers)?;
    let vfs_json: &[u8] = read_u64_block(&mut reader, "virtual file system directory")?;
    let files_len: usize = read_u64_block(&mut reader, "virtual file system data")?.len();
    let files_base: usize = reader.position() - files_len;
    expect_magic(&mut reader, "closing magic")?;
    let end: usize = reader.position();

    let header: MetadataHeader = serde_json::from_slice(metadata)
        .map_err(|error: serde_json::Error| malformed(&format!("metadata json: {error}")))?;
    let entries: Vec<VfsEntry> =
        serde_json::from_slice(vfs_json).map_err(|error: serde_json::Error| {
            malformed(&format!("virtual file system json: {error}"))
        })?;

    let mut walk: VfsWalk = VfsWalk {
        files_base,
        files_len,
        used_paths: UniquePaths::default(),
        modules: Vec::new(),
        symlinks: Vec::new(),
    };
    walk.visit(&entries, "")?;

    for record in remote {
        let candidate: Option<String> = remote_module_path(&record.specifier);
        let index: usize = walk.modules.len();
        let path: String = walk
            .used_paths
            .claim(candidate.unwrap_or_else(|| format!("remote/module_{index}")));
        walk.modules.push(DenoCompileModule {
            specifier: record.specifier,
            path,
            origin: DenoModuleOrigin::RemoteModule,
            source: record.source,
            transpiled: record.transpiled,
            source_map: record.source_map,
        });
    }

    Ok(DenoCompilePayload {
        layout: DenoCompileLayout::ModuleStore,
        base_offset: base,
        len: end - base,
        entrypoint: header.entrypoint_key,
        modules: walk.modules,
        symlinks: walk.symlinks,
        redirects,
        unread_npm_files: false,
    })
}

struct VfsWalk {
    files_base: usize,
    files_len: usize,
    used_paths: UniquePaths,
    modules: Vec<DenoCompileModule>,
    symlinks: Vec<DenoCompileSymlink>,
}

impl VfsWalk {
    fn visit(&mut self, entries: &[VfsEntry], prefix: &str) -> Result<()> {
        for entry in entries {
            if self.modules.len() + self.symlinks.len() >= ABSOLUTE_MAX_ENTRIES {
                return Err(malformed(
                    "virtual file system entry count exceeds sanity bound",
                ));
            }
            match entry {
                VfsEntry::Dir(dir) => {
                    let joined: String = join_vfs_path(prefix, &dir.name)?;
                    self.visit(&dir.entries, &joined)?;
                }
                VfsEntry::File(file) => self.push_file(prefix, file)?,
                VfsEntry::Symlink(link) => {
                    let joined: String = join_vfs_path(prefix, &link.name)?;
                    self.symlinks.push(DenoCompileSymlink {
                        path: joined,
                        target: link.parts.join("/"),
                    });
                }
            }
        }
        Ok(())
    }

    fn resolve(&self, pair: [u64; 2], context: &'static str) -> Result<ByteSpan> {
        let offset: usize = u64_to_usize(pair[0], context)?;
        let len: usize = u64_to_usize(pair[1], context)?;
        let end: usize = offset.checked_add(len).ok_or_else(|| malformed(context))?;
        if end > self.files_len {
            return Err(malformed(context));
        }
        let absolute: usize = self
            .files_base
            .checked_add(offset)
            .ok_or_else(|| malformed(context))?;
        Ok(ByteSpan {
            offset: absolute,
            len,
        })
    }

    fn push_file(&mut self, prefix: &str, file: &VfsFile) -> Result<()> {
        let specifier: String = join_vfs_path(prefix, &file.name)?;
        let source: ByteSpan = self.resolve(file.offset, "file range")?;
        let transpiled: Option<ByteSpan> = file
            .transpiled
            .map(|pair: [u64; 2]| self.resolve(pair, "transpiled range"))
            .transpose()?;
        let source_map: Option<ByteSpan> = file
            .source_map
            .map(|pair: [u64; 2]| self.resolve(pair, "source map range"))
            .transpose()?;
        let index: usize = self.modules.len();
        let candidate: String =
            sanitize_vfs_path(&specifier).unwrap_or_else(|| format!("vfs/file_{index}"));
        let path: String = self.used_paths.claim(candidate);
        self.modules.push(DenoCompileModule {
            specifier,
            path,
            origin: DenoModuleOrigin::EmbeddedFile,
            source,
            transpiled,
            source_map,
        });
        Ok(())
    }
}

fn join_vfs_path(prefix: &str, name: &str) -> Result<String> {
    let joined: String = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    if joined.len() > MAX_ENTRY_PATH_BYTES {
        return Err(malformed(
            "virtual file system path exceeds the length bound",
        ));
    }
    Ok(joined)
}

fn sanitize_vfs_path(path: &str) -> Option<String> {
    let bytes: &[u8] = path.as_bytes();
    let without_drive: String = if bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || bytes[2] == b'/')
    {
        format!("{}{}", char::from(bytes[0]), &path[2..])
    } else {
        path.to_owned()
    };
    sanitize_entry_path(&without_drive).ok()
}

fn remote_module_path(specifier: &str) -> Option<String> {
    let without_scheme: &str = specifier
        .split_once("://")
        .map_or(specifier, |(_scheme, rest): (&str, &str)| rest);
    let without_query: &str = without_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(without_scheme);
    sanitize_entry_path(&without_query.replace(':', "_")).ok()
}

#[derive(Debug, Default)]
pub(crate) struct UniquePaths {
    used: BTreeSet<String>,
    next_suffix: BTreeMap<String, usize>,
}

impl UniquePaths {
    pub(crate) fn reserve(&mut self, path: String) {
        self.used.insert(path);
    }

    pub(crate) fn claim(&mut self, candidate: String) -> String {
        if self.used.insert(candidate.clone()) {
            return candidate;
        }
        let mut suffix: usize = self.next_suffix.get(&candidate).copied().unwrap_or(1);
        loop {
            let renamed: String = format!("{candidate}~{suffix}");
            suffix += 1;
            if self.used.insert(renamed.clone()) {
                self.next_suffix.insert(candidate, suffix);
                return renamed;
            }
        }
    }
}

fn parse_eszip_trailer_at(bytes: &[u8], base: usize) -> Result<DenoCompilePayload> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(base)
        .map_err(read_err("payload offset out of range"))?;
    expect_magic(&mut reader, "trailer magic")?;
    let eszip_pos: u64 = reader
        .read_u64_be()
        .map_err(read_err("trailer eszip position"))?;
    let metadata_pos: usize = u64_to_usize(
        reader
            .read_u64_be()
            .map_err(read_err("trailer metadata position"))?,
        "trailer metadata position",
    )?;
    let npm_vfs_pos: usize = u64_to_usize(
        reader
            .read_u64_be()
            .map_err(read_err("trailer npm directory position"))?,
        "trailer npm directory position",
    )?;
    let npm_files_pos: usize = u64_to_usize(
        reader
            .read_u64_be()
            .map_err(read_err("trailer npm data position"))?,
        "trailer npm data position",
    )?;
    if eszip_pos != 0 || metadata_pos > npm_vfs_pos || npm_vfs_pos > npm_files_pos {
        return Err(malformed("trailer positions are out of order"));
    }
    let body: usize = base
        .checked_add(ESZIP_TRAILER_HEADER_LEN)
        .ok_or_else(|| malformed("trailer body offset overflows"))?;
    let body_end: usize = body
        .checked_add(npm_files_pos)
        .filter(|end: &usize| *end <= bytes.len())
        .ok_or_else(|| malformed("trailer positions run past the input"))?;
    let eszip_region: &[u8] = &bytes[body..body + metadata_pos];
    let metadata: &[u8] = &bytes[body + metadata_pos..body + npm_vfs_pos];
    let npm_vfs: &[u8] = &bytes[body + npm_vfs_pos..body_end];

    let archive: EszipArchive = parse_eszip_at(eszip_region, 0)?;
    let header: MetadataHeader = serde_json::from_slice(metadata)
        .map_err(|error: serde_json::Error| malformed(&format!("metadata json: {error}")))?;

    let mut used_paths: UniquePaths = UniquePaths::default();
    let mut modules: Vec<DenoCompileModule> = Vec::new();
    for (index, module) in archive.modules.iter().enumerate() {
        if module.source_len == 0 {
            continue;
        }
        let candidate: String =
            crate::containers::eszip::sanitize_eszip_specifier(&module.specifier)
                .unwrap_or_else(|| format!("module_{index}"));
        modules.push(DenoCompileModule {
            specifier: module.specifier.clone(),
            path: used_paths.claim(candidate),
            origin: DenoModuleOrigin::EszipModule,
            source: rebase(body, module.source_offset, module.source_len)?,
            transpiled: None,
            source_map: eszip_source_map(body, module)?,
        });
    }

    Ok(DenoCompilePayload {
        layout: DenoCompileLayout::EszipTrailer,
        base_offset: base,
        len: body_end - base,
        entrypoint: header.entrypoint_key,
        modules,
        symlinks: Vec::new(),
        redirects: archive
            .redirects
            .into_iter()
            .map(
                |redirect: crate::containers::eszip::EszipRedirect| DenoCompileRedirect {
                    specifier: redirect.specifier,
                    target: redirect.target,
                },
            )
            .collect(),
        unread_npm_files: npm_vfs.trim_ascii() != EMPTY_NPM_VFS,
    })
}

fn rebase(body: usize, offset: usize, len: usize) -> Result<ByteSpan> {
    Ok(ByteSpan {
        offset: body
            .checked_add(offset)
            .ok_or_else(|| malformed("eszip range overflows"))?,
        len,
    })
}

fn eszip_source_map(body: usize, module: &EszipModuleEntry) -> Result<Option<ByteSpan>> {
    if module.source_map_len == 0 {
        return Ok(None);
    }
    rebase(body, module.source_map_offset, module.source_map_len).map(Some)
}

pub fn extract_deno_compile(
    bytes: &[u8],
    quota: &ExtractionQuota,
) -> Result<Vec<DenoCompileExtractedFile>> {
    let payload: DenoCompilePayload = parse_deno_compile(bytes)?;
    extract_deno_compile_payload(bytes, &payload, quota)
}

pub fn extract_deno_compile_payload(
    bytes: &[u8],
    payload: &DenoCompilePayload,
    quota: &ExtractionQuota,
) -> Result<Vec<DenoCompileExtractedFile>> {
    let mut guard: QuotaGuard = QuotaGuard::new(*quota);
    let mut used_paths: UniquePaths = UniquePaths::default();
    for module in &payload.modules {
        used_paths.reserve(module.path.clone());
    }
    let mut out: Vec<DenoCompileExtractedFile> = Vec::new();
    for module in &payload.modules {
        let source: &[u8] = module
            .source
            .slice(bytes)
            .ok_or_else(|| malformed("module range runs past the input"))?;
        guard.admit_entry(&module.path, source.len() as u64, source.len() as u64)?;
        out.push(DenoCompileExtractedFile {
            path: module.path.clone(),
            specifier: module.specifier.clone(),
            role: DenoExtractedRole::Source,
            bytes: source.to_vec(),
        });
        if module.origin != DenoModuleOrigin::EszipModule {
            continue;
        }
        let Some(span): Option<ByteSpan> = module.source_map else {
            continue;
        };
        let map: &[u8] = span
            .slice(bytes)
            .ok_or_else(|| malformed("source map range runs past the input"))?;
        let path: String = used_paths.claim(format!("{}.map", module.path));
        guard.admit_entry(&path, map.len() as u64, map.len() as u64)?;
        out.push(DenoCompileExtractedFile {
            path,
            specifier: module.specifier.clone(),
            role: DenoExtractedRole::SourceMap,
            bytes: map.to_vec(),
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct Remote<'a> {
        id: u32,
        media_type: u8,
        source: &'a [u8],
        transpiled: Option<&'a [u8]>,
    }

    fn push_u32_block(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(data);
    }

    fn push_u64_block(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }

    fn module_store(
        specifiers: &[(&str, u32)],
        redirects: &[(u32, u32)],
        remote: &[Remote<'_>],
        vfs_json: &str,
        files: &[u8],
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(DENO_COMPILE_MAGIC);
        push_u64_block(&mut out, METADATA);
        push_u64_block(&mut out, b"");
        out.extend_from_slice(&u32::try_from(specifiers.len()).unwrap().to_le_bytes());
        for (text, id) in specifiers {
            push_u32_block(&mut out, text.as_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out.extend_from_slice(&u32::try_from(redirects.len()).unwrap().to_le_bytes());
        for (from, to) in redirects {
            out.extend_from_slice(&from.to_le_bytes());
            out.extend_from_slice(&to.to_le_bytes());
        }
        out.extend_from_slice(&u32::try_from(remote.len()).unwrap().to_le_bytes());
        for module in remote {
            out.extend_from_slice(&module.id.to_le_bytes());
            out.push(module.media_type);
            push_u32_block(&mut out, module.source);
            let flags: u8 = if module.transpiled.is_some() {
                HAS_TRANSPILED_FLAG | 8
            } else {
                8
            };
            out.push(flags);
            if let Some(transpiled) = module.transpiled {
                push_u32_block(&mut out, transpiled);
            }
        }
        push_u64_block(&mut out, vfs_json.as_bytes());
        push_u64_block(&mut out, files);
        out.extend_from_slice(DENO_COMPILE_MAGIC);
        out
    }

    const METADATA: &[u8] = br#"{"argv":[],"entrypoint_key":"main.ts"}"#;
    const FILES: &[u8] = b"export const a = 1;\nconsole.log(a);\n";
    const VFS: &str = r#"[{"Dir":{"n":"lib","e":[{"File":{"n":"a.ts","o":[0,20],"u":true,"t":1}},{"Symlink":{"n":"alias.ts","p":["lib","a.ts"]}}]}},{"File":{"n":"main.ts","o":[20,16]}}]"#;

    fn sample() -> Vec<u8> {
        module_store(
            &[
                ("https://deno.land/x/mod.ts", 0),
                ("https://deno.land/x/old.ts", 1),
            ],
            &[(1, 0)],
            &[Remote {
                id: 0,
                media_type: 4,
                source: b"export const b: number = 2;\n",
                transpiled: Some(b"export const b = 2;\n"),
            }],
            VFS,
            FILES,
        )
    }

    #[test]
    fn module_store_yields_files_remote_modules_and_links() {
        let mut host: Vec<u8> = b"MZ\x90\x00".to_vec();
        host.extend_from_slice(DENO_COMPILE_MAGIC);
        host.extend(std::iter::repeat_n(0u8, 64));
        let base: usize = host.len();
        host.extend_from_slice(&sample());
        host.extend(std::iter::repeat_n(0u8, 32));
        let payload: DenoCompilePayload = parse_deno_compile(&host).expect("parse");
        assert_eq!(payload.layout, DenoCompileLayout::ModuleStore);
        assert_eq!(payload.base_offset, base);
        assert_eq!(payload.entrypoint, "main.ts");
        assert_eq!(detect_deno_compile(&host), Some(base));
        let paths: Vec<&str> = payload
            .modules
            .iter()
            .map(|module: &DenoCompileModule| module.path.as_str())
            .collect();
        assert_eq!(paths, ["lib/a.ts", "main.ts", "deno.land/x/mod.ts"]);
        assert_eq!(payload.symlinks[0].path, "lib/alias.ts");
        assert_eq!(payload.symlinks[0].target, "lib/a.ts");
        assert_eq!(payload.redirects[0].specifier, "https://deno.land/x/old.ts");
        let remote: &DenoCompileModule = &payload.modules[2];
        assert_eq!(
            remote
                .transpiled
                .and_then(|span: ByteSpan| span.slice(&host)),
            Some(&b"export const b = 2;\n"[..])
        );
        let files: Vec<DenoCompileExtractedFile> =
            extract_deno_compile(&host, &ExtractionQuota::default_safe()).expect("extract");
        let recovered: Vec<(&str, &[u8])> = files
            .iter()
            .map(|file: &DenoCompileExtractedFile| (file.path.as_str(), file.bytes.as_slice()))
            .collect();
        assert_eq!(
            recovered,
            [
                ("lib/a.ts", &b"export const a = 1;\n"[..]),
                ("main.ts", &b"console.log(a);\n"[..]),
                ("deno.land/x/mod.ts", &b"export const b: number = 2;\n"[..]),
            ]
        );
    }

    #[test]
    fn a_file_range_past_the_data_block_is_refused() {
        let vfs: &str = r#"[{"File":{"n":"main.ts","o":[20,17]}}]"#;
        let bytes: Vec<u8> = module_store(&[], &[], &[], vfs, FILES);
        assert!(parse_deno_compile(&bytes).is_err());
    }

    #[test]
    fn an_unknown_specifier_id_is_refused() {
        let bytes: Vec<u8> = module_store(&[("https://a/x.ts", 0)], &[(0, 7)], &[], VFS, FILES);
        assert!(parse_deno_compile(&bytes).is_err());
    }

    #[test]
    fn a_count_larger_than_the_input_is_refused_without_allocating() {
        let mut bytes: Vec<u8> = module_store(&[], &[], &[], VFS, FILES);
        let count_at: usize = 8 + 8 + METADATA.len() + 8;
        bytes[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_deno_compile(&bytes).is_err());
    }

    #[test]
    fn a_corrupt_closing_magic_is_refused() {
        let mut bytes: Vec<u8> = sample();
        let last: usize = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert!(parse_deno_compile(&bytes).is_err());
        assert!(detect_deno_compile(&bytes).is_none());
    }

    #[test]
    fn traversal_names_fall_back_to_indexed_paths_and_duplicates_are_renamed() {
        let vfs: &str = r#"[{"File":{"n":"../../evil.js","o":[0,20]}},{"Dir":{"n":"x","e":[{"File":{"n":"y","o":[20,16]}}]}},{"File":{"n":"x/y","o":[0,20]}}]"#;
        let bytes: Vec<u8> = module_store(&[], &[], &[], vfs, FILES);
        let payload: DenoCompilePayload = parse_deno_compile(&bytes).expect("parse");
        let paths: Vec<&str> = payload
            .modules
            .iter()
            .map(|module: &DenoCompileModule| module.path.as_str())
            .collect();
        assert_eq!(paths, ["vfs/file_0", "x/y", "x/y~1"]);
    }

    #[test]
    fn an_overlong_directory_chain_is_refused() {
        let name: String = "d".repeat(1500);
        let vfs: String = format!(
            r#"[{{"Dir":{{"n":"{name}","e":[{{"Dir":{{"n":"{name}","e":[{{"Dir":{{"n":"{name}","e":[{{"File":{{"n":"a.ts","o":[0,20]}}}}]}}}}]}}}}]}}}}]"#
        );
        let bytes: Vec<u8> = module_store(&[], &[], &[], &vfs, FILES);
        let error: Error = parse_deno_compile_at(&bytes, 0).expect_err("long path refused");
        assert!(error.to_string().contains("length bound"), "{error}");
    }

    #[test]
    fn duplicate_paths_take_the_next_free_suffix() {
        let mut paths: UniquePaths = UniquePaths::default();
        paths.reserve("a~2".to_owned());
        let claimed: Vec<String> = (0..5).map(|_| paths.claim("a".to_owned())).collect();
        assert_eq!(claimed, ["a", "a~1", "a~3", "a~4", "a~5"]);
    }

    #[test]
    fn a_drive_rooted_windows_tree_keeps_the_drive_letter_as_a_directory() {
        assert_eq!(
            sanitize_vfs_path("C:/app/main.ts").as_deref(),
            Some("C/app/main.ts")
        );
        assert_eq!(sanitize_vfs_path("lib/a:b.ts"), None);
    }

    #[test]
    fn truncated_payloads_do_not_panic() {
        let full: Vec<u8> = sample();
        for cut in 0..full.len() {
            let _ = parse_deno_compile(&full[..cut]);
        }
    }

    #[test]
    fn nesting_past_the_json_recursion_limit_is_a_typed_error() {
        let mut vfs: String = String::new();
        for _ in 0..200 {
            vfs.push_str(r#"[{"Dir":{"n":"d","e":"#);
        }
        vfs.push_str(r#"[{"File":{"n":"a.ts","o":[0,20]}}]"#);
        for _ in 0..200 {
            vfs.push_str("}}]");
        }
        let bytes: Vec<u8> = module_store(&[], &[], &[], &vfs, FILES);
        let error: Error = parse_deno_compile_at(&bytes, 0).expect_err("nesting refused");
        assert!(error.to_string().contains("recursion limit"), "{error}");
    }
}
