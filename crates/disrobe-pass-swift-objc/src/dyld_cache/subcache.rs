use std::fs;
use std::path::{Path, PathBuf};

use disrobe_bytes::{ByteReadError, read_u64_le_at};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const SUBCACHE_ENTRY_V1_SIZE: usize = 24;
pub const SUBCACHE_ENTRY_SIZE: usize = 56;
pub const MAX_SUB_CACHES: usize = 128;
pub const MAX_FAMILY_BYTES: u64 = 12 * 1024 * 1024 * 1024;

const UUID_LEN: usize = 16;
const SUFFIX_FIELD_LEN: usize = 32;
const SYMBOLS_SUFFIX: &str = ".symbols";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubCacheEntryKind {
    WithFileSuffix,
    UuidAndOffsetOnly,
}

impl SubCacheEntryKind {
    #[must_use]
    pub const fn entry_size(self) -> usize {
        match self {
            Self::WithFileSuffix => SUBCACHE_ENTRY_SIZE,
            Self::UuidAndOffsetOnly => SUBCACHE_ENTRY_V1_SIZE,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WithFileSuffix => "uuid+offset+suffix",
            Self::UuidAndOffsetOnly => "uuid+offset",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubCacheEntry {
    pub index: u32,
    pub uuid: String,
    pub vm_offset: u64,
    pub declared_suffix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingSubCache {
    pub index: u32,
    pub candidate_names: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct LoadedSubCache {
    pub entry: SubCacheEntry,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SymbolsSubCache {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CacheFamily {
    pub primary_path: PathBuf,
    pub primary: Vec<u8>,
    pub sub_caches: Vec<LoadedSubCache>,
    pub missing: Vec<MissingSubCache>,
    pub symbols: Option<SymbolsSubCache>,
    pub symbols_missing: Option<MissingSubCache>,
}

impl CacheFamily {
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    #[must_use]
    pub fn partial_reason(&self) -> Option<String> {
        if self.missing.is_empty() {
            return None;
        }
        let named: Vec<String> = self
            .missing
            .iter()
            .map(|entry: &MissingSubCache| {
                format!(
                    "sub-cache {} ({})",
                    entry.index,
                    entry.candidate_names.join(", ")
                )
            })
            .collect();
        Some(format!(
            "{} of {} sibling cache files were not found next to the primary cache: {}",
            self.missing.len(),
            self.missing.len() + self.sub_caches.len(),
            named.join("; ")
        ))
    }
}

pub fn parse_entries(
    cache: &[u8],
    array_offset: u32,
    array_count: u32,
    kind: SubCacheEntryKind,
) -> Result<Vec<SubCacheEntry>> {
    let count: usize = array_count as usize;
    if count > MAX_SUB_CACHES {
        return Err(Error::BadDyldCache(format!(
            "sub-cache count {array_count} exceeds the {MAX_SUB_CACHES} sub-cache cap"
        )));
    }
    let entry_size: usize = kind.entry_size();
    let base: usize = array_offset as usize;
    let span: usize = count
        .checked_mul(entry_size)
        .ok_or_else(|| Error::BadDyldCache("sub-cache array size overflows".to_owned()))?;
    let end: usize = base
        .checked_add(span)
        .ok_or_else(|| Error::BadDyldCache("sub-cache array end overflows".to_owned()))?;
    if end > cache.len() {
        return Err(Error::BadDyldCache(format!(
            "sub-cache array [{base}, {end}) exceeds cache length {}",
            cache.len()
        )));
    }
    let mut out: Vec<SubCacheEntry> = Vec::with_capacity(count);
    for index in 0..count {
        let at: usize = base + index * entry_size;
        let uuid_bytes: &[u8] = cache
            .get(at..at + UUID_LEN)
            .ok_or_else(|| Error::BadDyldCache(format!("sub-cache {index} uuid is truncated")))?;
        let vm_offset: u64 =
            read_u64_le_at(cache, at + UUID_LEN).map_err(|error: ByteReadError| {
                Error::BadDyldCache(format!(
                    "sub-cache {index} vm offset is unreadable: {error}"
                ))
            })?;
        let declared_suffix: Option<String> = match kind {
            SubCacheEntryKind::UuidAndOffsetOnly => None,
            SubCacheEntryKind::WithFileSuffix => {
                let field: &[u8] = cache
                    .get(at + UUID_LEN + 8..at + UUID_LEN + 8 + SUFFIX_FIELD_LEN)
                    .ok_or_else(|| {
                        Error::BadDyldCache(format!("sub-cache {index} file suffix is truncated"))
                    })?;
                declared_suffix_of(field)?
            }
        };
        let ordinal: u32 = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        out.push(SubCacheEntry {
            index: ordinal,
            uuid: hex_uuid(uuid_bytes),
            vm_offset,
            declared_suffix,
        });
    }
    Ok(out)
}

fn declared_suffix_of(field: &[u8]) -> Result<Option<String>> {
    let stop: usize = field
        .iter()
        .position(|byte: &u8| *byte == 0)
        .unwrap_or(field.len());
    if stop == 0 {
        return Ok(None);
    }
    let text: String = String::from_utf8_lossy(&field[..stop]).into_owned();
    validate_suffix(&text)?;
    Ok(Some(text))
}

pub fn validate_suffix(suffix: &str) -> Result<()> {
    let reject = |reason: &str| -> Error {
        Error::DyldSubCachePathRejected {
            suffix: suffix.to_owned(),
            reason: reason.to_owned(),
        }
    };
    if suffix.is_empty() {
        return Err(reject("it is empty"));
    }
    if suffix.len() > SUFFIX_FIELD_LEN {
        return Err(reject("it is longer than the 32-byte suffix field"));
    }
    if suffix.contains("..") {
        return Err(reject("it contains a parent-directory component"));
    }
    for character in suffix.chars() {
        match character {
            '/' | '\\' => return Err(reject("it contains a path separator")),
            ':' => return Err(reject("it contains a drive or stream separator")),
            '*' | '?' | '"' | '<' | '>' | '|' => {
                return Err(reject(
                    "it contains a path wildcard or redirection character",
                ));
            }
            other if !other.is_ascii_graphic() => {
                return Err(reject("it contains a byte outside printable ASCII"));
            }
            _ => {}
        }
    }
    Ok(())
}

#[must_use]
pub fn candidate_names(primary_file_name: &str, index: u32) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(3);
    out.push(format!("{primary_file_name}.{index}"));
    let padded: String = format!("{primary_file_name}.{index:02}");
    if !out.contains(&padded) {
        out.push(padded);
    }
    out
}

#[must_use]
pub fn symbols_candidate_names(primary_file_name: &str) -> Vec<String> {
    vec![format!("{primary_file_name}{SYMBOLS_SUFFIX}")]
}

pub fn sibling_path(primary: &Path, suffix: &str) -> Result<PathBuf> {
    validate_suffix(suffix)?;
    let parent: &Path = primary
        .parent()
        .ok_or_else(|| Error::DyldSubCachePathRejected {
            suffix: suffix.to_owned(),
            reason: "the primary cache path has no parent directory".to_owned(),
        })?;
    let stem: &str = primary
        .file_name()
        .and_then(|name: &std::ffi::OsStr| name.to_str())
        .ok_or_else(|| Error::DyldSubCachePathRejected {
            suffix: suffix.to_owned(),
            reason: "the primary cache path has no readable file name".to_owned(),
        })?;
    let joined: PathBuf = parent.join(format!("{stem}{suffix}"));
    if joined.parent() != Some(parent) {
        return Err(Error::DyldSubCachePathRejected {
            suffix: suffix.to_owned(),
            reason: "the resolved sibling leaves the primary cache directory".to_owned(),
        });
    }
    Ok(joined)
}

fn read_sibling(parent: &Path, name: &str, budget: &mut u64) -> Result<Option<(PathBuf, Vec<u8>)>> {
    let path: PathBuf = parent.join(name);
    if path.parent() != Some(parent) {
        return Err(Error::DyldSubCachePathRejected {
            suffix: name.to_owned(),
            reason: "the computed sibling name leaves the primary cache directory".to_owned(),
        });
    }
    let meta: fs::Metadata = match fs::metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::Io(error)),
    };
    if !meta.is_file() {
        return Ok(None);
    }
    let size: u64 = meta.len();
    if size > *budget {
        return Err(Error::BadDyldCache(format!(
            "sibling cache '{name}' is {size} bytes, which exceeds the remaining {budget}-byte family budget"
        )));
    }
    *budget -= size;
    let bytes: Vec<u8> = fs::read(&path)?;
    Ok(Some((path, bytes)))
}

pub fn open_family(
    primary_path: &Path,
    primary: Vec<u8>,
    entries: &[SubCacheEntry],
    wants_symbols_file: bool,
) -> Result<CacheFamily> {
    let parent: PathBuf = primary_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let mut budget: u64 = MAX_FAMILY_BYTES.saturating_sub(primary.len() as u64);
    let mut sub_caches: Vec<LoadedSubCache> = Vec::with_capacity(entries.len());
    let mut missing: Vec<MissingSubCache> = Vec::new();

    let primary_name: String = primary_path
        .file_name()
        .and_then(|name: &std::ffi::OsStr| name.to_str())
        .unwrap_or_default()
        .to_owned();

    for entry in entries {
        let names: Vec<String> = candidate_names(&primary_name, entry.index);
        let mut loaded: Option<(PathBuf, Vec<u8>)> = None;
        for name in &names {
            if let Some(found) = read_sibling(&parent, name, &mut budget)? {
                loaded = Some(found);
                break;
            }
        }
        match loaded {
            Some((path, bytes)) => sub_caches.push(LoadedSubCache {
                entry: entry.clone(),
                path,
                bytes,
            }),
            None => missing.push(MissingSubCache {
                index: entry.index,
                candidate_names: names,
                reason: format!(
                    "no file with a computed sibling name exists next to {}",
                    primary_path.display()
                ),
            }),
        }
    }

    let symbols_names: Vec<String> = symbols_candidate_names(&primary_name);
    let mut symbols: Option<SymbolsSubCache> = None;
    let mut symbols_missing: Option<MissingSubCache> = None;
    if wants_symbols_file {
        for name in &symbols_names {
            if let Some((path, bytes)) = read_sibling(&parent, name, &mut budget)? {
                symbols = Some(SymbolsSubCache { path, bytes });
                break;
            }
        }
        if symbols.is_none() {
            symbols_missing = Some(MissingSubCache {
                index: 0,
                candidate_names: symbols_names,
                reason: format!(
                    "the cache declares an unmapped local-symbols file but no computed sibling name exists next to {}",
                    primary_path.display()
                ),
            });
        }
    }

    Ok(CacheFamily {
        primary_path: primary_path.to_path_buf(),
        primary,
        sub_caches,
        missing,
        symbols,
        symbols_missing,
    })
}

const HEX_DIGITS: [u8; 16] = *b"0123456789ABCDEF";

#[must_use]
pub fn hex_uuid(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn computed_names_cover_bare_and_zero_padded_forms() {
        let names: Vec<String> = candidate_names("dyld_shared_cache_arm64e", 1);
        assert_eq!(
            names,
            vec![
                "dyld_shared_cache_arm64e.1".to_owned(),
                "dyld_shared_cache_arm64e.01".to_owned()
            ]
        );
        assert_eq!(
            candidate_names("cache", 25),
            vec!["cache.25".to_owned()],
            "a two-digit index needs no zero-padded alternative"
        );
    }

    #[test]
    fn a_traversal_suffix_is_refused_on_both_separator_styles() {
        for hostile in ["../evil", "..\\evil", "/etc/passwd", "C:evil", "sub/dir"] {
            let refusal: Error = validate_suffix(hostile).expect_err("must refuse");
            assert!(
                matches!(refusal, Error::DyldSubCachePathRejected { .. }),
                "{hostile} produced {refusal}"
            );
        }
    }

    #[test]
    fn an_ordinary_suffix_resolves_inside_the_cache_directory() {
        let primary: PathBuf = PathBuf::from("/caches/dyld_shared_cache_arm64e");
        let resolved: PathBuf = sibling_path(&primary, ".01.data").expect("ordinary suffix");
        assert_eq!(resolved.parent(), primary.parent());
        assert_eq!(
            resolved.file_name().and_then(|n| n.to_str()),
            Some("dyld_shared_cache_arm64e.01.data")
        );
    }

    #[test]
    fn a_suffix_longer_than_the_field_is_refused() {
        let long: String = ".".repeat(SUFFIX_FIELD_LEN + 1);
        assert!(matches!(
            validate_suffix(&long),
            Err(Error::DyldSubCachePathRejected { .. })
        ));
    }

    #[test]
    fn uuid_rendering_is_stable() {
        let bytes: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        assert_eq!(hex_uuid(&bytes), "01234567-89AB-CDEF-0123-456789ABCDEF");
    }
}
