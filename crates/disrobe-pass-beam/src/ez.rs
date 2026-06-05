use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Resource limits applied while extracting an `.ez` (zip) archive.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct EzQuota {
    pub max_entries: usize,
    pub max_total_uncompressed: u64,
    pub max_per_entry_uncompressed: u64,
    pub max_aggregate_ratio: u64,
}

impl EzQuota {
    #[must_use]
    pub const fn default_safe() -> Self {
        Self {
            max_entries: 16_384,
            max_total_uncompressed: 512 * 1024 * 1024,
            max_per_entry_uncompressed: 128 * 1024 * 1024,
            max_aggregate_ratio: 200,
        }
    }

    #[must_use]
    pub const fn unrestricted() -> Self {
        Self {
            max_entries: usize::MAX,
            max_total_uncompressed: u64::MAX,
            max_per_entry_uncompressed: u64::MAX,
            max_aggregate_ratio: u64::MAX,
        }
    }
}

impl Default for EzQuota {
    fn default() -> Self {
        Self::default_safe()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EzEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EzArchive {
    pub entries: BTreeMap<String, EzEntry>,
}

impl EzArchive {
    /// Parses an `.ez` archive under [`EzQuota::default_safe`] limits.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        Self::parse_with_quota(buf, EzQuota::default_safe())
    }

    /// Parses an `.ez` archive, enforcing `quota` against entry count and sizes.
    pub fn parse_with_quota(buf: &[u8], quota: EzQuota) -> Result<Self> {
        let cursor: Cursor<&[u8]> = Cursor::new(buf);
        let mut archive: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(cursor)?;
        let count: usize = archive.len();
        if count > quota.max_entries {
            return Err(Error::EzQuotaExceeded {
                entry: "<archive>".to_owned(),
                reason: format!("entry count {count} exceeds cap {}", quota.max_entries),
            });
        }
        let mut entries: BTreeMap<String, EzEntry> = BTreeMap::new();
        let mut total_uncompressed: u64 = 0;
        let mut total_compressed: u64 = 0;
        for i in 0..count {
            let mut file: zip::read::ZipFile<'_> = archive.by_index(i)?;
            let raw_name: String = file.name().to_owned();
            let path: String = sanitize_entry_path(&raw_name)?;
            let is_dir: bool = file.is_dir();
            let declared: u64 = file.size();
            let compressed: u64 = file.compressed_size();

            if declared > quota.max_per_entry_uncompressed {
                return Err(Error::EzQuotaExceeded {
                    entry: path,
                    reason: format!(
                        "declared size {declared} exceeds per-entry cap {}",
                        quota.max_per_entry_uncompressed
                    ),
                });
            }
            let projected_total: u64 = total_uncompressed.saturating_add(declared);
            if projected_total > quota.max_total_uncompressed {
                return Err(Error::EzQuotaExceeded {
                    entry: path,
                    reason: format!(
                        "running total {projected_total} exceeds cap {}",
                        quota.max_total_uncompressed
                    ),
                });
            }

            let data: Vec<u8> = if is_dir {
                Vec::new()
            } else {
                let ceiling: u64 = quota.max_per_entry_uncompressed.min(
                    quota
                        .max_total_uncompressed
                        .saturating_sub(total_uncompressed),
                );
                read_bounded(&mut file, declared, ceiling, &path)?
            };
            let actual: u64 = data.len() as u64;

            total_uncompressed = total_uncompressed.saturating_add(actual);
            total_compressed = total_compressed.saturating_add(compressed);
            if total_compressed > 0 {
                let aggregate_ratio: u64 = total_uncompressed / total_compressed.max(1);
                if aggregate_ratio > quota.max_aggregate_ratio {
                    return Err(Error::EzQuotaExceeded {
                        entry: path,
                        reason: format!(
                            "aggregate expansion ratio {aggregate_ratio} exceeds cap {}",
                            quota.max_aggregate_ratio
                        ),
                    });
                }
            }

            entries.insert(
                path.clone(),
                EzEntry {
                    path,
                    size: actual,
                    is_dir,
                    data,
                },
            );
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn beam_files(&self) -> Vec<&EzEntry> {
        self.entries
            .values()
            .filter(|e: &&EzEntry| !e.is_dir && e.path.ends_with(".beam"))
            .collect()
    }
}

fn read_bounded(
    reader: &mut impl Read,
    declared: u64,
    ceiling: u64,
    entry: &str,
) -> Result<Vec<u8>> {
    let cap_hint: usize = usize::try_from(declared.min(ceiling).min(1024 * 1024)).unwrap_or(0);
    let mut out: Vec<u8> = Vec::with_capacity(cap_hint);
    let limit: u64 = ceiling.saturating_add(1);
    let read: u64 = std::io::copy(&mut reader.take(limit), &mut out).map_err(Error::Io)?;
    if read > ceiling {
        return Err(Error::EzQuotaExceeded {
            entry: entry.to_owned(),
            reason: format!("decompressed stream exceeds remaining budget {ceiling}"),
        });
    }
    Ok(out)
}

fn sanitize_entry_path(name: &str) -> Result<String> {
    let normalized: String = name.replace('\\', "/");
    if normalized
        .split('/')
        .any(|component: &str| component == "..")
    {
        return Err(Error::EzUnsafePath(name.to_owned()));
    }
    if normalized.starts_with('/') {
        return Err(Error::EzUnsafePath(name.to_owned()));
    }
    let cleaned: String = normalized
        .split('/')
        .filter(|component: &&str| !component.is_empty() && *component != ".")
        .collect::<Vec<&str>>()
        .join("/");
    if cleaned.is_empty() {
        return Err(Error::EzUnsafePath(name.to_owned()));
    }
    Ok(cleaned)
}
