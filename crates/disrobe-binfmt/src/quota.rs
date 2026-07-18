use crate::error::{Error, Result};

use std::io::Read;

pub(crate) const MAX_ENTRY_PREALLOC: usize = 64 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_ENTRIES: usize = 65_535;
pub(crate) const ABSOLUTE_MAX_ENTRIES: usize = 1_000_000;

#[inline]
#[must_use]
pub(crate) fn bounded_prealloc(declared: u64) -> usize {
    usize::try_from(declared).map_or(MAX_ENTRY_PREALLOC, |n: usize| n.min(MAX_ENTRY_PREALLOC))
}

pub(crate) fn read_entry_to_limit<R: Read + ?Sized>(
    reader: &mut R,
    entry: &str,
    cap: u64,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(bounded_prealloc(cap));
    let mut limited: std::io::Take<&mut R> = reader.take(cap.saturating_add(1));
    let _: usize = limited.read_to_end(&mut out)?;
    let observed: u64 = u64::try_from(out.len()).map_or(u64::MAX, |n: u64| n);
    if observed > cap {
        return Err(Error::QuotaExceeded {
            entry: entry.to_owned(),
            reason: format!("read cap {cap} bytes exceeded"),
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct ExtractionQuota {
    pub max_entries: usize,
    pub max_total_uncompressed: u64,
    pub max_per_entry_uncompressed: u64,
    pub max_per_entry_ratio: u64,
    pub max_aggregate_ratio: u64,
}

impl ExtractionQuota {
    #[must_use]
    pub const fn default_safe() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_total_uncompressed: 4 * 1024 * 1024 * 1024,
            max_per_entry_uncompressed: 512 * 1024 * 1024,
            max_per_entry_ratio: 100,
            max_aggregate_ratio: 10,
        }
    }

    #[must_use]
    pub const fn unrestricted() -> Self {
        Self {
            max_entries: usize::MAX,
            max_total_uncompressed: u64::MAX,
            max_per_entry_uncompressed: u64::MAX,
            max_per_entry_ratio: u64::MAX,
            max_aggregate_ratio: u64::MAX,
        }
    }
}

impl Default for ExtractionQuota {
    fn default() -> Self {
        Self::default_safe()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaReport {
    pub entries_accepted: usize,
    pub total_uncompressed_bytes: u64,
    pub total_compressed_bytes: u64,
    pub max_observed_ratio: u64,
}

#[derive(Debug)]
pub struct QuotaGuard {
    quota: ExtractionQuota,
    report: QuotaReport,
}

impl QuotaGuard {
    #[must_use]
    pub const fn new(quota: ExtractionQuota) -> Self {
        Self {
            quota,
            report: QuotaReport {
                entries_accepted: 0,
                total_uncompressed_bytes: 0,
                total_compressed_bytes: 0,
                max_observed_ratio: 0,
            },
        }
    }

    pub fn admit_entry(&mut self, name: &str, uncompressed: u64, compressed: u64) -> Result<()> {
        if self.report.entries_accepted >= self.quota.max_entries {
            return Err(Error::QuotaExceeded {
                entry: name.to_owned(),
                reason: format!("max_entries={} reached", self.quota.max_entries),
            });
        }
        if uncompressed > self.quota.max_per_entry_uncompressed {
            return Err(Error::QuotaExceeded {
                entry: name.to_owned(),
                reason: format!(
                    "uncompressed={uncompressed} exceeds per-entry cap {}",
                    self.quota.max_per_entry_uncompressed
                ),
            });
        }
        let new_total: u64 = self
            .report
            .total_uncompressed_bytes
            .saturating_add(uncompressed);
        if new_total > self.quota.max_total_uncompressed {
            return Err(Error::QuotaExceeded {
                entry: name.to_owned(),
                reason: format!(
                    "running total {new_total} exceeds cap {}",
                    self.quota.max_total_uncompressed
                ),
            });
        }
        if compressed > 0 {
            let ratio: u64 = uncompressed / compressed.max(1);
            if ratio > self.quota.max_per_entry_ratio {
                return Err(Error::QuotaExceeded {
                    entry: name.to_owned(),
                    reason: format!(
                        "per-entry expansion ratio {ratio} exceeds cap {}",
                        self.quota.max_per_entry_ratio
                    ),
                });
            }
            if ratio > self.report.max_observed_ratio {
                self.report.max_observed_ratio = ratio;
            }
        }
        let new_compressed: u64 = self
            .report
            .total_compressed_bytes
            .saturating_add(compressed);
        if new_compressed > 0 {
            let aggregate_ratio: u64 = new_total / new_compressed.max(1);
            if aggregate_ratio > self.quota.max_aggregate_ratio {
                return Err(Error::QuotaExceeded {
                    entry: name.to_owned(),
                    reason: format!(
                        "aggregate expansion ratio {aggregate_ratio} exceeds cap {}",
                        self.quota.max_aggregate_ratio
                    ),
                });
            }
        }
        self.report.entries_accepted += 1;
        self.report.total_uncompressed_bytes = new_total;
        self.report.total_compressed_bytes = new_compressed;
        Ok(())
    }

    #[must_use]
    pub const fn report(&self) -> &QuotaReport {
        &self.report
    }

    #[must_use]
    pub const fn max_per_entry_uncompressed(&self) -> u64 {
        self.quota.max_per_entry_uncompressed
    }
}

pub fn sanitize_entry_path(name: &str) -> Result<String> {
    let normalized: String = name.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(Error::UnsafeEntryPath(name.to_owned()));
    }
    if normalized
        .split('/')
        .any(|component: &str| component == ".." || component.contains(':'))
    {
        return Err(Error::UnsafeEntryPath(name.to_owned()));
    }
    let cleaned: String = normalized
        .split('/')
        .filter(|component: &&str| !component.is_empty() && *component != ".")
        .collect::<Vec<&str>>()
        .join("/");
    if cleaned.is_empty() {
        return Err(Error::UnsafeEntryPath(name.to_owned()));
    }
    Ok(cleaned)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rejects_parent_escape() {
        assert!(sanitize_entry_path("../etc/passwd").is_err());
        assert!(sanitize_entry_path("sub/../bad").is_err());
        assert!(sanitize_entry_path("a/../../b").is_err());
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert!(sanitize_entry_path("").is_err());
        assert!(sanitize_entry_path("///").is_err());
    }

    #[test]
    fn sanitize_rejects_absolute_and_drive_prefixed_paths() {
        assert!(sanitize_entry_path("/etc/passwd").is_err());
        assert!(sanitize_entry_path("C:/Windows/win.ini").is_err());
        assert!(sanitize_entry_path("C:\\Windows\\win.ini").is_err());
        assert!(sanitize_entry_path("dir/file.txt:stream").is_err());
    }

    #[test]
    fn sanitize_normalizes_backslashes() {
        let cleaned: String = sanitize_entry_path("a\\b\\c.txt").expect("ok");
        assert_eq!(cleaned, "a/b/c.txt");
    }

    #[test]
    fn sanitize_passes_normal() {
        let cleaned: String = sanitize_entry_path("pkg/mod.pyc").expect("ok");
        assert_eq!(cleaned, "pkg/mod.pyc");
    }

    #[test]
    fn quota_per_entry_ratio_caps_at_100() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        let err: Error = g.admit_entry("bomb", 200, 1).expect_err("must reject");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn quota_aggregate_ratio_caps_at_10() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        g.admit_entry("a", 100, 50).expect("ok");
        let err: Error = g.admit_entry("b", 800, 5).expect_err("aggregate ratio");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn quota_admits_normal_traffic() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        g.admit_entry("a.py", 1024, 512).expect("ok");
        g.admit_entry("b.py", 2048, 1024).expect("ok");
        assert_eq!(g.report().entries_accepted, 2);
    }

    #[test]
    fn quota_unrestricted_admits_anything() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::unrestricted());
        g.admit_entry("huge", 1 << 30, 1).expect("unrestricted ok");
    }

    #[test]
    fn bounded_prealloc_clamps_huge_declared_sizes() {
        assert_eq!(bounded_prealloc(0), 0);
        assert_eq!(bounded_prealloc(1024), 1024);
        assert_eq!(
            bounded_prealloc(MAX_ENTRY_PREALLOC as u64),
            MAX_ENTRY_PREALLOC
        );
        assert_eq!(bounded_prealloc(4 * 1024 * 1024 * 1024), MAX_ENTRY_PREALLOC);
        assert_eq!(bounded_prealloc(u64::MAX), MAX_ENTRY_PREALLOC);
    }

    #[test]
    fn bounded_entry_read_accepts_exact_cap() {
        let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(b"abc");
        let bytes: Vec<u8> = read_entry_to_limit(&mut reader, "entry.bin", 3).expect("read");
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn bounded_entry_read_rejects_over_cap() {
        let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(b"abcd");
        let err: Error =
            read_entry_to_limit(&mut reader, "entry.bin", 3).expect_err("over-cap read must fail");
        assert!(matches!(
            err,
            Error::QuotaExceeded { entry, reason }
                if entry == "entry.bin" && reason.contains("read cap")
        ));
    }
}
