#![allow(clippy::struct_field_names)]

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub struct ExtractionQuota {
    pub max_entries: usize,
    pub max_total_uncompressed: u64,
    pub max_per_entry_uncompressed: u64,
    pub max_expansion_ratio: u64,
}

impl ExtractionQuota {
    #[must_use]
    pub const fn default_safe() -> Self {
        Self {
            max_entries: 65_535,
            max_total_uncompressed: 4 * 1024 * 1024 * 1024,
            max_per_entry_uncompressed: 512 * 1024 * 1024,
            max_expansion_ratio: 1024,
        }
    }

    #[must_use]
    pub const fn unrestricted() -> Self {
        Self {
            max_entries: usize::MAX,
            max_total_uncompressed: u64::MAX,
            max_per_entry_uncompressed: u64::MAX,
            max_expansion_ratio: u64::MAX,
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
    pub max_observed_ratio: u64,
}

#[derive(Debug)]
pub struct QuotaGuard {
    quota: ExtractionQuota,
    report: QuotaReport,
}

impl QuotaGuard {
    #[must_use]
    pub fn new(quota: ExtractionQuota) -> Self {
        Self {
            quota,
            report: QuotaReport::default(),
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
            if ratio > self.quota.max_expansion_ratio {
                return Err(Error::QuotaExceeded {
                    entry: name.to_owned(),
                    reason: format!(
                        "expansion ratio {ratio} exceeds cap {}",
                        self.quota.max_expansion_ratio
                    ),
                });
            }
            if ratio > self.report.max_observed_ratio {
                self.report.max_observed_ratio = ratio;
            }
        }
        self.report.entries_accepted += 1;
        self.report.total_uncompressed_bytes = new_total;
        Ok(())
    }

    #[must_use]
    pub const fn report(&self) -> &QuotaReport {
        &self.report
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_quota_caps_are_finite() {
        let q: ExtractionQuota = ExtractionQuota::default_safe();
        assert!(q.max_entries < usize::MAX);
        assert!(q.max_total_uncompressed < u64::MAX);
        assert!(q.max_expansion_ratio < u64::MAX);
    }

    #[test]
    fn admit_within_caps_accepts() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        g.admit_entry("a.py", 1024, 256).expect("ok");
        g.admit_entry("b.py", 2048, 1024).expect("ok");
        assert_eq!(g.report().entries_accepted, 2);
        assert_eq!(g.report().total_uncompressed_bytes, 3072);
    }

    #[test]
    fn admit_rejects_oversize_entry() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota {
            max_per_entry_uncompressed: 1024,
            ..ExtractionQuota::default_safe()
        });
        let err: Error = g
            .admit_entry("huge.bin", 2048, 1024)
            .expect_err("must reject");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn admit_rejects_zip_bomb_ratio() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
        let err: Error = g
            .admit_entry("bomb", 4 * 1024 * 1024, 16)
            .expect_err("must reject expansion ratio");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn admit_rejects_total_bytes() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota {
            max_total_uncompressed: 4096,
            ..ExtractionQuota::default_safe()
        });
        g.admit_entry("a", 2048, 1024).expect("ok");
        let err: Error = g
            .admit_entry("b", 3072, 1024)
            .expect_err("must reject total");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn admit_rejects_entry_count_overflow() {
        let mut g: QuotaGuard = QuotaGuard::new(ExtractionQuota {
            max_entries: 1,
            ..ExtractionQuota::default_safe()
        });
        g.admit_entry("a", 16, 16).expect("ok");
        let err: Error = g.admit_entry("b", 16, 16).expect_err("must reject");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }
}
