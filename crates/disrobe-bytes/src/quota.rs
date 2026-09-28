use std::fmt;
use std::io::{Read, Write};

pub const MAX_ENTRY_PREALLOC: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_ENTRIES: usize = 65_535;
pub const ABSOLUTE_MAX_ENTRIES: usize = 1_000_000;

#[inline]
#[must_use]
pub fn bounded_prealloc(declared: u64) -> usize {
    usize::try_from(declared).map_or(MAX_ENTRY_PREALLOC, |n: usize| n.min(MAX_ENTRY_PREALLOC))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaExceeded {
    pub entry: String,
    pub reason: String,
}

impl fmt::Display for QuotaExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "quota exceeded for {}: {}", self.entry, self.reason)
    }
}

impl std::error::Error for QuotaExceeded {}

#[derive(Debug)]
pub enum LimitedReadError {
    Io(std::io::Error),
    Quota(QuotaExceeded),
}

impl fmt::Display for LimitedReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Quota(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LimitedReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Quota(error) => Some(error),
        }
    }
}

pub fn read_to_limit<R: Read + ?Sized>(
    reader: &mut R,
    entry: &str,
    cap: u64,
) -> Result<Vec<u8>, LimitedReadError> {
    let mut out: Vec<u8> = Vec::with_capacity(bounded_prealloc(cap));
    let mut limited: std::io::Take<&mut R> = reader.take(cap.saturating_add(1));
    let _: usize = limited
        .read_to_end(&mut out)
        .map_err(LimitedReadError::Io)?;
    let observed: u64 = u64::try_from(out.len()).map_or(u64::MAX, |n: u64| n);
    if observed > cap {
        return Err(LimitedReadError::Quota(QuotaExceeded {
            entry: entry.to_owned(),
            reason: format!("read cap {cap} bytes exceeded"),
        }));
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedSizeMismatch {
    pub decoded: usize,
    pub expected: usize,
}

#[derive(Debug)]
pub struct BoundedVecWriter {
    out: Vec<u8>,
    cap: usize,
}

impl BoundedVecWriter {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        let declared: u64 = u64::try_from(cap).map_or(u64::MAX, |value: u64| value);
        Self {
            out: Vec::with_capacity(bounded_prealloc(declared)),
            cap,
        }
    }

    pub fn finish_exact(self) -> Result<Vec<u8>, DecodedSizeMismatch> {
        if self.out.len() == self.cap {
            Ok(self.out)
        } else {
            Err(DecodedSizeMismatch {
                decoded: self.out.len(),
                expected: self.cap,
            })
        }
    }
}

impl Write for BoundedVecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining: usize = self.cap.saturating_sub(self.out.len());
        if buf.len() > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decoded block exceeds its declared size",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

#[derive(Debug, Clone)]
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

    pub fn admit_entry(
        &mut self,
        name: &str,
        uncompressed: u64,
        compressed: u64,
    ) -> Result<(), QuotaExceeded> {
        let exceeded = |reason: String| -> QuotaExceeded {
            QuotaExceeded {
                entry: name.to_owned(),
                reason,
            }
        };
        if self.report.entries_accepted >= self.quota.max_entries {
            return Err(exceeded(format!(
                "max_entries={} reached",
                self.quota.max_entries
            )));
        }
        if uncompressed > self.quota.max_per_entry_uncompressed {
            return Err(exceeded(format!(
                "uncompressed={uncompressed} exceeds per-entry cap {}",
                self.quota.max_per_entry_uncompressed
            )));
        }
        let new_total: u64 = self
            .report
            .total_uncompressed_bytes
            .saturating_add(uncompressed);
        if new_total > self.quota.max_total_uncompressed {
            return Err(exceeded(format!(
                "running total {new_total} exceeds cap {}",
                self.quota.max_total_uncompressed
            )));
        }
        if compressed > 0 {
            let ratio: u64 = uncompressed / compressed.max(1);
            if ratio > self.quota.max_per_entry_ratio {
                return Err(exceeded(format!(
                    "per-entry expansion ratio {ratio} exceeds cap {}",
                    self.quota.max_per_entry_ratio
                )));
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
                return Err(exceeded(format!(
                    "aggregate expansion ratio {aggregate_ratio} exceeds cap {}",
                    self.quota.max_aggregate_ratio
                )));
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

#[cfg(test)]
mod tests {
    use super::{
        BoundedVecWriter, DecodedSizeMismatch, ExtractionQuota, LimitedReadError, QuotaGuard,
        read_to_limit,
    };
    use std::io::Write;

    #[test]
    fn a_read_past_the_cap_is_a_quota_error_and_one_at_the_cap_is_not() {
        let bytes: [u8; 4] = [1, 2, 3, 4];
        assert_eq!(
            read_to_limit(&mut &bytes[..], "a", 4).ok(),
            Some(bytes.to_vec())
        );
        assert!(matches!(
            read_to_limit(&mut &bytes[..], "a", 3),
            Err(LimitedReadError::Quota(exceeded)) if exceeded.entry == "a"
        ));
    }

    #[test]
    fn the_writer_refuses_bytes_past_its_size_and_reports_a_short_block() {
        let mut writer: BoundedVecWriter = BoundedVecWriter::new(3);
        assert!(writer.write_all(&[1, 2]).is_ok());
        assert!(writer.write_all(&[3, 4]).is_err());
        assert_eq!(
            writer.finish_exact(),
            Err(DecodedSizeMismatch {
                decoded: 2,
                expected: 3
            })
        );
    }

    #[test]
    fn the_guard_counts_entries_and_rejects_the_first_over_the_ratio() {
        let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
            max_entries: 2,
            ..ExtractionQuota::default_safe()
        });
        assert_eq!(guard.admit_entry("a", 100, 10), Ok(()));
        assert!(guard.admit_entry("b", 10_000, 10).is_err());
        assert_eq!(guard.admit_entry("c", 10, 10), Ok(()));
        assert!(guard.admit_entry("d", 1, 1).is_err());
        assert_eq!(guard.report().entries_accepted, 2);
    }
}
