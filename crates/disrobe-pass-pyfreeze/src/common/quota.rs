use crate::error::{Error, Result};

pub use disrobe_binfmt::{ExtractionQuota, QuotaGuard, QuotaReport};

#[must_use]
pub(crate) const fn default_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_entries: 65_535,
        max_total_uncompressed: 4 * 1024 * 1024 * 1024,
        max_per_entry_uncompressed: 512 * 1024 * 1024,
        max_per_entry_ratio: 1024,
        max_aggregate_ratio: 256,
    }
}

#[must_use]
pub(crate) const fn charge_compressed_for_ratio(uncompressed: u64, compressed: u64) -> u64 {
    if uncompressed == 0 {
        compressed
    } else if compressed == 0 {
        1
    } else {
        compressed
    }
}

pub(crate) fn reject_declared_entry_over_cap(
    quota: ExtractionQuota,
    name: &str,
    declared: u64,
) -> Result<()> {
    if declared > quota.max_per_entry_uncompressed {
        return Err(Error::QuotaExceeded {
            entry: name.to_owned(),
            reason: format!(
                "declared uncompressed={declared} exceeds per-entry cap {}",
                quota.max_per_entry_uncompressed
            ),
        });
    }
    Ok(())
}

#[must_use]
pub(crate) fn next_entry_uncompressed_limit(quota: ExtractionQuota, guard: &QuotaGuard) -> u64 {
    let remaining_total: u64 = quota
        .max_total_uncompressed
        .saturating_sub(guard.report().total_uncompressed_bytes);
    remaining_total.min(quota.max_per_entry_uncompressed)
}

pub(crate) fn admit_charged_entry(
    guard: &mut QuotaGuard,
    name: &str,
    uncompressed: u64,
    compressed: u64,
) -> Result<()> {
    guard
        .admit_entry(
            name,
            uncompressed,
            charge_compressed_for_ratio(uncompressed, compressed),
        )
        .map_err(Error::from)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_quota_matches_prior_pyfreeze_caps() {
        let q: ExtractionQuota = default_quota();
        assert_eq!(q.max_entries, 65_535);
        assert_eq!(q.max_total_uncompressed, 4 * 1024 * 1024 * 1024);
        assert_eq!(q.max_per_entry_uncompressed, 512 * 1024 * 1024);
        assert_eq!(q.max_per_entry_ratio, 1024);
        assert_eq!(q.max_aggregate_ratio, 256);
        assert!(q.max_aggregate_ratio <= q.max_per_entry_ratio);
    }

    #[test]
    fn charge_compressed_matches_prior_zero_compressed_handling() {
        assert_eq!(charge_compressed_for_ratio(0, 0), 0);
        assert_eq!(charge_compressed_for_ratio(0, 5), 5);
        assert_eq!(charge_compressed_for_ratio(10, 0), 1);
        assert_eq!(charge_compressed_for_ratio(10, 4), 4);
    }

    #[test]
    fn declared_size_over_entry_cap_rejects_without_charging() {
        let quota: ExtractionQuota = ExtractionQuota {
            max_per_entry_uncompressed: 1024,
            ..default_quota()
        };
        let err: Error = reject_declared_entry_over_cap(quota, "huge.bin", 2048)
            .expect_err("must reject declared cap overrun");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn declared_size_within_cap_is_accepted() {
        let quota: ExtractionQuota = ExtractionQuota {
            max_per_entry_uncompressed: 1024,
            ..default_quota()
        };
        reject_declared_entry_over_cap(quota, "small.bin", 512).expect("ok");
    }

    #[test]
    fn next_entry_limit_respects_remaining_total() {
        let quota: ExtractionQuota = ExtractionQuota {
            max_total_uncompressed: 100,
            max_per_entry_uncompressed: 80,
            ..default_quota()
        };
        let mut guard: QuotaGuard = QuotaGuard::new(quota);
        assert_eq!(next_entry_uncompressed_limit(quota, &guard), 80);
        admit_charged_entry(&mut guard, "a", 60, 60).expect("ok");
        assert_eq!(next_entry_uncompressed_limit(quota, &guard), 40);
    }

    #[test]
    fn admit_rejects_zip_bomb_ratio_via_charged_compressed() {
        let mut guard: QuotaGuard = QuotaGuard::new(default_quota());
        let err: Error = admit_charged_entry(&mut guard, "bomb", 4 * 1024 * 1024, 16)
            .expect_err("must reject expansion ratio");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn admit_rejects_zip_bomb_ratio_when_compressed_size_is_spoofed_zero() {
        let mut guard: QuotaGuard = QuotaGuard::new(default_quota());
        let err: Error = admit_charged_entry(&mut guard, "bomb", 4 * 1024 * 1024, 0)
            .expect_err("a spoofed zero compressed size must not bypass the ratio cap");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }
}
