use serde::{Deserialize, Serialize};

pub const RECOVERY_SCHEMA: &str = "disrobe.recovery/v0";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidenceTier {
    Skeleton = 0,
    Partial = 1,
    Semantic = 2,
    Exact = 3,
}

impl ConfidenceTier {
    #[inline]
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skeleton => "skeleton",
            Self::Partial => "partial",
            Self::Semantic => "semantic",
            Self::Exact => "exact",
        }
    }

    #[inline]
    #[must_use]
    pub const fn from_rank(rank: u8) -> Option<Self> {
        match rank {
            0 => Some(Self::Skeleton),
            1 => Some(Self::Partial),
            2 => Some(Self::Semantic),
            3 => Some(Self::Exact),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoverySignal {
    ByteRoundtripVerified,
    RecompilesEquivalent,
    FullBodyLifted,
    SomeBodiesLifted,
    StructuredNoVerify,
    SignaturesOnly,
    NoRecovery,
}

#[inline]
#[must_use]
pub const fn assign_tier(signal: RecoverySignal) -> ConfidenceTier {
    match signal {
        RecoverySignal::ByteRoundtripVerified => ConfidenceTier::Exact,
        RecoverySignal::RecompilesEquivalent | RecoverySignal::FullBodyLifted => {
            ConfidenceTier::Semantic
        }
        RecoverySignal::SomeBodiesLifted | RecoverySignal::StructuredNoVerify => {
            ConfidenceTier::Partial
        }
        RecoverySignal::SignaturesOnly | RecoverySignal::NoRecovery => ConfidenceTier::Skeleton,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassRecovery {
    pub pass_id: String,
    pub tier: ConfidenceTier,
    pub unit_count: u32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierHistogram {
    pub exact: u32,
    pub semantic: u32,
    pub partial: u32,
    pub skeleton: u32,
}

impl TierHistogram {
    #[inline]
    pub const fn record(&mut self, tier: ConfidenceTier) {
        match tier {
            ConfidenceTier::Exact => self.exact += 1,
            ConfidenceTier::Semantic => self.semantic += 1,
            ConfidenceTier::Partial => self.partial += 1,
            ConfidenceTier::Skeleton => self.skeleton += 1,
        }
    }

    #[inline]
    #[must_use]
    pub const fn total(self) -> u32 {
        self.exact + self.semantic + self.partial + self.skeleton
    }

    #[must_use]
    pub fn from_tiers<I: IntoIterator<Item = ConfidenceTier>>(tiers: I) -> Self {
        tiers
            .into_iter()
            .fold(Self::default(), |mut acc: Self, tier: ConfidenceTier| {
                acc.record(tier);
                acc
            })
    }

    #[inline]
    #[must_use]
    pub const fn get(self, tier: ConfidenceTier) -> u32 {
        match tier {
            ConfidenceTier::Exact => self.exact,
            ConfidenceTier::Semantic => self.semantic,
            ConfidenceTier::Partial => self.partial,
            ConfidenceTier::Skeleton => self.skeleton,
        }
    }
}

#[inline]
const fn recovery_schema() -> &'static str {
    RECOVERY_SCHEMA
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    #[serde(default = "recovery_schema", skip_deserializing)]
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub passes: Vec<PassRecovery>,
    pub histogram: TierHistogram,
    pub total_duration_ms: u64,
}

impl RecoveryReport {
    #[must_use]
    pub fn new(uri: Option<String>, passes: Vec<PassRecovery>) -> Self {
        let histogram: TierHistogram =
            TierHistogram::from_tiers(passes.iter().map(|p: &PassRecovery| p.tier));
        let total_duration_ms: u64 = passes.iter().map(|p: &PassRecovery| p.duration_ms).sum();
        Self {
            schema: RECOVERY_SCHEMA,
            uri,
            passes,
            histogram,
            total_duration_ms,
        }
    }

    #[inline]
    #[must_use]
    pub fn min_tier(&self) -> Option<ConfidenceTier> {
        self.passes.iter().map(|p: &PassRecovery| p.tier).min()
    }

    #[inline]
    #[must_use]
    pub fn max_tier(&self) -> Option<ConfidenceTier> {
        self.passes.iter().map(|p: &PassRecovery| p.tier).max()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rank_round_trips_all_tiers() {
        for rank in 0u8..=3 {
            let tier: ConfidenceTier = ConfidenceTier::from_rank(rank).expect("valid rank");
            assert_eq!(tier.rank(), rank);
        }
        assert_eq!(ConfidenceTier::from_rank(4), None);
    }

    #[test]
    fn as_str_matches_each_variant() {
        assert_eq!(ConfidenceTier::Skeleton.as_str(), "skeleton");
        assert_eq!(ConfidenceTier::Partial.as_str(), "partial");
        assert_eq!(ConfidenceTier::Semantic.as_str(), "semantic");
        assert_eq!(ConfidenceTier::Exact.as_str(), "exact");
    }

    #[test]
    fn ordering_is_weakest_first() {
        assert!(ConfidenceTier::Exact > ConfidenceTier::Semantic);
        assert!(ConfidenceTier::Semantic > ConfidenceTier::Partial);
        assert!(ConfidenceTier::Partial > ConfidenceTier::Skeleton);
    }

    #[test]
    fn record_increments_correct_field() {
        let mut h: TierHistogram = TierHistogram::default();
        h.record(ConfidenceTier::Exact);
        h.record(ConfidenceTier::Exact);
        h.record(ConfidenceTier::Skeleton);
        assert_eq!(h.exact, 2);
        assert_eq!(h.skeleton, 1);
        assert_eq!(h.semantic, 0);
        assert_eq!(h.partial, 0);
        assert_eq!(h.get(ConfidenceTier::Exact), 2);
        assert_eq!(h.total(), 3);
    }
}
