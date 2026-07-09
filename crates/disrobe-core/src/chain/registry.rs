use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::pass::PassId;

use super::detection::{ConfidenceBand, DetectContext, DetectVerdict};
use super::detector::{Detector, Pass};
use super::precedence;

#[derive(Debug, Clone)]
pub struct DetectorPick {
    pub pass: &'static dyn Pass,
    pub verdict: DetectVerdict,
}

pub type TieBreak = fn(&DetectVerdict, &DetectVerdict) -> Ordering;

#[derive(Debug, Clone, Copy)]
pub struct SelectionPolicy {
    pub min_confidence: f32,
    pub tie_break: TieBreak,
}

impl SelectionPolicy {
    pub const DEFAULT_MIN_CONFIDENCE: f32 = 0.5;

    #[inline]
    #[must_use]
    pub const fn new(min_confidence: f32, tie_break: TieBreak) -> Self {
        Self {
            min_confidence,
            tie_break,
        }
    }

    #[must_use]
    pub fn select(&self, mut candidates: Vec<DetectVerdict>) -> PolicyOutcome {
        let considered: usize = candidates.len();
        candidates.retain(|v: &DetectVerdict| v.confidence >= self.min_confidence);
        let dropped: usize = considered.saturating_sub(candidates.len());
        candidates.sort_by(|a: &DetectVerdict, b: &DetectVerdict| (self.tie_break)(a, b).reverse());
        let winner: Option<DetectVerdict> = if candidates.is_empty() {
            None
        } else {
            Some(candidates.swap_remove(0))
        };
        PolicyOutcome { winner, dropped }
    }
}

impl Default for SelectionPolicy {
    #[inline]
    fn default() -> Self {
        Self::new(Self::DEFAULT_MIN_CONFIDENCE, precedence::compare)
    }
}

#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    pub winner: Option<DetectVerdict>,
    pub dropped: usize,
}

#[derive(Debug, Clone)]
pub struct PickOutcome {
    pub pick: Option<DetectorPick>,
    pub dropped: usize,
}

#[derive(Debug, Default)]
pub struct PassRegistry {
    passes: BTreeMap<PassId, &'static dyn Pass>,
}

impl PassRegistry {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            passes: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, pass: &'static dyn Pass) -> Option<&'static dyn Pass> {
        self.passes.insert(pass.id(), pass)
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.passes.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    #[must_use]
    pub fn get(&self, pass_id: &str) -> Option<&'static dyn Pass> {
        self.passes.get(pass_id).copied()
    }

    pub fn iter_passes(&self) -> impl Iterator<Item = &'static dyn Pass> + '_ {
        self.passes.values().copied()
    }

    pub fn iter_detectors(&self) -> impl Iterator<Item = &'static dyn Detector> + '_ {
        self.passes.values().map(|p: &&dyn Pass| p.detector())
    }

    #[must_use]
    pub fn run_all(&self, ctx: &DetectContext<'_>) -> Vec<DetectVerdict> {
        let mut out: Vec<DetectVerdict> = Vec::with_capacity(self.passes.len());
        for pass in self.iter_passes_priority() {
            if let Some(v) = pass.detector().detect(ctx) {
                let decisive: bool = v.band == ConfidenceBand::High && v.specificity <= 30;
                out.push(v);
                if decisive {
                    return out;
                }
            }
        }
        out
    }

    fn iter_passes_priority(&self) -> impl Iterator<Item = &'static dyn Pass> + '_ {
        const FIRST: [&str; 6] = [
            "nuitka.extract",
            "pyinstaller.extract",
            "pyfreeze.extract",
            "pyarmor.unpack",
            "binfmt.container",
            "sourcedefender.decrypt",
        ];
        let primary = FIRST.iter().filter_map(move |id: &&str| self.get(id));
        let rest = self
            .passes
            .values()
            .copied()
            .filter(|p: &&'static dyn Pass| !FIRST.contains(&p.id()));
        primary.chain(rest)
    }

    #[must_use]
    pub fn pick(&self, candidates: Vec<DetectVerdict>) -> Option<DetectorPick> {
        self.pick_with_policy(candidates, &SelectionPolicy::default())
            .pick
    }

    #[must_use]
    pub fn pick_with_policy(
        &self,
        candidates: Vec<DetectVerdict>,
        policy: &SelectionPolicy,
    ) -> PickOutcome {
        let outcome: PolicyOutcome = policy.select(candidates);
        let dropped: usize = outcome.dropped;
        let Some(winner): Option<DetectVerdict> = outcome.winner else {
            return PickOutcome {
                pick: None,
                dropped,
            };
        };
        let pick: Option<DetectorPick> =
            self.get(winner.pass_id)
                .map(|pass: &'static dyn Pass| DetectorPick {
                    pass,
                    verdict: winner,
                });
        PickOutcome { pick, dropped }
    }

    #[must_use]
    pub fn run_all_and_pick(&self, ctx: &DetectContext<'_>) -> Option<DetectorPick> {
        let candidates: Vec<DetectVerdict> = self.run_all(ctx);
        self.pick(candidates)
    }

    #[inline]
    #[must_use]
    pub fn compare(a: &DetectVerdict, b: &DetectVerdict) -> Ordering {
        precedence::compare(a, b)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_has_zero_len() {
        let r: PassRegistry = PassRegistry::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        assert!(r.get("anything").is_none());
    }

    #[test]
    fn empty_registry_run_all_is_empty() {
        let r: PassRegistry = PassRegistry::new();
        let ctx: DetectContext<'_> = DetectContext {
            bytes: b"hello",
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: Vec<DetectVerdict> = r.run_all(&ctx);
        assert!(v.is_empty());
        assert!(r.run_all_and_pick(&ctx).is_none());
    }

    #[test]
    fn pick_filters_below_threshold() {
        let r: PassRegistry = PassRegistry::new();
        let verdicts: Vec<DetectVerdict> = vec![DetectVerdict::new(
            "low",
            "tag",
            super::super::FAMILY_OBFUSCATOR_WRAPPER,
            0.3,
            10,
            vec![],
            String::new(),
        )];
        assert!(r.pick(verdicts).is_none());
    }

    fn mk_verdict(
        pass_id: &'static str,
        family: &'static str,
        confidence: f32,
        specificity: u16,
    ) -> DetectVerdict {
        DetectVerdict::new(
            pass_id,
            "tag",
            family,
            confidence,
            specificity,
            vec![],
            String::new(),
        )
    }

    #[test]
    fn selection_policy_default_min_confidence_matches_the_former_hardcoded_cutoff() {
        assert!((SelectionPolicy::DEFAULT_MIN_CONFIDENCE - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn selection_policy_band_filter_drops_below_threshold_and_counts_them() {
        let policy: SelectionPolicy = SelectionPolicy::default();
        let candidates: Vec<DetectVerdict> = vec![
            mk_verdict("low.pass", super::super::FAMILY_UNKNOWN, 0.2, 10),
            mk_verdict(
                "winner.pass",
                super::super::FAMILY_OBFUSCATOR_WRAPPER,
                0.95,
                10,
            ),
        ];
        let outcome: PolicyOutcome = policy.select(candidates);
        assert_eq!(outcome.dropped, 1);
        assert_eq!(
            outcome.winner.expect("a winner survives the band").pass_id,
            "winner.pass"
        );
    }

    #[test]
    fn selection_policy_admits_a_lower_band_when_configured() {
        let policy: SelectionPolicy = SelectionPolicy::new(0.1, precedence::compare);
        let candidates: Vec<DetectVerdict> = vec![mk_verdict(
            "low.pass",
            super::super::FAMILY_UNKNOWN,
            0.2,
            10,
        )];
        let outcome: PolicyOutcome = policy.select(candidates);
        assert_eq!(outcome.dropped, 0);
        assert!(outcome.winner.is_some());
    }

    #[test]
    fn selection_policy_tie_break_matches_precedence_compare_specificity_rule() {
        let policy: SelectionPolicy = SelectionPolicy::default();
        let candidates: Vec<DetectVerdict> = vec![
            mk_verdict(
                "py.decompile",
                super::super::FAMILY_OBFUSCATOR_WRAPPER,
                0.95,
                50,
            ),
            mk_verdict(
                "pyarmor.unpack",
                super::super::FAMILY_OBFUSCATOR_WRAPPER,
                0.95,
                10,
            ),
        ];
        let outcome: PolicyOutcome = policy.select(candidates);
        assert_eq!(
            outcome.winner.expect("a winner").pass_id,
            "pyarmor.unpack",
            "lower specificity must win the tie exactly like registry::pick did before"
        );
    }

    #[test]
    fn selection_policy_empty_candidates_yield_no_winner_and_no_drops() {
        let policy: SelectionPolicy = SelectionPolicy::default();
        let outcome: PolicyOutcome = policy.select(Vec::new());
        assert!(outcome.winner.is_none());
        assert_eq!(outcome.dropped, 0);
    }

    #[test]
    fn pick_with_policy_reports_dropped_count_and_missing_pass_yields_no_pick() {
        let r: PassRegistry = PassRegistry::new();
        let policy: SelectionPolicy = SelectionPolicy::default();
        let candidates: Vec<DetectVerdict> = vec![
            mk_verdict("low.pass", super::super::FAMILY_UNKNOWN, 0.1, 10),
            mk_verdict(
                "unregistered.pass",
                super::super::FAMILY_OBFUSCATOR_WRAPPER,
                0.95,
                10,
            ),
        ];
        let outcome: PickOutcome = r.pick_with_policy(candidates, &policy);
        assert_eq!(outcome.dropped, 1);
        assert!(
            outcome.pick.is_none(),
            "a winner whose pass is not registered must not yield a pick"
        );
    }
}
