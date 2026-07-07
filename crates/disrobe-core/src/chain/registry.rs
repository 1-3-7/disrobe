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
    pub fn pick(&self, mut candidates: Vec<DetectVerdict>) -> Option<DetectorPick> {
        candidates.retain(|v: &DetectVerdict| v.confidence >= 0.5);
        if candidates.is_empty() {
            return None;
        }
        candidates
            .sort_by(|a: &DetectVerdict, b: &DetectVerdict| precedence::compare(a, b).reverse());
        let winner: DetectVerdict = candidates.swap_remove(0);
        let pass: &'static dyn Pass = self.get(winner.pass_id)?;
        Some(DetectorPick {
            pass,
            verdict: winner,
        })
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
}
