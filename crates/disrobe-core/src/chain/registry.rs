//! Explicit detector / pass registry keyed by `PassId` in a `BTreeMap` for deterministic iteration.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::pass::PassId;

use super::detection::{DetectContext, DetectVerdict};
use super::detector::{Detector, Pass};
use super::precedence;

/// A detector verdict joined with the pass that will execute on a win.
#[derive(Debug, Clone)]
pub struct DetectorPick {
    pub pass: &'static dyn Pass,
    pub verdict: DetectVerdict,
}

/// Explicit detector + pass registry.
///
/// Default-constructed empty. Pass crates call [`PassRegistry::register`]
/// during CLI boot - there is no implicit registration.
///
/// ```
/// # #[cfg(feature = "chain")] {
/// use disrobe_core::chain::PassRegistry;
/// let reg: PassRegistry = PassRegistry::new();
/// assert_eq!(reg.len(), 0);
/// # }
/// ```
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

    /// Register a pass. Returns the previous registration if any.
    /// Pass crates call this at boot from `disrobe-cli::main`.
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

    /// Iterate registered passes in deterministic lex order of pass-id.
    pub fn iter_passes(&self) -> impl Iterator<Item = &'static dyn Pass> + '_ {
        self.passes.values().copied()
    }

    /// Iterate registered detectors in deterministic lex order of pass-id.
    pub fn iter_detectors(&self) -> impl Iterator<Item = &'static dyn Detector> + '_ {
        self.passes.values().map(|p: &&dyn Pass| p.detector())
    }

    /// Run every registered detector against `ctx` sequentially.
    #[must_use]
    pub fn run_all(&self, ctx: &DetectContext<'_>) -> Vec<DetectVerdict> {
        let mut out: Vec<DetectVerdict> = Vec::with_capacity(self.passes.len());
        for d in self.iter_detectors() {
            if let Some(v) = d.detect(ctx) {
                out.push(v);
            }
        }
        out
    }

    /// Filter, sort, and pick the highest-precedence verdict (spec §5.2).
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

    /// Convenience: detect-then-pick.
    #[must_use]
    pub fn run_all_and_pick(&self, ctx: &DetectContext<'_>) -> Option<DetectorPick> {
        let candidates: Vec<DetectVerdict> = self.run_all(ctx);
        self.pick(candidates)
    }

    /// Compare two verdicts with the registry's precedence order
    /// (`Ordering::Greater` means `a` wins).
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
