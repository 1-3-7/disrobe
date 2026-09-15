use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CapabilityKind {
    Requires,
    Produces,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub major: u32,
    pub kind: CapabilityKind,
}

impl PartialOrd for Capability {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Capability {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| self.major.cmp(&other.major))
    }
}

impl Capability {
    #[inline]
    #[must_use]
    pub fn produces(name: impl Into<String>, major: u32) -> Self {
        Self {
            name: name.into(),
            major,
            kind: CapabilityKind::Produces,
        }
    }

    #[inline]
    #[must_use]
    pub fn requires(name: impl Into<String>, major: u32) -> Self {
        Self {
            name: name.into(),
            major,
            kind: CapabilityKind::Requires,
        }
    }

    #[inline]
    #[must_use]
    pub fn satisfies(&self, requirement: &Self) -> bool {
        matches!(requirement.kind, CapabilityKind::Requires)
            && matches!(self.kind, CapabilityKind::Produces)
            && self.name == requirement.name
            && self.major == requirement.major
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn produces_satisfies_matching_requires() {
        let p: Capability = Capability::produces("mir.core", 2);
        let r: Capability = Capability::requires("mir.core", 2);
        assert!(p.satisfies(&r));
    }

    #[test]
    fn produces_does_not_satisfy_different_major() {
        let p: Capability = Capability::produces("mir.core", 1);
        let r: Capability = Capability::requires("mir.core", 2);
        assert!(!p.satisfies(&r));
    }

    #[test]
    fn requires_never_satisfies() {
        let a: Capability = Capability::requires("x", 1);
        let b: Capability = Capability::requires("x", 1);
        assert!(!a.satisfies(&b));
    }

    #[test]
    fn ordering_is_total_and_stable() {
        let a: Capability = Capability::produces("alpha", 1);
        let b: Capability = Capability::produces("beta", 1);
        let c: Capability = Capability::requires("alpha", 1);
        assert!(c < a);
        assert!(a < b);
    }
}
