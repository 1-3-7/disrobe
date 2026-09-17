use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::rung::Rung;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub rung: Rung,
    pub envelope: Vec<u8>,
    pub capabilities: BTreeSet<Capability>,
    pub root_hash: [u8; 32],
}

impl Artifact {
    #[inline]
    #[must_use]
    pub const fn new(rung: Rung, envelope: Vec<u8>, root_hash: [u8; 32]) -> Self {
        Self {
            rung,
            envelope,
            capabilities: BTreeSet::new(),
            root_hash,
        }
    }

    #[inline]
    #[must_use]
    pub fn with_capabilities(
        rung: Rung,
        envelope: Vec<u8>,
        capabilities: impl IntoIterator<Item = Capability>,
        root_hash: [u8; 32],
    ) -> Self {
        Self {
            rung,
            envelope,
            capabilities: capabilities.into_iter().collect(),
            root_hash,
        }
    }

    #[inline]
    #[must_use]
    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }

    #[inline]
    pub fn add_capability(&mut self, cap: Capability) -> bool {
        self.capabilities.insert(cap)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![1, 2, 3], [0u8; 32]);
        assert!(a.capabilities.is_empty());
        assert_eq!(a.rung, Rung::Raw);
        assert_eq!(a.envelope, vec![1, 2, 3]);
    }

    #[test]
    fn with_capabilities_dedupes_via_set() {
        let caps: Vec<Capability> = vec![
            Capability::produces("a", 1),
            Capability::produces("a", 1),
            Capability::produces("b", 2),
        ];
        let a: Artifact = Artifact::with_capabilities(Rung::Mir, vec![], caps, [0u8; 32]);
        assert_eq!(a.capabilities.len(), 2);
    }
}
