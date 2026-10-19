use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConstantPointers {
    by_slot: BTreeMap<u64, u64>,
}

impl ConstantPointers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_slot(mut self, slot: u64, target: u64) -> Self {
        self.insert(slot, target);
        self
    }

    pub fn insert(&mut self, slot: u64, target: u64) {
        self.by_slot.insert(slot, target);
    }

    #[must_use]
    pub fn from_pairs(pairs: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let mut pointers: Self = Self::new();
        for (slot, target) in pairs {
            pointers.insert(slot, target);
        }
        pointers
    }

    #[must_use]
    pub fn target_at(&self, slot: u64) -> Option<u64> {
        self.by_slot.get(&slot).copied()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_slot.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_slot.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.by_slot
            .iter()
            .map(|(slot, target): (&u64, &u64)| (*slot, *target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_maps_to_the_address_its_relocated_value_names() {
        let pointers: ConstantPointers = ConstantPointers::new()
            .with_slot(0x1_4000_4370, 0x1_4000_7038)
            .with_slot(0x1_4000_4380, 0x1_4000_7040);
        assert_eq!(pointers.target_at(0x1_4000_4370), Some(0x1_4000_7038));
        assert_eq!(pointers.target_at(0x1_4000_4378), None);
        assert_eq!(pointers.len(), 2);
    }

    #[test]
    fn pairs_from_a_relocation_scan_build_the_same_map() {
        let pointers: ConstantPointers =
            ConstantPointers::from_pairs([(0x20_u64, 0x100_u64), (0x10_u64, 0x200_u64)]);
        assert_eq!(
            pointers.iter().collect::<Vec<(u64, u64)>>(),
            vec![(0x10, 0x200), (0x20, 0x100)]
        );
    }
}
