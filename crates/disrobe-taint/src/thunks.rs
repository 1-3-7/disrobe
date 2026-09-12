use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ImportThunks {
    by_address: BTreeMap<u64, String>,
}

impl ImportThunks {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_thunk(mut self, address: u64, name: impl AsRef<str>) -> Self {
        self.insert(address, name);
        self
    }

    pub fn insert(&mut self, address: u64, name: impl AsRef<str>) {
        let name: &str = name.as_ref().trim();
        if name.is_empty() {
            return;
        }
        self.by_address.insert(address, name.to_owned());
    }

    #[must_use]
    pub fn from_pairs<S: AsRef<str>>(pairs: impl IntoIterator<Item = (u64, S)>) -> Self {
        let mut thunks: Self = Self::new();
        for (address, name) in pairs {
            thunks.insert(address, name);
        }
        thunks
    }

    #[must_use]
    pub fn name_at(&self, address: u64) -> Option<&str> {
        self.by_address.get(&address).map(String::as_str)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &str)> {
        self.by_address
            .iter()
            .map(|(address, name): (&u64, &String)| (*address, name.as_str()))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_thunk_map_is_keyed_by_the_stub_address_the_call_lands_on() {
        let thunks: ImportThunks = ImportThunks::new()
            .with_thunk(0x13d0, "fgets")
            .with_thunk(0x13e0, "system");
        assert_eq!(thunks.name_at(0x13d0), Some("fgets"));
        assert_eq!(thunks.name_at(0x13e0), Some("system"));
        assert_eq!(thunks.name_at(0x1234), None);
        assert_eq!(thunks.len(), 2);
    }

    #[test]
    fn an_unnamed_stub_is_never_recorded() {
        let mut thunks: ImportThunks = ImportThunks::new();
        thunks.insert(0x100, "");
        thunks.insert(0x104, "   ");
        assert!(
            thunks.is_empty(),
            "a stub the container could not name must stay absent rather than bind an empty name"
        );
    }

    #[test]
    fn pairs_from_a_resolver_build_the_same_map() {
        let thunks: ImportThunks =
            ImportThunks::from_pairs([(0x13d0_u64, "fgets"), (0x13e0_u64, "system")]);
        assert_eq!(
            thunks.iter().collect::<Vec<(u64, &str)>>(),
            vec![(0x13d0, "fgets"), (0x13e0, "system")]
        );
    }
}
