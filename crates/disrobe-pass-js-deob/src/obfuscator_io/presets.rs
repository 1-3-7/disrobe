use std::collections::BTreeSet;

use serde::Serialize;

use super::controls::ObfControl;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Preset {
    Low,
    Medium,
    High,
}

impl Preset {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    #[must_use]
    pub fn controls(self) -> BTreeSet<ObfControl> {
        match self {
            Self::Low => low_controls(),
            Self::Medium => medium_controls(),
            Self::High => high_controls(),
        }
    }

    pub const ALL: [Self; 3] = [Self::Low, Self::Medium, Self::High];
}

fn low_controls() -> BTreeSet<ObfControl> {
    let mut set: BTreeSet<ObfControl> = BTreeSet::new();
    set.insert(ObfControl::Booleans);
    set.insert(ObfControl::Identifiers);
    set.insert(ObfControl::Numbers);
    set.insert(ObfControl::Statements);
    set.insert(ObfControl::Strings);
    set.insert(ObfControl::Minification);
    set
}

fn medium_controls() -> BTreeSet<ObfControl> {
    let mut set: BTreeSet<ObfControl> = low_controls();
    set.insert(ObfControl::ControlFlowFlattening);
    set.insert(ObfControl::Objects);
    set.insert(ObfControl::RegularExpressions);
    set.insert(ObfControl::Variables);
    set
}

fn high_controls() -> BTreeSet<ObfControl> {
    let mut set: BTreeSet<ObfControl> = medium_controls();
    set.insert(ObfControl::FunctionInlining);
    set.insert(ObfControl::Predicates);
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_preset_has_minimal_controls() {
        let controls: BTreeSet<ObfControl> = Preset::Low.controls();
        assert!(controls.contains(&ObfControl::Statements));
        assert!(controls.contains(&ObfControl::Identifiers));
        assert!(!controls.contains(&ObfControl::ControlFlowFlattening));
        assert!(!controls.contains(&ObfControl::FunctionInlining));
    }

    #[test]
    fn medium_preset_is_superset_of_low() {
        let low: BTreeSet<ObfControl> = Preset::Low.controls();
        let medium: BTreeSet<ObfControl> = Preset::Medium.controls();
        assert!(low.is_subset(&medium));
        assert!(medium.contains(&ObfControl::ControlFlowFlattening));
        assert!(medium.contains(&ObfControl::Objects));
    }

    #[test]
    fn high_preset_is_superset_of_medium() {
        let medium: BTreeSet<ObfControl> = Preset::Medium.controls();
        let high: BTreeSet<ObfControl> = Preset::High.controls();
        assert!(medium.is_subset(&high));
        assert!(high.contains(&ObfControl::Predicates));
        assert!(high.contains(&ObfControl::FunctionInlining));
    }
}
