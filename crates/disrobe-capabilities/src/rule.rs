use std::collections::BTreeSet;

use serde::Serialize;

use crate::feature::{Feature, FeatureSet, Scope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountBound {
    Exact(usize),
    AtLeast(usize),
    AtMost(usize),
    Range(usize, usize),
}

impl CountBound {
    #[must_use]
    pub const fn satisfied_by(self, n: usize) -> bool {
        match self {
            Self::Exact(want) => n == want,
            Self::AtLeast(lo) => n >= lo,
            Self::AtMost(hi) => n <= hi,
            Self::Range(lo, hi) => n >= lo && n <= hi,
        }
    }

    fn render(self) -> String {
        match self {
            Self::Exact(want) => format!("= {want}"),
            Self::AtLeast(lo) => format!(">= {lo}"),
            Self::AtMost(hi) => format!("<= {hi}"),
            Self::Range(lo, hi) => format!("{lo}..{hi}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleExpr {
    Feature(Feature),
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
    NOf { n: usize, of: Vec<Self> },
    Optional(Box<Self>),
    Count { feature: Feature, bound: CountBound },
    Match(String),
}

impl RuleExpr {
    #[must_use]
    pub const fn feature(feature: Feature) -> Self {
        Self::Feature(feature)
    }

    #[must_use]
    pub const fn and(children: Vec<Self>) -> Self {
        Self::And(children)
    }

    #[must_use]
    pub const fn or(children: Vec<Self>) -> Self {
        Self::Or(children)
    }

    #[must_use]
    pub fn negate(child: Self) -> Self {
        Self::Not(Box::new(child))
    }

    #[must_use]
    pub const fn n_of(n: usize, of: Vec<Self>) -> Self {
        Self::NOf { n, of }
    }

    #[must_use]
    pub fn optional(child: Self) -> Self {
        Self::Optional(Box::new(child))
    }

    #[must_use]
    pub const fn count(feature: Feature, bound: CountBound) -> Self {
        Self::Count { feature, bound }
    }

    #[must_use]
    pub const fn matches_rule(name: String) -> Self {
        Self::Match(name)
    }

    pub(crate) fn evaluate(
        &self,
        set: &FeatureSet,
        matched: &BTreeSet<String>,
        evidence: &mut Vec<Evidence>,
    ) -> bool {
        match self {
            Self::Feature(feature) => {
                let addrs: Vec<u64> = set.matches(feature);
                if addrs.is_empty() {
                    return false;
                }
                for address in addrs {
                    evidence.push(Evidence {
                        feature: feature.render(),
                        address,
                    });
                }
                true
            }
            Self::And(children) => {
                let mut collected: Vec<Evidence> = Vec::new();
                for child in children {
                    if !child.evaluate(set, matched, &mut collected) {
                        return false;
                    }
                }
                evidence.extend(collected);
                true
            }
            Self::Or(children) => {
                let mut any: bool = false;
                for child in children {
                    let mut branch: Vec<Evidence> = Vec::new();
                    if child.evaluate(set, matched, &mut branch) {
                        any = true;
                        evidence.extend(branch);
                    }
                }
                any
            }
            Self::Not(child) => {
                let mut discard: Vec<Evidence> = Vec::new();
                !child.evaluate(set, matched, &mut discard)
            }
            Self::NOf { n, of } => {
                let mut satisfied: usize = 0;
                let mut collected: Vec<Evidence> = Vec::new();
                for child in of {
                    let mut branch: Vec<Evidence> = Vec::new();
                    if child.evaluate(set, matched, &mut branch) {
                        satisfied += 1;
                        collected.extend(branch);
                    }
                }
                if satisfied >= *n {
                    evidence.extend(collected);
                    true
                } else {
                    false
                }
            }
            Self::Optional(child) => {
                let mut branch: Vec<Evidence> = Vec::new();
                if child.evaluate(set, matched, &mut branch) {
                    evidence.extend(branch);
                }
                true
            }
            Self::Count { feature, bound } => {
                let addrs: Vec<u64> = set.matches(feature);
                if !bound.satisfied_by(addrs.len()) {
                    return false;
                }
                evidence.push(Evidence {
                    feature: format!("count({} {})", feature.render(), bound.render()),
                    address: addrs.first().copied().unwrap_or_default(),
                });
                true
            }
            Self::Match(name) => {
                if matched.contains(name) {
                    evidence.push(Evidence {
                        feature: format!("match({name})"),
                        address: 0,
                    });
                    true
                } else {
                    false
                }
            }
        }
    }

    pub(crate) fn references_rules(&self) -> bool {
        match self {
            Self::Match(_) => true,
            Self::Feature(_) | Self::Count { .. } => false,
            Self::Not(child) | Self::Optional(child) => child.references_rules(),
            Self::And(children) | Self::Or(children) | Self::NOf { of: children, .. } => {
                children.iter().any(Self::references_rules)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: &'static str,
    pub namespace: &'static str,
    pub scope: Scope,
    pub attack: &'static [&'static str],
    pub mbc: &'static [&'static str],
    pub description: &'static str,
    pub expr: RuleExpr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub feature: String,
    pub address: u64,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::feature::{FeatureHit, FeatureValue};

    fn set_with(values: &[(FeatureValue, u64)]) -> FeatureSet {
        let mut set: FeatureSet = FeatureSet::new();
        for (value, address) in values {
            set.push(FeatureHit::new(value.clone(), *address));
        }
        set
    }

    fn no_rules() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn and_requires_every_child_and_collects_each_address() {
        let set: FeatureSet = set_with(&[
            (
                FeatureValue::Api("KERNEL32.dll!CreateFileW".to_owned()),
                0x10,
            ),
            (FeatureValue::Api("KERNEL32.dll!WriteFile".to_owned()), 0x20),
        ]);
        let expr: RuleExpr = RuleExpr::and(vec![
            RuleExpr::feature(Feature::Api("CreateFile".to_owned())),
            RuleExpr::feature(Feature::Api("WriteFile".to_owned())),
        ]);
        let mut evidence: Vec<Evidence> = Vec::new();
        assert!(expr.evaluate(&set, &no_rules(), &mut evidence));
        let addrs: Vec<u64> = evidence.iter().map(|e: &Evidence| e.address).collect();
        assert_eq!(addrs, vec![0x10, 0x20]);
    }

    #[test]
    fn and_fails_when_one_child_absent_and_emits_no_evidence() {
        let set: FeatureSet = set_with(&[(
            FeatureValue::Api("KERNEL32.dll!CreateFileW".to_owned()),
            0x10,
        )]);
        let expr: RuleExpr = RuleExpr::and(vec![
            RuleExpr::feature(Feature::Api("CreateFile".to_owned())),
            RuleExpr::feature(Feature::Api("WriteFile".to_owned())),
        ]);
        let mut evidence: Vec<Evidence> = Vec::new();
        assert!(!expr.evaluate(&set, &no_rules(), &mut evidence));
        assert!(evidence.is_empty());
    }

    #[test]
    fn not_inverts_and_keeps_evidence_clean() {
        let set: FeatureSet = set_with(&[(FeatureValue::Mnemonic("xor".to_owned()), 0x5)]);
        let expr: RuleExpr =
            RuleExpr::negate(RuleExpr::feature(Feature::Mnemonic("aesenc".to_owned())));
        let mut evidence: Vec<Evidence> = Vec::new();
        assert!(expr.evaluate(&set, &no_rules(), &mut evidence));
        assert!(evidence.is_empty());
    }

    #[test]
    fn n_of_needs_at_least_n_satisfied() {
        let set: FeatureSet = set_with(&[
            (
                FeatureValue::Api("KERNEL32.dll!IsDebuggerPresent".to_owned()),
                0x1,
            ),
            (
                FeatureValue::Api("KERNEL32.dll!GetTickCount".to_owned()),
                0x2,
            ),
        ]);
        let expr: RuleExpr = RuleExpr::n_of(
            2,
            vec![
                RuleExpr::feature(Feature::Api("IsDebuggerPresent".to_owned())),
                RuleExpr::feature(Feature::Api("GetTickCount".to_owned())),
                RuleExpr::feature(Feature::Api("OutputDebugString".to_owned())),
            ],
        );
        let mut evidence: Vec<Evidence> = Vec::new();
        assert!(expr.evaluate(&set, &no_rules(), &mut evidence));

        let too_high: RuleExpr = RuleExpr::n_of(
            3,
            vec![
                RuleExpr::feature(Feature::Api("IsDebuggerPresent".to_owned())),
                RuleExpr::feature(Feature::Api("GetTickCount".to_owned())),
                RuleExpr::feature(Feature::Api("OutputDebugString".to_owned())),
            ],
        );
        let mut none: Vec<Evidence> = Vec::new();
        assert!(!too_high.evaluate(&set, &no_rules(), &mut none));
        assert!(none.is_empty());
    }

    #[test]
    fn optional_is_always_true_and_collects_when_present() {
        let present: FeatureSet = set_with(&[(FeatureValue::Mnemonic("rdtsc".to_owned()), 0x9)]);
        let expr: RuleExpr =
            RuleExpr::optional(RuleExpr::feature(Feature::Mnemonic("rdtsc".to_owned())));
        let mut evidence: Vec<Evidence> = Vec::new();
        assert!(expr.evaluate(&present, &no_rules(), &mut evidence));
        assert_eq!(evidence.len(), 1);

        let absent: FeatureSet = set_with(&[(FeatureValue::Mnemonic("nop".to_owned()), 0x9)]);
        let mut empty: Vec<Evidence> = Vec::new();
        assert!(expr.evaluate(&absent, &no_rules(), &mut empty));
        assert!(empty.is_empty());
    }

    #[test]
    fn count_bounds_gate_on_tally() {
        let set: FeatureSet = set_with(&[
            (FeatureValue::Mnemonic("push".to_owned()), 0x1),
            (FeatureValue::Mnemonic("push".to_owned()), 0x2),
            (FeatureValue::Mnemonic("push".to_owned()), 0x3),
        ]);
        let at_least: RuleExpr =
            RuleExpr::count(Feature::Mnemonic("push".to_owned()), CountBound::AtLeast(3));
        let mut ev: Vec<Evidence> = Vec::new();
        assert!(at_least.evaluate(&set, &no_rules(), &mut ev));
        assert_eq!(ev.len(), 1);

        let exact_two: RuleExpr =
            RuleExpr::count(Feature::Mnemonic("push".to_owned()), CountBound::Exact(2));
        let mut none: Vec<Evidence> = Vec::new();
        assert!(!exact_two.evaluate(&set, &no_rules(), &mut none));

        let range: RuleExpr = RuleExpr::count(
            Feature::Mnemonic("push".to_owned()),
            CountBound::Range(2, 4),
        );
        let mut ok: Vec<Evidence> = Vec::new();
        assert!(range.evaluate(&set, &no_rules(), &mut ok));
    }

    #[test]
    fn match_resolves_against_already_matched_rules() {
        let set: FeatureSet = FeatureSet::new();
        let mut matched: BTreeSet<String> = BTreeSet::new();
        matched.insert("write file".to_owned());
        let expr: RuleExpr = RuleExpr::matches_rule("write file".to_owned());
        let mut ev: Vec<Evidence> = Vec::new();
        assert!(expr.evaluate(&set, &matched, &mut ev));
        assert_eq!(ev.len(), 1);

        let other: RuleExpr = RuleExpr::matches_rule("delete file".to_owned());
        let mut none: Vec<Evidence> = Vec::new();
        assert!(!other.evaluate(&set, &matched, &mut none));
    }

    #[test]
    fn references_rules_detects_match_nodes() {
        let plain: RuleExpr = RuleExpr::feature(Feature::Mnemonic("xor".to_owned()));
        assert!(!plain.references_rules());
        let composite: RuleExpr = RuleExpr::and(vec![
            RuleExpr::feature(Feature::Mnemonic("xor".to_owned())),
            RuleExpr::matches_rule("write file".to_owned()),
        ]);
        assert!(composite.references_rules());
    }
}
