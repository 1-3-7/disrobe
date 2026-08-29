use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{NirFunction, NirModule, NirOp};

use crate::structural::{
    Indeterminate, MatchTier, StructuralMatchReport, StructuralPair, structural_match,
};

pub const MAX_LINEAGE_VARIANTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineageVariant<'a> {
    pub label: &'a str,
    pub module: &'a NirModule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageMember {
    Matched {
        variant: usize,
        address: u64,
        tier: MatchTier,
        possible_outlined: Vec<u64>,
    },
    Absent {
        variant: usize,
        reason: Indeterminate,
    },
}

impl LineageMember {
    #[must_use]
    pub const fn is_matched(&self) -> bool {
        matches!(self, Self::Matched { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantFamily {
    pub anchor_address: u64,
    pub members: Vec<LineageMember>,
}

impl VariantFamily {
    pub const MAX_OUTLINED_FRAGMENTS: usize = 8;

    #[must_use]
    pub fn matched_count(&self) -> usize {
        self.members
            .iter()
            .filter(|member: &&LineageMember| member.is_matched())
            .count()
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.matched_count() == self.members.len()
    }

    #[must_use]
    pub fn tier_of(&self, variant: usize) -> Option<MatchTier> {
        self.members
            .iter()
            .find_map(|member: &LineageMember| match member {
                LineageMember::Matched {
                    variant: candidate,
                    tier,
                    ..
                } if *candidate == variant => Some(*tier),
                _ => None,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageReport {
    pub anchor_label: String,
    pub variant_labels: Vec<String>,
    pub families: Vec<VariantFamily>,
    pub refused: Vec<(usize, Indeterminate)>,
}

impl LineageReport {
    #[must_use]
    pub fn family(&self, anchor_address: u64) -> Option<&VariantFamily> {
        self.families
            .iter()
            .find(|family: &&VariantFamily| family.anchor_address == anchor_address)
    }

    #[must_use]
    pub fn membership(&self) -> (usize, usize) {
        let mut matched: usize = 0;
        let mut possible: usize = 0;
        for family in &self.families {
            for member in &family.members {
                possible += 1;
                if let LineageMember::Matched {
                    possible_outlined, ..
                } = member
                {
                    matched += 1;
                    possible += possible_outlined.len();
                }
            }
        }
        (matched, possible)
    }

    #[must_use]
    pub fn complete_families(&self) -> usize {
        self.families
            .iter()
            .filter(|family: &&VariantFamily| family.is_complete())
            .count()
    }

    #[must_use]
    pub fn grade_named_relations(
        &self,
        anchor_names: &BTreeMap<u64, &str>,
        variant_names: &[BTreeMap<u64, &str>],
    ) -> Option<(usize, usize, usize)> {
        let mut expected: usize = 0;
        let mut reported: usize = 0;
        let mut correct: usize = 0;
        for (&anchor_address, &anchor_name) in anchor_names {
            for (variant, names) in variant_names.iter().enumerate() {
                if names.is_empty() {
                    continue;
                }
                let expected_primary: Option<u64> = names
                    .iter()
                    .find(|&(_, &name): &(&u64, &&str)| name == anchor_name)
                    .map(|(&addr, _): (&u64, &&str)| addr);
                let expected_outlined: BTreeSet<u64> = names
                    .iter()
                    .filter(|&(_, &name): &(&u64, &&str)| {
                        is_outlined_fragment_name(anchor_name, name)
                    })
                    .map(|(&addr, _): (&u64, &&str)| addr)
                    .collect();
                if expected_primary.is_some() {
                    expected += 1;
                }
                expected += expected_outlined.len();

                let Some(LineageMember::Matched {
                    address,
                    possible_outlined,
                    ..
                }) = self
                    .family(anchor_address)
                    .and_then(|family: &VariantFamily| family.members.get(variant))
                else {
                    continue;
                };
                reported += 1;
                if expected_primary == Some(*address) {
                    correct += 1;
                }
                reported += possible_outlined.len();
                for fragment in possible_outlined {
                    if expected_outlined.contains(fragment) {
                        correct += 1;
                    }
                }
            }
        }
        if expected == 0 && reported == 0 {
            return None;
        }
        Some((expected, reported, correct))
    }
}

fn is_outlined_fragment_name(primary: &str, candidate: &str) -> bool {
    candidate.len() > primary.len()
        && candidate.as_bytes().get(primary.len()) == Some(&b'.')
        && candidate.starts_with(primary)
}

fn function_by_address(module: &NirModule, address: u64) -> Option<&NirFunction> {
    module
        .functions
        .iter()
        .find(|function: &&NirFunction| function.address == address)
}

fn call_targets(function: &NirFunction) -> impl Iterator<Item = u64> + '_ {
    function
        .instructions
        .iter()
        .filter_map(|instruction| match instruction.op {
            NirOp::Call {
                target: Some(target),
            } => Some(target),
            _ => None,
        })
}

fn function_addresses(module: &NirModule) -> BTreeSet<u64> {
    module
        .functions
        .iter()
        .map(|function: &NirFunction| function.address)
        .collect()
}

fn call_targets_without_a_body(function: &NirFunction, bodies: &BTreeSet<u64>) -> BTreeSet<u64> {
    call_targets(function)
        .filter(|target: &u64| !bodies.contains(target))
        .collect()
}

fn possible_outlined_by_partner(
    report: &StructuralMatchReport,
    anchor_module: &NirModule,
    variant_module: &NirModule,
) -> BTreeMap<u64, Vec<u64>> {
    let no_candidate: BTreeSet<u64> = report
        .unmatched_other
        .iter()
        .filter(|&&(_, reason): &&(u64, Indeterminate)| reason == Indeterminate::NoCandidate)
        .map(|&(address, _): &(u64, Indeterminate)| address)
        .collect();
    if no_candidate.is_empty() {
        return BTreeMap::new();
    }
    let anchor_of_partner: BTreeMap<u64, u64> = report
        .matches
        .iter()
        .map(|pair: &StructuralPair| (pair.other_address, pair.base_address))
        .collect();

    let mut callers_of: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for function in &variant_module.functions {
        for target in call_targets(function) {
            if no_candidate.contains(&target) {
                callers_of
                    .entry(target)
                    .or_default()
                    .insert(function.address);
            }
        }
    }

    let mut by_partner: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (candidate, callers) in callers_of {
        if callers.len() != 1 {
            continue;
        }
        let Some(&partner) = callers.first() else {
            continue;
        };
        if anchor_of_partner.contains_key(&partner) {
            by_partner.entry(partner).or_default().push(candidate);
        }
    }

    let anchor_bodies: BTreeSet<u64> = function_addresses(anchor_module);
    by_partner.retain(|partner: &u64, fragments: &mut Vec<u64>| {
        anchor_of_partner
            .get(partner)
            .and_then(|&anchor_address: &u64| function_by_address(anchor_module, anchor_address))
            .is_some_and(|anchor_function: &NirFunction| {
                call_targets_without_a_body(anchor_function, &anchor_bodies).len()
                    >= fragments.len()
            })
    });
    for fragments in by_partner.values_mut() {
        fragments.sort_unstable();
        fragments.truncate(VariantFamily::MAX_OUTLINED_FRAGMENTS);
    }
    by_partner
}

fn unmatched_reason(report: &StructuralMatchReport, address: u64) -> Indeterminate {
    report
        .unmatched_base
        .iter()
        .find(|&&(candidate, _): &&(u64, Indeterminate)| candidate == address)
        .map_or(
            Indeterminate::NoCandidate,
            |&(_, reason): &(u64, Indeterminate)| reason,
        )
}

#[must_use]
pub fn variant_lineage(
    anchor: &LineageVariant<'_>,
    variants: &[LineageVariant<'_>],
) -> LineageReport {
    let considered: &[LineageVariant<'_>] = variants
        .get(..variants.len().min(MAX_LINEAGE_VARIANTS))
        .unwrap_or(variants);
    let mut refused: Vec<(usize, Indeterminate)> = Vec::new();
    let mut reports: BTreeMap<usize, StructuralMatchReport> = BTreeMap::new();
    let mut possible_outlined_by_variant: BTreeMap<usize, BTreeMap<u64, Vec<u64>>> =
        BTreeMap::new();
    for (index, variant) in considered.iter().enumerate() {
        if variant.module.lang != anchor.module.lang {
            refused.push((
                index,
                Indeterminate::SourceLanguageMismatch {
                    base: anchor.module.lang,
                    other: variant.module.lang,
                },
            ));
            continue;
        }
        let report: StructuralMatchReport = structural_match(anchor.module, variant.module);
        possible_outlined_by_variant.insert(
            index,
            possible_outlined_by_partner(&report, anchor.module, variant.module),
        );
        reports.insert(index, report);
    }

    let mut families: Vec<VariantFamily> = Vec::with_capacity(anchor.module.functions.len());
    for function in &anchor.module.functions {
        let address: u64 = function.address;
        let mut members: Vec<LineageMember> = Vec::with_capacity(considered.len());
        for index in 0..considered.len() {
            let Some(report): Option<&StructuralMatchReport> = reports.get(&index) else {
                let reason: Indeterminate = refused
                    .iter()
                    .find(|&&(candidate, _): &&(usize, Indeterminate)| candidate == index)
                    .map_or(
                        Indeterminate::NoCandidate,
                        |&(_, reason): &(usize, Indeterminate)| reason,
                    );
                members.push(LineageMember::Absent {
                    variant: index,
                    reason,
                });
                continue;
            };
            match (
                report.matched_partner(address),
                report.matched_tier(address),
            ) {
                (Some(partner), Some(tier)) => {
                    let possible_outlined: Vec<u64> = possible_outlined_by_variant
                        .get(&index)
                        .and_then(|by_partner: &BTreeMap<u64, Vec<u64>>| by_partner.get(&partner))
                        .cloned()
                        .unwrap_or_default();
                    members.push(LineageMember::Matched {
                        variant: index,
                        address: partner,
                        tier,
                        possible_outlined,
                    });
                }
                _ => members.push(LineageMember::Absent {
                    variant: index,
                    reason: unmatched_reason(report, address),
                }),
            }
        }
        families.push(VariantFamily {
            anchor_address: address,
            members,
        });
    }

    LineageReport {
        anchor_label: anchor.label.to_owned(),
        variant_labels: considered
            .iter()
            .map(|variant: &LineageVariant<'_>| variant.label.to_owned())
            .collect(),
        families,
        refused,
    }
}
