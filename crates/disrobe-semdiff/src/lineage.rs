use std::collections::BTreeMap;

use disrobe_nir::NirModule;

use crate::structural::{Indeterminate, MatchTier, StructuralMatchReport, structural_match};

pub const MAX_LINEAGE_VARIANTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineageVariant<'a> {
    pub label: &'a str,
    pub module: &'a NirModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageMember {
    Matched {
        variant: usize,
        address: u64,
        tier: MatchTier,
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
        let matched: usize = self.families.iter().map(VariantFamily::matched_count).sum();
        let possible: usize = self
            .families
            .iter()
            .map(|family: &VariantFamily| family.members.len())
            .sum();
        (matched, possible)
    }

    #[must_use]
    pub fn complete_families(&self) -> usize {
        self.families
            .iter()
            .filter(|family: &&VariantFamily| family.is_complete())
            .count()
    }
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
        reports.insert(index, structural_match(anchor.module, variant.module));
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
                (Some(partner), Some(tier)) => members.push(LineageMember::Matched {
                    variant: index,
                    address: partner,
                    tier,
                }),
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
