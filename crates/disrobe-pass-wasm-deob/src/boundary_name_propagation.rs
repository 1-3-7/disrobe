use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::boundary_links::{
    BoundaryLinks, BoundarySymbol, MAX_BOUNDARY_LINK_STRING_BYTES, MAX_BOUNDARY_LINKS,
};
use thiserror::Error;

pub const MAX_BOUNDARY_NAME_SEEDS: usize = 256;
pub const MAX_BOUNDARY_NAME_PROPAGATION_WORK: usize =
    MAX_BOUNDARY_NAME_SEEDS * MAX_BOUNDARY_LINKS * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundaryNameConfidence {
    Low,
    Certain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundaryNameEvidence {
    NameSection { function_index: u32 },
    SourceMap { name_index: u32 },
    MatchingArity { parameters: u32, results: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredBoundaryName {
    origin: BoundarySymbol,
    symbol: BoundarySymbol,
    name: String,
    confidence: BoundaryNameConfidence,
    evidence: BoundaryNameEvidence,
    link_path: Vec<usize>,
}

impl RecoveredBoundaryName {
    pub fn seed(
        symbol: BoundarySymbol,
        name: String,
        confidence: BoundaryNameConfidence,
        evidence: BoundaryNameEvidence,
    ) -> Result<Self, BoundaryNamePropagationError> {
        validate_name(&name)?;
        if confidence == BoundaryNameConfidence::Certain
            && matches!(evidence, BoundaryNameEvidence::MatchingArity { .. })
        {
            return Err(BoundaryNamePropagationError::CertainArityOnly);
        }
        Ok(Self {
            origin: symbol.clone(),
            symbol,
            name,
            confidence,
            evidence,
            link_path: Vec::new(),
        })
    }

    #[inline]
    #[must_use]
    pub const fn origin(&self) -> &BoundarySymbol {
        &self.origin
    }

    #[inline]
    #[must_use]
    pub const fn symbol(&self) -> &BoundarySymbol {
        &self.symbol
    }

    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    #[must_use]
    pub const fn confidence(&self) -> BoundaryNameConfidence {
        self.confidence
    }

    #[inline]
    #[must_use]
    pub const fn evidence(&self) -> BoundaryNameEvidence {
        self.evidence
    }

    #[inline]
    #[must_use]
    pub fn link_path(&self) -> &[usize] {
        &self.link_path
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundaryNamePropagationError {
    #[error("boundary name is empty")]
    EmptyName,
    #[error("boundary name has {size} bytes, exceeding the {maximum}-byte limit")]
    NameTooLong { size: usize, maximum: usize },
    #[error("arity-only name evidence cannot carry certain confidence")]
    CertainArityOnly,
    #[error("boundary-name input has {count} roots, exceeding the {maximum}-root limit")]
    TooManyNames { count: usize, maximum: usize },
    #[error("boundary-name seed {seed_index} does not identify an endpoint in the link graph")]
    UnknownSeedSymbol { seed_index: usize },
    #[error("boundary-name propagation exceeded its {maximum}-step work limit")]
    WorkLimitExceeded { maximum: usize },
    #[error("boundary-name propagation could not reconstruct a validated link path")]
    PathReconstructionFailed,
}

pub fn propagate_boundary_names(
    links: &BoundaryLinks,
    names: &[RecoveredBoundaryName],
) -> Result<Vec<RecoveredBoundaryName>, BoundaryNamePropagationError> {
    let input_roots: Vec<RecoveredBoundaryName> = names
        .iter()
        .filter(|name: &&RecoveredBoundaryName| name.link_path.is_empty())
        .cloned()
        .collect();
    if input_roots.len() > MAX_BOUNDARY_NAME_SEEDS {
        return Err(BoundaryNamePropagationError::TooManyNames {
            count: input_roots.len(),
            maximum: MAX_BOUNDARY_NAME_SEEDS,
        });
    }
    let adjacency: Adjacency = build_adjacency(links);
    let mut roots: BTreeMap<BoundarySymbol, RecoveredBoundaryName> = BTreeMap::new();
    for (seed_index, root) in input_roots.into_iter().enumerate() {
        validate_name(&root.name)?;
        if root.confidence == BoundaryNameConfidence::Certain
            && matches!(root.evidence, BoundaryNameEvidence::MatchingArity { .. })
        {
            return Err(BoundaryNamePropagationError::CertainArityOnly);
        }
        if !adjacency.contains_key(&root.symbol) {
            return Err(BoundaryNamePropagationError::UnknownSeedSymbol { seed_index });
        }
        match roots.get(&root.symbol) {
            Some(current) if !seed_preferred(&root, current) => {}
            _ => {
                roots.insert(root.symbol.clone(), root);
            }
        }
    }
    let mut assignments: BTreeMap<BoundarySymbol, RecoveredBoundaryName> = roots.clone();
    let mut work: usize = 0;
    for (origin, root) in &roots {
        let parents: Parents = breadth_first_parents(origin, &adjacency, &mut work)?;
        for target in parents.keys() {
            if target == origin || roots.contains_key(target) {
                continue;
            }
            let path: Vec<usize> = reconstruct_path(origin, target, &parents, &mut work)?;
            let candidate: RecoveredBoundaryName = RecoveredBoundaryName {
                origin: origin.clone(),
                symbol: target.clone(),
                name: root.name.clone(),
                confidence: root.confidence,
                evidence: root.evidence,
                link_path: path,
            };
            match assignments.get(target) {
                Some(current) if !propagation_preferred(&candidate, current) => {}
                _ => {
                    assignments.insert(target.clone(), candidate);
                }
            }
        }
    }
    disambiguate_receiver_names(&adjacency, &mut assignments, &mut work)?;
    Ok(assignments.into_values().collect())
}

const fn validate_name(name: &str) -> Result<(), BoundaryNamePropagationError> {
    if name.is_empty() {
        return Err(BoundaryNamePropagationError::EmptyName);
    }
    if name.len() > MAX_BOUNDARY_LINK_STRING_BYTES {
        return Err(BoundaryNamePropagationError::NameTooLong {
            size: name.len(),
            maximum: MAX_BOUNDARY_LINK_STRING_BYTES,
        });
    }
    Ok(())
}

type Adjacency = BTreeMap<BoundarySymbol, Vec<(BoundarySymbol, usize)>>;
type Parents = BTreeMap<BoundarySymbol, Option<(BoundarySymbol, usize)>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NameScope {
    language: String,
    module: Option<String>,
}

fn build_adjacency(links: &BoundaryLinks) -> Adjacency {
    let mut adjacency: Adjacency = BTreeMap::new();
    for (link_index, link) in links.links().iter().enumerate() {
        adjacency
            .entry(link.source.clone())
            .or_default()
            .push((link.target.clone(), link_index));
        adjacency
            .entry(link.target.clone())
            .or_default()
            .push((link.source.clone(), link_index));
    }
    for edges in adjacency.values_mut() {
        edges.sort_unstable();
        edges.dedup();
    }
    adjacency
}

fn breadth_first_parents(
    origin: &BoundarySymbol,
    adjacency: &Adjacency,
    work: &mut usize,
) -> Result<Parents, BoundaryNamePropagationError> {
    let mut parents: Parents = BTreeMap::from([(origin.clone(), None)]);
    let mut pending: VecDeque<BoundarySymbol> = VecDeque::from([origin.clone()]);
    while let Some(current) = pending.pop_front() {
        let edges: &[(BoundarySymbol, usize)] = adjacency.get(&current).map_or(&[], Vec::as_slice);
        for (target, link_index) in edges {
            claim_work(work)?;
            if parents.contains_key(target) {
                continue;
            }
            parents.insert(target.clone(), Some((current.clone(), *link_index)));
            pending.push_back(target.clone());
        }
    }
    Ok(parents)
}

fn reconstruct_path(
    origin: &BoundarySymbol,
    target: &BoundarySymbol,
    parents: &Parents,
    work: &mut usize,
) -> Result<Vec<usize>, BoundaryNamePropagationError> {
    let mut reversed: Vec<usize> = Vec::new();
    let mut current: BoundarySymbol = target.clone();
    while &current != origin {
        claim_work(work)?;
        let Some(Some((parent, link_index))): Option<&Option<(BoundarySymbol, usize)>> =
            parents.get(&current)
        else {
            return Err(BoundaryNamePropagationError::PathReconstructionFailed);
        };
        reversed.push(*link_index);
        current = parent.clone();
    }
    reversed.reverse();
    Ok(reversed)
}

fn seed_preferred(candidate: &RecoveredBoundaryName, current: &RecoveredBoundaryName) -> bool {
    candidate.confidence > current.confidence
        || candidate.confidence == current.confidence
            && (evidence_strength(candidate.evidence) > evidence_strength(current.evidence)
                || evidence_strength(candidate.evidence) == evidence_strength(current.evidence)
                    && candidate.name < current.name)
}

fn propagation_preferred(
    candidate: &RecoveredBoundaryName,
    current: &RecoveredBoundaryName,
) -> bool {
    seed_preferred(candidate, current)
        || candidate.confidence == current.confidence
            && evidence_strength(candidate.evidence) == evidence_strength(current.evidence)
            && candidate.name == current.name
            && (candidate.link_path.len() < current.link_path.len()
                || candidate.link_path.len() == current.link_path.len()
                    && candidate.origin < current.origin)
}

const fn evidence_strength(evidence: BoundaryNameEvidence) -> u8 {
    match evidence {
        BoundaryNameEvidence::NameSection { .. } => 3,
        BoundaryNameEvidence::SourceMap { .. } => 2,
        BoundaryNameEvidence::MatchingArity { .. } => 1,
    }
}

fn disambiguate_receiver_names(
    adjacency: &Adjacency,
    assignments: &mut BTreeMap<BoundarySymbol, RecoveredBoundaryName>,
    work: &mut usize,
) -> Result<(), BoundaryNamePropagationError> {
    let mut used: BTreeMap<NameScope, BTreeMap<String, BTreeSet<BoundarySymbol>>> = BTreeMap::new();
    for symbol in adjacency.keys() {
        reserve_name(&mut used, symbol, &symbol.name);
    }
    for assignment in assignments.values_mut() {
        if assignment.link_path.is_empty() {
            reserve_name(&mut used, &assignment.symbol, &assignment.name);
            continue;
        }
        let scope: NameScope = name_scope(&assignment.symbol);
        let mut candidate: String = assignment.name.clone();
        let mut suffix_index: usize = 2;
        while name_is_owned_by_other(&used, &scope, &candidate, &assignment.symbol) {
            claim_work(work)?;
            candidate = suffixed_name(&assignment.name, suffix_index);
            suffix_index = suffix_index.saturating_add(1);
        }
        assignment.name = candidate;
        reserve_name(&mut used, &assignment.symbol, &assignment.name);
    }
    Ok(())
}

fn name_scope(symbol: &BoundarySymbol) -> NameScope {
    NameScope {
        language: symbol.language.as_str().to_owned(),
        module: symbol.module.clone(),
    }
}

fn reserve_name(
    used: &mut BTreeMap<NameScope, BTreeMap<String, BTreeSet<BoundarySymbol>>>,
    symbol: &BoundarySymbol,
    name: &str,
) {
    used.entry(name_scope(symbol))
        .or_default()
        .entry(name.to_owned())
        .or_default()
        .insert(symbol.clone());
}

fn name_is_owned_by_other(
    used: &BTreeMap<NameScope, BTreeMap<String, BTreeSet<BoundarySymbol>>>,
    scope: &NameScope,
    name: &str,
    symbol: &BoundarySymbol,
) -> bool {
    used.get(scope)
        .and_then(|names: &BTreeMap<String, BTreeSet<BoundarySymbol>>| names.get(name))
        .is_some_and(|owners: &BTreeSet<BoundarySymbol>| {
            owners.iter().any(|owner: &BoundarySymbol| owner != symbol)
        })
}

fn suffixed_name(base: &str, suffix_index: usize) -> String {
    let suffix: String = format!("_{suffix_index}");
    let available: usize = MAX_BOUNDARY_LINK_STRING_BYTES.saturating_sub(suffix.len());
    let mut end: usize = base.len().min(available);
    while !base.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}{suffix}", &base[..end])
}

const fn claim_work(work: &mut usize) -> Result<(), BoundaryNamePropagationError> {
    *work = work.saturating_add(1);
    if *work > MAX_BOUNDARY_NAME_PROPAGATION_WORK {
        return Err(BoundaryNamePropagationError::WorkLimitExceeded {
            maximum: MAX_BOUNDARY_NAME_PROPAGATION_WORK,
        });
    }
    Ok(())
}
