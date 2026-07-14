use std::collections::BTreeSet;

pub(crate) const MAX_BOOLEAN_ATOMS: usize = 8;
const MAX_BOOLEAN_PRIMES: usize = 64;
const MAX_BOOLEAN_SEARCH_STEPS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Implicant {
    pub(crate) bits: u16,
    pub(crate) care: u16,
}

impl Implicant {
    #[must_use]
    pub(crate) const fn literal_count(self) -> u32 {
        self.care.count_ones()
    }

    #[must_use]
    pub(crate) const fn covers(self, minterm: u16) -> bool {
        minterm & self.care == self.bits
    }

    const fn combine(self, other: Self) -> Option<Self> {
        if self.care != other.care {
            return None;
        }
        let difference: u16 = (self.bits ^ other.bits) & self.care;
        if difference.count_ones() != 1 {
            return None;
        }
        let care: u16 = self.care & !difference;
        Some(Self {
            bits: self.bits & care,
            care,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cover {
    selected: Vec<bool>,
    terms: usize,
    literals: u32,
}

struct CoverSearch<'a> {
    primes: &'a [Implicant],
    choices: &'a [Vec<usize>],
    selected: Vec<bool>,
    covered: Vec<bool>,
    steps: usize,
    exhausted: bool,
    best: Option<Cover>,
}

impl Cover {
    fn from_selection(primes: &[Implicant], selected: Vec<bool>) -> Self {
        let terms: usize = selected
            .iter()
            .filter(|selected: &&bool| **selected)
            .count();
        let literals: u32 = selected
            .iter()
            .zip(primes.iter())
            .filter_map(|(selected, implicant): (&bool, &Implicant)| {
                if *selected {
                    Some(implicant.literal_count())
                } else {
                    None
                }
            })
            .sum();
        Self {
            selected,
            terms,
            literals,
        }
    }

    fn is_better_than(&self, other: &Self) -> bool {
        (self.terms, self.literals, &self.selected) < (other.terms, other.literals, &other.selected)
    }
}

impl CoverSearch<'_> {
    fn run(&mut self) {
        self.search();
    }

    fn search(&mut self) {
        if self.exhausted {
            return;
        }
        let Some(next_steps): Option<usize> = self.steps.checked_add(1) else {
            self.exhausted = true;
            return;
        };
        self.steps = next_steps;
        if self.steps > MAX_BOOLEAN_SEARCH_STEPS {
            self.exhausted = true;
            return;
        }
        let candidate: Cover = Cover::from_selection(self.primes, self.selected.clone());
        let best: Option<&Cover> = self.best.as_ref();
        if let Some(best) = best
            && (candidate.terms, candidate.literals) > (best.terms, best.literals)
        {
            return;
        }
        let Some(minterm): Option<usize> = self.next_uncovered() else {
            self.record(candidate);
            return;
        };
        let candidates: Vec<usize> = self.choices[minterm].clone();
        for prime in candidates {
            if self.selected[prime] {
                continue;
            }
            self.selected[prime] = true;
            let newly_covered: Vec<usize> = self.mark_covered(prime);
            self.search();
            for index in newly_covered {
                self.covered[index] = false;
            }
            self.selected[prime] = false;
            if self.exhausted {
                return;
            }
        }
    }

    fn next_uncovered(&self) -> Option<usize> {
        self.covered
            .iter()
            .enumerate()
            .filter(|(_, covered): &(usize, &bool)| !**covered)
            .min_by_key(|(index, _): &(usize, &bool)| self.choices[*index].len())
            .map(|(index, _): (usize, &bool)| index)
    }

    fn mark_covered(&mut self, prime: usize) -> Vec<usize> {
        let mut newly_covered: Vec<usize> = Vec::new();
        for (minterm, candidates) in self.choices.iter().enumerate() {
            if !self.covered[minterm] && candidates.contains(&prime) {
                self.covered[minterm] = true;
                newly_covered.push(minterm);
            }
        }
        newly_covered
    }

    fn record(&mut self, candidate: Cover) {
        let replace: bool = self
            .best
            .as_ref()
            .is_none_or(|best: &Cover| candidate.is_better_than(best));
        if replace {
            self.best = Some(candidate);
        }
    }
}

#[must_use]
pub(crate) fn minimize_sop(values: &[bool], atom_count: usize) -> Option<Vec<Implicant>> {
    if atom_count > MAX_BOOLEAN_ATOMS {
        return None;
    }
    let Ok(shift): Result<u32, _> = u32::try_from(atom_count) else {
        return None;
    };
    let expected_len: usize = 1usize.checked_shl(shift)?;
    if values.len() != expected_len {
        return None;
    }
    let mut minterms: Vec<u16> = Vec::new();
    for (index, value) in values.iter().copied().enumerate() {
        if value {
            let Ok(minterm): Result<u16, _> = u16::try_from(index) else {
                return None;
            };
            minterms.push(minterm);
        }
    }
    if minterms.is_empty() {
        return Some(Vec::new());
    }
    let care: u16 = if atom_count == 0 {
        0
    } else {
        (1u16 << atom_count) - 1
    };
    let primes: Vec<Implicant> = prime_implicants(&minterms, care);
    if primes.is_empty() || primes.len() > MAX_BOOLEAN_PRIMES {
        return None;
    }
    select_cover(&primes, &minterms)
}

fn prime_implicants(minterms: &[u16], care: u16) -> Vec<Implicant> {
    let mut current: BTreeSet<Implicant> = BTreeSet::new();
    for minterm in minterms {
        current.insert(Implicant {
            bits: *minterm & care,
            care,
        });
    }
    let mut primes: BTreeSet<Implicant> = BTreeSet::new();
    loop {
        let level: Vec<Implicant> = current.into_iter().collect();
        let mut combined: Vec<bool> = vec![false; level.len()];
        let mut next: BTreeSet<Implicant> = BTreeSet::new();
        for left_index in 0..level.len() {
            let left: Implicant = level[left_index];
            for right_index in (left_index + 1)..level.len() {
                let right: Implicant = level[right_index];
                let merged: Option<Implicant> = left.combine(right);
                if let Some(merged) = merged {
                    combined[left_index] = true;
                    combined[right_index] = true;
                    next.insert(merged);
                }
            }
        }
        for (index, implicant) in level.into_iter().enumerate() {
            if !combined[index] {
                primes.insert(implicant);
            }
        }
        if next.is_empty() {
            return primes.into_iter().collect();
        }
        current = next;
    }
}

fn select_cover(primes: &[Implicant], minterms: &[u16]) -> Option<Vec<Implicant>> {
    let mut choices: Vec<Vec<usize>> = Vec::with_capacity(minterms.len());
    for minterm in minterms {
        let mut covering: Vec<usize> = Vec::new();
        for (index, implicant) in primes.iter().copied().enumerate() {
            if implicant.covers(*minterm) {
                covering.push(index);
            }
        }
        if covering.is_empty() {
            return None;
        }
        choices.push(covering);
    }
    let mut selected: Vec<bool> = vec![false; primes.len()];
    for covering in &choices {
        if covering.len() == 1 {
            selected[covering[0]] = true;
        }
    }
    let mut covered: Vec<bool> = vec![false; minterms.len()];
    for (index, covering) in choices.iter().enumerate() {
        if covering.iter().any(|prime: &usize| selected[*prime]) {
            covered[index] = true;
        }
    }
    let mut search: CoverSearch<'_> = CoverSearch {
        primes,
        choices: &choices,
        selected,
        covered,
        steps: 0,
        exhausted: false,
        best: None,
    };
    search.run();
    if search.exhausted {
        return None;
    }
    let best: Cover = search.best?;
    let result: Vec<Implicant> = best
        .selected
        .iter()
        .zip(primes.iter().copied())
        .filter_map(
            |(selected, implicant): (&bool, Implicant)| {
                if *selected { Some(implicant) } else { None }
            },
        )
        .collect();
    Some(result)
}
