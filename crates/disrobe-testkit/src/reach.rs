use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedReach {
    driven: usize,
    surfaces: BTreeSet<&'static str>,
}

impl SeedReach {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            driven: 0usize,
            surfaces: BTreeSet::new(),
        }
    }

    pub const fn drove(&mut self) {
        self.driven = self.driven.saturating_add(1usize);
    }

    pub fn reached(&mut self, surface: &'static str) {
        self.driven = self.driven.saturating_add(1usize);
        self.surfaces.insert(surface);
    }

    pub fn record(&mut self, surface: &'static str, produced: bool) {
        if produced {
            self.reached(surface);
        } else {
            self.drove();
        }
    }

    pub fn record_len(&mut self, surface: &'static str, produced: usize) {
        self.record(surface, produced > 0usize);
    }

    pub fn record_result<T, E>(
        &mut self,
        surface: &'static str,
        outcome: &Result<T, E>,
        produced: impl FnOnce(&T) -> bool,
    ) {
        match outcome {
            Ok(value) => self.record(surface, produced(value)),
            Err(_) => self.drove(),
        }
    }

    #[must_use]
    pub const fn driven(&self) -> usize {
        self.driven
    }

    #[must_use]
    pub fn surfaces(&self) -> Vec<&'static str> {
        self.surfaces.iter().copied().collect()
    }

    #[must_use]
    pub fn is_inert(&self) -> bool {
        self.surfaces.is_empty()
    }

    #[must_use]
    pub fn reaches(&self, surface: &str) -> bool {
        self.surfaces.contains(surface)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapelessSeed {
    pub name: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct ReachTally {
    reaching: Vec<String>,
    inert: Vec<String>,
    exempt: Vec<String>,
}

impl ReachTally {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn observe(&mut self, seed: &str, reach: &SeedReach, shapeless: &[ShapelessSeed]) {
        assert!(
            reach.driven() > 0usize,
            "no entry point ran for the `{seed}` seed, so this suite mutates bytes nothing reads"
        );
        let exemption: Option<&ShapelessSeed> = shapeless
            .iter()
            .find(|entry: &&ShapelessSeed| entry.name == seed);
        match (exemption, reach.is_inert()) {
            (Some(_), _) => self.exempt.push(seed.to_owned()),
            (None, true) => self.inert.push(seed.to_owned()),
            (None, false) => self
                .reaching
                .push(format!("{seed} -> {:?}", reach.surfaces())),
        }
    }

    #[must_use]
    pub const fn reaching(&self) -> usize {
        self.reaching.len()
    }

    #[must_use]
    pub const fn inert(&self) -> usize {
        self.inert.len()
    }

    #[must_use]
    pub const fn exempt(&self) -> usize {
        self.exempt.len()
    }

    #[must_use]
    pub const fn total(&self) -> usize {
        self.reaching() + self.inert() + self.exempt()
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn assert_every_seed_reaches(&self, suite: &str) {
        assert!(
            self.inert.is_empty(),
            "{} of {} `{suite}` seeds never reach the surface they are named for, so every \
             mutation of them exercises a branch the parser does not enter: {:?}. Give each one the \
             shape its name claims, or declare it shapeless with a reason.",
            self.inert.len(),
            self.total(),
            self.inert
        );
        assert!(
            self.reaching() > 0usize,
            "no `{suite}` seed reaches any surface, so this suite measures nothing"
        );
    }

    #[must_use]
    pub fn summary(&self, suite: &str) -> String {
        let mut out: String = format!(
            "SEED REACH {suite}: {} of {} seeds reach a named surface, {} declared shapeless, {} \
             inert",
            self.reaching(),
            self.total(),
            self.exempt(),
            self.inert()
        );
        for line in &self.reaching {
            out.push_str("\n  reaches  ");
            out.push_str(line);
        }
        for line in &self.exempt {
            out.push_str("\n  shapeless ");
            out.push_str(line);
        }
        for line in &self.inert {
            out.push_str("\n  INERT    ");
            out.push_str(line);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_that_only_drove_entry_points_is_inert() {
        let mut reach: SeedReach = SeedReach::new();
        reach.drove();
        reach.drove();
        assert!(reach.is_inert());
        assert_eq!(reach.driven(), 2usize);
    }

    #[test]
    fn a_seed_that_produced_a_structure_reaches_that_surface() {
        let mut reach: SeedReach = SeedReach::new();
        reach.record_len("images", 2usize);
        reach.record_len("resources", 0usize);
        assert!(!reach.is_inert());
        assert!(reach.reaches("images"));
        assert!(!reach.reaches("resources"));
        assert_eq!(reach.driven(), 2usize);
    }

    #[test]
    fn an_ok_result_carrying_nothing_does_not_count_as_reach() {
        let mut reach: SeedReach = SeedReach::new();
        let empty: Result<Vec<u8>, ()> = Ok(Vec::new());
        reach.record_result("parse", &empty, |value: &Vec<u8>| !value.is_empty());
        assert!(
            reach.is_inert(),
            "an Ok that recovered nothing is exactly the wim case and must not count"
        );
    }

    #[test]
    fn a_declared_shapeless_seed_is_counted_separately_from_an_inert_one() {
        const SHAPELESS: [ShapelessSeed; 1] = [ShapelessSeed {
            name: "empty",
            reason: "the zero-length input every entry point must refuse",
        }];
        let mut tally: ReachTally = ReachTally::new();
        let mut inert: SeedReach = SeedReach::new();
        inert.drove();
        tally.observe("empty", &inert, &SHAPELESS);
        let mut shaped: SeedReach = SeedReach::new();
        shaped.record_len("parse", 1usize);
        tally.observe("real", &shaped, &SHAPELESS);

        assert_eq!(tally.exempt(), 1usize);
        assert_eq!(tally.reaching(), 1usize);
        assert_eq!(tally.inert(), 0usize);
        tally.assert_every_seed_reaches("probe");
    }

    #[test]
    #[should_panic(expected = "never reach the surface they are named for")]
    fn an_undeclared_inert_seed_fails_the_suite() {
        let mut tally: ReachTally = ReachTally::new();
        let mut inert: SeedReach = SeedReach::new();
        inert.drove();
        tally.observe("wim-archive", &inert, &[]);
        tally.assert_every_seed_reaches("probe");
    }

    #[test]
    #[should_panic(expected = "no entry point ran")]
    fn a_seed_no_entry_point_ran_against_fails_the_suite() {
        let mut tally: ReachTally = ReachTally::new();
        tally.observe("unused", &SeedReach::new(), &[]);
    }
}
