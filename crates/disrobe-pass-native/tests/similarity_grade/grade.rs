use std::collections::{BTreeMap, BTreeSet};

use crate::truth::{Address, Correspondence, SizeBand, TruthTable};

const PER_MILLE: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Stage {
    DataReference,
    ControlFlow,
    Propagation,
}

impl Stage {
    pub(crate) const ALL: [Self; 3] = [Self::DataReference, Self::ControlFlow, Self::Propagation];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DataReference => "data-reference",
            Self::ControlFlow => "control-flow",
            Self::Propagation => "propagation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Paired { counterpart: Address, stage: Stage },
    Declined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Emission {
    pub(crate) subject: Address,
    pub(crate) outcome: Outcome,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tally {
    pub(crate) recovered: usize,
    pub(crate) wrong: usize,
    pub(crate) refused: usize,
    pub(crate) missed: usize,
    pub(crate) unbacked: usize,
    pub(crate) unjudged: usize,
}

impl Tally {
    pub(crate) const fn expected(&self) -> usize {
        self.recovered + self.wrong + self.refused + self.missed
    }

    pub(crate) const fn judged_emissions(&self) -> usize {
        self.recovered + self.wrong + self.unbacked
    }

    pub(crate) const fn precision_permille(&self) -> u64 {
        rate(self.recovered, self.judged_emissions())
    }

    pub(crate) const fn recall_permille(&self) -> u64 {
        rate(self.recovered, self.expected())
    }

    const fn add(&mut self, other: &Self) {
        self.recovered += other.recovered;
        self.wrong += other.wrong;
        self.refused += other.refused;
        self.missed += other.missed;
        self.unbacked += other.unbacked;
        self.unjudged += other.unjudged;
    }
}

pub(crate) const fn rate(numerator: usize, denominator: usize) -> u64 {
    let denominator: u64 = denominator as u64;
    if denominator == 0 {
        return 0;
    }
    (numerator as u64).saturating_mul(PER_MILLE) / denominator
}

#[derive(Debug, Clone)]
pub(crate) struct WrongMatch {
    pub(crate) subject: Address,
    pub(crate) produced: Address,
    pub(crate) stage: Stage,
    pub(crate) names: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub(crate) struct Grade {
    pub(crate) overall: Tally,
    pub(crate) per_stage: BTreeMap<Stage, Tally>,
    pub(crate) per_band: BTreeMap<SizeBand, Tally>,
    pub(crate) changed: Tally,
    pub(crate) identical: Tally,
    pub(crate) wrong_matches: Vec<WrongMatch>,
    pub(crate) folded_recovered: usize,
}

impl Grade {
    pub(crate) fn stage(&self, stage: Stage) -> Tally {
        self.per_stage.get(&stage).copied().unwrap_or_default()
    }

    pub(crate) fn band(&self, band: SizeBand) -> Tally {
        self.per_band.get(&band).copied().unwrap_or_default()
    }

    pub(crate) fn absorb(&mut self, other: &Self) {
        self.overall.add(&other.overall);
        self.changed.add(&other.changed);
        self.identical.add(&other.identical);
        self.folded_recovered += other.folded_recovered;
        for (stage, tally) in &other.per_stage {
            self.per_stage.entry(*stage).or_default().add(tally);
        }
        for (band, tally) in &other.per_band {
            self.per_band.entry(*band).or_default().add(tally);
        }
        self.wrong_matches
            .extend(other.wrong_matches.iter().cloned());
    }
}

pub(crate) fn grade(emissions: &[Emission], truth: &TruthTable) -> Grade {
    let seen: BTreeMap<Address, Outcome> = emissions
        .iter()
        .map(|emission: &Emission| (emission.subject, emission.outcome))
        .collect();
    let mut report: Grade = Grade::default();

    for (address, expected) in &truth.entries {
        let verdict: Verdict = match seen.get(address) {
            Some(Outcome::Paired { counterpart, stage }) => {
                if expected.accepted.contains(counterpart) {
                    Verdict::Recovered(*stage)
                } else {
                    Verdict::Wrong {
                        stage: *stage,
                        produced: *counterpart,
                    }
                }
            }
            Some(Outcome::Declined) => Verdict::Refused,
            None => Verdict::Missed,
        };
        record(&mut report, expected, &verdict);
    }

    for emission in emissions {
        let Outcome::Paired { stage, .. } = emission.outcome else {
            continue;
        };
        if truth.entries.contains_key(&emission.subject) {
            continue;
        }
        if truth.left_only.contains(&emission.subject) {
            report.per_stage.entry(stage).or_default().unbacked += 1;
            report.overall.unbacked += 1;
            report.changed.unbacked += 1;
            if let Some(band) = truth.band_of.get(&emission.subject) {
                report.per_band.entry(*band).or_default().unbacked += 1;
            }
        } else {
            report.per_stage.entry(stage).or_default().unjudged += 1;
            report.overall.unjudged += 1;
        }
    }

    report
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Recovered(Stage),
    Wrong { stage: Stage, produced: Address },
    Refused,
    Missed,
}

const fn bump(target: &mut Tally, verdict: &Verdict) {
    match *verdict {
        Verdict::Recovered(_) => target.recovered += 1,
        Verdict::Wrong { .. } => target.wrong += 1,
        Verdict::Refused => target.refused += 1,
        Verdict::Missed => target.missed += 1,
    }
}

fn record(report: &mut Grade, expected: &Correspondence, verdict: &Verdict) {
    bump(report.per_band.entry(expected.band).or_default(), verdict);
    bump(&mut report.overall, verdict);
    if expected.unchanged {
        bump(&mut report.identical, verdict);
    } else {
        bump(&mut report.changed, verdict);
    }
    match *verdict {
        Verdict::Recovered(stage) => {
            report.per_stage.entry(stage).or_default().recovered += 1;
            if expected.folded {
                report.folded_recovered += 1;
            }
        }
        Verdict::Wrong { stage, produced } => {
            report.per_stage.entry(stage).or_default().wrong += 1;
            report.wrong_matches.push(WrongMatch {
                subject: expected.left,
                produced,
                stage,
                names: expected.names.clone(),
            });
        }
        Verdict::Refused | Verdict::Missed => {}
    }
}
