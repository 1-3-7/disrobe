use crate::equiv::{equivalent, screened_equivalent};
use crate::rng::SeededRng;
use crate::term::{Op, Term, Width};

pub const MAX_EXPANSION_NODES: usize = 4096;
pub const MAX_DRAWS_PER_ROUND: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    Linear,
    Polynomial,
    Mixed,
}

impl Family {
    pub const ALL: [Self; 3] = [Self::Linear, Self::Polynomial, Self::Mixed];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Linear => "linear",
            Self::Polynomial => "polynomial",
            Self::Mixed => "mixed",
        }
    }

    #[must_use]
    pub const fn rounds(self) -> usize {
        match self {
            Self::Linear => 3,
            Self::Polynomial => 2,
            Self::Mixed => 4,
        }
    }

    #[must_use]
    const fn admits(self, rule: Rule) -> bool {
        match self {
            Self::Linear => rule.is_linear(),
            Self::Polynomial => rule.is_linear() || rule.is_polynomial(),
            Self::Mixed => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Rule {
    AddXorCarry,
    AddOrAnd,
    AddDoubleOr,
    AddSubNot,
    SubAddNot,
    XorOrMinusAnd,
    XorSumMinusTwiceAnd,
    AndSumMinusOr,
    AndOrMinusXor,
    OrSumMinusAnd,
    OrXorPlusAnd,
    NotNegMinusOne,
    NegNotPlusOne,
    DoubleNot,
    DoubleNeg,
    ZeroAdd,
    ZeroXor,
    MulSplit,
    ConstantRound,
}

impl Rule {
    const ALL: [Self; 19] = [
        Self::AddXorCarry,
        Self::AddOrAnd,
        Self::AddDoubleOr,
        Self::AddSubNot,
        Self::SubAddNot,
        Self::XorOrMinusAnd,
        Self::XorSumMinusTwiceAnd,
        Self::AndSumMinusOr,
        Self::AndOrMinusXor,
        Self::OrSumMinusAnd,
        Self::OrXorPlusAnd,
        Self::NotNegMinusOne,
        Self::NegNotPlusOne,
        Self::DoubleNot,
        Self::DoubleNeg,
        Self::ZeroAdd,
        Self::ZeroXor,
        Self::MulSplit,
        Self::ConstantRound,
    ];

    const fn is_linear(self) -> bool {
        matches!(
            self,
            Self::AddXorCarry
                | Self::AddOrAnd
                | Self::AddDoubleOr
                | Self::AddSubNot
                | Self::SubAddNot
                | Self::XorOrMinusAnd
                | Self::XorSumMinusTwiceAnd
                | Self::AndSumMinusOr
                | Self::AndOrMinusXor
                | Self::OrSumMinusAnd
                | Self::OrXorPlusAnd
                | Self::NotNegMinusOne
                | Self::NegNotPlusOne
                | Self::DoubleNot
                | Self::DoubleNeg
                | Self::ZeroAdd
                | Self::ZeroXor
        )
    }

    const fn is_polynomial(self) -> bool {
        matches!(self, Self::MulSplit | Self::ConstantRound)
    }

    const fn is_structural(self) -> bool {
        !matches!(
            self,
            Self::DoubleNot | Self::DoubleNeg | Self::ZeroAdd | Self::ZeroXor | Self::ConstantRound
        )
    }

    fn matches(self, target: &Term) -> bool {
        match self {
            Self::AddXorCarry | Self::AddOrAnd | Self::AddDoubleOr | Self::AddSubNot => {
                binary(target, Op::Add).is_some()
            }
            Self::SubAddNot => binary(target, Op::Sub).is_some(),
            Self::XorOrMinusAnd | Self::XorSumMinusTwiceAnd => binary(target, Op::Xor).is_some(),
            Self::AndSumMinusOr | Self::AndOrMinusXor => binary(target, Op::And).is_some(),
            Self::OrSumMinusAnd | Self::OrXorPlusAnd => binary(target, Op::Or).is_some(),
            Self::MulSplit => binary(target, Op::Mul).is_some(),
            Self::NotNegMinusOne => matches!(target, Term::Not(_)),
            Self::NegNotPlusOne => matches!(target, Term::Neg(_)),
            Self::DoubleNot
            | Self::DoubleNeg
            | Self::ConstantRound
            | Self::ZeroAdd
            | Self::ZeroXor => true,
        }
    }

    fn expand(self, target: &Term, rng: &mut SeededRng, var_count: u32) -> Option<Term> {
        match self {
            Self::AddXorCarry => binary(target, Op::Add).map(|(left, right): (&Term, &Term)| {
                Term::add(
                    Term::xor(left.clone(), right.clone()),
                    Term::mul(Term::constant(2), Term::and(left.clone(), right.clone())),
                )
            }),
            Self::AddOrAnd => binary(target, Op::Add).map(|(left, right): (&Term, &Term)| {
                Term::add(
                    Term::or(left.clone(), right.clone()),
                    Term::and(left.clone(), right.clone()),
                )
            }),
            Self::AddDoubleOr => binary(target, Op::Add).map(|(left, right): (&Term, &Term)| {
                Term::sub(
                    Term::mul(Term::constant(2), Term::or(left.clone(), right.clone())),
                    Term::xor(left.clone(), right.clone()),
                )
            }),
            Self::AddSubNot => binary(target, Op::Add).map(|(left, right): (&Term, &Term)| {
                Term::sub(
                    Term::sub(left.clone(), Term::not(right.clone())),
                    Term::constant(1),
                )
            }),
            Self::SubAddNot => binary(target, Op::Sub).map(|(left, right): (&Term, &Term)| {
                Term::add(
                    Term::add(left.clone(), Term::not(right.clone())),
                    Term::constant(1),
                )
            }),
            Self::XorOrMinusAnd => binary(target, Op::Xor).map(|(left, right): (&Term, &Term)| {
                Term::sub(
                    Term::or(left.clone(), right.clone()),
                    Term::and(left.clone(), right.clone()),
                )
            }),
            Self::XorSumMinusTwiceAnd => {
                binary(target, Op::Xor).map(|(left, right): (&Term, &Term)| {
                    Term::sub(
                        Term::add(left.clone(), right.clone()),
                        Term::mul(Term::constant(2), Term::and(left.clone(), right.clone())),
                    )
                })
            }
            Self::AndSumMinusOr => binary(target, Op::And).map(|(left, right): (&Term, &Term)| {
                Term::sub(
                    Term::add(left.clone(), right.clone()),
                    Term::or(left.clone(), right.clone()),
                )
            }),
            Self::AndOrMinusXor => binary(target, Op::And).map(|(left, right): (&Term, &Term)| {
                Term::sub(
                    Term::or(left.clone(), right.clone()),
                    Term::xor(left.clone(), right.clone()),
                )
            }),
            Self::OrSumMinusAnd => binary(target, Op::Or).map(|(left, right): (&Term, &Term)| {
                Term::sub(
                    Term::add(left.clone(), right.clone()),
                    Term::and(left.clone(), right.clone()),
                )
            }),
            Self::OrXorPlusAnd => binary(target, Op::Or).map(|(left, right): (&Term, &Term)| {
                Term::add(
                    Term::xor(left.clone(), right.clone()),
                    Term::and(left.clone(), right.clone()),
                )
            }),
            Self::NotNegMinusOne => match target {
                Term::Not(inner) => Some(Term::sub(
                    Term::neg(inner.as_ref().clone()),
                    Term::constant(1),
                )),
                _ => None,
            },
            Self::NegNotPlusOne => match target {
                Term::Neg(inner) => Some(Term::add(
                    Term::not(inner.as_ref().clone()),
                    Term::constant(1),
                )),
                _ => None,
            },
            Self::DoubleNot => Some(Term::not(Term::not(target.clone()))),
            Self::DoubleNeg => Some(Term::neg(Term::neg(target.clone()))),
            Self::ZeroAdd => {
                zero_term(rng, var_count).map(|zero: Term| Term::add(target.clone(), zero))
            }
            Self::ZeroXor => {
                zero_term(rng, var_count).map(|zero: Term| Term::xor(target.clone(), zero))
            }
            Self::MulSplit => binary(target, Op::Mul).map(|(left, right): (&Term, &Term)| {
                Term::add(
                    Term::mul(
                        Term::and(left.clone(), right.clone()),
                        Term::or(left.clone(), right.clone()),
                    ),
                    Term::mul(
                        Term::and(left.clone(), Term::not(right.clone())),
                        Term::and(Term::not(left.clone()), right.clone()),
                    ),
                )
            }),
            Self::ConstantRound => {
                let offset: u64 = rng.next_u64() & 0xFF;
                Some(Term::sub(
                    Term::add(target.clone(), Term::constant(offset)),
                    Term::constant(offset),
                ))
            }
        }
    }
}

fn binary(target: &Term, wanted: Op) -> Option<(&Term, &Term)> {
    match target {
        Term::Bin(op, left, right) if *op == wanted => Some((left.as_ref(), right.as_ref())),
        _ => None,
    }
}

fn zero_term(rng: &mut SeededRng, var_count: u32) -> Option<Term> {
    if var_count == 0 {
        return None;
    }
    let index: u32 = u32::try_from(rng.below(var_count as usize)).ok()?;
    let variable: Term = Term::var(index);
    Some(Term::and(variable.clone(), Term::not(variable)))
}

fn attempt_round(
    original: &Term,
    current: &mut Term,
    admitted: &[Rule],
    rng: &mut SeededRng,
    width: Width,
    var_count: u32,
    structural_only: bool,
) -> bool {
    for _ in 0..MAX_DRAWS_PER_ROUND {
        let nodes: usize = current.node_count();
        if nodes >= MAX_EXPANSION_NODES {
            return false;
        }
        let position: usize = rng.below(nodes);
        let Some(target) = current.subterm(position) else {
            continue;
        };
        let applicable: Vec<Rule> = admitted
            .iter()
            .copied()
            .filter(|rule: &Rule| rule.is_structural() == structural_only)
            .filter(|rule: &Rule| rule.matches(target))
            .collect();
        let Some(rule) = rng.pick(&applicable).copied() else {
            continue;
        };
        let Some(expanded) = rule.expand(target, rng, var_count) else {
            continue;
        };
        let Some(candidate) = current.replace_subterm(position, &expanded) else {
            continue;
        };
        if candidate.node_count() > MAX_EXPANSION_NODES
            || !screened_equivalent(original, &candidate, width, var_count)
        {
            continue;
        }
        *current = candidate;
        return true;
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obfuscation {
    pub obfuscated: Term,
    pub applied: usize,
}

#[must_use]
pub fn obfuscate(
    original: &Term,
    family: Family,
    width: Width,
    seed: u64,
    var_count: u32,
) -> Option<Obfuscation> {
    let mut rng: SeededRng = SeededRng::new(seed);
    let mut current: Term = original.clone();
    let mut applied: usize = 0;
    let admitted: Vec<Rule> = Rule::ALL
        .into_iter()
        .filter(|rule: &Rule| family.admits(*rule))
        .collect();
    for _ in 0..family.rounds() {
        let structural: bool = attempt_round(
            original,
            &mut current,
            &admitted,
            &mut rng,
            width,
            var_count,
            true,
        );
        if structural {
            applied += 1;
            continue;
        }
        if attempt_round(
            original,
            &mut current,
            &admitted,
            &mut rng,
            width,
            var_count,
            false,
        ) {
            applied += 1;
        } else {
            break;
        }
    }
    if applied == 0 || current == *original || !equivalent(original, &current, width, var_count) {
        return None;
    }
    Some(Obfuscation {
        obfuscated: current,
        applied,
    })
}
