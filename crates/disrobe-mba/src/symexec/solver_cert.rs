use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{self, AssertUnwindSafe};
use std::time::Duration;

use oxiz::core::ast::TermKind;
use oxiz::resource_limits::ResourceLimits;
use oxiz::solver::Model;
use oxiz::{Solver, SolverResult, Term, TermId, TermManager};

const EVAL_NODE_BUDGET: usize = 1usize << 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Certified {
    Sat,
    Unsat,
    Abstain,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CertBudget {
    pub(crate) timeout: Duration,
    pub(crate) max_conflicts: u64,
    pub(crate) max_decisions: u64,
    pub(crate) node_budget: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TermVal {
    Bv { width: u32, value: u64 },
    Bool(bool),
}

const fn mask_bits(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

const fn sign_extend(value: u64, width: u32) -> i64 {
    if width == 0 || width >= 64 {
        value as i64
    } else {
        let shift: u32 = 64 - width;
        ((value << shift) as i64) >> shift
    }
}

fn bitvec_width(manager: &TermManager, id: TermId) -> Option<u32> {
    let term: &Term = manager.get(id)?;
    manager.sorts.get(term.sort)?.bitvec_width()
}

fn eval_bv(
    manager: &TermManager,
    id: TermId,
    env: &BTreeMap<TermId, u64>,
    cache: &mut BTreeMap<TermId, TermVal>,
    budget: &mut usize,
) -> Option<(u32, u64)> {
    match eval_term(manager, id, env, cache, budget)? {
        TermVal::Bv { width, value } => Some((width, value)),
        TermVal::Bool(_) => None,
    }
}

fn eval_bool(
    manager: &TermManager,
    id: TermId,
    env: &BTreeMap<TermId, u64>,
    cache: &mut BTreeMap<TermId, TermVal>,
    budget: &mut usize,
) -> Option<bool> {
    match eval_term(manager, id, env, cache, budget)? {
        TermVal::Bool(value) => Some(value),
        TermVal::Bv { .. } => None,
    }
}

fn eval_term(
    manager: &TermManager,
    id: TermId,
    env: &BTreeMap<TermId, u64>,
    cache: &mut BTreeMap<TermId, TermVal>,
    budget: &mut usize,
) -> Option<TermVal> {
    if let Some(cached) = cache.get(&id) {
        return Some(*cached);
    }
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    let kind: TermKind = manager.get(id)?.kind.clone();
    let result: TermVal = match kind {
        TermKind::True => TermVal::Bool(true),
        TermKind::False => TermVal::Bool(false),
        TermKind::BitVecConst { value, width } => {
            if width > 64 {
                return None;
            }
            let low: u64 = value.iter_u64_digits().next().unwrap_or(0);
            TermVal::Bv {
                width,
                value: low & mask_bits(width),
            }
        }
        TermKind::Var(_) => {
            let width: u32 = bitvec_width(manager, id)?;
            let &bound: &u64 = env.get(&id)?;
            TermVal::Bv {
                width,
                value: bound & mask_bits(width),
            }
        }
        TermKind::Not(a) => TermVal::Bool(!eval_bool(manager, a, env, cache, budget)?),
        TermKind::And(args) => {
            let mut acc: bool = true;
            for arg in args {
                acc = acc && eval_bool(manager, arg, env, cache, budget)?;
            }
            TermVal::Bool(acc)
        }
        TermKind::Or(args) => {
            let mut acc: bool = false;
            for arg in args {
                acc = acc || eval_bool(manager, arg, env, cache, budget)?;
            }
            TermVal::Bool(acc)
        }
        TermKind::Xor(a, b) => {
            let x: bool = eval_bool(manager, a, env, cache, budget)?;
            let y: bool = eval_bool(manager, b, env, cache, budget)?;
            TermVal::Bool(x ^ y)
        }
        TermKind::Eq(a, b) => {
            let x: TermVal = eval_term(manager, a, env, cache, budget)?;
            let y: TermVal = eval_term(manager, b, env, cache, budget)?;
            match (x, y) {
                (TermVal::Bv { value: xv, .. }, TermVal::Bv { value: yv, .. }) => {
                    TermVal::Bool(xv == yv)
                }
                (TermVal::Bool(xb), TermVal::Bool(yb)) => TermVal::Bool(xb == yb),
                _ => return None,
            }
        }
        TermKind::Ite(c, t, e) => {
            let cond: bool = eval_bool(manager, c, env, cache, budget)?;
            let chosen: TermId = if cond { t } else { e };
            eval_term(manager, chosen, env, cache, budget)?
        }
        TermKind::BvNot(a) => {
            let (width, value): (u32, u64) = eval_bv(manager, a, env, cache, budget)?;
            TermVal::Bv {
                width,
                value: (!value) & mask_bits(width),
            }
        }
        TermKind::BvAnd(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            Some((x & y) & mask_bits(w))
        })?,
        TermKind::BvOr(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            Some((x | y) & mask_bits(w))
        })?,
        TermKind::BvXor(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            Some((x ^ y) & mask_bits(w))
        })?,
        TermKind::BvAdd(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            Some(x.wrapping_add(y) & mask_bits(w))
        })?,
        TermKind::BvSub(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            Some(x.wrapping_sub(y) & mask_bits(w))
        })?,
        TermKind::BvMul(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            Some(x.wrapping_mul(y) & mask_bits(w))
        })?,
        TermKind::BvShl(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            if y >= u64::from(w) {
                Some(0)
            } else {
                Some(x.wrapping_shl(y as u32) & mask_bits(w))
            }
        })?,
        TermKind::BvLshr(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            if y >= u64::from(w) {
                Some(0)
            } else {
                Some((x & mask_bits(w)) >> y)
            }
        })?,
        TermKind::BvAshr(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            if w == 0 {
                return None;
            }
            let sign: bool = (x >> (w - 1)) & 1 == 1;
            if y >= u64::from(w) {
                Some(if sign { mask_bits(w) } else { 0 })
            } else {
                Some((sign_extend(x, w) >> y) as u64 & mask_bits(w))
            }
        })?,
        TermKind::BvUdiv(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            x.checked_div(y)
                .map(|quotient: u64| quotient & mask_bits(w))
        })?,
        TermKind::BvUrem(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            x.checked_rem(y)
                .map(|remainder: u64| remainder & mask_bits(w))
        })?,
        TermKind::BvSdiv(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            sign_extend(x, w)
                .checked_div(sign_extend(y, w))
                .map(|quotient: i64| quotient as u64 & mask_bits(w))
        })?,
        TermKind::BvSrem(a, b) => bv_binary(manager, a, b, env, cache, budget, |w, x, y| {
            sign_extend(x, w)
                .checked_rem(sign_extend(y, w))
                .map(|remainder: i64| remainder as u64 & mask_bits(w))
        })?,
        TermKind::BvConcat(high, low) => {
            let (high_width, high_value): (u32, u64) = eval_bv(manager, high, env, cache, budget)?;
            let (low_width, low_value): (u32, u64) = eval_bv(manager, low, env, cache, budget)?;
            let width: u32 = high_width + low_width;
            if width > 64 || low_width >= 64 {
                return None;
            }
            let value: u64 = (high_value.wrapping_shl(low_width) | low_value) & mask_bits(width);
            TermVal::Bv { width, value }
        }
        TermKind::BvExtract { high, low, arg } => {
            let (source_width, source_value): (u32, u64) =
                eval_bv(manager, arg, env, cache, budget)?;
            if low > high || high >= source_width {
                return None;
            }
            let width: u32 = high - low + 1;
            TermVal::Bv {
                width,
                value: (source_value >> low) & mask_bits(width),
            }
        }
        TermKind::BvUlt(a, b) => bv_compare(manager, a, b, env, cache, budget, |_, x, y| x < y)?,
        TermKind::BvUle(a, b) => bv_compare(manager, a, b, env, cache, budget, |_, x, y| x <= y)?,
        TermKind::BvSlt(a, b) => bv_compare(manager, a, b, env, cache, budget, |w, x, y| {
            sign_extend(x, w) < sign_extend(y, w)
        })?,
        TermKind::BvSle(a, b) => bv_compare(manager, a, b, env, cache, budget, |w, x, y| {
            sign_extend(x, w) <= sign_extend(y, w)
        })?,
        _ => return None,
    };
    cache.insert(id, result);
    Some(result)
}

fn bv_binary(
    manager: &TermManager,
    a: TermId,
    b: TermId,
    env: &BTreeMap<TermId, u64>,
    cache: &mut BTreeMap<TermId, TermVal>,
    budget: &mut usize,
    op: impl Fn(u32, u64, u64) -> Option<u64>,
) -> Option<TermVal> {
    let (width, x): (u32, u64) = eval_bv(manager, a, env, cache, budget)?;
    let (_, y): (u32, u64) = eval_bv(manager, b, env, cache, budget)?;
    let value: u64 = op(width, x, y)?;
    Some(TermVal::Bv { width, value })
}

fn bv_compare(
    manager: &TermManager,
    a: TermId,
    b: TermId,
    env: &BTreeMap<TermId, u64>,
    cache: &mut BTreeMap<TermId, TermVal>,
    budget: &mut usize,
    op: impl Fn(u32, u64, u64) -> bool,
) -> Option<TermVal> {
    let (width, x): (u32, u64) = eval_bv(manager, a, env, cache, budget)?;
    let (_, y): (u32, u64) = eval_bv(manager, b, env, cache, budget)?;
    Some(TermVal::Bool(op(width, x, y)))
}

fn collect_free_vars(manager: &TermManager, assumptions: &[TermId]) -> Vec<TermId> {
    let mut set: BTreeSet<TermId> = BTreeSet::new();
    for &assumption in assumptions {
        for var in manager.free_vars(assumption) {
            set.insert(var);
        }
    }
    set.into_iter().collect()
}

fn ground_value(manager: &TermManager, term: TermId, width: u32) -> u64 {
    let empty: BTreeMap<TermId, u64> = BTreeMap::new();
    let mut cache: BTreeMap<TermId, TermVal> = BTreeMap::new();
    let mut budget: usize = 256;
    match eval_term(manager, term, &empty, &mut cache, &mut budget) {
        Some(TermVal::Bv { value, .. }) => value & mask_bits(width),
        Some(TermVal::Bool(flag)) => u64::from(flag) & mask_bits(width),
        None => 0,
    }
}

fn model_environment(
    model: &Model,
    free: &[TermId],
    manager: &TermManager,
) -> BTreeMap<TermId, u64> {
    let mut env: BTreeMap<TermId, u64> = BTreeMap::new();
    for &var in free {
        let width: u32 = bitvec_width(manager, var).unwrap_or(64);
        let value: u64 = model.get(var).map_or(0, |value_term: TermId| {
            ground_value(manager, value_term, width)
        });
        env.insert(var, value);
    }
    env
}

pub(crate) fn model_satisfies(
    manager: &TermManager,
    assumptions: &[TermId],
    env: &BTreeMap<TermId, u64>,
) -> bool {
    let mut cache: BTreeMap<TermId, TermVal> = BTreeMap::new();
    let mut budget: usize = EVAL_NODE_BUDGET;
    for &assumption in assumptions {
        match eval_term(manager, assumption, env, &mut cache, &mut budget) {
            Some(TermVal::Bool(true)) => {}
            _ => return false,
        }
    }
    true
}

#[derive(Debug)]
enum RawOutcome {
    Sat(Option<BTreeMap<TermId, u64>>),
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Enumerated {
    NoModel,
    ModelFound,
    Undecided,
}

const MAX_ENUM_VARS: usize = 6;
const MAX_ENUM_VAR_BITS: u32 = 16;
const MAX_ENUM_ASSIGNMENTS: u64 = 1u64 << 12;
const MAX_ENUM_STEPS: usize = 1usize << 15;

fn enumeration_domain(manager: &TermManager, free: &[TermId]) -> Option<(Vec<(TermId, u32)>, u64)> {
    if free.is_empty() || free.len() > MAX_ENUM_VARS {
        return None;
    }
    let mut domain: Vec<(TermId, u32)> = Vec::with_capacity(free.len());
    let mut total: u64 = 1;
    for &var in free {
        let width: u32 = bitvec_width(manager, var)?;
        if width == 0 || width > MAX_ENUM_VAR_BITS {
            return None;
        }
        total = total.checked_mul(1u64 << width)?;
        if total > MAX_ENUM_ASSIGNMENTS {
            return None;
        }
        domain.push((var, width));
    }
    Some((domain, total))
}

pub(crate) fn enumerate_conjunction(
    manager: &TermManager,
    assumptions: &[TermId],
    free: &[TermId],
    step_budget: usize,
) -> Enumerated {
    let Some((domain, total)): Option<(Vec<(TermId, u32)>, u64)> =
        enumeration_domain(manager, free)
    else {
        return Enumerated::Undecided;
    };
    let mut budget: usize = step_budget.min(MAX_ENUM_STEPS);
    for index in 0..total {
        let mut env: BTreeMap<TermId, u64> = BTreeMap::new();
        let mut rest: u64 = index;
        for &(var, width) in &domain {
            let modulus: u64 = 1u64 << width;
            env.insert(var, rest % modulus);
            rest /= modulus;
        }
        let mut cache: BTreeMap<TermId, TermVal> = BTreeMap::new();
        let mut refuted: bool = false;
        let mut undecided: bool = false;
        for &assumption in assumptions {
            match eval_term(manager, assumption, &env, &mut cache, &mut budget) {
                Some(TermVal::Bool(true)) => {}
                Some(TermVal::Bool(false)) => {
                    refuted = true;
                    undecided = false;
                    break;
                }
                Some(TermVal::Bv { .. }) | None => undecided = true,
            }
        }
        if undecided {
            return Enumerated::Undecided;
        }
        if !refuted {
            return Enumerated::ModelFound;
        }
        if budget == 0 {
            return Enumerated::Undecided;
        }
    }
    Enumerated::NoModel
}

pub(crate) fn certified_check(
    manager: &mut TermManager,
    assumptions: &[TermId],
    budget: CertBudget,
) -> Certified {
    let outcome: Result<Certified, Box<dyn Any + Send>> =
        panic::catch_unwind(AssertUnwindSafe(|| run(manager, assumptions, budget)));
    outcome.unwrap_or(Certified::Abstain)
}

fn run(manager: &mut TermManager, assumptions: &[TermId], budget: CertBudget) -> Certified {
    if assumptions.is_empty() {
        return Certified::Sat;
    }
    let free: Vec<TermId> = collect_free_vars(manager, assumptions);
    let raw: RawOutcome = raw_solve(manager, assumptions, &free, budget);
    certify(manager, assumptions, &free, raw, budget)
}

fn raw_solve(
    manager: &mut TermManager,
    assumptions: &[TermId],
    free: &[TermId],
    budget: CertBudget,
) -> RawOutcome {
    let mut solver: Solver = Solver::new();
    for &assumption in assumptions {
        solver.assert(assumption, manager);
    }
    solver.set_timeout(budget.timeout);
    solver.set_conflict_limit(budget.max_conflicts);
    solver.set_decision_limit(budget.max_decisions);
    let limits: ResourceLimits = ResourceLimits::new()
        .with_timeout(budget.timeout)
        .with_max_conflicts(budget.max_conflicts)
        .with_max_decisions(budget.max_decisions);
    match solver.check_with_limits(manager, &limits) {
        Ok(SolverResult::Sat) => {
            let env: Option<BTreeMap<TermId, u64>> = solver
                .model()
                .map(|model: &Model| model_environment(model, free, manager));
            RawOutcome::Sat(env)
        }
        Ok(SolverResult::Unsat) => RawOutcome::Unsat,
        Ok(SolverResult::Unknown) | Err(_) => RawOutcome::Unknown,
    }
}

fn certify(
    manager: &TermManager,
    assumptions: &[TermId],
    free: &[TermId],
    raw: RawOutcome,
    budget: CertBudget,
) -> Certified {
    match raw {
        RawOutcome::Sat(Some(env)) if model_satisfies(manager, assumptions, &env) => Certified::Sat,
        RawOutcome::Unsat => {
            if super::cross_check::independent_refutation(manager, assumptions, free, budget)
                .confirms()
            {
                Certified::Unsat
            } else {
                Certified::Abstain
            }
        }
        RawOutcome::Sat(_) | RawOutcome::Unknown => Certified::Abstain,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::verify::{term_conjunction_unsat, term_conjunction_unsat_via_polynomial};

    const FUZZ_BUDGET: CertBudget = CertBudget {
        timeout: Duration::from_millis(250),
        max_conflicts: 20_000,
        max_decisions: 100_000,
        node_budget: 1usize << 16,
    };

    struct Rng(u64);

    impl Rng {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            let mut z: u64 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            self.0 = z;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: u32) -> u32 {
            (self.next() % u64::from(bound)) as u32
        }
    }

    fn sort(manager: &mut TermManager, width: u32) -> oxiz::SortId {
        manager.sorts.bitvec(width)
    }

    fn exhaustive_sat(
        manager: &TermManager,
        assumptions: &[TermId],
        vars: &[(TermId, u32)],
    ) -> bool {
        let mut total: u64 = 1;
        for &(_, width) in vars {
            total = total.saturating_mul(1u64 << width);
        }
        for index in 0..total {
            let mut env: BTreeMap<TermId, u64> = BTreeMap::new();
            let mut rest: u64 = index;
            for &(var, width) in vars {
                let modulus: u64 = 1u64 << width;
                env.insert(var, (rest % modulus) & mask_bits(width));
                rest /= modulus;
            }
            if model_satisfies(manager, assumptions, &env) {
                return true;
            }
        }
        false
    }

    fn random_bv(
        manager: &mut TermManager,
        rng: &mut Rng,
        vars: &[TermId],
        width: u32,
        depth: u32,
    ) -> TermId {
        if depth == 0 || rng.below(3) == 0 {
            if rng.below(2) == 0 {
                return vars[rng.below(vars.len() as u32) as usize];
            }
            let value: u64 = u64::from(rng.below(1u32 << width));
            return manager.mk_bitvec(value, width);
        }
        let left: TermId = random_bv(manager, rng, vars, width, depth - 1);
        let right: TermId = random_bv(manager, rng, vars, width, depth - 1);
        match rng.below(8) {
            0 => manager.mk_bv_add(left, right),
            1 => manager.mk_bv_sub(left, right),
            2 => manager.mk_bv_and(left, right),
            3 => manager.mk_bv_or(left, right),
            4 => manager.mk_bv_xor(left, right),
            5 => manager.mk_bv_mul(left, right),
            6 => manager.mk_bv_not(left),
            _ => manager.mk_bv_shl(left, right),
        }
    }

    fn random_predicate(
        manager: &mut TermManager,
        rng: &mut Rng,
        vars: &[TermId],
        width: u32,
        depth: u32,
    ) -> TermId {
        let left: TermId = random_bv(manager, rng, vars, width, depth);
        let right: TermId = random_bv(manager, rng, vars, width, depth);
        match rng.below(6) {
            0 => manager.mk_eq(left, right),
            1 => {
                let equal: TermId = manager.mk_eq(left, right);
                manager.mk_not(equal)
            }
            2 => manager.mk_bv_ult(left, right),
            3 => manager.mk_bv_ule(left, right),
            4 => manager.mk_bv_slt(left, right),
            _ => manager.mk_bv_sle(left, right),
        }
    }

    #[test]
    fn differential_fuzz_never_disagrees_with_exhaustive() {
        let mut rng: Rng = Rng::new(0xD150_0BE5_1337_C0DE_u64);
        let mut wrong: u32 = 0;
        let mut decided: u32 = 0;
        for iteration in 0..600u32 {
            let mut manager: TermManager = TermManager::new();
            let width: u32 = 1 + rng.below(4);
            let var_count: usize = 1 + rng.below(2) as usize;
            let bv_sort: oxiz::SortId = sort(&mut manager, width);
            let vars: Vec<TermId> = (0..var_count)
                .map(|index: usize| manager.mk_var(&format!("x{index}"), bv_sort))
                .collect();
            let conjuncts: usize = 1 + rng.below(3) as usize;
            let assumptions: Vec<TermId> = (0..conjuncts)
                .map(|_| random_predicate(&mut manager, &mut rng, &vars, width, 2))
                .collect();
            let widths: Vec<(TermId, u32)> =
                vars.iter().map(|&var: &TermId| (var, width)).collect();
            let truth: bool = exhaustive_sat(&manager, &assumptions, &widths);
            let verdict: Certified = certified_check(&mut manager, &assumptions, FUZZ_BUDGET);
            match verdict {
                Certified::Sat => {
                    decided += 1;
                    if !truth {
                        wrong += 1;
                    }
                }
                Certified::Unsat => {
                    decided += 1;
                    if truth {
                        wrong += 1;
                    }
                }
                Certified::Abstain => {}
            }
            assert_eq!(
                wrong, 0,
                "wrapper disagreed with exhaustive on iteration {iteration}"
            );
        }
        assert!(
            decided > 100,
            "fuzz decided too few queries ({decided}); oracle may be vacuous"
        );
    }

    #[test]
    fn bv_and_ult_conjunction_is_never_spuriously_sat() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let one: TermId = manager.mk_bitvec(1u64, 8);
        let low_bit: TermId = manager.mk_bv_and(x, one);
        let odd: TermId = manager.mk_eq(low_bit, one);
        let below_one: TermId = manager.mk_bv_ult(x, one);
        let assumptions: [TermId; 2] = [odd, below_one];
        let verdict: Certified = certified_check(&mut manager, &assumptions, FUZZ_BUDGET);
        assert_ne!(
            verdict,
            Certified::Sat,
            "bv_and+ult contradiction must not certify Sat"
        );
    }

    #[test]
    fn disequality_conjunction_with_bound_is_never_spuriously_unsat() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let zero: TermId = manager.mk_bitvec(0u64, 8);
        let one: TermId = manager.mk_bitvec(1u64, 8);
        let five: TermId = manager.mk_bitvec(5u64, 8);
        let ne_zero: TermId = {
            let equal: TermId = manager.mk_eq(x, zero);
            manager.mk_not(equal)
        };
        let ne_one: TermId = {
            let equal: TermId = manager.mk_eq(x, one);
            manager.mk_not(equal)
        };
        let below_five: TermId = manager.mk_bv_ult(x, five);
        let assumptions: [TermId; 3] = [ne_zero, ne_one, below_five];
        let verdict: Certified = certified_check(&mut manager, &assumptions, FUZZ_BUDGET);
        assert_ne!(
            verdict,
            Certified::Unsat,
            "a satisfiable disequality+bound conjunction must not certify Unsat"
        );
    }

    #[test]
    fn a_non_satisfying_assignment_is_rejected() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let seven: TermId = manager.mk_bitvec(7u64, 8);
        let equals_seven: TermId = manager.mk_eq(x, seven);
        let mut wrong: BTreeMap<TermId, u64> = BTreeMap::new();
        wrong.insert(x, 3);
        assert!(!model_satisfies(&manager, &[equals_seven], &wrong));
        let mut right: BTreeMap<TermId, u64> = BTreeMap::new();
        right.insert(x, 7);
        assert!(model_satisfies(&manager, &[equals_seven], &right));
    }

    #[test]
    fn genuine_unsat_is_confirmed() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let five: TermId = manager.mk_bitvec(5u64, 8);
        let six: TermId = manager.mk_bitvec(6u64, 8);
        let eq_five: TermId = manager.mk_eq(x, five);
        let eq_six: TermId = manager.mk_eq(x, six);
        let verdict: Certified = certified_check(&mut manager, &[eq_five, eq_six], FUZZ_BUDGET);
        assert_eq!(verdict, Certified::Unsat);
    }

    #[test]
    fn genuine_sat_is_certified() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let seven: TermId = manager.mk_bitvec(7u64, 8);
        let equals_seven: TermId = manager.mk_eq(x, seven);
        let verdict: Certified = certified_check(&mut manager, &[equals_seven], FUZZ_BUDGET);
        assert_eq!(verdict, Certified::Sat);
    }

    #[test]
    fn even_product_predicate_is_confirmed_unsat_when_the_bdd_cannot() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 32);
        let x: TermId = manager.mk_var("x", bv_sort);
        let square: TermId = manager.mk_bv_mul(x, x);
        let plus: TermId = manager.mk_bv_add(square, x);
        let one: TermId = manager.mk_bitvec(1u64, 32);
        let masked: TermId = manager.mk_bv_and(plus, one);
        let zero: TermId = manager.mk_bitvec(0u64, 32);
        let equal_zero: TermId = manager.mk_eq(masked, zero);
        let odd: TermId = manager.mk_not(equal_zero);
        let verdict: Certified = certified_check(&mut manager, &[odd], FUZZ_BUDGET);
        assert_eq!(verdict, Certified::Unsat);
    }

    #[test]
    fn always_odd_product_predicate_is_confirmed_unsat() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 32);
        let x: TermId = manager.mk_var("x", bv_sort);
        let square: TermId = manager.mk_bv_mul(x, x);
        let plus: TermId = manager.mk_bv_add(square, x);
        let one: TermId = manager.mk_bitvec(1u64, 32);
        let plus_one: TermId = manager.mk_bv_add(plus, one);
        let masked: TermId = manager.mk_bv_and(plus_one, one);
        let equal_one: TermId = manager.mk_eq(masked, one);
        let not_one: TermId = manager.mk_not(equal_one);
        let verdict: Certified = certified_check(&mut manager, &[not_one], FUZZ_BUDGET);
        assert_eq!(verdict, Certified::Unsat);
    }

    const CONFIRM_NODE_BUDGET: usize = 1usize << 16;

    fn free_of(manager: &TermManager, assumptions: &[TermId]) -> Vec<TermId> {
        collect_free_vars(manager, assumptions)
    }

    fn enumerated(manager: &TermManager, assumptions: &[TermId]) -> Enumerated {
        let free: Vec<TermId> = free_of(manager, assumptions);
        enumerate_conjunction(manager, assumptions, &free, CONFIRM_NODE_BUDGET)
    }

    fn certify_raw(manager: &TermManager, assumptions: &[TermId], raw: RawOutcome) -> Certified {
        let free: Vec<TermId> = free_of(manager, assumptions);
        certify(manager, assumptions, &free, raw, FUZZ_BUDGET)
    }

    #[test]
    fn an_injected_unsat_on_a_satisfiable_bv_and_ult_conjunction_abstains() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let three: TermId = manager.mk_bitvec(3u64, 8);
        let sixteen: TermId = manager.mk_bitvec(16u64, 8);
        let low_bits: TermId = manager.mk_bv_and(x, three);
        let odd_low: TermId = manager.mk_eq(low_bits, three);
        let bounded: TermId = manager.mk_bv_ult(x, sixteen);
        let assumptions: [TermId; 2] = [odd_low, bounded];
        assert_eq!(enumerated(&manager, &assumptions), Enumerated::ModelFound);
        assert_eq!(
            certify_raw(&manager, &assumptions, RawOutcome::Unsat),
            Certified::Abstain
        );
    }

    #[test]
    fn an_injected_unsat_on_a_refutable_bv_and_ult_conjunction_still_certifies() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let one: TermId = manager.mk_bitvec(1u64, 8);
        let low_bit: TermId = manager.mk_bv_and(x, one);
        let odd: TermId = manager.mk_eq(low_bit, one);
        let below_one: TermId = manager.mk_bv_ult(x, one);
        let assumptions: [TermId; 2] = [odd, below_one];
        assert_eq!(enumerated(&manager, &assumptions), Enumerated::NoModel);
        assert_eq!(
            certify_raw(&manager, &assumptions, RawOutcome::Unsat),
            Certified::Unsat
        );
    }

    #[test]
    fn a_disequality_conjunction_needs_the_whole_conjunction() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 2);
        let x: TermId = manager.mk_var("x", bv_sort);
        let assumptions: Vec<TermId> = (0..4u64)
            .map(|value: u64| {
                let konst: TermId = manager.mk_bitvec(value, 2);
                let equal: TermId = manager.mk_eq(x, konst);
                manager.mk_not(equal)
            })
            .collect();
        for &assumption in &assumptions {
            let single: [TermId; 1] = [assumption];
            assert!(
                !term_conjunction_unsat(&manager, &single, CONFIRM_NODE_BUDGET),
                "a single disequality over a free variable is satisfiable"
            );
        }
        assert!(!term_conjunction_unsat_via_polynomial(
            &manager,
            &assumptions
        ));
        assert!(term_conjunction_unsat(
            &manager,
            &assumptions,
            CONFIRM_NODE_BUDGET
        ));
        assert_eq!(enumerated(&manager, &assumptions), Enumerated::NoModel);
        assert_eq!(
            certify_raw(&manager, &assumptions, RawOutcome::Unsat),
            Certified::Unsat
        );
    }

    #[test]
    fn enumeration_declines_above_the_width_threshold() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 32);
        let x: TermId = manager.mk_var("x", bv_sort);
        let five: TermId = manager.mk_bitvec(5u64, 32);
        let six: TermId = manager.mk_bitvec(6u64, 32);
        let eq_five: TermId = manager.mk_eq(x, five);
        let eq_six: TermId = manager.mk_eq(x, six);
        let assumptions: [TermId; 2] = [eq_five, eq_six];
        assert_eq!(enumerated(&manager, &assumptions), Enumerated::Undecided);
    }

    #[test]
    fn enumeration_declines_when_a_point_cannot_be_evaluated() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 4);
        let x: TermId = manager.mk_var("x", bv_sort);
        let y: TermId = manager.mk_var("y", bv_sort);
        let quotient: TermId = manager.mk_bv_udiv(x, y);
        let zero: TermId = manager.mk_bitvec(0u64, 4);
        let one: TermId = manager.mk_bitvec(1u64, 4);
        let is_zero: TermId = manager.mk_eq(quotient, zero);
        let is_one: TermId = manager.mk_eq(quotient, one);
        let assumptions: [TermId; 2] = [is_zero, is_one];
        assert_eq!(enumerated(&manager, &assumptions), Enumerated::Undecided);
        assert_eq!(
            certify_raw(&manager, &assumptions, RawOutcome::Unsat),
            Certified::Abstain
        );
    }

    #[test]
    fn enumeration_declines_when_the_step_budget_is_spent() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let five: TermId = manager.mk_bitvec(5u64, 8);
        let six: TermId = manager.mk_bitvec(6u64, 8);
        let eq_five: TermId = manager.mk_eq(x, five);
        let eq_six: TermId = manager.mk_eq(x, six);
        let assumptions: [TermId; 2] = [eq_five, eq_six];
        let free: Vec<TermId> = free_of(&manager, &assumptions);
        assert_eq!(
            enumerate_conjunction(&manager, &assumptions, &free, 0),
            Enumerated::Undecided
        );
        assert_eq!(
            enumerate_conjunction(&manager, &assumptions, &free, CONFIRM_NODE_BUDGET),
            Enumerated::NoModel
        );
    }

    #[test]
    fn no_procedure_covers_a_wide_variable_divisor_so_the_accept_is_refused() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 32);
        let x: TermId = manager.mk_var("x", bv_sort);
        let y: TermId = manager.mk_var("y", bv_sort);
        let quotient: TermId = manager.mk_bv_udiv(x, y);
        let zero: TermId = manager.mk_bitvec(0u64, 32);
        let one: TermId = manager.mk_bitvec(1u64, 32);
        let is_zero: TermId = manager.mk_eq(quotient, zero);
        let is_one: TermId = manager.mk_eq(quotient, one);
        let assumptions: [TermId; 2] = [is_zero, is_one];
        assert_eq!(enumerated(&manager, &assumptions), Enumerated::Undecided);
        assert!(!term_conjunction_unsat(
            &manager,
            &assumptions,
            CONFIRM_NODE_BUDGET
        ));
        assert!(!term_conjunction_unsat_via_polynomial(
            &manager,
            &assumptions
        ));
        assert_eq!(
            certify_raw(&manager, &assumptions, RawOutcome::Unsat),
            Certified::Abstain
        );
    }

    fn reference_ashr_four_bits(value: u64, shift: u64) -> u64 {
        let signed: i64 = if value & 0b1000 == 0 {
            (value & 0b0111) as i64
        } else {
            (value & 0b1111) as i64 - 16
        };
        if shift >= 4 {
            if signed < 0 { 0b1111 } else { 0 }
        } else {
            (signed >> shift) as u64 & 0b1111
        }
    }

    #[test]
    fn the_blaster_matches_a_hand_written_arithmetic_shift_at_four_bits() {
        for shift in 0..6u64 {
            for target in 0..16u64 {
                let mut manager: TermManager = TermManager::new();
                let bv_sort: oxiz::SortId = sort(&mut manager, 4);
                let x: TermId = manager.mk_var("x", bv_sort);
                let amount: TermId = manager.mk_bitvec(shift, 4);
                let shifted: TermId = manager.mk_bv_ashr(x, amount);
                let konst: TermId = manager.mk_bitvec(target, 4);
                let equal: TermId = manager.mk_eq(shifted, konst);
                let assumptions: [TermId; 1] = [equal];
                let reachable: bool =
                    (0..16u64).any(|value: u64| reference_ashr_four_bits(value, shift) == target);
                assert_eq!(
                    term_conjunction_unsat(&manager, &assumptions, CONFIRM_NODE_BUDGET),
                    !reachable,
                    "shift {shift} target {target}"
                );
            }
        }
    }

    #[test]
    fn the_blaster_matches_a_hand_written_arithmetic_shift_under_a_symbolic_amount() {
        for value in 0..16u64 {
            for shift in 0..16u64 {
                let mut manager: TermManager = TermManager::new();
                let bv_sort: oxiz::SortId = sort(&mut manager, 4);
                let x: TermId = manager.mk_var("x", bv_sort);
                let y: TermId = manager.mk_var("y", bv_sort);
                let shifted: TermId = manager.mk_bv_ashr(x, y);
                let value_term: TermId = manager.mk_bitvec(value, 4);
                let shift_term: TermId = manager.mk_bitvec(shift, 4);
                let pin_value: TermId = manager.mk_eq(x, value_term);
                let pin_shift: TermId = manager.mk_eq(y, shift_term);
                let expected: u64 = reference_ashr_four_bits(value, shift);
                let expected_term: TermId = manager.mk_bitvec(expected, 4);
                let agrees: TermId = manager.mk_eq(shifted, expected_term);
                let differs: TermId = manager.mk_not(agrees);
                assert!(
                    term_conjunction_unsat(
                        &manager,
                        &[pin_value, pin_shift, differs],
                        CONFIRM_NODE_BUDGET
                    ),
                    "blasted shift of {value} by {shift} must equal {expected}"
                );
                let wrong_term: TermId = manager.mk_bitvec((expected + 1) & 0b1111, 4);
                let wrong: TermId = manager.mk_eq(shifted, wrong_term);
                assert!(
                    term_conjunction_unsat(
                        &manager,
                        &[pin_value, pin_shift, wrong],
                        CONFIRM_NODE_BUDGET
                    ),
                    "blasted shift of {value} by {shift} must reject a neighbouring value"
                );
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Coverage {
        operation: &'static str,
        blasted: bool,
        enumerated: bool,
    }

    type BinaryBuilder = fn(&mut TermManager, TermId, TermId) -> TermId;

    fn measure(operation: &'static str, manager: &TermManager, assumptions: &[TermId]) -> Coverage {
        Coverage {
            operation,
            blasted: term_conjunction_unsat(manager, assumptions, CONFIRM_NODE_BUDGET),
            enumerated: enumerated(manager, assumptions) == Enumerated::NoModel,
        }
    }

    #[test]
    fn the_confirmer_coverage_over_the_emitted_operator_set_is_pinned() {
        let mut measured: Vec<Coverage> = Vec::new();
        let word_ops: [(&'static str, BinaryBuilder); 15] = [
            ("add", TermManager::mk_bv_add),
            ("sub", TermManager::mk_bv_sub),
            ("mul", TermManager::mk_bv_mul),
            ("and", TermManager::mk_bv_and),
            ("or", TermManager::mk_bv_or),
            ("xor", TermManager::mk_bv_xor),
            ("shl", TermManager::mk_bv_shl),
            ("lshr", TermManager::mk_bv_lshr),
            ("ashr", TermManager::mk_bv_ashr),
            ("udiv", TermManager::mk_bv_udiv),
            ("sdiv", TermManager::mk_bv_sdiv),
            ("urem", TermManager::mk_bv_urem),
            ("srem", TermManager::mk_bv_srem),
            (
                "not",
                |manager: &mut TermManager, left: TermId, _: TermId| manager.mk_bv_not(left),
            ),
            (
                "neg",
                |manager: &mut TermManager, left: TermId, _: TermId| manager.mk_bv_neg(left),
            ),
        ];
        for (name, build) in word_ops {
            let mut manager: TermManager = TermManager::new();
            let bv_sort: oxiz::SortId = sort(&mut manager, 4);
            let x: TermId = manager.mk_var("x", bv_sort);
            let three: TermId = manager.mk_bitvec(3u64, 4);
            let value: TermId = build(&mut manager, x, three);
            let zero: TermId = manager.mk_bitvec(0u64, 4);
            let one: TermId = manager.mk_bitvec(1u64, 4);
            let is_zero: TermId = manager.mk_eq(value, zero);
            let is_one: TermId = manager.mk_eq(value, one);
            measured.push(measure(name, &manager, &[is_zero, is_one]));
        }

        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 4);
        let x: TermId = manager.mk_var("x", bv_sort);
        let y: TermId = manager.mk_var("y", bv_sort);
        let zero: TermId = manager.mk_bitvec(0u64, 4);
        let one: TermId = manager.mk_bitvec(1u64, 4);
        let narrow_zero: TermId = manager.mk_bitvec(0u64, 2);
        let narrow_one: TermId = manager.mk_bitvec(1u64, 2);

        let low_x: TermId = manager.mk_bv_extract(1, 0, x);
        let low_y: TermId = manager.mk_bv_extract(1, 0, y);
        let joined: TermId = manager.mk_bv_concat(low_x, low_y);
        let joined_zero: TermId = manager.mk_eq(joined, zero);
        let joined_one: TermId = manager.mk_eq(joined, one);
        measured.push(measure("concat", &manager, &[joined_zero, joined_one]));

        let extract_zero: TermId = manager.mk_eq(low_x, narrow_zero);
        let extract_one: TermId = manager.mk_eq(low_x, narrow_one);
        measured.push(measure("extract", &manager, &[extract_zero, extract_one]));

        let widened: TermId = manager.mk_bv_concat(narrow_zero, low_x);
        let widened_zero: TermId = manager.mk_eq(widened, zero);
        let widened_one: TermId = manager.mk_eq(widened, one);
        measured.push(measure(
            "zero-extend",
            &manager,
            &[widened_zero, widened_one],
        ));

        let selector: TermId = manager.mk_bv_ult(x, y);
        let chosen: TermId = manager.mk_ite(selector, x, y);
        let chosen_zero: TermId = manager.mk_eq(chosen, zero);
        let chosen_one: TermId = manager.mk_eq(chosen, one);
        measured.push(measure("ite", &manager, &[chosen_zero, chosen_one]));

        let predicates: [(&'static str, BinaryBuilder); 5] = [
            ("eq", TermManager::mk_eq),
            ("ult", TermManager::mk_bv_ult),
            ("ule", TermManager::mk_bv_ule),
            ("slt", TermManager::mk_bv_slt),
            ("sle", TermManager::mk_bv_sle),
        ];
        for (name, build) in predicates {
            let mut manager: TermManager = TermManager::new();
            let bv_sort: oxiz::SortId = sort(&mut manager, 4);
            let x: TermId = manager.mk_var("x", bv_sort);
            let y: TermId = manager.mk_var("y", bv_sort);
            let predicate: TermId = build(&mut manager, x, y);
            let negated: TermId = manager.mk_not(predicate);
            measured.push(measure(name, &manager, &[predicate, negated]));
        }

        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 4);
        let x: TermId = manager.mk_var("x", bv_sort);
        let y: TermId = manager.mk_var("y", bv_sort);
        let equal: TermId = manager.mk_eq(x, y);
        let distinct: TermId = manager.mk_not(equal);
        let doubly_distinct: TermId = manager.mk_not(distinct);
        measured.push(measure("distinct", &manager, &[distinct, doubly_distinct]));

        let expected: [Coverage; 25] = [
            Coverage {
                operation: "add",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "sub",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "mul",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "and",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "or",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "xor",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "shl",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "lshr",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "ashr",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "udiv",
                blasted: false,
                enumerated: true,
            },
            Coverage {
                operation: "sdiv",
                blasted: false,
                enumerated: true,
            },
            Coverage {
                operation: "urem",
                blasted: false,
                enumerated: true,
            },
            Coverage {
                operation: "srem",
                blasted: false,
                enumerated: true,
            },
            Coverage {
                operation: "not",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "neg",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "concat",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "extract",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "zero-extend",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "ite",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "eq",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "ult",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "ule",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "slt",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "sle",
                blasted: true,
                enumerated: true,
            },
            Coverage {
                operation: "distinct",
                blasted: true,
                enumerated: true,
            },
        ];
        assert_eq!(measured.as_slice(), expected.as_slice());
    }

    #[test]
    fn the_two_confirmers_never_split_on_a_random_narrow_conjunction() {
        let mut rng: Rng = Rng::new(0x51DE_B00B_5EED_1234_u64);
        let mut agreements: u32 = 0;
        for iteration in 0..400u32 {
            let mut manager: TermManager = TermManager::new();
            let width: u32 = 1 + rng.below(4);
            let var_count: usize = 1 + rng.below(2) as usize;
            let bv_sort: oxiz::SortId = sort(&mut manager, width);
            let vars: Vec<TermId> = (0..var_count)
                .map(|index: usize| manager.mk_var(&format!("x{index}"), bv_sort))
                .collect();
            let conjuncts: usize = 1 + rng.below(3) as usize;
            let assumptions: Vec<TermId> = (0..conjuncts)
                .map(|_| random_predicate(&mut manager, &mut rng, &vars, width, 2))
                .collect();
            let blasted: bool = term_conjunction_unsat(&manager, &assumptions, CONFIRM_NODE_BUDGET);
            let enumerated_verdict: Enumerated = enumerated(&manager, &assumptions);
            if enumerated_verdict == Enumerated::Undecided {
                continue;
            }
            agreements += 1;
            assert_eq!(
                blasted,
                enumerated_verdict == Enumerated::NoModel,
                "bit-blasting and enumeration split on iteration {iteration}"
            );
        }
        assert!(
            agreements > 200,
            "cross-check decided too few queries ({agreements})"
        );
    }

    #[test]
    fn satisfiable_product_predicate_is_never_confirmed_unsat() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: oxiz::SortId = sort(&mut manager, 32);
        let x: TermId = manager.mk_var("x", bv_sort);
        let y: TermId = manager.mk_var("y", bv_sort);
        let product: TermId = manager.mk_bv_mul(x, y);
        let one: TermId = manager.mk_bitvec(1u64, 32);
        let masked: TermId = manager.mk_bv_and(product, one);
        let zero: TermId = manager.mk_bitvec(0u64, 32);
        let equal_zero: TermId = manager.mk_eq(masked, zero);
        let odd: TermId = manager.mk_not(equal_zero);
        let verdict: Certified = certified_check(&mut manager, &[odd], FUZZ_BUDGET);
        assert_ne!(verdict, Certified::Unsat);
    }
}
