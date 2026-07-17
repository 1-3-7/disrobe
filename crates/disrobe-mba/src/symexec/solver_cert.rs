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
            let value: u64 = env.get(&id).copied().unwrap_or(0) & mask_bits(width);
            TermVal::Bv { width, value }
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
            if width > 64 {
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

fn model_satisfies(
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
    let raw: RawOutcome = {
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
                    .map(|model: &Model| model_environment(model, &free, manager));
                RawOutcome::Sat(env)
            }
            Ok(SolverResult::Unsat) => RawOutcome::Unsat,
            Ok(SolverResult::Unknown) | Err(_) => RawOutcome::Unknown,
        }
    };
    match raw {
        RawOutcome::Sat(Some(env)) if model_satisfies(manager, assumptions, &env) => Certified::Sat,
        RawOutcome::Unsat => {
            if crate::verify::term_conjunction_unsat(manager, assumptions, budget.node_budget) {
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
}
