use oxiz::{TermId, TermManager};

use super::solver_cert::{CertBudget, Enumerated, enumerate_conjunction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Procedure {
    Enumeration,
    BitBlast,
    Disequality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refutation {
    Confirmed(Procedure),
    Contradicted,
    Undecided,
}

impl Refutation {
    pub(crate) const fn confirms(self) -> bool {
        matches!(self, Self::Confirmed(_))
    }
}

pub(crate) fn independent_refutation(
    manager: &TermManager,
    assumptions: &[TermId],
    free: &[TermId],
    budget: CertBudget,
) -> Refutation {
    match enumerate_conjunction(manager, assumptions, free, budget.node_budget) {
        Enumerated::ModelFound => return Refutation::Contradicted,
        Enumerated::NoModel => return Refutation::Confirmed(Procedure::Enumeration),
        Enumerated::Undecided => {}
    }
    if crate::verify::term_conjunction_unsat(manager, assumptions, budget.node_budget) {
        return Refutation::Confirmed(Procedure::BitBlast);
    }
    if crate::verify::term_conjunction_unsat_via_polynomial(manager, assumptions) {
        return Refutation::Confirmed(Procedure::Disequality);
    }
    Refutation::Undecided
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::super::solver_cert::{Certified, certified_check, model_satisfies};
    use super::{Procedure, Refutation, independent_refutation};
    use crate::verify::{term_conjunction_unsat, term_conjunction_unsat_via_polynomial};
    use oxiz::{SortId, TermId, TermManager};

    use super::CertBudget;

    const CROSS_BUDGET: CertBudget = CertBudget {
        timeout: Duration::from_millis(250),
        max_conflicts: 20_000,
        max_decisions: 100_000,
        node_budget: 1usize << 16,
    };
    const FUZZ_SEED: u64 = 0x0BAD_5EED_C0FF_EE11;
    const NARROW_ITERATIONS: u32 = 600;
    const WIDE_ITERATIONS: u32 = 90;
    const PRODUCTION_ENUMERATION_CAP: u64 = 1u64 << 12;
    const TEST_ENUMERATION_CAP: u64 = 1u64 << 14;
    const MIN_ENUMERATION_CONFIRMATIONS: u32 = 100;
    const MIN_BIT_BLAST_CONFIRMATIONS: u32 = 20;

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

    fn free_vars(manager: &TermManager, assumptions: &[TermId]) -> Vec<TermId> {
        let mut seen: Vec<TermId> = Vec::new();
        for &assumption in assumptions {
            for var in manager.free_vars(assumption) {
                if !seen.contains(&var) {
                    seen.push(var);
                }
            }
        }
        seen.sort_unstable();
        seen
    }

    fn exhaustively_satisfiable(
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
                env.insert(var, rest % modulus);
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
                let pick: usize = rng.below(vars.len() as u32) as usize;
                return vars.get(pick).copied().unwrap_or_else(|| {
                    let fallback: u64 = 0;
                    manager.mk_bitvec(fallback, width)
                });
            }
            let value: u64 = u64::from(rng.below(1u32 << width));
            return manager.mk_bitvec(value, width);
        }
        let left: TermId = random_bv(manager, rng, vars, width, depth - 1);
        let right: TermId = random_bv(manager, rng, vars, width, depth - 1);
        match rng.below(14) {
            0 => manager.mk_bv_add(left, right),
            1 => manager.mk_bv_sub(left, right),
            2 => manager.mk_bv_and(left, right),
            3 => manager.mk_bv_or(left, right),
            4 => manager.mk_bv_xor(left, right),
            5 => manager.mk_bv_mul(left, right),
            6 => manager.mk_bv_not(left),
            7 => manager.mk_bv_neg(left),
            8 => manager.mk_bv_shl(left, right),
            9 => manager.mk_bv_lshr(left, right),
            10 => manager.mk_bv_ashr(left, right),
            11 => {
                let high: u32 = width.saturating_sub(1);
                let low: u32 = rng.below(high.max(1)).min(high);
                let extracted: TermId = manager.mk_bv_extract(high, low, left);
                let extracted_width: u32 = high - low + 1;
                if extracted_width >= width {
                    extracted
                } else {
                    let pad: TermId = manager.mk_bitvec(0u64, width - extracted_width);
                    manager.mk_bv_concat(pad, extracted)
                }
            }
            12 => {
                let zero: TermId = manager.mk_bitvec(0u64, width);
                let is_zero: TermId = manager.mk_eq(right, zero);
                manager.mk_ite(is_zero, left, right)
            }
            _ => {
                let mask: u64 = u64::from(rng.below(1u32 << width));
                let mask_term: TermId = manager.mk_bitvec(mask, width);
                manager.mk_bv_and(left, mask_term)
            }
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

    struct Shape {
        width: u32,
        var_count: usize,
    }

    fn sweep(
        rng: &mut Rng,
        iterations: u32,
        shape: &dyn Fn(&mut Rng) -> Shape,
        label: &str,
    ) -> (u32, u32, u32, u32) {
        let mut enumeration: u32 = 0;
        let mut bit_blast: u32 = 0;
        let mut disequality: u32 = 0;
        let mut refutable: u32 = 0;
        for iteration in 0..iterations {
            let chosen: Shape = shape(rng);
            let mut manager: TermManager = TermManager::new();
            let bv_sort: SortId = manager.sorts.bitvec(chosen.width);
            let vars: Vec<TermId> = (0..chosen.var_count)
                .map(|index: usize| manager.mk_var(&format!("x{index}"), bv_sort))
                .collect();
            let conjuncts: usize = 1 + rng.below(3) as usize;
            let assumptions: Vec<TermId> = (0..conjuncts)
                .map(|_| random_predicate(&mut manager, rng, &vars, chosen.width, 2))
                .collect();
            let widths: Vec<(TermId, u32)> = vars
                .iter()
                .map(|&var: &TermId| (var, chosen.width))
                .collect();
            let satisfiable: bool = exhaustively_satisfiable(&manager, &assumptions, &widths);
            if !satisfiable {
                refutable += 1;
            }
            let free: Vec<TermId> = free_vars(&manager, &assumptions);
            let blasted: bool =
                term_conjunction_unsat(&manager, &assumptions, CROSS_BUDGET.node_budget);
            assert!(
                !(blasted && satisfiable),
                "{label}: the bit-blast re-prover confirmed a refutation of a satisfiable conjunction at seed {FUZZ_SEED:#x} iteration {iteration}, width {}, {} variable(s)",
                chosen.width,
                chosen.var_count
            );
            let by_disequality: bool =
                term_conjunction_unsat_via_polynomial(&manager, &assumptions);
            assert!(
                !(by_disequality && satisfiable),
                "{label}: the disequality re-prover confirmed a refutation of a satisfiable conjunction at seed {FUZZ_SEED:#x} iteration {iteration}, width {}, {} variable(s)",
                chosen.width,
                chosen.var_count
            );
            let domain: u64 = free
                .len()
                .try_into()
                .ok()
                .and_then(|count: u32| 1u64.checked_shl(count.saturating_mul(chosen.width)))
                .unwrap_or(u64::MAX);
            match independent_refutation(&manager, &assumptions, &free, CROSS_BUDGET) {
                Refutation::Confirmed(procedure) => {
                    assert!(
                        !satisfiable,
                        "{label}: the independent chain confirmed a refutation of a satisfiable conjunction at seed {FUZZ_SEED:#x} iteration {iteration}, width {}, {} variable(s)",
                        chosen.width, chosen.var_count
                    );
                    assert!(
                        !(procedure == Procedure::Enumeration
                            && domain > PRODUCTION_ENUMERATION_CAP),
                        "{label}: a domain of {domain} assignments is above the production cap of {PRODUCTION_ENUMERATION_CAP} and must not be confirmed by the enumerator"
                    );
                    match procedure {
                        Procedure::Enumeration => enumeration += 1,
                        Procedure::BitBlast => bit_blast += 1,
                        Procedure::Disequality => disequality += 1,
                    }
                }
                Refutation::Contradicted | Refutation::Undecided => {}
            }
        }
        (refutable, enumeration, bit_blast, disequality)
    }

    fn rust_sources(directory: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path: std::path::PathBuf = entry.path();
            if path.is_dir() {
                rust_sources(&path, into);
            } else if path
                .extension()
                .is_some_and(|kind: &std::ffi::OsStr| kind == "rs")
            {
                into.push(path);
            }
        }
    }

    #[test]
    fn the_primary_solver_is_constructed_only_behind_the_certified_funnel() {
        let source_root: std::path::PathBuf =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources: Vec<std::path::PathBuf> = Vec::new();
        rust_sources(&source_root, &mut sources);
        assert!(sources.len() > 10, "the source scan found too few files");
        let mut construction_sites: Vec<String> = Vec::new();
        for path in &sources {
            let Ok(body): std::io::Result<String> = std::fs::read_to_string(path) else {
                continue;
            };
            if body.contains(concat!("Solver", "::new()")) {
                let name: String = path
                    .file_name()
                    .and_then(|raw: &std::ffi::OsStr| raw.to_str())
                    .unwrap_or("?")
                    .to_owned();
                construction_sites.push(name);
            }
        }
        construction_sites.sort_unstable();
        construction_sites.dedup();
        assert_eq!(
            construction_sites,
            vec!["solver_cert.rs".to_owned()],
            "the primary solver may only be constructed inside the certifying funnel, so no caller can read a raw answer"
        );
    }

    #[test]
    fn a_re_prover_never_confirms_a_refutation_that_is_false() {
        let mut rng: Rng = Rng::new(FUZZ_SEED);
        let narrow: (u32, u32, u32, u32) = sweep(
            &mut rng,
            NARROW_ITERATIONS,
            &|rng: &mut Rng| Shape {
                width: 1 + rng.below(4),
                var_count: 1 + rng.below(2) as usize,
            },
            "narrow",
        );
        let wide: (u32, u32, u32, u32) = sweep(
            &mut rng,
            WIDE_ITERATIONS,
            &|rng: &mut Rng| {
                if rng.below(2) == 0 {
                    Shape {
                        width: 13 + rng.below(2),
                        var_count: 1,
                    }
                } else {
                    Shape {
                        width: 7,
                        var_count: 2,
                    }
                }
            },
            "wide",
        );
        println!(
            "mba independent refutation, domains at or below the production enumeration cap of {PRODUCTION_ENUMERATION_CAP}: {} refutable over {NARROW_ITERATIONS} cases, confirmed by enumeration {}, bit-blast {}, disequality {}",
            narrow.0, narrow.1, narrow.2, narrow.3
        );
        println!(
            "mba independent refutation, domains above that cap and at or below {TEST_ENUMERATION_CAP}: {} refutable over {WIDE_ITERATIONS} cases, confirmed by enumeration {}, bit-blast {}, disequality {}",
            wide.0, wide.1, wide.2, wide.3
        );
        assert!(
            narrow.1 >= MIN_ENUMERATION_CONFIRMATIONS,
            "the enumeration procedure confirmed only {} refutations, so its leg is close to vacuous",
            narrow.1
        );
        assert!(
            wide.2 >= MIN_BIT_BLAST_CONFIRMATIONS,
            "the bit-blast procedure confirmed only {} refutations above the enumeration cap, so the only conjunction-level check available to real formulas is close to vacuous",
            wide.2
        );
    }

    #[test]
    fn a_disequality_conjunction_needs_the_conjunction_level_check() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: SortId = manager.sorts.bitvec(16);
        let x: TermId = manager.mk_var("x", bv_sort);
        let zero: TermId = manager.mk_bitvec(0u64, 16);
        let one: TermId = manager.mk_bitvec(1u64, 16);
        let two: TermId = manager.mk_bitvec(2u64, 16);
        let differs_from_zero: TermId = {
            let equal: TermId = manager.mk_eq(x, zero);
            manager.mk_not(equal)
        };
        let differs_from_one: TermId = {
            let equal: TermId = manager.mk_eq(x, one);
            manager.mk_not(equal)
        };
        let below_two: TermId = manager.mk_bv_ult(x, two);
        let assumptions: [TermId; 3] = [differs_from_zero, differs_from_one, below_two];
        assert!(
            !term_conjunction_unsat_via_polynomial(&manager, &assumptions),
            "every conjunct is satisfiable alone, so the per-assumption shortcut must not claim a refutation"
        );
        assert!(
            term_conjunction_unsat(&manager, &assumptions, CROSS_BUDGET.node_budget),
            "the conjunction-level bit-blast must refute a conjunction no single assumption refutes"
        );
        let free: Vec<TermId> = free_vars(&manager, &assumptions);
        assert_eq!(
            independent_refutation(&manager, &assumptions, &free, CROSS_BUDGET),
            Refutation::Confirmed(Procedure::BitBlast),
            "at a width the enumerator cannot cover, the bit-blast must be the procedure that confirms"
        );
        assert_ne!(
            certified_check(&mut manager, &assumptions, CROSS_BUDGET),
            Certified::Sat,
            "a conjunction with no satisfying assignment must never certify Sat"
        );
    }

    #[test]
    fn the_enumerator_covers_the_narrow_width_of_the_same_conjunction() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: SortId = manager.sorts.bitvec(8);
        let x: TermId = manager.mk_var("x", bv_sort);
        let zero: TermId = manager.mk_bitvec(0u64, 8);
        let one: TermId = manager.mk_bitvec(1u64, 8);
        let two: TermId = manager.mk_bitvec(2u64, 8);
        let differs_from_zero: TermId = {
            let equal: TermId = manager.mk_eq(x, zero);
            manager.mk_not(equal)
        };
        let differs_from_one: TermId = {
            let equal: TermId = manager.mk_eq(x, one);
            manager.mk_not(equal)
        };
        let below_two: TermId = manager.mk_bv_ult(x, two);
        let assumptions: [TermId; 3] = [differs_from_zero, differs_from_one, below_two];
        let free: Vec<TermId> = free_vars(&manager, &assumptions);
        assert_eq!(
            independent_refutation(&manager, &assumptions, &free, CROSS_BUDGET),
            Refutation::Confirmed(Procedure::Enumeration),
            "a 256-assignment domain is inside the enumeration cap"
        );
        assert_ne!(
            certified_check(&mut manager, &assumptions, CROSS_BUDGET),
            Certified::Sat,
            "a conjunction with no satisfying assignment must never certify Sat"
        );
    }

    #[test]
    fn a_primary_model_that_does_not_satisfy_the_query_is_never_accepted() {
        for width in [8u32, 16, 32] {
            let mut manager: TermManager = TermManager::new();
            let bv_sort: SortId = manager.sorts.bitvec(width);
            let x: TermId = manager.mk_var("x", bv_sort);
            let zero: TermId = manager.mk_bitvec(0u64, width);
            let one: TermId = manager.mk_bitvec(1u64, width);
            let two: TermId = manager.mk_bitvec(2u64, width);
            let differs_from_zero: TermId = {
                let equal: TermId = manager.mk_eq(x, zero);
                manager.mk_not(equal)
            };
            let differs_from_one: TermId = {
                let equal: TermId = manager.mk_eq(x, one);
                manager.mk_not(equal)
            };
            let below_two: TermId = manager.mk_bv_ult(x, two);
            let assumptions: [TermId; 3] = [differs_from_zero, differs_from_one, below_two];
            let free: Vec<TermId> = free_vars(&manager, &assumptions);
            assert!(
                independent_refutation(&manager, &assumptions, &free, CROSS_BUDGET).confirms(),
                "the conjunction has no satisfying assignment at width {width}"
            );
            assert_eq!(
                certified_check(&mut manager, &assumptions, CROSS_BUDGET),
                Certified::Abstain,
                "at width {width} the primary answers satisfiable with a model that does not satisfy the query while the independent chain refutes, so the funnel must land on abstain"
            );
        }
    }

    #[test]
    fn an_independent_refutation_alone_never_reaches_an_accept() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: SortId = manager.sorts.bitvec(16);
        let x: TermId = manager.mk_var("x", bv_sort);
        let zero: TermId = manager.mk_bitvec(0u64, 16);
        let one: TermId = manager.mk_bitvec(1u64, 16);
        let two: TermId = manager.mk_bitvec(2u64, 16);
        let differs_from_zero: TermId = {
            let equal: TermId = manager.mk_eq(x, zero);
            manager.mk_not(equal)
        };
        let differs_from_one: TermId = {
            let equal: TermId = manager.mk_eq(x, one);
            manager.mk_not(equal)
        };
        let below_two: TermId = manager.mk_bv_ult(x, two);
        let assumptions: [TermId; 3] = [differs_from_zero, differs_from_one, below_two];
        let free: Vec<TermId> = free_vars(&manager, &assumptions);
        assert!(
            independent_refutation(&manager, &assumptions, &free, CROSS_BUDGET).confirms(),
            "the bit-blast refutes this conjunction on its own"
        );
        assert_eq!(
            certified_check(&mut manager, &assumptions, CROSS_BUDGET),
            Certified::Abstain,
            "the funnel abstains because the primary solver never proposed the refutation, so no accept rests on one procedure; a primary that starts refuting this conjunction will surface here"
        );
    }

    #[test]
    fn a_bit_blast_that_cannot_run_never_confirms_a_refutation() {
        let mut manager: TermManager = TermManager::new();
        let bv_sort: SortId = manager.sorts.bitvec(16);
        let x: TermId = manager.mk_var("x", bv_sort);
        let zero: TermId = manager.mk_bitvec(0u64, 16);
        let one: TermId = manager.mk_bitvec(1u64, 16);
        let two: TermId = manager.mk_bitvec(2u64, 16);
        let differs_from_zero: TermId = {
            let equal: TermId = manager.mk_eq(x, zero);
            manager.mk_not(equal)
        };
        let differs_from_one: TermId = {
            let equal: TermId = manager.mk_eq(x, one);
            manager.mk_not(equal)
        };
        let below_two: TermId = manager.mk_bv_ult(x, two);
        let assumptions: [TermId; 3] = [differs_from_zero, differs_from_one, below_two];
        let starved: CertBudget = CertBudget {
            node_budget: 0,
            ..CROSS_BUDGET
        };
        assert!(!term_conjunction_unsat(&manager, &assumptions, 0));
        let free: Vec<TermId> = free_vars(&manager, &assumptions);
        assert_eq!(
            independent_refutation(&manager, &assumptions, &free, starved),
            Refutation::Undecided,
            "a starved second procedure must leave the refutation unconfirmed"
        );
        assert_eq!(
            certified_check(&mut manager, &assumptions, starved),
            Certified::Abstain,
            "an unconfirmed refutation must abstain, never fold to the solver's own answer"
        );
    }

    #[test]
    fn a_bv_and_with_ult_contradiction_is_confirmed_by_a_second_procedure() {
        for width in [4u32, 8, 16, 32, 64] {
            let mut manager: TermManager = TermManager::new();
            let bv_sort: SortId = manager.sorts.bitvec(width);
            let x: TermId = manager.mk_var("x", bv_sort);
            let one: TermId = manager.mk_bitvec(1u64, width);
            let low_bit: TermId = manager.mk_bv_and(x, one);
            let odd: TermId = manager.mk_eq(low_bit, one);
            let below_one: TermId = manager.mk_bv_ult(x, one);
            let assumptions: [TermId; 2] = [odd, below_one];
            let free: Vec<TermId> = free_vars(&manager, &assumptions);
            let refutation: Refutation =
                independent_refutation(&manager, &assumptions, &free, CROSS_BUDGET);
            assert!(
                refutation.confirms(),
                "the bv_and plus ult contradiction at width {width} reached no independent confirmation"
            );
            assert_eq!(
                certified_check(&mut manager, &assumptions, CROSS_BUDGET),
                Certified::Unsat,
                "width {width}"
            );
        }
    }

    #[test]
    fn a_satisfiable_bv_and_with_ult_conjunction_is_never_confirmed_as_refuted() {
        for width in [4u32, 8, 16, 32, 64] {
            let mut manager: TermManager = TermManager::new();
            let bv_sort: SortId = manager.sorts.bitvec(width);
            let x: TermId = manager.mk_var("x", bv_sort);
            let one: TermId = manager.mk_bitvec(1u64, width);
            let four: TermId = manager.mk_bitvec(4u64, width);
            let low_bit: TermId = manager.mk_bv_and(x, one);
            let odd: TermId = manager.mk_eq(low_bit, one);
            let below_four: TermId = manager.mk_bv_ult(x, four);
            let assumptions: [TermId; 2] = [odd, below_four];
            let free: Vec<TermId> = free_vars(&manager, &assumptions);
            assert!(
                !independent_refutation(&manager, &assumptions, &free, CROSS_BUDGET).confirms(),
                "x odd and x below four is satisfiable at width {width} and must never be confirmed as refuted"
            );
            assert_ne!(
                certified_check(&mut manager, &assumptions, CROSS_BUDGET),
                Certified::Unsat,
                "width {width}"
            );
        }
    }
}
