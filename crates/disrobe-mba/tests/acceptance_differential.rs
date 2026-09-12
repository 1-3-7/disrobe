#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[path = "support/solver_requirement.rs"]
#[allow(clippy::redundant_pub_crate)]
mod solver_requirement;

use disrobe_mba::{
    BranchFold, CmpOp, Expr, OpaqueVerdict, Predicate, PredicateSimplification, Simplification,
    Verification, Width, classify, equivalence_query, fold_branch, is_column_faithful, simplify,
    simplify_predicate, truth_column,
};
use solver_requirement::{enforce_solver_requirement, solver_is_required};

const WIDE_FIRST_WIDTHS: [Width; 7] = [
    Width::W64,
    Width::W32,
    Width::W16,
    Width::W8,
    Width::W4,
    Width::W2,
    Width::W1,
];

const EXHAUSTIVE_EVAL_CAP: u128 = 1 << 22;
const DEEP_SWEEP_VAR: &str = "DISROBE_MBA_DEEP_DIFFERENTIAL";
const FIXED_CASES_PER_CELL: usize = 4;
const FIXED_PREDICATES_PER_CELL: u64 = 10;
const FIXED_PREDICATE_MAX_NODES: usize = 48;
const DEEP_SWEEP_BUDGET: Duration = Duration::from_mins(10);
const DEEP_PREDICATE_BUDGET: Duration = Duration::from_mins(5);
const FIXED_ACCEPTED_FLOORS: [(Width, usize); 3] =
    [(Width::W1, 69), (Width::W4, 45), (Width::W8, 40)];
const FIXED_EXHAUSTIVE_FLOORS: [(Width, usize); 3] =
    [(Width::W1, 69), (Width::W4, 45), (Width::W8, 40)];

const FAST_WIDTHS: [Width; 3] = [Width::W1, Width::W4, Width::W8];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepKind {
    FixedMatrix,
    Deep,
}

#[derive(Debug, Clone, Copy)]
struct Plan {
    label: &'static str,
    kind: SweepKind,
    widths: &'static [Width],
    max_vars: u32,
    max_nodes: usize,
    sweep_seeds: u64,
    predicate_seeds: u64,
    cross_product_values: usize,
    shared_random_envs: usize,
    pair_random_envs: usize,
}

const FAST_PLAN: Plan = Plan {
    label: "fixed narrow",
    kind: SweepKind::FixedMatrix,
    widths: &FAST_WIDTHS,
    max_vars: 2,
    max_nodes: 24,
    sweep_seeds: 0,
    predicate_seeds: 0,
    cross_product_values: 8,
    shared_random_envs: 48,
    pair_random_envs: 24,
};

const DEEP_PLAN: Plan = Plan {
    label: "deep",
    kind: SweepKind::Deep,
    widths: &WIDE_FIRST_WIDTHS,
    max_vars: 4,
    max_nodes: 48,
    sweep_seeds: 60,
    predicate_seeds: 250,
    cross_product_values: 20,
    shared_random_envs: 256,
    pair_random_envs: 128,
};

fn deep_sweep_requested() -> bool {
    let Some(raw): Option<std::ffi::OsString> = std::env::var_os(DEEP_SWEEP_VAR) else {
        return false;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    !matches!(text.as_str(), "" | "0" | "false" | "no" | "off")
}

fn active_plan() -> Plan {
    if deep_sweep_requested() {
        return DEEP_PLAN;
    }
    eprintln!(
        "NOT RUN: the deep sweep is opt-in. This run uses the {} matrix. Set {DEEP_SWEEP_VAR}=1 to run the broad timed sweep.",
        FAST_PLAN.label
    );
    FAST_PLAN
}

#[derive(Debug)]
struct SplitMix {
    state: u64,
}

impl SplitMix {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x2545_F491_4F6C_DD1D,
        }
    }

    const fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed: u64 = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    const fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 { 0 } else { self.next() % bound }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    LinearMba,
    PolynomialMba,
    NullResidue,
    NearNullResidue,
    NarrowVanishing,
    MixedArithBitwise,
    BooleanNest,
    OpaqueLeaf,
    FreeForm,
}

const SHAPES: [Shape; 9] = [
    Shape::LinearMba,
    Shape::PolynomialMba,
    Shape::NullResidue,
    Shape::NearNullResidue,
    Shape::NarrowVanishing,
    Shape::MixedArithBitwise,
    Shape::BooleanNest,
    Shape::OpaqueLeaf,
    Shape::FreeForm,
];

#[derive(Debug, Clone, Copy)]
struct FixedCell {
    width: Width,
    var_count: u32,
    shape: Shape,
    seeds: [u64; FIXED_CASES_PER_CELL],
}

const FIXED_MATRIX_CELLS: [FixedCell; 54] = [
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::LinearMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::PolynomialMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::NullResidue,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::NearNullResidue,
        seeds: [0, 2, 6, 7],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::NarrowVanishing,
        seeds: [0, 1, 2, 4],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::MixedArithBitwise,
        seeds: [0, 1, 7, 8],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::BooleanNest,
        seeds: [1, 3, 4, 5],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::OpaqueLeaf,
        seeds: [1, 2, 4, 9],
    },
    FixedCell {
        width: Width::W1,
        var_count: 1,
        shape: Shape::FreeForm,
        seeds: [0, 2, 5, 6],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::LinearMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::PolynomialMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::NullResidue,
        seeds: [3, 4, 5, 7],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::NearNullResidue,
        seeds: [6, 9, 10, 11],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::NarrowVanishing,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::MixedArithBitwise,
        seeds: [1, 2, 3, 6],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::BooleanNest,
        seeds: [1, 2, 3, 5],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::OpaqueLeaf,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W1,
        var_count: 2,
        shape: Shape::FreeForm,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::LinearMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::PolynomialMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::NullResidue,
        seeds: [2, 3, 4, 5],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::NearNullResidue,
        seeds: [1, 2, 5, 8],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::NarrowVanishing,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::MixedArithBitwise,
        seeds: [0, 5, 6, 8],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::BooleanNest,
        seeds: [1, 4, 5, 6],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::OpaqueLeaf,
        seeds: [0, 3, 5, 6],
    },
    FixedCell {
        width: Width::W4,
        var_count: 1,
        shape: Shape::FreeForm,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::LinearMba,
        seeds: [0, 2, 3, 4],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::PolynomialMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::NullResidue,
        seeds: [2, 5, 8, 9],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::NearNullResidue,
        seeds: [0, 3, 7, 14],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::NarrowVanishing,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::MixedArithBitwise,
        seeds: [8, 9, 10, 31],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::BooleanNest,
        seeds: [0, 5, 8, 9],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::OpaqueLeaf,
        seeds: [2, 4, 14, 16],
    },
    FixedCell {
        width: Width::W4,
        var_count: 2,
        shape: Shape::FreeForm,
        seeds: [0, 1, 4, 6],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::LinearMba,
        seeds: [0, 1, 2, 4],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::PolynomialMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::NullResidue,
        seeds: [2, 3, 6, 7],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::NearNullResidue,
        seeds: [0, 3, 4, 6],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::NarrowVanishing,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::MixedArithBitwise,
        seeds: [1, 5, 6, 23],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::BooleanNest,
        seeds: [0, 1, 4, 7],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::OpaqueLeaf,
        seeds: [3, 9, 10, 13],
    },
    FixedCell {
        width: Width::W8,
        var_count: 1,
        shape: Shape::FreeForm,
        seeds: [2, 3, 5, 8],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::LinearMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::PolynomialMba,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::NullResidue,
        seeds: [1, 2, 3, 5],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::NearNullResidue,
        seeds: [1, 14, 16, 17],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::NarrowVanishing,
        seeds: [0, 1, 2, 3],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::MixedArithBitwise,
        seeds: [5, 14, 23, 24],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::BooleanNest,
        seeds: [9, 16, 23, 25],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::OpaqueLeaf,
        seeds: [1, 3, 4, 8],
    },
    FixedCell {
        width: Width::W8,
        var_count: 2,
        shape: Shape::FreeForm,
        seeds: [1, 2, 3, 4],
    },
];

const FIXED_MATRIX_FINGERPRINT: u64 = 0x54E6_4B7B_DC87_B976;

const fn shape_name(shape: Shape) -> &'static str {
    match shape {
        Shape::LinearMba => "linear_mba",
        Shape::PolynomialMba => "polynomial_mba",
        Shape::NullResidue => "null_residue",
        Shape::NearNullResidue => "near_null_residue",
        Shape::NarrowVanishing => "narrow_vanishing",
        Shape::MixedArithBitwise => "mixed_arith_bitwise",
        Shape::BooleanNest => "boolean_nest",
        Shape::OpaqueLeaf => "opaque_leaf",
        Shape::FreeForm => "free_form",
    }
}

const fn verification_name(verification: Verification) -> &'static str {
    match verification {
        Verification::Unverified => "unverified",
        Verification::ExhaustiveAtWidth(_) => "exhaustive",
        Verification::LinearColumnIdentity(_) => "linear_column_identity",
        Verification::PolynomialIdentity(_) => "polynomial_identity",
        #[cfg(feature = "smt-verify")]
        Verification::SmtProvenAtWidth(_) => "bit_blast",
    }
}

const fn verification_width(verification: Verification) -> Option<Width> {
    match verification {
        Verification::Unverified => None,
        Verification::ExhaustiveAtWidth(width)
        | Verification::LinearColumnIdentity(width)
        | Verification::PolynomialIdentity(width) => Some(width),
        #[cfg(feature = "smt-verify")]
        Verification::SmtProvenAtWidth(width) => Some(width),
    }
}

fn bitwise_atoms(var_count: u32) -> Vec<Expr> {
    let mut pool: Vec<Expr> = Vec::new();
    for index in 0..var_count {
        pool.push(Expr::var(index));
        pool.push(Expr::not(Expr::var(index)));
    }
    for left in 0..var_count {
        for right in (left + 1)..var_count {
            pool.push(Expr::and(Expr::var(left), Expr::var(right)));
            pool.push(Expr::or(Expr::var(left), Expr::var(right)));
            pool.push(Expr::xor(Expr::var(left), Expr::var(right)));
            pool.push(Expr::not(Expr::and(Expr::var(left), Expr::var(right))));
            pool.push(Expr::and(Expr::var(left), Expr::not(Expr::var(right))));
        }
    }
    pool
}

fn opaque_atoms(var_count: u32) -> Vec<Expr> {
    let mut pool: Vec<Expr> = Vec::new();
    for index in 0..var_count {
        pool.push(Expr::shr(Expr::var(index), Expr::konst(1)));
        pool.push(Expr::slice(Expr::var(index), 0, 4));
        pool.push(Expr::mem(Expr::var(index), Width::W8));
        pool.push(Expr::mem(
            Expr::add(Expr::var(index), Expr::konst(4)),
            Width::W32,
        ));
        pool.push(Expr::ite(
            Expr::var(index),
            Expr::var(index),
            Expr::konst(1),
        ));
    }
    pool
}

fn pick<'pool>(rng: &mut SplitMix, pool: &'pool [Expr]) -> &'pool Expr {
    &pool[rng.below(pool.len() as u64) as usize]
}

fn scaled(coefficient: u64, base: Expr) -> Expr {
    match coefficient {
        0 => Expr::konst(0),
        1 => base,
        other => Expr::mul(Expr::konst(other), base),
    }
}

fn join_sum(rng: &mut SplitMix, terms: Vec<Expr>) -> Expr {
    let mut iterator: std::vec::IntoIter<Expr> = terms.into_iter();
    let Some(first): Option<Expr> = iterator.next() else {
        return Expr::konst(0);
    };
    let mut combined: Expr = first;
    for term in iterator {
        combined = if rng.below(2) == 0 {
            Expr::add(combined, term)
        } else {
            Expr::sub(combined, term)
        };
    }
    combined
}

fn random_coefficient(rng: &mut SplitMix, width: Width) -> u64 {
    let raw: u64 = rng.next();
    match rng.below(4) {
        0 => 1,
        1 => (raw % 8).wrapping_add(1) & width.mask(),
        2 => (1u64 << rng.below(u64::from(width.bits()))) & width.mask(),
        _ => raw & width.mask(),
    }
}

fn null_residue(rng: &mut SplitMix, pool: &[Expr], width: Width) -> Expr {
    let atom: Expr = pick(rng, pool).clone();
    let half: u64 = 1u64 << (width.bits() - 1);
    if rng.below(2) == 0 {
        let predecessor: Expr = Expr::add(atom.clone(), Expr::konst(width.mask()));
        Expr::mul(Expr::konst(half), Expr::mul(atom, predecessor))
    } else {
        let successor: Expr = Expr::add(atom.clone(), Expr::konst(1));
        Expr::mul(Expr::konst(half), Expr::mul(atom, successor))
    }
}

fn near_null_residue(rng: &mut SplitMix, pool: &[Expr], width: Width) -> Expr {
    let atom: Expr = pick(rng, pool).clone();
    let bits: u32 = width.bits();
    let quarter: u64 = if bits >= 2 { 1u64 << (bits - 2) } else { 1 };
    let predecessor: Expr = Expr::add(atom.clone(), Expr::konst(width.mask()));
    let second: Expr = Expr::add(atom.clone(), Expr::konst(width.mask().wrapping_sub(1)));
    Expr::mul(
        Expr::konst(quarter),
        Expr::mul(atom, Expr::mul(predecessor, second)),
    )
}

fn narrow_vanishing(rng: &mut SplitMix, pool: &[Expr], width: Width) -> Expr {
    let bits: u32 = width.bits();
    let narrow: u32 = 1 + rng.below(u64::from(bits.max(2) - 1)) as u32;
    let atom: Expr = pick(rng, pool).clone();
    let half: u64 = (1u64 << (narrow - 1)) & width.mask();
    let predecessor: Expr = Expr::add(atom.clone(), Expr::konst(width.mask()));
    let residue: Expr = Expr::mul(Expr::konst(half), Expr::mul(atom, predecessor));
    let shifted: Expr = scaled(
        (1u64 << rng.below(u64::from(bits))) & width.mask(),
        pick(rng, pool).clone(),
    );
    Expr::add(residue, shifted)
}

fn linear_mba(rng: &mut SplitMix, pool: &[Expr], width: Width) -> Expr {
    let count: usize = 2 + rng.below(4) as usize;
    let mut terms: Vec<Expr> = Vec::with_capacity(count);
    for _ in 0..count {
        let coefficient: u64 = random_coefficient(rng, width);
        let base: Expr = pick(rng, pool).clone();
        terms.push(match rng.below(6) {
            0 => Expr::shl(base, Expr::konst(rng.below(u64::from(width.bits()) + 2))),
            1 => Expr::neg(scaled(coefficient, base)),
            _ => scaled(coefficient, base),
        });
    }
    if rng.below(3) == 0 {
        terms.push(Expr::konst(rng.next() & width.mask()));
    }
    join_sum(rng, terms)
}

fn polynomial_mba(rng: &mut SplitMix, pool: &[Expr], width: Width) -> Expr {
    let count: usize = 1 + rng.below(3) as usize;
    let mut terms: Vec<Expr> = Vec::with_capacity(count);
    for _ in 0..count {
        let degree: u64 = 1 + rng.below(3);
        let mut product: Expr = pick(rng, pool).clone();
        for _ in 1..degree {
            product = Expr::mul(product, pick(rng, pool).clone());
        }
        terms.push(scaled(random_coefficient(rng, width), product));
    }
    join_sum(rng, terms)
}

fn mixed_arith_bitwise(rng: &mut SplitMix, pool: &[Expr], width: Width) -> Expr {
    let left: Expr = polynomial_mba(rng, pool, width);
    let right: Expr = linear_mba(rng, pool, width);
    match rng.below(4) {
        0 => Expr::xor(left, right),
        1 => Expr::and(left, right),
        2 => Expr::or(left, right),
        _ => Expr::xor(
            Expr::add(left.clone(), right.clone()),
            Expr::sub(left, right),
        ),
    }
}

fn boolean_nest(rng: &mut SplitMix, pool: &[Expr], depth: u32) -> Expr {
    if depth == 0 {
        return pick(rng, pool).clone();
    }
    let left: Expr = boolean_nest(rng, pool, depth - 1);
    let right: Expr = boolean_nest(rng, pool, depth - 1);
    match rng.below(5) {
        0 => Expr::and(left, right),
        1 => Expr::or(left, right),
        2 => Expr::xor(left, right),
        3 => Expr::not(Expr::and(left, right)),
        _ => Expr::or(
            Expr::and(left.clone(), Expr::not(right.clone())),
            Expr::and(Expr::not(left), right),
        ),
    }
}

fn free_form(rng: &mut SplitMix, pool: &[Expr], width: Width, depth: u32) -> Expr {
    if depth == 0 || rng.below(4) == 0 {
        return match rng.below(4) {
            0 => Expr::konst(rng.next() & width.mask()),
            _ => pick(rng, pool).clone(),
        };
    }
    let left: Expr = free_form(rng, pool, width, depth - 1);
    let right: Expr = free_form(rng, pool, width, depth - 1);
    match rng.below(12) {
        0 => Expr::add(left, right),
        1 => Expr::sub(left, right),
        2 => Expr::mul(left, right),
        3 => Expr::and(left, right),
        4 => Expr::or(left, right),
        5 => Expr::xor(left, right),
        6 => Expr::not(left),
        7 => Expr::neg(left),
        8 => Expr::shl(left, Expr::konst(rng.below(u64::from(width.bits()) + 3))),
        9 => Expr::shr(left, Expr::konst(rng.below(u64::from(width.bits()) + 3))),
        10 => Expr::ite(left, right, free_form(rng, pool, width, depth - 1)),
        _ => Expr::add(left, Expr::neg(right)),
    }
}

fn generate(shape: Shape, seed: u64, var_count: u32, width: Width) -> Expr {
    let mut rng: SplitMix = SplitMix::new(
        seed ^ (u64::from(width.bits()) << 40)
            ^ (u64::from(var_count) << 32)
            ^ ((shape as u64) << 24),
    );
    let bitwise: Vec<Expr> = bitwise_atoms(var_count);
    let opaque: Vec<Expr> = opaque_atoms(var_count);
    let mut mixed_pool: Vec<Expr> = bitwise.clone();
    mixed_pool.extend(opaque.iter().cloned());
    match shape {
        Shape::LinearMba => linear_mba(&mut rng, &bitwise, width),
        Shape::PolynomialMba => polynomial_mba(&mut rng, &bitwise, width),
        Shape::NullResidue => {
            let body: Expr = polynomial_mba(&mut rng, &bitwise, width);
            let residue: Expr = null_residue(&mut rng, &bitwise, width);
            Expr::add(body, residue)
        }
        Shape::NearNullResidue => {
            let body: Expr = polynomial_mba(&mut rng, &bitwise, width);
            let residue: Expr = near_null_residue(&mut rng, &bitwise, width);
            Expr::add(body, residue)
        }
        Shape::NarrowVanishing => narrow_vanishing(&mut rng, &bitwise, width),
        Shape::MixedArithBitwise => mixed_arith_bitwise(&mut rng, &bitwise, width),
        Shape::BooleanNest => {
            let depth: u32 = 2 + rng.below(2) as u32;
            boolean_nest(&mut rng, &bitwise, depth)
        }
        Shape::OpaqueLeaf => {
            let body: Expr = polynomial_mba(&mut rng, &mixed_pool, width);
            let residue: Expr = null_residue(&mut rng, &opaque, width);
            Expr::add(body, residue)
        }
        Shape::FreeForm => free_form(&mut rng, &mixed_pool, width, 4),
    }
}

fn lift_memory(expr: &Expr, table: &mut Vec<Expr>, first_free: u32) -> Expr {
    match expr {
        Expr::Mem(_, load_width) => {
            let position: usize = table
                .iter()
                .position(|known: &Expr| known == expr)
                .unwrap_or(table.len());
            if position == table.len() {
                table.push(expr.clone());
            }
            let index: u32 = first_free + position as u32;
            Expr::and(Expr::var(index), Expr::konst(load_width.mask()))
        }
        Expr::Const(_) | Expr::Var(_) => expr.clone(),
        Expr::Unary(op, inner) => Expr::Unary(*op, Box::new(lift_memory(inner, table, first_free))),
        Expr::Binary(op, left, right) => Expr::Binary(
            *op,
            Box::new(lift_memory(left, table, first_free)),
            Box::new(lift_memory(right, table, first_free)),
        ),
        Expr::Ite(cond, then_branch, else_branch) => Expr::Ite(
            Box::new(lift_memory(cond, table, first_free)),
            Box::new(lift_memory(then_branch, table, first_free)),
            Box::new(lift_memory(else_branch, table, first_free)),
        ),
        Expr::Slice(inner, lo, hi) => {
            Expr::Slice(Box::new(lift_memory(inner, table, first_free)), *lo, *hi)
        }
        Expr::Compose(low, high, low_bits) => Expr::Compose(
            Box::new(lift_memory(low, table, first_free)),
            Box::new(lift_memory(high, table, first_free)),
            *low_bits,
        ),
    }
}

fn boundary_values(width: Width) -> Vec<u64> {
    let mask: u64 = width.mask();
    let bits: u32 = width.bits();
    let sign: u64 = 1u64 << (bits - 1);
    let mut values: Vec<u64> = vec![
        0,
        1 & mask,
        2 & mask,
        3 & mask,
        mask,
        mask.wrapping_sub(1) & mask,
        mask.wrapping_sub(2) & mask,
        sign,
        sign.wrapping_sub(1) & mask,
        sign.wrapping_add(1) & mask,
        0x5555_5555_5555_5555 & mask,
        0xAAAA_AAAA_AAAA_AAAA & mask,
    ];
    for bit in 0..bits {
        let power: u64 = (1u64 << bit) & mask;
        values.push(power);
        values.push(power.wrapping_sub(1) & mask);
        values.push(power.wrapping_add(1) & mask);
    }
    values.sort_unstable();
    values.dedup();
    values
}

fn build_battery(width: Width, var_count: u32, plan: Plan) -> Vec<Vec<u64>> {
    let slots: usize = var_count as usize;
    let values: Vec<u64> = boundary_values(width);
    let mut battery: Vec<Vec<u64>> = Vec::new();
    for value in &values {
        battery.push(vec![*value; slots]);
    }
    if slots >= 2 {
        let stride: usize = values.len().div_ceil(plan.cross_product_values).max(1);
        let reduced: Vec<u64> = values.iter().copied().step_by(stride).collect();
        let mut filler: SplitMix = SplitMix::new(0x00C0_FFEE_0BAD_F00D ^ u64::from(width.bits()));
        for left in &reduced {
            for right in &reduced {
                let mut environment: Vec<u64> = Vec::with_capacity(slots);
                environment.push(*left);
                environment.push(*right);
                for _ in 2..slots {
                    let position: usize = filler.below(reduced.len() as u64) as usize;
                    environment.push(reduced.get(position).copied().unwrap_or(0));
                }
                battery.push(environment);
            }
        }
    }
    let mut rng: SplitMix = SplitMix::new(
        0x5EED_1234_ABCD_0001 ^ (u64::from(width.bits()) << 8) ^ u64::from(var_count),
    );
    for _ in 0..plan.shared_random_envs {
        battery.push((0..slots).map(|_| rng.next() & width.mask()).collect());
    }
    battery
}

#[derive(Debug)]
struct Batteries {
    plan: Plan,
    cache: BTreeMap<(u32, u32), Vec<Vec<u64>>>,
    values: BTreeMap<u32, Vec<u64>>,
}

impl Batteries {
    const fn new(plan: Plan) -> Self {
        Self {
            plan,
            cache: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }

    fn get(&mut self, width: Width, var_count: u32) -> &[Vec<u64>] {
        let plan: Plan = self.plan;
        self.cache
            .entry((width.bits(), var_count))
            .or_insert_with(|| build_battery(width, var_count, plan))
    }

    fn values(&mut self, width: Width) -> &[u64] {
        self.values
            .entry(width.bits())
            .or_insert_with(|| boundary_values(width))
    }
}

fn pair_environments(
    width: Width,
    var_count: u32,
    seed: u64,
    values: &[u64],
    rounds: usize,
) -> Vec<Vec<u64>> {
    let slots: usize = var_count as usize;
    let mut rng: SplitMix = SplitMix::new(seed ^ 0x00A5_5A00_F0F0_0F0F);
    let mut environments: Vec<Vec<u64>> = Vec::with_capacity(rounds);
    for round in 0..rounds {
        let environment: Vec<u64> = (0..slots)
            .map(|_| {
                if round % 3 == 0 {
                    let position: usize = rng.below(values.len() as u64) as usize;
                    values.get(position).copied().unwrap_or(0)
                } else {
                    rng.next() & width.mask()
                }
            })
            .collect();
        environments.push(environment);
    }
    environments
}

fn disagreement(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    environments: &[Vec<u64>],
) -> Option<Vec<u64>> {
    environments
        .iter()
        .find(|environment: &&Vec<u64>| {
            original.eval(environment, width) != candidate.eval(environment, width)
        })
        .cloned()
}

fn domain_size(width: Width, var_count: u32) -> u128 {
    let modulus: u128 = width.modulus();
    let mut total: u128 = 1;
    for _ in 0..var_count {
        total = total.saturating_mul(modulus);
    }
    total
}

fn exhaustive_disagreement(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: u32,
) -> Option<Vec<u64>> {
    let modulus: u128 = width.modulus();
    let total: u128 = domain_size(width, var_count);
    if total > EXHAUSTIVE_EVAL_CAP {
        return None;
    }
    let mut environment: Vec<u64> = vec![0; var_count as usize];
    for index in 0..total {
        let mut remaining: u128 = index;
        for slot in &mut environment {
            *slot = (remaining % modulus) as u64;
            remaining /= modulus;
        }
        if original.eval(&environment, width) != candidate.eval(&environment, width) {
            return Some(environment);
        }
    }
    None
}

fn exhaustive_environments(width: Width, var_count: u32) -> Vec<Vec<u64>> {
    let modulus: u128 = width.modulus();
    let total: u128 = domain_size(width, var_count);
    assert!(
        total <= EXHAUSTIVE_EVAL_CAP,
        "the requested predicate domain at {width:?} with {var_count} variables exceeds the exhaustive cap"
    );
    let Ok(capacity): Result<usize, std::num::TryFromIntError> = usize::try_from(total) else {
        panic!("the requested predicate domain does not fit in memory");
    };
    let mut environments: Vec<Vec<u64>> = Vec::with_capacity(capacity);
    for index in 0..total {
        let mut remaining: u128 = index;
        let mut environment: Vec<u64> = vec![0; var_count as usize];
        for slot in &mut environment {
            *slot = (remaining % modulus) as u64;
            remaining /= modulus;
        }
        environments.push(environment);
    }
    environments
}

#[derive(Debug, Default)]
struct Tally {
    generated: usize,
    accepted: usize,
    exhaustively_checked: usize,
    sampled_only: usize,
    sample_points: u64,
    failures: Vec<String>,
    by_tag: BTreeMap<(&'static str, u32), usize>,
    generated_by_width: BTreeMap<u32, usize>,
    generated_by_cell: BTreeMap<(&'static str, u32, u32), usize>,
    exhaustively_checked_by_width: BTreeMap<u32, usize>,
    accepted_by_width: BTreeMap<u32, usize>,
    accepted_by_shape: BTreeMap<(&'static str, u32), usize>,
    deadline_hit: bool,
}

impl Tally {
    fn wide_tag_total(&self, tag: &str) -> usize {
        self.by_tag
            .iter()
            .filter(|((name, bits), _): &(&(&'static str, u32), &usize)| {
                *name == tag && *bits >= 32
            })
            .map(|(_, count): (&(&'static str, u32), &usize)| *count)
            .sum()
    }
}

fn check_acceptance(
    tally: &mut Tally,
    batteries: &mut Batteries,
    shape: Shape,
    width: Width,
    seed: u64,
    original: &Expr,
    result: &Simplification,
) {
    let mut table: Vec<Expr> = Vec::new();
    let dense_vars: u32 = original.max_var().map_or(0, |index: u32| index + 1);
    let lifted_original: Expr = lift_memory(original, &mut table, dense_vars);
    let lifted_candidate: Expr = lift_memory(&result.simplified, &mut table, dense_vars);
    let reference_vars: u32 = dense_vars + table.len() as u32;

    if domain_size(width, reference_vars) <= EXHAUSTIVE_EVAL_CAP {
        tally.exhaustively_checked += 1;
        *tally
            .exhaustively_checked_by_width
            .entry(width.bits())
            .or_default() += 1;
        tally.sample_points += domain_size(width, reference_vars) as u64;
        if let Some(environment) =
            exhaustive_disagreement(&lifted_original, &lifted_candidate, width, reference_vars)
        {
            tally.failures.push(format!(
                "{} at {width:?} seed {seed}: `{original}` -> `{}` differs exhaustively at {environment:?} ({} vs {}), verdict {:?}",
                shape_name(shape),
                result.simplified,
                lifted_original.eval(&environment, width),
                lifted_candidate.eval(&environment, width),
                result.verification
            ));
        }
        return;
    }

    tally.sampled_only += 1;
    let rounds: usize = batteries.plan.pair_random_envs;
    let extra: Vec<Vec<u64>> = {
        let values: &[u64] = batteries.values(width);
        pair_environments(width, reference_vars, seed, values, rounds)
    };
    let shared: &[Vec<u64>] = batteries.get(width, reference_vars);
    tally.sample_points += (shared.len() + extra.len()) as u64;
    let found: Option<Vec<u64>> = disagreement(&lifted_original, &lifted_candidate, width, shared)
        .or_else(|| -> Option<Vec<u64>> {
            disagreement(&lifted_original, &lifted_candidate, width, &extra)
        });
    if let Some(environment) = found {
        tally.failures.push(format!(
            "{} at {width:?} seed {seed}: `{original}` -> `{}` differs at {environment:?} ({} vs {}), verdict {:?}",
            shape_name(shape),
            result.simplified,
            lifted_original.eval(&environment, width),
            lifted_candidate.eval(&environment, width),
            result.verification
        ));
    }
}

fn exercise_case(
    tally: &mut Tally,
    batteries: &mut Batteries,
    shape: Shape,
    width: Width,
    var_count: u32,
    seed: u64,
    original: Expr,
) {
    tally.generated += 1;
    *tally.generated_by_width.entry(width.bits()).or_default() += 1;
    *tally
        .generated_by_cell
        .entry((shape_name(shape), width.bits(), var_count))
        .or_default() += 1;
    let result: Simplification = simplify(&original, width);
    *tally
        .by_tag
        .entry((verification_name(result.verification), width.bits()))
        .or_default() += 1;
    if !result.changed() {
        assert_eq!(
            result.verification,
            Verification::Unverified,
            "an unchanged expression must carry no verdict, got {:?} for `{original}` at {width:?}",
            result.verification
        );
        return;
    }
    assert!(
        result.verification.is_proven(),
        "{} at {width:?} seed {seed}: `{original}` was rewritten to `{}` with no proof",
        shape_name(shape),
        result.simplified
    );
    assert_eq!(
        verification_width(result.verification),
        Some(width),
        "{} at {width:?} seed {seed}: `{original}` was accepted on a verdict recorded for another width",
        shape_name(shape)
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "{} at {width:?} seed {seed}: `{original}` was rewritten without shrinking",
        shape_name(shape)
    );
    tally.accepted += 1;
    *tally.accepted_by_width.entry(width.bits()).or_default() += 1;
    *tally
        .accepted_by_shape
        .entry((shape_name(shape), width.bits()))
        .or_default() += 1;
    check_acceptance(tally, batteries, shape, width, seed, &original, &result);
}

fn fixed_matrix_fingerprint(cases: &[(Shape, Width, u32, u64, Expr)]) -> u64 {
    let mut fingerprint: u64 = 0xCBF2_9CE4_8422_2325;
    for (shape, width, var_count, seed, original) in cases {
        let canonical: String = format!(
            "{}:{}:{var_count}:{seed}:{original:?}\n",
            shape_name(*shape),
            width.bits()
        );
        for byte in canonical.bytes() {
            fingerprint ^= u64::from(byte);
            fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    fingerprint
}

fn fixed_matrix_cases(plan: Plan) -> Vec<(Shape, Width, u32, u64, Expr)> {
    assert_eq!(
        plan.kind,
        SweepKind::FixedMatrix,
        "the fixed corpus was invoked for a non-fixed plan"
    );
    let expected_cells: usize = plan.widths.len() * plan.max_vars as usize * SHAPES.len();
    assert_eq!(
        FIXED_MATRIX_CELLS.len(),
        expected_cells,
        "the fixed corpus no longer matches the default Cartesian matrix"
    );
    let mut configured_cells: BTreeMap<(&'static str, u32, u32), usize> = BTreeMap::new();
    let mut cases: Vec<(Shape, Width, u32, u64, Expr)> = Vec::new();
    for cell in FIXED_MATRIX_CELLS {
        assert!(
            plan.widths.contains(&cell.width),
            "the fixed corpus includes an unsupported width {:?}",
            cell.width
        );
        assert!(
            (1..=plan.max_vars).contains(&cell.var_count),
            "the fixed corpus includes an unsupported variable count {}",
            cell.var_count
        );
        assert!(
            SHAPES.contains(&cell.shape),
            "the fixed corpus includes an unsupported shape {}",
            shape_name(cell.shape)
        );
        *configured_cells
            .entry((shape_name(cell.shape), cell.width.bits(), cell.var_count))
            .or_default() += 1;
        let mut generated: Vec<Expr> = Vec::with_capacity(FIXED_CASES_PER_CELL);
        for seed in cell.seeds {
            let original: Expr = generate(cell.shape, seed, cell.var_count, cell.width);
            assert!(
                original.node_count() <= plan.max_nodes,
                "the fixed corpus case {} at {:?} seed {seed} has {} nodes, above the {}-node bound",
                shape_name(cell.shape),
                cell.width,
                original.node_count(),
                plan.max_nodes
            );
            assert!(
                !generated
                    .iter()
                    .any(|existing: &Expr| existing == &original),
                "the fixed corpus repeats {} at {:?} with {} variables",
                shape_name(cell.shape),
                cell.width,
                cell.var_count
            );
            generated.push(original.clone());
            cases.push((cell.shape, cell.width, cell.var_count, seed, original));
        }
    }
    for width in plan.widths.iter().copied() {
        for var_count in 1u32..=plan.max_vars {
            for shape in SHAPES {
                assert_eq!(
                    configured_cells
                        .get(&(shape_name(shape), width.bits(), var_count))
                        .copied()
                        .unwrap_or(0),
                    1,
                    "the fixed corpus has the wrong number of {} cells at {width:?} with {var_count} variables",
                    shape_name(shape)
                );
            }
        }
    }
    assert_eq!(
        cases.len(),
        expected_cells * FIXED_CASES_PER_CELL,
        "the fixed corpus has the wrong number of cases"
    );
    let fingerprint: u64 = fixed_matrix_fingerprint(&cases);
    assert_eq!(
        fingerprint, FIXED_MATRIX_FINGERPRINT,
        "the fixed corpus identity changed: got {fingerprint:#018x}"
    );
    cases
}

fn sweep_fixed_matrix(plan: Plan) -> Tally {
    let mut tally: Tally = Tally::default();
    let mut batteries: Batteries = Batteries::new(plan);
    for (shape, width, var_count, seed, original) in fixed_matrix_cases(plan) {
        exercise_case(
            &mut tally,
            &mut batteries,
            shape,
            width,
            var_count,
            seed,
            original,
        );
    }
    tally
}

fn sweep_deep(plan: Plan) -> Tally {
    let deadline: Instant = Instant::now() + DEEP_SWEEP_BUDGET;
    let mut tally: Tally = Tally::default();
    let mut batteries: Batteries = Batteries::new(plan);
    for width in plan.widths.iter().copied() {
        for var_count in 1u32..=plan.max_vars {
            for shape in SHAPES {
                for seed in 0..plan.sweep_seeds {
                    if Instant::now() >= deadline {
                        tally.deadline_hit = true;
                        return tally;
                    }
                    let original: Expr = generate(shape, seed, var_count, width);
                    if original.node_count() > plan.max_nodes {
                        continue;
                    }
                    exercise_case(
                        &mut tally,
                        &mut batteries,
                        shape,
                        width,
                        var_count,
                        seed,
                        original,
                    );
                }
            }
        }
    }
    tally
}

fn sweep(plan: Plan) -> Tally {
    match plan.kind {
        SweepKind::FixedMatrix => sweep_fixed_matrix(plan),
        SweepKind::Deep => sweep_deep(plan),
    }
}

fn report(tally: &Tally) {
    eprintln!(
        "acceptance differential: generated={} accepted={} exhaustively_checked={} sampled_only={} independent_evaluations={} failures={} deadline_hit={}",
        tally.generated,
        tally.accepted,
        tally.exhaustively_checked,
        tally.sampled_only,
        tally.sample_points,
        tally.failures.len(),
        tally.deadline_hit
    );
    for ((tag, bits), count) in &tally.by_tag {
        eprintln!("  verdict {tag} at {bits} bits: {count}");
    }
    for ((shape, bits), count) in &tally.accepted_by_shape {
        eprintln!("  accepted {shape} at {bits} bits: {count}");
    }
    for (bits, generated) in &tally.generated_by_width {
        let exhaustive: usize = tally
            .exhaustively_checked_by_width
            .get(bits)
            .copied()
            .unwrap_or(0);
        eprintln!("  width {bits}: generated={generated} exhaustive={exhaustive}");
    }
}

fn assert_fixed_matrix_coverage(tally: &Tally) {
    let expected_per_width: usize =
        SHAPES.len() * FAST_PLAN.max_vars as usize * FIXED_CASES_PER_CELL;
    for width in FAST_PLAN.widths.iter().copied() {
        let Some((_, accepted_floor)): Option<&(Width, usize)> = FIXED_ACCEPTED_FLOORS
            .iter()
            .find(|(candidate, _): &&(Width, usize)| *candidate == width)
        else {
            panic!("the fixed acceptance floors omit {width:?}");
        };
        let Some((_, exhaustive_floor)): Option<&(Width, usize)> = FIXED_EXHAUSTIVE_FLOORS
            .iter()
            .find(|(candidate, _): &&(Width, usize)| *candidate == width)
        else {
            panic!("the fixed exhaustive floors omit {width:?}");
        };
        assert_eq!(
            tally
                .generated_by_width
                .get(&width.bits())
                .copied()
                .unwrap_or(0),
            expected_per_width,
            "the fixed matrix covered the wrong number of expressions at {width:?}"
        );
        assert!(
            tally
                .accepted_by_width
                .get(&width.bits())
                .copied()
                .unwrap_or(0)
                >= *accepted_floor,
            "the fixed matrix accepted too few cases at {width:?}: floor is {accepted_floor}"
        );
        assert!(
            tally
                .exhaustively_checked_by_width
                .get(&width.bits())
                .copied()
                .unwrap_or(0)
                >= *exhaustive_floor,
            "the fixed matrix performed too few whole-domain checks at {width:?}: floor is {exhaustive_floor}"
        );
        for var_count in 1u32..=FAST_PLAN.max_vars {
            for shape in SHAPES {
                assert_eq!(
                    tally
                        .generated_by_cell
                        .get(&(shape_name(shape), width.bits(), var_count))
                        .copied()
                        .unwrap_or(0),
                    FIXED_CASES_PER_CELL,
                    "the fixed matrix covered the wrong number of {} cases at {width:?} with {var_count} variables",
                    shape_name(shape)
                );
            }
        }
    }
}

#[test]
fn accepted_rewrites_survive_an_independent_equivalence_check() {
    let plan: Plan = active_plan();
    let deep: bool = plan.kind == SweepKind::Deep;
    let tally: Tally = sweep(plan);
    report(&tally);

    assert!(
        tally.failures.is_empty(),
        "{} accepted rewrites failed the independent check:\n{}",
        tally.failures.len(),
        tally.failures.join("\n")
    );
    let (generated_floor, accepted_floor, exhaustive_floor): (usize, usize, usize) = if deep {
        (10_000, 800, 300)
    } else {
        (
            FAST_PLAN.widths.len()
                * FAST_PLAN.max_vars as usize
                * SHAPES.len()
                * FIXED_CASES_PER_CELL,
            FIXED_ACCEPTED_FLOORS
                .iter()
                .map(|(_, floor): &(Width, usize)| *floor)
                .sum(),
            FIXED_EXHAUSTIVE_FLOORS
                .iter()
                .map(|(_, floor): &(Width, usize)| *floor)
                .sum(),
        )
    };
    assert!(
        tally.generated >= generated_floor,
        "a sweep this small proves little: only {} expressions were generated, floor is {generated_floor}",
        tally.generated
    );
    assert!(
        tally.accepted >= accepted_floor,
        "a sweep that accepts almost nothing checks almost nothing: only {} rewrites were accepted, floor is {accepted_floor}",
        tally.accepted
    );
    assert!(
        tally.exhaustively_checked >= exhaustive_floor,
        "only {} acceptances were graded by whole-domain enumeration, floor is {exhaustive_floor}",
        tally.exhaustively_checked
    );
    if deep {
        assert!(
            !tally.deadline_hit,
            "the deep sweep ran out of wall clock after {} expressions, so its verdict does not cover the plan",
            tally.generated
        );
        assert!(
            tally.wide_tag_total("polynomial_identity") > 0,
            "the polynomial-identity leg is the weakest wide acceptance path and the sweep never reached it"
        );
        assert!(
            tally.wide_tag_total("linear_column_identity") > 0,
            "the column-identity leg is a wide acceptance path and the sweep never reached it"
        );
    } else {
        assert_fixed_matrix_coverage(&tally);
    }
}

#[test]
fn independent_evaluator_rejects_a_bad_rewrite() {
    let original: Expr = Expr::add(Expr::var(0), Expr::var(1));
    let wrong: Expr = Expr::sub(Expr::var(0), Expr::var(1));
    assert!(
        exhaustive_disagreement(&original, &wrong, Width::W4, 2).is_some(),
        "the independent evaluator did not reject a deliberately non-equivalent rewrite"
    );
}

const fn width_vanishing_constants() -> [(Width, u64); 3] {
    [
        (Width::W8, 0x100),
        (Width::W16, 0x1_0000),
        (Width::W32, 0x1_0000_0000),
    ]
}

fn column_reproduces_evaluation(expr: &Expr, width: Width, var_count: u32) -> bool {
    let rows: usize = 1usize << var_count;
    let column: Vec<i128> = truth_column(expr, var_count, rows);
    let modulus: i128 = width.modulus() as i128;
    build_battery(width, var_count, FAST_PLAN)
        .into_iter()
        .all(|environment: Vec<u64>| -> bool {
            let mut reconstructed: i128 = 0;
            for bit in (0..width.bits()).rev() {
                let mut row: usize = 0;
                for (index, value) in environment.iter().enumerate() {
                    row |= (((*value >> bit) & 1) as usize) << index;
                }
                let entry: i128 = column.get(row).copied().unwrap_or_default();
                reconstructed = (reconstructed * 2 + entry.rem_euclid(modulus)).rem_euclid(modulus);
            }
            i128::from(expr.eval(&environment, width)) == reconstructed
        })
}

#[test]
fn a_bitwise_constant_that_vanishes_at_the_width_is_not_column_faithful() {
    for (width, constant) in width_vanishing_constants() {
        let masked_off: Expr = Expr::and(Expr::var(0), Expr::konst(constant));
        assert!(
            !column_reproduces_evaluation(&masked_off, width, 1),
            "`{masked_off}` at {width:?} reproduces its value through the truth column, so this guard is aimed at the wrong shape"
        );
        assert!(
            !is_column_faithful(&masked_off, width),
            "`{masked_off}` at {width:?} is reported column faithful, yet its truth column reads the constant as all ones and rebuilds `v0` instead of 0"
        );
        let result: Simplification = simplify(&masked_off, width);
        assert_ne!(
            result.verification,
            Verification::LinearColumnIdentity(width),
            "`{masked_off}` at {width:?} must not be carried by the column identity"
        );
        let environments: Vec<Vec<u64>> = build_battery(width, 1, FAST_PLAN);
        if let Some(environment) =
            disagreement(&masked_off, &result.simplified, width, &environments)
        {
            panic!(
                "`{masked_off}` at {width:?} was rewritten to `{}` which differs at {environment:?}",
                result.simplified
            );
        }
    }
}

fn column_shape_pool(var_count: u32, width: Width) -> Vec<Expr> {
    let mut pool: Vec<Expr> = bitwise_atoms(var_count);
    let bits: u32 = width.bits();
    for index in 0..var_count {
        pool.push(Expr::and(
            Expr::var(index),
            Expr::konst(1u64.wrapping_shl(bits)),
        ));
        pool.push(Expr::xor(
            Expr::var(index),
            Expr::konst(1u64.wrapping_shl(bits)),
        ));
        pool.push(Expr::or(Expr::var(index), Expr::konst(width.mask())));
        pool.push(Expr::and(Expr::var(index), Expr::konst(0)));
        pool.push(Expr::not(Expr::konst(0)));
        pool.push(Expr::shl(Expr::var(index), Expr::konst(u64::from(bits))));
    }
    pool
}

fn column_shape(rng: &mut SplitMix, pool: &[Expr], width: Width, depth: u32) -> Expr {
    if depth == 0 {
        return pick(rng, pool).clone();
    }
    let left: Expr = column_shape(rng, pool, width, depth - 1);
    let right: Expr = column_shape(rng, pool, width, depth - 1);
    match rng.below(7) {
        0 => Expr::add(left, right),
        1 => Expr::sub(left, right),
        2 => Expr::neg(left),
        3 => scaled(random_coefficient(rng, width), left),
        4 => Expr::shl(left, Expr::konst(rng.below(u64::from(width.bits()) + 2))),
        5 => Expr::and(left, right),
        _ => Expr::xor(left, right),
    }
}

#[test]
fn column_faithfulness_implies_the_truth_column_reproduces_evaluation() {
    let mut faithful: usize = 0;
    let mut rejected: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
        for var_count in 1u32..=3 {
            let pool: Vec<Expr> = column_shape_pool(var_count, width);
            for seed in 0..900u64 {
                let mut rng: SplitMix =
                    SplitMix::new(seed ^ (u64::from(width.bits()) << 32) ^ u64::from(var_count));
                let depth: u32 = 1 + rng.below(3) as u32;
                let expr: Expr = column_shape(&mut rng, &pool, width, depth);
                if expr.node_count() > DEEP_PLAN.max_nodes {
                    continue;
                }
                if !is_column_faithful(&expr, width) {
                    rejected += 1;
                    continue;
                }
                faithful += 1;
                if !column_reproduces_evaluation(&expr, width, var_count) {
                    failures.push(format!(
                        "`{expr}` at {width:?} is reported column faithful but its truth column does not reproduce its value"
                    ));
                }
            }
        }
    }
    eprintln!(
        "column faithfulness: {faithful} shapes admitted, {rejected} rejected, {} broken",
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} column-faithful shapes are not reproduced by their truth column:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        faithful >= 500,
        "only {faithful} shapes were admitted, too few to test the predicate"
    );
    assert!(
        rejected > 0,
        "the generator produced nothing the predicate rejects, so it is not probing the boundary"
    );
}

const COMPARISONS: [CmpOp; 10] = [
    CmpOp::Eq,
    CmpOp::Ne,
    CmpOp::UnsignedLt,
    CmpOp::UnsignedLe,
    CmpOp::UnsignedGt,
    CmpOp::UnsignedGe,
    CmpOp::SignedLt,
    CmpOp::SignedLe,
    CmpOp::SignedGt,
    CmpOp::SignedGe,
];

fn evaluable_atoms(var_count: u32) -> Vec<Expr> {
    let mut pool: Vec<Expr> = bitwise_atoms(var_count);
    for index in 0..var_count {
        pool.push(Expr::shr(Expr::var(index), Expr::konst(1)));
        pool.push(Expr::slice(Expr::var(index), 0, 4));
        pool.push(Expr::mul(Expr::var(index), Expr::var(index)));
    }
    pool
}

fn random_predicate(rng: &mut SplitMix, pool: &[Expr], width: Width, depth: u32) -> Predicate {
    if depth == 0 || rng.below(3) == 0 {
        let left: Expr = pick(rng, pool).clone();
        let position: usize = rng.below(COMPARISONS.len() as u64) as usize;
        let op: CmpOp = COMPARISONS.get(position).copied().unwrap_or(CmpOp::Eq);
        return match rng.below(6) {
            0 => Predicate::Nonzero(left),
            1 => Predicate::Compare {
                op,
                left,
                right: Expr::konst(rng.next() & width.mask()),
            },
            _ => Predicate::Compare {
                op,
                left,
                right: pick(rng, pool).clone(),
            },
        };
    }
    let left: Predicate = random_predicate(rng, pool, width, depth - 1);
    let right: Predicate = random_predicate(rng, pool, width, depth - 1);
    if rng.below(2) == 0 {
        Predicate::or(left, right)
    } else {
        Predicate::and(left, right)
    }
}

#[test]
fn accepted_predicate_rewrites_and_opaque_verdicts_survive_an_independent_check() {
    let plan: Plan = active_plan();
    let deep: bool = plan.kind == SweepKind::Deep;
    let deadline: Option<Instant> = deep.then(|| Instant::now() + DEEP_PREDICATE_BUDGET);
    let seeds_per_cell: u64 = if deep {
        plan.predicate_seeds
    } else {
        FIXED_PREDICATES_PER_CELL
    };
    let max_nodes: usize = if deep {
        plan.max_nodes
    } else {
        FIXED_PREDICATE_MAX_NODES
    };
    let mut batteries: Batteries = Batteries::new(plan);
    let mut generated: usize = 0;
    let mut generated_by_cell: BTreeMap<(u32, u32), usize> = BTreeMap::new();
    let mut exhaustively_checked_by_width: BTreeMap<u32, usize> = BTreeMap::new();
    let mut rewritten: usize = 0;
    let mut always_true: usize = 0;
    let mut always_false: usize = 0;
    let mut data_dependent: usize = 0;
    let mut out_of_budget: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut deadline_hit: bool = false;

    for width in plan.widths.iter().copied() {
        for var_count in 1u32..=plan.max_vars.min(3) {
            let pool: Vec<Expr> = evaluable_atoms(var_count);
            let environments: Vec<Vec<u64>> = if deep {
                batteries.get(width, var_count).to_vec()
            } else {
                *exhaustively_checked_by_width
                    .entry(width.bits())
                    .or_default() += FIXED_PREDICATES_PER_CELL as usize;
                exhaustive_environments(width, var_count)
            };
            for seed in 0..seeds_per_cell {
                if let Some(limit) = deadline
                    && Instant::now() >= limit
                {
                    deadline_hit = true;
                    break;
                }
                let mut rng: SplitMix = SplitMix::new(
                    seed ^ (u64::from(width.bits()) << 48) ^ (u64::from(var_count) << 40),
                );
                let depth: u32 = 1 + rng.below(2) as u32;
                let original: Predicate = random_predicate(&mut rng, &pool, width, depth);
                if original.node_count() > max_nodes {
                    assert!(
                        deep,
                        "the fixed predicate matrix produced `{original:?}` at {width:?} seed {seed} with {} nodes, above the {}-node bound",
                        original.node_count(),
                        max_nodes
                    );
                    continue;
                }
                generated += 1;
                *generated_by_cell
                    .entry((width.bits(), var_count))
                    .or_default() += 1;

                let result: PredicateSimplification = simplify_predicate(&original, width);
                if result.changed() {
                    rewritten += 1;
                    assert!(
                        result.verification.is_proven(),
                        "`{original:?}` was rewritten at {width:?} with no proof"
                    );
                    let divergent: Option<&Vec<u64>> =
                        environments.iter().find(|environment: &&Vec<u64>| {
                            original.evaluate(environment, width)
                                != result.simplified.evaluate(environment, width)
                        });
                    if let Some(environment) = divergent {
                        failures.push(format!(
                            "predicate at {width:?} seed {seed}: `{original:?}` -> `{:?}` differs at {environment:?}",
                            result.simplified
                        ));
                    }
                }

                match classify(&original, width) {
                    OpaqueVerdict::AlwaysTrue { .. } => {
                        always_true += 1;
                        let divergent: Option<&Vec<u64>> = environments
                            .iter()
                            .find(|environment: &&Vec<u64>| !original.evaluate(environment, width));
                        if let Some(environment) = divergent {
                            failures.push(format!(
                                "predicate at {width:?} seed {seed}: `{original:?}` was called always true but is false at {environment:?}"
                            ));
                        }
                    }
                    OpaqueVerdict::AlwaysFalse { .. } => {
                        always_false += 1;
                        let divergent: Option<&Vec<u64>> = environments
                            .iter()
                            .find(|environment: &&Vec<u64>| original.evaluate(environment, width));
                        if let Some(environment) = divergent {
                            failures.push(format!(
                                "predicate at {width:?} seed {seed}: `{original:?}` was called always false but is true at {environment:?}"
                            ));
                        }
                    }
                    OpaqueVerdict::DataDependent => {
                        data_dependent += 1;
                    }
                    OpaqueVerdict::OutOfBudget => {
                        out_of_budget += 1;
                    }
                }
            }
        }
    }

    eprintln!(
        "predicate differential: generated={generated} rewritten={rewritten} always_true={always_true} always_false={always_false} data_dependent={data_dependent} out_of_budget={out_of_budget} exhaustive_by_width={exhaustively_checked_by_width:?} failures={} deadline_hit={deadline_hit}",
        failures.len(),
    );
    assert!(
        failures.is_empty(),
        "{} predicate acceptances failed the independent check:\n{}",
        failures.len(),
        failures.join("\n")
    );
    let generated_floor: usize = if deep {
        4_000
    } else {
        FAST_PLAN.widths.len() * FAST_PLAN.max_vars as usize * FIXED_PREDICATES_PER_CELL as usize
    };
    if deep {
        assert!(
            !deadline_hit,
            "the deep predicate sweep ran out of wall clock after {generated} predicates"
        );
    } else {
        let expected_per_width: usize =
            FAST_PLAN.max_vars as usize * FIXED_PREDICATES_PER_CELL as usize;
        for width in FAST_PLAN.widths.iter().copied() {
            assert_eq!(
                exhaustively_checked_by_width
                    .get(&width.bits())
                    .copied()
                    .unwrap_or(0),
                expected_per_width,
                "the fixed predicate matrix did not exhaustively check every case at {width:?}"
            );
            for var_count in 1u32..=FAST_PLAN.max_vars {
                assert_eq!(
                    generated_by_cell
                        .get(&(width.bits(), var_count))
                        .copied()
                        .unwrap_or(0),
                    FIXED_PREDICATES_PER_CELL as usize,
                    "the fixed predicate matrix covered the wrong number of cases at {width:?} with {var_count} variables"
                );
            }
        }
    }
    assert!(
        generated >= generated_floor,
        "the predicate sweep covered only {generated} predicates, floor is {generated_floor}"
    );
    assert!(
        rewritten > 0,
        "the predicate sweep never exercised a rewrite acceptance"
    );
    assert!(
        always_true + always_false > 0,
        "the predicate sweep never exercised a constant verdict"
    );
}

fn narrow_only_constant_predicates() -> Vec<(&'static str, Predicate)> {
    vec![
        (
            "high_half_shifted_out",
            Predicate::eq(Expr::shr(Expr::var(0), Expr::konst(16)), Expr::konst(0)),
        ),
        (
            "mask_vanishes_at_sixteen_bits",
            Predicate::eq(
                Expr::and(Expr::var(0), Expr::konst(0xFFFF_0000)),
                Expr::konst(0),
            ),
        ),
        (
            "scale_vanishes_at_sixteen_bits",
            Predicate::eq(
                Expr::mul(Expr::var(0), Expr::konst(0x1_0000)),
                Expr::konst(0),
            ),
        ),
    ]
}

#[test]
fn a_predicate_constant_only_at_a_narrower_width_is_not_reported_constant() {
    let mut failures: Vec<String> = Vec::new();
    for width in [Width::W32, Width::W64] {
        let environments: Vec<Vec<u64>> = build_battery(width, 1, FAST_PLAN);
        for (name, predicate) in narrow_only_constant_predicates() {
            let witness: Option<&Vec<u64>> = environments
                .iter()
                .find(|environment: &&Vec<u64>| !predicate.evaluate(environment, width));
            let Some(witness): Option<&Vec<u64>> = witness else {
                failures.push(format!(
                    "{name} at {width:?} holds everywhere sampled, so this guard is aimed at the wrong shape"
                ));
                continue;
            };
            let verdict: OpaqueVerdict = classify(&predicate, width);
            if verdict.constant_value().is_some() {
                failures.push(format!(
                    "{name}: classify called `{predicate:?}` {verdict:?} at {width:?}, yet it is false at {witness:?}"
                ));
            }
            if fold_branch(&predicate, width) != BranchFold::Unresolved {
                failures.push(format!(
                    "{name}: fold_branch folded `{predicate:?}` at {width:?} to {:?}, yet it is false at {witness:?}",
                    fold_branch(&predicate, width)
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} predicates were called constant at a width where they are not:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum SolverKind {
    Z3,
    Bitwuzla,
}

#[derive(Debug, Clone)]
struct Solver {
    program: &'static str,
    kind: SolverKind,
    version: String,
}

fn probe_version(program: &str) -> Option<String> {
    let output: std::process::Output = Command::new(program).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    let first: String = text.lines().next().unwrap_or("").trim().to_owned();
    if first.is_empty() {
        Some(program.to_owned())
    } else {
        Some(first)
    }
}

fn detect_solver() -> Option<Solver> {
    const CANDIDATES: [(&str, SolverKind); 2] =
        [("z3", SolverKind::Z3), ("bitwuzla", SolverKind::Bitwuzla)];
    CANDIDATES
        .into_iter()
        .find_map(|(program, kind): (&'static str, SolverKind)| {
            probe_version(program).map(|version: String| Solver {
                program,
                kind,
                version,
            })
        })
}

static QUERY_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn parse_answer(text: &str) -> Answer {
    for line in text.lines() {
        match line.trim() {
            "unsat" => return Answer::Unsat,
            "sat" => return Answer::Sat,
            "unknown" => return Answer::Unknown,
            _ => {}
        }
    }
    panic!("solver produced no sat/unsat/unknown verdict: {text:?}");
}

fn run_solver(solver: &Solver, script: &str) -> Answer {
    let unique: usize = QUERY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_mba_accept_{}_{}", std::process::id(), unique);
    let (scratch, mut file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&purpose, "smt2")
            .expect("write smt2 query to a temp file");
    let path: PathBuf = scratch.path().to_path_buf();
    std::io::Write::write_all(&mut file, script.as_bytes())
        .expect("write smt2 query to a temp file");
    drop(file);
    let mut command: Command = Command::new(solver.program);
    match solver.kind {
        SolverKind::Z3 => {
            command.arg("-smt2").arg(&path);
        }
        SolverKind::Bitwuzla => {
            command.arg(&path);
        }
    }
    let output: std::process::Output = command.output().expect("invoke the external solver");
    parse_answer(&String::from_utf8_lossy(&output.stdout))
}

fn fixed_wide_acceptances() -> Vec<(Expr, Expr, Width)> {
    let mut accepted: Vec<(Expr, Expr, Width)> = Vec::new();
    for width in [Width::W32, Width::W64] {
        let x: Expr = Expr::var(0);
        let y: Expr = Expr::var(1);
        let cases: Vec<Expr> = vec![
            Expr::add(
                Expr::xor(x.clone(), y.clone()),
                Expr::mul(Expr::konst(2), Expr::and(x.clone(), y.clone())),
            ),
            Expr::sub(
                Expr::mul(x.clone(), Expr::add(y.clone(), Expr::konst(1))),
                Expr::mul(x.clone(), y.clone()),
            ),
            Expr::sub(x.clone(), Expr::and(x.clone(), y.clone())),
        ];
        for original in cases {
            let result: Simplification = simplify(&original, width);
            assert!(
                result.changed(),
                "the fixed wide solver case `{original}` did not simplify at {width:?}"
            );
            assert!(
                result.verification.is_proven(),
                "the fixed wide solver case `{original}` at {width:?} has no proof"
            );
            assert_eq!(
                verification_width(result.verification),
                Some(width),
                "the fixed wide solver case `{original}` was accepted at the wrong width"
            );
            assert!(
                result.simplified_nodes < result.original_nodes,
                "the fixed wide solver case `{original}` did not shrink"
            );
            accepted.push((original, result.simplified, width));
        }
    }
    assert_eq!(
        accepted.len(),
        6,
        "the fixed wide solver corpus changed size unexpectedly"
    );
    accepted
}

#[test]
fn wide_acceptances_are_confirmed_by_an_external_bitvector_solver() {
    let detected: Option<Solver> = detect_solver();
    enforce_solver_requirement(detected.as_ref(), solver_is_required());
    let sample: Vec<(Expr, Expr, Width)> = fixed_wide_acceptances();
    let Some(solver): Option<Solver> = detected else {
        eprintln!(
            "NOT CHECKED: neither z3 nor bitwuzla is executable on PATH, so the fixed corpus of {} wide acceptances at 32 and 64 bits has no external solver confirmation. Set DISROBE_REQUIRE_SOLVER=1 to make this fatal.",
            sample.len()
        );
        return;
    };
    eprintln!(
        "external confirmation: grading {} wide acceptances against {} ({})",
        sample.len(),
        solver.program,
        solver.version
    );
    let mut confirmed: usize = 0;
    for (original, simplified, width) in &sample {
        let script: String = equivalence_query(original, simplified, *width);
        assert_eq!(
            run_solver(&solver, &script),
            Answer::Unsat,
            "the external solver did not prove the accepted rewrite at {width:?}: `{original}` -> `{simplified}`\n{script}"
        );
        confirmed += 1;
    }
    assert_eq!(
        confirmed,
        sample.len(),
        "the external solver must prove every fixed wide acceptance"
    );

    let clean: Expr = Expr::add(Expr::var(0), Expr::var(1));
    let wrong: Expr = Expr::sub(Expr::var(0), Expr::var(1));
    assert_eq!(
        run_solver(&solver, &equivalence_query(&clean, &wrong, Width::W64)),
        Answer::Sat,
        "the solver leg must refute a non-equivalent rewrite, otherwise this grading is vacuous"
    );
}
