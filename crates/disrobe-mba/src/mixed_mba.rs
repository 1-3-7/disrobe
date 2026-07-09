#![doc = "General mixed mixed-boolean-arithmetic simplification via GAMBA-style AST recursion."]
#![doc = ""]
#![doc = "A mixed MBA expression nests bitwise operators inside arithmetic operators inside"]
#![doc = "bitwise operators, for example `(x + y) ^ (x - y)`, or an obfuscated encoding of"]
#![doc = "`x + y` XOR-ed against a second, differently obfuscated encoding of the same sum."]
#![doc = "Neither the linear solver nor the polynomial reducer can cross a bitwise boundary:"]
#![doc = "both treat any `And`/`Or`/`Xor`/`Not` node as an opaque atom the instant they reach"]
#![doc = "it, by design, because crossing that boundary is not a ring homomorphism. This module"]
#![doc = "instead recurses the expression tree bottom-up, reducing each nonlinear subterm to its"]
#![doc = "own minimal form (by driving the existing canonicalizer, linear solver, and polynomial"]
#![doc = "reducer over that subterm alone, remapped to dense variable indices) and substituting"]
#![doc = "the result back into the parent before the parent itself is considered. That is what"]
#![doc = "lets an obfuscated encoding of `x + y` collapse to its minimal form before an outer XOR"]
#![doc = "against a second, differently obfuscated encoding of the same value can recognize the"]
#![doc = "two sides are now syntactically identical and fold away. A subterm is only ever"]
#![doc = "replaced by a strictly smaller reduction; a same-size restructuring (for example a"]
#![doc = "purely commutative reordering) is discarded so an irreducible construct is always"]
#![doc = "returned byte-identical to its input rather than merely reshuffled."]
#![doc = ""]
#![doc = "Composition of already-proven-sound component rewrites is not treated as sufficient on"]
#![doc = "its own: the final reassembled expression is always re-checked against the original at"]
#![doc = "the exact operand width, by exhaustive enumeration when the width and variable count"]
#![doc = "allow it, or otherwise by the crate's sound bit-blasting verifier, before ever being"]
#![doc = "returned. On any verification failure the original is returned unchanged."]
#![doc = ""]
#![doc = "Right shift, unsigned division, `Ite`, `Slice`, `Compose`, and `Mem` are not ring"]
#![doc = "operations. `Ite`/`Slice`/`Compose`/`Mem` subtrees are treated as opaque leaves, never"]
#![doc = "recursed into or rewritten, exactly like a bare variable. A right shift is recursed"]
#![doc = "into (its operands may still simplify) but the shift itself is never a rewrite target,"]
#![doc = "since none of the reused solvers accept it."]

use crate::expr::{Expr, Width, equivalent_exhaustive, equivalent_exhaustive_runnable};
use crate::linear_solver::solve_linear_mba;
use crate::poly_mba::solve_polynomial_mba;
use crate::rewrite::canonicalize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_MIXED_MBA_VARS: u32 = 6;

#[must_use]
pub fn simplify_mixed(expr: &Expr, width: Width) -> Option<Expr> {
    if expr.depth() > crate::expr::MAX_MBA_DEPTH {
        return None;
    }
    let candidate: Expr = rewrite(expr, width);
    if candidate == *expr {
        return None;
    }
    if verify_whole(expr, &candidate, width) {
        Some(candidate)
    } else {
        None
    }
}

fn rewrite(expr: &Expr, width: Width) -> Expr {
    match expr {
        Expr::Const(_) | Expr::Var(_) => expr.clone(),
        Expr::Unary(op, inner) => {
            let inner: Expr = rewrite(inner, width);
            let node: Expr = Expr::Unary(*op, Box::new(inner));
            best_local(&node, width)
        }
        Expr::Binary(op, left, right) => {
            let left: Expr = rewrite(left, width);
            let right: Expr = rewrite(right, width);
            let node: Expr = Expr::Binary(*op, Box::new(left), Box::new(right));
            best_local(&node, width)
        }
        Expr::Ite(_, _, _) | Expr::Slice(_, _, _) | Expr::Compose(_, _, _) | Expr::Mem(_, _) => {
            expr.clone()
        }
    }
}

fn best_local(node: &Expr, width: Width) -> Expr {
    let mut best: Expr = node.clone();

    let canonicalized: Expr = canonicalize(node, width);
    if canonicalized.node_count() < best.node_count() {
        best = canonicalized;
    }

    let vars: BTreeSet<u32> = node.vars();
    let Ok(var_count): Result<u32, _> = u32::try_from(vars.len()) else {
        return best;
    };
    if var_count == 0 || var_count > MAX_MIXED_MBA_VARS {
        return best;
    }

    let (dense, inverse): (BTreeMap<u32, u32>, BTreeMap<u32, u32>) = build_remap(&vars);
    let dense_node: Expr = best.remap_vars(&dense);

    if let Some(solved) = solve_linear_mba(&dense_node, width, var_count) {
        let restored: Expr = solved.remap_vars(&inverse);
        if restored.node_count() < best.node_count() {
            best = restored;
        }
    }
    if let Some(solved) = solve_polynomial_mba(&dense_node, width, var_count) {
        let restored: Expr = solved.remap_vars(&inverse);
        if restored.node_count() < best.node_count() {
            best = restored;
        }
    }

    best
}

fn build_remap(vars: &BTreeSet<u32>) -> (BTreeMap<u32, u32>, BTreeMap<u32, u32>) {
    let mut dense: BTreeMap<u32, u32> = BTreeMap::new();
    let mut inverse: BTreeMap<u32, u32> = BTreeMap::new();
    for (index, &original) in vars.iter().enumerate() {
        let dense_index: u32 = index.try_into().unwrap_or(u32::MAX);
        dense.insert(original, dense_index);
        inverse.insert(dense_index, original);
    }
    (dense, inverse)
}

fn verify_whole(original: &Expr, candidate: &Expr, width: Width) -> bool {
    let var_count: u32 = original
        .max_var()
        .map_or(0, |index: u32| index + 1)
        .max(candidate.max_var().map_or(0, |index: u32| index + 1));
    if width.is_exhaustible() && equivalent_exhaustive_runnable(width, var_count) {
        return equivalent_exhaustive(original, candidate, width, var_count);
    }
    #[cfg(feature = "smt-verify")]
    {
        if crate::verify::verify_equivalent(original, candidate, width).is_proven() {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::simplify::{Simplification, simplify};

    fn var(index: u32) -> Expr {
        Expr::var(index)
    }

    fn hidden_sum(a: u32, b: u32) -> Expr {
        Expr::add(
            Expr::xor(var(a), var(b)),
            Expr::mul(Expr::konst(2), Expr::and(var(a), var(b))),
        )
    }

    #[test]
    fn xor_of_obfuscated_and_clean_sum_cancels_to_zero() {
        let obfuscated: Expr = Expr::xor(hidden_sum(0, 1), Expr::add(var(0), var(1)));
        let result: Expr = simplify_mixed(&obfuscated, Width::W8).expect("must simplify");
        assert_eq!(result, Expr::konst(0));
        assert!(equivalent_exhaustive(&obfuscated, &result, Width::W8, 2));
    }

    #[test]
    fn xor_of_obfuscated_and_clean_sum_cancels_to_zero_at_wide_width() {
        let obfuscated: Expr = Expr::xor(hidden_sum(0, 1), Expr::add(var(0), var(1)));
        let result: Expr = simplify_mixed(&obfuscated, Width::W64).expect("must simplify");
        assert_eq!(result, Expr::konst(0));
    }

    #[test]
    fn bitwise_sum_nested_inside_outer_xor_reduces_before_recombining() {
        let inner: Expr = Expr::add(Expr::and(var(0), var(1)), Expr::xor(var(0), var(1)));
        let obfuscated: Expr = Expr::xor(inner, var(2));
        let result: Expr = simplify_mixed(&obfuscated, Width::W8).expect("must simplify");
        let expected: Expr = Expr::xor(Expr::or(var(0), var(1)), var(2));
        assert!(
            equivalent_exhaustive(&result, &expected, Width::W8, 3),
            "expected (x|y)^z, got `{result}`"
        );
        assert!(result.node_count() < obfuscated.node_count());
    }

    #[test]
    fn product_cancellation_nested_inside_xor_collapses() {
        let product: Expr = Expr::mul(var(0), var(1));
        let obfuscated: Expr = Expr::xor(Expr::sub(product.clone(), product), var(2));
        let result: Expr = simplify_mixed(&obfuscated, Width::W8).expect("must simplify");
        assert_eq!(result, var(2));
    }

    #[test]
    fn right_shift_nested_inside_xor_is_left_untouched() {
        let obfuscated: Expr = Expr::xor(Expr::shr(var(0), Expr::konst(1)), var(1));
        assert!(simplify_mixed(&obfuscated, Width::W8).is_none());
    }

    #[test]
    fn unsigned_division_shaped_shift_chain_is_left_untouched() {
        let shifted_product: Expr = Expr::mul(Expr::shr(var(0), Expr::konst(2)), var(1));
        let obfuscated: Expr = Expr::and(shifted_product, var(2));
        assert!(simplify_mixed(&obfuscated, Width::W8).is_none());
    }

    #[test]
    fn genuine_irreducible_mixed_expression_is_left_untouched() {
        let irreducible: Expr = Expr::xor(Expr::add(var(0), var(1)), Expr::sub(var(0), var(1)));
        assert!(
            simplify_mixed(&irreducible, Width::W8).is_none(),
            "an XOR of two unrelated arithmetic sides has no smaller sound form and must stay untouched"
        );
    }

    #[test]
    fn never_returns_a_structurally_identical_candidate() {
        let plain: Expr = Expr::add(var(0), var(1));
        assert!(simplify_mixed(&plain, Width::W8).is_none());
    }

    #[test]
    fn sparse_variable_indices_inside_a_subterm_remap_correctly() {
        let obfuscated: Expr = Expr::xor(hidden_sum(3, 7), Expr::add(var(3), var(7)));
        let result: Expr = simplify_mixed(&obfuscated, Width::W8).expect("must simplify");
        assert_eq!(result, Expr::konst(0));
    }

    #[test]
    fn deeply_nested_expression_within_depth_budget_does_not_panic() {
        let mut expr: Expr = var(0);
        for _ in 0..64 {
            expr = Expr::xor(expr, Expr::konst(0));
        }
        let _: Option<Expr> = simplify_mixed(&expr, Width::W8);
    }

    #[test]
    fn beyond_depth_budget_is_rejected_without_recursing() {
        let mut expr: Expr = var(0);
        for _ in 0..=crate::expr::MAX_MBA_DEPTH {
            expr = Expr::not(expr);
        }
        assert!(simplify_mixed(&expr, Width::W8).is_none());
    }

    #[test]
    fn wiring_into_top_level_simplify_collapses_the_same_construct() {
        let obfuscated: Expr = Expr::xor(hidden_sum(0, 1), Expr::add(var(0), var(1)));
        let result: Simplification = simplify(&obfuscated, Width::W16);
        assert!(result.changed());
        assert!(result.verification.is_proven());
        assert_eq!(result.simplified, Expr::konst(0));
    }
}
