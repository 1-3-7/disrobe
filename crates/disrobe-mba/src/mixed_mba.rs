use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::linear_solver::solve_linear_mba;
use crate::poly_mba::solve_polynomial_mba;
use crate::rewrite::canonicalize;
use crate::simplify::Verification;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_MIXED_MBA_VARS: u32 = 6;
pub const MAX_MIXED_MBA_NODES: usize = 16_384;
pub const MAX_MIXED_MBA_WORK: usize = 1_024;

const MAX_MIXED_RECURSION_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MixedRefusal {
    DepthLimit { depth: usize, limit: usize },
    NodeLimit { nodes: usize, limit: usize },
    WorkLimit { required: usize, limit: usize },
    VariableLimit { required: u32, limit: u32 },
    InvalidSlice { lo: u32, hi: u32 },
    Memory,
    BackSubstitution,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MixedSimplification {
    Simplified {
        expression: Expr,
        verification: Verification,
    },
    Unchanged,
    Refused(MixedRefusal),
}

#[must_use]
pub fn simplify_mixed(expr: &Expr, width: Width) -> Option<Expr> {
    match simplify_mixed_detailed(expr, width) {
        MixedSimplification::Simplified { expression, .. } => Some(expression),
        MixedSimplification::Unchanged | MixedSimplification::Refused(_) => None,
    }
}

#[must_use]
pub fn simplify_mixed_detailed(expr: &Expr, width: Width) -> MixedSimplification {
    let depth: usize = expr.depth();
    let depth_limit: usize = MAX_MIXED_RECURSION_DEPTH.min(crate::expr::MAX_MBA_DEPTH);
    if depth >= depth_limit {
        return MixedSimplification::Refused(MixedRefusal::DepthLimit {
            depth,
            limit: depth_limit,
        });
    }
    let nodes: usize = expr.node_count();
    if nodes > MAX_MIXED_MBA_NODES {
        return MixedSimplification::Refused(MixedRefusal::NodeLimit {
            nodes,
            limit: MAX_MIXED_MBA_NODES,
        });
    }
    if contains_memory(expr) {
        return MixedSimplification::Refused(MixedRefusal::Memory);
    }
    let variables: BTreeSet<u32> = expr.vars();
    let Ok(variable_count): Result<u32, _> = u32::try_from(variables.len()) else {
        return MixedSimplification::Refused(MixedRefusal::VariableLimit {
            required: u32::MAX,
            limit: MAX_MIXED_MBA_VARS,
        });
    };
    if variable_count > MAX_MIXED_MBA_VARS {
        return MixedSimplification::Refused(MixedRefusal::VariableLimit {
            required: variable_count,
            limit: MAX_MIXED_MBA_VARS,
        });
    }
    let mut work: WorkBudget = WorkBudget {
        consumed: 0,
        limit: MAX_MIXED_MBA_WORK,
    };
    let candidate: Expr = match rewrite(expr, width, 1, &mut work) {
        Ok(candidate) => candidate,
        Err(refusal) => return MixedSimplification::Refused(refusal),
    };
    if candidate == *expr {
        return MixedSimplification::Unchanged;
    }
    let proof_var_count: u32 = expr
        .max_var()
        .map_or(0, |index: u32| index.saturating_add(1))
        .max(
            candidate
                .max_var()
                .map_or(0, |index: u32| index.saturating_add(1)),
        );
    let verification: Verification =
        crate::simplify::prove_mixed_equivalent(expr, &candidate, width, proof_var_count);
    if !verification.is_proven() {
        return MixedSimplification::Refused(MixedRefusal::Unproven);
    }
    MixedSimplification::Simplified {
        expression: candidate,
        verification,
    }
}

#[derive(Debug)]
struct WorkBudget {
    consumed: usize,
    limit: usize,
}

impl WorkBudget {
    const fn consume(&mut self) -> Result<(), MixedRefusal> {
        let Some(required): Option<usize> = self.consumed.checked_add(1) else {
            return Err(MixedRefusal::WorkLimit {
                required: usize::MAX,
                limit: self.limit,
            });
        };
        if required > self.limit {
            return Err(MixedRefusal::WorkLimit {
                required,
                limit: self.limit,
            });
        }
        self.consumed = required;
        Ok(())
    }
}

fn rewrite(
    expr: &Expr,
    width: Width,
    depth: usize,
    work: &mut WorkBudget,
) -> Result<Expr, MixedRefusal> {
    if depth >= MAX_MIXED_RECURSION_DEPTH {
        return Err(MixedRefusal::DepthLimit {
            depth,
            limit: MAX_MIXED_RECURSION_DEPTH,
        });
    }
    work.consume()?;
    match expr {
        Expr::Const(_) | Expr::Var(_) => Ok(expr.clone()),
        Expr::Unary(op, inner) => {
            let inner: Expr = rewrite(inner, width, depth.saturating_add(1), work)?;
            let node: Expr = Expr::Unary(*op, Box::new(inner));
            best_local(&node, width)
        }
        Expr::Binary(op, left, right) => {
            let left: Expr = rewrite(left, width, depth.saturating_add(1), work)?;
            let right: Expr = rewrite(right, width, depth.saturating_add(1), work)?;
            let node: Expr = Expr::Binary(*op, Box::new(left), Box::new(right));
            best_local(&node, width)
        }
        Expr::Ite(cond, then_branch, else_branch) => {
            let cond: Expr = rewrite(cond, width, depth.saturating_add(1), work)?;
            let then_branch: Expr = rewrite(then_branch, width, depth.saturating_add(1), work)?;
            let else_branch: Expr = rewrite(else_branch, width, depth.saturating_add(1), work)?;
            let node: Expr = Expr::ite(cond, then_branch, else_branch);
            best_local(&node, width)
        }
        Expr::Slice(inner, lo, hi) => {
            if hi <= lo {
                return Err(MixedRefusal::InvalidSlice { lo: *lo, hi: *hi });
            }
            let inner: Expr = rewrite(inner, width, depth.saturating_add(1), work)?;
            let node: Expr = Expr::slice(inner, *lo, *hi);
            best_local(&node, width)
        }
        Expr::Compose(low, high, low_bits) => {
            let low: Expr = rewrite(low, width, depth.saturating_add(1), work)?;
            let high: Expr = rewrite(high, width, depth.saturating_add(1), work)?;
            let node: Expr = Expr::compose(low, high, *low_bits);
            best_local(&node, width)
        }
        Expr::Mem(_, _) => Err(MixedRefusal::Memory),
    }
}

fn best_local(node: &Expr, width: Width) -> Result<Expr, MixedRefusal> {
    let mut best: Expr = node.clone();

    let canonicalized: Expr = canonicalize(node, width);
    if canonicalized.node_count() < best.node_count() {
        best = canonicalized;
    }

    #[cfg(feature = "smt-verify")]
    {
        let minimized: Option<Expr> = crate::simplify::minimize_boolean_verified(&best, width);
        if let Some(minimized) = minimized
            && minimized.node_count() < best.node_count()
        {
            best = minimized;
        }
    }

    let vars: BTreeSet<u32> = node.vars();
    let Ok(var_count): Result<u32, _> = u32::try_from(vars.len()) else {
        return Err(MixedRefusal::VariableLimit {
            required: u32::MAX,
            limit: MAX_MIXED_MBA_VARS,
        });
    };
    if var_count == 0 || var_count > MAX_MIXED_MBA_VARS {
        return Ok(best);
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

    if let Some(solved) = solve_substituted(&dense_node, width, var_count)? {
        let restored: Expr = solved.remap_vars(&inverse);
        if restored.node_count() < best.node_count() {
            best = restored;
        }
    }

    Ok(best)
}

#[derive(Debug)]
struct Substitutions {
    atoms: Vec<Expr>,
    first_fresh: u32,
}

impl Substitutions {
    fn intern(&mut self, atom: &Expr) -> Result<Expr, MixedRefusal> {
        if let Some(position) = self
            .atoms
            .iter()
            .position(|existing: &Expr| existing == atom)
        {
            let Ok(offset): Result<u32, _> = u32::try_from(position) else {
                return Err(MixedRefusal::VariableLimit {
                    required: u32::MAX,
                    limit: MAX_MIXED_MBA_VARS,
                });
            };
            let Some(index): Option<u32> = self.first_fresh.checked_add(offset) else {
                return Err(MixedRefusal::VariableLimit {
                    required: u32::MAX,
                    limit: MAX_MIXED_MBA_VARS,
                });
            };
            return Ok(Expr::var(index));
        }
        let Ok(offset): Result<u32, _> = u32::try_from(self.atoms.len()) else {
            return Err(MixedRefusal::VariableLimit {
                required: u32::MAX,
                limit: MAX_MIXED_MBA_VARS,
            });
        };
        let Some(index): Option<u32> = self.first_fresh.checked_add(offset) else {
            return Err(MixedRefusal::VariableLimit {
                required: u32::MAX,
                limit: MAX_MIXED_MBA_VARS,
            });
        };
        let Some(required): Option<u32> = index.checked_add(1) else {
            return Err(MixedRefusal::VariableLimit {
                required: u32::MAX,
                limit: MAX_MIXED_MBA_VARS,
            });
        };
        if required > MAX_MIXED_MBA_VARS {
            return Err(MixedRefusal::VariableLimit {
                required,
                limit: MAX_MIXED_MBA_VARS,
            });
        }
        self.atoms.push(atom.clone());
        Ok(Expr::var(index))
    }
}

fn solve_substituted(
    expr: &Expr,
    width: Width,
    var_count: u32,
) -> Result<Option<Expr>, MixedRefusal> {
    let mut substitutions: Substitutions = Substitutions {
        atoms: Vec::new(),
        first_fresh: var_count,
    };
    let purified: Expr = purify_value(expr, width, &mut substitutions)?;
    if substitutions.atoms.is_empty() {
        return Ok(None);
    }
    let Ok(atom_count): Result<u32, _> = u32::try_from(substitutions.atoms.len()) else {
        return Err(MixedRefusal::VariableLimit {
            required: u32::MAX,
            limit: MAX_MIXED_MBA_VARS,
        });
    };
    let Some(effective_count): Option<u32> = var_count.checked_add(atom_count) else {
        return Err(MixedRefusal::VariableLimit {
            required: u32::MAX,
            limit: MAX_MIXED_MBA_VARS,
        });
    };
    if effective_count > MAX_MIXED_MBA_VARS {
        return Err(MixedRefusal::VariableLimit {
            required: effective_count,
            limit: MAX_MIXED_MBA_VARS,
        });
    }
    let mut best: Option<Expr> = None;
    for solved in [
        solve_linear_mba(&purified, width, effective_count),
        solve_polynomial_mba(&purified, width, effective_count),
    ]
    .into_iter()
    .flatten()
    {
        let Some(restored): Option<Expr> = restore_substitutions(&solved, &substitutions) else {
            return Err(MixedRefusal::BackSubstitution);
        };
        let reabstracted: Expr = abstract_known_atoms(&restored, &substitutions);
        if reabstracted != solved {
            return Err(MixedRefusal::BackSubstitution);
        }
        if restored.node_count() >= expr.node_count() || restored.node_count() > MAX_MIXED_MBA_NODES
        {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current: &Expr| restored.node_count() < current.node_count())
        {
            best = Some(restored);
        }
    }
    Ok(best)
}

fn purify_value(
    expr: &Expr,
    width: Width,
    substitutions: &mut Substitutions,
) -> Result<Expr, MixedRefusal> {
    match expr {
        Expr::Const(_) | Expr::Var(_) => Ok(expr.clone()),
        Expr::Unary(UnOp::Neg, inner) => Ok(Expr::neg(purify_value(inner, width, substitutions)?)),
        Expr::Unary(UnOp::Not, _) | Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, _, _) => {
            purify_bitwise(expr, width, substitutions)
        }
        Expr::Binary(BinOp::Add, left, right) => Ok(Expr::add(
            purify_value(left, width, substitutions)?,
            purify_value(right, width, substitutions)?,
        )),
        Expr::Binary(BinOp::Sub, left, right) => Ok(Expr::sub(
            purify_value(left, width, substitutions)?,
            purify_value(right, width, substitutions)?,
        )),
        Expr::Binary(BinOp::Mul, left, right) => Ok(Expr::mul(
            purify_value(left, width, substitutions)?,
            purify_value(right, width, substitutions)?,
        )),
        Expr::Binary(BinOp::Shl, left, right) if matches!(right.as_ref(), Expr::Const(_)) => Ok(
            Expr::shl(purify_value(left, width, substitutions)?, (**right).clone()),
        ),
        Expr::Binary(BinOp::Shl | BinOp::Shr, _, _)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _) => substitutions.intern(expr),
        Expr::Mem(_, _) => Err(MixedRefusal::Memory),
    }
}

fn purify_bitwise(
    expr: &Expr,
    width: Width,
    substitutions: &mut Substitutions,
) -> Result<Expr, MixedRefusal> {
    match expr {
        Expr::Const(value) if value & width.mask() == 0 || value & width.mask() == width.mask() => {
            Ok(expr.clone())
        }
        Expr::Var(_) => Ok(expr.clone()),
        Expr::Unary(UnOp::Not, inner) => {
            Ok(Expr::not(purify_bitwise(inner, width, substitutions)?))
        }
        Expr::Binary(BinOp::And, left, right) => Ok(Expr::and(
            purify_bitwise(left, width, substitutions)?,
            purify_bitwise(right, width, substitutions)?,
        )),
        Expr::Binary(BinOp::Or, left, right) => Ok(Expr::or(
            purify_bitwise(left, width, substitutions)?,
            purify_bitwise(right, width, substitutions)?,
        )),
        Expr::Binary(BinOp::Xor, left, right) => Ok(Expr::xor(
            purify_bitwise(left, width, substitutions)?,
            purify_bitwise(right, width, substitutions)?,
        )),
        Expr::Mem(_, _) => Err(MixedRefusal::Memory),
        _ => substitutions.intern(expr),
    }
}

fn restore_substitutions(expr: &Expr, substitutions: &Substitutions) -> Option<Expr> {
    match expr {
        Expr::Const(_) => Some(expr.clone()),
        Expr::Var(index) if *index < substitutions.first_fresh => Some(expr.clone()),
        Expr::Var(index) => {
            let offset: u32 = index.checked_sub(substitutions.first_fresh)?;
            let offset: usize = usize::try_from(offset).ok()?;
            substitutions.atoms.get(offset).cloned()
        }
        Expr::Unary(op, inner) => Some(Expr::Unary(
            *op,
            Box::new(restore_substitutions(inner, substitutions)?),
        )),
        Expr::Binary(op, left, right) => Some(Expr::Binary(
            *op,
            Box::new(restore_substitutions(left, substitutions)?),
            Box::new(restore_substitutions(right, substitutions)?),
        )),
        Expr::Ite(cond, then_branch, else_branch) => Some(Expr::ite(
            restore_substitutions(cond, substitutions)?,
            restore_substitutions(then_branch, substitutions)?,
            restore_substitutions(else_branch, substitutions)?,
        )),
        Expr::Slice(inner, lo, hi) => Some(Expr::slice(
            restore_substitutions(inner, substitutions)?,
            *lo,
            *hi,
        )),
        Expr::Compose(low, high, low_bits) => Some(Expr::compose(
            restore_substitutions(low, substitutions)?,
            restore_substitutions(high, substitutions)?,
            *low_bits,
        )),
        Expr::Mem(_, _) => None,
    }
}

fn abstract_known_atoms(expr: &Expr, substitutions: &Substitutions) -> Expr {
    let position: Option<usize> = substitutions
        .atoms
        .iter()
        .position(|atom: &Expr| atom == expr);
    if let Some(position) = position {
        let offset: Result<u32, _> = u32::try_from(position);
        if let Ok(offset) = offset {
            let index: Option<u32> = substitutions.first_fresh.checked_add(offset);
            if let Some(index) = index {
                return Expr::var(index);
            }
        }
    }
    match expr {
        Expr::Const(_) | Expr::Var(_) | Expr::Mem(_, _) => expr.clone(),
        Expr::Unary(op, inner) => {
            Expr::Unary(*op, Box::new(abstract_known_atoms(inner, substitutions)))
        }
        Expr::Binary(op, left, right) => Expr::Binary(
            *op,
            Box::new(abstract_known_atoms(left, substitutions)),
            Box::new(abstract_known_atoms(right, substitutions)),
        ),
        Expr::Ite(cond, then_branch, else_branch) => Expr::ite(
            abstract_known_atoms(cond, substitutions),
            abstract_known_atoms(then_branch, substitutions),
            abstract_known_atoms(else_branch, substitutions),
        ),
        Expr::Slice(inner, lo, hi) => {
            Expr::slice(abstract_known_atoms(inner, substitutions), *lo, *hi)
        }
        Expr::Compose(low, high, low_bits) => Expr::compose(
            abstract_known_atoms(low, substitutions),
            abstract_known_atoms(high, substitutions),
            *low_bits,
        ),
    }
}

fn contains_memory(expr: &Expr) -> bool {
    match expr {
        Expr::Mem(_, _) => true,
        Expr::Const(_) | Expr::Var(_) => false,
        Expr::Unary(_, inner) | Expr::Slice(inner, _, _) => contains_memory(inner),
        Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => {
            contains_memory(left) || contains_memory(right)
        }
        Expr::Ite(cond, then_branch, else_branch) => {
            contains_memory(cond) || contains_memory(then_branch) || contains_memory(else_branch)
        }
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;
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
    fn equal_subterms_share_exactly_one_fresh_atom() {
        let atom: Expr = Expr::mul(var(0), var(1));
        let mut substitutions: Substitutions = Substitutions {
            atoms: Vec::new(),
            first_fresh: 2,
        };
        let first: Expr = substitutions.intern(&atom).expect("within atom cap");
        let second: Expr = substitutions.intern(&atom).expect("within atom cap");
        assert_eq!(first, second);
        assert_eq!(substitutions.atoms, vec![atom]);
    }

    #[test]
    fn distinct_subterms_receive_distinct_fresh_atoms() {
        let left: Expr = Expr::mul(var(0), var(1));
        let right: Expr = Expr::mul(var(1), var(0));
        let mut substitutions: Substitutions = Substitutions {
            atoms: Vec::new(),
            first_fresh: 2,
        };
        let left_var: Expr = substitutions.intern(&left).expect("within atom cap");
        let right_var: Expr = substitutions.intern(&right).expect("within atom cap");
        assert_ne!(left_var, right_var);
        assert_eq!(substitutions.atoms, vec![left, right]);
    }

    #[test]
    fn substitution_model_never_proves_a_wrong_back_substitution() {
        let original: Expr = Expr::add(Expr::mul(var(0), var(1)), var(2));
        let wrong: Expr = Expr::add(Expr::mul(var(0), var(0)), var(2));
        for width in [
            Width::W1,
            Width::W2,
            Width::W4,
            Width::W8,
            Width::W16,
            Width::W32,
            Width::W64,
        ] {
            let proof: Verification =
                crate::simplify::prove_mixed_equivalent(&original, &wrong, width, 3);
            assert!(!proof.is_proven(), "{width:?}: {proof:?}");
        }
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
        let result: Option<Expr> = simplify_mixed(&obfuscated, Width::W64);
        if cfg!(feature = "smt-verify") {
            assert_eq!(result, Some(Expr::konst(0)));
        } else {
            assert_eq!(
                result, None,
                "W64 is beyond the enumerable core, so without the bit-blasting leg the mixed path must abstain"
            );
        }
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
        let result: Option<Expr> = simplify_mixed(&obfuscated, Width::W8);
        if cfg!(feature = "smt-verify") {
            assert_eq!(result, Some(Expr::konst(0)));
        } else {
            assert_eq!(
                result, None,
                "eight sparse indices put W8 beyond the enumerable core, so without the bit-blasting leg the mixed path must abstain"
            );
        }
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
        if cfg!(feature = "smt-verify") {
            assert!(result.changed());
            assert!(result.verification.is_proven());
            assert_eq!(result.simplified, Expr::konst(0));
        } else {
            assert!(
                !result.changed(),
                "two W16 variables are beyond the enumerable core, so without the bit-blasting leg this construct must be left alone, got `{}`",
                result.simplified
            );
        }
    }
}
