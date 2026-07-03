use crate::bitwise_synth::{MAX_BITWISE_SYNTH_VARS, synthesize_bitwise_masked};
use crate::expr::{BinOp, Expr, UnOp, Width, equivalent_exhaustive};
use crate::linear_mba::synthesize_linear_basis;
use crate::linear_solver::{
    MAX_SOLVER_VARS, columns_equal_mod_width, is_column_faithful, solve_linear_mba, truth_column,
};
use crate::rewrite::canonicalize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Unverified,
    ExhaustiveAtWidth(Width),
    LinearLiftedFrom(Width),
    LinearColumnIdentity(Width),
    AlgebraicIdentity,
    #[cfg(feature = "smt-verify")]
    SmtProvenAtWidth(Width),
}

impl Verification {
    #[must_use]
    pub const fn is_proven(self) -> bool {
        !matches!(self, Self::Unverified)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simplification {
    pub original: Expr,
    pub simplified: Expr,
    pub width: Width,
    pub verification: Verification,
    pub original_nodes: usize,
    pub simplified_nodes: usize,
}

impl Simplification {
    #[must_use]
    pub fn changed(&self) -> bool {
        self.simplified != self.original
    }
}

const MAX_LINEAR_VARS: u32 = 4;
const MAX_BASIS_VARS: u32 = 3;
const MAX_TEMPLATE_VARS: u32 = 2;
const VERIFY_BUDGET_LOG2: u32 = 22;

#[must_use]
pub fn simplify(expr: &Expr, width: Width) -> Simplification {
    if expr.depth() > crate::expr::MAX_MBA_DEPTH {
        let nodes: usize = expr.node_count();
        return Simplification {
            original: expr.clone(),
            simplified: expr.clone(),
            width,
            verification: Verification::Unverified,
            original_nodes: nodes,
            simplified_nodes: nodes,
        };
    }
    let original_nodes: usize = expr.node_count();
    let var_count: u32 = expr.max_var().map_or(0, |index: u32| index + 1);
    let original_is_mba: bool = expr.is_linear_mba();

    let mut best: (Expr, Verification) = (expr.clone(), Verification::Unverified);
    let mut consider = |candidate: Expr, fallback: Verification| {
        if candidate.node_count() >= original_nodes {
            return;
        }
        if candidate.node_count() >= best.0.node_count() {
            return;
        }
        let verified: Verification =
            verify_equivalent(expr, &candidate, width, var_count, original_is_mba);
        let proof: Verification = prefer_proof(verified, fallback);
        if proof.is_proven() {
            best = (candidate, proof);
        }
    };

    let folded: Expr = canonicalize(expr, width);
    if folded != *expr {
        consider(folded, Verification::AlgebraicIdentity);
    }

    if var_count <= MAX_TEMPLATE_VARS {
        for candidate in template_candidates(var_count) {
            consider(candidate, Verification::Unverified);
        }
    }
    if var_count <= MAX_LINEAR_VARS
        && original_is_mba
        && let Some(synth) = synthesize_linear(expr, width, var_count)
    {
        consider(synth, Verification::Unverified);
    }
    if (2..=MAX_BASIS_VARS).contains(&var_count)
        && original_is_mba
        && let Some(synth) = synthesize_linear_basis(expr, width, var_count)
    {
        consider(synth, Verification::Unverified);
    }
    if (1..=MAX_SOLVER_VARS).contains(&var_count)
        && original_is_mba
        && let Some(solved) = solve_linear_mba(expr, width, var_count)
    {
        consider(solved, Verification::Unverified);
    }
    if var_count == 1 && is_bitwise(expr) {
        consider(
            synthesize_bitwise_unary(expr, width),
            Verification::Unverified,
        );
    }
    if (2..=MAX_BITWISE_SYNTH_VARS).contains(&var_count)
        && let Some(synth) = synthesize_bitwise_masked(expr, width, var_count)
    {
        consider(synth, Verification::Unverified);
    }

    let (simplified, verification): (Expr, Verification) = best;

    let simplified_nodes: usize = simplified.node_count();
    Simplification {
        original: expr.clone(),
        simplified,
        width,
        verification,
        original_nodes,
        simplified_nodes,
    }
}

const fn prefer_proof(verified: Verification, fallback: Verification) -> Verification {
    match verified {
        Verification::ExhaustiveAtWidth(_)
        | Verification::LinearColumnIdentity(_)
        | Verification::LinearLiftedFrom(_) => verified,
        #[cfg(feature = "smt-verify")]
        Verification::SmtProvenAtWidth(_) => verified,
        other => {
            if fallback.is_proven() {
                fallback
            } else {
                other
            }
        }
    }
}

fn verify_equivalent(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: u32,
    original_is_mba: bool,
) -> Verification {
    let budget_width: Width = largest_verifiable_width(var_count);
    if width.is_exhaustible() && width.bits() <= budget_width.bits() {
        if equivalent_exhaustive(original, candidate, width, var_count) {
            return Verification::ExhaustiveAtWidth(width);
        }
        return Verification::Unverified;
    }
    let liftable: bool = original_is_mba && candidate.is_linear_mba();
    if liftable
        && (1..=MAX_SOLVER_VARS).contains(&var_count)
        && column_identity_proves(original, candidate, width, var_count)
    {
        return Verification::LinearColumnIdentity(width);
    }
    if liftable && equivalent_exhaustive(original, candidate, budget_width, var_count) {
        return Verification::LinearLiftedFrom(budget_width);
    }
    #[cfg(feature = "smt-verify")]
    if crate::verify::verify_equivalent(original, candidate, width).is_proven() {
        return Verification::SmtProvenAtWidth(width);
    }
    Verification::Unverified
}

fn column_identity_proves(original: &Expr, candidate: &Expr, width: Width, var_count: u32) -> bool {
    if !is_column_faithful(original, width) || !is_column_faithful(candidate, width) {
        return false;
    }
    let rows: usize = 1usize << var_count;
    let original_column: Vec<i128> = truth_column(original, var_count, rows);
    let candidate_column: Vec<i128> = truth_column(candidate, var_count, rows);
    columns_equal_mod_width(&original_column, &candidate_column, width)
}

fn largest_verifiable_width(var_count: u32) -> Width {
    let widths: [Width; 5] = [Width::W16, Width::W8, Width::W4, Width::W2, Width::W1];
    let count: u32 = var_count.max(1);
    for width in widths {
        let total_log2: u64 = u64::from(width.bits()) * u64::from(count);
        if total_log2 <= u64::from(VERIFY_BUDGET_LOG2) {
            return width;
        }
    }
    Width::W1
}

fn template_candidates(var_count: u32) -> Vec<Expr> {
    let mut out: Vec<Expr> = vec![Expr::konst(0)];
    if var_count >= 1 {
        out.push(Expr::var(0));
        out.push(Expr::not(Expr::var(0)));
        out.push(Expr::neg(Expr::var(0)));
    }
    if var_count >= 2 {
        let x: Expr = Expr::var(0);
        let y: Expr = Expr::var(1);
        out.push(Expr::add(x.clone(), y.clone()));
        out.push(Expr::sub(x.clone(), y.clone()));
        out.push(Expr::sub(y.clone(), x.clone()));
        out.push(Expr::and(x.clone(), y.clone()));
        out.push(Expr::or(x.clone(), y.clone()));
        out.push(Expr::xor(x.clone(), y.clone()));
        out.push(Expr::not(Expr::or(x.clone(), y.clone())));
        out.push(Expr::not(Expr::and(x.clone(), y.clone())));
        out.push(Expr::not(Expr::xor(x, y)));
    }
    out
}

fn synthesize_linear(expr: &Expr, width: Width, var_count: u32) -> Option<Expr> {
    let basis_len: usize = 1usize << var_count;
    let column: Vec<i128> = truth_table_column(expr, var_count, basis_len);
    let coeffs: Vec<i128> = mobius_coefficients(&column, basis_len);
    build_from_coefficients(&coeffs, width, var_count)
}

fn truth_table_column(expr: &Expr, var_count: u32, basis_len: usize) -> Vec<i128> {
    let mut column: Vec<i128> = vec![0; basis_len];
    let mut bits: Vec<u8> = vec![0; var_count as usize];
    for (row, slot) in column.iter_mut().enumerate() {
        for (index, bit) in bits.iter_mut().enumerate() {
            *bit = ((row >> index) & 1) as u8;
        }
        *slot = expr.eval_truth_row(&bits);
    }
    column
}

fn mobius_coefficients(column: &[i128], basis_len: usize) -> Vec<i128> {
    let mut coeffs: Vec<i128> = column.to_vec();
    let mut bit: usize = 0;
    while (1usize << bit) < basis_len {
        let step: usize = 1usize << bit;
        let mut mask: usize = 0;
        while mask < basis_len {
            if mask & step != 0 {
                coeffs[mask] -= coeffs[mask ^ step];
            }
            mask += 1;
        }
        bit += 1;
    }
    coeffs
}

fn build_from_coefficients(coeffs: &[i128], width: Width, var_count: u32) -> Option<Expr> {
    let mut terms: Vec<Expr> = Vec::new();

    for (pattern, &coeff) in coeffs.iter().enumerate() {
        let signed: SignedCoeff = reduce_mod_width(coeff, width);
        if signed.magnitude == 0 {
            continue;
        }
        if pattern == 0 {
            push_signed_const(&mut terms, &signed);
            continue;
        }
        let basis: Expr = basis_expression(pattern, var_count)?;
        push_scaled_term(&mut terms, &signed, basis);
    }

    if terms.is_empty() {
        return Some(Expr::konst(0));
    }
    Some(sum_terms(terms))
}

fn basis_expression(pattern: usize, var_count: u32) -> Option<Expr> {
    if pattern == 0 {
        return None;
    }
    let mut factors: Vec<Expr> = Vec::new();
    for index in 0..var_count {
        if (pattern >> index) & 1 == 1 {
            factors.push(Expr::var(index));
        }
    }
    let mut iter: std::vec::IntoIter<Expr> = factors.into_iter();
    let first: Expr = iter.next()?;
    let mut acc: Expr = first;
    for factor in iter {
        acc = Expr::and(acc, factor);
    }
    Some(acc)
}

fn push_scaled_term(terms: &mut Vec<Expr>, signed: &SignedCoeff, basis: Expr) {
    let magnitude_term: Expr = if signed.magnitude == 1 {
        basis
    } else {
        Expr::mul(Expr::konst(signed.magnitude), basis)
    };
    if signed.negative {
        terms.push(Expr::neg(magnitude_term));
    } else {
        terms.push(magnitude_term);
    }
}

fn push_signed_const(terms: &mut Vec<Expr>, signed: &SignedCoeff) {
    if signed.negative {
        terms.push(Expr::neg(Expr::konst(signed.magnitude)));
    } else {
        terms.push(Expr::konst(signed.magnitude));
    }
}

struct SignedCoeff {
    magnitude: u64,
    negative: bool,
}

const fn reduce_mod_width(coeff: i128, width: Width) -> SignedCoeff {
    let modulus: i128 = width.modulus() as i128;
    let residue: i128 = coeff.rem_euclid(modulus);
    if residue * 2 <= modulus {
        SignedCoeff {
            magnitude: residue as u64,
            negative: false,
        }
    } else {
        SignedCoeff {
            magnitude: (modulus - residue) as u64,
            negative: true,
        }
    }
}

fn sum_terms(terms: Vec<Expr>) -> Expr {
    let mut iter: std::vec::IntoIter<Expr> = terms.into_iter();
    let Some(first): Option<Expr> = iter.next() else {
        return Expr::konst(0);
    };
    let mut acc: Expr = first;
    for term in iter {
        acc = match term {
            Expr::Unary(UnOp::Neg, inner) => Expr::Binary(BinOp::Sub, Box::new(acc), inner),
            other => Expr::Binary(BinOp::Add, Box::new(acc), Box::new(other)),
        };
    }
    acc
}

fn is_bitwise(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_) | Expr::Var(_) => true,
        Expr::Unary(UnOp::Not, inner) => is_bitwise(inner),
        Expr::Unary(UnOp::Neg, _)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => false,
        Expr::Binary(op, left, right) => {
            matches!(op, BinOp::And | BinOp::Or | BinOp::Xor)
                && is_bitwise(left)
                && is_bitwise(right)
        }
    }
}

fn synthesize_bitwise_unary(expr: &Expr, width: Width) -> Expr {
    let mask: u64 = width.mask();
    let at_zero: u64 = expr.eval(&[0], width);
    let at_ones: u64 = expr.eval(&[mask], width);
    let id_mask: u64 = !at_zero & at_ones & mask;
    let not_mask: u64 = at_zero & !at_ones & mask;
    let one_mask: u64 = at_zero & at_ones & mask;
    let zero_mask: u64 = !at_zero & !at_ones & mask;
    debug_assert_eq!(id_mask | not_mask | one_mask | zero_mask, mask);

    universal_bitwise_form(id_mask, not_mask, one_mask, mask)
}

/// The canonical minimal form of a single-variable bitwise function of `v0` at
/// `width`. Every output bit is `0`, `1`, `v0`, or `~v0`; the four masks name
/// which bits do what. The value equals `((v0 ^ not_mask) & keep_mask) | one_mask`
/// with `keep_mask = id_mask | not_mask`: XOR flips the `not` bits, the AND keeps
/// only the input-dependent bits (dropping the `one`/`zero` positions), and the OR
/// sets the constant-one bits. Zero-bits fall out because they are absent from every
/// mask. Each factor collapses when its mask is trivial, so pure `~`, `&`, `|`, and
/// `^` shapes reduce to the obvious two-node forms. The result is width-independent
/// by construction, so the caller's exact oracle (exhaustive on narrow widths, the
/// bit-blast verifier on wide ones) can prove it before it is emitted.
fn universal_bitwise_form(id_mask: u64, not_mask: u64, one_mask: u64, mask: u64) -> Expr {
    let keep_mask: u64 = id_mask | not_mask;
    if keep_mask == 0 {
        return Expr::konst(one_mask);
    }
    let flipped: Expr = if not_mask == 0 {
        Expr::var(0)
    } else if not_mask == mask {
        Expr::not(Expr::var(0))
    } else {
        Expr::xor(Expr::var(0), Expr::konst(not_mask))
    };
    let masked: Expr = if keep_mask == mask {
        flipped
    } else {
        Expr::and(flipped, Expr::konst(keep_mask))
    };
    if one_mask == 0 {
        masked
    } else {
        Expr::or(masked, Expr::konst(one_mask))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn xor_and_basis(a: u32, b: u32) -> Expr {
        Expr::add(
            Expr::xor(Expr::var(a), Expr::var(b)),
            Expr::mul(Expr::konst(2), Expr::and(Expr::var(a), Expr::var(b))),
        )
    }

    #[test]
    fn xor_plus_twice_and_is_add() {
        let obfuscated: Expr = xor_and_basis(0, 1);
        let result: Simplification = simplify(&obfuscated, Width::W8);
        assert!(result.changed(), "expected a simplification to fire");
        assert_eq!(
            result.verification,
            Verification::ExhaustiveAtWidth(Width::W8)
        );
        let expected: Expr = Expr::add(Expr::var(0), Expr::var(1));
        assert!(
            equivalent_exhaustive(&result.simplified, &expected, Width::W8, 2),
            "simplified `{}` not equal to x + y",
            result.simplified
        );
        assert!(result.simplified.node_count() <= expected.node_count() + 1);
    }

    #[test]
    fn or_equals_xor_plus_and() {
        let obfuscated: Expr = Expr::add(
            Expr::xor(Expr::var(0), Expr::var(1)),
            Expr::and(Expr::var(0), Expr::var(1)),
        );
        let result: Simplification = simplify(&obfuscated, Width::W8);
        assert!(result.changed());
        assert!(result.verification.is_proven());
        let expected: Expr = Expr::or(Expr::var(0), Expr::var(1));
        assert!(
            equivalent_exhaustive(&result.simplified, &expected, Width::W8, 2),
            "simplified `{}` not equal to x | y",
            result.simplified
        );
    }

    #[test]
    fn xor_via_and_or_with_not_as_xor_all_ones_is_recognized_as_mba() {
        let not_b: Expr = Expr::xor(Expr::var(1), Expr::konst(0xFF));
        let not_a: Expr = Expr::xor(Expr::var(0), Expr::konst(0xFF));
        let obfuscated: Expr = Expr::or(
            Expr::and(Expr::var(0), not_b),
            Expr::and(not_a, Expr::var(1)),
        );
        assert!(
            obfuscated.is_linear_mba(),
            "NOT expressed as `x ^ all-ones` must classify as linear-MBA so the synthesizer fires"
        );
        let result: Simplification = simplify(&obfuscated, Width::W8);
        assert!(
            result.changed(),
            "the OLLVM XOR-substitution (a & ~b) | (~a & b) must reduce: {}",
            result.simplified
        );
        let expected: Expr = Expr::xor(Expr::var(0), Expr::var(1));
        assert!(
            equivalent_exhaustive(&result.simplified, &expected, Width::W8, 2),
            "simplified `{}` not equal to x ^ y",
            result.simplified
        );
    }

    #[test]
    fn collapses_to_constant_zero() {
        let obfuscated: Expr = Expr::sub(Expr::var(0), Expr::var(0));
        let result: Simplification = simplify(&obfuscated, Width::W8);
        assert!(result.verification.is_proven());
        assert!(
            equivalent_exhaustive(&result.simplified, &Expr::konst(0), Width::W8, 1),
            "expected zero, got `{}`",
            result.simplified
        );
    }

    #[test]
    fn single_var_xor_neg_one_is_not() {
        let obfuscated: Expr = Expr::sub(Expr::neg(Expr::var(0)), Expr::konst(1));
        let result: Simplification = simplify(&obfuscated, Width::W8);
        assert!(
            equivalent_exhaustive(&result.simplified, &Expr::not(Expr::var(0)), Width::W8, 1),
            "expected ~x, got `{}`",
            result.simplified
        );
    }

    #[test]
    fn nonlinear_is_left_untouched() {
        let nonlinear: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        let result: Simplification = simplify(&nonlinear, Width::W8);
        assert!(!result.changed());
        assert!(!result.verification.is_proven());
    }

    #[test]
    fn wide_width_proven_by_column_identity() {
        let obfuscated: Expr = xor_and_basis(0, 1);
        let result: Simplification = simplify(&obfuscated, Width::W64);
        assert!(result.changed());
        assert_eq!(
            result.verification,
            Verification::LinearColumnIdentity(Width::W64),
            "xor-carry at 64-bit must now prove exactly by column identity, not lift from 8-bit"
        );
    }

    #[test]
    fn single_var_wide_width_uses_w16_budget() {
        let obfuscated: Expr = Expr::sub(Expr::neg(Expr::var(0)), Expr::konst(1));
        let result: Simplification = simplify(&obfuscated, Width::W64);
        if result.changed() {
            assert_eq!(
                result.verification,
                Verification::LinearLiftedFrom(Width::W16),
                "neg is not per-bit independent, so the two's-complement identity ~x = -x-1 falls to the W16 lift, not the column-identity proof"
            );
        }
    }

    #[test]
    fn never_emits_unverified_change() {
        let obfuscated: Expr = xor_and_basis(0, 1);
        for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
            let result: Simplification = simplify(&obfuscated, width);
            if result.changed() {
                assert!(result.verification.is_proven());
            }
        }
    }

    #[test]
    fn algebraic_identity_collapses_wide_nonlinear_residue() {
        let obfuscated: Expr = Expr::sub(
            Expr::mul(Expr::var(0), Expr::var(1)),
            Expr::mul(Expr::var(1), Expr::var(0)),
        );
        let result: Simplification = simplify(&obfuscated, Width::W64);
        assert!(
            result.changed(),
            "x*y - y*x must collapse to 0 by structural identity even at 64-bit width"
        );
        assert_eq!(result.verification, Verification::AlgebraicIdentity);
        assert_eq!(result.simplified, Expr::konst(0));
    }

    #[test]
    fn algebraic_identity_strips_add_zero_at_wide_width() {
        let obfuscated: Expr = Expr::add(
            Expr::mul(Expr::var(0), Expr::var(1)),
            Expr::xor(Expr::var(2), Expr::var(2)),
        );
        let result: Simplification = simplify(&obfuscated, Width::W64);
        assert!(result.changed());
        assert_eq!(result.verification, Verification::AlgebraicIdentity);
        assert_eq!(
            result.simplified,
            Expr::mul(Expr::var(0), Expr::var(1)),
            "x*y + (z^z) must reduce to x*y"
        );
    }

    #[test]
    fn algebraic_and_exhaustive_agree_on_small_width() {
        let obfuscated: Expr = Expr::xor(Expr::var(0), Expr::konst(0xFF));
        let result: Simplification = simplify(&obfuscated, Width::W8);
        if result.changed() {
            assert!(result.verification.is_proven());
            assert!(equivalent_exhaustive(
                &result.simplified,
                &Expr::not(Expr::var(0)),
                Width::W8,
                1
            ));
        }
    }
}
