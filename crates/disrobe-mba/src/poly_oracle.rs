use crate::expr::{BinOp, Expr, UnOp, Width};
use std::collections::BTreeMap;

const MAX_MONOMIALS: usize = 4096;
const MAX_MONOMIAL_DEGREE: u32 = 128;
const MAX_CERTIFICATE_ATOMS: usize = 8;

type Monomial = BTreeMap<u32, u32>;
type Poly = BTreeMap<Monomial, u64>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Atom {
    Opaque(Expr),
    ShiftRight(Poly, Poly),
}

#[derive(Debug, Default)]
struct AtomTable {
    registry: Vec<Atom>,
}

impl AtomTable {
    fn intern(&mut self, expr: &Expr) -> Option<u32> {
        self.intern_atom(Atom::Opaque(expr.clone()))
    }

    fn intern_shift_right(&mut self, value: Poly, amount: Poly) -> Option<u32> {
        self.intern_atom(Atom::ShiftRight(value, amount))
    }

    fn intern_atom(&mut self, atom: Atom) -> Option<u32> {
        if let Some(position) = self.registry.iter().position(|entry: &Atom| *entry == atom) {
            return u32::try_from(position).ok();
        }
        self.registry.push(atom);
        u32::try_from(self.registry.len() - 1).ok()
    }
}

fn poly_constant(value: u64) -> Poly {
    let mut poly: Poly = Poly::new();
    if value != 0 {
        poly.insert(Monomial::new(), value);
    }
    poly
}

fn poly_atom(id: u32) -> Poly {
    let mut monomial: Monomial = Monomial::new();
    monomial.insert(id, 1);
    let mut poly: Poly = Poly::new();
    poly.insert(monomial, 1);
    poly
}

fn accumulate(poly: &mut Poly, monomial: Monomial, coeff: u64, mask: u64) {
    if coeff == 0 {
        return;
    }
    let updated: u64 = poly
        .get(&monomial)
        .copied()
        .unwrap_or(0)
        .wrapping_add(coeff)
        & mask;
    if updated == 0 {
        poly.remove(&monomial);
    } else {
        poly.insert(monomial, updated);
    }
}

fn negate(poly: &Poly, mask: u64) -> Poly {
    poly.iter()
        .map(|(monomial, coeff): (&Monomial, &u64)| (monomial.clone(), coeff.wrapping_neg() & mask))
        .collect()
}

fn add(left: &Poly, right: &Poly, mask: u64) -> Poly {
    let mut result: Poly = left.clone();
    for (monomial, coeff) in right {
        accumulate(&mut result, monomial.clone(), *coeff, mask);
    }
    result
}

fn scale(poly: &Poly, factor: u64, mask: u64) -> Poly {
    let mut result: Poly = Poly::new();
    for (monomial, coeff) in poly {
        let product: u64 = ((u128::from(*coeff) * u128::from(factor)) & u128::from(mask)) as u64;
        accumulate(&mut result, monomial.clone(), product, mask);
    }
    result
}

fn multiply_monomials(left: &Monomial, right: &Monomial) -> Option<Monomial> {
    let mut result: Monomial = left.clone();
    let mut degree: u32 = result.values().sum();
    for (atom, exponent) in right {
        let entry: &mut u32 = result.entry(*atom).or_insert(0);
        *entry = entry.checked_add(*exponent)?;
        degree = degree.checked_add(*exponent)?;
    }
    if degree > MAX_MONOMIAL_DEGREE {
        return None;
    }
    Some(result)
}

fn multiply(left: &Poly, right: &Poly, mask: u64) -> Option<Poly> {
    let mut result: Poly = Poly::new();
    for (left_monomial, left_coeff) in left {
        for (right_monomial, right_coeff) in right {
            let monomial: Monomial = multiply_monomials(left_monomial, right_monomial)?;
            let coeff: u64 =
                ((u128::from(*left_coeff) * u128::from(*right_coeff)) & u128::from(mask)) as u64;
            accumulate(&mut result, monomial, coeff, mask);
            if result.len() > MAX_MONOMIALS {
                return None;
            }
        }
    }
    Some(result)
}

fn normalize(expr: &Expr, width: Width, atoms: &mut AtomTable) -> Option<Poly> {
    let mask: u64 = width.mask();
    match expr {
        Expr::Const(value) => Some(poly_constant(value & mask)),
        Expr::Unary(UnOp::Neg, inner) => {
            let inner_poly: Poly = normalize(inner, width, atoms)?;
            Some(negate(&inner_poly, mask))
        }
        Expr::Binary(BinOp::Add, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            Some(add(&left_poly, &right_poly, mask))
        }
        Expr::Binary(BinOp::Sub, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            Some(add(&left_poly, &negate(&right_poly, mask), mask))
        }
        Expr::Binary(BinOp::Mul, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            multiply(&left_poly, &right_poly, mask)
        }
        Expr::Binary(BinOp::Shl, left, right) => {
            let Expr::Const(shift) = right.as_ref() else {
                return Some(poly_atom(atoms.intern(expr)?));
            };
            let left_poly: Poly = normalize(left, width, atoms)?;
            let amount: u64 = *shift & mask;
            let factor: u64 = if amount >= u64::from(width.bits()) {
                0
            } else {
                (1u64 << amount) & mask
            };
            Some(scale(&left_poly, factor, mask))
        }
        Expr::Binary(BinOp::Shr, value, amount) => {
            let value_poly: Poly = normalize(value, width, atoms)?;
            let amount_poly: Poly = normalize(amount, width, atoms)?;
            Some(poly_atom(
                atoms.intern_shift_right(value_poly, amount_poly)?,
            ))
        }
        Expr::Binary(BinOp::Xor, left, right) if left == right => Some(poly_constant(0)),
        Expr::Binary(BinOp::And | BinOp::Or, left, right) if left == right => {
            normalize(left, width, atoms)
        }
        Expr::Binary(BinOp::Xor, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            let conjunction: u32 = atoms.intern(&Expr::and((**left).clone(), (**right).clone()))?;
            let sum: Poly = add(&left_poly, &right_poly, mask);
            Some(add(
                &sum,
                &negate(&scale(&poly_atom(conjunction), 2, mask), mask),
                mask,
            ))
        }
        Expr::Binary(BinOp::Or, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            let conjunction: u32 = atoms.intern(&Expr::and((**left).clone(), (**right).clone()))?;
            let sum: Poly = add(&left_poly, &right_poly, mask);
            Some(add(&sum, &negate(&poly_atom(conjunction), mask), mask))
        }
        Expr::Unary(UnOp::Not, inner) => {
            let inner_poly: Poly = normalize(inner, width, atoms)?;
            Some(add(&poly_constant(mask), &negate(&inner_poly, mask), mask))
        }
        _ => Some(poly_atom(atoms.intern(expr)?)),
    }
}

fn var_upper_bound(expr: &Expr, bound: &mut u32) {
    match expr {
        Expr::Const(_) => {}
        Expr::Var(index) => *bound = (*bound).max(index.saturating_add(1)),
        Expr::Unary(_, inner) | Expr::Slice(inner, _, _) | Expr::Mem(inner, _) => {
            var_upper_bound(inner, bound);
        }
        Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => {
            var_upper_bound(left, bound);
            var_upper_bound(right, bound);
        }
        Expr::Ite(cond, then_branch, else_branch) => {
            var_upper_bound(cond, bound);
            var_upper_bound(then_branch, bound);
            var_upper_bound(else_branch, bound);
        }
    }
}

const MIXED_PROBE_ROUNDS: usize = 64;
const RANDOM_PROBE_ROUNDS: usize = 64;

fn lift_memory_leaves(expr: &Expr, table: &mut Vec<Expr>, first_free: u32) -> Expr {
    match expr {
        Expr::Mem(_, load_width) => {
            let position: usize = table
                .iter()
                .position(|entry: &Expr| entry == expr)
                .unwrap_or(table.len());
            if position == table.len() {
                table.push(expr.clone());
            }
            let Ok(offset): Result<u32, _> = u32::try_from(position) else {
                return expr.clone();
            };
            let Some(index): Option<u32> = first_free.checked_add(offset) else {
                return expr.clone();
            };
            Expr::and(Expr::var(index), Expr::konst(load_width.mask()))
        }
        Expr::Const(_) | Expr::Var(_) => expr.clone(),
        Expr::Unary(op, inner) => {
            Expr::Unary(*op, Box::new(lift_memory_leaves(inner, table, first_free)))
        }
        Expr::Binary(op, left, right) => Expr::Binary(
            *op,
            Box::new(lift_memory_leaves(left, table, first_free)),
            Box::new(lift_memory_leaves(right, table, first_free)),
        ),
        Expr::Ite(cond, then_branch, else_branch) => Expr::Ite(
            Box::new(lift_memory_leaves(cond, table, first_free)),
            Box::new(lift_memory_leaves(then_branch, table, first_free)),
            Box::new(lift_memory_leaves(else_branch, table, first_free)),
        ),
        Expr::Slice(inner, lo, hi) => Expr::Slice(
            Box::new(lift_memory_leaves(inner, table, first_free)),
            *lo,
            *hi,
        ),
        Expr::Compose(low, high, low_bits) => Expr::Compose(
            Box::new(lift_memory_leaves(low, table, first_free)),
            Box::new(lift_memory_leaves(high, table, first_free)),
            *low_bits,
        ),
    }
}

fn probe_values(width: Width) -> Vec<u64> {
    let mask: u64 = width.mask();
    let bits: u32 = width.bits();
    let sign: u64 = 1u64 << (bits - 1);
    let mut values: Vec<u64> = vec![
        0,
        1 & mask,
        2 & mask,
        mask,
        mask ^ 1,
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

const fn advance(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn concrete_refutes(original: &Expr, candidate: &Expr, width: Width) -> bool {
    let mask: u64 = width.mask();
    let mut leaf_base: u32 = 0;
    var_upper_bound(original, &mut leaf_base);
    var_upper_bound(candidate, &mut leaf_base);
    let mut table: Vec<Expr> = Vec::new();
    let probe_original: Expr = lift_memory_leaves(original, &mut table, leaf_base);
    let probe_candidate: Expr = lift_memory_leaves(candidate, &mut table, leaf_base);
    let Ok(extra): Result<u32, _> = u32::try_from(table.len()) else {
        return false;
    };
    let Some(var_count): Option<u32> = leaf_base.checked_add(extra) else {
        return false;
    };
    let mut env: Vec<u64> = vec![0; var_count as usize];
    let differs = |assignment: &[u64]| -> bool {
        probe_original.eval(assignment, width) & mask
            != probe_candidate.eval(assignment, width) & mask
    };
    if var_count == 0 {
        return differs(&env);
    }
    let values: Vec<u64> = probe_values(width);
    for value in &values {
        env.fill(*value);
        if differs(&env) {
            return true;
        }
    }
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..MIXED_PROBE_ROUNDS {
        for slot in &mut env {
            let draw: u64 = advance(&mut state);
            let position: usize = (draw % values.len() as u64) as usize;
            *slot = values.get(position).copied().unwrap_or(0);
        }
        if differs(&env) {
            return true;
        }
    }
    for _ in 0..RANDOM_PROBE_ROUNDS {
        for slot in &mut env {
            *slot = advance(&mut state) & mask;
        }
        if differs(&env) {
            return true;
        }
    }
    false
}

fn difference_monomials(
    left: &Poly,
    right: &Poly,
    mask: u64,
    atom_count: usize,
) -> Option<Vec<(Vec<u32>, u128)>> {
    let mut difference: Poly = left.clone();
    for (monomial, coeff) in right {
        accumulate(
            &mut difference,
            monomial.clone(),
            coeff.wrapping_neg() & mask,
            mask,
        );
    }
    let mut rows: Vec<(Vec<u32>, u128)> = Vec::with_capacity(difference.len());
    for (monomial, coeff) in difference {
        let mut key: Vec<u32> = vec![0; atom_count];
        for (atom, exponent) in monomial {
            let axis: usize = usize::try_from(atom).ok()?;
            *key.get_mut(axis)? = exponent;
        }
        rows.push((key, u128::from(coeff)));
    }
    Some(rows)
}

fn induces_zero_over_free_atoms(
    left: &Poly,
    right: &Poly,
    width: Width,
    atom_count: usize,
) -> bool {
    if atom_count == 0 || atom_count > MAX_CERTIFICATE_ATOMS {
        return false;
    }
    let Some(rows): Option<Vec<(Vec<u32>, u128)>> =
        difference_monomials(left, right, width.mask(), atom_count)
    else {
        return false;
    };
    crate::finite_diff::multivar_induces_zero(&rows, atom_count, width)
}

pub(crate) fn congruent_to_constant(
    expr: &Expr,
    constant: u64,
    width: Width,
    reduction: Width,
) -> bool {
    if reduction.bits() > width.bits() {
        return false;
    }
    let mut atoms: AtomTable = AtomTable::default();
    let Some(poly): Option<Poly> = normalize(expr, width, &mut atoms) else {
        return false;
    };
    let atom_count: usize = atoms.registry.len();
    if atom_count > MAX_CERTIFICATE_ATOMS {
        return false;
    }
    let target: Poly = poly_constant(constant & width.mask());
    let Some(rows): Option<Vec<(Vec<u32>, u128)>> =
        difference_monomials(&poly, &target, width.mask(), atom_count)
    else {
        return false;
    };
    crate::finite_diff::multivar_induces_zero(&rows, atom_count, reduction)
}

#[must_use]
pub fn polynomial_identity_proves(original: &Expr, candidate: &Expr, width: Width) -> bool {
    if concrete_refutes(original, candidate, width) {
        return false;
    }
    let mut atoms: AtomTable = AtomTable::default();
    let Some(original_poly): Option<Poly> = normalize(original, width, &mut atoms) else {
        return false;
    };
    let Some(candidate_poly): Option<Poly> = normalize(candidate, width, &mut atoms) else {
        return false;
    };
    if original_poly == candidate_poly {
        return true;
    }
    induces_zero_over_free_atoms(&original_poly, &candidate_poly, width, atoms.registry.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{AtomTable, Poly, normalize, polynomial_identity_proves};
    use crate::expr::{Expr, Width};

    fn var(index: u32) -> Expr {
        Expr::var(index)
    }

    #[test]
    fn commuted_product_difference_is_zero_at_w64() {
        let original: Expr = Expr::sub(Expr::mul(var(0), var(1)), Expr::mul(var(1), var(0)));
        assert!(polynomial_identity_proves(
            &original,
            &Expr::konst(0),
            Width::W64
        ));
    }

    #[test]
    fn xor_self_cancels_under_product_at_w64() {
        let original: Expr = Expr::add(Expr::mul(var(0), var(1)), Expr::xor(var(2), var(2)));
        let candidate: Expr = Expr::mul(var(0), var(1));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W64
        ));
    }

    #[test]
    fn distributes_multiplication_over_addition() {
        let original: Expr = Expr::mul(var(0), Expr::add(var(1), var(2)));
        let candidate: Expr = Expr::add(Expr::mul(var(0), var(1)), Expr::mul(var(0), var(2)));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn shift_left_by_constant_is_multiplication() {
        let original: Expr = Expr::shl(var(0), Expr::konst(3));
        let candidate: Expr = Expr::mul(var(0), Expr::konst(8));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn oversized_constant_shift_uses_the_width_masked_amount() {
        let atom: Expr = Expr::mem(var(0), Width::W8);
        let shifted: Expr = Expr::shl(atom.clone(), Expr::konst(256));
        assert!(!polynomial_identity_proves(
            &shifted,
            &Expr::konst(0),
            Width::W8
        ));
        assert!(polynomial_identity_proves(&shifted, &atom, Width::W8));
    }

    #[test]
    fn rejects_a_non_equivalent_product() {
        let original: Expr = Expr::mul(var(0), var(1));
        let candidate: Expr = Expr::add(var(0), var(1));
        assert!(!polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn abstains_on_opaque_shift_mismatch() {
        let original: Expr = Expr::shr(var(0), Expr::konst(1));
        let candidate: Expr = Expr::konst(0);
        assert!(!polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn opaque_atoms_cancel_when_structurally_shared() {
        let shifted: Expr = Expr::shr(var(0), Expr::konst(1));
        let original: Expr = Expr::sub(
            Expr::add(Expr::mul(var(1), var(1)), shifted.clone()),
            shifted,
        );
        let candidate: Expr = Expr::mul(var(1), var(1));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W64
        ));
    }

    #[test]
    fn xor_plus_twice_and_recovers_addition_at_w64() {
        let obfuscated: Expr = Expr::add(
            Expr::xor(var(0), var(1)),
            Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
        );
        let clean: Expr = Expr::add(var(0), var(1));
        assert!(polynomial_identity_proves(&obfuscated, &clean, Width::W64));
    }

    #[test]
    fn or_plus_and_recovers_addition_at_w64() {
        let obfuscated: Expr = Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1)));
        let clean: Expr = Expr::add(var(0), var(1));
        assert!(polynomial_identity_proves(&obfuscated, &clean, Width::W64));
    }

    #[test]
    fn or_minus_xor_recovers_and_at_w32() {
        let obfuscated: Expr = Expr::sub(Expr::or(var(0), var(1)), Expr::xor(var(0), var(1)));
        let clean: Expr = Expr::and(var(0), var(1));
        assert!(polynomial_identity_proves(&obfuscated, &clean, Width::W32));
    }

    #[test]
    fn complement_plus_self_is_all_ones_at_w32() {
        let obfuscated: Expr = Expr::add(Expr::not(var(0)), var(0));
        assert!(polynomial_identity_proves(
            &obfuscated,
            &Expr::konst(0xFFFF_FFFF),
            Width::W32
        ));
    }

    #[test]
    fn does_not_falsely_equate_or_with_and_at_w32() {
        let disjunction: Expr = Expr::or(var(0), var(1));
        let conjunction: Expr = Expr::and(var(0), var(1));
        assert!(!polynomial_identity_proves(
            &disjunction,
            &conjunction,
            Width::W32
        ));
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_expr(state: &mut u64, depth: u32) -> Expr {
        if depth == 0 || xorshift(state).is_multiple_of(5) {
            return match xorshift(state) % 3 {
                0 => var(0),
                1 => var(1),
                _ => Expr::konst(xorshift(state) & 0xFF),
            };
        }
        let left: Expr = random_expr(state, depth - 1);
        let right: Expr = random_expr(state, depth - 1);
        match xorshift(state) % 11 {
            0 => Expr::add(left, right),
            1 => Expr::sub(left, right),
            2 => Expr::mul(left, right),
            3 => Expr::xor(left, right),
            4 => Expr::and(left, right),
            5 => Expr::or(left, right),
            6 => Expr::neg(left),
            7 => Expr::not(left),
            8 => Expr::shl(left, Expr::konst(xorshift(state) % 300)),
            9 => Expr::shr(left, Expr::konst(xorshift(state) % 300)),
            _ => Expr::ite(left, right, random_expr(state, depth - 1)),
        }
    }

    #[test]
    fn oracle_never_accepts_a_non_equivalent_pair_under_w8_exhaustive() {
        use crate::expr::equivalent_exhaustive;
        let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut proven: u32 = 0;
        let mut certified: u32 = 0;
        for _ in 0..4000u32 {
            let original: Expr = random_expr(&mut state, 4);
            let candidate: Expr = random_expr(&mut state, 4);
            let padded: Expr = Expr::add(original.clone(), vanishing_at_w8(&candidate));
            for (left, right) in [
                (&original, &candidate),
                (&padded, &original),
                (&padded, &candidate),
            ] {
                if !polynomial_identity_proves(left, right, Width::W8) {
                    continue;
                }
                proven += 1;
                if !normal_forms_match(left, right, Width::W8) {
                    certified += 1;
                }
                assert!(
                    equivalent_exhaustive(left, right, Width::W8, 2),
                    "oracle accepted a non-equivalent pair at W8: {left:?} vs {right:?}",
                );
            }
        }
        assert!(proven > 0, "fuzz never exercised the accept path");
        assert!(
            certified > 0,
            "fuzz never exercised the finite-difference certificate path, so it is unguarded"
        );
    }

    fn vanishing_at_w8(atom: &Expr) -> Expr {
        Expr::mul(
            Expr::konst(0x80),
            Expr::mul(atom.clone(), Expr::add(atom.clone(), Expr::konst(0xFF))),
        )
    }

    fn normal_forms_match(original: &Expr, candidate: &Expr, width: Width) -> bool {
        let mut atoms: AtomTable = AtomTable::default();
        let Some(left): Option<Poly> = normalize(original, width, &mut atoms) else {
            return false;
        };
        let Some(right): Option<Poly> = normalize(candidate, width, &mut atoms) else {
            return false;
        };
        left == right
    }
}
