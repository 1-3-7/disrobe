#![doc = "Polynomial / affine linear MBA solver over Z/2^n with an exact algebraic proof."]
#![doc = ""]
#![doc = "A linear mixed Boolean-arithmetic expression is an affine sum of"]
#![doc = "integer-scaled, width-uniform bitwise terms over a variable set. The `SiMBA`"]
#![doc = "signature evaluates the whole fixed-width expression on every assignment of"]
#![doc = "numeric zero and one to those variables. Two linear MBAs are equal over"]
#![doc = "Z/2^n exactly when these signatures are equal modulo 2^n. Whole-expression"]
#![doc = "evaluation handles arithmetic constants and bitwise negation without replacing"]
#![doc = "them by one-bit logical values. Partial masks and cross-bit operations remain"]
#![doc = "outside the proof grammar."]
#![doc = ""]
#![doc = "This module recovers the simplest linear form of an expression by solving for"]
#![doc = "its coefficient vector over the canonical minterm basis, then proves the result"]
#![doc = "with [`columns_equal_mod_width`]. The proof is structural over the modeled"]
#![doc = "width, not a sampled check, so it holds at W16, W32, and W64 and for more"]
#![doc = "variables than the exhaustive bitvector core can enumerate."]

use crate::expr::{BinOp, Expr, UnOp, Width};

pub const MAX_SOLVER_VARS: u32 = 8;

const MAX_SUBSET_SEARCH_VARS: u32 = 5;

const MAX_SUBSET_COMBOS: usize = 60_000;

#[must_use]
pub fn solve_linear_mba(expr: &Expr, width: Width, var_count: u32) -> Option<Expr> {
    if var_count == 0 || var_count > MAX_SOLVER_VARS {
        return None;
    }
    if !is_affine_signature_faithful(expr, width) {
        return None;
    }
    let rows: usize = 1usize << var_count;
    let target: Vec<i128> = affine_signature(expr, var_count, rows);

    let mut best: Option<(usize, Expr)> = None;
    let mut consider = |candidate: Expr| {
        if !is_affine_signature_faithful(&candidate, width) {
            return;
        }
        let candidate_column: Vec<i128> = affine_signature(&candidate, var_count, rows);
        if !columns_equal_mod_width(&target, &candidate_column, width) {
            return;
        }
        let nodes: usize = candidate.node_count();
        if best
            .as_ref()
            .is_none_or(|(current, _): &(usize, Expr)| nodes < *current)
        {
            best = Some((nodes, candidate));
        }
    };

    let minterm: Expr = reconstruct_from_minterms(&target, width, var_count);
    consider(minterm);

    if var_count <= MAX_SUBSET_SEARCH_VARS
        && let Some(subset) = solve_over_subset_basis(&target, width, var_count, rows)
    {
        consider(subset);
    }

    best.map(|(_, candidate): (usize, Expr)| candidate)
}

#[must_use]
pub fn columns_equal_mod_width(left: &[i128], right: &[i128], width: Width) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let modulus: i128 = width.modulus() as i128;
    left.iter()
        .zip(right.iter())
        .all(|(a, b): (&i128, &i128)| (a - b).rem_euclid(modulus) == 0)
}

#[must_use]
pub fn is_column_faithful(expr: &Expr, width: Width) -> bool {
    faithful_value(expr, width, false)
}

fn is_affine_signature_faithful(expr: &Expr, width: Width) -> bool {
    faithful_value(expr, width, true)
}

fn faithful_value(expr: &Expr, width: Width, affine_constants: bool) -> bool {
    match expr {
        Expr::Const(value) => {
            let masked: u64 = value & width.mask();
            affine_constants || masked == 0 || masked == width.mask()
        }
        Expr::Var(_) => true,
        Expr::Unary(UnOp::Not, inner) => faithful_bitwise(inner, width),
        Expr::Unary(UnOp::Neg, inner) => faithful_value(inner, width, affine_constants),
        Expr::Binary(BinOp::Add | BinOp::Sub, left, right) => {
            faithful_value(left, width, affine_constants)
                && faithful_value(right, width, affine_constants)
        }
        Expr::Binary(BinOp::Mul, left, right) => match (&**left, &**right) {
            (Expr::Const(_), other) | (other, Expr::Const(_)) => faithful_bitwise(other, width),
            _ => false,
        },
        Expr::Binary(BinOp::Shl, left, right) => {
            matches!(&**right, Expr::Const(amount) if *amount < u64::from(width.bits()))
                && faithful_bitwise(left, width)
        }
        Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, left, right) => {
            faithful_bitwise(left, width) && faithful_bitwise(right, width)
        }
        Expr::Binary(BinOp::Shr, _, _)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => false,
    }
}

fn faithful_bitwise(expr: &Expr, width: Width) -> bool {
    match expr {
        Expr::Const(value) => {
            let masked: u64 = value & width.mask();
            masked == 0 || masked == width.mask()
        }
        Expr::Var(_) => true,
        Expr::Unary(UnOp::Not, inner) => faithful_bitwise(inner, width),
        Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, left, right) => {
            faithful_bitwise(left, width) && faithful_bitwise(right, width)
        }
        _ => false,
    }
}

#[must_use]
pub fn truth_column(expr: &Expr, var_count: u32, rows: usize) -> Vec<i128> {
    let mut column: Vec<i128> = vec![0; rows];
    let mut bits: Vec<u8> = vec![0; var_count as usize];
    for (row, slot) in column.iter_mut().enumerate() {
        for (index, bit) in bits.iter_mut().enumerate() {
            *bit = ((row >> index) & 1) as u8;
        }
        *slot = expr.eval_truth_row(&bits);
    }
    column
}

fn affine_signature(expr: &Expr, var_count: u32, rows: usize) -> Vec<i128> {
    let mut column: Vec<i128> = vec![0; rows];
    let mut inputs: Vec<u64> = vec![0; var_count as usize];
    for (row, slot) in column.iter_mut().enumerate() {
        for (index, input) in inputs.iter_mut().enumerate() {
            *input = ((row >> index) & 1) as u64;
        }
        *slot = i128::from(expr.eval(&inputs, Width::W64));
    }
    column
}

fn reconstruct_from_minterms(target: &[i128], width: Width, var_count: u32) -> Expr {
    let coeffs: Vec<i128> = mobius_transform(target);
    let mut terms: Vec<Expr> = Vec::new();
    for (pattern, &coeff) in coeffs.iter().enumerate() {
        let signed: SignedCoeff = reduce_mod_width(coeff, width);
        if signed.magnitude == 0 {
            continue;
        }
        if pattern == 0 {
            push_const(&mut terms, &signed);
            continue;
        }
        let Some(basis): Option<Expr> = minterm_expr(pattern, var_count) else {
            continue;
        };
        push_scaled(&mut terms, &signed, basis);
    }
    if terms.is_empty() {
        return Expr::konst(0);
    }
    sum_terms(terms)
}

fn mobius_transform(column: &[i128]) -> Vec<i128> {
    let len: usize = column.len();
    let mut coeffs: Vec<i128> = column.to_vec();
    let mut bit: usize = 0;
    while (1usize << bit) < len {
        let step: usize = 1usize << bit;
        let mut mask: usize = 0;
        while mask < len {
            if mask & step != 0 {
                coeffs[mask] -= coeffs[mask ^ step];
            }
            mask += 1;
        }
        bit += 1;
    }
    coeffs
}

fn minterm_expr(pattern: usize, var_count: u32) -> Option<Expr> {
    if pattern == 0 {
        return None;
    }
    let mut factors: Vec<Expr> = Vec::with_capacity(var_count as usize);
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

fn solve_over_subset_basis(
    target: &[i128],
    width: Width,
    var_count: u32,
    rows: usize,
) -> Option<Expr> {
    let library: Vec<BasisFn> = subset_basis_library(var_count, rows);
    if library.is_empty() {
        return None;
    }
    let mut best: Option<(usize, Expr)> = None;
    for combo in subset_combinations(library.len()) {
        let Some(coeffs): Option<Vec<i128>> = solve_combo(&combo, &library, target, rows) else {
            continue;
        };
        let candidate: Expr = reconstruct_subset(&combo, &coeffs, &library, width);
        let reconstructed: Vec<i128> = affine_signature(&candidate, var_count, rows);
        if !columns_equal_mod_width(target, &reconstructed, width) {
            continue;
        }
        let nodes: usize = candidate.node_count();
        if best
            .as_ref()
            .is_none_or(|(current, _): &(usize, Expr)| nodes < *current)
        {
            best = Some((nodes, candidate));
        }
    }
    best.map(|(_, candidate): (usize, Expr)| candidate)
}

#[derive(Debug, Clone)]
struct BasisFn {
    table: Vec<i128>,
    expr: Option<Expr>,
}

fn subset_basis_library(var_count: u32, rows: usize) -> Vec<BasisFn> {
    let mut out: Vec<BasisFn> = Vec::new();
    let mut seen: std::collections::BTreeSet<Vec<i128>> = std::collections::BTreeSet::new();
    let mut push = |table: Vec<i128>, expr: Option<Expr>| {
        if table.iter().all(|value: &i128| *value == 0) {
            return;
        }
        if seen.insert(table.clone()) {
            out.push(BasisFn { table, expr });
        }
    };
    push(vec![1; rows], None);
    for candidate in subset_basis_exprs(var_count) {
        let table: Vec<i128> = bit_table(&candidate, var_count, rows);
        push(table, Some(candidate));
    }
    out
}

fn subset_basis_exprs(var_count: u32) -> Vec<Expr> {
    let vars: Vec<Expr> = (0..var_count).map(Expr::var).collect();
    let mut out: Vec<Expr> = Vec::new();
    for var in &vars {
        out.push(var.clone());
        out.push(Expr::not(var.clone()));
    }
    for (i, left) in vars.iter().enumerate() {
        for right in vars.iter().skip(i + 1) {
            out.push(Expr::and(left.clone(), right.clone()));
            out.push(Expr::or(left.clone(), right.clone()));
            out.push(Expr::xor(left.clone(), right.clone()));
            out.push(Expr::and(left.clone(), Expr::not(right.clone())));
            out.push(Expr::and(Expr::not(left.clone()), right.clone()));
        }
    }
    out
}

fn bit_table(expr: &Expr, var_count: u32, rows: usize) -> Vec<i128> {
    let mut table: Vec<i128> = vec![0; rows];
    let mut bits: Vec<u8> = vec![0; var_count as usize];
    for (row, slot) in table.iter_mut().enumerate() {
        for (index, bit) in bits.iter_mut().enumerate() {
            *bit = ((row >> index) & 1) as u8;
        }
        *slot = i128::from(eval_single_bit(expr, &bits));
    }
    table
}

fn eval_single_bit(expr: &Expr, bits: &[u8]) -> u8 {
    match expr {
        Expr::Const(value) => (*value & 1) as u8,
        Expr::Var(index) => bits.get(*index as usize).copied().unwrap_or(0),
        Expr::Unary(op, inner) => {
            let value: u8 = eval_single_bit(inner, bits);
            match op {
                UnOp::Not => value ^ 1,
                UnOp::Neg => value & 1,
            }
        }
        Expr::Binary(op, left, right) => {
            let lhs: u8 = eval_single_bit(left, bits);
            let rhs: u8 = eval_single_bit(right, bits);
            match op {
                BinOp::And => lhs & rhs,
                BinOp::Or => lhs | rhs,
                BinOp::Xor => lhs ^ rhs,
                BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Shl | BinOp::Shr => 0,
            }
        }
        Expr::Ite(_, _, _) | Expr::Slice(_, _, _) | Expr::Compose(_, _, _) | Expr::Mem(_, _) => 0,
    }
}

fn subset_combinations(len: usize) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = Vec::new();
    for i in 0..len {
        out.push(vec![i]);
        if out.len() >= MAX_SUBSET_COMBOS {
            return out;
        }
    }
    for i in 0..len {
        for j in (i + 1)..len {
            out.push(vec![i, j]);
            if out.len() >= MAX_SUBSET_COMBOS {
                return out;
            }
        }
    }
    for i in 0..len {
        for j in (i + 1)..len {
            for k in (j + 1)..len {
                out.push(vec![i, j, k]);
                if out.len() >= MAX_SUBSET_COMBOS {
                    return out;
                }
            }
        }
    }
    out
}

fn solve_combo(
    combo: &[usize],
    library: &[BasisFn],
    target: &[i128],
    rows: usize,
) -> Option<Vec<i128>> {
    let cols: usize = combo.len();
    let mut matrix: Vec<Vec<i128>> = vec![vec![0; cols + 1]; rows];
    for (row, &goal) in target.iter().enumerate() {
        for (col, &basis_index) in combo.iter().enumerate() {
            matrix[row][col] = library[basis_index].table[row];
        }
        matrix[row][cols] = goal;
    }
    gaussian_integer_solve(&mut matrix, rows, cols)
}

fn gaussian_integer_solve(matrix: &mut [Vec<i128>], rows: usize, cols: usize) -> Option<Vec<i128>> {
    let mut pivot_cols: Vec<usize> = Vec::with_capacity(cols);
    let mut current_row: usize = 0;
    for col in 0..cols {
        let pivot: Option<usize> = (current_row..rows).find(|&row: &usize| matrix[row][col] != 0);
        let Some(pivot_row): Option<usize> = pivot else {
            continue;
        };
        matrix.swap(current_row, pivot_row);
        let pivot_values: Vec<i128> = matrix[current_row].clone();
        for (row, values) in matrix.iter_mut().enumerate().take(rows) {
            if row != current_row && values[col] != 0 {
                eliminate(values, &pivot_values, col, cols);
            }
        }
        pivot_cols.push(col);
        current_row += 1;
        if current_row == rows {
            break;
        }
    }

    for row in matrix.iter().skip(current_row).take(rows - current_row) {
        if row.iter().take(cols).all(|value: &i128| *value == 0) && row[cols] != 0 {
            return None;
        }
    }
    if pivot_cols.len() != cols {
        return None;
    }

    let mut solution: Vec<i128> = vec![0; cols];
    for (row, &col) in pivot_cols.iter().enumerate() {
        let pivot: i128 = matrix[row][col];
        let value: i128 = matrix[row][cols];
        if pivot == 0 || value % pivot != 0 {
            return None;
        }
        solution[col] = value / pivot;
    }
    Some(solution)
}

fn eliminate(target: &mut [i128], pivot: &[i128], col: usize, cols: usize) {
    let pivot_lead: i128 = pivot[col];
    let target_lead: i128 = target[col];
    let divisor: i128 = gcd(pivot_lead.abs(), target_lead.abs()).max(1);
    let scale_target: i128 = pivot_lead / divisor;
    let scale_pivot: i128 = target_lead / divisor;
    for (slot, pivot_value) in target.iter_mut().zip(pivot.iter()).take(cols + 1) {
        *slot = *slot * scale_target - pivot_value * scale_pivot;
    }
    normalize_row(target, cols);
}

fn normalize_row(row: &mut [i128], cols: usize) {
    let mut divisor: i128 = 0;
    for value in row.iter().take(cols + 1) {
        divisor = gcd(divisor, value.abs());
    }
    if divisor > 1 {
        for value in row.iter_mut().take(cols + 1) {
            *value /= divisor;
        }
    }
}

const fn gcd(a: i128, b: i128) -> i128 {
    let mut x: i128 = a;
    let mut y: i128 = b;
    while y != 0 {
        let temp: i128 = y;
        y = x % y;
        x = temp;
    }
    x
}

fn reconstruct_subset(combo: &[usize], coeffs: &[i128], library: &[BasisFn], width: Width) -> Expr {
    let mut terms: Vec<Expr> = Vec::new();
    for (&basis_index, &coeff) in combo.iter().zip(coeffs.iter()) {
        let signed: SignedCoeff = reduce_mod_width(coeff, width);
        if signed.magnitude == 0 {
            continue;
        }
        match &library[basis_index].expr {
            None => push_const(&mut terms, &signed),
            Some(expr) => push_scaled(&mut terms, &signed, expr.clone()),
        }
    }
    if terms.is_empty() {
        return Expr::konst(0);
    }
    sum_terms(terms)
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

fn push_const(terms: &mut Vec<Expr>, signed: &SignedCoeff) {
    if signed.negative {
        terms.push(Expr::neg(Expr::konst(signed.magnitude)));
    } else {
        terms.push(Expr::konst(signed.magnitude));
    }
}

fn push_scaled(terms: &mut Vec<Expr>, signed: &SignedCoeff, basis: Expr) {
    let body: Expr = if signed.magnitude == 1 {
        basis
    } else {
        Expr::mul(Expr::konst(signed.magnitude), basis)
    };
    if signed.negative {
        terms.push(Expr::neg(body));
    } else {
        terms.push(body);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;

    fn var(index: u32) -> Expr {
        Expr::var(index)
    }

    #[test]
    fn columns_identity_is_exact_over_modulus() {
        let left: Vec<i128> = vec![0, 1, 1, 2];
        let same: Vec<i128> = vec![256, 257, -255, 2];
        assert!(columns_equal_mod_width(&left, &same, Width::W8));
        let different: Vec<i128> = vec![0, 1, 1, 3];
        assert!(!columns_equal_mod_width(&left, &different, Width::W8));
    }

    #[test]
    fn solves_xor_carry_addition_at_w8() {
        let obfuscated: Expr = Expr::add(
            Expr::xor(var(0), var(1)),
            Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
        );
        let solved: Expr = solve_linear_mba(&obfuscated, Width::W8, 2).expect("must solve");
        assert!(equivalent_exhaustive(&obfuscated, &solved, Width::W8, 2));
        assert!(solved.node_count() <= Expr::add(var(0), var(1)).node_count() + 1);
    }

    #[test]
    fn solves_four_var_linear_combination() {
        let obfuscated: Expr = Expr::add(
            Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1))),
            Expr::add(var(2), var(3)),
        );
        let solved: Expr = solve_linear_mba(&obfuscated, Width::W16, 4).expect("must solve");
        let column_a: Vec<i128> = truth_column(&obfuscated, 4, 16);
        let column_b: Vec<i128> = truth_column(&solved, 4, 16);
        assert!(columns_equal_mod_width(&column_a, &column_b, Width::W16));
        assert!(solved.node_count() < obfuscated.node_count());
    }

    #[test]
    fn refuses_genuine_multiplication() {
        let genuine: Expr = Expr::mul(var(0), var(1));
        assert!(solve_linear_mba(&genuine, Width::W8, 2).is_none());
    }

    #[test]
    fn solves_x_minus_and_recovers_and_not_at_w32() {
        let obfuscated: Expr = Expr::sub(var(0), Expr::and(var(0), var(1)));
        let solved: Expr = solve_linear_mba(&obfuscated, Width::W32, 2).expect("must solve");
        let clean: Expr = Expr::and(var(0), Expr::not(var(1)));
        let column_solved: Vec<i128> = truth_column(&solved, 2, 4);
        let column_clean: Vec<i128> = truth_column(&clean, 2, 4);
        assert!(columns_equal_mod_width(
            &column_solved,
            &column_clean,
            Width::W32
        ));
    }

    #[test]
    fn solves_w4_affine_form_with_native_all_ones_mask() {
        let obfuscated: Expr = Expr::add(
            Expr::xor(var(0), Expr::konst(Width::W4.mask())),
            Expr::konst(1),
        );
        let solved: Expr =
            solve_linear_mba(&obfuscated, Width::W4, 1).expect("must solve W4 affine form");
        assert!(equivalent_exhaustive(&obfuscated, &solved, Width::W4, 1));
        assert!(solved.node_count() <= Expr::neg(var(0)).node_count());
    }

    #[test]
    fn refuses_over_var_budget() {
        let mut expr: Expr = var(0);
        for index in 1..=MAX_SOLVER_VARS {
            expr = Expr::add(expr, var(index));
        }
        assert!(solve_linear_mba(&expr, Width::W16, MAX_SOLVER_VARS + 1).is_none());
    }
}
