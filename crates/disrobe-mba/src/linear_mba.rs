use crate::expr::{BinOp, Expr, UnOp, Width};

const MAX_BASIS_VARS: u32 = 3;

#[must_use]
pub fn synthesize_linear_basis(expr: &Expr, width: Width, var_count: u32) -> Option<Expr> {
    if var_count == 0 || var_count > MAX_BASIS_VARS {
        return None;
    }
    let rows: usize = 1usize << var_count;
    let column: Vec<i128> = truth_column(expr, var_count, rows);
    let library: Vec<BasisFn> = basis_library(var_count);
    let modulus: i128 = width.modulus() as i128;

    let mut best: Option<(usize, Expr)> = None;
    for combo in single_and_pair_combinations(library.len()) {
        let Some(coeffs): Option<Vec<i128>> = solve_combo(&combo, &library, &column, rows) else {
            continue;
        };
        let candidate: Expr = reconstruct(&combo, &coeffs, &library, modulus);
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

fn truth_column(expr: &Expr, var_count: u32, rows: usize) -> Vec<i128> {
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

#[derive(Debug, Clone)]
struct BasisFn {
    table: Vec<i128>,
    expr: Option<Expr>,
}

fn basis_library(var_count: u32) -> Vec<BasisFn> {
    let rows: usize = 1usize << var_count;
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

    let candidates: Vec<Expr> = candidate_basis_exprs(var_count);
    for candidate in candidates {
        let table: Vec<i128> = bitwise_table(&candidate, var_count, rows);
        push(table, Some(candidate));
    }
    out
}

fn candidate_basis_exprs(var_count: u32) -> Vec<Expr> {
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
            out.push(Expr::not(Expr::and(left.clone(), right.clone())));
            out.push(Expr::not(Expr::or(left.clone(), right.clone())));
            out.push(Expr::not(Expr::xor(left.clone(), right.clone())));
            out.push(Expr::and(left.clone(), Expr::not(right.clone())));
            out.push(Expr::and(Expr::not(left.clone()), right.clone()));
        }
    }
    if var_count == 3 {
        let (x, y, z): (&Expr, &Expr, &Expr) = (&vars[0], &vars[1], &vars[2]);
        out.push(Expr::and(Expr::and(x.clone(), y.clone()), z.clone()));
        out.push(Expr::or(Expr::or(x.clone(), y.clone()), z.clone()));
        out.push(Expr::xor(Expr::xor(x.clone(), y.clone()), z.clone()));
    }
    out
}

fn bitwise_table(expr: &Expr, var_count: u32, rows: usize) -> Vec<i128> {
    let mut table: Vec<i128> = vec![0; rows];
    let mut bits: Vec<u8> = vec![0; var_count as usize];
    for (row, slot) in table.iter_mut().enumerate() {
        for (index, bit) in bits.iter_mut().enumerate() {
            *bit = ((row >> index) & 1) as u8;
        }
        *slot = i128::from(eval_bit(expr, &bits));
    }
    table
}

fn eval_bit(expr: &Expr, bits: &[u8]) -> u8 {
    match expr {
        Expr::Const(value) => (*value & 1) as u8,
        Expr::Var(index) => bits.get(*index as usize).copied().unwrap_or(0),
        Expr::Unary(op, inner) => {
            let value: u8 = eval_bit(inner, bits);
            match op {
                UnOp::Not => value ^ 1,
                UnOp::Neg => value & 1,
            }
        }
        Expr::Binary(op, left, right) => {
            let lhs: u8 = eval_bit(left, bits);
            let rhs: u8 = eval_bit(right, bits);
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

fn single_and_pair_combinations(len: usize) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = Vec::new();
    for i in 0..len {
        out.push(vec![i]);
    }
    for i in 0..len {
        for j in (i + 1)..len {
            out.push(vec![i, j]);
        }
    }
    for i in 0..len {
        for j in (i + 1)..len {
            for k in (j + 1)..len {
                out.push(vec![i, j, k]);
            }
        }
    }
    out
}

fn solve_combo(
    combo: &[usize],
    library: &[BasisFn],
    column: &[i128],
    rows: usize,
) -> Option<Vec<i128>> {
    let width: usize = combo.len();
    let mut matrix: Vec<Vec<i128>> = vec![vec![0; width + 1]; rows];
    for (row, target) in column.iter().enumerate() {
        for (col, &basis_index) in combo.iter().enumerate() {
            matrix[row][col] = library[basis_index].table[row];
        }
        matrix[row][width] = *target;
    }
    let solution: Vec<i128> = gaussian_integer_solve(&mut matrix, rows, width)?;
    Some(solution)
}

fn gaussian_integer_solve(
    matrix: &mut [Vec<i128>],
    rows: usize,
    width: usize,
) -> Option<Vec<i128>> {
    let mut pivot_rows: Vec<usize> = Vec::with_capacity(width);
    let mut current_row: usize = 0;
    for col in 0..width {
        let pivot: Option<usize> = matrix
            .iter()
            .enumerate()
            .skip(current_row)
            .take(rows - current_row)
            .find_map(|(row, values): (usize, &Vec<i128>)| (values[col] != 0).then_some(row));
        let Some(pivot_row): Option<usize> = pivot else {
            continue;
        };
        matrix.swap(current_row, pivot_row);
        let pivot_values: Vec<i128> = matrix[current_row].clone();
        for (row, values) in matrix.iter_mut().enumerate().take(rows) {
            if row != current_row && values[col] != 0 {
                eliminate(values, &pivot_values, col, width);
            }
        }
        pivot_rows.push(col);
        current_row += 1;
        if current_row == rows {
            break;
        }
    }

    for row in matrix.iter().skip(current_row).take(rows - current_row) {
        if row.iter().take(width).all(|value: &i128| *value == 0) && row[width] != 0 {
            return None;
        }
    }

    if pivot_rows.len() != width {
        return None;
    }

    let mut solution: Vec<i128> = vec![0; width];
    for (row, &col) in pivot_rows.iter().enumerate() {
        let pivot: i128 = matrix[row][col];
        let value: i128 = matrix[row][width];
        if pivot == 0 || value % pivot != 0 {
            return None;
        }
        solution[col] = value / pivot;
    }
    Some(solution)
}

fn eliminate(target: &mut [i128], pivot: &[i128], col: usize, width: usize) {
    let pivot_lead: i128 = pivot[col];
    let target_lead: i128 = target[col];
    let divisor: i128 = gcd(pivot_lead.abs(), target_lead.abs()).max(1);
    let scale_target: i128 = pivot_lead / divisor;
    let scale_pivot: i128 = target_lead / divisor;
    for (slot, pivot_value) in target.iter_mut().zip(pivot.iter()).take(width + 1) {
        *slot = *slot * scale_target - pivot_value * scale_pivot;
    }
    normalize_row(target, width);
}

fn normalize_row(row: &mut [i128], width: usize) {
    let mut divisor: i128 = 0;
    for value in row.iter().take(width + 1) {
        divisor = gcd(divisor, value.abs());
    }
    if divisor > 1 {
        for value in row.iter_mut().take(width + 1) {
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

fn reconstruct(combo: &[usize], coeffs: &[i128], library: &[BasisFn], modulus: i128) -> Expr {
    let mut terms: Vec<Expr> = Vec::new();
    for (&basis_index, &coeff) in combo.iter().zip(coeffs.iter()) {
        let signed: SignedCoeff = reduce_mod(coeff, modulus);
        if signed.magnitude == 0 {
            continue;
        }
        let basis: &BasisFn = &library[basis_index];
        match &basis.expr {
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

const fn reduce_mod(coeff: i128, modulus: i128) -> SignedCoeff {
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

    fn check(obfuscated: &Expr, width: Width, var_count: u32) -> Expr {
        let synth: Expr = synthesize_linear_basis(obfuscated, width, var_count)
            .expect("synthesizer produced no candidate");
        assert!(
            equivalent_exhaustive(obfuscated, &synth, width, var_count),
            "synthesized `{synth}` not equivalent to `{obfuscated}`"
        );
        synth
    }

    #[test]
    fn x_minus_and_recovers_and_not() {
        let obfuscated: Expr = Expr::sub(var(0), Expr::and(var(0), var(1)));
        let synth: Expr = check(&obfuscated, Width::W8, 2);
        let clean: Expr = Expr::and(var(0), Expr::not(var(1)));
        assert!(equivalent_exhaustive(&synth, &clean, Width::W8, 2));
        assert!(synth.node_count() <= clean.node_count() + 1);
    }

    #[test]
    fn xor_carry_recovers_addition() {
        let obfuscated: Expr = Expr::add(
            Expr::xor(var(0), var(1)),
            Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
        );
        let synth: Expr = check(&obfuscated, Width::W8, 2);
        let clean: Expr = Expr::add(var(0), var(1));
        assert!(equivalent_exhaustive(&synth, &clean, Width::W8, 2));
        assert!(synth.node_count() <= obfuscated.node_count());
    }

    #[test]
    fn or_minus_and_recovers_xor() {
        let obfuscated: Expr = Expr::sub(Expr::or(var(0), var(1)), Expr::and(var(0), var(1)));
        let synth: Expr = check(&obfuscated, Width::W8, 2);
        let clean: Expr = Expr::xor(var(0), var(1));
        assert!(equivalent_exhaustive(&synth, &clean, Width::W8, 2));
    }
}
