#![doc = "Minimal-form synthesis for multi-variable bitwise functions with partial-mask constants."]
#![doc = ""]
#![doc = "A pure bitwise expression over variables `v0..v_{k-1}` acts strictly per bit: the"]
#![doc = "operators `~`, `&`, `|`, `^` and any mask constant never move data between bit"]
#![doc = "positions. So at width `W` the value is fully described by, for each output bit"]
#![doc = "position `i < W`, a boolean function `g_i(v0[i], .., v_{k-1}[i])` of the `k` input"]
#![doc = "bits at that position. A partial-mask bitwise function is one where different"]
#![doc = "positions compute different `g_i`; the mask constants name which positions do what."]
#![doc = ""]
#![doc = "This synthesizer reads out every position's `g_i` with `2^k` word evaluations, groups"]
#![doc = "positions by their boolean truth table, synthesizes a minimal bitwise expression per"]
#![doc = "distinct truth table by a breadth-first search over the `~`/`&`/`|`/`^` operator DAG,"]
#![doc = "and recombines them as `Σ_g (expr_g & positions_mask_g) | one_mask`. The masks are"]
#![doc = "pairwise disjoint by construction, so the OR is a partition, not an approximation."]
#![doc = "The result is width-independent, so the caller's non-circular oracle (exhaustive"]
#![doc = "bitvector at narrow widths, the bit-blast verifier at wide ones) can prove it before"]
#![doc = "it is emitted. This generalizes the single-variable universal partial-mask form to"]
#![doc = "`k` variables."]

use crate::expr::{BinOp, Expr, UnOp, Width};
use std::collections::BTreeMap;

pub const MAX_BITWISE_SYNTH_VARS: u32 = 4;

const BFS_TABLE_BUDGET: usize = 1usize << 14;

/// Recover a minimal partial-mask bitwise form of `expr` at `width`.
///
/// Returns `None` when `expr` is not a pure bitwise function, when it has more than
/// [`MAX_BITWISE_SYNTH_VARS`] variables, or when per-truth-table synthesis exceeds its
/// bounded search budget.
///
/// The candidate is a proposal only. Callers must prove equivalence with a non-circular
/// oracle before emitting it; nothing here trusts the synthesis on confidence alone.
#[must_use]
pub fn synthesize_bitwise_masked(expr: &Expr, width: Width, var_count: u32) -> Option<Expr> {
    if var_count == 0 || var_count > MAX_BITWISE_SYNTH_VARS || !is_pure_bitwise(expr) {
        return None;
    }
    let bits: usize = width.bits() as usize;
    let mask: u64 = width.mask();
    let rows: usize = 1usize << var_count;
    let full_table: u32 = table_all_ones(var_count);

    let words: Vec<u64> = evaluate_corner_words(expr, width, var_count, rows);
    let mut groups: BTreeMap<u32, u64> = BTreeMap::new();
    for position in 0..bits {
        let table: u32 = position_truth_table(&words, position, rows);
        *groups.entry(table).or_insert(0) |= 1u64 << position;
    }

    let mut cache: BTreeMap<u32, Option<Expr>> = BTreeMap::new();
    let mut one_mask: u64 = 0;
    let mut terms: Vec<Expr> = Vec::new();
    for (&table, &positions) in &groups {
        let group_mask: u64 = positions & mask;
        if group_mask == 0 || table == 0 {
            continue;
        }
        if table == full_table {
            one_mask |= group_mask;
            continue;
        }
        let body: Expr = synth_cached(&mut cache, table, var_count)?.clone();
        let masked: Expr = if group_mask == mask {
            body
        } else {
            Expr::and(body, Expr::konst(group_mask))
        };
        terms.push(masked);
    }

    Some(assemble(terms, one_mask, mask))
}

fn assemble(terms: Vec<Expr>, one_mask: u64, mask: u64) -> Expr {
    let mut iter: std::vec::IntoIter<Expr> = terms.into_iter();
    let Some(first): Option<Expr> = iter.next() else {
        return Expr::konst(one_mask & mask);
    };
    let mut acc: Expr = first;
    for term in iter {
        acc = Expr::or(acc, term);
    }
    if one_mask == 0 {
        acc
    } else {
        Expr::or(acc, Expr::konst(one_mask & mask))
    }
}

fn synth_cached(
    cache: &mut BTreeMap<u32, Option<Expr>>,
    table: u32,
    var_count: u32,
) -> Option<&Expr> {
    cache
        .entry(table)
        .or_insert_with(|| minimal_bitwise_for_table(table, var_count))
        .as_ref()
}

fn is_pure_bitwise(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_) | Expr::Var(_) => true,
        Expr::Unary(UnOp::Not, inner) => is_pure_bitwise(inner),
        Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, left, right) => {
            is_pure_bitwise(left) && is_pure_bitwise(right)
        }
        Expr::Unary(UnOp::Neg, _)
        | Expr::Binary(_, _, _)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => false,
    }
}

const fn table_all_ones(var_count: u32) -> u32 {
    let rows: u32 = 1u32 << var_count;
    if rows >= 32 {
        u32::MAX
    } else {
        (1u32 << rows) - 1
    }
}

fn evaluate_corner_words(expr: &Expr, width: Width, var_count: u32, rows: usize) -> Vec<u64> {
    let mask: u64 = width.mask();
    let mut env: Vec<u64> = vec![0; var_count as usize];
    let mut words: Vec<u64> = vec![0; rows];
    for (row, slot) in words.iter_mut().enumerate() {
        for (index, cell) in env.iter_mut().enumerate() {
            *cell = if (row >> index) & 1 == 1 { mask } else { 0 };
        }
        *slot = expr.eval(&env, width) & mask;
    }
    words
}

fn position_truth_table(words: &[u64], position: usize, rows: usize) -> u32 {
    let mut table: u32 = 0;
    for (row, word) in words.iter().enumerate().take(rows) {
        if (word >> position) & 1 == 1 {
            table |= 1u32 << row;
        }
    }
    table
}

fn minimal_bitwise_for_table(table: u32, var_count: u32) -> Option<Expr> {
    let rows: usize = 1usize << var_count;
    let atoms: Vec<(u32, Expr)> = atom_tables(var_count, rows);
    let mut best: BTreeMap<u32, Expr> = BTreeMap::new();
    let mut frontier: Vec<u32> = Vec::new();
    for (atom_table, atom_expr) in &atoms {
        if best.insert(*atom_table, atom_expr.clone()).is_none() {
            frontier.push(*atom_table);
        }
    }
    if let Some(found) = best.get(&table) {
        return Some(found.clone());
    }
    let row_mask: u32 = table_all_ones(var_count);
    while !frontier.is_empty() {
        if best.len() > BFS_TABLE_BUDGET {
            return None;
        }
        let mut next: Vec<u32> = Vec::new();
        let known: Vec<u32> = best.keys().copied().collect();
        for &left in &frontier {
            for &right in &known {
                for combined in combine(left, right, row_mask) {
                    if best.contains_key(&combined) {
                        continue;
                    }
                    let expr: Expr = build_combined(&best, left, right, combined, row_mask);
                    best.insert(combined, expr);
                    if combined == table {
                        return best.get(&table).cloned();
                    }
                    next.push(combined);
                    if best.len() > BFS_TABLE_BUDGET {
                        return None;
                    }
                }
            }
        }
        frontier = next;
    }
    None
}

const fn combine(left: u32, right: u32, row_mask: u32) -> [u32; 3] {
    [
        (left & right) & row_mask,
        (left | right) & row_mask,
        (left ^ right) & row_mask,
    ]
}

fn build_combined(
    best: &BTreeMap<u32, Expr>,
    left: u32,
    right: u32,
    combined: u32,
    row_mask: u32,
) -> Expr {
    let left_expr: &Expr = &best[&left];
    let right_expr: &Expr = &best[&right];
    if (left & right) & row_mask == combined {
        Expr::and(left_expr.clone(), right_expr.clone())
    } else if (left | right) & row_mask == combined {
        Expr::or(left_expr.clone(), right_expr.clone())
    } else {
        Expr::xor(left_expr.clone(), right_expr.clone())
    }
}

fn atom_tables(var_count: u32, rows: usize) -> Vec<(u32, Expr)> {
    let mut out: Vec<(u32, Expr)> = Vec::with_capacity(var_count as usize * 2);
    for index in 0..var_count {
        let mut table: u32 = 0;
        for row in 0..rows {
            if (row >> index) & 1 == 1 {
                table |= 1u32 << row;
            }
        }
        out.push((table, Expr::var(index)));
        let complement: u32 = (!table) & table_all_ones(var_count);
        out.push((complement, Expr::not(Expr::var(index))));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;

    fn v(index: u32) -> Expr {
        Expr::var(index)
    }

    fn assert_synth_equivalent(obfuscated: &Expr, width: Width, var_count: u32) -> Expr {
        let synth: Expr = synthesize_bitwise_masked(obfuscated, width, var_count)
            .expect("synthesizer produced no candidate");
        assert!(
            equivalent_exhaustive(obfuscated, &synth, width, var_count),
            "synthesized `{synth}` not equivalent to `{obfuscated}` at {width:?}"
        );
        synth
    }

    #[test]
    fn two_var_partial_mask_recovers_and_xor_blend() {
        let obfuscated: Expr = Expr::or(
            Expr::and(Expr::and(v(0), v(1)), Expr::konst(0xF0)),
            Expr::and(Expr::xor(v(0), v(1)), Expr::konst(0x0F)),
        );
        let synth: Expr = assert_synth_equivalent(&obfuscated, Width::W8, 2);
        assert!(synth.node_count() <= obfuscated.node_count());
    }

    #[test]
    fn pure_uniform_and_collapses_to_two_nodes() {
        let obfuscated: Expr = Expr::and(v(0), v(1));
        let synth: Expr = assert_synth_equivalent(&obfuscated, Width::W8, 2);
        assert_eq!(synth, Expr::and(v(0), v(1)));
    }

    #[test]
    fn three_var_majority_partial_mask_is_synthesized() {
        let majority: Expr = Expr::or(
            Expr::or(Expr::and(v(0), v(1)), Expr::and(v(0), v(2))),
            Expr::and(v(1), v(2)),
        );
        let obfuscated: Expr = Expr::or(
            Expr::and(majority, Expr::konst(0x0F)),
            Expr::and(Expr::xor(Expr::xor(v(0), v(1)), v(2)), Expr::konst(0xF0)),
        );
        let synth: Expr = assert_synth_equivalent(&obfuscated, Width::W8, 3);
        assert!(
            is_pure_bitwise(&synth),
            "synthesized form must stay bitwise"
        );
    }

    #[test]
    fn constant_one_mask_positions_become_or_constant() {
        let obfuscated: Expr = Expr::or(Expr::and(v(0), Expr::konst(0x0F)), Expr::konst(0xF0));
        let synth: Expr = assert_synth_equivalent(&obfuscated, Width::W8, 1);
        assert!(equivalent_exhaustive(
            &synth,
            &Expr::or(Expr::and(v(0), Expr::konst(0x0F)), Expr::konst(0xF0)),
            Width::W8,
            1
        ));
    }

    #[test]
    fn all_zero_function_is_constant_zero() {
        let obfuscated: Expr = Expr::and(v(0), Expr::konst(0));
        let synth: Expr = assert_synth_equivalent(&obfuscated, Width::W8, 1);
        assert_eq!(synth, Expr::konst(0));
    }

    #[test]
    fn rejects_arithmetic_expression() {
        let arithmetic: Expr = Expr::add(v(0), v(1));
        assert!(synthesize_bitwise_masked(&arithmetic, Width::W8, 2).is_none());
    }

    #[test]
    fn rejects_over_var_budget() {
        let mut wide: Expr = v(0);
        for index in 1..=MAX_BITWISE_SYNTH_VARS {
            wide = Expr::and(wide, v(index));
        }
        assert!(synthesize_bitwise_masked(&wide, Width::W8, MAX_BITWISE_SYNTH_VARS + 1).is_none());
    }

    #[test]
    fn synth_matches_at_every_narrow_width() {
        let obfuscated: Expr = Expr::or(
            Expr::and(Expr::or(v(0), v(1)), Expr::konst(0x33)),
            Expr::and(Expr::not(Expr::xor(v(0), v(1))), Expr::konst(0xCC)),
        );
        for width in [Width::W8, Width::W16] {
            let synth: Expr = synthesize_bitwise_masked(&obfuscated, width, 2).expect("candidate");
            for narrow in [Width::W4, Width::W8] {
                assert!(
                    equivalent_exhaustive(&obfuscated, &synth, narrow, 2),
                    "width={width:?} synth `{synth}` diverges at {narrow:?}"
                );
            }
        }
    }
}
