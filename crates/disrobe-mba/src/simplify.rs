use crate::bitwise_synth::{MAX_BITWISE_SYNTH_VARS, synthesize_bitwise_masked};
#[cfg(any(feature = "smt-verify", test))]
use crate::boolean::{Implicant, MAX_BOOLEAN_ATOMS, minimize_sop};
use crate::expr::{
    BinOp, Expr, UnOp, Width, equivalent_exhaustive, equivalent_exhaustive_runnable,
};
use crate::linear_mba::synthesize_linear_basis;
use crate::linear_solver::{
    MAX_SOLVER_VARS, columns_equal_mod_width, is_column_faithful, solve_linear_mba, truth_column,
};
#[cfg(feature = "smt-verify")]
use crate::opaque::CmpOp;
use crate::opaque::Predicate;
use crate::rewrite::canonicalize;
#[cfg(feature = "smt-verify")]
use crate::rewrite::order_key;
#[cfg(feature = "smt-verify")]
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Unverified,
    ExhaustiveAtWidth(Width),
    LinearColumnIdentity(Width),
    PolynomialIdentity(Width),
    #[cfg(feature = "smt-verify")]
    SmtProvenAtWidth(Width),
}

impl Verification {
    #[must_use]
    pub const fn is_proven(self) -> bool {
        match self {
            Self::Unverified => false,
            Self::ExhaustiveAtWidth(_)
            | Self::LinearColumnIdentity(_)
            | Self::PolynomialIdentity(_) => true,
            #[cfg(feature = "smt-verify")]
            Self::SmtProvenAtWidth(_) => true,
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateSimplification {
    pub original: Predicate,
    pub simplified: Predicate,
    pub width: Width,
    pub verification: Verification,
}

impl PredicateSimplification {
    #[must_use]
    pub fn changed(&self) -> bool {
        self.simplified != self.original
    }
}

const MAX_LINEAR_VARS: u32 = 4;
const MAX_BASIS_VARS: u32 = 3;
const MAX_TEMPLATE_VARS: u32 = 2;
const VERIFY_BUDGET_LOG2: u32 = 22;

#[derive(Debug)]
struct DenseExpression {
    expr: Expr,
    to_dense: BTreeMap<u32, u32>,
    to_original: BTreeMap<u32, u32>,
    var_count: u32,
    indices_changed: bool,
}

impl DenseExpression {
    fn restore(&self, candidate: &Expr) -> Option<Expr> {
        if candidate
            .vars()
            .iter()
            .any(|index: &u32| !self.to_original.contains_key(index))
        {
            return None;
        }
        let restored: Expr = candidate.remap_vars(&self.to_original);
        (restored.remap_vars(&self.to_dense) == *candidate).then_some(restored)
    }
}

#[must_use]
pub fn simplify(expr: &Expr, width: Width) -> Simplification {
    if expr.depth() > crate::expr::MAX_MBA_DEPTH {
        return unchanged_simplification(expr, width);
    }
    let original_nodes: usize = expr.node_count();
    let Some(dense): Option<DenseExpression> = compact_expression(expr) else {
        return unchanged_simplification(expr, width);
    };
    let (candidate, verification): (Expr, Verification) =
        simplify_dense(&dense.expr, width, dense.var_count);
    if candidate == dense.expr || !verification.is_proven() {
        return unchanged_simplification(expr, width);
    }
    let Some(restored): Option<Expr> = dense.restore(&candidate) else {
        return unchanged_simplification(expr, width);
    };
    let simplified: Expr = if dense.indices_changed {
        let Some(accepted): Option<Expr> = accept_expression_candidate(expr, restored, width)
        else {
            return unchanged_simplification(expr, width);
        };
        accepted
    } else {
        restored
    };
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

fn unchanged_simplification(expr: &Expr, width: Width) -> Simplification {
    let nodes: usize = expr.node_count();
    Simplification {
        original: expr.clone(),
        simplified: expr.clone(),
        width,
        verification: Verification::Unverified,
        original_nodes: nodes,
        simplified_nodes: nodes,
    }
}

fn compact_expression(expr: &Expr) -> Option<DenseExpression> {
    let variables: BTreeSet<u32> = expr.vars();
    let Ok(var_count): Result<u32, _> = u32::try_from(variables.len()) else {
        return None;
    };
    let mut to_dense: BTreeMap<u32, u32> = BTreeMap::new();
    let mut to_original: BTreeMap<u32, u32> = BTreeMap::new();
    let mut indices_changed: bool = false;
    for (index, original) in variables.into_iter().enumerate() {
        let Ok(index): Result<u32, _> = u32::try_from(index) else {
            return None;
        };
        indices_changed |= index != original;
        to_dense.insert(original, index);
        to_original.insert(index, original);
    }
    Some(DenseExpression {
        expr: expr.remap_vars(&to_dense),
        to_dense,
        to_original,
        var_count,
        indices_changed,
    })
}

fn simplify_dense(expr: &Expr, width: Width, var_count: u32) -> (Expr, Verification) {
    let mut best: (Expr, Verification) = simplify_l0_l5(expr, width, var_count);
    if best.0 == *expr
        && expr_is_eval_faithful(expr)
        && let Some((candidate, proof)) = crate::enum_synth::synthesize(expr, width, var_count)
    {
        best = (candidate, proof);
    }
    best
}

pub(crate) fn simplify_l0_l5(expr: &Expr, width: Width, var_count: u32) -> (Expr, Verification) {
    let original_nodes: usize = expr.node_count();
    let original_is_mba: bool = expr.is_linear_mba();

    let mut best: (Expr, Verification) = (expr.clone(), Verification::Unverified);
    let mut consider = |candidate: Expr| {
        if candidate.node_count() >= original_nodes {
            return;
        }
        if candidate.node_count() >= best.0.node_count() {
            return;
        }
        let proof: Verification =
            verify_equivalent(expr, &candidate, width, var_count, original_is_mba);
        if proof.is_proven() {
            best = (candidate, proof);
        }
    };

    let folded: Expr = canonicalize(expr, width);
    if folded != *expr {
        consider(folded);
    }

    #[cfg(feature = "smt-verify")]
    {
        let minimized: Option<Expr> = minimize_boolean_verified(expr, width);
        if let Some(minimized) = minimized {
            consider(minimized);
        }
    }

    if var_count <= MAX_TEMPLATE_VARS {
        for candidate in template_candidates(var_count) {
            consider(candidate);
        }
    }
    if var_count <= MAX_LINEAR_VARS
        && original_is_mba
        && let Some(synth) = synthesize_linear(expr, width, var_count)
    {
        consider(synth);
    }
    if (2..=MAX_BASIS_VARS).contains(&var_count)
        && original_is_mba
        && let Some(synth) = synthesize_linear_basis(expr, width, var_count)
    {
        consider(synth);
    }
    if (1..=MAX_SOLVER_VARS).contains(&var_count)
        && let Some(solved) = solve_linear_mba(expr, width, var_count)
    {
        consider(solved);
    }
    if var_count == 1 && is_bitwise(expr) {
        consider(synthesize_bitwise_unary(expr, width));
    }
    if (2..=MAX_BITWISE_SYNTH_VARS).contains(&var_count)
        && let Some(synth) = synthesize_bitwise_masked(expr, width, var_count)
    {
        consider(synth);
    }
    if !original_is_mba
        && (1..=crate::poly_mba::MAX_POLY_MBA_VARS).contains(&var_count)
        && let Some(reduced) = crate::poly_mba::solve_polynomial_mba(expr, width, var_count)
    {
        consider(reduced);
    }
    if !original_is_mba
        && (1..=crate::mixed_mba::MAX_MIXED_MBA_VARS).contains(&var_count)
        && let Some(mixed) = crate::mixed_mba::simplify_mixed(expr, width)
    {
        consider(mixed);
    }

    if let Some(saturated) = crate::egraph::saturate_simplify(expr, width)
        && saturated.node_count() < best.0.node_count()
        && let Some(proof) = accept_verified(expr, &saturated, width, var_count)
    {
        best = (saturated, proof);
    }

    best
}

pub(crate) fn expr_is_eval_faithful(expr: &Expr) -> bool {
    match expr {
        Expr::Mem(_, _) => false,
        Expr::Const(_) | Expr::Var(_) => true,
        Expr::Unary(_, inner) | Expr::Slice(inner, _, _) => expr_is_eval_faithful(inner),
        Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => {
            expr_is_eval_faithful(left) && expr_is_eval_faithful(right)
        }
        Expr::Ite(cond, then, otherwise) => {
            expr_is_eval_faithful(cond)
                && expr_is_eval_faithful(then)
                && expr_is_eval_faithful(otherwise)
        }
    }
}

#[cfg(feature = "smt-verify")]
pub(crate) fn accept_verified(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: u32,
) -> Option<Verification> {
    if candidate.node_count() >= original.node_count() {
        return None;
    }
    let faithful: bool = expr_is_eval_faithful(original) && expr_is_eval_faithful(candidate);
    let bdd: crate::verify::Equivalence =
        crate::verify::verify_equivalent(original, candidate, width);
    if faithful && width.is_exhaustible() && equivalent_exhaustive_runnable(width, var_count) {
        let exhaustive: bool = equivalent_exhaustive(original, candidate, width, var_count);
        if exhaustive != bdd.is_proven() {
            return None;
        }
        return exhaustive.then_some(Verification::ExhaustiveAtWidth(width));
    }
    if bdd.is_disproven() {
        return None;
    }
    if bdd.is_proven() {
        return Some(Verification::SmtProvenAtWidth(width));
    }
    crate::poly_oracle::polynomial_identity_proves(original, candidate, width)
        .then_some(Verification::PolynomialIdentity(width))
}

#[cfg(not(feature = "smt-verify"))]
pub(crate) fn accept_verified(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: u32,
) -> Option<Verification> {
    if candidate.node_count() >= original.node_count() {
        return None;
    }
    let faithful: bool = expr_is_eval_faithful(original) && expr_is_eval_faithful(candidate);
    let exhaustive: Option<bool> =
        (faithful && width.is_exhaustible() && equivalent_exhaustive_runnable(width, var_count))
            .then(|| equivalent_exhaustive(original, candidate, width, var_count));
    if exhaustive == Some(false) {
        return None;
    }
    if exhaustive == Some(true) {
        return Some(Verification::ExhaustiveAtWidth(width));
    }
    crate::poly_oracle::polynomial_identity_proves(original, candidate, width)
        .then_some(Verification::PolynomialIdentity(width))
}

#[must_use]
pub fn simplify_predicate(predicate: &Predicate, width: Width) -> PredicateSimplification {
    if predicate.depth() > crate::expr::MAX_MBA_DEPTH {
        return PredicateSimplification {
            original: predicate.clone(),
            simplified: predicate.clone(),
            width,
            verification: Verification::Unverified,
        };
    }
    #[cfg(not(feature = "smt-verify"))]
    {
        PredicateSimplification {
            original: predicate.clone(),
            simplified: predicate.clone(),
            width,
            verification: Verification::Unverified,
        }
    }
    #[cfg(feature = "smt-verify")]
    {
        let canonical: Predicate = canonicalize_predicate_candidate(predicate, width);
        let minimized: Predicate = match predicate_minimization_candidate(&canonical, width) {
            Some(candidate) if candidate.node_count() < canonical.node_count() => candidate,
            _ => canonical,
        };
        if minimized == *predicate {
            return PredicateSimplification {
                original: predicate.clone(),
                simplified: predicate.clone(),
                width,
                verification: Verification::Unverified,
            };
        }
        if let Some(minimized) = accept_predicate_candidate(predicate, minimized, width) {
            return PredicateSimplification {
                original: predicate.clone(),
                simplified: minimized,
                width,
                verification: Verification::SmtProvenAtWidth(width),
            };
        }
        PredicateSimplification {
            original: predicate.clone(),
            simplified: predicate.clone(),
            width,
            verification: Verification::Unverified,
        }
    }
}

#[cfg(feature = "smt-verify")]
fn accept_predicate_candidate(
    original: &Predicate,
    candidate: Predicate,
    width: Width,
) -> Option<Predicate> {
    if crate::verify::verify_equivalent(original, &candidate, width).is_proven() {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(feature = "smt-verify")]
#[must_use]
pub(crate) fn minimize_boolean_verified(expr: &Expr, width: Width) -> Option<Expr> {
    let candidate: Expr = boolean_minimization_candidate(expr, width)?;
    if candidate.node_count() >= expr.node_count() {
        return None;
    }
    accept_expression_candidate(expr, candidate, width)
}

#[cfg(feature = "smt-verify")]
fn accept_expression_candidate(original: &Expr, candidate: Expr, width: Width) -> Option<Expr> {
    if crate::verify::verify_equivalent(original, &candidate, width).is_proven() {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(not(feature = "smt-verify"))]
fn accept_expression_candidate(_original: &Expr, _candidate: Expr, _width: Width) -> Option<Expr> {
    None
}

#[cfg(any(feature = "smt-verify", test))]
fn boolean_minimization_candidate(expr: &Expr, width: Width) -> Option<Expr> {
    if !contains_boolean_operator(expr) {
        return None;
    }
    let mut atoms: Vec<Expr> = Vec::new();
    collect_boolean_atoms(expr, &mut atoms)?;
    if atoms.is_empty() || atoms.len() > MAX_BOOLEAN_ATOMS {
        return None;
    }
    let Ok(shift): Result<u32, _> = u32::try_from(atoms.len()) else {
        return None;
    };
    let rows: usize = 1usize.checked_shl(shift)?;
    let mut values: Vec<bool> = Vec::with_capacity(rows);
    for row in 0..rows {
        values.push(boolean_row(expr, &atoms, row)?);
    }
    let implicants: Vec<Implicant> = minimize_sop(&values, atoms.len())?;
    build_boolean_sop(&implicants, &atoms, width)
}

#[cfg(any(feature = "smt-verify", test))]
const fn contains_boolean_operator(expr: &Expr) -> bool {
    match expr {
        Expr::Unary(UnOp::Not, _) | Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, _, _) => true,
        Expr::Const(_)
        | Expr::Var(_)
        | Expr::Unary(UnOp::Neg, _)
        | Expr::Binary(BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Shl | BinOp::Shr, _, _)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => false,
    }
}

#[cfg(any(feature = "smt-verify", test))]
fn collect_boolean_atoms(expr: &Expr, atoms: &mut Vec<Expr>) -> Option<()> {
    match expr {
        Expr::Unary(UnOp::Not, inner) => collect_boolean_atoms(inner, atoms),
        Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, left, right) => {
            collect_boolean_atoms(left, atoms)?;
            collect_boolean_atoms(right, atoms)
        }
        _ => {
            if atoms.iter().all(|atom: &Expr| atom != expr) {
                if atoms.len() == MAX_BOOLEAN_ATOMS {
                    return None;
                }
                atoms.push(expr.clone());
            }
            Some(())
        }
    }
}

#[cfg(any(feature = "smt-verify", test))]
fn boolean_row(expr: &Expr, atoms: &[Expr], row: usize) -> Option<bool> {
    match expr {
        Expr::Unary(UnOp::Not, inner) => Some(!boolean_row(inner, atoms, row)?),
        Expr::Binary(BinOp::And, left, right) => {
            Some(boolean_row(left, atoms, row)? && boolean_row(right, atoms, row)?)
        }
        Expr::Binary(BinOp::Or, left, right) => {
            Some(boolean_row(left, atoms, row)? || boolean_row(right, atoms, row)?)
        }
        Expr::Binary(BinOp::Xor, left, right) => {
            Some(boolean_row(left, atoms, row)? ^ boolean_row(right, atoms, row)?)
        }
        _ => {
            let index: usize = atoms.iter().position(|atom: &Expr| atom == expr)?;
            Some((row >> index) & 1 == 1)
        }
    }
}

#[cfg(any(feature = "smt-verify", test))]
fn build_boolean_sop(implicants: &[Implicant], atoms: &[Expr], width: Width) -> Option<Expr> {
    if implicants.is_empty() {
        return Some(Expr::konst(0));
    }
    let mut terms: Vec<Expr> = Vec::with_capacity(implicants.len());
    for implicant in implicants {
        terms.push(build_boolean_term(*implicant, atoms, width)?);
    }
    join_boolean_terms(terms, BinOp::Or)
}

#[cfg(any(feature = "smt-verify", test))]
fn build_boolean_term(implicant: Implicant, atoms: &[Expr], width: Width) -> Option<Expr> {
    if implicant.care == 0 {
        return Some(Expr::konst(width.mask()));
    }
    let mut factors: Vec<Expr> = Vec::with_capacity(atoms.len());
    for (index, atom) in atoms.iter().enumerate() {
        let Ok(shift): Result<u32, _> = u32::try_from(index) else {
            return None;
        };
        let bit: u16 = 1u16.checked_shl(shift)?;
        if implicant.care & bit == 0 {
            continue;
        }
        let factor: Expr = if implicant.bits & bit == 0 {
            Expr::not(atom.clone())
        } else {
            atom.clone()
        };
        factors.push(factor);
    }
    join_boolean_terms(factors, BinOp::And)
}

#[cfg(any(feature = "smt-verify", test))]
fn join_boolean_terms(terms: Vec<Expr>, op: BinOp) -> Option<Expr> {
    let mut iterator: std::vec::IntoIter<Expr> = terms.into_iter();
    let first: Expr = iterator.next()?;
    let mut combined: Expr = first;
    for term in iterator {
        combined = Expr::Binary(op, Box::new(combined), Box::new(term));
    }
    Some(combined)
}

#[cfg(feature = "smt-verify")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PredicateConnective {
    Or,
    And,
}

#[cfg(feature = "smt-verify")]
fn canonicalize_predicate_candidate(predicate: &Predicate, width: Width) -> Predicate {
    match predicate {
        Predicate::Compare { op, left, right } => {
            canonicalize_predicate_comparison(*op, left.clone(), right.clone(), width)
        }
        Predicate::Nonzero(inner) => {
            canonicalize_predicate_comparison(CmpOp::Ne, inner.clone(), Expr::konst(0), width)
        }
        Predicate::Or(_, _) => {
            canonicalize_predicate_chain(predicate, PredicateConnective::Or, width)
        }
        Predicate::And(_, _) => {
            canonicalize_predicate_chain(predicate, PredicateConnective::And, width)
        }
    }
}

#[cfg(feature = "smt-verify")]
fn canonicalize_predicate_chain(
    predicate: &Predicate,
    connective: PredicateConnective,
    width: Width,
) -> Predicate {
    let mut terms: Vec<Predicate> = Vec::new();
    collect_canonical_predicate_terms(predicate, connective, width, &mut terms);
    terms.sort_by(compare_predicates);
    let Some(combined): Option<Predicate> = join_predicate_terms(terms, connective) else {
        return predicate.clone();
    };
    combined
}

#[cfg(feature = "smt-verify")]
fn collect_canonical_predicate_terms(
    predicate: &Predicate,
    connective: PredicateConnective,
    width: Width,
    terms: &mut Vec<Predicate>,
) {
    match (connective, predicate) {
        (PredicateConnective::Or, Predicate::Or(left, right))
        | (PredicateConnective::And, Predicate::And(left, right)) => {
            collect_canonical_predicate_terms(left, connective, width, terms);
            collect_canonical_predicate_terms(right, connective, width, terms);
        }
        _ => {
            let canonical: Predicate = canonicalize_predicate_candidate(predicate, width);
            terms.push(canonical);
        }
    }
}

#[cfg(feature = "smt-verify")]
fn canonicalize_predicate_comparison(
    op: CmpOp,
    left: Expr,
    right: Expr,
    width: Width,
) -> Predicate {
    let mut left: Expr = canonicalize(&left, width);
    let mut right: Expr = canonicalize(&right, width);
    let op: CmpOp = match op {
        CmpOp::UnsignedGt => {
            std::mem::swap(&mut left, &mut right);
            CmpOp::UnsignedLt
        }
        CmpOp::SignedGt => {
            std::mem::swap(&mut left, &mut right);
            CmpOp::SignedLt
        }
        CmpOp::UnsignedLe => {
            std::mem::swap(&mut left, &mut right);
            CmpOp::UnsignedGe
        }
        CmpOp::SignedLe => {
            std::mem::swap(&mut left, &mut right);
            CmpOp::SignedGe
        }
        other => other,
    };
    if matches!(op, CmpOp::Eq | CmpOp::Ne) && order_key(&right) < order_key(&left) {
        std::mem::swap(&mut left, &mut right);
    }
    Predicate::Compare { op, left, right }
}

#[cfg(feature = "smt-verify")]
const fn predicate_rank(predicate: &Predicate) -> u8 {
    match predicate {
        Predicate::Compare { .. } => 0,
        Predicate::Nonzero(_) => 1,
        Predicate::Or(_, _) => 2,
        Predicate::And(_, _) => 3,
    }
}

#[cfg(feature = "smt-verify")]
fn compare_predicates(left: &Predicate, right: &Predicate) -> Ordering {
    let rank_order: Ordering = predicate_rank(left).cmp(&predicate_rank(right));
    if rank_order != Ordering::Equal {
        return rank_order;
    }
    match (left, right) {
        (
            Predicate::Compare {
                op: left_op,
                left: left_left,
                right: left_right,
            },
            Predicate::Compare {
                op: right_op,
                left: right_left,
                right: right_right,
            },
        ) => {
            let op_order: Ordering = left_op.cmp(right_op);
            if op_order != Ordering::Equal {
                return op_order;
            }
            let left_order: Ordering = order_key(left_left).cmp(&order_key(right_left));
            if left_order != Ordering::Equal {
                return left_order;
            }
            order_key(left_right).cmp(&order_key(right_right))
        }
        (Predicate::Nonzero(left), Predicate::Nonzero(right)) => {
            order_key(left).cmp(&order_key(right))
        }
        (Predicate::Or(left_left, left_right), Predicate::Or(right_left, right_right))
        | (Predicate::And(left_left, left_right), Predicate::And(right_left, right_right)) => {
            let left_order: Ordering = compare_predicates(left_left, right_left);
            if left_order != Ordering::Equal {
                return left_order;
            }
            compare_predicates(left_right, right_right)
        }
        _ => Ordering::Equal,
    }
}

#[cfg(feature = "smt-verify")]
fn predicate_minimization_candidate(predicate: &Predicate, width: Width) -> Option<Predicate> {
    if !contains_predicate_boolean_operator(predicate) {
        return None;
    }
    let mut atoms: Vec<Predicate> = Vec::new();
    collect_predicate_atoms(predicate, &mut atoms)?;
    if atoms.is_empty() || atoms.len() > MAX_BOOLEAN_ATOMS {
        return None;
    }
    let Ok(shift): Result<u32, _> = u32::try_from(atoms.len()) else {
        return None;
    };
    let rows: usize = 1usize.checked_shl(shift)?;
    let mut values: Vec<bool> = Vec::with_capacity(rows);
    for row in 0..rows {
        values.push(predicate_boolean_row(predicate, &atoms, row)?);
    }
    let implicants: Vec<Implicant> = minimize_sop(&values, atoms.len())?;
    let candidate: Predicate = build_predicate_sop(&implicants, &atoms)?;
    Some(canonicalize_predicate_candidate(&candidate, width))
}

#[cfg(feature = "smt-verify")]
const fn contains_predicate_boolean_operator(predicate: &Predicate) -> bool {
    matches!(predicate, Predicate::Or(_, _) | Predicate::And(_, _))
}

#[cfg(feature = "smt-verify")]
fn collect_predicate_atoms(predicate: &Predicate, atoms: &mut Vec<Predicate>) -> Option<()> {
    match predicate {
        Predicate::Or(left, right) | Predicate::And(left, right) => {
            collect_predicate_atoms(left, atoms)?;
            collect_predicate_atoms(right, atoms)
        }
        Predicate::Compare { .. } | Predicate::Nonzero(_) => {
            let (atom, _positive): (Predicate, bool) = predicate_atom_parts(predicate)?;
            if atoms.iter().all(|known: &Predicate| known != &atom) {
                if atoms.len() == MAX_BOOLEAN_ATOMS {
                    return None;
                }
                atoms.push(atom);
            }
            Some(())
        }
    }
}

#[cfg(feature = "smt-verify")]
fn predicate_boolean_row(predicate: &Predicate, atoms: &[Predicate], row: usize) -> Option<bool> {
    match predicate {
        Predicate::Or(left, right) => Some(
            predicate_boolean_row(left, atoms, row)? || predicate_boolean_row(right, atoms, row)?,
        ),
        Predicate::And(left, right) => Some(
            predicate_boolean_row(left, atoms, row)? && predicate_boolean_row(right, atoms, row)?,
        ),
        Predicate::Compare { .. } | Predicate::Nonzero(_) => {
            let (atom, positive): (Predicate, bool) = predicate_atom_parts(predicate)?;
            let index: usize = atoms.iter().position(|known: &Predicate| known == &atom)?;
            let value: bool = (row >> index) & 1 == 1;
            Some(if positive { value } else { !value })
        }
    }
}

#[cfg(feature = "smt-verify")]
fn predicate_atom_parts(predicate: &Predicate) -> Option<(Predicate, bool)> {
    let Predicate::Compare { op, left, right } = predicate else {
        return None;
    };
    let (base, positive): (CmpOp, bool) = match op {
        CmpOp::Eq => (CmpOp::Eq, true),
        CmpOp::Ne => (CmpOp::Eq, false),
        CmpOp::UnsignedLt => (CmpOp::UnsignedLt, true),
        CmpOp::UnsignedGe => (CmpOp::UnsignedLt, false),
        CmpOp::SignedLt => (CmpOp::SignedLt, true),
        CmpOp::SignedGe => (CmpOp::SignedLt, false),
        CmpOp::UnsignedLe | CmpOp::UnsignedGt | CmpOp::SignedLe | CmpOp::SignedGt => return None,
    };
    Some((
        Predicate::Compare {
            op: base,
            left: left.clone(),
            right: right.clone(),
        },
        positive,
    ))
}

#[cfg(feature = "smt-verify")]
fn build_predicate_sop(implicants: &[Implicant], atoms: &[Predicate]) -> Option<Predicate> {
    if implicants.is_empty() {
        return Some(predicate_constant(false));
    }
    let mut terms: Vec<Predicate> = Vec::with_capacity(implicants.len());
    for implicant in implicants {
        terms.push(build_predicate_term(*implicant, atoms)?);
    }
    join_predicate_terms(terms, PredicateConnective::Or)
}

#[cfg(feature = "smt-verify")]
fn build_predicate_term(implicant: Implicant, atoms: &[Predicate]) -> Option<Predicate> {
    if implicant.care == 0 {
        return Some(predicate_constant(true));
    }
    let mut factors: Vec<Predicate> = Vec::with_capacity(atoms.len());
    for (index, atom) in atoms.iter().enumerate() {
        let Ok(shift): Result<u32, _> = u32::try_from(index) else {
            return None;
        };
        let bit: u16 = 1u16.checked_shl(shift)?;
        if implicant.care & bit == 0 {
            continue;
        }
        let positive: bool = implicant.bits & bit != 0;
        factors.push(predicate_literal(atom, positive)?);
    }
    join_predicate_terms(factors, PredicateConnective::And)
}

#[cfg(feature = "smt-verify")]
fn predicate_literal(atom: &Predicate, positive: bool) -> Option<Predicate> {
    let Predicate::Compare { op, left, right } = atom else {
        return None;
    };
    let op: CmpOp = match (*op, positive) {
        (CmpOp::Eq, true) => CmpOp::Eq,
        (CmpOp::Eq, false) => CmpOp::Ne,
        (CmpOp::UnsignedLt, true) => CmpOp::UnsignedLt,
        (CmpOp::UnsignedLt, false) => CmpOp::UnsignedGe,
        (CmpOp::SignedLt, true) => CmpOp::SignedLt,
        (CmpOp::SignedLt, false) => CmpOp::SignedGe,
        _ => return None,
    };
    Some(Predicate::Compare {
        op,
        left: left.clone(),
        right: right.clone(),
    })
}

#[cfg(feature = "smt-verify")]
fn join_predicate_terms(
    terms: Vec<Predicate>,
    connective: PredicateConnective,
) -> Option<Predicate> {
    let mut iterator: std::vec::IntoIter<Predicate> = terms.into_iter();
    let first: Predicate = iterator.next()?;
    let mut combined: Predicate = first;
    for term in iterator {
        combined = match connective {
            PredicateConnective::Or => Predicate::or(combined, term),
            PredicateConnective::And => Predicate::and(combined, term),
        };
    }
    Some(combined)
}

#[cfg(feature = "smt-verify")]
const fn predicate_constant(value: bool) -> Predicate {
    let right: u64 = (!value) as u64;
    Predicate::eq(Expr::konst(0), Expr::konst(right))
}

fn verify_equivalent(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: u32,
    original_is_mba: bool,
) -> Verification {
    let budget_width: Width = largest_verifiable_width(var_count);
    let enumerable: bool = expr_is_eval_faithful(original)
        && expr_is_eval_faithful(candidate)
        && width.is_exhaustible()
        && width.bits() <= budget_width.bits();
    if enumerable {
        if equivalent_exhaustive(original, candidate, width, var_count) {
            return Verification::ExhaustiveAtWidth(width);
        }
        return Verification::Unverified;
    }
    if original_is_mba
        && candidate.is_linear_mba()
        && (1..=MAX_SOLVER_VARS).contains(&var_count)
        && column_identity_proves(original, candidate, width, var_count)
    {
        return Verification::LinearColumnIdentity(width);
    }
    #[cfg(feature = "smt-verify")]
    if crate::verify::verify_equivalent(original, candidate, width).is_proven() {
        return Verification::SmtProvenAtWidth(width);
    }
    if crate::poly_oracle::polynomial_identity_proves(original, candidate, width) {
        return Verification::PolynomialIdentity(width);
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
    fn the_gate_refuses_a_seeded_wrong_rewrite_at_every_width() {
        let original: Expr = xor_and_basis(0, 1);
        let correct: Expr = Expr::add(Expr::var(0), Expr::var(1));
        let corrupted: Expr = Expr::xor(Expr::var(0), Expr::var(1));
        let original_is_mba: bool = original.is_linear_mba();
        assert!(corrupted.node_count() < original.node_count());
        for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
            assert_eq!(
                verify_equivalent(&original, &corrupted, width, 2, original_is_mba),
                Verification::Unverified,
                "{width:?}: a smaller but non-equivalent rewrite was accepted"
            );
            assert!(
                verify_equivalent(&original, &correct, width, 2, original_is_mba).is_proven(),
                "{width:?}: the same gate cannot establish the correct rewrite, so the refusal above proves nothing"
            );
            let result: Simplification = simplify(&original, width);
            assert_ne!(
                result.simplified, corrupted,
                "{width:?}: the pipeline emitted the non-equivalent rewrite"
            );
            assert!(
                result.verification.is_proven(),
                "{width:?}: a changed result carries no independently established proof"
            );
        }
        for (scaled, vanishing_width) in reduced_width_vanishing_shapes() {
            let zero: Expr = Expr::konst(0);
            let scaled_is_mba: bool = scaled.is_linear_mba();
            let var_count: u32 = u32::try_from(scaled.vars().len()).expect("small var count");
            assert!(
                equivalent_exhaustive(&scaled, &zero, vanishing_width, var_count),
                "`{scaled}` must vanish at {vanishing_width:?} or it does not exercise the reduced-width route"
            );
            for width in [Width::W32, Width::W64] {
                assert_eq!(
                    verify_equivalent(&scaled, &zero, width, var_count, scaled_is_mba),
                    Verification::Unverified,
                    "{width:?}: `{scaled}` was accepted as zero on the strength of a narrower width"
                );
                let result: Simplification = simplify(&scaled, width);
                assert_ne!(
                    result.simplified, zero,
                    "{width:?}: the pipeline collapsed `{scaled}` to zero"
                );
            }
        }
        for shape in fallback_prone_shapes() {
            for width in [Width::W32, Width::W64] {
                let result: Simplification = simplify(&shape, width);
                if !result.changed() {
                    continue;
                }
                let rederived: Verification =
                    verify_equivalent(&shape, &result.simplified, width, 2, shape.is_linear_mba());
                assert!(
                    rederived.is_proven(),
                    "{width:?}: `{shape}` was rewritten to `{}` and tagged {:?}, but no independent checker reproduces that proof",
                    result.simplified,
                    result.verification
                );
            }
        }
    }

    fn reduced_width_vanishing_shapes() -> Vec<(Expr, Width)> {
        vec![
            (
                Expr::mul(Expr::konst(256), Expr::xor(Expr::var(0), Expr::var(1))),
                Width::W8,
            ),
            (
                Expr::mul(Expr::konst(256), Expr::and(Expr::var(0), Expr::var(1))),
                Width::W8,
            ),
            (
                Expr::shl(Expr::xor(Expr::var(0), Expr::var(1)), Expr::konst(8)),
                Width::W8,
            ),
            (
                Expr::mul(Expr::konst(0x1_0000), Expr::xor(Expr::var(0), Expr::var(1))),
                Width::W8,
            ),
            (Expr::mul(Expr::konst(0x1_0000), Expr::var(0)), Width::W16),
        ]
    }

    fn fallback_prone_shapes() -> Vec<Expr> {
        vec![
            Expr::ite(
                Expr::and(Expr::var(0), Expr::konst(1)),
                Expr::add(Expr::var(1), Expr::konst(0)),
                Expr::var(1),
            ),
            Expr::add(Expr::neg(Expr::not(Expr::var(0))), Expr::konst(0)),
            Expr::xor(
                Expr::xor(Expr::var(0), Expr::konst(0xFF)),
                Expr::konst(0xFF),
            ),
            Expr::or(Expr::var(0), Expr::and(Expr::var(0), Expr::var(1))),
        ]
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
    fn two_complement_identity_is_settled_at_the_real_width() {
        let obfuscated: Expr = Expr::sub(Expr::neg(Expr::var(0)), Expr::konst(1));
        let result: Simplification = simplify(&obfuscated, Width::W64);
        assert!(result.changed());
        #[cfg(feature = "smt-verify")]
        assert_eq!(
            result.verification,
            Verification::SmtProvenAtWidth(Width::W64)
        );
        #[cfg(not(feature = "smt-verify"))]
        assert_eq!(
            result.verification,
            Verification::PolynomialIdentity(Width::W64)
        );
        assert_eq!(result.simplified, Expr::not(Expr::var(0)));
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
        assert_eq!(
            result.verification,
            Verification::PolynomialIdentity(Width::W64)
        );
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
        assert_eq!(
            result.verification,
            Verification::PolynomialIdentity(Width::W64)
        );
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

    #[test]
    fn quine_mccluskey_candidate_reduces_consensus() {
        let input: Expr = Expr::or(
            Expr::or(
                Expr::and(Expr::var(0), Expr::var(1)),
                Expr::and(Expr::not(Expr::var(0)), Expr::var(2)),
            ),
            Expr::and(Expr::var(1), Expr::var(2)),
        );
        let expected: Expr = Expr::or(
            Expr::and(Expr::var(0), Expr::var(1)),
            Expr::and(Expr::not(Expr::var(0)), Expr::var(2)),
        );
        let Some(candidate): Option<Expr> = boolean_minimization_candidate(&input, Width::W32)
        else {
            panic!("expected a boolean minimization candidate");
        };
        assert_eq!(candidate, expected);
    }

    #[cfg(feature = "smt-verify")]
    #[test]
    fn boolean_acceptance_rejects_disproven_candidate() {
        let input: Expr = Expr::and(Expr::var(0), Expr::var(1));
        let incorrect: Expr = Expr::var(0);
        assert!(crate::verify::verify_equivalent(&input, &incorrect, Width::W32).is_disproven());
        assert_eq!(
            accept_expression_candidate(&input, incorrect, Width::W32),
            None
        );
    }

    #[cfg(feature = "smt-verify")]
    #[test]
    fn expression_acceptance_rejects_wrong_sparse_restore() {
        let input: Expr = xor_and_basis(7, 19);
        let incorrect: Expr = Expr::sub(Expr::var(7), Expr::var(19));
        assert!(crate::verify::verify_equivalent(&input, &incorrect, Width::W64).is_disproven());
        assert_eq!(
            accept_expression_candidate(&input, incorrect, Width::W64),
            None
        );
    }

    #[cfg(feature = "smt-verify")]
    #[test]
    fn expression_acceptance_rejects_unknown_result() {
        let input: Expr = Expr::var(1024);
        let candidate: Expr = Expr::konst(0);
        assert_eq!(
            crate::verify::verify_equivalent(&input, &candidate, Width::W8),
            crate::verify::Equivalence::Unknown
        );
        assert_eq!(
            accept_expression_candidate(&input, candidate, Width::W8),
            None
        );
    }

    #[test]
    fn dense_restoration_rejects_unmapped_variable() -> Result<(), &'static str> {
        let input: Expr = xor_and_basis(7, 19);
        let Some(dense): Option<DenseExpression> = compact_expression(&input) else {
            return Err("expected a dense expression");
        };
        assert_eq!(dense.restore(&Expr::var(2)), None);
        Ok(())
    }

    #[cfg(not(feature = "smt-verify"))]
    #[test]
    fn sparse_rewrite_is_discarded_without_bitblast_verifier() {
        let input: Expr = Expr::xor(Expr::var(7), Expr::var(7));
        let result: Simplification = simplify(&input, Width::W8);
        assert!(!result.changed());
        assert_eq!(result.simplified, input);
    }

    #[cfg(not(feature = "smt-verify"))]
    #[test]
    fn predicate_minimization_is_discarded_without_bitblast_verifier() {
        let atom: Predicate = Predicate::eq(Expr::var(0), Expr::konst(0));
        let predicate: Predicate = Predicate::or(atom.clone(), atom);
        let result: PredicateSimplification = simplify_predicate(&predicate, Width::W32);
        assert_eq!(result.original, predicate);
        assert_eq!(result.simplified, predicate);
        assert_eq!(result.width, Width::W32);
        assert_eq!(result.verification, Verification::Unverified);
        assert!(!result.changed());
    }

    #[cfg(feature = "smt-verify")]
    #[test]
    fn predicate_acceptance_rejects_disproven_candidate() {
        let input: Predicate = Predicate::eq(Expr::var(0), Expr::konst(0));
        let incorrect: Predicate = Predicate::eq(Expr::var(0), Expr::konst(1));
        assert!(crate::verify::verify_equivalent(&input, &incorrect, Width::W32).is_disproven());
        assert_eq!(
            accept_predicate_candidate(&input, incorrect, Width::W32),
            None
        );
    }
}
