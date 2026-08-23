use std::collections::{BTreeMap, BTreeSet};
use std::panic::{self, AssertUnwindSafe};
use std::time::Duration;

use oxiz::{TermId, TermManager};

use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::opaque::{CmpOp, Predicate};
use crate::symexec::solver_cert::{CertBudget, Certified, certified_check};

const CERT_NODE_BUDGET: usize = 1usize << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtVerdict {
    Unsat,
    Sat,
    Indeterminate,
}

impl SmtVerdict {
    #[must_use]
    pub const fn is_unsat(self) -> bool {
        matches!(self, Self::Unsat)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtBudget {
    pub timeout: Duration,
    pub max_conflicts: u64,
    pub max_decisions: u64,
    pub max_encode_nodes: usize,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(750);
const DEFAULT_MAX_CONFLICTS: u64 = 50_000;
const DEFAULT_MAX_DECISIONS: u64 = 200_000;
const DEFAULT_MAX_ENCODE_NODES: usize = 1 << 16;

impl SmtBudget {
    #[must_use]
    pub const fn bounded_default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_conflicts: DEFAULT_MAX_CONFLICTS,
            max_decisions: DEFAULT_MAX_DECISIONS,
            max_encode_nodes: DEFAULT_MAX_ENCODE_NODES,
        }
    }
}

impl Default for SmtBudget {
    fn default() -> Self {
        Self::bounded_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodeExhausted;

struct Encoder {
    manager: TermManager,
    query_width: Width,
    vars: BTreeMap<u32, TermId>,
    mem_vars: BTreeMap<String, TermId>,
    node_budget: usize,
    nodes_built: usize,
}

impl Encoder {
    fn new(query_width: Width, node_budget: usize) -> Self {
        Self {
            manager: TermManager::new(),
            query_width,
            vars: BTreeMap::new(),
            mem_vars: BTreeMap::new(),
            node_budget,
            nodes_built: 0,
        }
    }

    const fn charge(&mut self) -> Result<(), EncodeExhausted> {
        self.nodes_built += 1;
        if self.nodes_built > self.node_budget {
            return Err(EncodeExhausted);
        }
        Ok(())
    }

    const fn width_bits(&self) -> u32 {
        self.query_width.bits()
    }

    fn var_term(&mut self, index: u32) -> TermId {
        if let Some(existing) = self.vars.get(&index) {
            return *existing;
        }
        let sort_id: oxiz::SortId = self.manager.sorts.bitvec(self.width_bits());
        let name: String = format!("v{index}");
        let term: TermId = self.manager.mk_var(&name, sort_id);
        self.vars.insert(index, term);
        term
    }

    fn mem_term(&mut self, key: String) -> TermId {
        if let Some(existing) = self.mem_vars.get(&key) {
            return *existing;
        }
        let sort_id: oxiz::SortId = self.manager.sorts.bitvec(self.width_bits());
        let term: TermId = self.manager.mk_var(&key, sort_id);
        self.mem_vars.insert(key, term);
        term
    }

    fn zero(&mut self) -> TermId {
        self.manager.mk_bitvec(0u64, self.width_bits())
    }

    fn zero_extend(&mut self, term: TermId, from_width: u32) -> TermId {
        let width_bits: u32 = self.width_bits();
        if from_width >= width_bits {
            return term;
        }
        let pad_width: u32 = width_bits - from_width;
        let pad: TermId = self.manager.mk_bitvec(0u64, pad_width);
        self.manager.mk_bv_concat(pad, term)
    }

    fn mask_low(&mut self, term: TermId, bits: u32) -> TermId {
        let width_bits: u32 = self.width_bits();
        if bits >= width_bits {
            return term;
        }
        let mask_value: u64 = (1u64 << bits) - 1;
        let mask_term: TermId = self.manager.mk_bitvec(mask_value, width_bits);
        self.manager.mk_bv_and(term, mask_term)
    }

    fn shift_left_const(&mut self, term: TermId, amount: u32) -> TermId {
        let width_bits: u32 = self.width_bits();
        if amount >= width_bits {
            return self.zero();
        }
        let amount_term: TermId = self.manager.mk_bitvec(u64::from(amount), width_bits);
        self.manager.mk_bv_shl(term, amount_term)
    }

    fn encode_expr(&mut self, expr: &Expr) -> Result<TermId, EncodeExhausted> {
        self.charge()?;
        let width_bits: u32 = self.width_bits();
        let term: TermId = match expr {
            Expr::Const(value) => {
                let masked: u64 = value & self.query_width.mask();
                self.manager.mk_bitvec(masked, width_bits)
            }
            Expr::Var(index) => self.var_term(*index),
            Expr::Unary(op, inner) => {
                let inner_term: TermId = self.encode_expr(inner)?;
                match op {
                    UnOp::Neg => self.manager.mk_bv_neg(inner_term),
                    UnOp::Not => self.manager.mk_bv_not(inner_term),
                }
            }
            Expr::Binary(op, left, right) => {
                let left_term: TermId = self.encode_expr(left)?;
                let right_term: TermId = self.encode_expr(right)?;
                match op {
                    BinOp::Add => self.manager.mk_bv_add(left_term, right_term),
                    BinOp::Sub => self.manager.mk_bv_sub(left_term, right_term),
                    BinOp::Mul => self.manager.mk_bv_mul(left_term, right_term),
                    BinOp::And => self.manager.mk_bv_and(left_term, right_term),
                    BinOp::Or => self.manager.mk_bv_or(left_term, right_term),
                    BinOp::Xor => self.manager.mk_bv_xor(left_term, right_term),
                    BinOp::Shl => self.manager.mk_bv_shl(left_term, right_term),
                    BinOp::Shr => self.manager.mk_bv_lshr(left_term, right_term),
                }
            }
            Expr::Ite(cond, then_branch, else_branch) => {
                let cond_term: TermId = self.encode_expr(cond)?;
                let then_term: TermId = self.encode_expr(then_branch)?;
                let else_term: TermId = self.encode_expr(else_branch)?;
                let zero_term: TermId = self.zero();
                let is_zero: TermId = self.manager.mk_eq(cond_term, zero_term);
                let cond_bool: TermId = self.manager.mk_not(is_zero);
                self.manager.mk_ite(cond_bool, then_term, else_term)
            }
            Expr::Slice(inner, lo, hi) => {
                let inner_term: TermId = self.encode_expr(inner)?;
                if hi <= lo {
                    self.zero()
                } else {
                    let high_bit: u32 = (hi - 1).min(width_bits.saturating_sub(1));
                    let low_bit: u32 = (*lo).min(high_bit);
                    let extracted: TermId =
                        self.manager.mk_bv_extract(high_bit, low_bit, inner_term);
                    let extracted_width: u32 = high_bit - low_bit + 1;
                    self.zero_extend(extracted, extracted_width)
                }
            }
            Expr::Compose(low, high, low_bits) => {
                let low_term: TermId = self.encode_expr(low)?;
                let high_term: TermId = self.encode_expr(high)?;
                if *low_bits == 0 {
                    high_term
                } else if *low_bits >= width_bits {
                    low_term
                } else {
                    let low_masked: TermId = self.mask_low(low_term, *low_bits);
                    let high_shifted: TermId = self.shift_left_const(high_term, *low_bits);
                    self.manager.mk_bv_or(low_masked, high_shifted)
                }
            }
            Expr::Mem(addr, load_width) => {
                let key: String = format!("mem:{addr}:{}", load_width.bits());
                self.mem_term(key)
            }
        };
        Ok(term)
    }

    fn cmp_bool(&mut self, op: CmpOp, left: TermId, right: TermId) -> TermId {
        match op {
            CmpOp::Eq => self.manager.mk_eq(left, right),
            CmpOp::Ne => {
                let equal: TermId = self.manager.mk_eq(left, right);
                self.manager.mk_not(equal)
            }
            CmpOp::UnsignedLt => self.manager.mk_bv_ult(left, right),
            CmpOp::UnsignedLe => self.manager.mk_bv_ule(left, right),
            CmpOp::UnsignedGt => self.manager.mk_bv_ult(right, left),
            CmpOp::UnsignedGe => self.manager.mk_bv_ule(right, left),
            CmpOp::SignedLt => self.manager.mk_bv_slt(left, right),
            CmpOp::SignedLe => self.manager.mk_bv_sle(left, right),
            CmpOp::SignedGt => self.manager.mk_bv_slt(right, left),
            CmpOp::SignedGe => self.manager.mk_bv_sle(right, left),
        }
    }

    fn encode_predicate(&mut self, predicate: &Predicate) -> Result<TermId, EncodeExhausted> {
        self.charge()?;
        let term: TermId = match predicate {
            Predicate::Compare { op, left, right } => {
                let left_term: TermId = self.encode_expr(left)?;
                let right_term: TermId = self.encode_expr(right)?;
                self.cmp_bool(*op, left_term, right_term)
            }
            Predicate::Nonzero(inner) => {
                let inner_term: TermId = self.encode_expr(inner)?;
                let zero_term: TermId = self.zero();
                let is_zero: TermId = self.manager.mk_eq(inner_term, zero_term);
                self.manager.mk_not(is_zero)
            }
            Predicate::Or(left, right) => {
                let left_term: TermId = self.encode_predicate(left)?;
                let right_term: TermId = self.encode_predicate(right)?;
                self.manager.mk_or([left_term, right_term])
            }
            Predicate::And(left, right) => {
                let left_term: TermId = self.encode_predicate(left)?;
                let right_term: TermId = self.encode_predicate(right)?;
                self.manager.mk_and([left_term, right_term])
            }
        };
        Ok(term)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    lo: u64,
    hi: u64,
}

#[derive(Debug, Clone)]
struct UnaryDomain {
    width: Width,
    spans: Vec<Span>,
    excluded: BTreeSet<u64>,
}

#[derive(Debug, Clone, Copy)]
struct UnaryAtom {
    variable: u32,
    op: CmpOp,
    constant: u64,
    width: Width,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preflight {
    Decided(SmtVerdict),
    Unsupported,
}

const fn complement_comparison(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::Eq => CmpOp::Ne,
        CmpOp::Ne => CmpOp::Eq,
        CmpOp::UnsignedLt => CmpOp::UnsignedGe,
        CmpOp::UnsignedLe => CmpOp::UnsignedGt,
        CmpOp::UnsignedGt => CmpOp::UnsignedLe,
        CmpOp::UnsignedGe => CmpOp::UnsignedLt,
        CmpOp::SignedLt => CmpOp::SignedGe,
        CmpOp::SignedLe => CmpOp::SignedGt,
        CmpOp::SignedGt => CmpOp::SignedLe,
        CmpOp::SignedGe => CmpOp::SignedLt,
    }
}

const fn reverse_comparison(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::Eq | CmpOp::Ne => op,
        CmpOp::UnsignedLt => CmpOp::UnsignedGt,
        CmpOp::UnsignedLe => CmpOp::UnsignedGe,
        CmpOp::UnsignedGt => CmpOp::UnsignedLt,
        CmpOp::UnsignedGe => CmpOp::UnsignedLe,
        CmpOp::SignedLt => CmpOp::SignedGt,
        CmpOp::SignedLe => CmpOp::SignedGe,
        CmpOp::SignedGt => CmpOp::SignedLt,
        CmpOp::SignedGe => CmpOp::SignedLe,
    }
}

const fn normalize_atom(predicate: &Predicate, expected: bool, width: Width) -> Option<UnaryAtom> {
    let (variable, mut op, constant): (u32, CmpOp, u64) = match predicate {
        Predicate::Compare {
            op,
            left: Expr::Var(variable),
            right: Expr::Const(constant),
        } => (*variable, *op, *constant),
        Predicate::Compare {
            op,
            left: Expr::Const(constant),
            right: Expr::Var(variable),
        } => (*variable, reverse_comparison(*op), *constant),
        Predicate::Nonzero(Expr::Var(variable)) => (*variable, CmpOp::Ne, 0),
        Predicate::Compare { .. }
        | Predicate::Nonzero(_)
        | Predicate::Or(_, _)
        | Predicate::And(_, _) => return None,
    };
    if !expected {
        op = complement_comparison(op);
    }
    Some(UnaryAtom {
        variable,
        op,
        constant: constant & width.mask(),
        width,
    })
}

const fn signed_value(value: u64, width: Width) -> i64 {
    let bits: u32 = width.bits();
    if bits == 64 {
        value as i64
    } else {
        let shift: u32 = 64 - bits;
        ((value << shift) as i64) >> shift
    }
}

fn signed_spans(lo: i64, hi: i64, width: Width) -> Vec<Span> {
    if lo > hi {
        return Vec::new();
    }
    let mask: u64 = width.mask();
    let encoded_lo: u64 = lo as u64 & mask;
    let encoded_hi: u64 = hi as u64 & mask;
    if lo < 0 && hi >= 0 {
        vec![
            Span {
                lo: encoded_lo,
                hi: mask,
            },
            Span {
                lo: 0,
                hi: encoded_hi,
            },
        ]
    } else {
        vec![Span {
            lo: encoded_lo,
            hi: encoded_hi,
        }]
    }
}

fn allowed_spans(atom: UnaryAtom) -> Option<Vec<Span>> {
    let mask: u64 = atom.width.mask();
    let spans: Vec<Span> = match atom.op {
        CmpOp::Eq => vec![Span {
            lo: atom.constant,
            hi: atom.constant,
        }],
        CmpOp::Ne => return None,
        CmpOp::UnsignedLt => atom
            .constant
            .checked_sub(1)
            .map_or_else(Vec::new, |hi: u64| vec![Span { lo: 0, hi }]),
        CmpOp::UnsignedLe => vec![Span {
            lo: 0,
            hi: atom.constant,
        }],
        CmpOp::UnsignedGt => atom
            .constant
            .checked_add(1)
            .filter(|lo: &u64| *lo <= mask)
            .map_or_else(Vec::new, |lo: u64| vec![Span { lo, hi: mask }]),
        CmpOp::UnsignedGe => vec![Span {
            lo: atom.constant,
            hi: mask,
        }],
        CmpOp::SignedLt | CmpOp::SignedLe | CmpOp::SignedGt | CmpOp::SignedGe => {
            let bits: u32 = atom.width.bits();
            let signed_min: i64 = if bits == 64 {
                i64::MIN
            } else {
                -(1i64 << (bits - 1))
            };
            let signed_max: i64 = if bits == 64 {
                i64::MAX
            } else {
                (1i64 << (bits - 1)) - 1
            };
            let constant: i64 = signed_value(atom.constant, atom.width);
            let (lo, hi): (i64, i64) = match atom.op {
                CmpOp::SignedLt => (signed_min, constant.checked_sub(1)?),
                CmpOp::SignedLe => (signed_min, constant),
                CmpOp::SignedGt => (constant.checked_add(1)?, signed_max),
                CmpOp::SignedGe => (constant, signed_max),
                CmpOp::Eq
                | CmpOp::Ne
                | CmpOp::UnsignedLt
                | CmpOp::UnsignedLe
                | CmpOp::UnsignedGt
                | CmpOp::UnsignedGe => return Some(Vec::new()),
            };
            signed_spans(lo, hi, atom.width)
        }
    };
    Some(spans)
}

fn intersect_spans(current: &[Span], allowed: &[Span]) -> Vec<Span> {
    let mut intersections: Vec<Span> = current
        .iter()
        .flat_map(|left: &Span| {
            allowed.iter().filter_map(move |right: &Span| {
                let lo: u64 = left.lo.max(right.lo);
                let hi: u64 = left.hi.min(right.hi);
                (lo <= hi).then_some(Span { lo, hi })
            })
        })
        .collect();
    intersections.sort_unstable_by_key(|span: &Span| span.lo);
    let mut merged: Vec<Span> = Vec::with_capacity(intersections.len());
    for span in intersections {
        if let Some(last) = merged.last_mut()
            && span.lo <= last.hi.saturating_add(1)
        {
            last.hi = last.hi.max(span.hi);
        } else {
            merged.push(span);
        }
    }
    merged
}

impl UnaryDomain {
    fn new(width: Width) -> Self {
        Self {
            width,
            spans: vec![Span {
                lo: 0,
                hi: width.mask(),
            }],
            excluded: BTreeSet::new(),
        }
    }

    fn constrain(&mut self, atom: UnaryAtom) {
        if atom.op == CmpOp::Ne {
            self.excluded.insert(atom.constant);
        } else {
            let allowed: Vec<Span> = allowed_spans(atom).unwrap_or_default();
            self.spans = intersect_spans(&self.spans, &allowed);
        }
    }

    fn witness(&self) -> Option<u64> {
        for span in &self.spans {
            let mut candidate: u64 = span.lo;
            for excluded in self.excluded.range(span.lo..=span.hi) {
                if *excluded > candidate {
                    return Some(candidate);
                }
                if *excluded == candidate {
                    if candidate == span.hi {
                        break;
                    }
                    candidate += 1;
                }
            }
            if candidate <= span.hi && !self.excluded.contains(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

fn atom_holds(atom: UnaryAtom, value: u64) -> bool {
    let unsigned: std::cmp::Ordering = value.cmp(&atom.constant);
    let signed: std::cmp::Ordering =
        signed_value(value, atom.width).cmp(&signed_value(atom.constant, atom.width));
    match atom.op {
        CmpOp::Eq => unsigned.is_eq(),
        CmpOp::Ne => unsigned.is_ne(),
        CmpOp::UnsignedLt => unsigned.is_lt(),
        CmpOp::UnsignedLe => unsigned.is_le(),
        CmpOp::UnsignedGt => unsigned.is_gt(),
        CmpOp::UnsignedGe => unsigned.is_ge(),
        CmpOp::SignedLt => signed.is_lt(),
        CmpOp::SignedLe => signed.is_le(),
        CmpOp::SignedGt => signed.is_gt(),
        CmpOp::SignedGe => signed.is_ge(),
    }
}

fn unary_preflight(constraints: &[(Predicate, bool, Width)]) -> Preflight {
    let Some(atoms): Option<Vec<UnaryAtom>> = constraints
        .iter()
        .map(|(predicate, expected, width): &(Predicate, bool, Width)| {
            normalize_atom(predicate, *expected, *width)
        })
        .collect()
    else {
        return Preflight::Unsupported;
    };
    let mut domains: BTreeMap<u32, UnaryDomain> = BTreeMap::new();
    for atom in &atoms {
        let domain: &mut UnaryDomain = domains
            .entry(atom.variable)
            .or_insert_with(|| UnaryDomain::new(atom.width));
        if domain.width != atom.width {
            return Preflight::Unsupported;
        }
        domain.constrain(*atom);
    }
    let mut witnesses: BTreeMap<u32, u64> = BTreeMap::new();
    for (variable, domain) in &domains {
        let Some(witness): Option<u64> = domain.witness() else {
            return Preflight::Decided(SmtVerdict::Unsat);
        };
        witnesses.insert(*variable, witness);
    }
    if atoms.iter().all(|atom: &UnaryAtom| {
        witnesses
            .get(&atom.variable)
            .is_some_and(|value: &u64| atom_holds(*atom, *value))
    }) {
        Preflight::Decided(SmtVerdict::Sat)
    } else {
        Preflight::Unsupported
    }
}

#[must_use]
pub fn check_unsat(constraints: &[(Predicate, bool, Width)], budget: SmtBudget) -> SmtVerdict {
    if constraints.is_empty() {
        return SmtVerdict::Sat;
    }
    for (predicate, _, _) in constraints {
        if predicate.depth() > crate::expr::MAX_MBA_DEPTH {
            return SmtVerdict::Indeterminate;
        }
    }
    if let Preflight::Decided(verdict) = unary_preflight(constraints) {
        return verdict;
    }
    let Some(query_width): Option<Width> = constraints
        .iter()
        .map(|entry: &(Predicate, bool, Width)| entry.2)
        .max()
    else {
        return SmtVerdict::Indeterminate;
    };
    let outcome: Result<SmtVerdict, Box<dyn std::any::Any + Send>> =
        panic::catch_unwind(AssertUnwindSafe(|| solve(constraints, query_width, budget)));
    outcome.unwrap_or(SmtVerdict::Indeterminate)
}

fn solve(
    constraints: &[(Predicate, bool, Width)],
    query_width: Width,
    budget: SmtBudget,
) -> SmtVerdict {
    let mut encoder: Encoder = Encoder::new(query_width, budget.max_encode_nodes);
    let mut asserted: Vec<TermId> = Vec::with_capacity(constraints.len());
    for (predicate, expect, _) in constraints {
        let Ok(term): Result<TermId, EncodeExhausted> = encoder.encode_predicate(predicate) else {
            return SmtVerdict::Indeterminate;
        };
        let term: TermId = if *expect {
            term
        } else {
            encoder.manager.mk_not(term)
        };
        asserted.push(term);
    }
    let cert_budget: CertBudget = CertBudget {
        timeout: budget.timeout,
        max_conflicts: budget.max_conflicts,
        max_decisions: budget.max_decisions,
        node_budget: CERT_NODE_BUDGET,
    };
    match certified_check(&mut encoder.manager, &asserted, cert_budget) {
        Certified::Unsat => SmtVerdict::Unsat,
        Certified::Sat => SmtVerdict::Sat,
        Certified::Abstain => SmtVerdict::Indeterminate,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn x_squared_plus_x() -> Expr {
        Expr::add(Expr::mul(Expr::var(0), Expr::var(0)), Expr::var(0))
    }

    #[test]
    fn proves_two_divides_x_squared_plus_x_unsat_on_odd_side() {
        let predicate: Predicate = Predicate::eq(
            Expr::and(x_squared_plus_x(), Expr::konst(1)),
            Expr::konst(1),
        );
        let constraints: [(Predicate, bool, Width); 1] = [(predicate, true, Width::W8)];
        let verdict: SmtVerdict = check_unsat(&constraints, SmtBudget::default());
        assert_eq!(verdict, SmtVerdict::Unsat);
    }

    #[test]
    fn genuine_data_dependent_predicate_is_sat_both_ways() {
        let predicate: Predicate = Predicate::eq(Expr::var(0), Expr::konst(7));
        let sat_side: [(Predicate, bool, Width); 1] = [(predicate.clone(), true, Width::W8)];
        let other_side: [(Predicate, bool, Width); 1] = [(predicate, false, Width::W8)];
        assert_eq!(
            check_unsat(&sat_side, SmtBudget::default()),
            SmtVerdict::Sat
        );
        assert_eq!(
            check_unsat(&other_side, SmtBudget::default()),
            SmtVerdict::Sat
        );
    }

    #[test]
    fn correlated_prior_branch_makes_contradicting_edge_unsat() {
        let x_eq_five: Predicate = Predicate::eq(Expr::var(0), Expr::konst(5));
        let x_eq_six: Predicate = Predicate::eq(Expr::var(0), Expr::konst(6));
        let constraints: [(Predicate, bool, Width); 2] =
            [(x_eq_five, true, Width::W8), (x_eq_six, true, Width::W8)];
        assert_eq!(
            check_unsat(&constraints, SmtBudget::default()),
            SmtVerdict::Unsat
        );
    }

    #[test]
    fn one_variable_signed_dispatch_path_is_decided_before_the_smt_backend() {
        let constraints: [(Predicate, bool, Width); 3] = [
            (
                Predicate::Compare {
                    op: CmpOp::SignedGt,
                    left: Expr::var(0),
                    right: Expr::konst(1_773_180_476),
                },
                false,
                Width::W32,
            ),
            (
                Predicate::eq(Expr::var(0), Expr::konst(844_609_675)),
                false,
                Width::W32,
            ),
            (
                Predicate::ne(Expr::var(0), Expr::konst(1_483_007_430)),
                false,
                Width::W32,
            ),
        ];
        let exhausted_backend: SmtBudget = SmtBudget {
            timeout: Duration::ZERO,
            max_conflicts: 0,
            max_decisions: 0,
            ..SmtBudget::bounded_default()
        };
        assert_eq!(
            check_unsat(&constraints, exhausted_backend),
            SmtVerdict::Sat
        );
    }

    #[test]
    fn unary_preflight_handles_signed_and_unsigned_boundaries_exactly() {
        let signed_min: u64 = i32::MIN as u32 as u64;
        let signed_max: u64 = i32::MAX as u64;
        for (op, constant, expected) in [
            (CmpOp::SignedLt, signed_min, SmtVerdict::Unsat),
            (CmpOp::SignedGe, signed_min, SmtVerdict::Sat),
            (CmpOp::SignedGt, signed_max, SmtVerdict::Unsat),
            (CmpOp::SignedLt, 0, SmtVerdict::Sat),
            (CmpOp::SignedGt, u32::MAX as u64, SmtVerdict::Sat),
            (CmpOp::UnsignedLt, 0, SmtVerdict::Unsat),
            (CmpOp::UnsignedGe, u32::MAX as u64, SmtVerdict::Sat),
        ] {
            let constraints: [(Predicate, bool, Width); 1] = [(
                Predicate::Compare {
                    op,
                    left: Expr::var(0),
                    right: Expr::konst(constant),
                },
                true,
                Width::W32,
            )];
            assert_eq!(
                unary_preflight(&constraints),
                Preflight::Decided(expected),
                "{op:?} against {constant:#x}"
            );
        }
    }

    #[test]
    fn false_expectation_complements_every_comparison_operator() {
        let operators: [CmpOp; 10] = [
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
        for op in operators {
            for constant in 0..4 {
                let predicate: Predicate = Predicate::Compare {
                    op,
                    left: Expr::var(0),
                    right: Expr::konst(constant),
                };
                let atom: UnaryAtom =
                    normalize_atom(&predicate, false, Width::W2).expect("unary atom");
                for value in 0..4 {
                    assert_eq!(
                        atom_holds(atom, value),
                        !predicate.evaluate(&[value], Width::W2),
                        "{op:?}: value={value}, constant={constant}"
                    );
                }
            }
        }
    }

    #[test]
    fn unary_preflight_counts_distinct_exclusions_and_keeps_the_last_value() {
        let excluded: Vec<(Predicate, bool, Width)> = (0..4)
            .map(|value: u64| {
                (
                    Predicate::ne(Expr::var(0), Expr::konst(value)),
                    true,
                    Width::W2,
                )
            })
            .collect();
        assert_eq!(
            unary_preflight(&excluded),
            Preflight::Decided(SmtVerdict::Unsat)
        );

        let one_left: Vec<(Predicate, bool, Width)> = [0, 0, 1, 2]
            .into_iter()
            .map(|value: u64| {
                (
                    Predicate::ne(Expr::var(0), Expr::konst(value)),
                    true,
                    Width::W2,
                )
            })
            .collect();
        assert_eq!(
            unary_preflight(&one_left),
            Preflight::Decided(SmtVerdict::Sat)
        );
    }

    #[test]
    fn unary_preflight_reverses_constant_left_comparisons() {
        let constraints: [(Predicate, bool, Width); 2] = [
            (
                Predicate::Compare {
                    op: CmpOp::UnsignedLt,
                    left: Expr::konst(3),
                    right: Expr::var(0),
                },
                true,
                Width::W8,
            ),
            (
                Predicate::Compare {
                    op: CmpOp::UnsignedLe,
                    left: Expr::var(0),
                    right: Expr::konst(3),
                },
                true,
                Width::W8,
            ),
        ];
        assert_eq!(
            unary_preflight(&constraints),
            Preflight::Decided(SmtVerdict::Unsat)
        );
    }

    #[test]
    fn unary_preflight_supports_independent_widths_but_rejects_mixed_width_aliases() {
        let independent: [(Predicate, bool, Width); 2] = [
            (
                Predicate::eq(Expr::var(0), Expr::konst(0xff)),
                true,
                Width::W8,
            ),
            (
                Predicate::eq(Expr::var(1), Expr::konst(0x100)),
                true,
                Width::W16,
            ),
        ];
        assert_eq!(
            unary_preflight(&independent),
            Preflight::Decided(SmtVerdict::Sat)
        );

        let independently_contradictory: [(Predicate, bool, Width); 3] = [
            (
                Predicate::eq(Expr::var(0), Expr::konst(0xff)),
                true,
                Width::W8,
            ),
            (
                Predicate::eq(Expr::var(1), Expr::konst(0x100)),
                true,
                Width::W16,
            ),
            (
                Predicate::ne(Expr::var(1), Expr::konst(0x100)),
                true,
                Width::W16,
            ),
        ];
        assert_eq!(
            unary_preflight(&independently_contradictory),
            Preflight::Decided(SmtVerdict::Unsat)
        );

        let aliased: [(Predicate, bool, Width); 2] = [
            (
                Predicate::eq(Expr::var(0), Expr::konst(0xff)),
                true,
                Width::W8,
            ),
            (
                Predicate::eq(Expr::var(0), Expr::konst(0xff)),
                true,
                Width::W16,
            ),
        ];
        assert_eq!(unary_preflight(&aliased), Preflight::Unsupported);
    }

    #[test]
    fn unary_preflight_leaves_arithmetic_and_boolean_trees_to_the_certified_solver() {
        let arithmetic: [(Predicate, bool, Width); 1] = [(
            Predicate::eq(Expr::add(Expr::var(0), Expr::konst(1)), Expr::konst(2)),
            true,
            Width::W8,
        )];
        let boolean: [(Predicate, bool, Width); 1] = [(
            Predicate::and(
                Predicate::eq(Expr::var(0), Expr::konst(1)),
                Predicate::eq(Expr::var(1), Expr::konst(2)),
            ),
            true,
            Width::W8,
        )];
        assert_eq!(unary_preflight(&arithmetic), Preflight::Unsupported);
        assert_eq!(unary_preflight(&boolean), Preflight::Unsupported);
    }

    #[test]
    fn empty_constraint_set_is_trivially_sat() {
        assert_eq!(check_unsat(&[], SmtBudget::default()), SmtVerdict::Sat);
    }

    fn live_masked_product() -> Predicate {
        let live_bits: Expr = Expr::or(
            Expr::or(Expr::var(1), Expr::var(2)),
            Expr::or(Expr::var(3), Expr::var(4)),
        );
        Predicate::eq(Expr::and(x_squared_plus_x(), live_bits), Expr::konst(0))
    }

    #[test]
    fn an_exhausted_encode_budget_yields_indeterminate() {
        let budget: SmtBudget = SmtBudget {
            max_encode_nodes: 2,
            ..SmtBudget::bounded_default()
        };
        let constraints: [(Predicate, bool, Width); 1] =
            [(live_masked_product(), true, Width::W64)];
        assert_eq!(check_unsat(&constraints, budget), SmtVerdict::Indeterminate);
    }

    #[test]
    fn a_predicate_deeper_than_the_depth_cap_yields_indeterminate() {
        let mut deep: Expr = Expr::var(0);
        for _ in 0..=crate::expr::MAX_MBA_DEPTH {
            deep = Expr::add(deep, Expr::konst(1));
        }
        let predicate: Predicate = Predicate::eq(deep, Expr::konst(0));
        assert!(predicate.depth() > crate::expr::MAX_MBA_DEPTH);
        let constraints: [(Predicate, bool, Width); 1] = [(predicate, true, Width::W8)];
        assert_eq!(
            check_unsat(&constraints, SmtBudget::default()),
            SmtVerdict::Indeterminate
        );
    }

    #[test]
    fn an_exhausted_conflict_budget_yields_indeterminate() {
        let budget: SmtBudget = SmtBudget {
            max_conflicts: 0,
            ..SmtBudget::bounded_default()
        };
        let constraints: [(Predicate, bool, Width); 1] =
            [(live_masked_product(), true, Width::W64)];
        assert_eq!(check_unsat(&constraints, budget), SmtVerdict::Indeterminate);
    }

    #[test]
    fn an_exhausted_decision_budget_yields_indeterminate() {
        let budget: SmtBudget = SmtBudget {
            max_decisions: 0,
            ..SmtBudget::bounded_default()
        };
        let constraints: [(Predicate, bool, Width); 1] =
            [(live_masked_product(), true, Width::W64)];
        assert_eq!(check_unsat(&constraints, budget), SmtVerdict::Indeterminate);
    }

    #[test]
    fn an_exhausted_timeout_never_yields_an_unconfirmed_refutation() {
        let budget: SmtBudget = SmtBudget {
            timeout: Duration::from_nanos(1),
            ..SmtBudget::bounded_default()
        };
        let predicate: Predicate = live_masked_product();
        let constraints: [(Predicate, bool, Width); 1] = [(predicate.clone(), true, Width::W64)];
        let verdict: SmtVerdict = check_unsat(&constraints, budget);
        assert_ne!(verdict, SmtVerdict::Unsat);
        if verdict == SmtVerdict::Sat {
            let env: [u64; 5] = [0, 0, 0, 0, 0];
            assert!(
                predicate.evaluate(&env, Width::W64),
                "a Sat verdict under an exhausted timeout must still describe a satisfiable query"
            );
        }
    }

    #[test]
    fn tiny_conflict_budget_yields_indeterminate_not_a_guess() {
        let budget: SmtBudget = SmtBudget {
            timeout: Duration::from_nanos(1),
            max_conflicts: 0,
            max_decisions: 0,
            max_encode_nodes: 0,
        };
        let constraints: [(Predicate, bool, Width); 1] =
            [(live_masked_product(), true, Width::W64)];
        let verdict: SmtVerdict = check_unsat(&constraints, budget);
        assert_eq!(verdict, SmtVerdict::Indeterminate);
    }
}
