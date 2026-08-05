use std::collections::BTreeMap;
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
