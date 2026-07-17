use std::panic::{self, AssertUnwindSafe};
use std::time::{Duration, Instant};

use oxiz::resource_limits::ResourceLimits;
use oxiz::{Solver, SolverResult, TermId, TermManager};

use super::value::{AluOp, BitWidth, CmpOp, Sym, UnaryOp, fold_alu, fold_unary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SolverBudget {
    pub(crate) per_query_timeout: Duration,
    pub(crate) max_conflicts: u64,
    pub(crate) max_decisions: u64,
    pub(crate) cumulative: Duration,
    pub(crate) max_queries: u64,
}

impl SolverBudget {
    pub(crate) const fn bounded_default() -> Self {
        Self {
            per_query_timeout: Duration::from_millis(250),
            max_conflicts: 20_000,
            max_decisions: 100_000,
            cumulative: Duration::from_secs(5),
            max_queries: 4_096,
        }
    }
}

impl Default for SolverBudget {
    fn default() -> Self {
        Self::bounded_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Feasible {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Guard {
    Always,
    Never,
    Term(TermId),
}

#[derive(Debug)]
pub(crate) struct SymSolver {
    manager: TermManager,
    budget: SolverBudget,
    elapsed: Duration,
    queries: u64,
    fresh: u64,
}

impl SymSolver {
    pub(crate) fn new(budget: SolverBudget) -> Self {
        Self {
            manager: TermManager::new(),
            budget,
            elapsed: Duration::ZERO,
            queries: 0,
            fresh: 0,
        }
    }

    pub(crate) fn fresh_havoc(&mut self, width: BitWidth) -> Sym {
        let name: String = format!("havoc_{}", self.fresh);
        self.fresh = self.fresh.wrapping_add(1);
        let sort: oxiz::SortId = self.manager.sorts.bitvec(width.bits_u32());
        let term: TermId = self.manager.mk_var(&name, sort);
        Sym::bv(width, term)
    }

    fn term_of(&mut self, value: Sym) -> TermId {
        match value {
            Sym::Const { width, value } => self
                .manager
                .mk_bitvec(value & width.mask(), width.bits_u32()),
            Sym::Bv { term, .. } => term,
            Sym::Bool { width, pred } => {
                let one: TermId = self.manager.mk_bitvec(1u64, width.bits_u32());
                let zero: TermId = self.manager.mk_bitvec(0u64, width.bits_u32());
                self.manager.mk_ite(pred, one, zero)
            }
        }
    }

    fn zero_of(&mut self, width: BitWidth) -> TermId {
        self.manager.mk_bitvec(0u64, width.bits_u32())
    }

    pub(crate) fn alu(&mut self, op: AluOp, lhs: Sym, rhs: Sym, width: BitWidth) -> Sym {
        if lhs.width() != width || rhs.width() != width {
            return self.fresh_havoc(width);
        }
        if let (Some(a), Some(b)) = (lhs.const_value(), rhs.const_value())
            && let Some(folded) = fold_alu(op, a, b, width)
        {
            return Sym::constant(width, folded);
        }
        let a: TermId = self.term_of(lhs);
        let b: TermId = self.term_of(rhs);
        let term: TermId = match op {
            AluOp::Add => self.manager.mk_bv_add(a, b),
            AluOp::Sub => self.manager.mk_bv_sub(a, b),
            AluOp::Mul => self.manager.mk_bv_mul(a, b),
            AluOp::And => self.manager.mk_bv_and(a, b),
            AluOp::Or => self.manager.mk_bv_or(a, b),
            AluOp::Xor => self.manager.mk_bv_xor(a, b),
            AluOp::Shl => self.manager.mk_bv_shl(a, b),
            AluOp::Lshr => self.manager.mk_bv_lshr(a, b),
            AluOp::Ashr => self.manager.mk_bv_ashr(a, b),
            AluOp::Udiv => self.manager.mk_bv_udiv(a, b),
            AluOp::Sdiv => self.manager.mk_bv_sdiv(a, b),
            AluOp::Urem => self.manager.mk_bv_urem(a, b),
            AluOp::Srem => self.manager.mk_bv_srem(a, b),
        };
        Sym::bv(width, term)
    }

    pub(crate) fn unary(&mut self, op: UnaryOp, operand: Sym, width: BitWidth) -> Sym {
        if operand.width() != width {
            return self.fresh_havoc(width);
        }
        if let Some(value) = operand.const_value() {
            return Sym::constant(width, fold_unary(op, value, width));
        }
        let term: TermId = self.term_of(operand);
        let result: TermId = match op {
            UnaryOp::Not => self.manager.mk_bv_not(term),
        };
        Sym::bv(width, result)
    }

    pub(crate) fn compare(&mut self, op: CmpOp, lhs: Sym, rhs: Sym, result_width: BitWidth) -> Sym {
        if lhs.width() != rhs.width() {
            return self.fresh_havoc(result_width);
        }
        let a: TermId = self.term_of(lhs);
        let b: TermId = self.term_of(rhs);
        let cond: TermId = match op {
            CmpOp::Eq => self.manager.mk_eq(a, b),
            CmpOp::Ne => {
                let equal: TermId = self.manager.mk_eq(a, b);
                self.manager.mk_not(equal)
            }
            CmpOp::Ult => self.manager.mk_bv_ult(a, b),
            CmpOp::Ule => self.manager.mk_bv_ule(a, b),
            CmpOp::Slt => self.manager.mk_bv_slt(a, b),
            CmpOp::Sle => self.manager.mk_bv_sle(a, b),
        };
        Sym::boolean(result_width, cond)
    }

    pub(crate) fn zero_extend(&mut self, operand: Sym, target: BitWidth) -> Sym {
        let source: BitWidth = operand.width();
        if source.bits() > target.bits() {
            return self.fresh_havoc(target);
        }
        if source.bits() == target.bits() {
            return operand;
        }
        if let Some(value) = operand.const_value() {
            return Sym::constant(target, value);
        }
        let pad_bits: u32 = target.bits_u32() - source.bits_u32();
        let term: TermId = self.term_of(operand);
        let pad: TermId = self.manager.mk_bitvec(0u64, pad_bits);
        let extended: TermId = self.manager.mk_bv_concat(pad, term);
        Sym::bv(target, extended)
    }

    pub(crate) fn extract_low(&mut self, operand: Sym, offset_bits: u32, target: BitWidth) -> Sym {
        let source_bits: u32 = operand.width().bits_u32();
        let high: u32 = offset_bits.saturating_add(target.bits_u32());
        if high > source_bits || target.bits_u32() == 0 {
            return self.fresh_havoc(target);
        }
        if let Some(value) = operand.const_value() {
            let shifted: u64 = value >> offset_bits;
            return Sym::constant(target, shifted);
        }
        let term: TermId = self.term_of(operand);
        let extracted: TermId = self.manager.mk_bv_extract(high - 1, offset_bits, term);
        Sym::bv(target, extracted)
    }

    pub(crate) fn nonzero_guard(&mut self, value: Sym) -> Guard {
        match value {
            Sym::Const { width, value } => {
                if value & width.mask() == 0 {
                    Guard::Never
                } else {
                    Guard::Always
                }
            }
            Sym::Bv { width, term } => {
                let zero: TermId = self.manager.mk_bitvec(0u64, width.bits_u32());
                let equal: TermId = self.manager.mk_eq(term, zero);
                let nonzero: TermId = self.manager.mk_not(equal);
                Guard::Term(nonzero)
            }
            Sym::Bool { pred, .. } => Guard::Term(pred),
        }
    }

    pub(crate) fn zero_guard(&mut self, value: Sym) -> Guard {
        match value {
            Sym::Const { width, value } => {
                if value & width.mask() == 0 {
                    Guard::Always
                } else {
                    Guard::Never
                }
            }
            Sym::Bv { width, term } => {
                let zero: TermId = self.zero_of(width);
                let equal: TermId = self.manager.mk_eq(term, zero);
                Guard::Term(equal)
            }
            Sym::Bool { pred, .. } => {
                let negated: TermId = self.manager.mk_not(pred);
                Guard::Term(negated)
            }
        }
    }

    pub(crate) fn cumulative_exhausted(&self) -> bool {
        self.elapsed.saturating_add(self.budget.per_query_timeout) > self.budget.cumulative
            || self.queries >= self.budget.max_queries
    }

    pub(crate) fn feasible(&mut self, path: &[TermId], guard: Guard) -> Feasible {
        let extra: TermId = match guard {
            Guard::Always => return self.feasible_conjunction(path),
            Guard::Never => return Feasible::Unsat,
            Guard::Term(term) => term,
        };
        let mut assumptions: Vec<TermId> = Vec::with_capacity(path.len() + 1);
        assumptions.extend_from_slice(path);
        assumptions.push(extra);
        self.check(&assumptions)
    }

    fn feasible_conjunction(&mut self, path: &[TermId]) -> Feasible {
        if path.is_empty() {
            return Feasible::Sat;
        }
        self.check(path)
    }

    fn check(&mut self, assumptions: &[TermId]) -> Feasible {
        let start: Instant = Instant::now();
        let timeout: Duration = self.budget.per_query_timeout;
        let limits: ResourceLimits = ResourceLimits::new()
            .with_timeout(timeout)
            .with_max_conflicts(self.budget.max_conflicts)
            .with_max_decisions(self.budget.max_decisions);
        let manager: &mut TermManager = &mut self.manager;
        let outcome: Result<Feasible, Box<dyn std::any::Any + Send>> =
            panic::catch_unwind(AssertUnwindSafe(|| {
                let mut solver: Solver = Solver::new();
                for &term in assumptions {
                    solver.assert(term, manager);
                }
                solver.set_timeout(timeout);
                match solver.check_with_limits(manager, &limits) {
                    Ok(SolverResult::Sat) => Feasible::Sat,
                    Ok(SolverResult::Unsat) => Feasible::Unsat,
                    Ok(SolverResult::Unknown) | Err(_) => Feasible::Unknown,
                }
            }));
        self.elapsed = self.elapsed.saturating_add(start.elapsed());
        self.queries = self.queries.wrapping_add(1);
        outcome.unwrap_or(Feasible::Unknown)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn width(bits: u16) -> BitWidth {
        BitWidth::new(bits).expect("width is valid")
    }

    #[test]
    fn concrete_alu_never_touches_the_solver() {
        let mut solver: SymSolver = SymSolver::new(SolverBudget::default());
        let width8: BitWidth = width(8);
        let sum: Sym = solver.alu(
            AluOp::Add,
            Sym::constant(width8, 0x30),
            Sym::constant(width8, 0x12),
            width8,
        );
        assert_eq!(sum.const_value(), Some(0x42));
    }

    #[test]
    fn opaque_or_one_is_never_zero() {
        let mut solver: SymSolver = SymSolver::new(SolverBudget::default());
        let width8: BitWidth = width(8);
        let input: Sym = solver.fresh_havoc(width8);
        let ored: Sym = solver.alu(AluOp::Or, input, Sym::constant(width8, 1), width8);
        let nonzero: Guard = solver.nonzero_guard(ored);
        let zero: Guard = solver.zero_guard(ored);
        assert_eq!(solver.feasible(&[], nonzero), Feasible::Sat);
        assert_eq!(solver.feasible(&[], zero), Feasible::Unsat);
    }

    #[test]
    fn genuine_compare_is_sat_both_ways() {
        let mut solver: SymSolver = SymSolver::new(SolverBudget::default());
        let width8: BitWidth = width(8);
        let lhs: Sym = solver.fresh_havoc(width8);
        let rhs: Sym = solver.fresh_havoc(width8);
        let less: Sym = solver.compare(CmpOp::Ult, lhs, rhs, width8);
        let taken: Guard = solver.nonzero_guard(less);
        let fallthrough: Guard = solver.zero_guard(less);
        assert_eq!(solver.feasible(&[], taken), Feasible::Sat);
        assert_eq!(solver.feasible(&[], fallthrough), Feasible::Sat);
    }

    #[test]
    fn tiny_budget_degrades_to_unknown_not_a_guess() {
        let budget: SolverBudget = SolverBudget {
            per_query_timeout: Duration::from_nanos(1),
            max_conflicts: 0,
            max_decisions: 0,
            cumulative: Duration::from_secs(1),
            max_queries: 16,
        };
        let mut solver: SymSolver = SymSolver::new(budget);
        let width32: BitWidth = width(32);
        let a: Sym = solver.fresh_havoc(width32);
        let square: Sym = solver.alu(AluOp::Mul, a, a, width32);
        let plus: Sym = solver.alu(AluOp::Add, square, a, width32);
        let masked: Sym = solver.alu(AluOp::And, plus, Sym::constant(width32, 1), width32);
        let one: Sym = Sym::constant(width32, 1);
        let equal: Sym = solver.compare(CmpOp::Eq, masked, one, width32);
        let guard: Guard = solver.nonzero_guard(equal);
        assert_eq!(solver.feasible(&[], guard), Feasible::Unknown);
    }
}
