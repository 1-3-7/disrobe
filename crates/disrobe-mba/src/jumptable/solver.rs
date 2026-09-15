use oxiz::TermId;

use super::{
    ExecOutcome, IndexBound, IndirectSite, JumpTableAbstain, JumpTableResolution, Provenance,
    RejectCause, ResolveTier, SectionMap, Successor, SuccessorKind, TableForm, VsaOutcome,
    is_contiguous_low_mask, read_table_target, try_resolve_vsa,
};
use crate::symexec::explore::SymexecBudget;
use crate::symexec::solver::{Feasible, Guard, SymSolver};
use crate::symexec::value::{BitWidth, CmpOp, Sym};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interval {
    Range { lo: u64, hi: u64 },
    Empty,
    Unbounded,
    Unsupported,
}

fn feasible_interval(bounds: &[IndexBound], ceiling: u64) -> Interval {
    let mut lo: u64 = 0;
    let mut hi: u64 = ceiling;
    let mut bounded_above: bool = false;
    for bound in bounds {
        match bound {
            IndexBound::UnsignedAtMost(value) => {
                hi = hi.min(*value);
                bounded_above = true;
            }
            IndexBound::UnsignedLessThan(value) => {
                let Some(top): Option<u64> = value.checked_sub(1) else {
                    return Interval::Empty;
                };
                hi = hi.min(top);
                bounded_above = true;
            }
            IndexBound::UnsignedAtLeast(value) => {
                lo = lo.max(*value);
            }
            IndexBound::Mask(mask) => {
                if !is_contiguous_low_mask(*mask) {
                    return Interval::Unsupported;
                }
                hi = hi.min(*mask);
                bounded_above = true;
            }
            IndexBound::NotEqual(_) => {}
        }
    }
    if !bounded_above {
        return Interval::Unbounded;
    }
    if lo > hi {
        return Interval::Empty;
    }
    Interval::Range { lo, hi }
}

fn excluded_indices(bounds: &[IndexBound], lo: u64, hi: u64) -> Vec<u64> {
    bounds
        .iter()
        .filter_map(|bound: &IndexBound| match bound {
            IndexBound::NotEqual(value) if lo <= *value && *value <= hi => Some(*value),
            _ => None,
        })
        .collect()
}

#[must_use]
pub fn resolve_jump_table(site: &IndirectSite, sections: &SectionMap) -> JumpTableResolution {
    resolve_jump_table_with(site, sections, SymexecBudget::bounded_default())
}

#[must_use]
pub fn resolve_jump_table_with(
    site: &IndirectSite,
    sections: &SectionMap,
    budget: SymexecBudget,
) -> JumpTableResolution {
    resolve_jump_table_traced(site, sections, budget).0
}

pub(crate) fn resolve_jump_table_traced(
    site: &IndirectSite,
    sections: &SectionMap,
    budget: SymexecBudget,
) -> (JumpTableResolution, ResolveTier) {
    match try_resolve_vsa(site, sections) {
        VsaOutcome::Decided(resolution) => (resolution, ResolveTier::CheapVsa),
        VsaOutcome::SolverRequired => (solver_resolve(site, sections, budget), ResolveTier::Solver),
    }
}

pub(crate) fn solver_resolve(
    site: &IndirectSite,
    sections: &SectionMap,
    budget: SymexecBudget,
) -> JumpTableResolution {
    let form: TableForm = site.form;
    if form.stride == 0 || BitWidth::from_bytes(form.entry_bytes).is_none() {
        return JumpTableResolution::Abstain(JumpTableAbstain::StructureInvalid);
    }
    let Some(width): Option<BitWidth> = BitWidth::from_bytes(site.path.index_bytes) else {
        return JumpTableResolution::Abstain(JumpTableAbstain::StructureInvalid);
    };
    if sections.table_region_writable(form.table_base) {
        return JumpTableResolution::Abstain(JumpTableAbstain::WritableTable);
    }
    let cap: u64 = super::MAX_TABLE_ENTRIES.saturating_sub(1).min(width.mask());
    let (lo, hi): (u64, u64) = match feasible_interval(&site.path.bounds, width.mask()) {
        Interval::Range { lo, hi } => (lo, hi),
        Interval::Empty => return JumpTableResolution::Abstain(JumpTableAbstain::EmptyFeasibleSet),
        Interval::Unbounded => {
            return JumpTableResolution::Abstain(JumpTableAbstain::IndexUnbounded);
        }
        Interval::Unsupported => {
            return JumpTableResolution::Abstain(JumpTableAbstain::UnsupportedConstraint);
        }
    };
    if hi > cap || hi.saturating_sub(lo) >= super::MAX_TABLE_ENTRIES {
        return JumpTableResolution::Abstain(JumpTableAbstain::IndexUnbounded);
    }
    let excluded: Vec<u64> = excluded_indices(&site.path.bounds, lo, hi);
    let mut resolver: Resolver = Resolver::new(width, budget);
    if resolver.assert_bounds(&site.path.bounds).is_err() {
        return JumpTableResolution::Abstain(JumpTableAbstain::StructureInvalid);
    }
    resolver.resolve(site, sections, lo, hi, &excluded)
}

struct Resolver {
    solver: SymSolver,
    index: Sym,
    width: BitWidth,
    pi: Vec<TermId>,
}

impl Resolver {
    fn new(width: BitWidth, budget: SymexecBudget) -> Self {
        let mut solver: SymSolver = SymSolver::new(budget.solver());
        let index: Sym = solver.fresh_havoc(width);
        Self {
            solver,
            index,
            width,
            pi: Vec::new(),
        }
    }

    fn assert_bounds(&mut self, bounds: &[IndexBound]) -> Result<(), ()> {
        for bound in bounds {
            if matches!(bound, IndexBound::NotEqual(_)) {
                continue;
            }
            let predicate: Sym = self.bound_predicate(*bound);
            let Some(term): Option<TermId> = pred_of(predicate) else {
                return Err(());
            };
            self.pi.push(term);
        }
        Ok(())
    }

    fn bound_predicate(&mut self, bound: IndexBound) -> Sym {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        match bound {
            IndexBound::UnsignedAtMost(value) | IndexBound::Mask(value) => self.solver.compare(
                CmpOp::Ule,
                index,
                Sym::constant(width, value),
                BitWidth::BYTE,
            ),
            IndexBound::UnsignedLessThan(value) => self.solver.compare(
                CmpOp::Ult,
                index,
                Sym::constant(width, value),
                BitWidth::BYTE,
            ),
            IndexBound::UnsignedAtLeast(value) => self.solver.compare(
                CmpOp::Ule,
                Sym::constant(width, value),
                index,
                BitWidth::BYTE,
            ),
            IndexBound::NotEqual(value) => self.solver.compare(
                CmpOp::Ne,
                index,
                Sym::constant(width, value),
                BitWidth::BYTE,
            ),
        }
    }

    fn sat(&mut self, predicate: Sym) -> Feasible {
        let Some(term): Option<TermId> = pred_of(predicate) else {
            return Feasible::Unknown;
        };
        self.solver.feasible(&self.pi, Guard::Term(term))
    }

    fn index_gt(&mut self, bound: u64) -> Feasible {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        let predicate: Sym = self.solver.compare(
            CmpOp::Ult,
            Sym::constant(width, bound),
            index,
            BitWidth::BYTE,
        );
        self.sat(predicate)
    }

    fn index_lt(&mut self, bound: u64) -> Feasible {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        let predicate: Sym = self.solver.compare(
            CmpOp::Ult,
            index,
            Sym::constant(width, bound),
            BitWidth::BYTE,
        );
        self.sat(predicate)
    }

    fn index_eq(&mut self, value: u64) -> Feasible {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        let predicate: Sym = self.solver.compare(
            CmpOp::Eq,
            index,
            Sym::constant(width, value),
            BitWidth::BYTE,
        );
        self.sat(predicate)
    }

    fn confirm_bounds(&mut self, lo: u64, hi: u64) -> Option<JumpTableAbstain> {
        match self.index_gt(hi) {
            Feasible::Unsat => {}
            Feasible::Sat => return Some(JumpTableAbstain::SolverBoundMismatch),
            Feasible::Unknown => return Some(JumpTableAbstain::SolverUnknown),
        }
        if lo > 0 {
            match self.index_lt(lo) {
                Feasible::Unsat => {}
                Feasible::Sat => return Some(JumpTableAbstain::SolverBoundMismatch),
                Feasible::Unknown => return Some(JumpTableAbstain::SolverUnknown),
            }
        }
        None
    }

    fn resolve(
        &mut self,
        site: &IndirectSite,
        sections: &SectionMap,
        lo: u64,
        hi: u64,
        excluded: &[u64],
    ) -> JumpTableResolution {
        if self.solver.cumulative_exhausted() {
            return JumpTableResolution::Abstain(JumpTableAbstain::SolverBudget);
        }
        if let Some(reason) = self.confirm_bounds(lo, hi) {
            return JumpTableResolution::Abstain(reason);
        }
        self.enumerate(site, sections, lo, hi, excluded)
    }

    fn enumerate(
        &mut self,
        site: &IndirectSite,
        sections: &SectionMap,
        lo: u64,
        hi: u64,
        excluded: &[u64],
    ) -> JumpTableResolution {
        let mut successors: Vec<Successor> = Vec::new();
        let mut rejected: Vec<(u64, RejectCause)> = Vec::new();
        let mut index: u64 = lo;
        while index <= hi {
            if excluded.contains(&index) {
                let Some(next): Option<u64> = index.checked_add(1) else {
                    break;
                };
                index = next;
                continue;
            }
            if self.solver.cumulative_exhausted() {
                return JumpTableResolution::Abstain(JumpTableAbstain::SolverBudget);
            }
            match self.index_eq(index) {
                Feasible::Sat => match read_table_target(&site.form, sections, index) {
                    Ok(target) => successors.push(Successor {
                        table_index: index,
                        case_value: index.wrapping_add(site.form.case_base),
                        target,
                        kind: SuccessorKind::Case,
                    }),
                    Err(cause) => rejected.push((index, cause)),
                },
                Feasible::Unsat => {
                    return JumpTableResolution::Abstain(JumpTableAbstain::SolverBoundMismatch);
                }
                Feasible::Unknown => {
                    return JumpTableResolution::Abstain(JumpTableAbstain::SolverUnknown);
                }
            }
            let Some(next): Option<u64> = index.checked_add(1) else {
                break;
            };
            index = next;
        }
        if !rejected.is_empty() {
            return JumpTableResolution::Abstain(JumpTableAbstain::IncompleteRecovery { rejected });
        }
        if let Some(default) = site.default_target
            && sections.exec_check(default) == ExecOutcome::Valid
        {
            successors.push(Successor {
                table_index: u64::MAX,
                case_value: u64::MAX,
                target: default,
                kind: SuccessorKind::Default,
            });
        }
        JumpTableResolution::Resolved {
            successors,
            provenance: Provenance {
                table_base: site.form.table_base,
                bound_lo: lo,
                bound_hi: hi,
                entry_count: hi - lo + 1,
            },
        }
    }
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Resolver")
            .field("width", &self.width)
            .field("pi_len", &self.pi.len())
            .finish_non_exhaustive()
    }
}

const fn pred_of(value: Sym) -> Option<TermId> {
    match value {
        Sym::Bool { pred, .. } => Some(pred),
        Sym::Const { .. } | Sym::Bv { .. } => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::jumptable::{
        Endian, EntryKind, PathConstraint, Perms, Section, resolve_jump_table_vsa,
    };

    const TEXT_BASE: u64 = 0x1000;
    const RODATA_BASE: u64 = 0x4000;

    fn code_section(starts: &[u64]) -> Section {
        let set: BTreeSet<u64> = starts.iter().copied().collect();
        Section::new(TEXT_BASE, vec![0x90; 0x400], Perms::code(), false).with_insn_starts(set)
    }

    fn le64(values: &[u64]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value: &u64| value.to_le_bytes())
            .collect()
    }

    fn rodata(bytes: Vec<u8>) -> Section {
        Section::new(RODATA_BASE, bytes, Perms::ro(), true)
    }

    fn sorted_targets(resolution: &JumpTableResolution) -> Vec<u64> {
        let mut out: Vec<u64> = resolution
            .cases()
            .iter()
            .map(|successor: &Successor| successor.target)
            .collect();
        out.sort_unstable();
        out
    }

    fn absolute_form() -> TableForm {
        TableForm {
            table_base: RODATA_BASE,
            stride: 8,
            entry_bytes: 8,
            endian: Endian::Little,
            entry: EntryKind::AbsolutePointer,
            case_base: 0,
        }
    }

    #[test]
    fn masked_index_takes_the_cheap_tier_and_matches_the_solver() {
        let bodies: [u64; 8] = [
            0x1100, 0x1108, 0x1110, 0x1118, 0x1120, 0x1128, 0x1130, 0x1138,
        ];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: absolute_form(),
            path: PathConstraint::new(4, vec![IndexBound::Mask(0x7)]),
            default_target: None,
        };
        let (resolution, tier): (JumpTableResolution, ResolveTier) =
            resolve_jump_table_traced(&site, &sections, SymexecBudget::bounded_default());
        assert_eq!(tier, ResolveTier::CheapVsa);
        assert_eq!(
            resolution,
            solver_resolve_only(&site, &sections),
            "the cheap tier must agree with the solver-backed enumeration"
        );
    }

    #[test]
    fn compare_guarded_index_takes_the_cheap_tier() {
        let bodies: [u64; 4] = [0x1100, 0x1108, 0x1110, 0x1118];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: absolute_form(),
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(3)]),
            default_target: None,
        };
        let (resolution, tier): (JumpTableResolution, ResolveTier) =
            resolve_jump_table_traced(&site, &sections, SymexecBudget::bounded_default());
        assert_eq!(tier, ResolveTier::CheapVsa);
        assert_eq!(resolution, resolve_jump_table_vsa(&site, &sections));
        assert_eq!(resolution, solver_resolve_only(&site, &sections));
    }

    fn solver_resolve_only(site: &IndirectSite, sections: &SectionMap) -> JumpTableResolution {
        solver_resolve(site, sections, SymexecBudget::bounded_default())
    }

    #[test]
    fn disequality_hole_falls_back_to_the_solver_and_resolves_the_exact_set() {
        let bodies: [u64; 4] = [0x1100, 0x1108, 0x1110, 0x1118];
        let sections: SectionMap = SectionMap::new(vec![
            code_section(&[0x1100, 0x1108, 0x1110, 0x1118, 0x1200]),
            rodata(le64(&bodies)),
        ]);
        let site: IndirectSite = IndirectSite {
            form: absolute_form(),
            path: PathConstraint::new(
                4,
                vec![IndexBound::UnsignedAtMost(3), IndexBound::NotEqual(2)],
            ),
            default_target: Some(0x1200),
        };
        let (resolution, tier): (JumpTableResolution, ResolveTier) =
            resolve_jump_table_traced(&site, &sections, SymexecBudget::bounded_default());
        assert_eq!(tier, ResolveTier::Solver);
        let indices: Vec<u64> = resolution
            .cases()
            .iter()
            .map(|successor: &Successor| successor.table_index)
            .collect();
        assert_eq!(indices, vec![0, 1, 3]);
        assert_eq!(sorted_targets(&resolution), vec![0x1100, 0x1108, 0x1118]);
        let default: Vec<&Successor> = resolution
            .successors()
            .iter()
            .filter(|successor: &&Successor| successor.kind == SuccessorKind::Default)
            .collect();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].target, 0x1200);
    }

    #[test]
    fn solver_bound_mismatch_still_fires_for_a_non_hole_infeasibility() {
        let bodies: [u64; 4] = [0x1100, 0x1108, 0x1110, 0x1118];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: absolute_form(),
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(3)]),
            default_target: None,
        };
        assert_eq!(
            solver_resolve_only(&site, &sections),
            resolve_jump_table_vsa(&site, &sections)
        );
    }
}
