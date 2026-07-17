use std::collections::BTreeMap;
use std::collections::VecDeque;

use crate::cells::{CellStore, CellType};
use crate::lattice::{Confidence, Sign, TypeVar, Width};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constraint {
    Union(TypeVar, TypeVar),
    SignLink(TypeVar, TypeVar),
    Width(TypeVar, Width, Confidence),
    Sign(TypeVar, Sign, Confidence),
}

impl Constraint {
    const fn vars(self) -> [Option<TypeVar>; 2] {
        match self {
            Self::Union(a, b) | Self::SignLink(a, b) => [Some(a), Some(b)],
            Self::Width(a, _, _) | Self::Sign(a, _, _) => [Some(a), None],
        }
    }

    fn apply(self, store: &mut CellStore) -> bool {
        match self {
            Self::Union(a, b) => store.union(a, b),
            Self::SignLink(a, b) => {
                let ca: CellType = store.resolved(a);
                let cb: CellType = store.resolved(b);
                let mut changed: bool = false;
                if ca.class.sign().is_determined() {
                    changed |= store.apply_sign(b, ca.class.sign(), ca.sign_conf);
                }
                if cb.class.sign().is_determined() {
                    changed |= store.apply_sign(a, cb.class.sign(), cb.sign_conf);
                }
                changed
            }
            Self::Width(a, width, conf) => store.apply_width(a, width, conf),
            Self::Sign(a, sign, conf) => store.apply_sign(a, sign, conf),
        }
    }
}

const SOLVE_BUDGET_PER_CONSTRAINT: usize = 64;
const MIN_SOLVE_BUDGET: usize = 4096;

pub fn solve(store: &mut CellStore, constraints: &[Constraint]) {
    if constraints.is_empty() {
        return;
    }
    let mut dependents: BTreeMap<TypeVar, Vec<usize>> = BTreeMap::new();
    for (index, constraint) in constraints.iter().enumerate() {
        for var in constraint.vars().into_iter().flatten() {
            dependents.entry(var).or_default().push(index);
        }
    }
    let mut queued: Vec<bool> = vec![true; constraints.len()];
    let mut queue: VecDeque<usize> = (0..constraints.len()).collect();
    let mut budget: usize = constraints
        .len()
        .saturating_mul(SOLVE_BUDGET_PER_CONSTRAINT)
        .max(MIN_SOLVE_BUDGET);
    while let Some(index) = queue.pop_front() {
        queued[index] = false;
        if budget == 0 {
            break;
        }
        budget -= 1;
        if !constraints[index].apply(store) {
            continue;
        }
        for var in constraints[index].vars().into_iter().flatten() {
            let Some(deps): Option<&Vec<usize>> = dependents.get(&var) else {
                continue;
            };
            for &dep in deps {
                if !queued[dep] {
                    queued[dep] = true;
                    queue.push_back(dep);
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::lattice::TypeClass;

    #[test]
    fn sign_propagates_across_link_chain() {
        let mut store: CellStore = CellStore::new();
        let a: TypeVar = store.fresh(TypeClass::Top);
        let b: TypeVar = store.fresh(TypeClass::Top);
        let c: TypeVar = store.fresh(TypeClass::Top);
        let constraints: Vec<Constraint> = vec![
            Constraint::SignLink(a, b),
            Constraint::SignLink(b, c),
            Constraint::Sign(c, Sign::Unsigned, Confidence::UsageIdiom),
        ];
        solve(&mut store, &constraints);
        assert_eq!(store.resolved(a).class.sign(), Sign::Unsigned);
        assert_eq!(store.resolved(b).class.sign(), Sign::Unsigned);
    }

    #[test]
    fn signlink_keeps_width_independent() {
        let mut store: CellStore = CellStore::new();
        let slot: TypeVar = store.fresh(TypeClass::Top);
        let reg: TypeVar = store.fresh(TypeClass::Top);
        let constraints: Vec<Constraint> = vec![
            Constraint::Width(slot, Width::Byte, Confidence::UsageIdiom),
            Constraint::Width(reg, Width::Dword, Confidence::UsageIdiom),
            Constraint::SignLink(slot, reg),
            Constraint::Sign(reg, Sign::Unsigned, Confidence::UsageIdiom),
        ];
        solve(&mut store, &constraints);
        assert_eq!(store.resolved(slot).class.width(), Width::Byte);
        assert_eq!(store.resolved(slot).class.sign(), Sign::Unsigned);
        assert_eq!(store.resolved(reg).class.width(), Width::Dword);
    }

    #[test]
    fn union_merges_width_and_sign() {
        let mut store: CellStore = CellStore::new();
        let a: TypeVar = store.fresh(TypeClass::Top);
        let b: TypeVar = store.fresh(TypeClass::Top);
        let constraints: Vec<Constraint> = vec![
            Constraint::Width(a, Width::Qword, Confidence::UsageIdiom),
            Constraint::Sign(b, Sign::Signed, Confidence::UsageIdiom),
            Constraint::Union(a, b),
        ];
        solve(&mut store, &constraints);
        let cell: CellType = store.resolved(a);
        assert_eq!(cell.class.width(), Width::Qword);
        assert_eq!(cell.class.sign(), Sign::Signed);
    }
}
