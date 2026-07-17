use crate::lattice::{Confidence, Sign, TypeClass, TypeVar, Width};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellType {
    pub class: TypeClass,
    pub width_conf: Confidence,
    pub sign_conf: Confidence,
    pub sign_conflict: bool,
}

impl CellType {
    #[must_use]
    pub const fn top() -> Self {
        Self {
            class: TypeClass::Top,
            width_conf: Confidence::RawArith,
            sign_conf: Confidence::RawArith,
            sign_conflict: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CellStore {
    parent: Vec<u32>,
    rank: Vec<u8>,
    ty: Vec<CellType>,
}

impl CellStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.parent.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.parent.is_empty()
    }

    pub fn fresh(&mut self, class: TypeClass) -> TypeVar {
        let index: usize = self.parent.len();
        let id: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        self.parent.push(id);
        self.rank.push(0);
        self.ty.push(CellType {
            class,
            ..CellType::top()
        });
        TypeVar(id)
    }

    #[must_use]
    pub fn find(&mut self, var: TypeVar) -> TypeVar {
        let mut root: u32 = var.0;
        while self.parent[root as usize] != root {
            root = self.parent[root as usize];
        }
        let mut cursor: u32 = var.0;
        while self.parent[cursor as usize] != root {
            let next: u32 = self.parent[cursor as usize];
            self.parent[cursor as usize] = root;
            cursor = next;
        }
        TypeVar(root)
    }

    #[must_use]
    pub fn resolved(&mut self, var: TypeVar) -> CellType {
        let root: TypeVar = self.find(var);
        self.ty[root.0 as usize]
    }

    pub fn apply_width(&mut self, var: TypeVar, width: Width, conf: Confidence) -> bool {
        let root: TypeVar = self.find(var);
        let cell: &mut CellType = &mut self.ty[root.0 as usize];
        let widened: Width = cell.class.width().join(width);
        if widened == cell.class.width() && conf <= cell.width_conf {
            return false;
        }
        cell.class = set_width(cell.class, widened);
        if conf > cell.width_conf {
            cell.width_conf = conf;
        }
        true
    }

    pub fn apply_sign(&mut self, var: TypeVar, sign: Sign, conf: Confidence) -> bool {
        if !sign.is_determined() {
            return false;
        }
        let root: TypeVar = self.find(var);
        let cell: &mut CellType = &mut self.ty[root.0 as usize];
        let current: Sign = cell.class.sign();
        let (next_sign, next_conf, conflict): (Sign, Confidence, bool) = match current {
            Sign::Unknown => (sign, conf, cell.sign_conflict),
            Sign::Conflict => {
                if conf > cell.sign_conf {
                    (sign, conf, cell.sign_conflict)
                } else {
                    (Sign::Conflict, cell.sign_conf, true)
                }
            }
            existing if existing == sign => {
                (existing, cell.sign_conf.max(conf), cell.sign_conflict)
            }
            _ => match conf.cmp(&cell.sign_conf) {
                core::cmp::Ordering::Greater => (sign, conf, cell.sign_conflict),
                core::cmp::Ordering::Less => (current, cell.sign_conf, cell.sign_conflict),
                core::cmp::Ordering::Equal => (Sign::Conflict, cell.sign_conf, true),
            },
        };
        let changed: bool = next_sign != current || conflict != cell.sign_conflict;
        cell.class = set_sign(cell.class, next_sign);
        cell.sign_conf = next_conf;
        cell.sign_conflict = conflict;
        changed
    }

    pub fn mark_sign_conflict(&mut self, var: TypeVar) -> bool {
        let root: TypeVar = self.find(var);
        let cell: &mut CellType = &mut self.ty[root.0 as usize];
        if cell.class.sign() == Sign::Conflict && cell.sign_conflict {
            return false;
        }
        cell.class = set_sign(cell.class, Sign::Conflict);
        cell.sign_conflict = true;
        true
    }

    pub fn union(&mut self, a: TypeVar, b: TypeVar) -> bool {
        let ra: TypeVar = self.find(a);
        let rb: TypeVar = self.find(b);
        if ra == rb {
            return false;
        }
        let ta: CellType = self.ty[ra.0 as usize];
        let tb: CellType = self.ty[rb.0 as usize];
        let merged: CellType = combine(ta, tb);
        let (keep, drop): (TypeVar, TypeVar) =
            if self.rank[ra.0 as usize] >= self.rank[rb.0 as usize] {
                (ra, rb)
            } else {
                (rb, ra)
            };
        self.parent[drop.0 as usize] = keep.0;
        if self.rank[ra.0 as usize] == self.rank[rb.0 as usize] {
            self.rank[keep.0 as usize] = self.rank[keep.0 as usize].saturating_add(1);
        }
        self.ty[keep.0 as usize] = merged;
        true
    }
}

const fn set_width(class: TypeClass, width: Width) -> TypeClass {
    match class {
        TypeClass::Top => TypeClass::Numeric {
            width,
            sign: Sign::Unknown,
        },
        TypeClass::Numeric { sign, .. } => TypeClass::Numeric { width, sign },
        TypeClass::Float { .. } => TypeClass::Float { width },
        other => other,
    }
}

const fn set_sign(class: TypeClass, sign: Sign) -> TypeClass {
    match class {
        TypeClass::Top => TypeClass::Numeric {
            width: Width::Unknown,
            sign,
        },
        TypeClass::Numeric { width, .. } => TypeClass::Numeric { width, sign },
        other => other,
    }
}

fn combine(a: CellType, b: CellType) -> CellType {
    match (a.class, b.class) {
        (
            TypeClass::Numeric { .. } | TypeClass::Top,
            TypeClass::Numeric { .. } | TypeClass::Top,
        ) => {
            let width: Width = a.class.width().join(b.class.width());
            let (sign, sign_conf, sign_conflict): (Sign, Confidence, bool) = combine_sign(a, b);
            CellType {
                class: TypeClass::Numeric { width, sign },
                width_conf: a.width_conf.max(b.width_conf),
                sign_conf,
                sign_conflict,
            }
        }
        _ => CellType {
            class: a.class.meet(b.class),
            width_conf: a.width_conf.max(b.width_conf),
            sign_conf: a.sign_conf.max(b.sign_conf),
            sign_conflict: a.sign_conflict || b.sign_conflict,
        },
    }
}

fn combine_sign(a: CellType, b: CellType) -> (Sign, Confidence, bool) {
    let sa: Sign = a.class.sign();
    let sb: Sign = b.class.sign();
    match (sa, sb) {
        (Sign::Unknown, _) => (sb, b.sign_conf, a.sign_conflict || b.sign_conflict),
        (_, Sign::Unknown) => (sa, a.sign_conf, a.sign_conflict || b.sign_conflict),
        (Sign::Conflict, _) | (_, Sign::Conflict) => {
            (Sign::Conflict, a.sign_conf.max(b.sign_conf), true)
        }
        _ if sa == sb => (
            sa,
            a.sign_conf.max(b.sign_conf),
            a.sign_conflict || b.sign_conflict,
        ),
        _ => match a.sign_conf.cmp(&b.sign_conf) {
            core::cmp::Ordering::Greater => (sa, a.sign_conf, a.sign_conflict || b.sign_conflict),
            core::cmp::Ordering::Less => (sb, b.sign_conf, a.sign_conflict || b.sign_conflict),
            core::cmp::Ordering::Equal => (Sign::Conflict, a.sign_conf, true),
        },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn union_shares_representative_and_merges() {
        let mut store: CellStore = CellStore::new();
        let a: TypeVar = store.fresh(TypeClass::Top);
        let b: TypeVar = store.fresh(TypeClass::Top);
        store.apply_width(a, Width::Dword, Confidence::UsageIdiom);
        store.apply_sign(b, Sign::Signed, Confidence::UsageIdiom);
        assert!(store.union(a, b));
        assert_eq!(store.find(a), store.find(b));
        let merged: CellType = store.resolved(a);
        assert_eq!(merged.class.width(), Width::Dword);
        assert_eq!(merged.class.sign(), Sign::Signed);
    }

    #[test]
    fn apply_sign_equal_confidence_conflict_degrades() {
        let mut store: CellStore = CellStore::new();
        let a: TypeVar = store.fresh(TypeClass::Top);
        assert!(store.apply_sign(a, Sign::Signed, Confidence::UsageIdiom));
        assert!(store.apply_sign(a, Sign::Unsigned, Confidence::UsageIdiom));
        let cell: CellType = store.resolved(a);
        assert_eq!(cell.class.sign(), Sign::Conflict);
        assert!(cell.sign_conflict);
    }

    #[test]
    fn higher_confidence_overrides_sign() {
        let mut store: CellStore = CellStore::new();
        let a: TypeVar = store.fresh(TypeClass::Top);
        assert!(store.apply_sign(a, Sign::Signed, Confidence::UsageIdiom));
        assert!(store.apply_sign(a, Sign::Unsigned, Confidence::Metadata));
        assert_eq!(store.resolved(a).class.sign(), Sign::Unsigned);
    }

    #[test]
    fn width_join_widens_on_apply() {
        let mut store: CellStore = CellStore::new();
        let a: TypeVar = store.fresh(TypeClass::Top);
        assert!(store.apply_width(a, Width::Byte, Confidence::UsageIdiom));
        assert!(store.apply_width(a, Width::Qword, Confidence::UsageIdiom));
        assert_eq!(store.resolved(a).class.width(), Width::Qword);
        assert!(!store.apply_width(a, Width::Word, Confidence::UsageIdiom));
    }

    #[test]
    fn find_compresses_long_chain() {
        let mut store: CellStore = CellStore::new();
        let first: TypeVar = store.fresh(TypeClass::Top);
        let mut prev: TypeVar = first;
        for _ in 0..64 {
            let next: TypeVar = store.fresh(TypeClass::Top);
            store.union(prev, next);
            prev = next;
        }
        assert_eq!(store.find(first), store.find(prev));
    }
}
