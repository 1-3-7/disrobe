use std::collections::BTreeMap;

use crate::cells::CellType;
use crate::constraint::solve;
use crate::facts::{FactSet, extract, extract_split};
use crate::lattice::{Sign, TypeVar, Width};
use crate::memssa::VersionInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredScalar {
    pub width: Width,
    pub sign: Sign,
    pub sign_conflict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredObject {
    pub offset: i64,
    pub width: Width,
    pub sign: Sign,
    pub sign_conflict: bool,
    pub live_lo: u64,
    pub live_hi: u64,
    pub escaped: bool,
}

impl RecoveredObject {
    #[must_use]
    pub const fn scalar(&self) -> RecoveredScalar {
        RecoveredScalar {
            width: self.width,
            sign: self.sign,
            sign_conflict: self.sign_conflict,
        }
    }

    #[must_use]
    pub const fn covers(&self, lo: u64, hi: u64) -> bool {
        self.live_lo <= self.live_hi && self.live_lo < hi && lo <= self.live_hi
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecoveredFunction {
    pub rbp_slots: BTreeMap<i64, RecoveredScalar>,
    pub objects: Vec<RecoveredObject>,
    pub has_frame_pointer: bool,
}

impl RecoveredFunction {
    #[must_use]
    pub fn slot(&self, rbp_disp: i64) -> Option<RecoveredScalar> {
        self.rbp_slots.get(&rbp_disp).copied()
    }

    #[must_use]
    pub fn objects_covering(&self, offset: i64, lo: u64, hi: u64) -> Vec<RecoveredObject> {
        self.objects
            .iter()
            .filter(|object: &&RecoveredObject| object.offset == offset && object.covers(lo, hi))
            .copied()
            .collect()
    }
}

#[must_use]
pub fn recover_function(bytes: &[u8], base: u64) -> RecoveredFunction {
    let (rbp_slots, has_frame_pointer): (BTreeMap<i64, RecoveredScalar>, bool) =
        recover_merge(bytes, base);
    let objects: Vec<RecoveredObject> = recover_split(bytes, base);
    RecoveredFunction {
        rbp_slots,
        objects,
        has_frame_pointer,
    }
}

fn recover_merge(bytes: &[u8], base: u64) -> (BTreeMap<i64, RecoveredScalar>, bool) {
    let mut facts: FactSet = extract(bytes, base);
    let has_frame_pointer: bool = facts.has_frame_pointer;
    solve(&mut facts.store, &facts.constraints);
    let pairs: Vec<(i64, TypeVar)> = facts
        .rbp_slots
        .iter()
        .map(|(disp, cell): (&i64, &TypeVar)| (*disp, *cell))
        .collect();
    let mut rbp_slots: BTreeMap<i64, RecoveredScalar> = BTreeMap::new();
    for (disp, cell) in pairs {
        rbp_slots.insert(disp, scalar_of(&mut facts.store, cell));
    }
    (rbp_slots, has_frame_pointer)
}

fn recover_split(bytes: &[u8], base: u64) -> Vec<RecoveredObject> {
    let mut facts: FactSet = extract_split(bytes, base);
    solve(&mut facts.store, &facts.constraints);
    let versions: Vec<VersionInfo> = facts.ssa.versions().to_vec();
    let mut objects: Vec<RecoveredObject> = Vec::new();
    for version in versions {
        if version.is_phi || version.live_hi < version.live_lo {
            continue;
        }
        let scalar: RecoveredScalar = scalar_of(&mut facts.store, version.cell);
        objects.push(RecoveredObject {
            offset: version.offset,
            width: scalar.width,
            sign: scalar.sign,
            sign_conflict: scalar.sign_conflict,
            live_lo: version.live_lo,
            live_hi: version.live_hi,
            escaped: version.escaped,
        });
    }
    objects
}

fn scalar_of(store: &mut crate::cells::CellStore, cell: TypeVar) -> RecoveredScalar {
    let resolved: CellType = store.resolved(cell);
    let raw_sign: Sign = resolved.class.sign();
    RecoveredScalar {
        width: resolved.class.width(),
        sign: emit_sign(raw_sign),
        sign_conflict: resolved.sign_conflict || raw_sign == Sign::Conflict,
    }
}

const fn emit_sign(sign: Sign) -> Sign {
    match sign {
        Sign::Signed => Sign::Signed,
        Sign::Unsigned => Sign::Unsigned,
        Sign::Unknown | Sign::Conflict => Sign::Unknown,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn conflict_sign_is_reported_as_unknown_not_guessed() {
        assert_eq!(emit_sign(Sign::Conflict), Sign::Unknown);
        assert_eq!(emit_sign(Sign::Unknown), Sign::Unknown);
        assert_eq!(emit_sign(Sign::Signed), Sign::Signed);
        assert_eq!(emit_sign(Sign::Unsigned), Sign::Unsigned);
    }

    #[test]
    fn recovers_signed_qword_slot_from_prologue_and_sar() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x48, 0xc1,
            0xf8, 0x03, 0x5d, 0xc3,
        ];
        let recovered: RecoveredFunction = recover_function(bytes, 0x1000);
        assert!(recovered.has_frame_pointer);
        let slot: RecoveredScalar = recovered.slot(0x10).expect("slot present");
        assert_eq!(slot.width, Width::Qword);
        assert_eq!(slot.sign, Sign::Signed);
    }

    #[test]
    fn split_objects_expose_two_reused_definitions() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x85, 0xc9, 0x7e, 0x0a, 0x48, 0x89, 0x4d, 0x00, 0x48, 0xc1,
            0x7d, 0x00, 0x02, 0xeb, 0x08, 0x48, 0x89, 0x45, 0x00, 0x48, 0xd1, 0x6d, 0x00, 0x48,
            0x8b, 0x45, 0x00, 0x5d, 0xc3,
        ];
        let recovered: RecoveredFunction = recover_function(bytes, 0x1000);
        let at_zero: Vec<&RecoveredObject> = recovered
            .objects
            .iter()
            .filter(|object: &&RecoveredObject| object.offset == 0)
            .collect();
        assert!(
            at_zero.len() >= 2,
            "the reused slot must surface at least two objects",
        );
        let signs: Vec<Sign> = at_zero
            .iter()
            .map(|object: &&RecoveredObject| object.sign)
            .collect();
        assert!(signs.contains(&Sign::Signed));
        assert!(signs.contains(&Sign::Unsigned));
        let merged: RecoveredScalar = recovered.slot(0).expect("merged slot present");
        assert_eq!(
            merged.sign,
            Sign::Unknown,
            "the merge view abstains on the conflicting reuse",
        );
    }
}
