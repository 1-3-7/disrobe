use std::collections::BTreeMap;

use crate::cells::CellType;
use crate::constraint::solve;
use crate::facts::{FactSet, extract};
use crate::lattice::{Sign, TypeVar, Width};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredScalar {
    pub width: Width,
    pub sign: Sign,
    pub sign_conflict: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RecoveredFunction {
    pub rbp_slots: BTreeMap<i64, RecoveredScalar>,
    pub has_frame_pointer: bool,
}

impl RecoveredFunction {
    #[must_use]
    pub fn slot(&self, rbp_disp: i64) -> Option<RecoveredScalar> {
        self.rbp_slots.get(&rbp_disp).copied()
    }
}

#[must_use]
pub fn recover_function(bytes: &[u8], base: u64) -> RecoveredFunction {
    let mut facts: FactSet = extract(bytes, base);
    solve(&mut facts.store, &facts.constraints);
    let pairs: Vec<(i64, TypeVar)> = facts
        .rbp_slots
        .iter()
        .map(|(disp, cell): (&i64, &TypeVar)| (*disp, *cell))
        .collect();
    let mut rbp_slots: BTreeMap<i64, RecoveredScalar> = BTreeMap::new();
    for (disp, cell) in pairs {
        let resolved: CellType = facts.store.resolved(cell);
        let raw_sign: Sign = resolved.class.sign();
        rbp_slots.insert(
            disp,
            RecoveredScalar {
                width: resolved.class.width(),
                sign: emit_sign(raw_sign),
                sign_conflict: resolved.sign_conflict || raw_sign == Sign::Conflict,
            },
        );
    }
    RecoveredFunction {
        rbp_slots,
        has_frame_pointer: facts.has_frame_pointer,
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
}
