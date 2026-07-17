use std::collections::{BTreeMap, BTreeSet};

use crate::cells::CellType;
use crate::constraint::solve;
use crate::facts::{FactSet, extract, extract_split};
use crate::lattice::{Sign, TypeVar, Width};
use crate::memssa::VersionInfo;
use crate::structrec::{self, RecoveredStruct};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CIntType {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
}

impl CIntType {
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::I8 => "int8_t",
            Self::U8 => "uint8_t",
            Self::I16 => "int16_t",
            Self::U16 => "uint16_t",
            Self::I32 => "int32_t",
            Self::U32 => "uint32_t",
            Self::I64 => "int64_t",
            Self::U64 => "uint64_t",
        }
    }

    #[must_use]
    pub const fn width(self) -> Width {
        match self {
            Self::I8 | Self::U8 => Width::Byte,
            Self::I16 | Self::U16 => Width::Word,
            Self::I32 | Self::U32 => Width::Dword,
            Self::I64 | Self::U64 => Width::Qword,
        }
    }

    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64)
    }

    const fn from_width_sign(width: Width, sign: Sign) -> Option<Self> {
        match (width, sign) {
            (Width::Byte, Sign::Signed) => Some(Self::I8),
            (Width::Byte, Sign::Unsigned) => Some(Self::U8),
            (Width::Word, Sign::Signed) => Some(Self::I16),
            (Width::Word, Sign::Unsigned) => Some(Self::U16),
            (Width::Dword, Sign::Signed) => Some(Self::I32),
            (Width::Dword, Sign::Unsigned) => Some(Self::U32),
            (Width::Qword, Sign::Signed) => Some(Self::I64),
            (Width::Qword, Sign::Unsigned) => Some(Self::U64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TypedFunction {
    pub rbp_slots: BTreeMap<i64, RecoveredScalar>,
    pub objects: Vec<RecoveredObject>,
    pub structs: Vec<RecoveredStruct>,
    pub has_frame_pointer: bool,
}

impl TypedFunction {
    #[must_use]
    pub fn struct_at(&self, slot: i64) -> Option<&RecoveredStruct> {
        self.structs
            .iter()
            .find(|item: &&RecoveredStruct| item.slot == slot)
    }

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

    #[must_use]
    pub fn typed_slot(&self, rbp_disp: i64) -> Option<CIntType> {
        let live: Vec<&RecoveredObject> = self
            .objects
            .iter()
            .filter(|object: &&RecoveredObject| object.offset == rbp_disp)
            .collect();
        let [object]: [&RecoveredObject; 1] = live.try_into().ok()?;
        if object.escaped || object.sign_conflict {
            return None;
        }
        CIntType::from_width_sign(object.width, object.sign)
    }

    #[must_use]
    pub fn typed_slots(&self) -> BTreeMap<i64, CIntType> {
        let mut offsets: BTreeSet<i64> = BTreeSet::new();
        for object in &self.objects {
            offsets.insert(object.offset);
        }
        let mut out: BTreeMap<i64, CIntType> = BTreeMap::new();
        for offset in offsets {
            if let Some(cint) = self.typed_slot(offset) {
                out.insert(offset, cint);
            }
        }
        out
    }
}

#[must_use]
pub fn recover_function(bytes: &[u8], base: u64) -> TypedFunction {
    let (rbp_slots, has_frame_pointer): (BTreeMap<i64, RecoveredScalar>, bool) =
        recover_merge(bytes, base);
    let objects: Vec<RecoveredObject> = recover_split(bytes, base);
    let structs: Vec<RecoveredStruct> = structrec::recover_structs(bytes, base);
    TypedFunction {
        rbp_slots,
        objects,
        structs,
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
        let recovered: TypedFunction = recover_function(bytes, 0x1000);
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
        let recovered: TypedFunction = recover_function(bytes, 0x1000);
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

    #[test]
    fn typed_slot_reports_signed_qword_when_single_and_determined() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x48, 0xc1,
            0xf8, 0x03, 0x5d, 0xc3,
        ];
        let recovered: TypedFunction = recover_function(bytes, 0x1000);
        assert_eq!(recovered.typed_slot(0x10), Some(CIntType::I64));
        assert!(recovered.typed_slots().get(&0x10) == Some(&CIntType::I64));
    }

    #[test]
    fn typed_slot_abstains_on_a_reused_slot_with_two_versions() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x85, 0xc9, 0x7e, 0x0a, 0x48, 0x89, 0x4d, 0x00, 0x48, 0xc1,
            0x7d, 0x00, 0x02, 0xeb, 0x08, 0x48, 0x89, 0x45, 0x00, 0x48, 0xd1, 0x6d, 0x00, 0x48,
            0x8b, 0x45, 0x00, 0x5d, 0xc3,
        ];
        let recovered: TypedFunction = recover_function(bytes, 0x1000);
        assert_eq!(recovered.typed_slot(0), None);
        assert!(!recovered.typed_slots().contains_key(&0));
    }

    #[test]
    fn typed_slot_abstains_on_an_escaped_address_taken_slot() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x45, 0x10, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b,
            0x45, 0x10, 0x5d, 0xc3,
        ];
        let recovered: TypedFunction = recover_function(bytes, 0x1000);
        assert_eq!(recovered.typed_slot(0x10), None);
    }

    #[test]
    fn c_int_type_names_and_widths_are_stable() {
        assert_eq!(CIntType::I32.c_name(), "int32_t");
        assert_eq!(CIntType::U32.c_name(), "uint32_t");
        assert_eq!(CIntType::I8.c_name(), "int8_t");
        assert_eq!(CIntType::U64.c_name(), "uint64_t");
        assert_eq!(CIntType::I16.width(), Width::Word);
        assert!(CIntType::I64.is_signed());
        assert!(!CIntType::U8.is_signed());
    }
}
