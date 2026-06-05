//! YARV version model and opcode-table selection.

use serde::{Deserialize, Serialize};

pub use crate::yarv::opcode_tables::TsKind;
pub(crate) use crate::yarv::opcode_tables::{V2_6, V2_7, V3_0, V3_1, V3_2, V3_3, V3_4, YarvOpcode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct YarvVersion {
    pub major: u32,
    pub minor: u32,
}

impl YarvVersion {
    #[inline]
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    #[inline]
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!((self.major, self.minor), (2, 6 | 7) | (3, 0..=4))
    }

    /// The opcode table whose `DEFINE_INSN` ordering matches this version, or `None` if the
    /// version has no ported table (only 2.6-3.4 are public/supported).
    #[must_use]
    pub(crate) const fn opcode_table(self) -> Option<&'static [YarvOpcode]> {
        match (self.major, self.minor) {
            (2, 6) => Some(V2_6),
            (2, 7) => Some(V2_7),
            (3, 0) => Some(V3_0),
            (3, 1) => Some(V3_1),
            (3, 2) => Some(V3_2),
            (3, 3) => Some(V3_3),
            (3, 4) => Some(V3_4),
            _ => None,
        }
    }
}

/// Public opcode descriptor: resolves an opcode number to its mnemonic + operand arity for a
/// given version. Returned by [`opcode_spec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcodeSpec {
    pub mnemonic: &'static str,
    pub operands: u8,
}

/// Resolve a single opcode number for a version into its mnemonic and operand count.
#[must_use]
pub fn opcode_spec(version: YarvVersion, op: u32) -> Option<OpcodeSpec> {
    let table: &[YarvOpcode] = version.opcode_table()?;
    let idx: usize = usize::try_from(op).ok()?;
    table.get(idx).map(|o| OpcodeSpec {
        mnemonic: o.mnemonic,
        operands: u8::try_from(o.operands.len()).unwrap_or(u8::MAX),
    })
}

/// The number of opcodes defined for a version (size of its `insns.def` table).
#[must_use]
pub fn opcode_count(version: YarvVersion) -> usize {
    version.opcode_table().map_or(0, <[YarvOpcode]>::len)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn nop_is_opcode_zero_every_version() {
        for (maj, min) in [(2, 6), (2, 7), (3, 0), (3, 1), (3, 2), (3, 3), (3, 4)] {
            let v: YarvVersion = YarvVersion::new(maj, min);
            assert_eq!(
                opcode_spec(v, 0).expect("nop").mnemonic,
                "nop",
                "{maj}.{min}"
            );
            assert_eq!(opcode_spec(v, 0).expect("nop").operands, 0);
        }
    }

    #[test]
    fn putobject_resolves_to_value_operand() {
        let v: YarvVersion = YarvVersion::new(3, 4);
        let table: &[YarvOpcode] = v.opcode_table().expect("3.4 table");
        let (idx, _): (usize, &YarvOpcode) = table
            .iter()
            .enumerate()
            .find(|(_, o)| o.mnemonic == "putobject")
            .expect("putobject present");
        assert_eq!(table[idx].operands, &[TsKind::Value]);
    }

    #[test]
    fn table_sizes_match_runtime_instruction_set() {
        assert_eq!(opcode_count(YarvVersion::new(2, 6)), 202);
        assert_eq!(opcode_count(YarvVersion::new(2, 7)), 206);
        assert_eq!(opcode_count(YarvVersion::new(3, 0)), 202);
        assert_eq!(opcode_count(YarvVersion::new(3, 1)), 202);
        assert_eq!(opcode_count(YarvVersion::new(3, 2)), 202);
        assert_eq!(opcode_count(YarvVersion::new(3, 3)), 204);
        assert_eq!(opcode_count(YarvVersion::new(3, 4)), 220);
    }

    #[test]
    fn operand_unified_specializations_present() {
        let v: YarvVersion = YarvVersion::new(3, 4);
        let getlocal_wc0: OpcodeSpec = opcode_spec(v, 104).expect("getlocal_WC_0");
        assert_eq!(getlocal_wc0.mnemonic, "getlocal_WC_0");
        assert_eq!(getlocal_wc0.operands, 1);
        let int2fix0: OpcodeSpec = opcode_spec(v, 108).expect("putobject_INT2FIX_0_");
        assert_eq!(int2fix0.mnemonic, "putobject_INT2FIX_0_");
        assert_eq!(int2fix0.operands, 0);
    }

    #[test]
    fn leave_is_present_and_zero_operand() {
        let v: YarvVersion = YarvVersion::new(3, 2);
        let table: &[YarvOpcode] = v.opcode_table().expect("table");
        let leave: &YarvOpcode = table.iter().find(|o| o.mnemonic == "leave").expect("leave");
        assert!(leave.operands.is_empty());
    }

    #[test]
    fn supported_versions() {
        for (maj, min) in [(2, 6), (2, 7), (3, 0), (3, 1), (3, 2), (3, 3), (3, 4)] {
            assert!(YarvVersion::new(maj, min).is_supported());
        }
        assert!(!YarvVersion::new(1, 9).is_supported());
        assert!(!YarvVersion::new(4, 0).is_supported());
    }
}
