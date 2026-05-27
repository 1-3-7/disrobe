use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
        matches!((self.major, self.minor), (1, 9) | (2, 0..=7) | (3, 0..=4))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcodeSpec {
    pub mnemonic: &'static str,
    pub operands: u8,
}

const BASE_19: &[(u8, OpcodeSpec)] = &[
    (
        0x00,
        OpcodeSpec {
            mnemonic: "nop",
            operands: 0,
        },
    ),
    (
        0x01,
        OpcodeSpec {
            mnemonic: "getlocal",
            operands: 2,
        },
    ),
    (
        0x02,
        OpcodeSpec {
            mnemonic: "setlocal",
            operands: 2,
        },
    ),
    (
        0x03,
        OpcodeSpec {
            mnemonic: "getspecial",
            operands: 2,
        },
    ),
    (
        0x04,
        OpcodeSpec {
            mnemonic: "setspecial",
            operands: 1,
        },
    ),
    (
        0x05,
        OpcodeSpec {
            mnemonic: "getinstancevariable",
            operands: 2,
        },
    ),
    (
        0x06,
        OpcodeSpec {
            mnemonic: "setinstancevariable",
            operands: 2,
        },
    ),
    (
        0x07,
        OpcodeSpec {
            mnemonic: "getclassvariable",
            operands: 1,
        },
    ),
    (
        0x08,
        OpcodeSpec {
            mnemonic: "setclassvariable",
            operands: 1,
        },
    ),
    (
        0x09,
        OpcodeSpec {
            mnemonic: "getconstant",
            operands: 1,
        },
    ),
    (
        0x0A,
        OpcodeSpec {
            mnemonic: "setconstant",
            operands: 1,
        },
    ),
    (
        0x0B,
        OpcodeSpec {
            mnemonic: "getglobal",
            operands: 1,
        },
    ),
    (
        0x0C,
        OpcodeSpec {
            mnemonic: "setglobal",
            operands: 1,
        },
    ),
    (
        0x0D,
        OpcodeSpec {
            mnemonic: "putnil",
            operands: 0,
        },
    ),
    (
        0x0E,
        OpcodeSpec {
            mnemonic: "putself",
            operands: 0,
        },
    ),
    (
        0x0F,
        OpcodeSpec {
            mnemonic: "putobject",
            operands: 1,
        },
    ),
    (
        0x10,
        OpcodeSpec {
            mnemonic: "putspecialobject",
            operands: 1,
        },
    ),
    (
        0x11,
        OpcodeSpec {
            mnemonic: "putiseq",
            operands: 1,
        },
    ),
    (
        0x12,
        OpcodeSpec {
            mnemonic: "putstring",
            operands: 1,
        },
    ),
    (
        0x13,
        OpcodeSpec {
            mnemonic: "concatstrings",
            operands: 1,
        },
    ),
    (
        0x14,
        OpcodeSpec {
            mnemonic: "tostring",
            operands: 0,
        },
    ),
    (
        0x15,
        OpcodeSpec {
            mnemonic: "toregexp",
            operands: 2,
        },
    ),
    (
        0x16,
        OpcodeSpec {
            mnemonic: "newarray",
            operands: 1,
        },
    ),
    (
        0x17,
        OpcodeSpec {
            mnemonic: "duparray",
            operands: 1,
        },
    ),
    (
        0x18,
        OpcodeSpec {
            mnemonic: "expandarray",
            operands: 2,
        },
    ),
    (
        0x19,
        OpcodeSpec {
            mnemonic: "concatarray",
            operands: 0,
        },
    ),
    (
        0x1A,
        OpcodeSpec {
            mnemonic: "splatarray",
            operands: 1,
        },
    ),
    (
        0x1B,
        OpcodeSpec {
            mnemonic: "newhash",
            operands: 1,
        },
    ),
    (
        0x1C,
        OpcodeSpec {
            mnemonic: "newrange",
            operands: 1,
        },
    ),
    (
        0x1D,
        OpcodeSpec {
            mnemonic: "pop",
            operands: 0,
        },
    ),
    (
        0x1E,
        OpcodeSpec {
            mnemonic: "dup",
            operands: 0,
        },
    ),
    (
        0x1F,
        OpcodeSpec {
            mnemonic: "dupn",
            operands: 1,
        },
    ),
    (
        0x20,
        OpcodeSpec {
            mnemonic: "swap",
            operands: 0,
        },
    ),
    (
        0x21,
        OpcodeSpec {
            mnemonic: "reput",
            operands: 0,
        },
    ),
    (
        0x22,
        OpcodeSpec {
            mnemonic: "topn",
            operands: 1,
        },
    ),
    (
        0x23,
        OpcodeSpec {
            mnemonic: "setn",
            operands: 1,
        },
    ),
    (
        0x24,
        OpcodeSpec {
            mnemonic: "adjuststack",
            operands: 1,
        },
    ),
    (
        0x25,
        OpcodeSpec {
            mnemonic: "defined",
            operands: 3,
        },
    ),
    (
        0x26,
        OpcodeSpec {
            mnemonic: "checkmatch",
            operands: 1,
        },
    ),
    (
        0x27,
        OpcodeSpec {
            mnemonic: "checkkeyword",
            operands: 2,
        },
    ),
    (
        0x28,
        OpcodeSpec {
            mnemonic: "trace",
            operands: 1,
        },
    ),
    (
        0x29,
        OpcodeSpec {
            mnemonic: "defineclass",
            operands: 3,
        },
    ),
    (
        0x2A,
        OpcodeSpec {
            mnemonic: "send",
            operands: 3,
        },
    ),
    (
        0x2B,
        OpcodeSpec {
            mnemonic: "opt_send_without_block",
            operands: 1,
        },
    ),
    (
        0x2C,
        OpcodeSpec {
            mnemonic: "invokesuper",
            operands: 3,
        },
    ),
    (
        0x2D,
        OpcodeSpec {
            mnemonic: "invokeblock",
            operands: 1,
        },
    ),
    (
        0x2E,
        OpcodeSpec {
            mnemonic: "leave",
            operands: 0,
        },
    ),
    (
        0x2F,
        OpcodeSpec {
            mnemonic: "throw",
            operands: 1,
        },
    ),
    (
        0x30,
        OpcodeSpec {
            mnemonic: "jump",
            operands: 1,
        },
    ),
    (
        0x31,
        OpcodeSpec {
            mnemonic: "branchif",
            operands: 1,
        },
    ),
    (
        0x32,
        OpcodeSpec {
            mnemonic: "branchunless",
            operands: 1,
        },
    ),
    (
        0x33,
        OpcodeSpec {
            mnemonic: "branchnil",
            operands: 1,
        },
    ),
    (
        0x34,
        OpcodeSpec {
            mnemonic: "getinlinecache",
            operands: 2,
        },
    ),
    (
        0x35,
        OpcodeSpec {
            mnemonic: "setinlinecache",
            operands: 1,
        },
    ),
    (
        0x36,
        OpcodeSpec {
            mnemonic: "once",
            operands: 2,
        },
    ),
    (
        0x37,
        OpcodeSpec {
            mnemonic: "opt_case_dispatch",
            operands: 2,
        },
    ),
    (
        0x38,
        OpcodeSpec {
            mnemonic: "opt_plus",
            operands: 1,
        },
    ),
    (
        0x39,
        OpcodeSpec {
            mnemonic: "opt_minus",
            operands: 1,
        },
    ),
    (
        0x3A,
        OpcodeSpec {
            mnemonic: "opt_mult",
            operands: 1,
        },
    ),
    (
        0x3B,
        OpcodeSpec {
            mnemonic: "opt_div",
            operands: 1,
        },
    ),
    (
        0x3C,
        OpcodeSpec {
            mnemonic: "opt_mod",
            operands: 1,
        },
    ),
    (
        0x3D,
        OpcodeSpec {
            mnemonic: "opt_eq",
            operands: 1,
        },
    ),
    (
        0x3E,
        OpcodeSpec {
            mnemonic: "opt_neq",
            operands: 2,
        },
    ),
    (
        0x3F,
        OpcodeSpec {
            mnemonic: "opt_lt",
            operands: 1,
        },
    ),
    (
        0x40,
        OpcodeSpec {
            mnemonic: "opt_le",
            operands: 1,
        },
    ),
    (
        0x41,
        OpcodeSpec {
            mnemonic: "opt_gt",
            operands: 1,
        },
    ),
    (
        0x42,
        OpcodeSpec {
            mnemonic: "opt_ge",
            operands: 1,
        },
    ),
    (
        0x43,
        OpcodeSpec {
            mnemonic: "opt_ltlt",
            operands: 1,
        },
    ),
    (
        0x44,
        OpcodeSpec {
            mnemonic: "opt_aref",
            operands: 1,
        },
    ),
    (
        0x45,
        OpcodeSpec {
            mnemonic: "opt_aset",
            operands: 1,
        },
    ),
    (
        0x46,
        OpcodeSpec {
            mnemonic: "opt_length",
            operands: 1,
        },
    ),
    (
        0x47,
        OpcodeSpec {
            mnemonic: "opt_size",
            operands: 1,
        },
    ),
    (
        0x48,
        OpcodeSpec {
            mnemonic: "opt_empty_p",
            operands: 1,
        },
    ),
    (
        0x49,
        OpcodeSpec {
            mnemonic: "opt_succ",
            operands: 1,
        },
    ),
    (
        0x4A,
        OpcodeSpec {
            mnemonic: "opt_not",
            operands: 1,
        },
    ),
    (
        0x4B,
        OpcodeSpec {
            mnemonic: "opt_regexpmatch1",
            operands: 1,
        },
    ),
    (
        0x4C,
        OpcodeSpec {
            mnemonic: "opt_regexpmatch2",
            operands: 1,
        },
    ),
    (
        0x4D,
        OpcodeSpec {
            mnemonic: "opt_call_c_function",
            operands: 2,
        },
    ),
    (
        0x4E,
        OpcodeSpec {
            mnemonic: "bitblt",
            operands: 0,
        },
    ),
    (
        0x4F,
        OpcodeSpec {
            mnemonic: "answer",
            operands: 0,
        },
    ),
    (
        0x50,
        OpcodeSpec {
            mnemonic: "getlocal_OP__WC__0",
            operands: 1,
        },
    ),
    (
        0x51,
        OpcodeSpec {
            mnemonic: "getlocal_OP__WC__1",
            operands: 1,
        },
    ),
    (
        0x52,
        OpcodeSpec {
            mnemonic: "setlocal_OP__WC__0",
            operands: 1,
        },
    ),
    (
        0x53,
        OpcodeSpec {
            mnemonic: "setlocal_OP__WC__1",
            operands: 1,
        },
    ),
];

const ADDED_27: &[(u8, OpcodeSpec)] = &[
    (
        0x60,
        OpcodeSpec {
            mnemonic: "opt_str_freeze",
            operands: 2,
        },
    ),
    (
        0x61,
        OpcodeSpec {
            mnemonic: "opt_nil_p",
            operands: 1,
        },
    ),
    (
        0x62,
        OpcodeSpec {
            mnemonic: "opt_str_uminus",
            operands: 2,
        },
    ),
    (
        0x63,
        OpcodeSpec {
            mnemonic: "opt_newarray_max",
            operands: 1,
        },
    ),
    (
        0x64,
        OpcodeSpec {
            mnemonic: "opt_newarray_min",
            operands: 1,
        },
    ),
];

const ADDED_30: &[(u8, OpcodeSpec)] = &[
    (
        0x70,
        OpcodeSpec {
            mnemonic: "branchnil",
            operands: 1,
        },
    ),
    (
        0x71,
        OpcodeSpec {
            mnemonic: "opt_getinlinecache",
            operands: 2,
        },
    ),
    (
        0x72,
        OpcodeSpec {
            mnemonic: "opt_setinlinecache",
            operands: 1,
        },
    ),
    (
        0x73,
        OpcodeSpec {
            mnemonic: "getblockparam",
            operands: 2,
        },
    ),
    (
        0x74,
        OpcodeSpec {
            mnemonic: "setblockparam",
            operands: 2,
        },
    ),
    (
        0x75,
        OpcodeSpec {
            mnemonic: "getblockparamproxy",
            operands: 2,
        },
    ),
];

const ADDED_31: &[(u8, OpcodeSpec)] = &[
    (
        0x80,
        OpcodeSpec {
            mnemonic: "opt_getconstant_path",
            operands: 1,
        },
    ),
    (
        0x81,
        OpcodeSpec {
            mnemonic: "checktype",
            operands: 1,
        },
    ),
    (
        0x82,
        OpcodeSpec {
            mnemonic: "objtostring",
            operands: 1,
        },
    ),
    (
        0x83,
        OpcodeSpec {
            mnemonic: "anytostring",
            operands: 0,
        },
    ),
    (
        0x84,
        OpcodeSpec {
            mnemonic: "intern",
            operands: 0,
        },
    ),
];

const ADDED_32: &[(u8, OpcodeSpec)] = &[
    (
        0x90,
        OpcodeSpec {
            mnemonic: "opt_invokebuiltin_delegate",
            operands: 2,
        },
    ),
    (
        0x91,
        OpcodeSpec {
            mnemonic: "opt_invokebuiltin_delegate_leave",
            operands: 2,
        },
    ),
    (
        0x92,
        OpcodeSpec {
            mnemonic: "invokebuiltin",
            operands: 1,
        },
    ),
    (
        0x93,
        OpcodeSpec {
            mnemonic: "opt_ary_freeze",
            operands: 2,
        },
    ),
    (
        0x94,
        OpcodeSpec {
            mnemonic: "opt_hash_freeze",
            operands: 2,
        },
    ),
];

const ADDED_33: &[(u8, OpcodeSpec)] = &[
    (
        0xA0,
        OpcodeSpec {
            mnemonic: "concattoarray",
            operands: 0,
        },
    ),
    (
        0xA1,
        OpcodeSpec {
            mnemonic: "pushtoarray",
            operands: 1,
        },
    ),
    (
        0xA2,
        OpcodeSpec {
            mnemonic: "opt_duparray_send",
            operands: 3,
        },
    ),
    (
        0xA3,
        OpcodeSpec {
            mnemonic: "opt_newarray_send",
            operands: 2,
        },
    ),
];

const ADDED_34: &[(u8, OpcodeSpec)] = &[
    (
        0xB0,
        OpcodeSpec {
            mnemonic: "opt_reverse",
            operands: 1,
        },
    ),
    (
        0xB1,
        OpcodeSpec {
            mnemonic: "opt_succ_str",
            operands: 1,
        },
    ),
    (
        0xB2,
        OpcodeSpec {
            mnemonic: "opt_array_append",
            operands: 1,
        },
    ),
    (
        0xB3,
        OpcodeSpec {
            mnemonic: "splatkw",
            operands: 0,
        },
    ),
];

#[must_use]
pub fn opcode_table(version: YarvVersion) -> BTreeMap<u8, OpcodeSpec> {
    let mut table: BTreeMap<u8, OpcodeSpec> = BTreeMap::new();
    for (op, spec) in BASE_19 {
        table.insert(*op, *spec);
    }
    if version.major > 2 || (version.major == 2 && version.minor >= 7) {
        for (op, spec) in ADDED_27 {
            table.insert(*op, *spec);
        }
    }
    if version.major >= 3 {
        for (op, spec) in ADDED_30 {
            table.insert(*op, *spec);
        }
    }
    if version.major == 3 && version.minor >= 1 {
        for (op, spec) in ADDED_31 {
            table.insert(*op, *spec);
        }
    }
    if version.major == 3 && version.minor >= 2 {
        for (op, spec) in ADDED_32 {
            table.insert(*op, *spec);
        }
    }
    if version.major == 3 && version.minor >= 3 {
        for (op, spec) in ADDED_33 {
            table.insert(*op, *spec);
        }
    }
    if version.major == 3 && version.minor >= 4 {
        for (op, spec) in ADDED_34 {
            table.insert(*op, *spec);
        }
    }
    table
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn table_grows_with_version() {
        let v19: BTreeMap<u8, OpcodeSpec> = opcode_table(YarvVersion::new(1, 9));
        let v34: BTreeMap<u8, OpcodeSpec> = opcode_table(YarvVersion::new(3, 4));
        assert!(v34.len() > v19.len());
    }

    #[test]
    fn supported_versions() {
        for (maj, min) in [
            (1, 9),
            (2, 0),
            (2, 7),
            (3, 0),
            (3, 1),
            (3, 2),
            (3, 3),
            (3, 4),
        ] {
            assert!(YarvVersion::new(maj, min).is_supported());
        }
        assert!(!YarvVersion::new(3, 99).is_supported());
        assert!(!YarvVersion::new(4, 0).is_supported());
    }

    #[test]
    fn opcode_lookup_has_known_entries() {
        let t: BTreeMap<u8, OpcodeSpec> = opcode_table(YarvVersion::new(3, 2));
        assert_eq!(t.get(&0x00).expect("nop").mnemonic, "nop");
        assert_eq!(t.get(&0x2E).expect("leave").mnemonic, "leave");
        assert_eq!(
            t.get(&0x92).expect("invokebuiltin").mnemonic,
            "invokebuiltin"
        );
    }
}
