use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PyVersion {
    pub major: u8,
    pub minor: u8,
}

impl PyVersion {
    pub const PY10: Self = Self { major: 1, minor: 0 };
    pub const PY11: Self = Self { major: 1, minor: 1 };
    pub const PY13: Self = Self { major: 1, minor: 3 };
    pub const PY14: Self = Self { major: 1, minor: 4 };
    pub const PY15: Self = Self { major: 1, minor: 5 };
    pub const PY16: Self = Self { major: 1, minor: 6 };
    pub const PY20: Self = Self { major: 2, minor: 0 };
    pub const PY21: Self = Self { major: 2, minor: 1 };
    pub const PY22: Self = Self { major: 2, minor: 2 };
    pub const PY23: Self = Self { major: 2, minor: 3 };
    pub const PY24: Self = Self { major: 2, minor: 4 };
    pub const PY25: Self = Self { major: 2, minor: 5 };
    pub const PY26: Self = Self { major: 2, minor: 6 };
    pub const PY27: Self = Self { major: 2, minor: 7 };
    pub const PY30: Self = Self { major: 3, minor: 0 };
    pub const PY31: Self = Self { major: 3, minor: 1 };
    pub const PY32: Self = Self { major: 3, minor: 2 };
    pub const PY33: Self = Self { major: 3, minor: 3 };
    pub const PY34: Self = Self { major: 3, minor: 4 };
    pub const PY35: Self = Self { major: 3, minor: 5 };
    pub const PY36: Self = Self { major: 3, minor: 6 };
    pub const PY37: Self = Self { major: 3, minor: 7 };
    pub const PY38: Self = Self { major: 3, minor: 8 };
    pub const PY39: Self = Self { major: 3, minor: 9 };
    pub const PY310: Self = Self {
        major: 3,
        minor: 10,
    };
    pub const PY311: Self = Self {
        major: 3,
        minor: 11,
    };
    pub const PY312: Self = Self {
        major: 3,
        minor: 12,
    };
    pub const PY313: Self = Self {
        major: 3,
        minor: 13,
    };
    pub const PY314: Self = Self {
        major: 3,
        minor: 14,
    };
    pub const PY315: Self = Self {
        major: 3,
        minor: 15,
    };

    #[must_use]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn is_wordcode(self) -> bool {
        self.major > 3 || (self.major == 3 && self.minor >= 6)
    }

    #[must_use]
    pub const fn has_pep552_header(self) -> bool {
        self.major > 3 || (self.major == 3 && self.minor >= 7)
    }

    #[must_use]
    pub const fn has_source_size(self) -> bool {
        self.major > 3 || (self.major == 3 && self.minor >= 3)
    }

    #[must_use]
    pub const fn pyc_header_len(self) -> usize {
        if self.has_pep552_header() {
            16
        } else if self.has_source_size() {
            12
        } else {
            8
        }
    }
}

#[must_use]
pub const fn magic_for(v: PyVersion) -> Option<u32> {
    match (v.major, v.minor) {
        (1, 0) => Some(0x0099_9902),
        (1, 1) => Some(0x0099_9903),
        (1, 3) => Some(0x0A0D_2E89),
        (1, 4) => Some(0x0A0D_1704),
        (1, 5) => Some(0x0A0D_4E99),
        (1, 6) => Some(0x0A0D_C4FC),
        (2, 0) => Some(0x0A0D_C687),
        (2, 1) => Some(0x0A0D_EB2A),
        (2, 2) => Some(0x0A0D_ED2D),
        (2, 3) => Some(0x0A0D_F23B),
        (2, 4) => Some(0x0A0D_F26D),
        (2, 5) => Some(0x0A0D_F2B3),
        (2, 6) => Some(0x0A0D_F2D1),
        (2, 7) => Some(0x0A0D_F303),
        (3, 0) => Some(0x0A0D_0C3A),
        (3, 1) => Some(0x0A0D_0C4E),
        (3, 2) => Some(0x0A0D_0C6C),
        (3, 3) => Some(0x0A0D_0C9E),
        (3, 4) => Some(0x0A0D_0CEE),
        (3, 5) => Some(0x0A0D_0D17),
        (3, 6) => Some(0x0A0D_0D33),
        (3, 7) => Some(0x0A0D_0D42),
        (3, 8) => Some(0x0A0D_0D55),
        (3, 9) => Some(0x0A0D_0D61),
        (3, 10) => Some(0x0A0D_0D6F),
        (3, 11) => Some(0x0A0D_0DA7),
        (3, 12) => Some(0x0A0D_0DCB),
        (3, 13) => Some(0x0A0D_0DF3),
        (3, 14) => Some(0x0A0D_0E2B),
        (3, 15) => Some(0x0A0D_0E52),
        _ => None,
    }
}

#[must_use]
pub const fn pyversion_from_magic(magic: u32) -> Option<PyVersion> {
    match magic {
        0x0099_9902 => Some(PyVersion::PY10),
        0x0099_9903 => Some(PyVersion::PY11),
        0x0A0D_2E89 => Some(PyVersion::PY13),
        0x0A0D_1704 => Some(PyVersion::PY14),
        0x0A0D_4E99 => Some(PyVersion::PY15),
        0x0A0D_C4FC | 0x0A0D_C4FD => Some(PyVersion::PY16),
        0x0A0D_C687 | 0x0A0D_C688 => Some(PyVersion::PY20),
        0x0A0D_EB2A | 0x0A0D_EB2B => Some(PyVersion::PY21),
        0x0A0D_ED2D | 0x0A0D_ED2E => Some(PyVersion::PY22),
        0x0A0D_F23B | 0x0A0D_F23C => Some(PyVersion::PY23),
        0x0A0D_F26D | 0x0A0D_F26E => Some(PyVersion::PY24),
        0x0A0D_F2B3 | 0x0A0D_F2B4 => Some(PyVersion::PY25),
        0x0A0D_F2D1 | 0x0A0D_F2D2 => Some(PyVersion::PY26),
        0x0A0D_F303 | 0x0A0D_F304 => Some(PyVersion::PY27),
        0x0A0D_0C3A | 0x0A0D_0C3B => Some(PyVersion::PY30),
        0x0A0D_0C4E | 0x0A0D_0C4F => Some(PyVersion::PY31),
        0x0A0D_0C6C => Some(PyVersion::PY32),
        0x0A0D_0C9E => Some(PyVersion::PY33),
        0x0A0D_0CEE => Some(PyVersion::PY34),
        0x0A0D_0D16 | 0x0A0D_0D17 => Some(PyVersion::PY35),
        0x0A0D_0D33 => Some(PyVersion::PY36),
        0x0A0D_0D42 => Some(PyVersion::PY37),
        0x0A0D_0D55 => Some(PyVersion::PY38),
        0x0A0D_0D61 => Some(PyVersion::PY39),
        0x0A0D_0D6F | 0x0A0D_0180 => Some(PyVersion::PY310),
        0x0A0D_0DA7 | 0x0A0D_0181 => Some(PyVersion::PY311),
        0x0A0D_0DCB | 0x0A0D_0182 => Some(PyVersion::PY312),
        0x0A0D_0DF3 => Some(PyVersion::PY313),
        0x0A0D_0E2B => Some(PyVersion::PY314),
        0x0A0D_0E52 => Some(PyVersion::PY315),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_sizes_per_version() {
        assert_eq!(PyVersion::PY10.pyc_header_len(), 8);
        assert_eq!(PyVersion::PY16.pyc_header_len(), 8);
        assert_eq!(PyVersion::PY27.pyc_header_len(), 8);
        assert_eq!(PyVersion::PY30.pyc_header_len(), 8);
        assert_eq!(PyVersion::PY32.pyc_header_len(), 8);
        assert_eq!(PyVersion::PY33.pyc_header_len(), 12);
        assert_eq!(PyVersion::PY36.pyc_header_len(), 12);
        assert_eq!(PyVersion::PY37.pyc_header_len(), 16);
        assert_eq!(PyVersion::PY314.pyc_header_len(), 16);
    }

    #[test]
    fn legacy_headers_are_eight_bytes() {
        for v in [
            PyVersion::PY10,
            PyVersion::PY11,
            PyVersion::PY13,
            PyVersion::PY14,
            PyVersion::PY15,
            PyVersion::PY16,
            PyVersion::PY20,
            PyVersion::PY21,
            PyVersion::PY22,
            PyVersion::PY23,
            PyVersion::PY24,
            PyVersion::PY25,
            PyVersion::PY26,
            PyVersion::PY27,
            PyVersion::PY30,
            PyVersion::PY31,
            PyVersion::PY32,
        ] {
            assert_eq!(v.pyc_header_len(), 8, "header len for {v:?}");
        }
    }

    #[test]
    fn wordcode_transition_at_36() {
        assert!(!PyVersion::PY35.is_wordcode());
        assert!(PyVersion::PY36.is_wordcode());
        assert!(PyVersion::PY314.is_wordcode());
    }

    #[test]
    fn legacy_magics_resolve_to_versions() {
        assert_eq!(pyversion_from_magic(0x0099_9902), Some(PyVersion::PY10));
        assert_eq!(pyversion_from_magic(0x0099_9903), Some(PyVersion::PY11));
        assert_eq!(pyversion_from_magic(0x0A0D_2E89), Some(PyVersion::PY13));
        assert_eq!(pyversion_from_magic(0x0A0D_1704), Some(PyVersion::PY14));
        assert_eq!(pyversion_from_magic(0x0A0D_4E99), Some(PyVersion::PY15));
        assert_eq!(pyversion_from_magic(0x0A0D_C4FC), Some(PyVersion::PY16));
        assert_eq!(pyversion_from_magic(0x0A0D_C687), Some(PyVersion::PY20));
        assert_eq!(pyversion_from_magic(0x0A0D_F303), Some(PyVersion::PY27));
        assert_eq!(pyversion_from_magic(0x0A0D_0C3A), Some(PyVersion::PY30));
        assert_eq!(pyversion_from_magic(0x0A0D_0C4E), Some(PyVersion::PY31));
        assert_eq!(pyversion_from_magic(0x0A0D_0C6C), Some(PyVersion::PY32));
    }

    #[test]
    fn unicode_increment_magics_resolve() {
        assert_eq!(pyversion_from_magic(0x0A0D_C4FD), Some(PyVersion::PY16));
        assert_eq!(pyversion_from_magic(0x0A0D_F304), Some(PyVersion::PY27));
        assert_eq!(pyversion_from_magic(0x0A0D_0C3B), Some(PyVersion::PY30));
    }

    #[test]
    fn one_four_and_one_five_disambiguate() {
        assert_ne!(
            pyversion_from_magic(0x0A0D_1704),
            pyversion_from_magic(0x0A0D_4E99)
        );
        assert_eq!(pyversion_from_magic(0x0A0D_1704), Some(PyVersion::PY14));
        assert_eq!(pyversion_from_magic(0x0A0D_4E99), Some(PyVersion::PY15));
    }

    #[test]
    fn magic_round_trip() {
        for v in [
            PyVersion::PY10,
            PyVersion::PY11,
            PyVersion::PY13,
            PyVersion::PY14,
            PyVersion::PY15,
            PyVersion::PY16,
            PyVersion::PY20,
            PyVersion::PY21,
            PyVersion::PY22,
            PyVersion::PY23,
            PyVersion::PY24,
            PyVersion::PY25,
            PyVersion::PY26,
            PyVersion::PY27,
            PyVersion::PY30,
            PyVersion::PY31,
            PyVersion::PY32,
            PyVersion::PY36,
            PyVersion::PY39,
            PyVersion::PY311,
            PyVersion::PY312,
            PyVersion::PY313,
            PyVersion::PY314,
            PyVersion::PY315,
        ] {
            let m: u32 = magic_for(v).unwrap();
            assert_eq!(
                pyversion_from_magic(m),
                Some(v),
                "round trip failed for {v:?}"
            );
        }
    }

    #[test]
    fn tstring_magic_3_15_is_3666() {
        assert_eq!(magic_for(PyVersion::PY315), Some(0x0A0D_0E52));
        assert_eq!(0x0A0D_0E52_u32 & 0xFFFF, 3666);
        assert_eq!(pyversion_from_magic(0x0A0D_0E52), Some(PyVersion::PY315));
    }
}
