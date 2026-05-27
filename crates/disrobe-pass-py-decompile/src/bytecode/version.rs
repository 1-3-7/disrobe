use disrobe_py_marshal::PyVersion as MarshalVersion;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PyVersion {
    V1_0,
    V1_1,
    V1_3,
    V1_4,
    V1_5,
    V1_6,
    V2_0,
    V2_1,
    V2_2,
    V2_3,
    V2_4,
    V2_5,
    V2_6,
    V2_7,
    V3_0,
    V3_1,
    V3_2,
    V3_3,
    V3_4,
    V3_5,
    V3_6,
    V3_7,
    V3_8,
    V3_9,
    V3_10,
    V3_11,
    V3_12,
    V3_13,
    V3_14,
    V3_15,
    PyPy(Box<PyVersion>),
}

const ALL_NON_PYPY: &[PyVersion] = &[
    PyVersion::V1_0,
    PyVersion::V1_1,
    PyVersion::V1_3,
    PyVersion::V1_4,
    PyVersion::V1_5,
    PyVersion::V1_6,
    PyVersion::V2_0,
    PyVersion::V2_1,
    PyVersion::V2_2,
    PyVersion::V2_3,
    PyVersion::V2_4,
    PyVersion::V2_5,
    PyVersion::V2_6,
    PyVersion::V2_7,
    PyVersion::V3_0,
    PyVersion::V3_1,
    PyVersion::V3_2,
    PyVersion::V3_3,
    PyVersion::V3_4,
    PyVersion::V3_5,
    PyVersion::V3_6,
    PyVersion::V3_7,
    PyVersion::V3_8,
    PyVersion::V3_9,
    PyVersion::V3_10,
    PyVersion::V3_11,
    PyVersion::V3_12,
    PyVersion::V3_13,
    PyVersion::V3_14,
    PyVersion::V3_15,
];

impl PyVersion {
    #[must_use]
    pub fn all_non_pypy() -> &'static [Self] {
        ALL_NON_PYPY
    }

    #[must_use]
    pub fn from_magic(magic: u32) -> Option<Self> {
        let m16: u16 = u16::try_from(magic & 0xFFFF).ok()?;
        let base: Self = match m16 {
            39170 | 39171 => Self::V1_0,
            5892 => Self::V1_1,
            11913 => Self::V1_3,
            20122 => Self::V1_4,
            20121 => Self::V1_5,
            50428 => Self::V1_6,
            50823 => Self::V2_0,
            60202 => Self::V2_1,
            60717 => Self::V2_2,
            62011 => Self::V2_3,
            62061 => Self::V2_4,
            62131 => Self::V2_5,
            62161 => Self::V2_6,
            62211 => Self::V2_7,
            3000 => Self::V3_0,
            3151 => Self::V3_1,
            3180 => Self::V3_2,
            3230 => Self::V3_3,
            3310 => Self::V3_4,
            3351 => Self::V3_5,
            3379 => Self::V3_6,
            3394 => Self::V3_7,
            3413 => Self::V3_8,
            3425 => Self::V3_9,
            3439 => Self::V3_10,
            3495 => Self::V3_11,
            3531 => Self::V3_12,
            3571 => Self::V3_13,
            3627 => Self::V3_14,
            3700 => Self::V3_15,
            _ => return None,
        };
        if (magic & 0xFFFF_0000) == 0xA1B2_0000 {
            Some(Self::PyPy(Box::new(base)))
        } else {
            Some(base)
        }
    }

    #[must_use]
    pub fn major(&self) -> u8 {
        match self {
            Self::V1_0 | Self::V1_1 | Self::V1_3 | Self::V1_4 | Self::V1_5 | Self::V1_6 => 1,
            Self::V2_0
            | Self::V2_1
            | Self::V2_2
            | Self::V2_3
            | Self::V2_4
            | Self::V2_5
            | Self::V2_6
            | Self::V2_7 => 2,
            Self::V3_0
            | Self::V3_1
            | Self::V3_2
            | Self::V3_3
            | Self::V3_4
            | Self::V3_5
            | Self::V3_6
            | Self::V3_7
            | Self::V3_8
            | Self::V3_9
            | Self::V3_10
            | Self::V3_11
            | Self::V3_12
            | Self::V3_13
            | Self::V3_14
            | Self::V3_15 => 3,
            Self::PyPy(inner) => inner.major(),
        }
    }

    #[must_use]
    pub fn minor(&self) -> u8 {
        match self {
            Self::V1_0 | Self::V2_0 | Self::V3_0 => 0,
            Self::V1_1 | Self::V2_1 | Self::V3_1 => 1,
            Self::V2_2 | Self::V3_2 => 2,
            Self::V1_3 | Self::V2_3 | Self::V3_3 => 3,
            Self::V1_4 | Self::V2_4 | Self::V3_4 => 4,
            Self::V1_5 | Self::V2_5 | Self::V3_5 => 5,
            Self::V1_6 | Self::V2_6 | Self::V3_6 => 6,
            Self::V2_7 | Self::V3_7 => 7,
            Self::V3_8 => 8,
            Self::V3_9 => 9,
            Self::V3_10 => 10,
            Self::V3_11 => 11,
            Self::V3_12 => 12,
            Self::V3_13 => 13,
            Self::V3_14 => 14,
            Self::V3_15 => 15,
            Self::PyPy(inner) => inner.minor(),
        }
    }

    #[must_use]
    pub fn is_pre_311(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj < 3 || (maj == 3 && min < 11)
    }

    #[must_use]
    pub fn is_pre_310(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj < 3 || (maj == 3 && min < 10)
    }

    #[must_use]
    pub fn supports_match(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 10)
    }

    #[must_use]
    pub fn supports_walrus(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 8)
    }

    #[must_use]
    pub fn supports_async(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 5)
    }

    #[must_use]
    pub fn supports_fstring(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 6)
    }

    #[must_use]
    pub fn supports_tstring(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 14)
    }

    #[must_use]
    pub fn supports_pep_695(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 12)
    }

    #[must_use]
    pub fn supports_pep_696(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 13)
    }

    #[must_use]
    pub fn supports_pep_709(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 12)
    }

    #[must_use]
    pub fn supports_except_groups(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 11)
    }

    #[must_use]
    pub fn supports_zero_cost_exceptions(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 11)
    }

    #[must_use]
    pub fn supports_super_instructions(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 12)
    }

    #[must_use]
    pub fn supports_pep_657_exception_table(&self) -> bool {
        self.supports_zero_cost_exceptions()
    }

    #[must_use]
    pub fn supports_word_code(&self) -> bool {
        let (maj, min): (u8, u8) = (self.major(), self.minor());
        maj > 3 || (maj == 3 && min >= 6)
    }

    #[must_use]
    pub fn pyc_magic(&self) -> u32 {
        let base16: u32 = match self {
            Self::V1_0 => 39170,
            Self::V1_1 => 5892,
            Self::V1_3 => 11913,
            Self::V1_4 => 20122,
            Self::V1_5 => 20121,
            Self::V1_6 => 50428,
            Self::V2_0 => 50823,
            Self::V2_1 => 60202,
            Self::V2_2 => 60717,
            Self::V2_3 => 62011,
            Self::V2_4 => 62061,
            Self::V2_5 => 62131,
            Self::V2_6 => 62161,
            Self::V2_7 => 62211,
            Self::V3_0 => 3000,
            Self::V3_1 => 3151,
            Self::V3_2 => 3180,
            Self::V3_3 => 3230,
            Self::V3_4 => 3310,
            Self::V3_5 => 3351,
            Self::V3_6 => 3379,
            Self::V3_7 => 3394,
            Self::V3_8 => 3413,
            Self::V3_9 => 3425,
            Self::V3_10 => 3439,
            Self::V3_11 => 3495,
            Self::V3_12 => 3531,
            Self::V3_13 => 3571,
            Self::V3_14 => 3627,
            Self::V3_15 => 3700,
            Self::PyPy(inner) => return 0xA1B2_0000 | inner.pyc_magic(),
        };
        base16 | 0x0A0D_0000
    }

    #[must_use]
    pub fn to_marshal_version(&self) -> MarshalVersion {
        match self {
            Self::PyPy(inner) => inner.to_marshal_version(),
            _ => MarshalVersion {
                major: self.major(),
                minor: self.minor(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionCapabilities {
    pub wordcode: bool,
    pub zero_cost_exception_table: bool,
    pub super_instructions: bool,
    pub inlined_comprehensions: bool,
    pub return_const: bool,
    pub to_bool: bool,
    pub structural_match: bool,
    pub walrus: bool,
    pub fstring: bool,
    pub tstring: bool,
    pub async_await: bool,
    pub except_group: bool,
    pub pep695_type_params: bool,
    pub pep696_typevar_defaults: bool,
    pub pep709_inlined_comprehensions: bool,
}

impl VersionCapabilities {
    #[must_use]
    pub fn for_version(version: &PyVersion) -> Self {
        let (maj, min): (u8, u8) = (version.major(), version.minor());
        let ge: fn((u8, u8), (u8, u8)) -> bool =
            |a: (u8, u8), b: (u8, u8)| -> bool { a.0 > b.0 || (a.0 == b.0 && a.1 >= b.1) };
        Self {
            wordcode: ge((maj, min), (3, 6)),
            zero_cost_exception_table: ge((maj, min), (3, 11)),
            super_instructions: ge((maj, min), (3, 12)),
            inlined_comprehensions: ge((maj, min), (3, 12)),
            return_const: ge((maj, min), (3, 12)),
            to_bool: ge((maj, min), (3, 13)),
            structural_match: ge((maj, min), (3, 10)),
            walrus: ge((maj, min), (3, 8)),
            fstring: ge((maj, min), (3, 6)),
            tstring: ge((maj, min), (3, 14)),
            async_await: ge((maj, min), (3, 5)),
            except_group: ge((maj, min), (3, 11)),
            pep695_type_params: ge((maj, min), (3, 12)),
            pep696_typevar_defaults: ge((maj, min), (3, 13)),
            pep709_inlined_comprehensions: ge((maj, min), (3, 12)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn major_minor_known_values() {
        assert_eq!(
            (PyVersion::V3_11.major(), PyVersion::V3_11.minor()),
            (3, 11)
        );
        assert_eq!((PyVersion::V2_7.major(), PyVersion::V2_7.minor()), (2, 7));
        assert_eq!((PyVersion::V1_5.major(), PyVersion::V1_5.minor()), (1, 5));
    }

    #[test]
    fn pypy_unwraps_to_inner() {
        let v: PyVersion = PyVersion::PyPy(Box::new(PyVersion::V3_10));
        assert_eq!(v.major(), 3);
        assert_eq!(v.minor(), 10);
        assert!(v.supports_match());
    }

    #[test]
    fn capabilities_match_version_gates() {
        assert!(PyVersion::V3_11.supports_zero_cost_exceptions());
        assert!(!PyVersion::V3_10.supports_zero_cost_exceptions());
        assert!(PyVersion::V3_14.supports_tstring());
        assert!(!PyVersion::V3_13.supports_tstring());
        assert!(PyVersion::V3_8.supports_walrus());
        assert!(!PyVersion::V3_7.supports_walrus());
    }
}
