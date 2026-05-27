use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PyVersion {
    pub major: u8,
    pub minor: u8,
}

impl PyVersion {
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
pub const fn magic_for(v: PyVersion) -> Option<u16> {
    match (v.major, v.minor) {
        (2, 7) => Some(62211),
        (3, 3) => Some(3230),
        (3, 4) => Some(3310),
        (3, 5) => Some(3351),
        (3, 6) => Some(3379),
        (3, 7) => Some(3394),
        (3, 8) => Some(3413),
        (3, 9) => Some(3425),
        (3, 10) => Some(3439),
        (3, 11) => Some(3495),
        (3, 12) => Some(3531),
        (3, 13) => Some(3571),
        (3, 14) => Some(3627),
        _ => None,
    }
}

#[must_use]
pub const fn pyversion_from_magic(magic: u16) -> Option<PyVersion> {
    match magic {
        62211 => Some(PyVersion::PY27),
        3230 => Some(PyVersion::PY33),
        3310 => Some(PyVersion::PY34),
        3351 => Some(PyVersion::PY35),
        3379 => Some(PyVersion::PY36),
        3394 => Some(PyVersion::PY37),
        3413 => Some(PyVersion::PY38),
        3425 => Some(PyVersion::PY39),
        3439 | 384 => Some(PyVersion::PY310),
        3495 | 385 => Some(PyVersion::PY311),
        3531 | 386 => Some(PyVersion::PY312),
        3571 => Some(PyVersion::PY313),
        3627 => Some(PyVersion::PY314),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_sizes_per_version() {
        assert_eq!(PyVersion::PY27.pyc_header_len(), 8);
        assert_eq!(PyVersion::PY36.pyc_header_len(), 12);
        assert_eq!(PyVersion::PY37.pyc_header_len(), 16);
        assert_eq!(PyVersion::PY314.pyc_header_len(), 16);
    }

    #[test]
    fn wordcode_transition_at_36() {
        assert!(!PyVersion::PY35.is_wordcode());
        assert!(PyVersion::PY36.is_wordcode());
        assert!(PyVersion::PY314.is_wordcode());
    }

    #[test]
    fn magic_round_trip() {
        for v in [
            PyVersion::PY27,
            PyVersion::PY36,
            PyVersion::PY39,
            PyVersion::PY311,
            PyVersion::PY312,
            PyVersion::PY313,
            PyVersion::PY314,
        ] {
            let m: u16 = magic_for(v).unwrap();
            assert_eq!(
                pyversion_from_magic(m),
                Some(v),
                "round trip failed for {v:?}"
            );
        }
    }
}
