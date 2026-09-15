use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Rung {
    Raw = 0,
    Disasm = 1,
    Mir = 2,
    Hir = 3,
    Surface = 4,
}

impl Rung {
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Raw),
            1 => Some(Self::Disasm),
            2 => Some(Self::Mir),
            3 => Some(Self::Hir),
            4 => Some(Self::Surface),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_rungs() {
        for rung in [Rung::Raw, Rung::Disasm, Rung::Mir, Rung::Hir, Rung::Surface] {
            let byte: u8 = rung.as_u8();
            assert_eq!(Rung::from_u8(byte), Some(rung));
        }
    }

    #[test]
    fn unknown_byte_returns_none() {
        assert_eq!(Rung::from_u8(0xFF), None);
    }
}
