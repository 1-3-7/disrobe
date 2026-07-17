use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TypeVar(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    RawArith,
    UsageIdiom,
    Abi,
    ApiSig,
    Metadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sign {
    Unknown,
    Signed,
    Unsigned,
    Conflict,
}

impl Sign {
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Conflict, _)
            | (_, Self::Conflict)
            | (Self::Signed, Self::Unsigned)
            | (Self::Unsigned, Self::Signed) => Self::Conflict,
            (Self::Unknown, value) | (value, Self::Unknown) => value,
            (Self::Signed, Self::Signed) => Self::Signed,
            (Self::Unsigned, Self::Unsigned) => Self::Unsigned,
        }
    }

    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _)
            | (_, Self::Unknown)
            | (Self::Signed, Self::Unsigned)
            | (Self::Unsigned, Self::Signed) => Self::Unknown,
            (Self::Conflict, value) | (value, Self::Conflict) => value,
            (Self::Signed, Self::Signed) => Self::Signed,
            (Self::Unsigned, Self::Unsigned) => Self::Unsigned,
        }
    }

    #[must_use]
    pub const fn is_determined(self) -> bool {
        matches!(self, Self::Signed | Self::Unsigned)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Width {
    Unknown,
    Byte,
    Word,
    Dword,
    Qword,
    Oword,
}

impl Width {
    #[must_use]
    pub const fn from_bytes(bytes: u8) -> Self {
        match bytes {
            1 => Self::Byte,
            2 => Self::Word,
            4 => Self::Dword,
            8 => Self::Qword,
            16 => Self::Oword,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn bytes(self) -> Option<u8> {
        match self {
            Self::Unknown => None,
            Self::Byte => Some(1),
            Self::Word => Some(2),
            Self::Dword => Some(4),
            Self::Qword => Some(8),
            Self::Oword => Some(16),
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 3,
            Self::Qword => 4,
            Self::Oword => 5,
        }
    }

    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "class")]
pub enum TypeClass {
    Top,
    Bottom,
    Numeric { width: Width, sign: Sign },
    Float { width: Width },
    Pointer { level: u8, pointee: TypeVar },
    CodePtr,
    Aggregate { handle: TypeVar },
}

impl TypeClass {
    #[must_use]
    pub const fn top() -> Self {
        Self::Top
    }

    #[must_use]
    pub const fn numeric(width: Width, sign: Sign) -> Self {
        Self::Numeric { width, sign }
    }

    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, value) | (value, Self::Top) => value,
            (
                Self::Numeric {
                    width: wl,
                    sign: sl,
                },
                Self::Numeric {
                    width: wr,
                    sign: sr,
                },
            ) => Self::Numeric {
                width: wl.join(wr),
                sign: sl.meet(sr),
            },
            (Self::Float { width: wl }, Self::Float { width: wr }) => {
                Self::Float { width: wl.join(wr) }
            }
            (Self::CodePtr, Self::CodePtr) => Self::CodePtr,
            (Self::Pointer { level: ll, pointee }, Self::Pointer { level: rl, .. }) if ll == rl => {
                Self::Pointer { level: ll, pointee }
            }
            (Self::Aggregate { handle }, Self::Aggregate { .. }) => Self::Aggregate { handle },
            _ => Self::Bottom,
        }
    }

    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bottom, value) | (value, Self::Bottom) => value,
            (
                Self::Numeric {
                    width: wl,
                    sign: sl,
                },
                Self::Numeric {
                    width: wr,
                    sign: sr,
                },
            ) => Self::Numeric {
                width: wl.join(wr),
                sign: sl.join(sr),
            },
            (Self::Float { width: wl }, Self::Float { width: wr }) => {
                Self::Float { width: wl.join(wr) }
            }
            (Self::CodePtr, Self::CodePtr) => Self::CodePtr,
            (Self::Pointer { level: ll, pointee }, Self::Pointer { level: rl, .. }) if ll == rl => {
                Self::Pointer { level: ll, pointee }
            }
            (Self::Aggregate { handle }, Self::Aggregate { .. }) => Self::Aggregate { handle },
            _ => Self::Top,
        }
    }

    #[must_use]
    pub const fn width(self) -> Width {
        match self {
            Self::Numeric { width, .. } | Self::Float { width } => width,
            Self::Pointer { .. } | Self::CodePtr => Width::Qword,
            Self::Top | Self::Bottom | Self::Aggregate { .. } => Width::Unknown,
        }
    }

    #[must_use]
    pub const fn sign(self) -> Sign {
        match self {
            Self::Numeric { sign, .. } => sign,
            _ => Sign::Unknown,
        }
    }

    #[must_use]
    pub const fn is_conflict(self) -> bool {
        matches!(self, Self::Bottom) || matches!(self.sign(), Sign::Conflict)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sign_meet_refines_and_conflicts() {
        assert_eq!(Sign::Unknown.meet(Sign::Signed), Sign::Signed);
        assert_eq!(Sign::Signed.meet(Sign::Unknown), Sign::Signed);
        assert_eq!(Sign::Signed.meet(Sign::Signed), Sign::Signed);
        assert_eq!(Sign::Signed.meet(Sign::Unsigned), Sign::Conflict);
        assert_eq!(Sign::Conflict.meet(Sign::Signed), Sign::Conflict);
    }

    #[test]
    fn sign_join_widens_disagreement_to_unknown() {
        assert_eq!(Sign::Signed.join(Sign::Signed), Sign::Signed);
        assert_eq!(Sign::Signed.join(Sign::Unsigned), Sign::Unknown);
        assert_eq!(Sign::Unknown.join(Sign::Signed), Sign::Unknown);
        assert_eq!(Sign::Conflict.join(Sign::Signed), Sign::Signed);
    }

    #[test]
    fn width_join_widens_to_larger() {
        assert_eq!(Width::Byte.join(Width::Dword), Width::Dword);
        assert_eq!(Width::Qword.join(Width::Word), Width::Qword);
        assert_eq!(Width::Unknown.join(Width::Byte), Width::Byte);
        assert_eq!(Width::from_bytes(8), Width::Qword);
        assert_eq!(Width::from_bytes(3), Width::Unknown);
        assert_eq!(Width::Dword.bytes(), Some(4));
    }

    #[test]
    fn numeric_meet_pointer_is_bottom() {
        let numeric: TypeClass = TypeClass::numeric(Width::Qword, Sign::Signed);
        let pointer: TypeClass = TypeClass::Pointer {
            level: 1,
            pointee: TypeVar(0),
        };
        assert_eq!(numeric.meet(pointer), TypeClass::Bottom);
        assert_eq!(numeric.meet(TypeClass::Top), numeric);
    }

    #[test]
    fn numeric_meet_combines_axes() {
        let a: TypeClass = TypeClass::numeric(Width::Byte, Sign::Unknown);
        let b: TypeClass = TypeClass::numeric(Width::Dword, Sign::Signed);
        assert_eq!(a.meet(b), TypeClass::numeric(Width::Dword, Sign::Signed));
    }

    #[test]
    fn confidence_orders_metadata_above_heuristics() {
        assert!(Confidence::Metadata > Confidence::ApiSig);
        assert!(Confidence::ApiSig > Confidence::Abi);
        assert!(Confidence::Abi > Confidence::UsageIdiom);
        assert!(Confidence::UsageIdiom > Confidence::RawArith);
    }
}
