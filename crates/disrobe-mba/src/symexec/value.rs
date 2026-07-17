use oxiz::TermId;

pub(crate) const MAX_WIDTH_BITS: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BitWidth(u16);

impl BitWidth {
    pub(crate) const BYTE: Self = Self(8);
    pub(crate) const QWORD: Self = Self(64);

    pub(crate) const fn new(bits: u16) -> Option<Self> {
        if bits >= 1 && bits <= MAX_WIDTH_BITS {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub(crate) const fn from_bytes(bytes: u32) -> Option<Self> {
        match bytes {
            1..=8 => Self::new((bytes as u16).wrapping_mul(8)),
            _ => None,
        }
    }

    pub(crate) const fn bits(self) -> u16 {
        self.0
    }

    pub(crate) const fn bits_u32(self) -> u32 {
        self.0 as u32
    }

    pub(crate) const fn mask(self) -> u64 {
        if self.0 >= 64 {
            u64::MAX
        } else {
            (1u64 << self.0) - 1
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sym {
    Const { width: BitWidth, value: u64 },
    Bv { width: BitWidth, term: TermId },
    Bool { width: BitWidth, pred: TermId },
}

impl Sym {
    pub(crate) const fn constant(width: BitWidth, value: u64) -> Self {
        Self::Const {
            width,
            value: value & width.mask(),
        }
    }

    pub(crate) const fn bv(width: BitWidth, term: TermId) -> Self {
        Self::Bv { width, term }
    }

    pub(crate) const fn boolean(width: BitWidth, pred: TermId) -> Self {
        Self::Bool { width, pred }
    }

    pub(crate) const fn width(self) -> BitWidth {
        match self {
            Self::Const { width, .. } | Self::Bv { width, .. } | Self::Bool { width, .. } => width,
        }
    }

    pub(crate) const fn const_value(self) -> Option<u64> {
        match self {
            Self::Const { value, .. } => Some(value),
            Self::Bv { .. } | Self::Bool { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AluOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Lshr,
    Ashr,
    Udiv,
    Sdiv,
    Urem,
    Srem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnaryOp {
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CmpOp {
    Eq,
    Ne,
    Ult,
    Ule,
    Slt,
    Sle,
}

pub(crate) fn fold_alu(op: AluOp, lhs: u64, rhs: u64, width: BitWidth) -> Option<u64> {
    let mask: u64 = width.mask();
    let lhs: u64 = lhs & mask;
    let rhs: u64 = rhs & mask;
    let bits: u64 = u64::from(width.bits());
    let value: u64 = match op {
        AluOp::Add => lhs.wrapping_add(rhs),
        AluOp::Sub => lhs.wrapping_sub(rhs),
        AluOp::Mul => lhs.wrapping_mul(rhs),
        AluOp::And => lhs & rhs,
        AluOp::Or => lhs | rhs,
        AluOp::Xor => lhs ^ rhs,
        AluOp::Shl | AluOp::Lshr if rhs >= bits => 0,
        AluOp::Shl => lhs.wrapping_shl(rhs as u32),
        AluOp::Lshr => lhs >> rhs,
        AluOp::Ashr | AluOp::Udiv | AluOp::Sdiv | AluOp::Urem | AluOp::Srem => return None,
    };
    Some(value & mask)
}

pub(crate) const fn fold_unary(op: UnaryOp, operand: u64, width: BitWidth) -> u64 {
    let mask: u64 = width.mask();
    let operand: u64 = operand & mask;
    let value: u64 = match op {
        UnaryOp::Not => !operand,
    };
    value & mask
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn width_masks_are_exact() {
        assert_eq!(BitWidth::new(8).map(BitWidth::mask), Some(0xff));
        assert_eq!(BitWidth::new(64).map(BitWidth::mask), Some(u64::MAX));
        assert!(BitWidth::new(0).is_none());
        assert!(BitWidth::new(65).is_none());
    }

    #[test]
    fn bytes_convert_to_supported_widths() {
        assert_eq!(BitWidth::from_bytes(1).map(BitWidth::bits), Some(8));
        assert_eq!(BitWidth::from_bytes(8).map(BitWidth::bits), Some(64));
        assert!(BitWidth::from_bytes(0).is_none());
        assert!(BitWidth::from_bytes(16).is_none());
    }

    #[test]
    fn constant_is_masked_to_width() {
        let Some(width): Option<BitWidth> = BitWidth::new(8) else {
            panic!("width 8 is valid");
        };
        assert_eq!(Sym::constant(width, 0x1ff).const_value(), Some(0xff));
    }

    #[test]
    fn alu_fold_wraps_at_width() {
        let Some(width): Option<BitWidth> = BitWidth::new(8) else {
            panic!("width 8 is valid");
        };
        assert_eq!(fold_alu(AluOp::Add, 0xff, 0x02, width), Some(0x01));
        assert_eq!(fold_alu(AluOp::Or, 0xf0, 0x0f, width), Some(0xff));
        assert_eq!(fold_alu(AluOp::Shl, 0x01, 0x09, width), Some(0x00));
        assert_eq!(fold_alu(AluOp::Lshr, 0x80, 0x07, width), Some(0x01));
        assert_eq!(fold_alu(AluOp::Sdiv, 0x10, 0x02, width), None);
    }

    #[test]
    fn unary_fold_masks_result() {
        let Some(width): Option<BitWidth> = BitWidth::new(8) else {
            panic!("width 8 is valid");
        };
        assert_eq!(fold_unary(UnaryOp::Not, 0x0f, width), 0xf0);
    }
}
