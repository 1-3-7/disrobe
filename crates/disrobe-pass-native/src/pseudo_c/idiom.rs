use std::collections::{BTreeMap, BTreeSet};

use super::{
    BinOp, ExtSource, Flags, IndexExtend, IndexOperand, Item, ItemKind, MemRef, Reg, RegRef,
    Source, Stmt, Width,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Wide {
    high: u128,
    low: u128,
}

impl Wide {
    const fn from_u128(value: u128) -> Self {
        Self {
            high: 0,
            low: value,
        }
    }

    const fn narrow(self) -> Option<u128> {
        if self.high == 0 { Some(self.low) } else { None }
    }

    const fn mul(lhs: u128, rhs: u128) -> Self {
        const LIMB: u128 = u64::MAX as u128;
        let lhs_low: u128 = lhs & LIMB;
        let lhs_high: u128 = lhs >> 64;
        let rhs_low: u128 = rhs & LIMB;
        let rhs_high: u128 = rhs >> 64;
        let low_low: u128 = lhs_low.wrapping_mul(rhs_low);
        let low_high: u128 = lhs_low.wrapping_mul(rhs_high);
        let high_low: u128 = lhs_high.wrapping_mul(rhs_low);
        let high_high: u128 = lhs_high.wrapping_mul(rhs_high);
        let (middle, middle_carry): (u128, bool) = low_high.overflowing_add(high_low);
        let middle_low: u128 = middle << 64;
        let carried: u128 = if middle_carry { 1u128 << 64 } else { 0 };
        let middle_high: u128 = (middle >> 64).wrapping_add(carried);
        let (low, low_carry): (u128, bool) = low_low.overflowing_add(middle_low);
        let ripple: u128 = if low_carry { 1 } else { 0 };
        let high: u128 = high_high.wrapping_add(middle_high).wrapping_add(ripple);
        Self { high, low }
    }

    const fn pow2(exponent: u32) -> Option<Self> {
        if exponent < 128 {
            Some(Self {
                high: 0,
                low: 1u128 << exponent,
            })
        } else if exponent < 256 {
            Some(Self {
                high: 1u128 << (exponent - 128),
                low: 0,
            })
        } else {
            None
        }
    }

    const fn scaled_pow2(value: u128, exponent: u32) -> Option<Self> {
        if exponent >= 256 {
            return None;
        }
        if exponent < 128 {
            return Some(Self::mul(value, 1u128 << exponent));
        }
        let shifted: Self = Self::mul(value, 1u128 << (exponent - 128));
        if shifted.high != 0 {
            return None;
        }
        Some(Self {
            high: shifted.low,
            low: 0,
        })
    }

    const fn checked_sub(self, other: Self) -> Option<Self> {
        if self.high < other.high || (self.high == other.high && self.low < other.low) {
            return None;
        }
        let borrow: u128 = if self.low < other.low { 1 } else { 0 };
        let low: u128 = self.low.wrapping_sub(other.low);
        let high: u128 = self.high.wrapping_sub(other.high).wrapping_sub(borrow);
        Some(Self { high, low })
    }
}

pub(super) const MAX_DIVIDEND_BITS: u32 = 64;

const DIVISOR_SEARCH_STEPS: u32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MagicWitness {
    pub(super) multiplier: u128,
    pub(super) total_shift: u32,
    pub(super) dividend_bits: u32,
    pub(super) pre_shift: u32,
    pub(super) signed: bool,
}

fn quotient_is_exact_over(
    multiplier: u128,
    total_shift: u32,
    upper: u128,
    divisor: u128,
    inclusive: bool,
) -> bool {
    let Some(scale): Option<Wide> = Wide::pow2(total_shift) else {
        return false;
    };
    let product: Wide = Wide::mul(multiplier, divisor);
    if inclusive && product <= scale {
        return false;
    }
    let Some(error_wide): Option<Wide> = product.checked_sub(scale) else {
        return false;
    };
    let Some(error): Option<u128> = error_wide.narrow() else {
        return false;
    };
    let Some(span): Option<u128> = upper.checked_add(1) else {
        return false;
    };
    let full_blocks: u128 = span / divisor;
    if full_blocks > 0 {
        let bound: Wide = Wide::mul(full_blocks, error);
        let limit: Wide = Wide::from_u128(multiplier);
        if inclusive {
            if bound > limit {
                return false;
            }
        } else if bound >= limit {
            return false;
        }
    }
    let Some(blocks): Option<u128> = (upper / divisor).checked_add(1) else {
        return false;
    };
    let left: Wide = Wide::mul(upper, multiplier);
    let Some(right): Option<Wide> = Wide::scaled_pow2(blocks, total_shift) else {
        return false;
    };
    if inclusive {
        left <= right
    } else {
        left < right
    }
}

fn divisor_reproduces_witness(witness: MagicWitness, divisor: u128) -> bool {
    if divisor < 2 {
        return false;
    }
    let Some(value_bits): Option<u32> = witness.dividend_bits.checked_sub(witness.pre_shift) else {
        return false;
    };
    if value_bits == 0 || value_bits > MAX_DIVIDEND_BITS {
        return false;
    }
    if witness.signed {
        if witness.pre_shift != 0 {
            return false;
        }
        let magnitude: u128 = 1u128 << (value_bits - 1);
        if divisor >= magnitude {
            return false;
        }
        quotient_is_exact_over(
            witness.multiplier,
            witness.total_shift,
            magnitude - 1,
            divisor,
            false,
        ) && quotient_is_exact_over(
            witness.multiplier,
            witness.total_shift,
            magnitude,
            divisor,
            true,
        )
    } else {
        let upper: u128 = (1u128 << value_bits) - 1;
        if divisor > upper {
            return false;
        }
        quotient_is_exact_over(
            witness.multiplier,
            witness.total_shift,
            upper,
            divisor,
            false,
        )
    }
}

fn smallest_divisor_reaching_scale(
    multiplier: u128,
    total_shift: u32,
    ceiling: u128,
) -> Option<u128> {
    let scale: Wide = Wide::pow2(total_shift)?;
    if Wide::mul(multiplier, ceiling) < scale {
        return None;
    }
    let mut low: u128 = 1;
    let mut high: u128 = ceiling;
    let mut steps: u32 = 0;
    while low < high {
        if steps >= DIVISOR_SEARCH_STEPS {
            return None;
        }
        steps += 1;
        let middle: u128 = low + (high - low) / 2;
        if Wide::mul(multiplier, middle) < scale {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Some(low)
}

pub(super) fn recovered_divisor(witness: MagicWitness) -> Option<u64> {
    if witness.multiplier == 0 || witness.dividend_bits > MAX_DIVIDEND_BITS {
        return None;
    }
    if witness.total_shift >= 256 || witness.pre_shift >= witness.dividend_bits {
        return None;
    }
    let value_bits: u32 = witness.dividend_bits - witness.pre_shift;
    let ceiling: u128 = if witness.signed {
        1u128 << (value_bits - 1)
    } else {
        (1u128 << value_bits) - 1
    };
    let anchor: u128 =
        smallest_divisor_reaching_scale(witness.multiplier, witness.total_shift, ceiling)?;
    if !divisor_reproduces_witness(witness, anchor) {
        return None;
    }
    let scaled: u128 = anchor.checked_mul(1u128 << witness.pre_shift)?;
    u64::try_from(scaled).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuotientOp {
    Divide,
    Remainder,
}

pub(super) const fn quotient_binop(signed: bool, op: QuotientOp) -> BinOp {
    match (signed, op) {
        (true, QuotientOp::Divide) => BinOp::Sdiv,
        (false, QuotientOp::Divide) => BinOp::Udiv,
        (true, QuotientOp::Remainder) => BinOp::Srem,
        (false, QuotientOp::Remainder) => BinOp::Urem,
    }
}

const SLOT_DIVIDEND: u8 = 0;
const CONST_COUNT: usize = 2;
const CONST_SHIFT: usize = 0;
const CONST_PRE_SHIFT: usize = 1;
const IDIOM_WINDOW_STATEMENTS: usize = 24;
const IDIOM_LOOKBACK_STATEMENTS: usize = 6;
const REMAINDER_TAIL_STATEMENTS: usize = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Amount {
    Capture,
    CapturePreShift,
    DividendBits,
    DividendBitsLessOne,
    ProductBitsLessOne,
    Literal(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepKind {
    MulMagic,
    WideMulMagic,
    Shift,
    Add,
    Sub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Step {
    kind: StepKind,
    lhs: u8,
    rhs: u8,
    dest: u8,
    op: BinOp,
    amount: Amount,
    optional: bool,
}

const fn step(kind: StepKind, lhs: u8, rhs: u8, dest: u8) -> Step {
    Step {
        kind,
        lhs,
        rhs,
        dest,
        op: BinOp::Add,
        amount: Amount::Literal(0),
        optional: false,
    }
}

const fn shift_step(src: u8, op: BinOp, amount: Amount, dest: u8) -> Step {
    Step {
        kind: StepKind::Shift,
        lhs: src,
        rhs: src,
        dest,
        op,
        amount,
        optional: false,
    }
}

const fn optional_shift_step(src: u8, op: BinOp, amount: Amount, dest: u8) -> Step {
    Step {
        kind: StepKind::Shift,
        lhs: src,
        rhs: src,
        dest,
        op,
        amount,
        optional: true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShiftTerm {
    Captured,
    DividendBits,
    Literal(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extension {
    Zero,
    Sign,
    None,
}

#[derive(Debug, Clone, Copy)]
struct Rule {
    id: &'static str,
    steps: &'static [Step],
    signed: bool,
    implicit_high_bit: bool,
    shift_terms: &'static [ShiftTerm],
    quotient: u8,
}

const SLOT_ACC: u8 = 1;
const SLOT_TMP: u8 = 2;
const SLOT_SIGN: u8 = 3;

const UNSIGNED_PLAIN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::Capture, SLOT_ACC),
];

const UNSIGNED_WIDE_PLAIN: &[Step] = &[
    step(
        StepKind::WideMulMagic,
        SLOT_DIVIDEND,
        SLOT_DIVIDEND,
        SLOT_ACC,
    ),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::Capture, SLOT_ACC),
];

const UNSIGNED_ADD: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBits, SLOT_ACC),
    step(StepKind::Sub, SLOT_DIVIDEND, SLOT_ACC, SLOT_TMP),
    shift_step(SLOT_TMP, BinOp::Shr, Amount::Literal(1), SLOT_TMP),
    step(StepKind::Add, SLOT_ACC, SLOT_TMP, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::Capture, SLOT_ACC),
];

const UNSIGNED_WIDE_ADD: &[Step] = &[
    step(
        StepKind::WideMulMagic,
        SLOT_DIVIDEND,
        SLOT_DIVIDEND,
        SLOT_ACC,
    ),
    step(StepKind::Sub, SLOT_DIVIDEND, SLOT_ACC, SLOT_TMP),
    shift_step(SLOT_TMP, BinOp::Shr, Amount::Literal(1), SLOT_TMP),
    step(StepKind::Add, SLOT_ACC, SLOT_TMP, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::Capture, SLOT_ACC),
];

const SIGNED_PLAIN_DIVIDEND_SIGN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBits, SLOT_ACC),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    shift_step(
        SLOT_DIVIDEND,
        BinOp::Sar,
        Amount::DividendBitsLessOne,
        SLOT_SIGN,
    ),
    step(StepKind::Sub, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_PLAIN_PRODUCT_SIGN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::ProductBitsLessOne, SLOT_SIGN),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBits, SLOT_ACC),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_PLAIN_QUOTIENT_SIGN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBits, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBitsLessOne, SLOT_SIGN),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_ADD_DIVIDEND_SIGN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBits, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_DIVIDEND, SLOT_ACC),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    shift_step(
        SLOT_DIVIDEND,
        BinOp::Sar,
        Amount::DividendBitsLessOne,
        SLOT_SIGN,
    ),
    step(StepKind::Sub, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_ADD_QUOTIENT_SIGN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBits, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBitsLessOne, SLOT_SIGN),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const UNSIGNED_PRE_SHIFT: &[Step] = &[
    shift_step(SLOT_DIVIDEND, BinOp::Shr, Amount::CapturePreShift, SLOT_ACC),
    step(StepKind::MulMagic, SLOT_ACC, SLOT_ACC, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::Capture, SLOT_ACC),
];

const SIGNED_FUSED_DIVIDEND_SIGN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    shift_step(
        SLOT_DIVIDEND,
        BinOp::Sar,
        Amount::DividendBitsLessOne,
        SLOT_SIGN,
    ),
    step(StepKind::Sub, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_FUSED_PRODUCT_SIGN: &[Step] = &[
    step(StepKind::MulMagic, SLOT_DIVIDEND, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::ProductBitsLessOne, SLOT_SIGN),
    shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const UNSIGNED_WIDE_PRE_SHIFT: &[Step] = &[
    shift_step(SLOT_DIVIDEND, BinOp::Shr, Amount::CapturePreShift, SLOT_ACC),
    step(StepKind::WideMulMagic, SLOT_ACC, SLOT_ACC, SLOT_ACC),
    optional_shift_step(SLOT_ACC, BinOp::Shr, Amount::Capture, SLOT_ACC),
];

const SIGNED_WIDE_DIVIDEND_SIGN: &[Step] = &[
    step(
        StepKind::WideMulMagic,
        SLOT_DIVIDEND,
        SLOT_DIVIDEND,
        SLOT_ACC,
    ),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    shift_step(
        SLOT_DIVIDEND,
        BinOp::Sar,
        Amount::DividendBitsLessOne,
        SLOT_SIGN,
    ),
    step(StepKind::Sub, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_WIDE_QUOTIENT_SIGN: &[Step] = &[
    step(
        StepKind::WideMulMagic,
        SLOT_DIVIDEND,
        SLOT_DIVIDEND,
        SLOT_ACC,
    ),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBitsLessOne, SLOT_SIGN),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_WIDE_ADD_DIVIDEND_SIGN: &[Step] = &[
    step(
        StepKind::WideMulMagic,
        SLOT_DIVIDEND,
        SLOT_DIVIDEND,
        SLOT_ACC,
    ),
    step(StepKind::Add, SLOT_ACC, SLOT_DIVIDEND, SLOT_ACC),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    shift_step(
        SLOT_DIVIDEND,
        BinOp::Sar,
        Amount::DividendBitsLessOne,
        SLOT_SIGN,
    ),
    step(StepKind::Sub, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const SIGNED_WIDE_ADD_QUOTIENT_SIGN: &[Step] = &[
    step(
        StepKind::WideMulMagic,
        SLOT_DIVIDEND,
        SLOT_DIVIDEND,
        SLOT_ACC,
    ),
    step(StepKind::Add, SLOT_ACC, SLOT_DIVIDEND, SLOT_ACC),
    shift_step(SLOT_ACC, BinOp::Shr, Amount::DividendBitsLessOne, SLOT_SIGN),
    optional_shift_step(SLOT_ACC, BinOp::Sar, Amount::Capture, SLOT_ACC),
    step(StepKind::Add, SLOT_ACC, SLOT_SIGN, SLOT_ACC),
];

const RULES: &[Rule] = &[
    Rule {
        id: "udiv-magic-add",
        steps: UNSIGNED_ADD,
        signed: false,
        implicit_high_bit: true,
        shift_terms: &[
            ShiftTerm::DividendBits,
            ShiftTerm::Literal(1),
            ShiftTerm::Captured,
        ],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "udiv-magic-wide-add",
        steps: UNSIGNED_WIDE_ADD,
        signed: false,
        implicit_high_bit: true,
        shift_terms: &[
            ShiftTerm::DividendBits,
            ShiftTerm::Literal(1),
            ShiftTerm::Captured,
        ],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "udiv-magic-plain",
        steps: UNSIGNED_PLAIN,
        signed: false,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "udiv-magic-wide-plain",
        steps: UNSIGNED_WIDE_PLAIN,
        signed: false,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-add-dividend-sign",
        steps: SIGNED_ADD_DIVIDEND_SIGN,
        signed: true,
        implicit_high_bit: true,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-add-quotient-sign",
        steps: SIGNED_ADD_QUOTIENT_SIGN,
        signed: true,
        implicit_high_bit: true,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-plain-dividend-sign",
        steps: SIGNED_PLAIN_DIVIDEND_SIGN,
        signed: true,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-plain-product-sign",
        steps: SIGNED_PLAIN_PRODUCT_SIGN,
        signed: true,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-plain-quotient-sign",
        steps: SIGNED_PLAIN_QUOTIENT_SIGN,
        signed: true,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-fused-dividend-sign",
        steps: SIGNED_FUSED_DIVIDEND_SIGN,
        signed: true,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-fused-product-sign",
        steps: SIGNED_FUSED_PRODUCT_SIGN,
        signed: true,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-wide-add-dividend-sign",
        steps: SIGNED_WIDE_ADD_DIVIDEND_SIGN,
        signed: true,
        implicit_high_bit: true,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-wide-add-quotient-sign",
        steps: SIGNED_WIDE_ADD_QUOTIENT_SIGN,
        signed: true,
        implicit_high_bit: true,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-wide-dividend-sign",
        steps: SIGNED_WIDE_DIVIDEND_SIGN,
        signed: true,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "sdiv-magic-wide-quotient-sign",
        steps: SIGNED_WIDE_QUOTIENT_SIGN,
        signed: true,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "udiv-magic-pre-shift",
        steps: UNSIGNED_PRE_SHIFT,
        signed: false,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
    Rule {
        id: "udiv-magic-wide-pre-shift",
        steps: UNSIGNED_WIDE_PRE_SHIFT,
        signed: false,
        implicit_high_bit: false,
        shift_terms: &[ShiftTerm::DividendBits, ShiftTerm::Captured],
        quotient: SLOT_ACC,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Slot(u8),
    Constant(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Observed {
    MulConst {
        dest: RegRef,
        src: RegRef,
        magic: i64,
    },
    WideMul {
        src: RegRef,
        signed: bool,
    },
    Shift {
        dest: RegRef,
        op: BinOp,
        amount: u8,
    },
    Add {
        dest: RegRef,
        lhs: Reg,
        rhs: Reg,
    },
    Sub {
        dest: RegRef,
        lhs: Reg,
        rhs: Reg,
    },
    Copy {
        dest: RegRef,
        src: RegRef,
        extension: Extension,
    },
    LoadConst {
        dest: RegRef,
        value: u64,
    },
    Opaque,
}

fn immediate_value(width: Width, value: i64) -> u64 {
    match width {
        Width::W8 => u64::from(value as u8),
        Width::W16 => u64::from(value as u16),
        Width::W32 => u64::from(value as u32),
        Width::W64 => value as u64,
    }
}

fn classify(stmt: &Stmt, held: &BTreeMap<Reg, (Held, Width)>) -> Observed {
    match stmt {
        Stmt::Assign { dest, src } => match src {
            Source::Reg(source) => Observed::Copy {
                dest: *dest,
                src: *source,
                extension: Extension::Zero,
            },
            Source::Imm(value) => Observed::LoadConst {
                dest: *dest,
                value: immediate_value(dest.width, *value),
            },
            Source::Lea {
                base: Some(base),
                index: Some(index),
                disp: 0,
            } if index.scale == 1 && index.extend == IndexExtend::Full => Observed::Add {
                dest: *dest,
                lhs: *base,
                rhs: index.reg,
            },
            Source::Lea { .. } | Source::Mem(_) => Observed::Opaque,
        },
        Stmt::Extend {
            dest,
            src: ExtSource::Reg(source),
            signed,
        } => Observed::Copy {
            dest: *dest,
            src: *source,
            extension: if *signed {
                Extension::Sign
            } else {
                Extension::Zero
            },
        },
        Stmt::MulImm {
            dest,
            src: ExtSource::Reg(source),
            imm,
        } => Observed::MulConst {
            dest: *dest,
            src: *source,
            magic: *imm,
        },
        Stmt::WideMul { src, signed } => Observed::WideMul {
            src: *src,
            signed: *signed,
        },
        Stmt::BinAssign { dest, op, src } => match (op, src) {
            (BinOp::Imul, Source::Imm(value)) => Observed::MulConst {
                dest: *dest,
                src: *dest,
                magic: *value,
            },
            (BinOp::Imul, Source::Reg(source)) => {
                match (held.get(&source.reg), held.get(&dest.reg)) {
                    (Some((Held::Constant(value), _)), _) => Observed::MulConst {
                        dest: *dest,
                        src: *dest,
                        magic: *value as i64,
                    },
                    (_, Some((Held::Constant(value), _))) => Observed::MulConst {
                        dest: *dest,
                        src: *source,
                        magic: *value as i64,
                    },
                    _ => Observed::Opaque,
                }
            }
            (BinOp::Shr | BinOp::Sar, Source::Imm(value)) => {
                u8::try_from(*value).map_or(Observed::Opaque, |amount: u8| Observed::Shift {
                    dest: *dest,
                    op: *op,
                    amount,
                })
            }
            (BinOp::Add, Source::Reg(source)) => Observed::Add {
                dest: *dest,
                lhs: dest.reg,
                rhs: source.reg,
            },
            (BinOp::Sub, Source::Reg(source)) => Observed::Sub {
                dest: *dest,
                lhs: dest.reg,
                rhs: source.reg,
            },
            _ => Observed::Opaque,
        },
        _ => Observed::Opaque,
    }
}

fn written_registers(stmt: &Stmt) -> Option<Vec<Reg>> {
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::Cond { dest, .. }
        | Stmt::SetCc { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::PackedToGpr { dest, .. }
        | Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. } => Some(vec![dest.reg]),
        Stmt::WideMul { .. } | Stmt::Divide { .. } => Some(vec![Reg::Rax, Reg::Rdx]),
        Stmt::Store { .. }
        | Stmt::MemRmw { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMov { .. }
        | Stmt::FpStore { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpConvert { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpCsel { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::Packed { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::Vector(_) => Some(Vec::new()),
        Stmt::BlockMove { .. } | Stmt::BlockFill { .. } | Stmt::Call { .. } => None,
    }
}

fn note_every_read(reg: Reg, _: &BTreeMap<Reg, bool>, acc: &mut Vec<Reg>) {
    acc.push(reg);
}

fn collect_flag_reads(flags: &Flags, acc: &mut Vec<Reg>) {
    let written: BTreeMap<Reg, bool> = BTreeMap::new();
    super::read_flags(flags, &written, acc, &mut note_every_read);
}

fn collect_source_reads(src: &Source, acc: &mut Vec<Reg>) {
    let written: BTreeMap<Reg, bool> = BTreeMap::new();
    super::read_sources(src, &written, acc, &mut note_every_read);
}

fn collect_address_reads(addr: &MemRef, acc: &mut Vec<Reg>) {
    let written: BTreeMap<Reg, bool> = BTreeMap::new();
    super::read_addr(addr, &written, acc, &mut note_every_read);
}

const fn partial_write(width: Width) -> bool {
    matches!(width, Width::W8 | Width::W16)
}

fn read_registers(stmt: &Stmt) -> Option<Vec<Reg>> {
    let mut acc: Vec<Reg> = Vec::new();
    match stmt {
        Stmt::Assign { dest, src } => {
            if partial_write(dest.width) {
                acc.push(dest.reg);
            }
            collect_source_reads(src, &mut acc);
        }
        Stmt::BinAssign { dest, src, .. } => {
            acc.push(dest.reg);
            collect_source_reads(src, &mut acc);
        }
        Stmt::UnAssign { dest, .. } => acc.push(dest.reg),
        Stmt::Cond {
            dest, src, flags, ..
        } => {
            acc.push(dest.reg);
            collect_source_reads(src, &mut acc);
            collect_flag_reads(flags, &mut acc);
        }
        Stmt::SetCc { dest, flags, .. } => {
            if partial_write(dest.width) {
                acc.push(dest.reg);
            }
            collect_flag_reads(flags, &mut acc);
        }
        Stmt::Store { addr, src } => {
            collect_address_reads(addr, &mut acc);
            collect_source_reads(src, &mut acc);
        }
        Stmt::MemRmw { addr, op } => {
            collect_address_reads(addr, &mut acc);
            if let Some(src) = op.source() {
                collect_source_reads(src, &mut acc);
            }
        }
        Stmt::Extend { dest, src, .. } | Stmt::MulImm { dest, src, .. } => {
            if partial_write(dest.width) {
                acc.push(dest.reg);
            }
            match src {
                ExtSource::Reg(source) => acc.push(source.reg),
                ExtSource::Mem(mem) => collect_address_reads(mem, &mut acc),
            }
        }
        Stmt::WideMul { src, .. } => {
            acc.push(Reg::Rax);
            acc.push(src.reg);
        }
        Stmt::Divide { divisor, .. } => {
            acc.push(Reg::Rax);
            acc.push(Reg::Rdx);
            acc.push(divisor.reg);
        }
        Stmt::DoubleShift { dest, src, .. } => {
            acc.push(dest.reg);
            acc.push(src.reg);
        }
        Stmt::IntToFp { src, .. } | Stmt::GprToXmm { src, .. } => acc.push(src.reg),
        Stmt::FpToInt { dest, .. } | Stmt::XmmToGpr { dest, .. } => {
            if partial_write(dest.width) {
                acc.push(dest.reg);
            }
        }
        _ => return None,
    }
    Some(acc)
}

fn item_reads_register(item: &Item, reg: Reg) -> bool {
    match &item.kind {
        ItemKind::Stmt(stmt) => {
            read_registers(stmt).is_none_or(|regs: Vec<Reg>| regs.contains(&reg))
        }
        ItemKind::Branch { flags, .. } => {
            let mut acc: Vec<Reg> = Vec::new();
            collect_flag_reads(flags, &mut acc);
            acc.contains(&reg)
        }
        ItemKind::Switch { disc, .. } => disc.reg == reg,
        ItemKind::Jmp { .. } => false,
        ItemKind::Ret => reg == Reg::Rax,
    }
}

fn register_is_dead_after(items: &[Item], end: usize, reg: Reg) -> bool {
    let Some(tail): Option<&[Item]> = items.get(end + 1..) else {
        return false;
    };
    for (offset, item) in tail.iter().enumerate() {
        if item_reads_register(item, reg) {
            return false;
        }
        let ItemKind::Stmt(stmt) = &item.kind else {
            return !tail[offset..]
                .iter()
                .any(|later: &Item| item_reads_register(later, reg));
        };
        if written_registers(stmt).is_some_and(|writes: Vec<Reg>| writes.contains(&reg)) {
            return true;
        }
    }
    true
}

fn region_is_straight_line(items: &[Item], start: usize, end: usize) -> bool {
    let Some(entry): Option<&Item> = items.get(start) else {
        return false;
    };
    if !items[start..=end]
        .iter()
        .all(|item: &Item| matches!(item.kind, ItemKind::Stmt(_)))
    {
        return false;
    }
    let Some(exit): Option<&Item> = items.get(end) else {
        return false;
    };
    if items.iter().any(|item: &Item| match &item.kind {
        ItemKind::Branch { target, .. } | ItemKind::Jmp { target } => {
            *target > entry.address && *target <= exit.address
        }
        ItemKind::Switch { cases, default, .. } => {
            *default > entry.address && *default <= exit.address
                || cases.iter().any(|(_, target): &(i64, u64)| {
                    *target > entry.address && *target <= exit.address
                })
        }
        ItemKind::Stmt(_) | ItemKind::Ret => false,
    }) {
        return false;
    }
    !items[start..].iter().any(|item: &Item| match &item.kind {
        ItemKind::Branch { target, .. } | ItemKind::Jmp { target } => *target <= entry.address,
        ItemKind::Switch { cases, default, .. } => {
            *default <= entry.address
                || cases
                    .iter()
                    .any(|(_, target): &(i64, u64)| *target <= entry.address)
        }
        ItemKind::Stmt(_) | ItemKind::Ret => false,
    })
}

#[derive(Debug, Clone, Copy)]
struct DividendAnchor {
    register: Reg,
    width: Width,
    extension: Extension,
    start: usize,
}

fn trace_dividend(
    items: &[Item],
    anchor: usize,
    multiplicand: Reg,
    floor: usize,
) -> DividendAnchor {
    let mut register: Reg = multiplicand;
    let mut width: Width = Width::W64;
    let mut extension: Extension = Extension::None;
    let mut start: usize = anchor;
    let mut index: usize = anchor;
    while index > floor {
        index -= 1;
        let ItemKind::Stmt(stmt) = &items[index].kind else {
            break;
        };
        match classify(stmt, &BTreeMap::new()) {
            Observed::Copy {
                dest,
                src,
                extension: kind,
            } if dest.reg == register => {
                register = src.reg;
                width = src.width;
                extension = kind;
                start = index;
            }
            Observed::Shift {
                dest,
                op: BinOp::Shr,
                ..
            } if dest.reg == register => {
                width = dest.width;
                extension = Extension::Zero;
                start = index;
            }
            _ => {}
        }
    }
    while start > floor {
        let ItemKind::Stmt(stmt) = &items[start - 1].kind else {
            break;
        };
        if !matches!(classify(stmt, &BTreeMap::new()), Observed::LoadConst { .. }) {
            break;
        }
        start -= 1;
    }
    DividendAnchor {
        register,
        width,
        extension: if width == Width::W64 {
            Extension::None
        } else {
            extension
        },
        start,
    }
}

#[derive(Debug, Clone)]
struct IdiomMatch {
    start: usize,
    end: usize,
    dividend: RegRef,
    quotient: RegRef,
    carried: Vec<RegRef>,
    divisor: u64,
    signed: bool,
    rule: &'static str,
}

struct Matcher {
    held: BTreeMap<Reg, (Held, Width)>,
    captures: [Option<u8>; CONST_COUNT],
    matched: Vec<bool>,
    quotient: Option<RegRef>,
}

impl Matcher {
    fn slot_of(&self, reg: Reg) -> Option<u8> {
        match self.held.get(&reg) {
            Some((Held::Slot(slot), _)) => Some(*slot),
            _ => None,
        }
    }

    fn holds_slot(&self, reg: Reg, slot: u8) -> bool {
        self.slot_of(reg) == Some(slot)
    }

    fn bind(&mut self, dest: RegRef, slot: u8) {
        self.held.insert(dest.reg, (Held::Slot(slot), dest.width));
    }
}

const fn capture_index(amount: Amount) -> Option<usize> {
    match amount {
        Amount::Capture => Some(CONST_SHIFT),
        Amount::CapturePreShift => Some(CONST_PRE_SHIFT),
        Amount::DividendBits
        | Amount::DividendBitsLessOne
        | Amount::ProductBitsLessOne
        | Amount::Literal(_) => None,
    }
}

fn expected_amount(amount: Amount, dividend_bits: u32, product_bits: u32) -> Option<u8> {
    let value: u32 = match amount {
        Amount::Capture | Amount::CapturePreShift => return None,
        Amount::DividendBits => dividend_bits,
        Amount::DividendBitsLessOne => dividend_bits - 1,
        Amount::ProductBitsLessOne => product_bits - 1,
        Amount::Literal(literal) => u32::from(literal),
    };
    u8::try_from(value).ok()
}

fn step_matches(
    matcher: &Matcher,
    step: Step,
    observed: Observed,
    dividend_bits: u32,
    product_bits: u32,
    magic: Option<u64>,
    rule_signed: bool,
) -> Option<(RegRef, Option<u8>, u64)> {
    match (step.kind, observed) {
        (
            StepKind::MulMagic,
            Observed::MulConst {
                dest,
                src,
                magic: m,
            },
        ) => {
            if !matcher.holds_slot(src.reg, step.lhs) {
                return None;
            }
            let value: u64 = m as u64;
            if magic.is_some_and(|prior: u64| prior != value) {
                return None;
            }
            Some((dest, None, value))
        }
        (StepKind::WideMulMagic, Observed::WideMul { src, signed }) => {
            if signed != rule_signed {
                return None;
            }
            let (dividend, constant): (Reg, u64) = match (
                matcher.held.get(&Reg::Rax).copied(),
                matcher.held.get(&src.reg).copied(),
            ) {
                (Some((Held::Constant(value), _)), _) => (src.reg, value),
                (_, Some((Held::Constant(value), _))) => (Reg::Rax, value),
                _ => return None,
            };
            if !matcher.holds_slot(dividend, step.lhs) {
                return None;
            }
            if magic.is_some_and(|prior: u64| prior != constant) {
                return None;
            }
            Some((
                RegRef {
                    reg: Reg::Rdx,
                    width: Width::W64,
                },
                None,
                constant,
            ))
        }
        (StepKind::Shift, Observed::Shift { dest, op, amount }) => {
            if op != step.op || !matcher.holds_slot(dest.reg, step.lhs) {
                return None;
            }
            expected_amount(step.amount, dividend_bits, product_bits)
                .map_or(Some((dest, Some(amount), 0)), |expected: u8| {
                    (expected == amount).then_some((dest, None, 0))
                })
        }
        (StepKind::Add, Observed::Add { dest, lhs, rhs }) => {
            let direct: bool =
                matcher.holds_slot(lhs, step.lhs) && matcher.holds_slot(rhs, step.rhs);
            let swapped: bool =
                matcher.holds_slot(lhs, step.rhs) && matcher.holds_slot(rhs, step.lhs);
            (direct || swapped).then_some((dest, None, 0))
        }
        (StepKind::Sub, Observed::Sub { dest, lhs, rhs }) => (matcher.holds_slot(lhs, step.lhs)
            && matcher.holds_slot(rhs, step.rhs))
        .then_some((dest, None, 0)),
        _ => None,
    }
}

fn assemble_shift(rule: &Rule, captured: Option<u8>, dividend_bits: u32) -> Option<u32> {
    let mut total: u32 = 0;
    for term in rule.shift_terms {
        let value: u32 = match term {
            ShiftTerm::Captured => u32::from(captured.unwrap_or(0)),
            ShiftTerm::DividendBits => dividend_bits,
            ShiftTerm::Literal(literal) => *literal,
        };
        total = total.checked_add(value)?;
    }
    Some(total)
}

const fn sign_extended_magic(magic: u64, dividend_bits: u32) -> i64 {
    if dividend_bits >= 64 {
        magic as i64
    } else {
        ((magic << (64 - dividend_bits)) as i64) >> (64 - dividend_bits)
    }
}

fn magic_fits_product(magic: u64, dividend_bits: u32, product_bits: u32, signed: bool) -> bool {
    let magnitude: u64 = if signed {
        sign_extended_magic(magic, dividend_bits).unsigned_abs()
    } else {
        magic
    };
    let magic_bits: u32 = u64::BITS - magnitude.leading_zeros();
    dividend_bits
        .checked_add(magic_bits)
        .is_some_and(|needed: u32| needed <= product_bits)
}

fn effective_multiplier(rule: &Rule, magic: u64, dividend_bits: u32) -> Option<u128> {
    let base: i128 = if rule.signed {
        i128::from(sign_extended_magic(magic, dividend_bits))
    } else {
        i128::from(magic)
    };
    let raised: i128 = if rule.implicit_high_bit {
        base.checked_add(1i128 << dividend_bits)?
    } else {
        base
    };
    u128::try_from(raised).ok()
}

fn try_rule(items: &[Item], anchor: usize, rule: &'static Rule) -> Option<IdiomMatch> {
    let floor: usize = anchor.saturating_sub(IDIOM_LOOKBACK_STATEMENTS);
    let ItemKind::Stmt(anchor_stmt) = &items[anchor].kind else {
        return None;
    };
    let constants: BTreeMap<Reg, (Held, Width)> = constant_environment(items, floor, anchor);
    let multiplicand: Reg = match classify(anchor_stmt, &constants) {
        Observed::MulConst { src, .. } => src.reg,
        Observed::WideMul { src, .. } => match constants.get(&Reg::Rax) {
            Some((Held::Constant(_), _)) => src.reg,
            _ => Reg::Rax,
        },
        _ => return None,
    };
    let dividend: DividendAnchor = trace_dividend(items, anchor, multiplicand, floor);
    let dividend_bits: u32 = dividend.width.bits();
    if dividend_bits > MAX_DIVIDEND_BITS {
        return None;
    }
    let expected_extension: Extension = if dividend_bits == 64 {
        Extension::None
    } else if rule.signed {
        Extension::Sign
    } else {
        Extension::Zero
    };
    if dividend.extension != expected_extension {
        return None;
    }
    let mut matcher: Matcher = Matcher {
        held: BTreeMap::new(),
        captures: [None; CONST_COUNT],
        matched: vec![false; rule.steps.len()],
        quotient: None,
    };
    matcher.held.insert(
        dividend.register,
        (Held::Slot(SLOT_DIVIDEND), dividend.width),
    );
    let product_bits: u32 = if dividend_bits == 64 { 128 } else { 64 };
    let mut magic: Option<u64> = None;
    let mut end: usize = dividend.start;
    let limit: usize = (dividend.start + IDIOM_WINDOW_STATEMENTS).min(items.len());
    for (index, item) in items.iter().enumerate().take(limit).skip(dividend.start) {
        if matcher.matched.iter().all(|done: &bool| *done) {
            break;
        }
        let ItemKind::Stmt(stmt) = &item.kind else {
            break;
        };
        let observed: Observed = classify(stmt, &matcher.held);
        let mut consumed: bool = false;
        for slot in 0..rule.steps.len() {
            if matcher.matched[slot] {
                continue;
            }
            let step: Step = rule.steps[slot];
            let Some((dest, captured, found_magic)): Option<(RegRef, Option<u8>, u64)> =
                step_matches(
                    &matcher,
                    step,
                    observed,
                    dividend_bits,
                    product_bits,
                    magic,
                    rule.signed,
                )
            else {
                continue;
            };
            if step.kind == StepKind::MulMagic || step.kind == StepKind::WideMulMagic {
                magic = Some(found_magic);
            }
            if let Some(amount) = captured {
                let slot_index: usize = capture_index(step.amount)?;
                if matcher.captures[slot_index].is_some() {
                    return None;
                }
                matcher.captures[slot_index] = Some(amount);
            }
            matcher.matched[slot] = true;
            matcher.bind(dest, step.dest);
            if step.dest == rule.quotient {
                matcher.quotient = Some(dest);
            }
            consumed = true;
            end = index;
            break;
        }
        if consumed {
            continue;
        }
        match observed {
            Observed::Copy { dest, src, .. } => {
                let carried: Option<(Held, Width)> = matcher.held.get(&src.reg).copied();
                match carried {
                    Some((held, _)) => {
                        matcher.held.insert(dest.reg, (held, dest.width));
                    }
                    None => {
                        matcher.held.remove(&dest.reg);
                    }
                }
            }
            Observed::LoadConst { dest, value } => {
                matcher
                    .held
                    .insert(dest.reg, (Held::Constant(value), dest.width));
            }
            _ => {
                let writes: Vec<Reg> = written_registers(stmt)?;
                for reg in writes {
                    matcher.held.remove(&reg);
                }
            }
        }
    }
    if !matcher
        .matched
        .iter()
        .zip(rule.steps.iter())
        .all(|(done, step): (&bool, &Step)| *done || step.optional)
    {
        return None;
    }
    let quotient: RegRef = matcher.quotient?;
    let magic: u64 = magic?;
    if !magic_fits_product(magic, dividend_bits, product_bits, rule.signed) {
        return None;
    }
    let total_shift: u32 = assemble_shift(rule, matcher.captures[CONST_SHIFT], dividend_bits)?;
    let multiplier: u128 = effective_multiplier(rule, magic, dividend_bits)?;
    let witness: MagicWitness = MagicWitness {
        multiplier,
        total_shift,
        dividend_bits,
        pre_shift: u32::from(matcher.captures[CONST_PRE_SHIFT].unwrap_or(0)),
        signed: rule.signed,
    };
    let divisor: u64 = recovered_divisor(witness)?;
    let carried: Vec<RegRef> = matcher
        .held
        .iter()
        .filter(|(reg, (held, width)): &(&Reg, &(Held, Width))| {
            *held == Held::Slot(SLOT_DIVIDEND)
                && !(**reg == dividend.register && *width == dividend.width)
        })
        .map(|(reg, (_, width)): (&Reg, &(Held, Width))| RegRef {
            reg: *reg,
            width: *width,
        })
        .collect();
    if carried.iter().any(|held: &RegRef| held.reg == quotient.reg) {
        return None;
    }
    Some(IdiomMatch {
        start: dividend.start,
        end,
        dividend: RegRef {
            reg: dividend.register,
            width: dividend.width,
        },
        quotient: RegRef {
            reg: quotient.reg,
            width: dividend.width,
        },
        carried,
        divisor,
        signed: rule.signed,
        rule: rule.id,
    })
}

fn constant_environment(
    items: &[Item],
    floor: usize,
    anchor: usize,
) -> BTreeMap<Reg, (Held, Width)> {
    let mut held: BTreeMap<Reg, (Held, Width)> = BTreeMap::new();
    for item in &items[floor..anchor] {
        let ItemKind::Stmt(stmt) = &item.kind else {
            held.clear();
            continue;
        };
        match classify(stmt, &held) {
            Observed::LoadConst { dest, value } => {
                held.insert(dest.reg, (Held::Constant(value), dest.width));
            }
            _ => match written_registers(stmt) {
                Some(writes) => {
                    for reg in writes {
                        held.remove(&reg);
                    }
                }
                None => held.clear(),
            },
        }
    }
    held
}

fn window_is_removable(items: &[Item], found: &IdiomMatch) -> bool {
    if !region_is_straight_line(items, found.start, found.end) {
        return false;
    }
    let mut clobbered: BTreeSet<Reg> = BTreeSet::new();
    for item in &items[found.start..=found.end] {
        let ItemKind::Stmt(stmt) = &item.kind else {
            return false;
        };
        let Some(writes): Option<Vec<Reg>> = written_registers(stmt) else {
            return false;
        };
        clobbered.extend(writes);
        if matches!(stmt, Stmt::Store { .. } | Stmt::MemRmw { .. }) {
            return false;
        }
    }
    clobbered.remove(&found.quotient.reg);
    for held in &found.carried {
        clobbered.remove(&held.reg);
    }
    clobbered
        .into_iter()
        .all(|reg: Reg| register_is_dead_after(items, found.end, reg))
}

fn carried_statements(items: &[Item], found: &IdiomMatch, last: usize) -> Vec<Stmt> {
    found
        .carried
        .iter()
        .filter(|held: &&RegRef| !register_is_dead_after(items, last, held.reg))
        .map(|held: &RegRef| {
            let source: RegRef = RegRef {
                reg: found.dividend.reg,
                width: found.dividend.width,
            };
            if held.width.bits() > found.dividend.width.bits() {
                Stmt::Extend {
                    dest: *held,
                    src: ExtSource::Reg(source),
                    signed: found.signed,
                }
            } else {
                Stmt::Assign {
                    dest: *held,
                    src: Source::Reg(source),
                }
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Affine {
    dividend: i128,
    quotient: i128,
}

impl Affine {
    const fn scaled(self, factor: i128) -> Option<Self> {
        let dividend: i128 = match self.dividend.checked_mul(factor) {
            Some(value) => value,
            None => return None,
        };
        let quotient: i128 = match self.quotient.checked_mul(factor) {
            Some(value) => value,
            None => return None,
        };
        Some(Self { dividend, quotient })
    }

    const fn combined(self, other: Self, negate: bool) -> Option<Self> {
        let sign: i128 = if negate { -1 } else { 1 };
        let dividend: i128 = match other.dividend.checked_mul(sign) {
            Some(value) => match self.dividend.checked_add(value) {
                Some(sum) => sum,
                None => return None,
            },
            None => return None,
        };
        let quotient: i128 = match other.quotient.checked_mul(sign) {
            Some(value) => match self.quotient.checked_add(value) {
                Some(sum) => sum,
                None => return None,
            },
            None => return None,
        };
        Some(Self { dividend, quotient })
    }
}

fn remainder_register(items: &[Item], found: &IdiomMatch) -> Option<(usize, RegRef)> {
    let mut affine: BTreeMap<Reg, Affine> = BTreeMap::new();
    affine.insert(
        found.dividend.reg,
        Affine {
            dividend: 1,
            quotient: 0,
        },
    );
    affine.insert(
        found.quotient.reg,
        Affine {
            dividend: 0,
            quotient: 1,
        },
    );
    let target: Affine = Affine {
        dividend: 1,
        quotient: -i128::from(found.divisor),
    };
    let limit: usize = (found.end + 1 + REMAINDER_TAIL_STATEMENTS).min(items.len());
    for (index, item) in items.iter().enumerate().take(limit).skip(found.end + 1) {
        let ItemKind::Stmt(stmt) = &item.kind else {
            return None;
        };
        let observed: Observed = classify(stmt, &BTreeMap::new());
        let next: Option<(RegRef, Affine)> = match observed {
            Observed::Copy { dest, src, .. } => affine
                .get(&src.reg)
                .copied()
                .map(|value: Affine| (dest, value)),
            Observed::Add { dest, lhs, rhs } => match (affine.get(&lhs), affine.get(&rhs)) {
                (Some(left), Some(right)) => {
                    left.combined(*right, false).map(|v: Affine| (dest, v))
                }
                _ => None,
            },
            Observed::Sub { dest, lhs, rhs } => match (affine.get(&lhs), affine.get(&rhs)) {
                (Some(left), Some(right)) => left.combined(*right, true).map(|v: Affine| (dest, v)),
                _ => None,
            },
            Observed::MulConst { dest, src, magic } => affine
                .get(&src.reg)
                .and_then(|value: &Affine| value.scaled(i128::from(magic)))
                .map(|value: Affine| (dest, value)),
            Observed::Shift {
                dest,
                op: BinOp::Shl,
                amount,
            } => affine
                .get(&dest.reg)
                .and_then(|value: &Affine| value.scaled(1i128 << amount))
                .map(|value: Affine| (dest, value)),
            _ => scaled_lea(stmt, &affine),
        };
        match next {
            Some((dest, value)) => {
                if value == target {
                    return Some((index, dest));
                }
                affine.insert(dest.reg, value);
            }
            None => {
                let writes: Vec<Reg> = written_registers(stmt)?;
                for reg in writes {
                    affine.remove(&reg);
                }
            }
        }
    }
    None
}

fn scaled_lea(stmt: &Stmt, affine: &BTreeMap<Reg, Affine>) -> Option<(RegRef, Affine)> {
    let Stmt::Assign {
        dest,
        src: Source::Lea { base, index, disp },
    } = stmt
    else {
        return None;
    };
    if *disp != 0 {
        return None;
    }
    let index_operand: IndexOperand = (*index)?;
    if index_operand.extend != IndexExtend::Full {
        return None;
    }
    let scaled: Affine = affine
        .get(&index_operand.reg)?
        .scaled(i128::from(index_operand.scale))?;
    let total: Affine = match base {
        Some(base_reg) => affine.get(base_reg)?.combined(scaled, false)?,
        None => scaled,
    };
    Some((*dest, total))
}

fn division_statements(found: &IdiomMatch, op: QuotientOp, dest: RegRef) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(2);
    if dest.reg != found.dividend.reg {
        out.push(Stmt::Assign {
            dest,
            src: Source::Reg(RegRef {
                reg: found.dividend.reg,
                width: dest.width,
            }),
        });
    }
    out.push(Stmt::BinAssign {
        dest,
        op: quotient_binop(found.signed, op),
        src: Source::Imm(found.divisor as i64),
    });
    out
}

pub(super) fn fuse_constant_division_idioms(items: &mut Vec<Item>) {
    let mut index: usize = 0;
    while index < items.len() {
        let Some(found): Option<IdiomMatch> = RULES
            .iter()
            .find_map(|rule: &'static Rule| try_rule(items, index, rule))
        else {
            index += 1;
            continue;
        };
        if !window_is_removable(items, &found) {
            index += 1;
            continue;
        }
        let remainder: Option<(usize, RegRef)> = remainder_register(items, &found);
        let (last, replacement): (usize, Vec<Stmt>) = match remainder {
            Some((tail_end, tail_dest))
                if region_is_straight_line(items, found.start, tail_end) =>
            {
                let extended: IdiomMatch = IdiomMatch {
                    end: tail_end,
                    ..found.clone()
                };
                if !window_is_removable(items, &extended) {
                    index += 1;
                    continue;
                }
                let mut out: Vec<Stmt> = carried_statements(items, &found, tail_end);
                if tail_dest.reg != found.quotient.reg
                    && !register_is_dead_after(items, tail_end, found.quotient.reg)
                {
                    out.extend(division_statements(
                        &found,
                        QuotientOp::Divide,
                        found.quotient,
                    ));
                }
                out.extend(division_statements(
                    &found,
                    QuotientOp::Remainder,
                    RegRef {
                        reg: tail_dest.reg,
                        width: found.quotient.width,
                    },
                ));
                (tail_end, out)
            }
            _ => {
                let mut out: Vec<Stmt> = carried_statements(items, &found, found.end);
                out.extend(division_statements(
                    &found,
                    QuotientOp::Divide,
                    found.quotient,
                ));
                (found.end, out)
            }
        };
        let address: u64 = items[found.start].address;
        crate::debug::dbg_kv("idiom.const-division", || {
            format!(
                "{} at {address:#x} divisor {} signed {}",
                found.rule, found.divisor, found.signed
            )
        });
        let rewritten: Vec<Item> = replacement
            .into_iter()
            .map(|stmt: Stmt| Item {
                address,
                kind: ItemKind::Stmt(stmt),
            })
            .collect();
        let advance: usize = rewritten.len();
        items.splice(found.start..=last, rewritten);
        index = found.start + advance;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn witness(
        multiplier: u128,
        total_shift: u32,
        dividend_bits: u32,
        signed: bool,
    ) -> MagicWitness {
        MagicWitness {
            multiplier,
            total_shift,
            dividend_bits,
            pre_shift: 0,
            signed,
        }
    }

    #[test]
    fn wide_multiply_matches_u128_on_small_operands() {
        for lhs in [0u128, 1, 2, 3, 0xFFFF, 0x1_0000_0000, u64::MAX as u128] {
            for rhs in [0u128, 1, 7, 0xFFFF_FFFF, u64::MAX as u128] {
                let wide: Wide = Wide::mul(lhs, rhs);
                let expected: u128 = lhs.wrapping_mul(rhs);
                assert_eq!(
                    wide.narrow(),
                    Some(expected),
                    "{lhs} * {rhs} must stay inside 128 bits"
                );
            }
        }
    }

    #[test]
    fn wide_multiply_carries_into_the_high_half() {
        let wide: Wide = Wide::mul(u128::MAX, u128::MAX);
        assert_eq!(wide.high, u128::MAX - 1);
        assert_eq!(wide.low, 1);
    }

    #[test]
    fn scaled_pow2_places_high_bits() {
        let scaled: Wide = Wide::scaled_pow2(3, 128).expect("3 << 128 fits 256 bits");
        assert_eq!(scaled.high, 3);
        assert_eq!(scaled.low, 0);
        let small: Wide = Wide::scaled_pow2(5, 3).expect("5 << 3 fits");
        assert_eq!(small.narrow(), Some(40));
    }

    #[test]
    fn unsigned_plain_magic_recovers_its_divisor() {
        assert_eq!(
            recovered_divisor(witness(6_700_417, 32, 32, false)),
            Some(641)
        );
        assert_eq!(
            recovered_divisor(witness(0xAAAA_AAAB, 33, 32, false)),
            Some(3)
        );
    }

    #[test]
    fn unsigned_add_form_magic_recovers_its_divisor() {
        assert_eq!(
            recovered_divisor(witness(0x1_2492_4925, 35, 32, false)),
            Some(7)
        );
    }

    #[test]
    fn signed_magic_recovers_its_divisor() {
        assert_eq!(
            recovered_divisor(witness(0x5555_5556, 32, 32, true)),
            Some(3)
        );
        assert_eq!(
            recovered_divisor(witness(0x9249_2493, 34, 32, true)),
            Some(7)
        );
    }

    #[test]
    fn sixty_four_bit_magic_recovers_its_divisor() {
        assert_eq!(
            recovered_divisor(witness(0x1_2492_4924_9249_2493, 67, 64, false)),
            Some(7)
        );
        assert_eq!(
            recovered_divisor(witness(0x4924_9249_2492_4925, 65, 64, true)),
            Some(7)
        );
    }

    #[test]
    fn a_fixed_point_scale_is_not_a_division() {
        assert_eq!(recovered_divisor(witness(81_920, 16, 32, false)), None);
        assert_eq!(recovered_divisor(witness(0xCCCC_CCCD, 33, 32, false)), None);
        assert_eq!(recovered_divisor(witness(3, 1, 32, false)), None);
        assert_eq!(recovered_divisor(witness(0xC000_0000, 32, 32, false)), None);
    }

    #[test]
    fn a_perturbed_shift_is_rejected() {
        assert_eq!(
            recovered_divisor(witness(0x1_2492_4925, 33, 32, false)),
            None
        );
        assert_eq!(recovered_divisor(witness(0x9249_2493, 32, 32, true)), None);
        assert_eq!(recovered_divisor(witness(0x9249_2493, 33, 32, true)), None);
    }

    #[test]
    fn a_perturbed_multiplier_is_rejected() {
        assert_eq!(
            recovered_divisor(witness(0x1_2492_4926, 35, 32, false)),
            None
        );
        assert_eq!(
            recovered_divisor(witness(0x1_2492_4924, 35, 32, false)),
            None
        );
    }

    #[test]
    fn a_thirty_two_bit_magic_is_rejected_for_a_sixty_four_bit_dividend() {
        assert_eq!(
            recovered_divisor(witness(0x1_2492_4925, 35, 64, false)),
            None
        );
        assert_eq!(recovered_divisor(witness(0x5555_5556, 32, 64, true)), None);
    }

    #[test]
    fn pre_shifted_unsigned_magic_scales_the_divisor() {
        let pre: MagicWitness = MagicWitness {
            multiplier: 0xAAAA_AAAB,
            total_shift: 33,
            dividend_bits: 32,
            pre_shift: 1,
            signed: false,
        };
        assert_eq!(recovered_divisor(pre), Some(6));
    }
}
