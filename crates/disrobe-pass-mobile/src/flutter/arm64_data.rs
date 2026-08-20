#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

impl ShiftKind {
    const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Lsl),
            1 => Some(Self::Lsr),
            2 => Some(Self::Asr),
            3 => Some(Self::Ror),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogicalOp {
    And,
    Or,
    Xor,
    AndNot,
    OrNot,
    XorNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DivideOp {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VariableShiftOp {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FloatBinaryOp {
    Mul,
    Div,
    Add,
    Sub,
    Max,
    Min,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FloatUnaryOp {
    Move,
    Abs,
    Negate,
    SquareRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AddSubShiftedReg {
    pub(super) sixty_four: bool,
    pub(super) subtract: bool,
    pub(super) sets_flags: bool,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) rm: u8,
    pub(super) shift: ShiftKind,
    pub(super) amount: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LogicalShiftedReg {
    pub(super) sixty_four: bool,
    pub(super) op: LogicalOp,
    pub(super) sets_flags: bool,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) rm: u8,
    pub(super) shift: ShiftKind,
    pub(super) amount: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LogicalImmediate {
    pub(super) sixty_four: bool,
    pub(super) op: LogicalOp,
    pub(super) sets_flags: bool,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) mask: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BitfieldKind {
    ShiftRight { amount: u8, signed: bool },
    ShiftLeft { amount: u8 },
    Extract { lsb: u8, width: u8, signed: bool },
    ExtractInsert { lsb: u8, width: u8, signed: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Bitfield {
    pub(super) sixty_four: bool,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) kind: BitfieldKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MultiplyAccumulate {
    pub(super) sixty_four: bool,
    pub(super) subtract: bool,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) rm: u8,
    pub(super) ra: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DivideReg {
    pub(super) sixty_four: bool,
    pub(super) op: DivideOp,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) rm: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VariableShift {
    pub(super) sixty_four: bool,
    pub(super) op: VariableShiftOp,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) rm: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FloatBinary {
    pub(super) op: FloatBinaryOp,
    pub(super) rd: u8,
    pub(super) rn: u8,
    pub(super) rm: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FloatUnary {
    pub(super) op: FloatUnaryOp,
    pub(super) rd: u8,
    pub(super) rn: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IntegerToFloat {
    pub(super) signed: bool,
    pub(super) rd: u8,
    pub(super) rn: u8,
}

const ADD_SUB_SHIFTED_REG_MASK: u32 = 0x1F20_0000;

const ADD_SUB_SHIFTED_REG_MATCH: u32 = 0x0B00_0000;

const LOGICAL_SHIFTED_REG_MASK: u32 = 0x1F00_0000;

const LOGICAL_SHIFTED_REG_MATCH: u32 = 0x0A00_0000;

const LOGICAL_IMMEDIATE_MASK: u32 = 0x1F80_0000;

const LOGICAL_IMMEDIATE_MATCH: u32 = 0x1200_0000;

const BITFIELD_MASK: u32 = 0x1F80_0000;

const BITFIELD_MATCH: u32 = 0x1300_0000;

const MULTIPLY_MASK: u32 = 0x7FE0_0000;

const MULTIPLY_MATCH: u32 = 0x1B00_0000;

const DATA_PROC_2SRC_MASK: u32 = 0x7FE0_0000;

const DATA_PROC_2SRC_MATCH: u32 = 0x1AC0_0000;

const MOVN_MASK: u32 = 0x7F80_0000;

const MOVN_MATCH: u32 = 0x1280_0000;

const FLOAT_BINARY_MASK: u32 = 0xFF20_0C00;

const FLOAT_BINARY_MATCH: u32 = 0x1E20_0800;

const FLOAT_UNARY_MASK: u32 = 0xFF20_7C00;

const FLOAT_UNARY_MATCH: u32 = 0x1E20_4000;

const INTEGER_TO_FLOAT_MASK: u32 = 0x7F3E_FC00;

const INTEGER_TO_FLOAT_MATCH: u32 = 0x1E22_0000;

const DOUBLE_PRECISION_TYPE: u32 = 1;

const ARM64_ZERO_REGISTER: u8 = 31;

#[must_use]
pub(super) const fn is_zero_register(register: u8) -> bool {
    register == ARM64_ZERO_REGISTER
}

#[must_use]
pub(super) fn add_sub_shifted_reg(raw: u32) -> Option<AddSubShiftedReg> {
    if raw & ADD_SUB_SHIFTED_REG_MASK != ADD_SUB_SHIFTED_REG_MATCH {
        return None;
    }
    let shift: ShiftKind = ShiftKind::from_code((raw >> 22) & 0x3)?;
    if shift == ShiftKind::Ror {
        return None;
    }
    let sixty_four: bool = raw & 0x8000_0000 != 0;
    let amount: u8 = ((raw >> 10) & 0x3F) as u8;
    if !sixty_four && amount >= 32 {
        return None;
    }
    Some(AddSubShiftedReg {
        sixty_four,
        subtract: raw & 0x4000_0000 != 0,
        sets_flags: raw & 0x2000_0000 != 0,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
        rm: ((raw >> 16) & 0x1F) as u8,
        shift,
        amount,
    })
}

#[must_use]
pub(super) fn logical_shifted_reg(raw: u32) -> Option<LogicalShiftedReg> {
    if raw & LOGICAL_SHIFTED_REG_MASK != LOGICAL_SHIFTED_REG_MATCH {
        return None;
    }
    let shift: ShiftKind = ShiftKind::from_code((raw >> 22) & 0x3)?;
    let negated: bool = raw & 0x0020_0000 != 0;
    let opc: u32 = (raw >> 29) & 0x3;
    let op: LogicalOp = match (opc, negated) {
        (0 | 3, false) => LogicalOp::And,
        (0 | 3, true) => LogicalOp::AndNot,
        (1, false) => LogicalOp::Or,
        (1, true) => LogicalOp::OrNot,
        (2, false) => LogicalOp::Xor,
        (2, true) => LogicalOp::XorNot,
        _ => return None,
    };
    let sixty_four: bool = raw & 0x8000_0000 != 0;
    let amount: u8 = ((raw >> 10) & 0x3F) as u8;
    if !sixty_four && amount >= 32 {
        return None;
    }
    Some(LogicalShiftedReg {
        sixty_four,
        op,
        sets_flags: opc == 3,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
        rm: ((raw >> 16) & 0x1F) as u8,
        shift,
        amount,
    })
}

#[must_use]
pub(super) fn logical_immediate(raw: u32) -> Option<LogicalImmediate> {
    if raw & LOGICAL_IMMEDIATE_MASK != LOGICAL_IMMEDIATE_MATCH {
        return None;
    }
    let sixty_four: bool = raw & 0x8000_0000 != 0;
    let n: u32 = (raw >> 22) & 0x1;
    let immr: u32 = (raw >> 16) & 0x3F;
    let imms: u32 = (raw >> 10) & 0x3F;
    let mask: u64 = decode_bit_masks(sixty_four, n, immr, imms)?;
    let opc: u32 = (raw >> 29) & 0x3;
    let op: LogicalOp = match opc {
        0 | 3 => LogicalOp::And,
        1 => LogicalOp::Or,
        2 => LogicalOp::Xor,
        _ => return None,
    };
    Some(LogicalImmediate {
        sixty_four,
        op,
        sets_flags: opc == 3,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
        mask,
    })
}

#[must_use]
pub(super) fn decode_bit_masks(sixty_four: bool, n: u32, immr: u32, imms: u32) -> Option<u64> {
    if !sixty_four && n == 1 {
        return None;
    }
    let combined: u32 = (n << 6) | ((!imms) & 0x3F);
    if combined == 0 {
        return None;
    }
    let len: u32 = combined.ilog2();
    if len < 1 {
        return None;
    }
    let esize: u32 = 1_u32 << len;
    if !sixty_four && esize > 32 {
        return None;
    }
    let levels: u32 = esize - 1;
    if imms & levels == levels {
        return None;
    }
    let s: u32 = imms & levels;
    let r: u32 = immr & levels;
    let element: u64 = ones(s + 1);
    let rotated: u64 = rotate_right_within(element, r, esize);
    let mut result: u64 = 0;
    let mut position: u32 = 0;
    while position < 64 {
        result |= rotated << position;
        position += esize;
    }
    if sixty_four {
        Some(result)
    } else {
        Some(result & 0xFFFF_FFFF)
    }
}

fn ones(count: u32) -> u64 {
    if count >= 64 {
        u64::MAX
    } else {
        (1_u64 << count) - 1
    }
}

fn rotate_right_within(value: u64, amount: u32, esize: u32) -> u64 {
    let width: u64 = ones(esize);
    let amount: u32 = amount % esize;
    if amount == 0 {
        return value & width;
    }
    ((value >> amount) | (value << (esize - amount))) & width
}

#[must_use]
pub(super) fn bitfield(raw: u32) -> Option<Bitfield> {
    if raw & BITFIELD_MASK != BITFIELD_MATCH {
        return None;
    }
    let sixty_four: bool = raw & 0x8000_0000 != 0;
    let n: u32 = (raw >> 22) & 0x1;
    if u32::from(sixty_four) != n {
        return None;
    }
    let opc: u32 = (raw >> 29) & 0x3;
    let signed: bool = match opc {
        0 => true,
        2 => false,
        _ => return None,
    };
    let datasize: u32 = if sixty_four { 64 } else { 32 };
    let immr: u32 = (raw >> 16) & 0x3F;
    let imms: u32 = (raw >> 10) & 0x3F;
    if immr >= datasize || imms >= datasize {
        return None;
    }
    let rd: u8 = (raw & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let kind: BitfieldKind = if imms == datasize - 1 {
        BitfieldKind::ShiftRight {
            amount: immr as u8,
            signed,
        }
    } else if imms + 1 == immr {
        BitfieldKind::ShiftLeft {
            amount: (datasize - immr) as u8,
        }
    } else if imms > immr {
        BitfieldKind::Extract {
            lsb: immr as u8,
            width: (imms - immr + 1) as u8,
            signed,
        }
    } else {
        BitfieldKind::ExtractInsert {
            lsb: (datasize - immr) as u8,
            width: (imms + 1) as u8,
            signed,
        }
    };
    Some(Bitfield {
        sixty_four,
        rd,
        rn,
        kind,
    })
}

#[must_use]
pub(super) fn multiply_accumulate(raw: u32) -> Option<MultiplyAccumulate> {
    if raw & MULTIPLY_MASK != MULTIPLY_MATCH {
        return None;
    }
    Some(MultiplyAccumulate {
        sixty_four: raw & 0x8000_0000 != 0,
        subtract: raw & 0x0000_8000 != 0,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
        rm: ((raw >> 16) & 0x1F) as u8,
        ra: ((raw >> 10) & 0x1F) as u8,
    })
}

#[must_use]
pub(super) fn divide_reg(raw: u32) -> Option<DivideReg> {
    if raw & DATA_PROC_2SRC_MASK != DATA_PROC_2SRC_MATCH {
        return None;
    }
    let op: DivideOp = match (raw >> 10) & 0x3F {
        0b00_0010 => DivideOp::Unsigned,
        0b00_0011 => DivideOp::Signed,
        _ => return None,
    };
    Some(DivideReg {
        sixty_four: raw & 0x8000_0000 != 0,
        op,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
        rm: ((raw >> 16) & 0x1F) as u8,
    })
}

#[must_use]
pub(super) fn variable_shift(raw: u32) -> Option<VariableShift> {
    if raw & DATA_PROC_2SRC_MASK != DATA_PROC_2SRC_MATCH {
        return None;
    }
    let op: VariableShiftOp = match (raw >> 10) & 0x3F {
        0b00_1000 => VariableShiftOp::Lsl,
        0b00_1001 => VariableShiftOp::Lsr,
        0b00_1010 => VariableShiftOp::Asr,
        0b00_1011 => VariableShiftOp::Ror,
        _ => return None,
    };
    Some(VariableShift {
        sixty_four: raw & 0x8000_0000 != 0,
        op,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
        rm: ((raw >> 16) & 0x1F) as u8,
    })
}

#[must_use]
pub(super) fn movn(raw: u32) -> Option<(u8, i64)> {
    if raw & MOVN_MASK != MOVN_MATCH {
        return None;
    }
    let sixty_four: bool = raw & 0x8000_0000 != 0;
    let shift: u32 = ((raw >> 21) & 0x3) * 16;
    if !sixty_four && shift >= 32 {
        return None;
    }
    let imm16: u64 = u64::from((raw >> 5) & 0xFFFF);
    let value: u64 = !(imm16 << shift);
    let value: u64 = if sixty_four {
        value
    } else {
        value & 0xFFFF_FFFF
    };
    Some(((raw & 0x1F) as u8, value as i64))
}

#[must_use]
pub(super) fn float_binary(raw: u32) -> Option<FloatBinary> {
    if raw & FLOAT_BINARY_MASK != FLOAT_BINARY_MATCH {
        return None;
    }
    if (raw >> 22) & 0x3 != DOUBLE_PRECISION_TYPE {
        return None;
    }
    let op: FloatBinaryOp = match (raw >> 12) & 0xF {
        0b0000 => FloatBinaryOp::Mul,
        0b0001 => FloatBinaryOp::Div,
        0b0010 => FloatBinaryOp::Add,
        0b0011 => FloatBinaryOp::Sub,
        0b0100 => FloatBinaryOp::Max,
        0b0101 => FloatBinaryOp::Min,
        _ => return None,
    };
    Some(FloatBinary {
        op,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
        rm: ((raw >> 16) & 0x1F) as u8,
    })
}

#[must_use]
pub(super) fn float_unary(raw: u32) -> Option<FloatUnary> {
    if raw & FLOAT_UNARY_MASK != FLOAT_UNARY_MATCH {
        return None;
    }
    if (raw >> 22) & 0x3 != DOUBLE_PRECISION_TYPE {
        return None;
    }
    let op: FloatUnaryOp = match (raw >> 15) & 0x3F {
        0b00_0000 => FloatUnaryOp::Move,
        0b00_0001 => FloatUnaryOp::Abs,
        0b00_0010 => FloatUnaryOp::Negate,
        0b00_0011 => FloatUnaryOp::SquareRoot,
        _ => return None,
    };
    Some(FloatUnary {
        op,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
    })
}

#[must_use]
pub(super) fn integer_to_float(raw: u32) -> Option<IntegerToFloat> {
    if raw & INTEGER_TO_FLOAT_MASK != INTEGER_TO_FLOAT_MATCH {
        return None;
    }
    if (raw >> 22) & 0x3 != DOUBLE_PRECISION_TYPE {
        return None;
    }
    let signed: bool = match (raw >> 16) & 0x7 {
        0b010 => true,
        0b011 => false,
        _ => return None,
    };
    Some(IntegerToFloat {
        signed,
        rd: (raw & 0x1F) as u8,
        rn: ((raw >> 5) & 0x1F) as u8,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_real_add_shifted_register_from_the_committed_sample() {
        let decoded: AddSubShiftedReg = add_sub_shifted_reg(0x8b00_0022).expect("add x2, x1, x0");
        assert_eq!(decoded.rd, 2);
        assert_eq!(decoded.rn, 1);
        assert_eq!(decoded.rm, 0);
        assert!(decoded.sixty_four);
        assert!(!decoded.subtract);
        assert!(!decoded.sets_flags);
        assert_eq!(decoded.amount, 0);
    }

    #[test]
    fn decodes_the_real_shifted_element_address_add() {
        let decoded: AddSubShiftedReg =
            add_sub_shifted_reg(0x8b00_0830).expect("add x16, x1, x0, lsl #2");
        assert_eq!(decoded.rd, 16);
        assert_eq!(decoded.rn, 1);
        assert_eq!(decoded.rm, 0);
        assert_eq!(decoded.shift, ShiftKind::Lsl);
        assert_eq!(decoded.amount, 2);
    }

    #[test]
    fn decodes_the_real_negate_as_a_subtract_from_the_zero_register() {
        let decoded: AddSubShiftedReg = add_sub_shifted_reg(0xcb02_03e7).expect("neg x7, x2");
        assert!(decoded.subtract);
        assert!(is_zero_register(decoded.rn));
        assert_eq!(decoded.rm, 2);
        assert_eq!(decoded.rd, 7);
    }

    #[test]
    fn decodes_the_real_logical_and_of_two_registers() {
        let decoded: LogicalShiftedReg = logical_shifted_reg(0x8a03_0045).expect("and x5, x2, x3");
        assert_eq!(decoded.op, LogicalOp::And);
        assert_eq!(decoded.rd, 5);
        assert_eq!(decoded.rn, 2);
        assert_eq!(decoded.rm, 3);
        assert_eq!(decoded.amount, 0);
        assert!(!decoded.sets_flags);
    }

    #[test]
    fn decodes_the_real_and_with_a_shifted_second_operand() {
        let decoded: LogicalShiftedReg =
            logical_shifted_reg(0x8a50_0a30).expect("and x16, x17, x16, lsr #2");
        assert_eq!(decoded.op, LogicalOp::And);
        assert_eq!(decoded.shift, ShiftKind::Lsr);
        assert_eq!(decoded.amount, 2);
        assert_eq!(decoded.rn, 17);
        assert_eq!(decoded.rm, 16);
    }

    #[test]
    fn decodes_the_real_flag_setting_test_as_a_shifted_and() {
        let decoded: LogicalShiftedReg =
            logical_shifted_reg(0xea5c_821f).expect("tst x16, x28, lsr #32");
        assert!(decoded.sets_flags);
        assert_eq!(decoded.op, LogicalOp::And);
        assert!(is_zero_register(decoded.rd));
        assert_eq!(decoded.shift, ShiftKind::Lsr);
        assert_eq!(decoded.amount, 32);
    }

    #[test]
    fn decodes_the_real_smi_untag_bitfield_extract() {
        let decoded: Bitfield = bitfield(0x9341_7c22).expect("sbfx x2, x1, #1, #31");
        assert_eq!(decoded.rd, 2);
        assert_eq!(decoded.rn, 1);
        assert_eq!(
            decoded.kind,
            BitfieldKind::Extract {
                lsb: 1,
                width: 31,
                signed: true
            }
        );
    }

    #[test]
    fn decodes_the_real_arithmetic_shift_right_alias() {
        let decoded: Bitfield = bitfield(0x9341_fc43).expect("asr x3, x2, #1");
        assert_eq!(
            decoded.kind,
            BitfieldKind::ShiftRight {
                amount: 1,
                signed: true
            }
        );
    }

    #[test]
    fn decodes_the_real_zero_extending_word_extract() {
        let decoded: Bitfield = bitfield(0xd340_7c42).expect("ubfx x2, x2, #0, #32");
        assert_eq!(
            decoded.kind,
            BitfieldKind::Extract {
                lsb: 0,
                width: 32,
                signed: false
            }
        );
    }

    #[test]
    fn decodes_the_real_sign_extend_word_alias() {
        let decoded: Bitfield = bitfield(0x9340_7c20).expect("sxtw x0, w1");
        assert_eq!(
            decoded.kind,
            BitfieldKind::Extract {
                lsb: 0,
                width: 32,
                signed: true
            }
        );
    }

    #[test]
    fn decodes_the_real_multiply_and_its_zero_register_accumulator() {
        let decoded: MultiplyAccumulate = multiply_accumulate(0x9b03_7ca2).expect("mul x2, x5, x3");
        assert_eq!(decoded.rd, 2);
        assert_eq!(decoded.rn, 5);
        assert_eq!(decoded.rm, 3);
        assert!(is_zero_register(decoded.ra));
        assert!(!decoded.subtract);
    }

    #[test]
    fn decodes_the_real_signed_divide() {
        let decoded: DivideReg = divide_reg(0x9ac0_0c41).expect("sdiv x1, x2, x0");
        assert_eq!(decoded.op, DivideOp::Signed);
        assert_eq!(decoded.rd, 1);
        assert_eq!(decoded.rn, 2);
        assert_eq!(decoded.rm, 0);
    }

    #[test]
    fn decodes_the_real_double_multiply_and_add() {
        let product: FloatBinary = float_binary(0x1e61_0843).expect("fmul d3, d2, d1");
        assert_eq!(product.op, FloatBinaryOp::Mul);
        assert_eq!(product.rd, 3);
        assert_eq!(product.rn, 2);
        assert_eq!(product.rm, 1);
        let sum: FloatBinary = float_binary(0x1e63_2801).expect("fadd d1, d0, d3");
        assert_eq!(sum.op, FloatBinaryOp::Add);
        assert_eq!(sum.rd, 1);
        assert_eq!(sum.rn, 0);
        assert_eq!(sum.rm, 3);
    }

    #[test]
    fn decodes_the_real_signed_integer_to_double_conversion() {
        let decoded: IntegerToFloat = integer_to_float(0x9e62_0002).expect("scvtf d2, x0");
        assert!(decoded.signed);
        assert_eq!(decoded.rd, 2);
        assert_eq!(decoded.rn, 0);
    }

    #[test]
    fn logical_immediate_masks_match_the_published_decode_bit_masks_algorithm() {
        assert_eq!(decode_bit_masks(true, 1, 0, 0), Some(1));
        assert_eq!(decode_bit_masks(true, 1, 0, 31), Some(0xFFFF_FFFF));
        assert_eq!(
            decode_bit_masks(true, 1, 0, 62),
            Some(0x7FFF_FFFF_FFFF_FFFF)
        );
        assert_eq!(decode_bit_masks(true, 0, 0, 0), Some(0x0000_0001_0000_0001));
        assert_eq!(decode_bit_masks(true, 1, 0, 63), None);
        assert_eq!(decode_bit_masks(true, 0, 0, 31), None);
        assert_eq!(decode_bit_masks(false, 1, 0, 0), None);
    }

    #[test]
    fn a_rotated_logical_immediate_keeps_its_element_width() {
        assert_eq!(
            decode_bit_masks(true, 0, 0, 60),
            Some(0x5555_5555_5555_5555)
        );
        assert_eq!(
            decode_bit_masks(true, 0, 1, 60),
            Some(0xAAAA_AAAA_AAAA_AAAA)
        );
        assert_eq!(decode_bit_masks(true, 1, 1, 1), Some(0x8000_0000_0000_0001));
    }

    #[test]
    fn a_decoded_logical_immediate_matches_the_assembled_instruction_it_came_from() {
        let one: LogicalImmediate = logical_immediate(0x9240_0000).expect("and x0, x0, #1");
        assert_eq!(one.mask, 1);
        assert_eq!(one.op, LogicalOp::And);
        assert!(!one.sets_flags);
        let word: LogicalImmediate =
            logical_immediate(0x9240_7c00).expect("and x0, x0, #0xffffffff");
        assert_eq!(word.mask, 0xFFFF_FFFF);
        let rotated: LogicalImmediate =
            logical_immediate(0x9260_7c00).expect("and x0, x0, #0xffffffff00000000");
        assert_eq!(rotated.mask, 0xFFFF_FFFF_0000_0000);
        let test: LogicalImmediate = logical_immediate(0xf240_001f).expect("tst x0, #1");
        assert!(test.sets_flags);
        assert_eq!(test.mask, 1);
    }

    #[test]
    fn a_non_double_precision_float_operation_is_not_decoded() {
        assert_eq!(float_binary(0x1e21_0843), None);
        assert_eq!(float_unary(0x1e21_4020), None);
    }

    #[test]
    fn a_rotate_shifted_add_is_rejected_because_the_encoding_reserves_it() {
        assert_eq!(add_sub_shifted_reg(0x8bc0_0022), None);
    }
}
