use super::bitmask::decode_bit_masks;
use super::mcinst::{
    A64Opcode, BtiTarget, DecodeClass, DecodeError, ExtendKind, IndexMode, MCInst, Operand,
    RegView, ShiftKind,
};

const TOP_LEVEL: [DecodeClass; 16] = [
    DecodeClass::Reserved,
    DecodeClass::SimdFloatingPoint,
    DecodeClass::ScalableVector,
    DecodeClass::ScalableVector,
    DecodeClass::LoadsAndStores,
    DecodeClass::DataProcessingRegister,
    DecodeClass::LoadsAndStores,
    DecodeClass::SimdFloatingPoint,
    DecodeClass::DataProcessingImmediate,
    DecodeClass::DataProcessingImmediate,
    DecodeClass::BranchesAndSystem,
    DecodeClass::BranchesAndSystem,
    DecodeClass::LoadsAndStores,
    DecodeClass::DataProcessingRegister,
    DecodeClass::LoadsAndStores,
    DecodeClass::SimdFloatingPoint,
];

pub fn decode(bytes: &[u8], va: u64) -> Result<MCInst, DecodeError> {
    if bytes.len() < 4 {
        return Err(DecodeError::TruncatedInput);
    }
    let first: u8 = bytes[0];
    let second: u8 = bytes[1];
    let third: u8 = bytes[2];
    let fourth: u8 = bytes[3];
    let word: u32 = u32::from_le_bytes([first, second, third, fourth]);
    let selector: u8 = match u8::try_from((word >> 25) & 0x0f) {
        Ok(value) => value,
        Err(_) => return Ok(unmodeled(DecodeClass::Reserved, va)),
    };
    let class: DecodeClass = match TOP_LEVEL.get(usize::from(selector)) {
        Some(value) => *value,
        None => return Ok(unmodeled(DecodeClass::Reserved, va)),
    };
    Ok(match class {
        DecodeClass::Reserved => unallocated(va),
        DecodeClass::DataProcessingImmediate => decode_data_processing_immediate(word, va),
        DecodeClass::BranchesAndSystem => decode_branches_and_system(word, va),
        DecodeClass::LoadsAndStores => decode_loads_and_stores(word, va),
        DecodeClass::DataProcessingRegister => decode_data_processing_register(word, va),
        DecodeClass::SimdFloatingPoint => decode_scalar_floating_point(word, va),
        DecodeClass::ScalableVector => unmodeled(class, va),
    })
}

fn decode_scalar_floating_point(word: u32, va: u64) -> MCInst {
    let binary_opcode: Option<A64Opcode> = match word & 0xffa0_fc00 {
        0x1e20_0800 => Some(A64Opcode::Fmul),
        0x1e20_1800 => Some(A64Opcode::Fdiv),
        0x1e20_2800 => Some(A64Opcode::Fadd),
        0x1e20_3800 => Some(A64Opcode::Fsub),
        _ => None,
    };
    if let Some(opcode) = binary_opcode {
        return decode_scalar_binary(word, va, opcode);
    }
    match word & 0xffff_fc00 {
        0x1e62_4000 => return decode_fp_convert(word, va, RegView::S, RegView::D),
        0x1e22_c000 => return decode_fp_convert(word, va, RegView::D, RegView::S),
        0x1e22_0000 => {
            return decode_integer_to_fp(word, va, A64Opcode::Scvtf, RegView::S, RegView::W);
        }
        0x9e62_0000 => {
            return decode_integer_to_fp(word, va, A64Opcode::Scvtf, RegView::D, RegView::X);
        }
        0x1e23_0000 => {
            return decode_integer_to_fp(word, va, A64Opcode::Ucvtf, RegView::S, RegView::W);
        }
        0x9e63_0000 => {
            return decode_integer_to_fp(word, va, A64Opcode::Ucvtf, RegView::D, RegView::X);
        }
        0x1e38_0000 => {
            return decode_fp_to_integer(word, va, A64Opcode::Fcvtzs, RegView::W, RegView::S);
        }
        0x9e78_0000 => {
            return decode_fp_to_integer(word, va, A64Opcode::Fcvtzs, RegView::X, RegView::D);
        }
        0x1e39_0000 => {
            return decode_fp_to_integer(word, va, A64Opcode::Fcvtzu, RegView::W, RegView::S);
        }
        0x9e79_0000 => {
            return decode_fp_to_integer(word, va, A64Opcode::Fcvtzu, RegView::X, RegView::D);
        }
        0x1e20_4000 => return decode_fp_register_move(word, va, RegView::S),
        0x1e60_4000 => return decode_fp_register_move(word, va, RegView::D),
        0x9e66_0000 => return decode_gpr_from_fp_move(word, va, RegView::X, RegView::D),
        0x9e67_0000 => return decode_fp_from_gpr_move(word, va, RegView::D, RegView::X),
        0x1e26_0000 => return decode_gpr_from_fp_move(word, va, RegView::W, RegView::S),
        0x1e27_0000 => return decode_fp_from_gpr_move(word, va, RegView::S, RegView::W),
        _ => {}
    }
    if word & 0xff20_1fe0 == 0x1e20_1000 {
        return decode_fp_immediate_move(word, va);
    }
    match word & 0xffbf_fc1f {
        0x1e20_2008 => return decode_fp_compare_zero(word, va, A64Opcode::Fcmp),
        0x1e20_2018 => return decode_fp_compare_zero(word, va, A64Opcode::Fcmpe),
        _ => {}
    }
    match word & 0xffa0_fc1f {
        0x1e20_2000 => return decode_fp_compare_register(word, va, A64Opcode::Fcmp),
        0x1e20_2010 => return decode_fp_compare_register(word, va, A64Opcode::Fcmpe),
        _ => {}
    }
    if word & 0xffa0_0c00 == 0x1e20_0c00 {
        return decode_fp_conditional_select(word, va);
    }
    if word & 0xffa0_fc00 == 0x1e20_2000 {
        return unallocated(va);
    }
    unmodeled(DecodeClass::SimdFloatingPoint, va)
}

fn decode_scalar_binary(word: u32, va: u64, opcode: A64Opcode) -> MCInst {
    let (rd, rn, rm): (u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
    ) {
        (Some(destination), Some(first), Some(second)) => (destination, first, second),
        _ => return unallocated(va),
    };
    let view: RegView = match scalar_fp_view(word) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::SimdFloatingPoint, va),
    };
    instruction(
        opcode,
        vec![
            fp_register(rd, view),
            fp_register(rn, view),
            fp_register(rm, view),
        ],
        false,
        va,
    )
}

fn decode_fp_convert(
    word: u32,
    va: u64,
    destination_view: RegView,
    source_view: RegView,
) -> MCInst {
    let (rd, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(destination), Some(source)) => (destination, source),
        _ => return unallocated(va),
    };
    instruction(
        A64Opcode::Fcvt,
        vec![
            fp_register(rd, destination_view),
            fp_register(rn, source_view),
        ],
        false,
        va,
    )
}

fn decode_integer_to_fp(
    word: u32,
    va: u64,
    opcode: A64Opcode,
    destination_view: RegView,
    source_view: RegView,
) -> MCInst {
    let (rd, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(destination), Some(source)) => (destination, source),
        _ => return unallocated(va),
    };
    instruction(
        opcode,
        vec![
            fp_register(rd, destination_view),
            data_register(rn, source_view),
        ],
        false,
        va,
    )
}

fn decode_fp_to_integer(
    word: u32,
    va: u64,
    opcode: A64Opcode,
    destination_view: RegView,
    source_view: RegView,
) -> MCInst {
    let (rd, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(destination), Some(source)) => (destination, source),
        _ => return unallocated(va),
    };
    instruction(
        opcode,
        vec![
            data_register(rd, destination_view),
            fp_register(rn, source_view),
        ],
        false,
        va,
    )
}

fn decode_fp_register_move(word: u32, va: u64, view: RegView) -> MCInst {
    let (rd, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(destination), Some(source)) => (destination, source),
        _ => return unallocated(va),
    };
    instruction(
        A64Opcode::Fmov,
        vec![fp_register(rd, view), fp_register(rn, view)],
        false,
        va,
    )
}

fn decode_fp_immediate_move(word: u32, va: u64) -> MCInst {
    let (rd, immediate): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 13, 8)) {
        (Some(destination), Some(value)) => (destination, value),
        _ => return unallocated(va),
    };
    let view: RegView = match scalar_fp_view(word) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::SimdFloatingPoint, va),
    };
    instruction(
        A64Opcode::Fmov,
        vec![fp_register(rd, view), Operand::FpImm(immediate)],
        false,
        va,
    )
}

fn decode_gpr_from_fp_move(
    word: u32,
    va: u64,
    destination_view: RegView,
    source_view: RegView,
) -> MCInst {
    let (rd, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(destination), Some(source)) => (destination, source),
        _ => return unallocated(va),
    };
    instruction(
        A64Opcode::Fmov,
        vec![
            data_register(rd, destination_view),
            fp_register(rn, source_view),
        ],
        false,
        va,
    )
}

fn decode_fp_from_gpr_move(
    word: u32,
    va: u64,
    destination_view: RegView,
    source_view: RegView,
) -> MCInst {
    let (rd, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(destination), Some(source)) => (destination, source),
        _ => return unallocated(va),
    };
    instruction(
        A64Opcode::Fmov,
        vec![
            fp_register(rd, destination_view),
            data_register(rn, source_view),
        ],
        false,
        va,
    )
}

fn decode_fp_compare_zero(word: u32, va: u64, opcode: A64Opcode) -> MCInst {
    let rn: u8 = match field_u8(word, 5, 5) {
        Some(source) => source,
        None => return unallocated(va),
    };
    let view: RegView = match scalar_fp_view(word) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::SimdFloatingPoint, va),
    };
    instruction(
        opcode,
        vec![fp_register(rn, view), Operand::FpImm(0)],
        true,
        va,
    )
}

fn decode_fp_compare_register(word: u32, va: u64, opcode: A64Opcode) -> MCInst {
    let (rn, rm): (u8, u8) = match (field_u8(word, 5, 5), field_u8(word, 16, 5)) {
        (Some(first), Some(second)) => (first, second),
        _ => return unallocated(va),
    };
    let view: RegView = match scalar_fp_view(word) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::SimdFloatingPoint, va),
    };
    instruction(
        opcode,
        vec![fp_register(rn, view), fp_register(rm, view)],
        true,
        va,
    )
}

fn decode_fp_conditional_select(word: u32, va: u64) -> MCInst {
    let (rd, rn, rm, condition): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 12, 4),
    ) {
        (Some(destination), Some(first), Some(second), Some(code)) => {
            (destination, first, second, code)
        }
        _ => return unallocated(va),
    };
    if condition == 15 {
        return unallocated(va);
    }
    let view: RegView = match scalar_fp_view(word) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::SimdFloatingPoint, va),
    };
    instruction(
        A64Opcode::Fcsel,
        vec![
            fp_register(rd, view),
            fp_register(rn, view),
            fp_register(rm, view),
            Operand::CondCode(condition),
        ],
        false,
        va,
    )
}

fn scalar_fp_view(word: u32) -> Option<RegView> {
    match field_u8(word, 22, 2) {
        Some(0) => Some(RegView::S),
        Some(1) => Some(RegView::D),
        _ => None,
    }
}

fn fp_register(n: u8, view: RegView) -> Operand {
    register_with_view(n, view)
}

fn decode_data_processing_immediate(word: u32, va: u64) -> MCInst {
    if word & 0x1f00_0000 == 0x1000_0000 {
        return decode_pc_relative(word, va);
    }
    match word & 0x1f80_0000 {
        0x1100_0000 => decode_add_sub_immediate(word, va),
        0x1200_0000 => decode_logical_immediate(word, va),
        0x1280_0000 => decode_wide_immediate(word, va),
        0x1300_0000 => decode_bitfield(word, va),
        _ => unmodeled(DecodeClass::DataProcessingImmediate, va),
    }
}

fn decode_pc_relative(word: u32, va: u64) -> MCInst {
    let rd: u8 = match field_u8(word, 0, 5) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let immhi: u32 = field_u32(word, 5, 19);
    let immlo: u32 = field_u32(word, 29, 2);
    let immediate: i64 = match sign_extend(u64::from((immhi << 2) | immlo), 21) {
        Some(value) => value,
        None => return unallocated(va),
    };
    if bit(word, 31) {
        let delta: i64 = match immediate.checked_mul(4096) {
            Some(value) => value,
            None => return unallocated(va),
        };
        let target: u64 = (va & !0x0fff).wrapping_add_signed(delta);
        return instruction(
            A64Opcode::Adrp,
            vec![register_zr(rd, true), label(target)],
            false,
            va,
        );
    }
    instruction(
        A64Opcode::Adr,
        vec![
            register_zr(rd, true),
            label(va.wrapping_add_signed(immediate)),
        ],
        false,
        va,
    )
}

fn decode_add_sub_immediate(word: u32, va: u64) -> MCInst {
    let (rd, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(destination), Some(source)) => (destination, source),
        _ => return unallocated(va),
    };
    let shifted: bool = bit(word, 22);
    let amount: i64 = i64::from(field_u32(word, 10, 12));
    let immediate: i64 = if shifted {
        match amount.checked_mul(4096) {
            Some(value) => value,
            None => return unallocated(va),
        }
    } else {
        amount
    };
    let subtract: bool = bit(word, 30);
    let sets_flags: bool = bit(word, 29);
    let sf: bool = bit(word, 31);
    let opcode: A64Opcode = match (subtract, sets_flags) {
        (false, false) => A64Opcode::Add,
        (false, true) if rd == 31 => A64Opcode::Cmn,
        (false, true) => A64Opcode::Adds,
        (true, false) => A64Opcode::Sub,
        (true, true) if rd == 31 => A64Opcode::Cmp,
        (true, true) => A64Opcode::Subs,
    };
    let mut operands: Vec<Operand> = Vec::new();
    if !(sets_flags && rd == 31) {
        operands.push(register_add_sub_destination(rd, sf, sets_flags));
    }
    operands.push(register_sp(rn, sf));
    operands.push(Operand::Imm(immediate));
    instruction(opcode, operands, sets_flags, va)
}

fn decode_logical_immediate(word: u32, va: u64) -> MCInst {
    let (rd, rn, immr, imms): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 6),
        field_u8(word, 10, 6),
    ) {
        (Some(destination), Some(source), Some(rotation), Some(size)) => {
            (destination, source, rotation, size)
        }
        _ => return unallocated(va),
    };
    let sf: bool = bit(word, 31);
    let n: bool = bit(word, 22);
    if !sf && n {
        return unallocated(va);
    }
    let width: u8 = if sf { 64 } else { 32 };
    let masks: super::bitmask::BitMasks =
        if let Some(value) = decode_bit_masks(n, imms, immr, true, width) {
            value
        } else {
            return unallocated(va);
        };
    let opc: u8 = match field_u8(word, 29, 2) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let opcode: A64Opcode = match opc {
        0 => A64Opcode::And,
        1 => A64Opcode::Orr,
        2 => A64Opcode::Eor,
        3 if rd == 31 => A64Opcode::Tst,
        3 => A64Opcode::Ands,
        _ => return unallocated(va),
    };
    let sets_flags: bool = opc == 3;
    let mut operands: Vec<Operand> = Vec::new();
    if !(sets_flags && rd == 31) {
        operands.push(register_zr(rd, sf));
    }
    operands.push(register_zr(rn, sf));
    operands.push(Operand::Imm(bit_pattern_i64(masks.wmask)));
    instruction(opcode, operands, sets_flags, va)
}

fn decode_wide_immediate(word: u32, va: u64) -> MCInst {
    let (rd, hw): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 21, 2)) {
        (Some(destination), Some(halfword)) => (destination, halfword),
        _ => return unallocated(va),
    };
    let sf: bool = bit(word, 31);
    if !sf && hw >= 2 {
        return unallocated(va);
    }
    let opc: u8 = match field_u8(word, 29, 2) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let opcode: A64Opcode = match opc {
        0 => A64Opcode::Movn,
        2 => A64Opcode::Movz,
        3 => A64Opcode::Movk,
        _ => return unallocated(va),
    };
    let shift: u32 = u32::from(hw) * 16;
    let immediate: u64 = u64::from(field_u32(word, 5, 16)) << shift;
    instruction(
        opcode,
        vec![
            register_zr(rd, sf),
            Operand::Imm(bit_pattern_i64(immediate)),
        ],
        false,
        va,
    )
}

fn decode_bitfield(word: u32, va: u64) -> MCInst {
    let (rd, rn, immr, imms): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 6),
        field_u8(word, 10, 6),
    ) {
        (Some(destination), Some(source), Some(rotation), Some(size)) => {
            (destination, source, rotation, size)
        }
        _ => return unallocated(va),
    };
    let sf: bool = bit(word, 31);
    if bit(word, 22) != sf {
        return unallocated(va);
    }
    if !sf && (immr >= 32 || imms >= 32) {
        return unallocated(va);
    }
    let opc: u8 = match field_u8(word, 29, 2) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let opcode: A64Opcode = match opc {
        0 => A64Opcode::Sbfm,
        1 => A64Opcode::Bfm,
        2 => A64Opcode::Ubfm,
        _ => return unallocated(va),
    };
    instruction(
        opcode,
        vec![
            register_zr(rd, sf),
            register_zr(rn, sf),
            Operand::Imm(i64::from(immr)),
            Operand::Imm(i64::from(imms)),
        ],
        false,
        va,
    )
}

fn decode_branches_and_system(word: u32, va: u64) -> MCInst {
    match word {
        0xd503_233f => return instruction(A64Opcode::Paciasp, Vec::new(), false, va),
        0xd503_237f => return instruction(A64Opcode::Pacibsp, Vec::new(), false, va),
        0xd503_23bf => return instruction(A64Opcode::Autiasp, Vec::new(), false, va),
        0xd503_23ff => return instruction(A64Opcode::Autibsp, Vec::new(), false, va),
        0xd65f_0bff => return instruction(A64Opcode::Retaa, Vec::new(), false, va),
        0xd65f_0fff => return instruction(A64Opcode::Retab, Vec::new(), false, va),
        0xd503_241f => return instruction(A64Opcode::Bti, Vec::new(), false, va),
        0xd503_245f => {
            return instruction(
                A64Opcode::Bti,
                vec![Operand::BtiTarget(BtiTarget::C)],
                false,
                va,
            );
        }
        0xd503_249f => {
            return instruction(
                A64Opcode::Bti,
                vec![Operand::BtiTarget(BtiTarget::J)],
                false,
                va,
            );
        }
        0xd503_24df => {
            return instruction(
                A64Opcode::Bti,
                vec![Operand::BtiTarget(BtiTarget::Jc)],
                false,
                va,
            );
        }
        _ => {}
    }
    if word & 0xffff_fc00 == 0xd71f_0800
        || word & 0xffff_fc00 == 0xd71f_0c00
        || word & 0xffff_fc00 == 0xd73f_0800
        || word & 0xffff_fc00 == 0xd73f_0c00
    {
        return decode_authenticated_register_branch(word, va);
    }
    if word & 0x7c00_0000 == 0x1400_0000 {
        return decode_unconditional_branch(word, va);
    }
    if word & 0xff00_0010 == 0x5400_0000 {
        return decode_conditional_branch(word, va);
    }
    if word & 0x7e00_0000 == 0x3400_0000 {
        return decode_compare_branch(word, va);
    }
    if word & 0x7e00_0000 == 0x3600_0000 {
        return decode_test_branch(word, va);
    }
    if word & 0xffff_fc1f == 0xd61f_0000 {
        return decode_register_branch(word, va, A64Opcode::Br);
    }
    if word & 0xffff_fc1f == 0xd63f_0000 {
        return decode_register_branch(word, va, A64Opcode::Blr);
    }
    if word & 0xffff_fc1f == 0xd65f_0000 {
        return decode_register_branch(word, va, A64Opcode::Ret);
    }
    unmodeled(DecodeClass::BranchesAndSystem, va)
}

fn decode_authenticated_register_branch(word: u32, va: u64) -> MCInst {
    let (opcode, rn, rm): (A64Opcode, u8, u8) = match (
        word & 0xffff_fc00,
        field_u8(word, 5, 5),
        field_u8(word, 0, 5),
    ) {
        (0xd71f_0800, Some(target), Some(modifier)) => (A64Opcode::Braa, target, modifier),
        (0xd71f_0c00, Some(target), Some(modifier)) => (A64Opcode::Brab, target, modifier),
        (0xd73f_0800, Some(target), Some(modifier)) => (A64Opcode::Blraa, target, modifier),
        (0xd73f_0c00, Some(target), Some(modifier)) => (A64Opcode::Blrab, target, modifier),
        _ => return unallocated(va),
    };
    instruction(
        opcode,
        vec![register_zr(rn, true), register_sp(rm, true)],
        false,
        va,
    )
}

fn decode_unconditional_branch(word: u32, va: u64) -> MCInst {
    let immediate: i64 = match signed_field(word, 0, 26) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let delta: i64 = match immediate.checked_mul(4) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let opcode: A64Opcode = if bit(word, 31) {
        A64Opcode::Bl
    } else {
        A64Opcode::B
    };
    instruction(
        opcode,
        vec![label(va.wrapping_add_signed(delta))],
        false,
        va,
    )
}

fn decode_conditional_branch(word: u32, va: u64) -> MCInst {
    let condition: u8 = match field_u8(word, 0, 4) {
        Some(value) => value,
        None => return unallocated(va),
    };
    if condition == 15 {
        return unallocated(va);
    }
    let immediate: i64 = match signed_field(word, 5, 19) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let delta: i64 = match immediate.checked_mul(4) {
        Some(value) => value,
        None => return unallocated(va),
    };
    instruction(
        A64Opcode::BCond,
        vec![
            label(va.wrapping_add_signed(delta)),
            Operand::CondCode(condition),
        ],
        false,
        va,
    )
}

fn decode_compare_branch(word: u32, va: u64) -> MCInst {
    let rt: u8 = match field_u8(word, 0, 5) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let immediate: i64 = match signed_field(word, 5, 19) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let delta: i64 = match immediate.checked_mul(4) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let opcode: A64Opcode = if bit(word, 24) {
        A64Opcode::Cbnz
    } else {
        A64Opcode::Cbz
    };
    instruction(
        opcode,
        vec![
            register_zr(rt, bit(word, 31)),
            label(va.wrapping_add_signed(delta)),
        ],
        false,
        va,
    )
}

fn decode_test_branch(word: u32, va: u64) -> MCInst {
    let (rt, bit_low): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 19, 5)) {
        (Some(register), Some(index)) => (register, index),
        _ => return unallocated(va),
    };
    let immediate: i64 = match signed_field(word, 5, 14) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let delta: i64 = match immediate.checked_mul(4) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let index: u8 = if bit(word, 31) { bit_low | 32 } else { bit_low };
    let opcode: A64Opcode = if bit(word, 24) {
        A64Opcode::Tbnz
    } else {
        A64Opcode::Tbz
    };
    instruction(
        opcode,
        vec![
            register_zr(rt, bit(word, 31)),
            Operand::Imm(i64::from(index)),
            label(va.wrapping_add_signed(delta)),
        ],
        false,
        va,
    )
}

fn decode_register_branch(word: u32, va: u64, opcode: A64Opcode) -> MCInst {
    let rn: u8 = match field_u8(word, 5, 5) {
        Some(value) => value,
        None => return unallocated(va),
    };
    instruction(opcode, vec![register_zr(rn, true)], false, va)
}

fn decode_loads_and_stores(word: u32, va: u64) -> MCInst {
    if word & 0xbfff_fc00 == 0x885f_7c00 {
        return decode_exclusive_load(word, va, A64Opcode::Ldxr);
    }
    if word & 0xbfff_fc00 == 0x885f_fc00 {
        return decode_exclusive_load(word, va, A64Opcode::Ldaxr);
    }
    if word & 0xbfe0_fc00 == 0x8800_7c00 {
        return decode_exclusive_store(word, va, A64Opcode::Stxr);
    }
    if word & 0xbfe0_fc00 == 0x8800_fc00 {
        return decode_exclusive_store(word, va, A64Opcode::Stlxr);
    }
    if word & 0x3f20_0c00 == 0x3820_0000 {
        return decode_atomic_rmw(word, va);
    }
    if word & 0xbfa0_7c00 == 0x88a0_7c00 {
        return decode_atomic_cas(word, va);
    }
    if word & 0xff20_0c00 == 0xf820_0400 {
        return decode_authenticated_load(word, va);
    }
    if word & 0x3b00_0000 == 0x1800_0000 {
        return decode_literal_load(word, va);
    }
    if word & 0x3e00_0000 == 0x2800_0000 {
        return decode_pair(word, va);
    }
    if word & 0x3b00_0000 == 0x3900_0000 {
        return decode_unsigned_immediate(word, va);
    }
    if word & 0x3b20_0c00 == 0x3820_0800 {
        return decode_register_offset(word, va);
    }
    if word & 0x3b20_0000 == 0x3800_0000 {
        return decode_signed_immediate(word, va);
    }
    unmodeled(DecodeClass::LoadsAndStores, va)
}

fn decode_exclusive_load(word: u32, va: u64, opcode: A64Opcode) -> MCInst {
    let (rt, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(value), Some(base)) => (value, base),
        _ => return unallocated(va),
    };
    instruction(
        opcode,
        vec![
            data_register(rt, width_view(bit(word, 30))),
            atomic_memory(rn),
        ],
        false,
        va,
    )
}

fn decode_exclusive_store(word: u32, va: u64, opcode: A64Opcode) -> MCInst {
    let (rs, rt, rn): (u8, u8, u8) = match (
        field_u8(word, 16, 5),
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
    ) {
        (Some(status), Some(value), Some(base)) => (status, value, base),
        _ => return unallocated(va),
    };
    instruction(
        opcode,
        vec![
            data_register(rs, RegView::W),
            data_register(rt, width_view(bit(word, 30))),
            atomic_memory(rn),
        ],
        false,
        va,
    )
}

fn decode_atomic_rmw(word: u32, va: u64) -> MCInst {
    let size: u8 = match field_u8(word, 30, 2) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let view: RegView = match size {
        2 => RegView::W,
        3 => RegView::X,
        _ => return unmodeled(DecodeClass::LoadsAndStores, va),
    };
    let operation: u8 = match field_u8(word, 12, 4) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let opcode: A64Opcode = match atomic_rmw_opcode(operation, bit(word, 23), bit(word, 22)) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::LoadsAndStores, va),
    };
    let (rs, rt, rn): (u8, u8, u8) = match (
        field_u8(word, 16, 5),
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
    ) {
        (Some(source), Some(destination), Some(base)) => (source, destination, base),
        _ => return unallocated(va),
    };
    instruction(
        opcode,
        vec![
            data_register(rs, view),
            data_register(rt, view),
            atomic_memory(rn),
        ],
        false,
        va,
    )
}

fn decode_atomic_cas(word: u32, va: u64) -> MCInst {
    let opcode: A64Opcode = match (bit(word, 22), bit(word, 15)) {
        (false, false) => A64Opcode::Cas,
        (true, false) => A64Opcode::Casa,
        (false, true) => A64Opcode::Casl,
        (true, true) => A64Opcode::Casal,
    };
    let (rs, rt, rn): (u8, u8, u8) = match (
        field_u8(word, 16, 5),
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
    ) {
        (Some(compare), Some(value), Some(base)) => (compare, value, base),
        _ => return unallocated(va),
    };
    let view: RegView = width_view(bit(word, 30));
    instruction(
        opcode,
        vec![
            data_register(rs, view),
            data_register(rt, view),
            atomic_memory(rn),
        ],
        false,
        va,
    )
}

fn decode_authenticated_load(word: u32, va: u64) -> MCInst {
    let (rt, rn): (u8, u8) = match (field_u8(word, 0, 5), field_u8(word, 5, 5)) {
        (Some(value), Some(base)) => (value, base),
        _ => return unallocated(va),
    };
    let offset_bits: u32 = field_u32(word, 12, 9) | if bit(word, 22) { 512 } else { 0 };
    let offset: i64 = match sign_extend(u64::from(offset_bits), 10) {
        Some(value) => match value.checked_mul(8) {
            Some(scaled) => scaled,
            None => return unallocated(va),
        },
        None => return unallocated(va),
    };
    let opcode: A64Opcode = if bit(word, 23) {
        A64Opcode::Ldrab
    } else {
        A64Opcode::Ldraa
    };
    instruction(
        opcode,
        vec![
            data_register(rt, RegView::X),
            Operand::MemBaseImm {
                base: rn,
                off: offset,
                mode: IndexMode::Offset,
            },
        ],
        false,
        va,
    )
}

fn atomic_rmw_opcode(operation: u8, acquire: bool, release: bool) -> Option<A64Opcode> {
    match (operation, acquire, release) {
        (0, false, false) => Some(A64Opcode::Ldadd),
        (0, true, false) => Some(A64Opcode::Ldadda),
        (0, false, true) => Some(A64Opcode::Ldaddl),
        (0, true, true) => Some(A64Opcode::Ldaddal),
        (1, false, false) => Some(A64Opcode::Ldclr),
        (1, true, false) => Some(A64Opcode::Ldclra),
        (1, false, true) => Some(A64Opcode::Ldclrl),
        (1, true, true) => Some(A64Opcode::Ldclral),
        (2, false, false) => Some(A64Opcode::Ldeor),
        (2, true, false) => Some(A64Opcode::Ldeora),
        (2, false, true) => Some(A64Opcode::Ldeorl),
        (2, true, true) => Some(A64Opcode::Ldeoral),
        (3, false, false) => Some(A64Opcode::Ldset),
        (3, true, false) => Some(A64Opcode::Ldseta),
        (3, false, true) => Some(A64Opcode::Ldsetl),
        (3, true, true) => Some(A64Opcode::Ldsetal),
        (8, false, false) => Some(A64Opcode::Swp),
        (8, true, false) => Some(A64Opcode::Swpa),
        (8, false, true) => Some(A64Opcode::Swpl),
        (8, true, true) => Some(A64Opcode::Swpal),
        _ => None,
    }
}

fn atomic_memory(base: u8) -> Operand {
    Operand::MemBaseImm {
        base,
        off: 0,
        mode: IndexMode::Offset,
    }
}

fn decode_literal_load(word: u32, va: u64) -> MCInst {
    let rt: u8 = match field_u8(word, 0, 5) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let immediate: i64 = match signed_field(word, 5, 19) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let delta: i64 = match immediate.checked_mul(4) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let opc: u8 = match field_u8(word, 30, 2) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let (opcode, view): (A64Opcode, RegView) = match opc {
        0 => (A64Opcode::Ldr, RegView::W),
        1 => (A64Opcode::Ldr, RegView::X),
        2 => (A64Opcode::Ldrsw, RegView::X),
        _ => return unmodeled(DecodeClass::LoadsAndStores, va),
    };
    instruction(
        opcode,
        vec![
            data_register(rt, view),
            label(va.wrapping_add_signed(delta)),
        ],
        false,
        va,
    )
}

fn decode_pair(word: u32, va: u64) -> MCInst {
    let (rt, rt2, rn, opc, mode): (u8, u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 10, 5),
        field_u8(word, 5, 5),
        field_u8(word, 30, 2),
        field_u8(word, 23, 2),
    ) {
        (Some(first), Some(second), Some(base), Some(size), Some(addressing)) => {
            (first, second, base, size, addressing)
        }
        _ => return unallocated(va),
    };
    let index_mode: IndexMode = match mode {
        0 => return unmodeled(DecodeClass::LoadsAndStores, va),
        1 => IndexMode::PostIndex,
        2 => IndexMode::Offset,
        3 => IndexMode::PreIndex,
        _ => return unallocated(va),
    };
    let load: bool = bit(word, 22);
    let (opcode, view, scale): (A64Opcode, RegView, i64) = match (opc, load) {
        (0, false) => (A64Opcode::Stp, RegView::W, 4),
        (0, true) => (A64Opcode::Ldp, RegView::W, 4),
        (2, false) => (A64Opcode::Stp, RegView::X, 8),
        (2, true) => (A64Opcode::Ldp, RegView::X, 8),
        _ => return unmodeled(DecodeClass::LoadsAndStores, va),
    };
    let displacement: i64 = match signed_field(word, 15, 7) {
        Some(value) => match value.checked_mul(scale) {
            Some(scaled) => scaled,
            None => return unallocated(va),
        },
        None => return unallocated(va),
    };
    instruction(
        opcode,
        vec![
            data_register(rt, view),
            data_register(rt2, view),
            Operand::MemBaseImm {
                base: rn,
                off: displacement,
                mode: index_mode,
            },
        ],
        false,
        va,
    )
}

fn decode_unsigned_immediate(word: u32, va: u64) -> MCInst {
    let (rt, rn, size, opc): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 30, 2),
        field_u8(word, 22, 2),
    ) {
        (Some(register), Some(base), Some(access_size), Some(operation)) => {
            (register, base, access_size, operation)
        }
        _ => return unallocated(va),
    };
    let shift: u32 = u32::from(size);
    let displacement: i64 = i64::from(field_u32(word, 10, 12)) << shift;
    decode_load_store_operands(
        rt,
        rn,
        size,
        opc,
        false,
        displacement,
        IndexMode::Offset,
        va,
    )
}

fn decode_signed_immediate(word: u32, va: u64) -> MCInst {
    let (rt, rn, size, opc, mode): (u8, u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 30, 2),
        field_u8(word, 22, 2),
        field_u8(word, 10, 2),
    ) {
        (Some(register), Some(base), Some(access_size), Some(operation), Some(addressing)) => {
            (register, base, access_size, operation, addressing)
        }
        _ => return unallocated(va),
    };
    let index_mode: IndexMode = match mode {
        0 => IndexMode::Offset,
        1 => IndexMode::PostIndex,
        3 => IndexMode::PreIndex,
        _ => return unmodeled(DecodeClass::LoadsAndStores, va),
    };
    let displacement: i64 = match signed_field(word, 12, 9) {
        Some(value) => value,
        None => return unallocated(va),
    };
    decode_load_store_operands(rt, rn, size, opc, mode == 0, displacement, index_mode, va)
}

fn decode_register_offset(word: u32, va: u64) -> MCInst {
    let (rt, rn, rm, size, opc, option): (u8, u8, u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 30, 2),
        field_u8(word, 22, 2),
        field_u8(word, 13, 3),
    ) {
        (
            Some(register),
            Some(base),
            Some(index),
            Some(access_size),
            Some(operation),
            Some(extension),
        ) => (register, base, index, access_size, operation, extension),
        _ => return unallocated(va),
    };
    let extend: ExtendKind = match option {
        2 => ExtendKind::Uxtw,
        3 => ExtendKind::Lsl,
        6 => ExtendKind::Sxtw,
        7 => ExtendKind::Sxtx,
        _ => return unallocated(va),
    };
    let scale: u8 = if bit(word, 12) { size } else { 0 };
    let (opcode, view): (A64Opcode, RegView) = match load_store_info(size, opc, false) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::LoadsAndStores, va),
    };
    instruction(
        opcode,
        vec![
            data_register(rt, view),
            Operand::MemBaseReg {
                base: rn,
                index: rm,
                extend,
                scale,
            },
        ],
        false,
        va,
    )
}

fn decode_load_store_operands(
    rt: u8,
    rn: u8,
    size: u8,
    opc: u8,
    unscaled: bool,
    displacement: i64,
    mode: IndexMode,
    va: u64,
) -> MCInst {
    let (opcode, view): (A64Opcode, RegView) = match load_store_info(size, opc, unscaled) {
        Some(value) => value,
        None => return unmodeled(DecodeClass::LoadsAndStores, va),
    };
    instruction(
        opcode,
        vec![
            data_register(rt, view),
            Operand::MemBaseImm {
                base: rn,
                off: displacement,
                mode,
            },
        ],
        false,
        va,
    )
}

fn load_store_info(size: u8, opc: u8, unscaled: bool) -> Option<(A64Opcode, RegView)> {
    match (size, opc, unscaled) {
        (0, 0, false) => Some((A64Opcode::Strb, RegView::W)),
        (0, 0, true) => Some((A64Opcode::Sturb, RegView::W)),
        (0, 1, false) => Some((A64Opcode::Ldrb, RegView::W)),
        (0, 1, true) => Some((A64Opcode::Ldurb, RegView::W)),
        (0, 2, false) => Some((A64Opcode::Ldrsb, RegView::X)),
        (0, 2, true) => Some((A64Opcode::Ldursb, RegView::X)),
        (0, 3, false) => Some((A64Opcode::Ldrsb, RegView::W)),
        (0, 3, true) => Some((A64Opcode::Ldursb, RegView::W)),
        (1, 0, false) => Some((A64Opcode::Strh, RegView::W)),
        (1, 0, true) => Some((A64Opcode::Sturh, RegView::W)),
        (1, 1, false) => Some((A64Opcode::Ldrh, RegView::W)),
        (1, 1, true) => Some((A64Opcode::Ldurh, RegView::W)),
        (1, 2, false) => Some((A64Opcode::Ldrsh, RegView::X)),
        (1, 2, true) => Some((A64Opcode::Ldursh, RegView::X)),
        (1, 3, false) => Some((A64Opcode::Ldrsh, RegView::W)),
        (1, 3, true) => Some((A64Opcode::Ldursh, RegView::W)),
        (2, 0, false) => Some((A64Opcode::Str, RegView::W)),
        (2, 0, true) => Some((A64Opcode::Stur, RegView::W)),
        (2, 1, false) => Some((A64Opcode::Ldr, RegView::W)),
        (2, 1, true) => Some((A64Opcode::Ldur, RegView::W)),
        (2, 2, false) => Some((A64Opcode::Ldrsw, RegView::X)),
        (2, 2, true) => Some((A64Opcode::Ldursw, RegView::X)),
        (3, 0, false) => Some((A64Opcode::Str, RegView::X)),
        (3, 0, true) => Some((A64Opcode::Stur, RegView::X)),
        (3, 1, false) => Some((A64Opcode::Ldr, RegView::X)),
        (3, 1, true) => Some((A64Opcode::Ldur, RegView::X)),
        _ => None,
    }
}

fn decode_data_processing_register(word: u32, va: u64) -> MCInst {
    if word & 0x1f00_0000 == 0x0a00_0000 {
        return decode_logical_shifted_register(word, va);
    }
    if word & 0x1f00_0000 == 0x0b00_0000 {
        return if bit(word, 21) {
            decode_add_sub_extended_register(word, va)
        } else {
            decode_add_sub_shifted_register(word, va)
        };
    }
    if word & 0x1fe0_0800 == 0x1a80_0000 {
        if bit(word, 29) {
            return unallocated(va);
        }
        return decode_conditional_select(word, va);
    }
    if word & 0x1fe0_0000 == 0x1ac0_0000 {
        if word & 0x6000_0000 != 0 {
            return unallocated(va);
        }
        return decode_two_source(word, va);
    }
    if word & 0x1fe0_0000 == 0x1b00_0000 {
        if word & 0x6000_0000 != 0 {
            return unallocated(va);
        }
        return decode_madd_msub(word, va);
    }
    if word & 0x1fe0_0000 == 0x1b20_0000 {
        if word & 0x6000_0000 != 0 {
            return unallocated(va);
        }
        return decode_signed_long_multiply(word, va);
    }
    if word & 0x1fe0_0000 == 0x1ba0_0000 {
        if word & 0x6000_0000 != 0 {
            return unallocated(va);
        }
        return decode_unsigned_long_multiply(word, va);
    }
    unmodeled(DecodeClass::DataProcessingRegister, va)
}

fn decode_logical_shifted_register(word: u32, va: u64) -> MCInst {
    let (rd, rn, rm, amount, shift, opc): (u8, u8, u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 10, 6),
        field_u8(word, 22, 2),
        field_u8(word, 29, 2),
    ) {
        (
            Some(destination),
            Some(first),
            Some(second),
            Some(shift_amount),
            Some(kind),
            Some(op),
        ) => (destination, first, second, shift_amount, kind, op),
        _ => return unallocated(va),
    };
    let sf: bool = bit(word, 31);
    if !sf && amount >= 32 {
        return unallocated(va);
    }
    let shift_kind: ShiftKind = match shift {
        0 => ShiftKind::Lsl,
        1 => ShiftKind::Lsr,
        2 => ShiftKind::Asr,
        3 => ShiftKind::Ror,
        _ => return unallocated(va),
    };
    let invert: bool = bit(word, 21);
    let opcode: A64Opcode = match (opc, invert) {
        (0, false) => A64Opcode::And,
        (0, true) => A64Opcode::Bic,
        (1, false) if rn == 31 && shift == 0 && amount == 0 => A64Opcode::Mov,
        (1, false) => A64Opcode::Orr,
        (1, true) => A64Opcode::Orn,
        (2, false) => A64Opcode::Eor,
        (3, false) if rd == 31 => A64Opcode::Tst,
        (3, false) => A64Opcode::Ands,
        _ => return unmodeled(DecodeClass::DataProcessingRegister, va),
    };
    let sets_flags: bool = opc == 3 && !invert;
    let mut operands: Vec<Operand> = Vec::new();
    if opcode == A64Opcode::Mov {
        operands.push(register_zr(rd, sf));
        operands.push(register_zr(rm, sf));
        return instruction(opcode, operands, false, va);
    }
    if !(sets_flags && rd == 31) {
        operands.push(register_zr(rd, sf));
    }
    operands.push(register_zr(rn, sf));
    operands.push(Operand::ShiftedReg {
        n: rm,
        view: register_shifted_view(rm, sf),
        shift: shift_kind,
        amount,
    });
    instruction(opcode, operands, sets_flags, va)
}

fn decode_add_sub_shifted_register(word: u32, va: u64) -> MCInst {
    if word & 0x1f20_0000 != 0x0b00_0000 {
        return unallocated(va);
    }
    let (rd, rn, rm, amount, shift): (u8, u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 10, 6),
        field_u8(word, 22, 2),
    ) {
        (Some(destination), Some(first), Some(second), Some(shift_amount), Some(kind)) => {
            (destination, first, second, shift_amount, kind)
        }
        _ => return unallocated(va),
    };
    let sf: bool = bit(word, 31);
    if !sf && amount >= 32 {
        return unallocated(va);
    }
    let shift_kind: ShiftKind = match shift {
        0 => ShiftKind::Lsl,
        1 => ShiftKind::Lsr,
        2 => ShiftKind::Asr,
        3 => return unallocated(va),
        _ => return unallocated(va),
    };
    let subtract: bool = bit(word, 30);
    let sets_flags: bool = bit(word, 29);
    let opcode: A64Opcode = match (subtract, sets_flags) {
        (false, false) => A64Opcode::Add,
        (false, true) if rd == 31 => A64Opcode::Cmn,
        (false, true) => A64Opcode::Adds,
        (true, false) => A64Opcode::Sub,
        (true, true) if rd == 31 => A64Opcode::Cmp,
        (true, true) => A64Opcode::Subs,
    };
    let mut operands: Vec<Operand> = Vec::new();
    if !(sets_flags && rd == 31) {
        operands.push(register_zr(rd, sf));
    }
    operands.push(register_zr(rn, sf));
    operands.push(Operand::ShiftedReg {
        n: rm,
        view: register_shifted_view(rm, sf),
        shift: shift_kind,
        amount,
    });
    instruction(opcode, operands, sets_flags, va)
}

fn decode_add_sub_extended_register(word: u32, va: u64) -> MCInst {
    if word & 0x1fe0_0000 != 0x0b20_0000 {
        return unallocated(va);
    }
    let (rd, rn, rm, option, amount): (u8, u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 13, 3),
        field_u8(word, 10, 3),
    ) {
        (Some(destination), Some(first), Some(second), Some(extension), Some(shift)) => {
            (destination, first, second, extension, shift)
        }
        _ => return unallocated(va),
    };
    let sf: bool = bit(word, 31);
    if amount > 4 {
        return unallocated(va);
    }
    let extend: ExtendKind = match extend_kind(option) {
        Some(value) => value,
        None => return unallocated(va),
    };
    let subtract: bool = bit(word, 30);
    let sets_flags: bool = bit(word, 29);
    let opcode: A64Opcode = match (subtract, sets_flags) {
        (false, false) => A64Opcode::Add,
        (false, true) if rd == 31 => A64Opcode::Cmn,
        (false, true) => A64Opcode::Adds,
        (true, false) => A64Opcode::Sub,
        (true, true) if rd == 31 => A64Opcode::Cmp,
        (true, true) => A64Opcode::Subs,
    };
    let mut operands: Vec<Operand> = Vec::new();
    if !(sets_flags && rd == 31) {
        operands.push(register_add_sub_destination(rd, sf, sets_flags));
    }
    operands.push(register_sp(rn, sf));
    operands.push(Operand::ExtendedReg {
        n: rm,
        view: extended_register_view(rm, sf, extend),
        extend,
        amount,
    });
    instruction(opcode, operands, sets_flags, va)
}

fn decode_conditional_select(word: u32, va: u64) -> MCInst {
    let (rd, rn, rm, condition): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 12, 4),
    ) {
        (Some(destination), Some(first), Some(second), Some(code)) => {
            (destination, first, second, code)
        }
        _ => return unallocated(va),
    };
    let opcode: A64Opcode = match (bit(word, 30), bit(word, 10)) {
        (false, false) => A64Opcode::Csel,
        (false, true) => A64Opcode::Csinc,
        (true, false) => A64Opcode::Csinv,
        (true, true) => A64Opcode::Csneg,
    };
    let sf: bool = bit(word, 31);
    instruction(
        opcode,
        vec![
            register_zr(rd, sf),
            register_zr(rn, sf),
            register_zr(rm, sf),
            Operand::CondCode(condition),
        ],
        false,
        va,
    )
}

fn decode_two_source(word: u32, va: u64) -> MCInst {
    let (rd, rn, rm, operation): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 10, 6),
    ) {
        (Some(destination), Some(first), Some(second), Some(op)) => {
            (destination, first, second, op)
        }
        _ => return unallocated(va),
    };
    let opcode: A64Opcode = match operation {
        2 => A64Opcode::Udiv,
        3 => A64Opcode::Sdiv,
        8 => A64Opcode::Lslv,
        9 => A64Opcode::Lsrv,
        10 => A64Opcode::Asrv,
        11 => A64Opcode::Rorv,
        _ => return unmodeled(DecodeClass::DataProcessingRegister, va),
    };
    let sf: bool = bit(word, 31);
    instruction(
        opcode,
        vec![
            register_zr(rd, sf),
            register_zr(rn, sf),
            register_zr(rm, sf),
        ],
        false,
        va,
    )
}

fn decode_madd_msub(word: u32, va: u64) -> MCInst {
    let (rd, rn, rm, ra): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 10, 5),
    ) {
        (Some(destination), Some(first), Some(second), Some(addend)) => {
            (destination, first, second, addend)
        }
        _ => return unallocated(va),
    };
    let sf: bool = bit(word, 31);
    let subtract: bool = bit(word, 15);
    let opcode: A64Opcode = if !subtract && ra == 31 {
        A64Opcode::Mul
    } else if subtract {
        A64Opcode::Msub
    } else {
        A64Opcode::Madd
    };
    let mut operands: Vec<Operand> = vec![
        register_zr(rd, sf),
        register_zr(rn, sf),
        register_zr(rm, sf),
    ];
    if opcode != A64Opcode::Mul {
        operands.push(register_zr(ra, sf));
    }
    instruction(opcode, operands, false, va)
}

fn decode_signed_long_multiply(word: u32, va: u64) -> MCInst {
    decode_long_multiply(word, va, A64Opcode::Smull)
}

fn decode_unsigned_long_multiply(word: u32, va: u64) -> MCInst {
    decode_long_multiply(word, va, A64Opcode::Umull)
}

fn decode_long_multiply(word: u32, va: u64, opcode: A64Opcode) -> MCInst {
    let (rd, rn, rm, ra): (u8, u8, u8, u8) = match (
        field_u8(word, 0, 5),
        field_u8(word, 5, 5),
        field_u8(word, 16, 5),
        field_u8(word, 10, 5),
    ) {
        (Some(destination), Some(first), Some(second), Some(addend)) => {
            (destination, first, second, addend)
        }
        _ => return unallocated(va),
    };
    if !bit(word, 31) {
        return unallocated(va);
    }
    if bit(word, 15) || ra != 31 {
        return unmodeled(DecodeClass::DataProcessingRegister, va);
    }
    instruction(
        opcode,
        vec![
            register_zr(rd, true),
            register_zr(rn, false),
            register_zr(rm, false),
        ],
        false,
        va,
    )
}

fn instruction(opcode: A64Opcode, operands: Vec<Operand>, sets_flags: bool, va: u64) -> MCInst {
    MCInst {
        opcode,
        operands,
        sets_flags,
        va,
        len: 4,
    }
}

fn unallocated(va: u64) -> MCInst {
    instruction(A64Opcode::Unallocated, Vec::new(), false, va)
}

fn unmodeled(class: DecodeClass, va: u64) -> MCInst {
    instruction(A64Opcode::Unmodeled(class), Vec::new(), false, va)
}

fn register_zr(n: u8, sf: bool) -> Operand {
    if n == 31 {
        return register_with_view(n, RegView::Zr);
    }
    register_with_view(n, width_view(sf))
}

fn register_sp(n: u8, sf: bool) -> Operand {
    if n == 31 {
        return register_with_view(n, RegView::Sp);
    }
    register_with_view(n, width_view(sf))
}

fn register_add_sub_destination(n: u8, sf: bool, sets_flags: bool) -> Operand {
    if sets_flags {
        return register_zr(n, sf);
    }
    register_sp(n, sf)
}

fn register_with_view(n: u8, view: RegView) -> Operand {
    Operand::Reg { n, view }
}

fn data_register(n: u8, view: RegView) -> Operand {
    if n == 31 {
        return register_with_view(n, RegView::Zr);
    }
    register_with_view(n, view)
}

fn register_shifted_view(n: u8, sf: bool) -> RegView {
    if n == 31 {
        return RegView::Zr;
    }
    width_view(sf)
}

fn width_view(sf: bool) -> RegView {
    if sf { RegView::X } else { RegView::W }
}

fn label(target: u64) -> Operand {
    Operand::PcRelLabel { target }
}

fn extend_kind(option: u8) -> Option<ExtendKind> {
    match option {
        0 => Some(ExtendKind::Uxtb),
        1 => Some(ExtendKind::Uxth),
        2 => Some(ExtendKind::Uxtw),
        3 => Some(ExtendKind::Uxtx),
        4 => Some(ExtendKind::Sxtb),
        5 => Some(ExtendKind::Sxth),
        6 => Some(ExtendKind::Sxtw),
        7 => Some(ExtendKind::Sxtx),
        _ => None,
    }
}

fn extend_view(sf: bool, extend: ExtendKind) -> RegView {
    if sf && matches!(extend, ExtendKind::Uxtx | ExtendKind::Sxtx) {
        RegView::X
    } else {
        RegView::W
    }
}

fn extended_register_view(n: u8, sf: bool, extend: ExtendKind) -> RegView {
    if n == 31 {
        return RegView::Zr;
    }
    extend_view(sf, extend)
}

fn field_u8(word: u32, shift: u8, width: u8) -> Option<u8> {
    if width == 0 || width > 8 {
        return None;
    }
    let mask: u32 = (1_u32.checked_shl(u32::from(width))?).checked_sub(1)?;
    u8::try_from((word >> u32::from(shift)) & mask).ok()
}

fn field_u32(word: u32, shift: u8, width: u8) -> u32 {
    let mask: u32 = (1_u32 << u32::from(width)) - 1;
    (word >> u32::from(shift)) & mask
}

fn signed_field(word: u32, shift: u8, width: u8) -> Option<i64> {
    sign_extend(u64::from(field_u32(word, shift, width)), width)
}

fn sign_extend(value: u64, width: u8) -> Option<i64> {
    if width == 0 || width >= 64 {
        return None;
    }
    let range: u64 = 1_u64.checked_shl(u32::from(width))?;
    if value >= range {
        return None;
    }
    let sign_bit: u64 = 1_u64.checked_shl(u32::from(width.checked_sub(1)?))?;
    if value & sign_bit == 0 {
        return i64::try_from(value).ok();
    }
    let magnitude: u64 = range.checked_sub(value)?;
    i64::try_from(magnitude).ok()?.checked_neg()
}

fn bit(word: u32, index: u8) -> bool {
    word & (1_u32 << u32::from(index)) != 0
}

fn bit_pattern_i64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}
