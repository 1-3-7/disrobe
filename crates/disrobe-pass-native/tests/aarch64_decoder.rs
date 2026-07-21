use disrobe_pass_native::aarch64::{
    A64Opcode, BitMasks, DecodeError, ExtendKind, IndexMode, MCInst, Operand, RegView, ShiftKind,
    decode, decode_bit_masks,
};

fn decoded(word: u32, va: u64) -> Result<MCInst, DecodeError> {
    decode(&word.to_le_bytes(), va)
}

const fn instruction(
    opcode: A64Opcode,
    operands: Vec<Operand>,
    sets_flags: bool,
    va: u64,
) -> MCInst {
    MCInst {
        opcode,
        operands,
        sets_flags,
        va,
        len: 4,
    }
}

const fn reg(n: u8, view: RegView) -> Operand {
    Operand::Reg { n, view }
}

const fn shifted(n: u8, view: RegView, shift: ShiftKind, amount: u8) -> Operand {
    Operand::ShiftedReg {
        n,
        view,
        shift,
        amount,
    }
}

const fn extended(n: u8, view: RegView, extend: ExtendKind, amount: u8) -> Operand {
    Operand::ExtendedReg {
        n,
        view,
        extend,
        amount,
    }
}

const fn mem_imm(base: u8, off: i64, mode: IndexMode) -> Operand {
    Operand::MemBaseImm { base, off, mode }
}

const fn mem_reg(base: u8, index: u8, extend: ExtendKind, scale: u8) -> Operand {
    Operand::MemBaseReg {
        base,
        index,
        extend,
        scale,
    }
}

const fn label(target: u64) -> Operand {
    Operand::PcRelLabel { target }
}

#[test]
fn immediate_forms_preserve_register_roles_widths_and_targets() {
    assert_eq!(
        decoded(0x9100_43ff, 0x1000),
        Ok(instruction(
            A64Opcode::Add,
            vec![reg(31, RegView::Sp), reg(31, RegView::Sp), Operand::Imm(16)],
            false,
            0x1000,
        ))
    );
    assert_eq!(
        decoded(0xf140_803f, 0x1004),
        Ok(instruction(
            A64Opcode::Cmp,
            vec![reg(1, RegView::X), Operand::Imm(0x20_000)],
            true,
            0x1004,
        ))
    );
    assert_eq!(
        decoded(0x3100_0420, 0x1006),
        Ok(instruction(
            A64Opcode::Adds,
            vec![reg(0, RegView::W), reg(1, RegView::W), Operand::Imm(1)],
            true,
            0x1006,
        ))
    );
    assert_eq!(
        decoded(0xf100_1062, 0x1007),
        Ok(instruction(
            A64Opcode::Subs,
            vec![reg(2, RegView::X), reg(3, RegView::X), Operand::Imm(4)],
            true,
            0x1007,
        ))
    );
    assert_eq!(
        decoded(0x1200_0022, 0x1008),
        Ok(instruction(
            A64Opcode::And,
            vec![reg(2, RegView::W), reg(1, RegView::W), Operand::Imm(1)],
            false,
            0x1008,
        ))
    );
    assert_eq!(
        decoded(0x3200_0022, 0x100c),
        Ok(instruction(
            A64Opcode::Orr,
            vec![reg(2, RegView::W), reg(1, RegView::W), Operand::Imm(1)],
            false,
            0x100c,
        ))
    );
    assert_eq!(
        decoded(0x5200_0022, 0x1010),
        Ok(instruction(
            A64Opcode::Eor,
            vec![reg(2, RegView::W), reg(1, RegView::W), Operand::Imm(1)],
            false,
            0x1010,
        ))
    );
    assert_eq!(
        decoded(0x7200_009f, 0x1014),
        Ok(instruction(
            A64Opcode::Tst,
            vec![reg(4, RegView::W), Operand::Imm(1)],
            true,
            0x1014,
        ))
    );
    assert_eq!(
        decoded(0xf240_0020, 0x1016),
        Ok(instruction(
            A64Opcode::Ands,
            vec![reg(0, RegView::X), reg(1, RegView::X), Operand::Imm(1)],
            true,
            0x1016,
        ))
    );
    assert_eq!(
        decoded(0x9240_03ff, 0x1018),
        Ok(instruction(
            A64Opcode::And,
            vec![reg(31, RegView::Zr), reg(31, RegView::Zr), Operand::Imm(1)],
            false,
            0x1018,
        ))
    );
    assert_eq!(
        decoded(0xd2a2_4681, 0x101c),
        Ok(instruction(
            A64Opcode::Movz,
            vec![reg(1, RegView::X), Operand::Imm(0x1234_0000)],
            false,
            0x101c,
        ))
    );
    assert_eq!(
        decoded(0x1280_0022, 0x1020),
        Ok(instruction(
            A64Opcode::Movn,
            vec![reg(2, RegView::W), Operand::Imm(1)],
            false,
            0x1020,
        ))
    );
    assert_eq!(
        decoded(0xf2ea_cf03, 0x1024),
        Ok(instruction(
            A64Opcode::Movk,
            vec![reg(3, RegView::X), Operand::Imm(0x5678_0000_0000_0000)],
            false,
            0x1024,
        ))
    );
    assert_eq!(
        decoded(0x1000_0080, 0x1000),
        Ok(instruction(
            A64Opcode::Adr,
            vec![reg(0, RegView::X), label(0x1010)],
            false,
            0x1000,
        ))
    );
    assert_eq!(
        decoded(0xb000_0001, 0x1234),
        Ok(instruction(
            A64Opcode::Adrp,
            vec![reg(1, RegView::X), label(0x2000)],
            false,
            0x1234,
        ))
    );
    assert_eq!(
        decoded(0x9341_fc20, 0x1028),
        Ok(instruction(
            A64Opcode::Sbfm,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                Operand::Imm(1),
                Operand::Imm(63),
            ],
            false,
            0x1028,
        ))
    );
    assert_eq!(
        decoded(0x5300_1c62, 0x102c),
        Ok(instruction(
            A64Opcode::Ubfm,
            vec![
                reg(2, RegView::W),
                reg(3, RegView::W),
                Operand::Imm(0),
                Operand::Imm(7),
            ],
            false,
            0x102c,
        ))
    );
    assert_eq!(
        decoded(0xb348_3ca4, 0x1030),
        Ok(instruction(
            A64Opcode::Bfm,
            vec![
                reg(4, RegView::X),
                reg(5, RegView::X),
                Operand::Imm(8),
                Operand::Imm(15),
            ],
            false,
            0x1030,
        ))
    );
}

#[test]
fn register_forms_preserve_aliases_shifts_extensions_and_conditions() {
    assert_eq!(
        decoded(0x8b42_0c20, 0x2000),
        Ok(instruction(
            A64Opcode::Add,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                shifted(2, RegView::X, ShiftKind::Lsr, 3),
            ],
            false,
            0x2000,
        ))
    );
    assert_eq!(
        decoded(0x4b85_1c83, 0x2004),
        Ok(instruction(
            A64Opcode::Sub,
            vec![
                reg(3, RegView::W),
                reg(4, RegView::W),
                shifted(5, RegView::W, ShiftKind::Asr, 7),
            ],
            false,
            0x2004,
        ))
    );
    assert_eq!(
        decoded(0xab02_003f, 0x2008),
        Ok(instruction(
            A64Opcode::Cmn,
            vec![
                reg(1, RegView::X),
                shifted(2, RegView::X, ShiftKind::Lsl, 0),
            ],
            true,
            0x2008,
        ))
    );
    assert_eq!(
        decoded(0x2b08_00e6, 0x200a),
        Ok(instruction(
            A64Opcode::Adds,
            vec![
                reg(6, RegView::W),
                reg(7, RegView::W),
                shifted(8, RegView::W, ShiftKind::Lsl, 0),
            ],
            true,
            0x200a,
        ))
    );
    assert_eq!(
        decoded(0xeb0b_0149, 0x200b),
        Ok(instruction(
            A64Opcode::Subs,
            vec![
                reg(9, RegView::X),
                reg(10, RegView::X),
                shifted(11, RegView::X, ShiftKind::Lsl, 0),
            ],
            true,
            0x200b,
        ))
    );
    assert_eq!(
        decoded(0x8b21_4be0, 0x200c),
        Ok(instruction(
            A64Opcode::Add,
            vec![
                reg(0, RegView::X),
                reg(31, RegView::Sp),
                extended(1, RegView::W, ExtendKind::Uxtw, 2),
            ],
            false,
            0x200c,
        ))
    );
    assert_eq!(
        decoded(0x6b22_43ff, 0x2010),
        Ok(instruction(
            A64Opcode::Cmp,
            vec![
                reg(31, RegView::Sp),
                extended(2, RegView::W, ExtendKind::Uxtw, 0),
            ],
            true,
            0x2010,
        ))
    );
    assert_eq!(
        decoded(0x4b25_87e4, 0x2012),
        Ok(instruction(
            A64Opcode::Sub,
            vec![
                reg(4, RegView::W),
                reg(31, RegView::Sp),
                extended(5, RegView::W, ExtendKind::Sxtb, 1),
            ],
            false,
            0x2012,
        ))
    );
    assert_eq!(
        decoded(0x8ac2_1020, 0x2014),
        Ok(instruction(
            A64Opcode::And,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                shifted(2, RegView::X, ShiftKind::Ror, 4),
            ],
            false,
            0x2014,
        ))
    );
    assert_eq!(
        decoded(0x0a25_0483, 0x2018),
        Ok(instruction(
            A64Opcode::Bic,
            vec![
                reg(3, RegView::W),
                reg(4, RegView::W),
                shifted(5, RegView::W, ShiftKind::Lsl, 1),
            ],
            false,
            0x2018,
        ))
    );
    assert_eq!(
        decoded(0xaa27_03e6, 0x201c),
        Ok(instruction(
            A64Opcode::Orn,
            vec![
                reg(6, RegView::X),
                reg(31, RegView::Zr),
                shifted(7, RegView::X, ShiftKind::Lsl, 0),
            ],
            false,
            0x201c,
        ))
    );
    assert_eq!(
        decoded(0x4a42_0820, 0x2020),
        Ok(instruction(
            A64Opcode::Eor,
            vec![
                reg(0, RegView::W),
                reg(1, RegView::W),
                shifted(2, RegView::W, ShiftKind::Lsr, 2),
            ],
            false,
            0x2020,
        ))
    );
    assert_eq!(
        decoded(0xaa05_0483, 0x2022),
        Ok(instruction(
            A64Opcode::Orr,
            vec![
                reg(3, RegView::X),
                reg(4, RegView::X),
                shifted(5, RegView::X, ShiftKind::Lsl, 1),
            ],
            false,
            0x2022,
        ))
    );
    assert_eq!(
        decoded(0xea02_0020, 0x2023),
        Ok(instruction(
            A64Opcode::Ands,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                shifted(2, RegView::X, ShiftKind::Lsl, 0),
            ],
            true,
            0x2023,
        ))
    );
    assert_eq!(
        decoded(0x6a02_003f, 0x2024),
        Ok(instruction(
            A64Opcode::Tst,
            vec![
                reg(1, RegView::W),
                shifted(2, RegView::W, ShiftKind::Lsl, 0),
            ],
            true,
            0x2024,
        ))
    );
    assert_eq!(
        decoded(0x2a02_03e1, 0x2028),
        Ok(instruction(
            A64Opcode::Mov,
            vec![reg(1, RegView::W), reg(2, RegView::W)],
            false,
            0x2028,
        ))
    );
    assert_eq!(
        decoded(0x9b02_0c20, 0x202c),
        Ok(instruction(
            A64Opcode::Madd,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                reg(2, RegView::X),
                reg(3, RegView::X),
            ],
            false,
            0x202c,
        ))
    );
    assert_eq!(
        decoded(0x1b06_9ca4, 0x2030),
        Ok(instruction(
            A64Opcode::Msub,
            vec![
                reg(4, RegView::W),
                reg(5, RegView::W),
                reg(6, RegView::W),
                reg(7, RegView::W),
            ],
            false,
            0x2030,
        ))
    );
    assert_eq!(
        decoded(0x9b0a_7d28, 0x2034),
        Ok(instruction(
            A64Opcode::Mul,
            vec![reg(8, RegView::X), reg(9, RegView::X), reg(10, RegView::X)],
            false,
            0x2034,
        ))
    );
    assert_eq!(
        decoded(0x9b22_7c20, 0x2038),
        Ok(instruction(
            A64Opcode::Smull,
            vec![reg(0, RegView::X), reg(1, RegView::W), reg(2, RegView::W)],
            false,
            0x2038,
        ))
    );
    assert_eq!(
        decoded(0x9ba5_7c83, 0x203c),
        Ok(instruction(
            A64Opcode::Umull,
            vec![reg(3, RegView::X), reg(4, RegView::W), reg(5, RegView::W)],
            false,
            0x203c,
        ))
    );
    assert_eq!(
        decoded(0x9ac2_0820, 0x2040),
        Ok(instruction(
            A64Opcode::Udiv,
            vec![reg(0, RegView::X), reg(1, RegView::X), reg(2, RegView::X)],
            false,
            0x2040,
        ))
    );
    assert_eq!(
        decoded(0x1ac5_0c83, 0x2044),
        Ok(instruction(
            A64Opcode::Sdiv,
            vec![reg(3, RegView::W), reg(4, RegView::W), reg(5, RegView::W)],
            false,
            0x2044,
        ))
    );
    assert_eq!(
        decoded(0x9ac8_20e6, 0x2048),
        Ok(instruction(
            A64Opcode::Lslv,
            vec![reg(6, RegView::X), reg(7, RegView::X), reg(8, RegView::X)],
            false,
            0x2048,
        ))
    );
    assert_eq!(
        decoded(0x1acb_2549, 0x2049),
        Ok(instruction(
            A64Opcode::Lsrv,
            vec![reg(9, RegView::W), reg(10, RegView::W), reg(11, RegView::W)],
            false,
            0x2049,
        ))
    );
    assert_eq!(
        decoded(0x9ace_29ac, 0x204a),
        Ok(instruction(
            A64Opcode::Asrv,
            vec![
                reg(12, RegView::X),
                reg(13, RegView::X),
                reg(14, RegView::X)
            ],
            false,
            0x204a,
        ))
    );
    assert_eq!(
        decoded(0x1ad1_2e0f, 0x204b),
        Ok(instruction(
            A64Opcode::Rorv,
            vec![
                reg(15, RegView::W),
                reg(16, RegView::W),
                reg(17, RegView::W)
            ],
            false,
            0x204b,
        ))
    );
    assert_eq!(
        decoded(0x9a82_0020, 0x204c),
        Ok(instruction(
            A64Opcode::Csel,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                reg(2, RegView::X),
                Operand::CondCode(0),
            ],
            false,
            0x204c,
        ))
    );
    assert_eq!(
        decoded(0x1a85_1483, 0x2050),
        Ok(instruction(
            A64Opcode::Csinc,
            vec![
                reg(3, RegView::W),
                reg(4, RegView::W),
                reg(5, RegView::W),
                Operand::CondCode(1),
            ],
            false,
            0x2050,
        ))
    );
    assert_eq!(
        decoded(0xda88_40e6, 0x2054),
        Ok(instruction(
            A64Opcode::Csinv,
            vec![
                reg(6, RegView::X),
                reg(7, RegView::X),
                reg(8, RegView::X),
                Operand::CondCode(4),
            ],
            false,
            0x2054,
        ))
    );
    assert_eq!(
        decoded(0x5a8b_5549, 0x2058),
        Ok(instruction(
            A64Opcode::Csneg,
            vec![
                reg(9, RegView::W),
                reg(10, RegView::W),
                reg(11, RegView::W),
                Operand::CondCode(5),
            ],
            false,
            0x2058,
        ))
    );
    assert_eq!(
        decoded(0x8b1f_0020, 0x205c),
        Ok(instruction(
            A64Opcode::Add,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                shifted(31, RegView::Zr, ShiftKind::Lsl, 0),
            ],
            false,
            0x205c,
        ))
    );
    assert_eq!(
        decoded(0x8b3f_6020, 0x2060),
        Ok(instruction(
            A64Opcode::Add,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                extended(31, RegView::Zr, ExtendKind::Uxtx, 0),
            ],
            false,
            0x2060,
        ))
    );
}

#[test]
fn load_store_forms_keep_addressing_modes_and_extensions() {
    assert_eq!(
        decoded(0xf900_0be0, 0x3000),
        Ok(instruction(
            A64Opcode::Str,
            vec![reg(0, RegView::X), mem_imm(31, 16, IndexMode::Offset)],
            false,
            0x3000,
        ))
    );
    assert_eq!(
        decoded(0xb940_0c41, 0x3004),
        Ok(instruction(
            A64Opcode::Ldr,
            vec![reg(1, RegView::W), mem_imm(2, 12, IndexMode::Offset)],
            false,
            0x3004,
        ))
    );
    assert_eq!(
        decoded(0x7900_0c20, 0x3008),
        Ok(instruction(
            A64Opcode::Strh,
            vec![reg(0, RegView::W), mem_imm(1, 6, IndexMode::Offset)],
            false,
            0x3008,
        ))
    );
    assert_eq!(
        decoded(0x7940_1549, 0x300c),
        Ok(instruction(
            A64Opcode::Ldrh,
            vec![reg(9, RegView::W), mem_imm(10, 10, IndexMode::Offset)],
            false,
            0x300c,
        ))
    );
    assert_eq!(
        decoded(0x3980_0820, 0x3010),
        Ok(instruction(
            A64Opcode::Ldrsb,
            vec![reg(0, RegView::X), mem_imm(1, 2, IndexMode::Offset)],
            false,
            0x3010,
        ))
    );
    assert_eq!(
        decoded(0x79c0_0862, 0x3014),
        Ok(instruction(
            A64Opcode::Ldrsh,
            vec![reg(2, RegView::W), mem_imm(3, 4, IndexMode::Offset)],
            false,
            0x3014,
        ))
    );
    assert_eq!(
        decoded(0xf81f_8083, 0x3018),
        Ok(instruction(
            A64Opcode::Stur,
            vec![reg(3, RegView::X), mem_imm(4, -8, IndexMode::Offset)],
            false,
            0x3018,
        ))
    );
    assert_eq!(
        decoded(0xb85f_03e5, 0x301c),
        Ok(instruction(
            A64Opcode::Ldur,
            vec![reg(5, RegView::W), mem_imm(31, -16, IndexMode::Offset)],
            false,
            0x301c,
        ))
    );
    assert_eq!(
        decoded(0xf801_8ce6, 0x3020),
        Ok(instruction(
            A64Opcode::Str,
            vec![reg(6, RegView::X), mem_imm(7, 24, IndexMode::PreIndex)],
            false,
            0x3020,
        ))
    );
    assert_eq!(
        decoded(0xf85e_8528, 0x3024),
        Ok(instruction(
            A64Opcode::Ldr,
            vec![reg(8, RegView::X), mem_imm(9, -24, IndexMode::PostIndex)],
            false,
            0x3024,
        ))
    );
    assert_eq!(
        decoded(0xa941_07e0, 0x3028),
        Ok(instruction(
            A64Opcode::Ldp,
            vec![
                reg(0, RegView::X),
                reg(1, RegView::X),
                mem_imm(31, 16, IndexMode::Offset),
            ],
            false,
            0x3028,
        ))
    );
    assert_eq!(
        decoded(0x29bf_0c82, 0x302c),
        Ok(instruction(
            A64Opcode::Stp,
            vec![
                reg(2, RegView::W),
                reg(3, RegView::W),
                mem_imm(4, -8, IndexMode::PreIndex),
            ],
            false,
            0x302c,
        ))
    );
    assert_eq!(
        decoded(0x3862_4820, 0x3030),
        Ok(instruction(
            A64Opcode::Ldrb,
            vec![reg(0, RegView::W), mem_reg(1, 2, ExtendKind::Uxtw, 0)],
            false,
            0x3030,
        ))
    );
    assert_eq!(
        decoded(0xf865_7883, 0x3034),
        Ok(instruction(
            A64Opcode::Ldr,
            vec![reg(3, RegView::X), mem_reg(4, 5, ExtendKind::Lsl, 3)],
            false,
            0x3034,
        ))
    );
    assert_eq!(
        decoded(0xb8a7_dbe6, 0x3038),
        Ok(instruction(
            A64Opcode::Ldrsw,
            vec![reg(6, RegView::X), mem_reg(31, 7, ExtendKind::Sxtw, 2)],
            false,
            0x3038,
        ))
    );
    assert_eq!(
        decoded(0x5800_0041, 0x303c),
        Ok(instruction(
            A64Opcode::Ldr,
            vec![reg(1, RegView::X), label(0x3044)],
            false,
            0x303c,
        ))
    );
    assert_eq!(
        decoded(0xf940_003f, 0x3040),
        Ok(instruction(
            A64Opcode::Ldr,
            vec![reg(31, RegView::Zr), mem_imm(1, 0, IndexMode::Offset)],
            false,
            0x3040,
        ))
    );
    assert_eq!(
        decoded(0xa940_7c3f, 0x3044),
        Ok(instruction(
            A64Opcode::Ldp,
            vec![
                reg(31, RegView::Zr),
                reg(31, RegView::Zr),
                mem_imm(1, 0, IndexMode::Offset),
            ],
            false,
            0x3044,
        ))
    );
}

#[test]
fn branch_forms_compute_absolute_targets() {
    assert_eq!(
        decoded(0x1400_0001, 0x4000),
        Ok(instruction(
            A64Opcode::B,
            vec![label(0x4004)],
            false,
            0x4000
        ))
    );
    assert_eq!(
        decoded(0x97ff_ffff, 0x4004),
        Ok(instruction(
            A64Opcode::Bl,
            vec![label(0x4000)],
            false,
            0x4004
        ))
    );
    assert_eq!(
        decoded(0xd61f_0200, 0x4008),
        Ok(instruction(
            A64Opcode::Br,
            vec![reg(16, RegView::X)],
            false,
            0x4008,
        ))
    );
    assert_eq!(
        decoded(0xd63f_0060, 0x400c),
        Ok(instruction(
            A64Opcode::Blr,
            vec![reg(3, RegView::X)],
            false,
            0x400c,
        ))
    );
    assert_eq!(
        decoded(0xd65f_03c0, 0x4010),
        Ok(instruction(
            A64Opcode::Ret,
            vec![reg(30, RegView::X)],
            false,
            0x4010,
        ))
    );
    assert_eq!(
        decoded(0x5400_0041, 0x4014),
        Ok(instruction(
            A64Opcode::BCond,
            vec![label(0x401c), Operand::CondCode(1)],
            false,
            0x4014,
        ))
    );
    assert_eq!(
        decoded(0x3400_0060, 0x4018),
        Ok(instruction(
            A64Opcode::Cbz,
            vec![reg(0, RegView::W), label(0x4024)],
            false,
            0x4018,
        ))
    );
    assert_eq!(
        decoded(0xb500_0061, 0x401c),
        Ok(instruction(
            A64Opcode::Cbnz,
            vec![reg(1, RegView::X), label(0x4028)],
            false,
            0x401c,
        ))
    );
    assert_eq!(
        decoded(0x3628_0042, 0x4020),
        Ok(instruction(
            A64Opcode::Tbz,
            vec![reg(2, RegView::W), Operand::Imm(5), label(0x4028)],
            false,
            0x4020,
        ))
    );
    assert_eq!(
        decoded(0xb710_0023, 0x4024),
        Ok(instruction(
            A64Opcode::Tbnz,
            vec![reg(3, RegView::X), Operand::Imm(34), label(0x4028)],
            false,
            0x4024,
        ))
    );
}

#[test]
fn bitmask_decoding_replicates_rotates_and_rejects_invalid_forms() {
    assert_eq!(
        decode_bit_masks(true, 0, 0, true, 64),
        Some(BitMasks { wmask: 1, tmask: 1 })
    );
    assert_eq!(
        decode_bit_masks(false, 0b11_0000, 0, true, 64),
        Some(BitMasks {
            wmask: 0x0101_0101_0101_0101,
            tmask: 0x0101_0101_0101_0101,
        })
    );
    assert_eq!(
        decode_bit_masks(false, 0b11_0000, 1, true, 64),
        Some(BitMasks {
            wmask: 0x8080_8080_8080_8080,
            tmask: u64::MAX,
        })
    );
    assert_eq!(decode_bit_masks(false, 0b11_1111, 0, true, 64), None);
}

#[test]
fn decoder_rejects_short_input_and_marks_unallocated_words() {
    assert_eq!(decode(&[], 0x5000), Err(DecodeError::TruncatedInput));
    assert_eq!(decode(&[0, 0, 0], 0x5004), Err(DecodeError::TruncatedInput));
    assert_eq!(
        decoded(0, 0x5008),
        Ok(instruction(
            A64Opcode::Unallocated,
            Vec::new(),
            false,
            0x5008
        ))
    );
    assert_eq!(
        decoded(0x5400_000f, 0x500c),
        Ok(instruction(
            A64Opcode::Unallocated,
            Vec::new(),
            false,
            0x500c
        ))
    );
    assert_eq!(
        decoded(0x1e00_0000, 0x5010),
        Ok(instruction(
            A64Opcode::Unmodeled(disrobe_pass_native::aarch64::DecodeClass::SimdFloatingPoint),
            Vec::new(),
            false,
            0x5010,
        ))
    );
    assert_eq!(
        decoded(0x5320_1c62, 0x5014),
        Ok(instruction(
            A64Opcode::Unallocated,
            Vec::new(),
            false,
            0x5014
        ))
    );
    assert_eq!(
        decoded(0xba82_0020, 0x5018),
        Ok(instruction(
            A64Opcode::Unallocated,
            Vec::new(),
            false,
            0x5018
        ))
    );
    assert_eq!(
        decoded(0xbac2_0820, 0x501c),
        Ok(instruction(
            A64Opcode::Unallocated,
            Vec::new(),
            false,
            0x501c
        ))
    );
    assert_eq!(
        decoded(0xbb02_0c20, 0x5020),
        Ok(instruction(
            A64Opcode::Unallocated,
            Vec::new(),
            false,
            0x5020
        ))
    );
    assert_eq!(
        decoded(0x1b22_7c20, 0x5024),
        Ok(instruction(
            A64Opcode::Unallocated,
            Vec::new(),
            false,
            0x5024
        ))
    );
}

#[test]
fn gcd_instruction_sequence_decodes_without_loss() {
    assert_eq!(
        decoded(0x3400_0181, 0x1000),
        Ok(instruction(
            A64Opcode::Cbz,
            vec![reg(1, RegView::W), label(0x1030)],
            false,
            0x1000,
        ))
    );
    assert_eq!(
        decoded(0x6b01_001f, 0x1004),
        Ok(instruction(
            A64Opcode::Cmp,
            vec![
                reg(0, RegView::W),
                shifted(1, RegView::W, ShiftKind::Lsl, 0),
            ],
            true,
            0x1004,
        ))
    );
    assert_eq!(
        decoded(0x5400_00c3, 0x1008),
        Ok(instruction(
            A64Opcode::BCond,
            vec![label(0x1020), Operand::CondCode(3)],
            false,
            0x1008,
        ))
    );
    assert_eq!(
        decoded(0x1ac1_0802, 0x100c),
        Ok(instruction(
            A64Opcode::Udiv,
            vec![reg(2, RegView::W), reg(0, RegView::W), reg(1, RegView::W)],
            false,
            0x100c,
        ))
    );
    assert_eq!(
        decoded(0x1b01_8043, 0x1010),
        Ok(instruction(
            A64Opcode::Msub,
            vec![
                reg(3, RegView::W),
                reg(2, RegView::W),
                reg(1, RegView::W),
                reg(0, RegView::W),
            ],
            false,
            0x1010,
        ))
    );
    assert_eq!(
        decoded(0x2a01_03e0, 0x1014),
        Ok(instruction(
            A64Opcode::Mov,
            vec![reg(0, RegView::W), reg(1, RegView::W)],
            false,
            0x1014,
        ))
    );
    assert_eq!(
        decoded(0x2a03_03e1, 0x1018),
        Ok(instruction(
            A64Opcode::Mov,
            vec![reg(1, RegView::W), reg(3, RegView::W)],
            false,
            0x1018,
        ))
    );
    assert_eq!(
        decoded(0x17ff_fff9, 0x101c),
        Ok(instruction(
            A64Opcode::B,
            vec![label(0x1000)],
            false,
            0x101c
        ))
    );
    assert_eq!(
        decoded(0x2a00_03e2, 0x1020),
        Ok(instruction(
            A64Opcode::Mov,
            vec![reg(2, RegView::W), reg(0, RegView::W)],
            false,
            0x1020,
        ))
    );
    assert_eq!(
        decoded(0x2a01_03e0, 0x1024),
        Ok(instruction(
            A64Opcode::Mov,
            vec![reg(0, RegView::W), reg(1, RegView::W)],
            false,
            0x1024,
        ))
    );
    assert_eq!(
        decoded(0x2a02_03e1, 0x1028),
        Ok(instruction(
            A64Opcode::Mov,
            vec![reg(1, RegView::W), reg(2, RegView::W)],
            false,
            0x1028,
        ))
    );
    assert_eq!(
        decoded(0x17ff_fff5, 0x102c),
        Ok(instruction(
            A64Opcode::B,
            vec![label(0x1000)],
            false,
            0x102c
        ))
    );
    assert_eq!(
        decoded(0xd65f_03c0, 0x1030),
        Ok(instruction(
            A64Opcode::Ret,
            vec![reg(30, RegView::X)],
            false,
            0x1030,
        ))
    );
}
