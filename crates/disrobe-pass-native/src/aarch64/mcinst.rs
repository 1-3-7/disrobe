#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A64Opcode {
    Adr,
    Adrp,
    Add,
    Adds,
    Sub,
    Subs,
    Cmn,
    Cmp,
    And,
    Orr,
    Eor,
    Ands,
    Tst,
    Bic,
    Orn,
    Mov,
    Movn,
    Movz,
    Movk,
    Sbfm,
    Ubfm,
    Bfm,
    Madd,
    Msub,
    Mul,
    Smull,
    Umull,
    Udiv,
    Sdiv,
    Lslv,
    Lsrv,
    Asrv,
    Rorv,
    Csel,
    Csinc,
    Csinv,
    Csneg,
    Str,
    Ldr,
    Stur,
    Ldur,
    Strb,
    Ldrb,
    Sturb,
    Ldurb,
    Strh,
    Ldrh,
    Sturh,
    Ldurh,
    Ldrsb,
    Ldursb,
    Ldrsh,
    Ldursh,
    Ldrsw,
    Ldursw,
    Stp,
    Ldp,
    B,
    Bl,
    Ret,
    Br,
    Blr,
    BCond,
    Cbz,
    Cbnz,
    Tbz,
    Tbnz,
    Unallocated,
    Unmodeled(DecodeClass),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeClass {
    Reserved,
    DataProcessingImmediate,
    BranchesAndSystem,
    LoadsAndStores,
    DataProcessingRegister,
    SimdFloatingPoint,
    ScalableVector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MCInst {
    pub opcode: A64Opcode,
    pub operands: Vec<Operand>,
    pub sets_flags: bool,
    pub va: u64,
    pub len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Reg {
        n: u8,
        view: RegView,
    },
    Imm(i64),
    ShiftedReg {
        n: u8,
        view: RegView,
        shift: ShiftKind,
        amount: u8,
    },
    ExtendedReg {
        n: u8,
        view: RegView,
        extend: ExtendKind,
        amount: u8,
    },
    MemBaseImm {
        base: u8,
        off: i64,
        mode: IndexMode,
    },
    MemBaseReg {
        base: u8,
        index: u8,
        extend: ExtendKind,
        scale: u8,
    },
    PcRelLabel {
        target: u64,
    },
    CondCode(u8),
    SysReg(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegView {
    W,
    X,
    Sp,
    Zr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendKind {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
    Lsl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexMode {
    Offset,
    PreIndex,
    PostIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TruncatedInput,
}
